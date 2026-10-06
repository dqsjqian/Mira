#pragma once

#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"

#include <cstddef>
#include <exception>
#include <stdexcept>
#include <stop_token>
#include <thread>
#include <utility>

namespace Mira::http {

// Structured session scheduling for a single event loop. Wire::read and
// Wire::flush must allow one read concurrent with one write, and read must never
// send data; the protocol engine is only touched synchronously on this thread.
// One worker task per direction. Per-wait cancellation/deadlines are not
// forwarded to the shared I/O; only stop/join or a connection failure terminates
// connection I/O. The Wire, its borrowed engine/transport and the event loop
// must outlive join. Stop application tasks first, then join; join stops the
// driver, drains worker tasks and registered waiters, and rethrows the first
// worker exception. Never mix with explicit pump or another driver.
// Construction starts no I/O; the first flush/progress/notify starts it.
template<class Wire>
class SessionDriver {
public:
    static constexpr bool multiplexed = true;

    SessionDriver(EventLoop& loop, Wire wire, std::size_t max_waiters = 256)
        : loop_(loop), wire_(std::move(wire)), max_waiters_(max_waiters),
          join_task_(finish(this)) {}
    SessionDriver(const SessionDriver&) = delete;
    SessionDriver& operator=(const SessionDriver&) = delete;
    SessionDriver(SessionDriver&&) = delete;
    SessionDriver& operator=(SessionDriver&&) = delete;
    ~SessionDriver() {
        if (((started_ || joining_) && !joined_) || waiters_) std::terminate();
    }

    [[nodiscard]] Error error() const noexcept { return error_; }

    // Notifies synchronously submitted data, window updates generated after
    // consumption, or per-stream RESETs; never re-enters the Wire.
    void notify() noexcept {
        require_thread();
        if (error_ || joining_) return;
        start();
        if (error_) return;
        ++requested_;
        writer_wake_.request_stop();
        signal(false);
    }

    [[nodiscard]] Task<Result<void>> flush(OperationOptions options = {}) {
        if (auto checked = check(options); !checked) co_return checked;
        notify();
        co_return co_await wait(true, requested_, options);
    }

    // Waits for the next packet arrival or output budget release; a wakeup does
    // not promise a specific stream is ready, callers must retry the engine.
    [[nodiscard]] Task<Result<void>> progress(OperationOptions options = {}) {
        if (auto checked = check(options); !checked) co_return checked;
        const auto before = epoch_;
        start();
        if (epoch_ != before && !error_) co_return Result<void>{};
        co_return co_await wait(false, 0, options);
    }

    void stop(Error reason = make_error_code(Errc::cancelled)) noexcept {
        require_thread();
        if (!error_) error_ = reason ? reason : make_error_code(Errc::cancelled);
        auto wire = wire_stop_;
        auto writer = writer_wake_;
        auto timer = timer_wake_;
        signal(true);
        wire.request_stop();
        writer.request_stop();
        timer.request_stop();
    }

    [[nodiscard]] Task<void> join() {
        require_thread();
        if (joining_) throw std::logic_error("Mira::http::SessionDriver::join already requested");
        joining_ = true;
        stop();
        return std::move(join_task_);
    }

private:
    struct ForwardStop {
        std::stop_source source;
        void operator()() const noexcept { auto copy = source; copy.request_stop(); }
    };
    struct Waiter {
        Waiter* next = nullptr;
        std::stop_source wake;
        std::size_t target;
        bool output;
        bool signalled = false;
        Waiter(std::size_t ticket, bool flushing) : target(ticket), output(flushing) {}
    };
    struct Registration {
        SessionDriver& owner;
        Waiter& waiter;
        Registration(SessionDriver& driver, Waiter& item) : owner(driver), waiter(item) {
            waiter.next = owner.waiters_;
            owner.waiters_ = &waiter;
            ++owner.waiter_count_;
        }
        ~Registration() {
            auto** link = &owner.waiters_;
            while (*link != &waiter) link = &(*link)->next;
            *link = waiter.next;
            --owner.waiter_count_;
            if (!owner.waiters_) owner.drained_.request_stop();
        }
    };

    void require_thread() const noexcept {
        if (thread_ != std::this_thread::get_id()) std::terminate();
    }
    Result<void> check(OperationOptions options) const {
        require_thread();
        if (error_) return fail(error_);
        if (options.stop.stop_requested()) return fail(Errc::cancelled);
        if (options.deadline && *options.deadline <= Clock::now()) return fail(Errc::timed_out);
        return {};
    }
    void signal(bool all) noexcept {
        ++epoch_;
        for (auto* item = waiters_; item; item = item->next) {
            if (all || !item->output || item->target <= completed_) {
                item->signalled = true;
                item->wake.request_stop();
            }
        }
    }
    void fail_exception() noexcept {
        if (!exception_) exception_ = std::current_exception();
        stop(make_error_code(Errc::internal));
    }
    void start() noexcept {
        if (started_ || error_ || joining_) return;
        started_ = true;
        ++requested_;
        try {
            tasks_.spawn(read_loop());
            if (!error_) tasks_.spawn(write_loop());
            if constexpr (requires(Wire& wire) { wire.expiry(); wire.handle_expiry(); }) {
                if (!error_) tasks_.spawn(timer_loop());
            }
        } catch (...) {
            fail_exception();
        }
    }

    Task<Result<void>> wait(bool output, std::size_t target, OperationOptions options) {
        if (auto checked = check(options); !checked) co_return checked;
        if (output && target <= completed_) co_return Result<void>{};
        if (waiter_count_ >= max_waiters_) co_return fail(Errc::limit_exceeded);
        Waiter waiter{target, output};
        Registration registration{*this, waiter};
        std::stop_callback forward(options.stop, ForwardStop{waiter.wake});
        const auto result = co_await loop_.sleep_until(
            options.deadline.value_or(Clock::time_point::max()), {.stop = waiter.wake.get_token()});
        if (auto checked = check(options); !checked) co_return checked;
        if (waiter.signalled) co_return Result<void>{};
        co_return fail(result ? make_error_code(Errc::timed_out) : result.error());
    }

    Task<void> read_loop() {
        try {
            while (!error_) {
                auto result = co_await wire_.read({.stop = wire_stop_.get_token()});
                if (!result) { stop(result.error()); break; }
                ++requested_;
                writer_wake_.request_stop();
                timer_wake_.request_stop();
                signal(false);
                co_await loop_.yield();
            }
        } catch (...) { fail_exception(); }
    }
    Task<void> write_loop() {
        try {
            while (!error_) {
                if (completed_ == requested_) {
                    writer_wake_ = std::stop_source{};
                    static_cast<void>(co_await loop_.sleep_until(
                        Clock::time_point::max(), {.stop = writer_wake_.get_token()}));
                    continue;
                }
                const auto target = requested_;
                auto result = co_await wire_.flush({.stop = wire_stop_.get_token()});
                if (!result) { stop(result.error()); break; }
                completed_ = target;
                timer_wake_.request_stop();
                signal(false);
                co_await loop_.yield();
            }
        } catch (...) { fail_exception(); }
    }
    Task<void> timer_loop() {
        try {
            while (!error_) {
                timer_wake_ = std::stop_source{};
                auto result = co_await loop_.sleep_until(wire_.expiry(),
                                                         {.stop = timer_wake_.get_token()});
                if (error_) break;
                if (!result && result.error() == Errc::cancelled) continue;
                if (!result) { stop(result.error()); break; }
                auto handled = wire_.handle_expiry();
                if (!handled) { stop(handled.error()); break; }
                ++requested_;
                writer_wake_.request_stop();
                signal(false);
                co_await loop_.yield();
            }
        } catch (...) { fail_exception(); }
    }
    static Task<void> finish(SessionDriver* self) {
        co_await self->tasks_.join();
        if (self->waiters_) {
            self->drained_ = std::stop_source{};
            static_cast<void>(co_await self->loop_.sleep_until(
                Clock::time_point::max(), {.stop = self->drained_.get_token()}));
        }
        self->joined_ = true;
        if (self->exception_) std::rethrow_exception(self->exception_);
    }

    EventLoop& loop_;
    Wire wire_;
    const std::size_t max_waiters_;
    const std::thread::id thread_ = std::this_thread::get_id();
    TaskScope tasks_;
    Task<void> join_task_;
    std::stop_source wire_stop_;
    std::stop_source writer_wake_;
    std::stop_source timer_wake_;
    std::stop_source drained_;
    Waiter* waiters_ = nullptr;
    std::size_t waiter_count_ = 0;
    std::size_t requested_ = 0;
    std::size_t completed_ = 0;
    std::size_t epoch_ = 0;
    Error error_;
    std::exception_ptr exception_;
    bool started_ = false;
    bool joining_ = false;
    bool joined_ = false;
};

} // namespace Mira::http
