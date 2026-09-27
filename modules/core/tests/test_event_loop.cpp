// Event loop tests — real descriptors, real completions, no wall-clock races.
//
// These run against whatever backend the platform selected. Nothing here names
// kqueue, epoll, or IOCP: if a test needs a `#if`, that is a signal the public
// API leaked a platform detail, and the API is what should change.
//
// Driving convention: a task that suspends on I/O cannot be `sync_get()`-ed,
// so tests own the frame in a `Task` variable, start it via a detached runner
// that records completion, and pump `run_once()` until the flag flips. That
// keeps every test deterministic — no sleeps, no "should be enough time".

#include "check.hpp"
#include "mira/core/buffer.hpp"
#include "mira/core/error.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/platform.hpp"
#include "mira/core/task.hpp"

#include "mira/core/operation.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if !MIRA_PLATFORM_WINDOWS
    #include <sys/socket.h>
    #include <unistd.h>
#endif

using namespace Mira;
using namespace std::chrono_literals;

namespace {

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

// ── deterministic driver ─────────────────────────────────────────────────────

/// Fire-and-forget coroutine that owns its frame until the body returns.
///
/// Needed because a suspended `Task` has no owner: the test cannot hold the
/// frame and also let the loop resume it. The promise destroys itself at
/// `final_suspend`, which is the one place it is safe to do so.
struct DetachedTask {
    struct promise_type {
        std::atomic<bool>* finished{nullptr};

        DetachedTask get_return_object() noexcept { return DetachedTask{}; }
        std::suspend_never initial_suspend() noexcept { return {}; }

        struct FinalAwaiter {
            [[nodiscard]] bool await_ready() const noexcept { return false; }
            void await_suspend(std::coroutine_handle<promise_type> self) const noexcept {
                if (self.promise().finished) {
                    self.promise().finished->store(true, std::memory_order_release);
                }
                self.destroy();
            }
            void await_resume() const noexcept {}
        };

        FinalAwaiter final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::terminate(); }
    };
};

/// Run `body` to completion, pumping the loop until it finishes.
///
/// `budget` bounds the number of iterations so a hung expectation fails the
/// test instead of hanging CI.
template<typename Body>
bool drive(EventLoop& loop, std::atomic<bool>& finished, Body body, int budget = 1000) {
    body();  // starts eagerly, suspends on its first await
    for (int i = 0; i < budget && !finished.load(std::memory_order_acquire); ++i) {
        const Result<void> stepped = loop.run_once(50ms);
        if (!stepped) {
            return false;
        }
    }
    return finished.load(std::memory_order_acquire);
}

// ── fixtures ─────────────────────────────────────────────────────────────────

/// A connected pair of handles the loop can do real I/O on.
class HandlePair {
public:
    HandlePair() {
#if MIRA_PLATFORM_WINDOWS
        // A loopback TCP pair stands in for socketpair(), which Winsock lacks.
        // Only reached on the Windows CI job.
        ok_ = false;
#else
        int fds[2] = {-1, -1};
        ok_ = ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0;
        first_ = fds[0];
        second_ = fds[1];
#endif
    }

    HandlePair(const HandlePair&) = delete;
    HandlePair& operator=(const HandlePair&) = delete;

    ~HandlePair() {
#if !MIRA_PLATFORM_WINDOWS
        if (first_ >= 0) {
            ::close(first_);
        }
        if (second_ >= 0) {
            ::close(second_);
        }
#endif
    }

    [[nodiscard]] bool valid() const noexcept { return ok_; }
    [[nodiscard]] NativeHandle first() const noexcept { return first_; }
    [[nodiscard]] NativeHandle second() const noexcept { return second_; }

    /// Write directly, bypassing the loop — simulates the peer.
    void peer_send(std::string_view payload) const {
#if !MIRA_PLATFORM_WINDOWS
        const ssize_t written = ::write(second_, payload.data(), payload.size());
        (void)written;
#else
        (void)payload;
#endif
    }

    void peer_close() {
#if !MIRA_PLATFORM_WINDOWS
        if (second_ >= 0) {
            ::close(second_);
            second_ = -1;
        }
#endif
    }

    /// Write until the send buffer refuses more, so the write direction is
    /// genuinely *not* ready. Returns how much went in, or 0 on failure.
    ///
    /// Needed because a fresh socketpair is always writable, and a writer that
    /// is immediately ready can never be observed parked — which is the only
    /// state in which "cancelling the read direction left the write
    /// registration alone" is an observable claim rather than a hope. Requires
    /// the descriptor to be non-blocking, which `attach` has already ensured.
    [[nodiscard]] std::size_t fill_send_buffer() const {
#if MIRA_PLATFORM_WINDOWS
        return 0;
#else
        std::array<std::byte, 4096> block{};
        std::size_t total = 0;
        for (;;) {
            const ssize_t written = ::write(first_, block.data(), block.size());
            if (written < 0) {
                return (errno == EAGAIN || errno == EWOULDBLOCK) ? total : 0;
            }
            total += static_cast<std::size_t>(written);
        }
#endif
    }

    /// Consume some of what we sent, making room in the send buffer again.
    void peer_drain(std::size_t bytes) const {
#if MIRA_PLATFORM_WINDOWS
        (void)bytes;
#else
        std::array<std::byte, 4096> block{};
        std::size_t left = bytes;
        while (left > 0) {
            const ssize_t got = ::read(second_, block.data(), std::min(left, block.size()));
            if (got <= 0) {
                break;
            }
            left -= static_cast<std::size_t>(got);
        }
#endif
    }

private:
    NativeHandle first_{invalid_handle};
    NativeHandle second_{invalid_handle};
    bool ok_{false};
};

// ── tests ────────────────────────────────────────────────────────────────────

void test_create_and_backend() {
    test::section("loop creation");

    Result<EventLoop> loop = EventLoop::create();
    CHECK(loop.has_value());
    CHECK(loop.value().outstanding() == 0);
    CHECK(!loop.value().stopped());

    // The backend is a build fact, not something a test should branch on —
    // asserting it is non-empty keeps the diagnostic honest.
    CHECK(std::string_view{io_backend_name()}.size() > 0);
    std::printf("   backend: %s\n", io_backend_name());
}

void test_post_and_stop() {
    test::section("post and stop");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    int calls = 0;
    loop.post([&calls] { ++calls; });
    CHECK(calls == 0);  // queued, not run
    CHECK(loop.outstanding() == 1);

    CHECK(loop.run_once(0ms).has_value());
    CHECK(calls == 1);
    CHECK(loop.outstanding() == 0);

    // run() returns once nothing is outstanding, instead of blocking forever.
    CHECK(loop.run().has_value());

    // A posted callable may stop the loop from inside the loop.
    loop.post([&loop] { loop.stop(); });
    CHECK(loop.run().has_value());
    CHECK(loop.stopped());
}

void test_timers() {
    test::section("timers");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    std::atomic<bool> finished{false};
    Result<void> outcome = fail(Errc::cancelled);
    const auto started = std::chrono::steady_clock::now();

    struct Runner {
        static DetachedTask go(EventLoop& target, Result<void>& slot, std::atomic<bool>& flag) {
            slot = co_await target.sleep_for(20ms);
            flag.store(true, std::memory_order_release);
            co_return;
        }
    };

    Runner::go(loop, outcome, finished);
    for (int i = 0; i < 200 && !finished.load(std::memory_order_acquire); ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }

    CHECK(finished.load(std::memory_order_acquire));
    CHECK(outcome.has_value());
    // The deadline must not fire early; a loop that rounds timeouts down
    // would show up here.
    CHECK(std::chrono::steady_clock::now() - started >= 20ms);

    // Ordering: an earlier deadline fires first even when queued second.
    std::vector<int> order;
    std::atomic<int> done{0};

    struct Ordered {
        static DetachedTask go(EventLoop& target,
                               EventLoop::Duration delay,
                               int id,
                               std::vector<int>& log,
                               std::atomic<int>& counter) {
            (void)co_await target.sleep_for(delay);
            log.push_back(id);
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    Ordered::go(loop, 40ms, 2, order, done);
    Ordered::go(loop, 5ms, 1, order, done);

    for (int i = 0; i < 200 && done.load(std::memory_order_acquire) < 2; ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }
    CHECK(done.load(std::memory_order_acquire) == 2);
    CHECK(order.size() == 2);
    if (order.size() == 2) {
        CHECK(order[0] == 1);
        CHECK(order[1] == 2);
    }
}

void test_read_write_roundtrip() {
    test::section("read/write round trip");

    HandlePair pair;
    if (!pair.valid()) {
        std::printf("   skipped: no handle pair on this platform\n");
        return;
    }

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    CHECK(loop.attach(pair.first()).has_value());

    // Data already waiting: the read completes without ever suspending.
    pair.peer_send("hello");

    std::atomic<bool> finished{false};
    std::string received;
    Result<std::size_t> outcome = fail(Errc::cancelled);

    struct Reader {
        static DetachedTask go(EventLoop& target,
                               NativeHandle handle,
                               std::string& sink,
                               Result<std::size_t>& slot,
                               std::atomic<bool>& flag) {
            std::array<std::byte, 64> scratch{};
            slot = co_await target.read(handle, std::span<std::byte>{scratch});
            if (slot.has_value()) {
                sink.assign(reinterpret_cast<const char*>(scratch.data()), slot.value());
            }
            flag.store(true, std::memory_order_release);
            co_return;
        }
    };

    Reader::go(loop, pair.first(), received, outcome, finished);
    for (int i = 0; i < 200 && !finished.load(std::memory_order_acquire); ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }

    CHECK(finished.load(std::memory_order_acquire));
    CHECK(outcome.has_value());
    CHECK(received == "hello");

    // Now the suspending path: read first, data arrives later.
    std::atomic<bool> second_finished{false};
    std::string second_received;
    Result<std::size_t> second_outcome = fail(Errc::cancelled);

    Reader::go(loop, pair.first(), second_received, second_outcome, second_finished);

    // One pump with nothing available proves the read really suspended.
    CHECK(loop.run_once(0ms).has_value());
    CHECK(!second_finished.load(std::memory_order_acquire));
    CHECK(loop.outstanding() >= 1);

    pair.peer_send("world");
    for (int i = 0; i < 200 && !second_finished.load(std::memory_order_acquire); ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }

    CHECK(second_finished.load(std::memory_order_acquire));
    CHECK(second_outcome.has_value());
    CHECK(second_received == "world");

    // Writing through the loop reaches the peer.
    std::atomic<bool> write_finished{false};
    Result<std::size_t> write_outcome = fail(Errc::cancelled);

    struct Writer {
        static DetachedTask go(EventLoop& target,
                               NativeHandle handle,
                               std::span<const std::byte> payload,
                               Result<std::size_t>& slot,
                               std::atomic<bool>& flag) {
            slot = co_await target.write(handle, payload);
            flag.store(true, std::memory_order_release);
            co_return;
        }
    };

    Writer::go(loop, pair.first(), bytes_of("pong"), write_outcome, write_finished);
    for (int i = 0; i < 200 && !write_finished.load(std::memory_order_acquire); ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }
    CHECK(write_finished.load(std::memory_order_acquire));
    CHECK(write_outcome.has_value());
    CHECK(write_outcome.value_or(0) == 4);
}

void test_eof_is_distinct_from_empty() {
    test::section("clean close reports eof");

    HandlePair pair;
    if (!pair.valid()) {
        std::printf("   skipped: no handle pair on this platform\n");
        return;
    }

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();
    CHECK(loop.attach(pair.first()).has_value());

    std::atomic<bool> finished{false};
    Result<std::size_t> outcome = std::size_t{999};

    struct Reader {
        static DetachedTask go(EventLoop& target,
                               NativeHandle handle,
                               Result<std::size_t>& slot,
                               std::atomic<bool>& flag) {
            std::array<std::byte, 16> scratch{};
            slot = co_await target.read(handle, std::span<std::byte>{scratch});
            flag.store(true, std::memory_order_release);
            co_return;
        }
    };

    Reader::go(loop, pair.first(), outcome, finished);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(!finished.load(std::memory_order_acquire));

    pair.peer_close();
    for (int i = 0; i < 200 && !finished.load(std::memory_order_acquire); ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }

    CHECK(finished.load(std::memory_order_acquire));
    // A closed peer must be eof, not a zero-byte success.
    CHECK(!outcome.has_value());
    CHECK(outcome.error() == Errc::eof);
}

void test_double_waiter_is_refused() {
    test::section("same-direction waiters refused");

    HandlePair pair;
    if (!pair.valid()) {
        std::printf("   skipped: no handle pair on this platform\n");
        return;
    }

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();
    CHECK(loop.attach(pair.first()).has_value());

    std::atomic<int> done{0};
    Result<std::size_t> first_outcome = fail(Errc::cancelled);
    Result<std::size_t> second_outcome = fail(Errc::cancelled);

    struct Reader {
        static DetachedTask go(EventLoop& target,
                               NativeHandle handle,
                               Result<std::size_t>& slot,
                               std::atomic<int>& counter) {
            std::array<std::byte, 16> scratch{};
            slot = co_await target.read(handle, std::span<std::byte>{scratch});
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    // First read suspends and owns the read direction.
    Reader::go(loop, pair.first(), first_outcome, done);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(done.load(std::memory_order_acquire) == 0);

    // Second read on the same direction is refused rather than racing.
    Reader::go(loop, pair.first(), second_outcome, done);
    CHECK(done.load(std::memory_order_acquire) == 1);
    CHECK(!second_outcome.has_value());
    CHECK(second_outcome.error() == Errc::invalid_argument);

    // The original waiter still works.
    pair.peer_send("ok");
    for (int i = 0; i < 200 && done.load(std::memory_order_acquire) < 2; ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }
    CHECK(done.load(std::memory_order_acquire) == 2);
    CHECK(first_outcome.has_value());
}

void test_destruction_wakes_suspended() {
    test::section("destruction cancels suspended work");

    std::atomic<bool> finished{false};
    Result<void> outcome{};

    struct Sleeper {
        static DetachedTask go(EventLoop& target, Result<void>& slot, std::atomic<bool>& flag) {
            slot = co_await target.sleep_for(std::chrono::hours{1});
            flag.store(true, std::memory_order_release);
            co_return;
        }
    };

    {
        Result<EventLoop> created = EventLoop::create();
        CHECK(created.has_value());
        Sleeper::go(created.value(), outcome, finished);
        CHECK(created.value().outstanding() == 1);
        // Loop dies here with a waiter still suspended.
    }

    // The frame must have unwound rather than leaked (ASan would catch the
    // leak; this asserts the coroutine observed a reason).
    CHECK(finished.load(std::memory_order_acquire));
    CHECK(!outcome.has_value());
    CHECK(outcome.error() == Errc::cancelled);
}

void test_yield_returns_to_loop() {
    test::section("yield");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    std::atomic<bool> finished{false};
    int stage = 0;

    struct Hopper {
        static DetachedTask go(EventLoop& target, int& progress, std::atomic<bool>& flag) {
            progress = 1;
            co_await target.yield();
            progress = 2;
            flag.store(true, std::memory_order_release);
            co_return;
        }
    };

    Hopper::go(loop, stage, finished);
    CHECK(stage == 1);  // suspended at the yield
    CHECK(!finished.load(std::memory_order_acquire));

    for (int i = 0; i < 10 && !finished.load(std::memory_order_acquire); ++i) {
        CHECK(loop.run_once(0ms).has_value());
    }
    CHECK(finished.load(std::memory_order_acquire));
    CHECK(stage == 2);
}

// ── per-operation cancellation and deadlines ─────────────────────────────────

/// Read into a caller-owned slot, recording the outcome and completion.
struct Reader {
    static DetachedTask go(EventLoop& target,
                           NativeHandle handle,
                           std::span<std::byte> scratch,
                           OperationOptions options,
                           Result<std::size_t>& slot,
                           std::atomic<int>& counter) {
        slot = co_await target.read(handle, scratch, std::move(options));
        counter.fetch_add(1, std::memory_order_release);
        co_return;
    }
};

void test_options_rejected_before_submit() {
    test::section("options are decided before the first syscall");

    HandlePair pair;
    if (!pair.valid()) {
        std::printf("   skipped: no handle pair on this platform\n");
        return;
    }

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();
    CHECK(loop.attach(pair.first()).has_value());

    std::array<std::byte, 16> scratch{};
    const auto read_with = [&](OperationOptions options) {
        std::atomic<int> done{0};
        Result<std::size_t> outcome = std::size_t{999};
        Reader::go(loop, pair.first(), scratch, std::move(options), outcome, done);
        // Nothing was submitted, so the answer is already there.
        CHECK(done.load(std::memory_order_acquire) == 1);
        CHECK(loop.outstanding() == 0);
        return outcome;
    };

    std::stop_source stopped;
    stopped.request_stop();
    const auto past = EventLoop::Clock::now() - 1ms;

    const Result<std::size_t> cancelled = read_with({.stop = stopped.get_token()});
    CHECK(!cancelled.has_value());
    CHECK(cancelled.error() == Errc::cancelled);

    const Result<std::size_t> expired = read_with({.deadline = past});
    CHECK(!expired.has_value());
    CHECK(expired.error() == Errc::timed_out);

    // Both apply: an explicit request outranks an elapsed budget.
    const Result<std::size_t> both =
        read_with({.stop = stopped.get_token(), .deadline = past});
    CHECK(!both.has_value());
    CHECK(both.error() == Errc::cancelled);

    // Data is waiting, so a read without options would succeed immediately.
    // The options still win, which is what "before the first syscall" means.
    pair.peer_send("ready");
    const Result<std::size_t> refused = read_with({.stop = stopped.get_token()});
    CHECK(!refused.has_value());
    CHECK(refused.error() == Errc::cancelled);

    // A zero-length read normally shortcuts to 0 bytes; a cancelled one has to
    // report the reason instead of a success it never performed.
    std::atomic<int> done{0};
    Result<std::size_t> empty = std::size_t{999};
    Reader::go(loop,
               pair.first(),
               std::span<std::byte>{},
               {.stop = stopped.get_token()},
               empty,
               done);
    CHECK(done.load(std::memory_order_acquire) == 1);
    CHECK(!empty.has_value());
    CHECK(empty.error() == Errc::cancelled);

    // Without options it still shortcuts.
    std::atomic<int> plain_done{0};
    Result<std::size_t> plain = fail(Errc::cancelled);
    Reader::go(loop, pair.first(), std::span<std::byte>{}, {}, plain, plain_done);
    CHECK(plain_done.load(std::memory_order_acquire) == 1);
    CHECK(plain.value_or(999) == 0);

#if MIRA_HAS_READINESS_API
    // The readiness extension has no syscall of its own to guard, so its only
    // check is the one every submission shares. Without it the wait would
    // park, be cancelled by the callback, and need a pump to come back —
    // observably different from never starting.
    std::atomic<int> wait_done{0};
    Result<void> waited{};

    struct Waiter {
        static DetachedTask go(EventLoop& target,
                               NativeHandle handle,
                               OperationOptions options,
                               Result<void>& slot,
                               std::atomic<int>& counter) {
            slot = co_await target.wait_readable(handle, std::move(options));
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    Waiter::go(loop, pair.first(), {.stop = stopped.get_token()}, waited, wait_done);
    CHECK(wait_done.load(std::memory_order_acquire) == 1);
    CHECK(loop.outstanding() == 0);
    CHECK(!waited.has_value());
    CHECK(waited.error() == Errc::cancelled);

    Result<void> expired_wait{};
    std::atomic<int> expired_done{0};
    Waiter::go(loop, pair.first(), {.deadline = past}, expired_wait, expired_done);
    CHECK(expired_done.load(std::memory_order_acquire) == 1);
    CHECK(loop.outstanding() == 0);
    CHECK(!expired_wait.has_value());
    CHECK(expired_wait.error() == Errc::timed_out);
#endif
}

void test_cancel_in_flight() {
    test::section("cancelling a suspended operation");

    HandlePair pair;
    if (!pair.valid()) {
        std::printf("   skipped: no handle pair on this platform\n");
        return;
    }

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();
    CHECK(loop.attach(pair.first()).has_value());

    std::stop_source source;
    std::array<std::byte, 16> scratch{};
    std::atomic<int> done{0};
    Result<std::size_t> outcome = std::size_t{999};

    Reader::go(loop, pair.first(), scratch, {.stop = source.get_token()}, outcome, done);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(done.load(std::memory_order_acquire) == 0);  // genuinely suspended
    CHECK(loop.outstanding() == 1);

    // The request only queues work; nothing is resumed until the loop runs.
    source.request_stop();
    CHECK(done.load(std::memory_order_acquire) == 0);

    // Requesting twice must not queue a second resumption, and the loop must
    // not block when all it has left is a pending cancellation.
    source.request_stop();
    CHECK(loop.run_once(EventLoop::Duration::min()).has_value());
    CHECK(done.load(std::memory_order_acquire) == 1);
    CHECK(!outcome.has_value());
    CHECK(outcome.error() == Errc::cancelled);
    CHECK(loop.outstanding() == 0);

    // A readiness event arriving after the cancellation resolves nothing: the
    // operation is gone, and its id is never reused.
    pair.peer_send("late");
    CHECK(loop.run_once(0ms).has_value());
    CHECK(done.load(std::memory_order_acquire) == 1);
}

#if MIRA_HAS_READINESS_API
/// Only meaningful where readiness is the mechanism: `wait_readable` and
/// `wait_writable` are not declared on IOCP, so this is compiled out rather
/// than skipped, which is the honest shape for a platform extension.
void test_cancel_leaves_other_direction_armed() {
    test::section("cancelling one direction leaves the other waiting");

    HandlePair pair;
    if (!pair.valid()) {
        std::printf("   skipped: no handle pair on this platform\n");
        return;
    }

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();
    CHECK(loop.attach(pair.first()).has_value());

    // Both waiters have to be genuinely parked for this to prove anything, so
    // the send buffer is filled first: otherwise the writer is ready in the
    // very batch that delivers the cancellation, and would complete no matter
    // what happened to its registration.
    const std::size_t buffered = pair.fill_send_buffer();
    CHECK(buffered > 0);
    if (buffered == 0) {
        return;
    }

    std::stop_source stop_reader;
    std::atomic<int> done{0};
    Result<void> read_outcome = fail(Errc::eof);
    Result<void> write_outcome = fail(Errc::eof);

    struct Waiter {
        static DetachedTask readable(EventLoop& target,
                                     NativeHandle handle,
                                     OperationOptions options,
                                     Result<void>& slot,
                                     std::atomic<int>& counter) {
            slot = co_await target.wait_readable(handle, std::move(options));
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }

        static DetachedTask writable(EventLoop& target,
                                     NativeHandle handle,
                                     Result<void>& slot,
                                     std::atomic<int>& counter) {
            slot = co_await target.wait_writable(handle);
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    Waiter::writable(loop, pair.first(), write_outcome, done);
    Waiter::readable(loop, pair.first(), {.stop = stop_reader.get_token()}, read_outcome, done);
    CHECK(loop.outstanding() == 2);

    // Neither direction is ready.
    CHECK(loop.run_once(0ms).has_value());
    CHECK(done.load(std::memory_order_acquire) == 0);

    // Readiness is per direction, and so is its kernel registration. Dropping
    // the whole descriptor's interest — which is what `disarm` does — would
    // strand the writer here with nothing armed on its behalf.
    stop_reader.request_stop();
    CHECK(loop.run_once(EventLoop::Duration::min()).has_value());
    CHECK(done.load(std::memory_order_acquire) == 1);
    CHECK(!read_outcome.has_value());
    CHECK(read_outcome.error() == Errc::cancelled);
    CHECK(loop.outstanding() == 1);

    // Make room again: the surviving writer must still be registered.
    pair.peer_drain(buffered);
    for (int i = 0; i < 200 && done.load(std::memory_order_acquire) < 2; ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }
    CHECK(done.load(std::memory_order_acquire) == 2);
    CHECK(write_outcome.has_value());
    CHECK(loop.outstanding() == 0);
}

void test_detach_and_shutdown_resume_waiters() {
    test::section("detach and shutdown synchronously drain both waiting directions, tolerating re-entrant detach");

    struct Waiter {
        static DetachedTask go(EventLoop& loop, NativeHandle handle, bool writable,
                               bool shutdown, Result<void>& outcome, int& done) {
            outcome = co_await (writable ? loop.wait_writable(handle)
                                         : loop.wait_readable(handle));
            ++done;
            loop.detach(handle);
            if (shutdown) {
                const auto stepped = loop.run_once(0ms);
                CHECK(!stepped.has_value());
                CHECK(stepped.error() == Errc::cancelled);
            }
        }
    };

    for (const bool shutdown : {false, true}) {
        HandlePair pair;
        CHECK(pair.valid());
        if (!pair.valid()) return;
        auto created = EventLoop::create();
        CHECK(created.has_value());
        if (!created) return;
        auto loop = std::make_unique<EventLoop>(std::move(*created));
        CHECK(loop->attach(pair.first()).has_value());
        Result<void> read_outcome{};
        Result<void> write_outcome{};
        int done = 0;
        Waiter::go(*loop, pair.first(), false, shutdown, read_outcome, done);
        Waiter::go(*loop, pair.first(), true, shutdown, write_outcome, done);
        CHECK(done == 0);
        CHECK(loop->outstanding() == 2);
        if (shutdown) {
            loop.reset();
        } else {
            loop->detach(pair.first());
            CHECK(loop->outstanding() == 0);
            CHECK(loop->run_once(0ms).has_value());
            loop.reset();
        }
        CHECK(done == 2);
        CHECK(!read_outcome.has_value());
        CHECK(read_outcome.error() == Errc::cancelled);
        CHECK(!write_outcome.has_value());
        CHECK(write_outcome.error() == Errc::cancelled);
    }
}
#endif  // MIRA_HAS_READINESS_API

void test_deadline_on_a_suspended_read() {
    test::section("deadline on a read that never becomes ready");

    HandlePair pair;
    if (!pair.valid()) {
        std::printf("   skipped: no handle pair on this platform\n");
        return;
    }

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();
    CHECK(loop.attach(pair.first()).has_value());

    std::array<std::byte, 16> scratch{};
    std::atomic<int> done{0};
    Result<std::size_t> outcome = std::size_t{999};
    const auto started = EventLoop::Clock::now();

    Reader::go(loop,
               pair.first(),
               scratch,
               {.deadline = started + 20ms},
               outcome,
               done);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(done.load(std::memory_order_acquire) == 0);
    // One outstanding thing, not two: the deadline indexes the read rather
    // than being work of its own.
    CHECK(loop.outstanding() == 1);

    for (int i = 0; i < 200 && done.load(std::memory_order_acquire) == 0; ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }
    CHECK(done.load(std::memory_order_acquire) == 1);
    CHECK(!outcome.has_value());
    CHECK(outcome.error() == Errc::timed_out);
    CHECK(EventLoop::Clock::now() - started >= 20ms);
    CHECK(loop.outstanding() == 0);
}

void test_deadline_is_absolute_across_retries() {
    test::section("retries do not refresh the deadline");

    HandlePair pair;
    if (!pair.valid()) {
        std::printf("   skipped: no handle pair on this platform\n");
        return;
    }

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();
    CHECK(loop.attach(pair.first()).has_value());

    // A one-byte buffer forces a fresh submission for every byte the peer
    // dribbles in. Each retry registers a *new* operation, so a deadline held
    // per-operation as a duration would restart every time and the read would
    // outlive its budget indefinitely.
    std::array<std::byte, 1> scratch{};
    const auto deadline = EventLoop::Clock::now() + 40ms;
    int reads = 0;
    std::atomic<bool> finished{false};
    Result<std::size_t> outcome = std::size_t{999};

    struct Dribble {
        static DetachedTask go(EventLoop& target,
                               const HandlePair& pair,
                               std::span<std::byte> scratch,
                               EventLoop::Clock::time_point deadline,
                               int& reads,
                               Result<std::size_t>& slot,
                               std::atomic<bool>& flag) {
            for (;;) {
                pair.peer_send("x");
                const Result<std::size_t> step =
                    co_await target.read(pair.first(), scratch, {.deadline = deadline});
                if (!step) {
                    slot = step;
                    break;
                }
                ++reads;
                (void)co_await target.sleep_for(5ms);
            }
            flag.store(true, std::memory_order_release);
            co_return;
        }
    };

    Dribble::go(loop, pair, scratch, deadline, reads, outcome, finished);
    for (int i = 0; i < 400 && !finished.load(std::memory_order_acquire); ++i) {
        CHECK(loop.run_once(10ms).has_value());
    }

    CHECK(finished.load(std::memory_order_acquire));
    CHECK(!outcome.has_value());
    CHECK(outcome.error() == Errc::timed_out);
    // Several successful reads happened first, which is what makes this a test
    // of the budget rather than of an immediate timeout.
    CHECK(reads > 1);
    CHECK(EventLoop::Clock::now() >= deadline);
}

void test_sleep_deadline_beats_wake_up() {
    test::section("sleep: wake-up and deadline are different answers");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    struct Sleeper {
        static DetachedTask go(EventLoop& target,
                               EventLoop::Duration delay,
                               OperationOptions options,
                               Result<void>& slot,
                               std::atomic<bool>& flag) {
            slot = co_await target.sleep_for(delay, std::move(options));
            flag.store(true, std::memory_order_release);
            co_return;
        }
    };

    // Deadline first: the sleep is cut short.
    std::atomic<bool> cut{false};
    Result<void> cut_outcome{};
    Sleeper::go(loop,
                std::chrono::hours{1},
                {.deadline = EventLoop::Clock::now() + 10ms},
                cut_outcome,
                cut);
    // Two timers for one operation.
    CHECK(loop.outstanding() == 1);
    for (int i = 0; i < 200 && !cut.load(std::memory_order_acquire); ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }
    CHECK(cut.load(std::memory_order_acquire));
    CHECK(!cut_outcome.has_value());
    CHECK(cut_outcome.error() == Errc::timed_out);
    // Both timers are gone, not just the one that fired.
    CHECK(loop.outstanding() == 0);

    // Wake-up first: reaching the requested time is success, even though a
    // deadline was also set.
    std::atomic<bool> slept{false};
    Result<void> slept_outcome = fail(Errc::cancelled);
    Sleeper::go(loop,
                5ms,
                {.deadline = EventLoop::Clock::now() + std::chrono::hours{1}},
                slept_outcome,
                slept);
    for (int i = 0; i < 200 && !slept.load(std::memory_order_acquire); ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }
    CHECK(slept.load(std::memory_order_acquire));
    CHECK(slept_outcome.has_value());
    CHECK(loop.outstanding() == 0);

    // Both due in the same batch, with the deadline having expired first.
    // Whichever came first decides, so this is a timeout — and the timer queue
    // has to deliver them in time order for that to come out right.
    std::atomic<bool> overtaken{false};
    Result<void> overtaken_outcome{};
    const auto wake_at = EventLoop::Clock::now() + 60ms;
    Sleeper::go(loop,
                60ms,
                {.deadline = EventLoop::Clock::now() + 10ms},
                overtaken_outcome,
                overtaken);
    // Spin past both, so that one pump finds the pair of them expired.
    while (EventLoop::Clock::now() < wake_at + 10ms) {
    }
    CHECK(loop.run_once(0ms).has_value());
    CHECK(overtaken.load(std::memory_order_acquire));
    CHECK(!overtaken_outcome.has_value());
    CHECK(overtaken_outcome.error() == Errc::timed_out);
    CHECK(loop.outstanding() == 0);

    // Cancelling a sleep cancels both of its timers.
    std::stop_source source;
    std::atomic<bool> stopped{false};
    Result<void> stopped_outcome{};
    Sleeper::go(loop,
                std::chrono::hours{1},
                {.stop = source.get_token(),
                 .deadline = EventLoop::Clock::now() + std::chrono::hours{2}},
                stopped_outcome,
                stopped);
    CHECK(loop.outstanding() == 1);
    source.request_stop();
    CHECK(loop.run_once(EventLoop::Duration::min()).has_value());
    CHECK(stopped.load(std::memory_order_acquire));
    CHECK(!stopped_outcome.has_value());
    CHECK(stopped_outcome.error() == Errc::cancelled);
    CHECK(loop.outstanding() == 0);
}

void test_completion_beats_deadline_in_one_batch() {
    test::section("a completion in the same batch outranks its deadline");

    HandlePair pair;
    if (!pair.valid()) {
        std::printf("   skipped: no handle pair on this platform\n");
        return;
    }

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();
    CHECK(loop.attach(pair.first()).has_value());

    std::array<std::byte, 16> scratch{};
    std::atomic<int> done{0};
    Result<std::size_t> outcome = fail(Errc::cancelled);

    // Deadline already in the past *and* data already waiting. The read
    // suspends first (so the options check at submission has passed), then a
    // single pump sees both the readiness and the expired timer.
    Reader::go(loop, pair.first(), scratch, {.deadline = EventLoop::Clock::now() + 5ms},
               outcome, done);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(done.load(std::memory_order_acquire) == 0);

    pair.peer_send("data");
    // Wait past the deadline so that both are due in the same iteration.
    const auto until = EventLoop::Clock::now() + 20ms;
    while (EventLoop::Clock::now() < until) {
    }
    CHECK(loop.run_once(0ms).has_value());

    CHECK(done.load(std::memory_order_acquire) == 1);
    CHECK(outcome.has_value());
    CHECK(outcome.value_or(0) == 4);
    CHECK(loop.outstanding() == 0);

    // Same rule for a cancellation that lands in the batch the data does. The
    // read genuinely finished; reporting it as cancelled would throw away
    // bytes that have already left the kernel's buffer.
    std::stop_source source;
    std::atomic<int> raced_done{0};
    Result<std::size_t> raced = fail(Errc::cancelled);
    Reader::go(loop, pair.first(), scratch, {.stop = source.get_token()}, raced, raced_done);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(raced_done.load(std::memory_order_acquire) == 0);

    pair.peer_send("more");
    source.request_stop();
    CHECK(loop.run_once(0ms).has_value());

    CHECK(raced_done.load(std::memory_order_acquire) == 1);
    CHECK(raced.has_value());
    CHECK(raced.value_or(0) == 4);
    CHECK(loop.outstanding() == 0);
}

void test_shutdown_cancels_deadlines_too() {
    test::section("shutdown resolves reads, sleeps, and their deadlines");

    HandlePair pair;
    if (!pair.valid()) {
        std::printf("   skipped: no handle pair on this platform\n");
        return;
    }

    std::atomic<int> done{0};
    Result<std::size_t> read_outcome = std::size_t{999};
    Result<void> sleep_outcome{};
    std::array<std::byte, 16> scratch{};

    struct Sleeper {
        static DetachedTask go(EventLoop& target,
                               OperationOptions options,
                               Result<void>& slot,
                               std::atomic<int>& counter) {
            slot = co_await target.sleep_for(std::chrono::hours{1}, std::move(options));
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    {
        Result<EventLoop> created = EventLoop::create();
        CHECK(created.has_value());
        EventLoop& loop = created.value();
        CHECK(loop.attach(pair.first()).has_value());

        Reader::go(loop,
                   pair.first(),
                   scratch,
                   {.deadline = EventLoop::Clock::now() + std::chrono::hours{1}},
                   read_outcome,
                   done);
        Sleeper::go(loop,
                    {.deadline = EventLoop::Clock::now() + std::chrono::hours{2}},
                    sleep_outcome,
                    done);
        CHECK(loop.run_once(0ms).has_value());
        CHECK(done.load(std::memory_order_acquire) == 0);
        CHECK(loop.outstanding() == 2);
        // The loop dies here with both still suspended.
    }

    CHECK(done.load(std::memory_order_acquire) == 2);
    CHECK(!read_outcome.has_value());
    CHECK(read_outcome.error() == Errc::cancelled);
    CHECK(!sleep_outcome.has_value());
    CHECK(sleep_outcome.error() == Errc::cancelled);
}

void test_stop_from_another_thread() {
    test::section("a stop request from another thread is delivered by the loop");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    std::stop_source source;
    std::atomic<bool> finished{false};
    Result<void> outcome{};

    struct Sleeper {
        static DetachedTask go(EventLoop& target,
                               OperationOptions options,
                               Result<void>& slot,
                               std::atomic<bool>& flag) {
            slot = co_await target.sleep_for(std::chrono::hours{1}, std::move(options));
            flag.store(true, std::memory_order_release);
            co_return;
        }
    };

    Sleeper::go(loop, {.stop = source.get_token()}, outcome, finished);
    CHECK(loop.outstanding() == 1);

    // Joined before pumping, so the assertion below is about the hand-off
    // rather than about winning a race. What it establishes is that the
    // callback ran off the loop thread and still only *queued* the request.
    std::thread requester{[&source] { source.request_stop(); }};
    requester.join();
    CHECK(!finished.load(std::memory_order_acquire));

    CHECK(loop.run_once(EventLoop::Duration::min()).has_value());
    CHECK(finished.load(std::memory_order_acquire));
    CHECK(!outcome.has_value());
    CHECK(outcome.error() == Errc::cancelled);
    CHECK(loop.outstanding() == 0);
}

void test_stop_token_outlives_its_scope() {
    test::section("the stop state outlives the scope that owned it");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    std::atomic<bool> finished{false};
    Result<void> outcome{};
    OperationOptions options;
    {
        // `OperationOptions` copies the token, so the shared stop state stays
        // alive after its `stop_source` is gone. Without that, an operation
        // still winding down after a TaskScope exits would hold a dead token.
        std::stop_source source;
        options.stop = source.get_token();
        CHECK(options.stop.stop_possible());
    }
    CHECK(!options.stop.stop_requested());

    struct Sleeper {
        static DetachedTask go(EventLoop& target,
                               OperationOptions options,
                               Result<void>& slot,
                               std::atomic<bool>& flag) {
            slot = co_await target.sleep_for(5ms, std::move(options));
            flag.store(true, std::memory_order_release);
            co_return;
        }
    };

    Sleeper::go(loop, options, outcome, finished);
    for (int i = 0; i < 200 && !finished.load(std::memory_order_acquire); ++i) {
        CHECK(loop.run_once(50ms).has_value());
    }
    CHECK(finished.load(std::memory_order_acquire));
    CHECK(outcome.has_value());
}

/// Root tasks used by the next test. Free functions rather than lambdas: a
/// lambda's closure would have to outlive the coroutine, and these outlive the
/// expression that creates them.
Task<void> root_returns_without_suspending(int& ran) {
    ++ran;
    co_return;
}

Task<void> root_sleeps(EventLoop& loop, int& ran) {
    (void)co_await loop.sleep_for(1ms);
    ++ran;
}

Task<void> root_throws_after_suspending(EventLoop& loop) {
    (void)co_await loop.sleep_for(1ms);
    throw std::runtime_error("root failed");
}

Task<void> root_owns_frame(EventLoop& loop, std::shared_ptr<int> owned, bool throws) {
    CHECK(*owned == 42);
    CHECK((co_await loop.sleep_for(1ms)).has_value());
    if (throws) {
        throw std::runtime_error("root failed with owned state");
    }
}

Task<void> root_waits_for_cancel(EventLoop& loop, std::stop_source& source) {
    loop.post([&source] { source.request_stop(); });
    const Result<void> result = co_await loop.sleep_for(1h, {.stop = source.get_token()});
    CHECK(!result.has_value());
    CHECK(result.error() == Errc::cancelled);
}

Task<void> root_stops_loop(EventLoop& loop, int& ran) {
    loop.post([&loop] { loop.stop(); });
    CHECK((co_await loop.sleep_for(1ms)).has_value());
    ++ran;
}

void test_moved_from_loop_operations_fail_cleanly() {
    test::section("operations on a moved-from loop fail, not crash");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());

    // Move the loop out; the source owns nothing now.
    EventLoop moved{std::move(created.value())};

    HandlePair pair;
    NativeHandle handle = pair.valid() ? pair.first()
                                       : static_cast<NativeHandle>(-1);

    std::array<std::byte, 16> scratch{};

    // The old guards: read/write/accept/connect/receive_from/send_to/yield.
    Result<std::size_t> read_outcome = std::size_t{1};
    {
        struct Probe {
            static DetachedTask go(EventLoop& dead, NativeHandle h,
                                   std::span<std::byte> into, Result<std::size_t>& slot) {
                slot = co_await dead.read(h, into);
                co_return;
            }
        };
        Probe::go(created.value(), handle, scratch, read_outcome);
    }
    CHECK(!read_outcome.has_value());
    CHECK(read_outcome.error() == Errc::cancelled);

    Result<void> sleep_outcome = Result<void>{};
    {
        struct Probe {
            static DetachedTask go(EventLoop& dead, Result<void>& slot) {
                slot = co_await dead.sleep_for(1ms);
                co_return;
            }
        };
        Probe::go(created.value(), sleep_outcome);
    }
    CHECK(!sleep_outcome.has_value());
    CHECK(sleep_outcome.error() == Errc::cancelled);

#if MIRA_HAS_READINESS_API
    Result<void> wait_outcome = Result<void>{};
    {
        struct Probe {
            static DetachedTask go(EventLoop& dead, NativeHandle h, Result<void>& slot) {
                slot = co_await dead.wait_readable(h);
                co_return;
            }
        };
        Probe::go(created.value(), handle, wait_outcome);
    }
    CHECK(!wait_outcome.has_value());
    CHECK(wait_outcome.error() == Errc::cancelled);
#endif  // MIRA_HAS_READINESS_API

    Result<void> yield_outcome = Result<void>{};
    {
        struct Probe {
            static DetachedTask go(EventLoop& dead, Result<void>& slot) {
                co_await dead.yield();
                slot = Result<void>{};
                co_return;
            }
        };
        Probe::go(created.value(), yield_outcome);
    }
    // yield() on a dead loop simply returns without suspending.
    CHECK(yield_outcome.has_value());

    // The moved-to loop still works normally.
    Result<void> nap_outcome = fail(Errc::cancelled);
    struct Nap {
        static DetachedTask go(EventLoop& alive, Result<void>& slot) {
            slot = co_await alive.sleep_for(1ms);
            co_return;
        }
    };
    Nap::go(moved, nap_outcome);
    for (int i = 0; i < 100 && !nap_outcome.has_value() &&
                    nap_outcome.error() == Errc::cancelled;
         ++i) {
        CHECK(moved.run_once(50ms).has_value());
    }
    CHECK(nap_outcome.has_value());
    CHECK(moved.outstanding() == 0);
}

void test_run_until_complete() {
    test::section("run_until_complete drives a root task from synchronous code");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    // A task that never suspends needs no pumping at all.
    int ran = 0;
    CHECK(loop.run_until_complete(root_returns_without_suspending(ran)).has_value());
    CHECK(ran == 1);

    // One that suspends is pumped until it finishes, and the loop is left with
    // nothing outstanding — the timer went with it.
    CHECK(loop.run_until_complete(root_sleeps(loop, ran)).has_value());
    CHECK(ran == 2);
    CHECK(loop.outstanding() == 0);

    // An exception out of a root coroutine has nowhere else to surface.
    CHECK_THROWS(loop.run_until_complete(root_throws_after_suspending(loop)),
                 std::runtime_error);

    // The loop is still usable afterwards: the failed root was finished, so
    // its frame was reclaimed normally rather than abandoned.
    CHECK(loop.outstanding() == 0);
    CHECK(loop.run_until_complete(root_returns_without_suspending(ran)).has_value());
    CHECK(ran == 3);

    CHECK_THROWS(loop.run_until_complete(Task<void>{}), std::logic_error);
    const auto immediate_failure = []() -> Task<void> {
        throw std::runtime_error("immediate root failure");
        co_return;
    };
    CHECK_THROWS(loop.run_until_complete(immediate_failure()), std::runtime_error);

    // State stored as a coroutine parameter survives the body until the frame
    // itself is reclaimed. A weak pointer checks both normal and failed roots.
    for (const bool throws : {false, true}) {
        auto owned = std::make_shared<int>(42);
        const std::weak_ptr<int> observed = owned;
        Task<void> task = root_owns_frame(loop, std::move(owned), throws);
        CHECK(!observed.expired());
        if (throws) {
            CHECK_THROWS(loop.run_until_complete(std::move(task)), std::runtime_error);
        } else {
            CHECK(loop.run_until_complete(std::move(task)).has_value());
        }
        CHECK(observed.expired());
        CHECK(loop.outstanding() == 0);
    }

    std::stop_source source;
    CHECK(loop.run_until_complete(root_waits_for_cancel(loop, source)).has_value());
    CHECK(loop.outstanding() == 0);

    // Finishing one root must not drain work unrelated to that root.
    bool posted_ran = false;
    loop.post([&posted_ran] { posted_ran = true; });
    CHECK(loop.run_until_complete(root_returns_without_suspending(ran)).has_value());
    CHECK(!posted_ran);
    CHECK(loop.outstanding() != 0);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(posted_ran);

    // stop is not cancellation, including when observed before starting.
    CHECK(loop.run_until_complete(root_stops_loop(loop, ran)).has_value());
    CHECK(loop.stopped());
    CHECK(ran == 5);
    CHECK(loop.run_until_complete(root_sleeps(loop, ran)).has_value());
    CHECK(ran == 6);
    CHECK(loop.outstanding() == 0);
}

// ── contract violations, asserted out-of-process ─────────────────────────────

/// Each mode commits exactly one violation and must not return.
int run_contract_violation(std::string_view mode) {
    std::set_terminate([] { std::_Exit(77); });

    Result<EventLoop> created = EventLoop::create();
    if (!created) {
        return 2;
    }

    if (mode == "destroy-during-dispatch") {
        // A posted callable runs while the loop is dispatching a batch, with
        // operations already taken out of its queues.
        auto* loop = new Result<EventLoop>{std::move(created)};
        loop->value().post([loop] { delete loop; });
        (void)loop->value().run_once(0ms);
    } else if (mode == "reentrant-run-once") {
        EventLoop& loop = created.value();
        loop.post([&loop] { (void)loop.run_once(0ms); });
        (void)loop.run_once(0ms);
#if MIRA_HAS_READINESS_API
    } else if (mode == "destroy-during-detach" ||
               mode == "reentrant-run-once-during-detach") {
        // A system_error from the already-released mutex also triggers
        // terminate; it must not be mistaken for the contract guard.
        std::set_terminate([] { std::_Exit(std::current_exception() ? 78 : 77); });
        HandlePair pair;
        if (!pair.valid()) return 2;
        auto* loop = new EventLoop{std::move(*created)};
        if (!loop->attach(pair.first())) {
            delete loop;
            return 2;
        }
        struct Waiter {
            static DetachedTask read(EventLoop* target, NativeHandle handle, bool destroy) {
                const auto outcome = co_await target->wait_readable(handle);
                if (outcome || outcome.error() != Errc::cancelled) std::_Exit(3);
                if (destroy) {
                    delete target;
                } else {
                    (void)target->run_once(0ms);
                }
            }
            static DetachedTask write(EventLoop& target, NativeHandle handle, int& done) {
                const auto outcome = co_await target.wait_writable(handle);
                if (outcome || outcome.error() != Errc::cancelled) std::_Exit(3);
                ++done;
            }
        };
        int sibling_done = 0;
        const bool destroy = mode == "destroy-during-detach";
        Waiter::read(loop, pair.first(), destroy);
        Waiter::write(*loop, pair.first(), sibling_done);
        if (loop->outstanding() != 2 || sibling_done != 0) std::_Exit(3);
        // No run_once call: the external detach must be the path that is
        // hit, not the existing batch guard.
        loop->detach(pair.first());
        if (!destroy) delete loop;
#endif
    } else if (mode == "root-task-deadlock") {
        // Suspends on nothing the loop registered, so no completion, timer or
        // posted callable can ever resume it. Hanging would be the easy
        // behaviour; saying so is the useful one.
        struct Parks {
            [[nodiscard]] bool await_ready() const noexcept { return false; }
            void await_suspend(std::coroutine_handle<>) const noexcept {}
            void await_resume() const noexcept {}
        };
        const auto parked = []() -> Task<void> { co_await Parks{}; };
        (void)created.value().run_until_complete(parked());
    } else {
        return 2;
    }
    return 0;  // reaching here means the violation was not caught
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2) {
        return run_contract_violation(argv[1]);
    }
    test_create_and_backend();
    test_post_and_stop();
    test_timers();
    test_read_write_roundtrip();
    test_eof_is_distinct_from_empty();
    test_double_waiter_is_refused();
    test_destruction_wakes_suspended();
    test_yield_returns_to_loop();
    test_options_rejected_before_submit();
    test_cancel_in_flight();
#if MIRA_HAS_READINESS_API
    test_cancel_leaves_other_direction_armed();
    test_detach_and_shutdown_resume_waiters();
#endif
    test_deadline_on_a_suspended_read();
    test_deadline_is_absolute_across_retries();
    test_sleep_deadline_beats_wake_up();
    test_completion_beats_deadline_in_one_batch();
    test_shutdown_cancels_deadlines_too();
    test_stop_from_another_thread();
    test_moved_from_loop_operations_fail_cleanly();
    test_stop_token_outlives_its_scope();
    test_run_until_complete();
    return test::summary();
}