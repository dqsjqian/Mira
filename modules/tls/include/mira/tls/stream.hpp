#pragma once

#include "mira/core/event_loop.hpp"
#include "mira/core/stream.hpp"
#include "mira/tls/engine.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <coroutine>
#include <cstdio>
#include <exception>
#include <memory>
#include <optional>
#include <stop_token>
#include <thread>
#include <utility>

namespace Mira::tls {

/// Borrows, but never closes, the underlying BoundedStream and EventLoop.
/// Creation, operations, close(), destruction and transport completions belong
/// to the same loop thread. Only stop-token requests may originate elsewhere.
/// The transport must support one concurrent read and write and honor stop
/// tokens, delivering their completions on this thread.
///
/// Handshake and shutdown are exclusive. After handshake, one read_some and
/// one write_some may overlap; same-direction overlap is rejected. Cancellation,
/// timeout, transport failure or a fatal TLS error permanently invalidates the
/// session and stops its companion operation. The initiating request retains
/// its original error; its companion reports invalid_state. Pre-cancelled or
/// already-expired requests are rejected without affecting existing operations.
/// Each deadline uses a cancellable loop timer, which is joined before returning.
/// Wire I/O has no deadline and is never cancelled merely to change a deadline:
/// cancellation may discard bytes already transferred by the kernel.
///
/// Ciphertext is bounded by a BIO pair and two 16 KiB buffers. Output is sent in
/// generation order, and an operation only waits for output it generated. There
/// are no idle background reads. Await every started Task before moving or
/// destroying the Stream; otherwise the process terminates. The loop, transport
/// and user spans must outlive their operations. Do not use the transport behind
/// this wrapper. Context may be destroyed immediately after create().
template<BoundedStream Underlying>
class Stream {
public:
    // A conservative reservation for the two BIOs and wire input/output buffers.
    // OpenSSL internals, caller spans and allocator overhead are not included.
    static constexpr std::size_t reserved_buffer_bytes = Engine::reserved_buffer_bytes + 32 * 1024;
    [[nodiscard]] static Result<Stream>
    create(EventLoop& loop, Underlying& underlying, const Context& context,
           std::string_view peer_name = {}, std::optional<ResourceBudget> budget = {}) {
        ResourceBudget::Reservation reservation;
        if (budget) {
            auto acquired = budget->try_acquire(32 * 1024);
            if (!acquired) return fail(acquired.error());
            reservation = std::move(*acquired);
        }
        auto engine = Engine::create(context, peer_name, std::move(budget));
        if (!engine) return fail(engine.error());
        return Stream(std::make_shared<State>(loop, underlying, std::move(*engine), std::move(reservation)));
    }

    Stream(Stream&& other) noexcept {
        require_idle(other.state_);
        state_ = std::move(other.state_);
    }
    Stream& operator=(Stream&& other) noexcept {
        if (this != &other) {
            require_idle(state_);
            require_idle(other.state_);
            state_ = std::move(other.state_);
        }
        return *this;
    }
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    ~Stream() { require_idle(state_); }

    [[nodiscard]] Task<Result<void>> handshake(OperationOptions options = {}) {
        return run_void(state_, Operation::handshake, std::move(options));
    }
    [[nodiscard]] Task<Result<std::size_t>> read_some(std::span<std::byte> destination,
                                                     OperationOptions options = {}) {
        return run(state_, Operation::read, destination, {}, std::move(options));
    }
    [[nodiscard]] Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                                      OperationOptions options = {}) {
        return run(state_, Operation::write, {}, source, std::move(options));
    }

    /// Flush our close_notify without waiting for peer acknowledgement.
    /// Afterwards only repeated shutdown is allowed.
    [[nodiscard]] Task<Result<void>> shutdown(OperationOptions options = {}) {
        return run_void(state_, Operation::shutdown, std::move(options));
    }

    /// Permanently stop this wrapper, without closing the borrowed transport.
    /// Pending tasks must still be awaited before destruction.
    void close() noexcept {
        auto state = state_;
        if (!state) return;
        if (state->thread != std::this_thread::get_id()) std::terminate();
        const bool nested = std::exchange(state->pumping, true);
        fail_session(*state, nullptr, make_error_code(Errc::invalid_state));
        state->pumping = nested;
        pump(std::move(state));
    }

    /// Call on the loop thread while idle; the view borrows this Stream.
    [[nodiscard]] std::string_view negotiated_protocol() const noexcept {
        return state_ ? state_->engine.negotiated_protocol() : std::string_view{};
    }

private:
    enum class Operation { handshake, read, write, shutdown };
    enum class Phase { ready, input, output, finished };

    struct Request {
        Operation operation;
        std::span<std::byte> destination;
        std::span<const std::byte> source;
        OperationOptions options;
        std::coroutine_handle<> continuation{};
        Phase phase = Phase::ready;
        std::size_t id = 0;
        std::size_t epoch = 0;
        std::size_t target = 0;
        Result<std::size_t> result{std::size_t{0}};
        std::exception_ptr exception;
        std::stop_source timer_stop;
        bool timer_running = false;
        bool retiring = false;
        bool done = false;

        Request(Operation kind, std::span<std::byte> destination_bytes,
                std::span<const std::byte> source_bytes, OperationOptions settings)
            : operation(kind), destination(destination_bytes), source(source_bytes),
              options(std::move(settings)) {}
    };

    struct WireOperation {
        std::array<std::byte, 16 * 1024> buffer{};
        std::stop_source stop;
        std::size_t size = 0;
        std::size_t offset = 0;
        bool running = false;
    };

    struct State {
        ResourceBudget::Reservation reservation;
        EventLoop* loop;
        Underlying* underlying;
        Engine engine;
        const std::thread::id thread = std::this_thread::get_id();
        std::array<Request*, 2> requests{};
        std::atomic<unsigned> active{0};
        std::stop_source cancelled;
        WireOperation input;
        WireOperation output;
        std::size_t next_id = 0;
        std::size_t received_epoch = 0;
        std::size_t drained_epoch = 0;
        std::size_t produced = 0;
        std::size_t sent = 0;
        bool pumping = false;
        bool failed = false;
        bool alert = false;
        Request* retry = nullptr;

        State(EventLoop& executor, Underlying& stream, Engine value, ResourceBudget::Reservation charge)
            : reservation(std::move(charge)), loop(&executor), underlying(&stream), engine(std::move(value)) {}
    };

    struct ForwardStop {
        std::stop_source source;
        void operator()() const noexcept {
            auto retained = source;
            retained.request_stop();
        }
    };

    struct PostStop {
        EventLoop* loop;
        std::weak_ptr<State> state;
        std::size_t id;
        void operator()() const noexcept {
            // Never touch a Request or SSL on the cancelling thread. The ID
            // prevents a queued callback from cancelling a later request.
            loop->post([weak = state, request_id = id] {
                auto retained = weak.lock();
                if (!retained) return;
                const bool nested = std::exchange(retained->pumping, true);
                for (auto* request : retained->requests) {
                    if (request && request->id == request_id && !request->retiring) {
                        fail_session(*retained, request, Mira::make_error_code(Mira::Errc::cancelled));
                        break;
                    }
                }
                retained->pumping = nested;
                pump(std::move(retained));
            });
        }
    };

    // Drivers own their frames and retain State until they return. The awaited
    // Task is destroyed before notifying requests. A notification may destroy
    // the wrapper or the completed request, but never a running driver frame.
    struct DriverTask {
        struct promise_type {
            DriverTask get_return_object() const noexcept { return {}; }
            std::suspend_never initial_suspend() const noexcept { return {}; }
            std::suspend_never final_suspend() const noexcept { return {}; }
            void return_void() const noexcept {}
            void unhandled_exception() const noexcept { std::terminate(); }
        };
    };

    explicit Stream(std::shared_ptr<State> state) : state_(std::move(state)) {}

    static void require_idle(const std::shared_ptr<State>& state) noexcept {
        if (state && state->active.load(std::memory_order_acquire) != 0) {
            std::fprintf(stderr, "Mira::tls::Stream: moving or destroying an active stream.\n");
            std::terminate();
        }
    }

    static void cancel_wire(WireOperation& wire) noexcept {
        auto retained = wire.stop;
        retained.request_stop();
    }

    static void fail_session(State& state, Request* origin, Error error,
                             std::exception_ptr exception = {}, bool send_alert = false) noexcept {
        if (!state.failed) {
            state.failed = true;
            state.engine.invalidate();
            state.retry = nullptr;
            state.alert = send_alert;
            for (auto* request : state.requests) {
                if (!request || request->retiring) continue;
                request->phase = Phase::finished;
                request->target = 0;
                request->result = fail(request == origin ? error : make_error_code(Errc::invalid_state));
                if (request == origin) request->exception = exception;
            }
        } else if (!send_alert) {
            // A transport failure, close, timeout or cancellation during alert
            // flushing stops all further sends, without replacing the TLS error.
            state.alert = false;
        }
        cancel_wire(state.input);
        if (!state.alert) {
            auto retained = state.cancelled;
            retained.request_stop();
            cancel_wire(state.output);
        }
    }

    static void fail_wire(State& state, Error error, std::exception_ptr exception = {},
                          Request* preferred = nullptr) noexcept {
        Request* origin = preferred;
        for (auto* request : state.requests) {
            if (!request || request->retiring) continue;
            if (!origin) origin = request;
            if (request->options.stop.stop_requested()) {
                origin = request;
                error = Mira::make_error_code(Mira::Errc::cancelled);
                break;
            }
        }
        fail_session(state, origin, error, exception);
    }

    static DriverTask watch_deadline(std::shared_ptr<State> state, Request* request) {
        Result<void> result;
        std::exception_ptr exception;
        try {
            result = co_await state->loop->sleep_until(*request->options.deadline,
                                                       {.stop = request->timer_stop.get_token()});
        } catch (...) {
            exception = std::current_exception();
        }
        if (state->thread != std::this_thread::get_id()) std::terminate();
        const bool nested = std::exchange(state->pumping, true);
        request->timer_running = false;
        if (!request->retiring) {
            const auto error = result ? Mira::make_error_code(Mira::Errc::timed_out)
                                      : result.error();
            fail_session(*state, request, error, exception);
        }
        state->pumping = nested;
        pump(std::move(state));
        // request may have been destroyed by pump().
    }

    static DriverTask transfer(std::shared_ptr<State> state, bool reading) {
        Result<std::size_t> result = fail(make_error_code(Errc::invalid_state));
        std::exception_ptr exception;
        auto& wire = reading ? state->input : state->output;
        try {
            std::stop_callback forward(state->cancelled.get_token(), ForwardStop{wire.stop});
            const OperationOptions options{.stop = wire.stop.get_token()};
            if (reading) {
                result = co_await state->underlying->read_some(
                    std::span<std::byte>(wire.buffer).first(wire.size), options);
            } else {
                result = co_await state->underlying->write_some(
                    std::span<const std::byte>(wire.buffer).subspan(wire.offset, wire.size - wire.offset),
                    options);
            }
        } catch (...) {
            exception = std::current_exception();
        }
        if (state->thread != std::this_thread::get_id()) std::terminate();
        wire.running = false;
        const bool nested = std::exchange(state->pumping, true);
        auto* preferred = state->requests[reading ? 0U : 1U];
        if (exception) {
            fail_wire(*state, make_error_code(Errc::invalid_state), exception, preferred);
        } else if (!result) {
            const auto error = reading && result.error() == Mira::Errc::eof
                                   ? make_error_code(Errc::truncated) : result.error();
            fail_wire(*state, error, {}, preferred);
        } else if (*result == 0 || *result > wire.size - (reading ? 0 : wire.offset)) {
            fail_wire(*state, make_error_code(reading && *result == 0
                                                  ? Errc::truncated : Errc::protocol_error), {}, preferred);
        } else if (reading) {
            if (!state->failed) {
                const auto fed = state->engine.feed(
                    std::span<const std::byte>(wire.buffer).first(*result));
                if (!fed || *fed != *result) {
                    fail_wire(*state, fed ? make_error_code(Errc::protocol_error) : fed.error());
                } else {
                    ++state->received_epoch;
                }
            }
        } else {
            wire.offset += *result;
            state->sent += *result;
        }
        state->pumping = nested;
        pump(std::move(state));
    }

    static void start_transfer(const std::shared_ptr<State>& state, bool reading) noexcept {
        auto& wire = reading ? state->input : state->output;
        wire.running = true;
        try {
            transfer(state, reading);
        } catch (...) {
            wire.running = false;
            fail_wire(*state, make_error_code(Errc::invalid_state), std::current_exception());
        }
    }

    static bool step(State& state, Request& request) noexcept {
        if (request.phase == Phase::finished) return false;
        if (state.retry && state.retry != &request) return false;
        if (request.phase == Phase::input && request.epoch == state.received_epoch) return false;
        if (request.phase == Phase::output && request.epoch == state.drained_epoch) return false;
        const auto before = state.engine.output_pending();
        Result<Engine::Step> result = fail(make_error_code(Errc::invalid_state));
        switch (request.operation) {
        case Operation::handshake: result = state.engine.handshake(); break;
        case Operation::read: result = state.engine.read(request.destination); break;
        case Operation::write: result = state.engine.write(request.source); break;
        case Operation::shutdown: result = state.engine.shutdown(); break;
        }
        const auto produced = state.engine.output_pending() - before;
        state.produced += produced;
        if (produced != 0) request.target = state.produced;
        state.retry = nullptr;
        if (!result) {
            if (result.error() == Errc::invalid_state) {
                request.result = fail(result.error());
                request.phase = Phase::finished;
            } else {
                fail_session(state, &request, result.error(), {},
                             request.operation == Operation::handshake);
            }
            return true;
        }
        switch (result->status) {
        case Engine::Status::complete:
            request.phase = Phase::finished;
            request.result = result->transferred;
            break;
        case Engine::Status::eof:
            request.phase = Phase::finished;
            request.result = fail(Mira::Errc::eof);
            break;
        case Engine::Status::want_input:
            request.phase = Phase::input;
            request.epoch = state.received_epoch;
            if (request.operation != Operation::read) state.retry = &request;
            break;
        case Engine::Status::want_output:
            request.phase = Phase::output;
            request.epoch = state.drained_epoch;
            state.retry = &request;
            break;
        }
        return true;
    }

    static void pump(std::shared_ptr<State> state, Request* initiating = nullptr) noexcept {
        if (state->pumping) return;
        state->pumping = true;
        for (;;) {
            bool progress = false;
            if (!state->failed || state->alert) {
                for (auto* request : state->requests) {
                    if (!request || request->retiring) continue;
                    if (request->options.stop.stop_requested()) {
                        fail_session(*state, request, Mira::make_error_code(Mira::Errc::cancelled));
                        break;
                    }
                    if (request->options.deadline && *request->options.deadline <= Clock::now()) {
                        fail_session(*state, request, Mira::make_error_code(Mira::Errc::timed_out));
                        break;
                    }
                }
                for (auto* request : state->requests) {
                    if (state->failed) break;
                    if (request) progress = step(*state, *request) || progress;
                }
            }

            auto& output = state->output;
            if ((!state->failed || state->alert) && !output.running) {
                if (output.offset == output.size) {
                    const auto drained = state->engine.drain(output.buffer);
                    if (!drained) {
                        fail_wire(*state, drained.error());
                    } else {
                        output.offset = 0;
                        output.size = *drained;
                        if (*drained != 0) {
                            ++state->drained_epoch;
                            progress = true;
                        }
                    }
                }
                if (output.offset != output.size && (!state->failed || state->alert)) {
                    start_transfer(state, false);
                    progress = true;
                } else if (state->alert) {
                    state->alert = false;
                    progress = true;
                }
            }

            bool needs_input = false;
            bool has_reader = false;
            for (const auto* request : state->requests) {
                has_reader = has_reader || (request && request->phase == Phase::input);
                needs_input = needs_input || (request && request->phase == Phase::input &&
                    request->epoch == state->received_epoch &&
                    (!state->retry || state->retry == request));
            }
            if (!state->failed && needs_input && !state->input.running) {
                state->input.size = std::min(state->input.buffer.size(), state->engine.input_capacity());
                if (state->input.size == 0) {
                    fail_wire(*state, make_error_code(Errc::protocol_error));
                } else {
                    start_transfer(state, true);
                }
                progress = true;
            }
            if (!state->failed && !has_reader && state->input.running)
                fail_wire(*state, make_error_code(Errc::protocol_error));

            unsigned ready = 0;
            unsigned active = 0;
            for (const auto* request : state->requests) {
                if (!request) continue;
                ++active;
                if (request->phase == Phase::finished && request->target <= state->sent) ++ready;
            }
            const bool settled = !state->input.running && !state->output.running && !state->alert;
            if (ready != 0 && (ready != active || settled)) {
                for (auto*& slot : state->requests) {
                    auto* request = slot;
                    if (!request || request->phase != Phase::finished || request->target > state->sent)
                        continue;
                    if (!request->retiring) {
                        request->retiring = true;
                        progress = true;
                        auto retained = request->timer_stop;
                        retained.request_stop();
                    }
                    if (request->timer_running) continue;
                    slot = nullptr;
                    request->done = true;
                    state->active.fetch_sub(1, std::memory_order_release);
                    const auto continuation = request->continuation;
                    progress = true;
                    if (request != initiating) continuation.resume();
                    // Resumption may add work or destroy Request and Stream.
                    // Only the independently retained State is used afterwards.
                    break;
                }
            }
            if (!progress) break;
        }
        state->pumping = false;
    }

    struct AwaitRequest {
        const std::shared_ptr<State>& state;
        Request& request;
        std::optional<std::stop_callback<PostStop>>& forward;
        bool await_ready() const noexcept { return false; }
        bool await_suspend(std::coroutine_handle<> continuation) const noexcept {
            request.continuation = continuation;
            request.id = ++state->next_id;
            const auto index = request.operation == Operation::write ? 1U : 0U;
            const bool nested = std::exchange(state->pumping, true);
            state->requests[index] = &request;
            state->active.fetch_add(1, std::memory_order_release);
            // An already-stopped token invokes its callback during construction.
            // Finish registration before allowing any request to resume.
            forward.emplace(request.options.stop, PostStop{state->loop, state, request.id});
            if (request.options.deadline) {
                request.timer_running = true;
                try {
                    watch_deadline(state, &request);
                } catch (...) {
                    request.timer_running = false;
                    fail_session(*state, &request, make_error_code(Errc::invalid_state),
                                 std::current_exception());
                }
            }
            state->pumping = nested;
            pump(state, &request);
            return !request.done;
        }
        void await_resume() const noexcept {}
    };

    static Task<Result<std::size_t>> run(std::shared_ptr<State> state, Operation operation,
                                        std::span<std::byte> destination,
                                        std::span<const std::byte> source,
                                        OperationOptions options) {
        if (!state || state->thread != std::this_thread::get_id())
            co_return fail(make_error_code(Errc::invalid_state));
        if (options.stop.stop_requested()) co_return fail(Mira::Errc::cancelled);
        if (options.deadline && *options.deadline <= Clock::now()) co_return fail(Mira::Errc::timed_out);
        const bool exclusive = operation == Operation::handshake || operation == Operation::shutdown;
        const auto index = operation == Operation::write ? 1U : 0U;
        const auto* reader = state->requests[0];
        if (state->requests[index] || (exclusive && state->requests[1]) ||
            (reader && reader->operation != Operation::read))
            co_return fail(make_error_code(Errc::operation_in_progress));
        if (state->failed) co_return fail(make_error_code(Errc::invalid_state));
        Request request{operation, destination, source, std::move(options)};
        std::optional<std::stop_callback<PostStop>> forward;
        co_await AwaitRequest{state, request, forward};
        if (request.exception) std::rethrow_exception(request.exception);
        co_return request.result;
    }

    static Task<Result<void>> run_void(std::shared_ptr<State> state, Operation operation,
                                       OperationOptions options) {
        auto result = co_await run(std::move(state), operation, {}, {}, std::move(options));
        if (!result) co_return fail(result.error());
        co_return Result<void>{};
    }

    std::shared_ptr<State> state_;
};

}  // namespace Mira::tls
