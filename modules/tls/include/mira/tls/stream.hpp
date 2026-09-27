#pragma once

#include "mira/core/stream.hpp"
#include "mira/tls/engine.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <utility>

namespace Mira::tls {

/// Generic asynchronous TLS wrapper; it neither owns nor closes the underlying stream.
/// The Context may be destroyed after create; the underlying stream, the Stream, and
/// the storage behind any passed-in span must survive until the returned lazy Task
/// completes or is safely destroyed. The Stream must not be moved or destroyed while
/// a Task is outstanding. Only one operation at a time (reads and writes included) is
/// allowed per instance; overlapping operations return operation_in_progress. After a
/// started operation is cancelled or throws, or after a fatal error, the instance
/// cannot be reused; the destructor does not send close_notify. The underlying stream
/// must not be touched directly, bypassing this wrapper. Driving across threads must
/// also respect the underlying stream's threading constraints.
///
/// The underlying stream must be a `BoundedStream`. A single TLS operation performs
/// an unbounded number of reads and writes on the underlying stream, and only the
/// layer that is genuinely waiting can stop waiting; if the underlying stream cannot
/// carry `OperationOptions`, this wrapper cannot honour cancellation and deadlines,
/// and handshake degenerates into a wait that can hang at any moment.
///
/// `options` is forwarded verbatim to **every** underlying read and write. That is
/// exactly what an absolute deadline means: no layer needs to subtract elapsed time,
/// and a single `{.deadline = T}` naturally says "the whole handshake / read / write
/// must finish before T". With a duration instead, every layer would have to do its
/// own subtraction, and every layer would get it wrong.
template<BoundedStream Underlying>
class Stream {
public:
    [[nodiscard]] static Result<Stream>
    create(Underlying& underlying, const Context& context, std::string_view peer_name = {}) {
        auto engine = Engine::create(context, peer_name);
        if (!engine) return fail(engine.error());
        return Stream(std::make_unique<State>(underlying, std::move(*engine)));
    }

    Stream(Stream&&) noexcept = default;
    Stream& operator=(Stream&&) noexcept = default;
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    /// The assert is the contract: an operation still in flight at destruction time
    /// means coroutine frames still hold borrows of the State, and letting them run
    /// on is a use-after-free. Rather than silent UB, diagnose and terminate on the
    /// spot — the same deal as the Task destruction contract (std::thread's join
    /// contract is no different).
    ~Stream() {
        if (state_ && state_->active.test(std::memory_order_acquire)) {
            std::fprintf(stderr,
                         "Mira::tls::Stream destroyed with an operation still in flight; "
                         "await (or destroy) the pending Task before destroying the Stream.\n");
            std::terminate();
        }
    }

    [[nodiscard]] Task<Result<void>> handshake(OperationOptions options = {}) {
        return run_void(state_.get(), Operation::handshake, std::move(options));
    }

    [[nodiscard]] Task<Result<std::size_t>> read_some(std::span<std::byte> destination,
                                                      OperationOptions options = {}) {
        return run(state_.get(), Operation::read, destination, {}, std::move(options));
    }

    [[nodiscard]] Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                                       OperationOptions options = {}) {
        return run(state_.get(), Operation::write, {}, source, std::move(options));
    }

    /// Sends and flushes our close_notify; it does not wait for the peer's
    /// notification and does not imply that bidirectional close is complete.
    /// After success only another shutdown is allowed, not further application
    /// reads or writes; the underlying stream is closed by the caller.
    [[nodiscard]] Task<Result<void>> shutdown(OperationOptions options = {}) {
        return run_void(state_.get(), Operation::shutdown, std::move(options));
    }

    /// Call only while no operation is in flight; the returned view is invalidated
    /// once this Stream is destroyed.
    [[nodiscard]] std::string_view negotiated_protocol() const noexcept {
        return state_ ? state_->engine.negotiated_protocol() : std::string_view{};
    }

private:
    enum class Operation { handshake, read, write, shutdown };
    struct State {
        Underlying* underlying;
        Engine engine;
        std::atomic_flag active = ATOMIC_FLAG_INIT;
        std::array<std::byte, 16 * 1024> buffer{};
        State(Underlying& stream, Engine value) : underlying(&stream), engine(std::move(value)) {}
    };

    struct OperationGuard {
        State& state;
        bool acquired;
        bool completed = false;
        explicit OperationGuard(State& value)
            : state(value), acquired(!state.active.test_and_set(std::memory_order_acquire)) {}
        ~OperationGuard() {
            if (acquired) {
                // Cancellation may arrive after only part of the ciphertext was
                // written; the SSL object can no longer be driven.
                if (!completed) state.engine.invalidate();
                state.active.clear(std::memory_order_release);
            }
        }
    };

    explicit Stream(std::unique_ptr<State> state) : state_(std::move(state)) {}

    static Task<Result<void>> flush(State& state, const OperationOptions& options) {
        for (;;) {
            auto drained = state.engine.drain(state.buffer);
            if (!drained) co_return fail(drained.error());
            if (*drained == 0) co_return Result<void>{};
            std::size_t offset = 0;
            while (offset < *drained) {
                auto written = co_await state.underlying->write_some(
                    std::span<const std::byte>(state.buffer).subspan(offset, *drained - offset),
                    options);
                if (!written || *written == 0 || *written > *drained - offset) {
                    state.engine.invalidate();
                    if (!written) co_return fail(written.error());
                    co_return fail(make_error_code(Errc::protocol_error));
                }
                offset += *written;
            }
        }
    }

    static Task<Result<void>> receive(State& state, const OperationOptions& options) {
        const auto capacity = std::min(state.buffer.size(), state.engine.input_capacity());
        if (capacity == 0) {
            state.engine.invalidate();
            co_return fail(make_error_code(Errc::protocol_error));
        }
        auto received = co_await state.underlying->read_some(
            std::span<std::byte>(state.buffer).first(capacity), options);
        if (!received || *received == 0 || *received > capacity) {
            state.engine.invalidate();
            if ((!received && received.error() == Mira::Errc::eof) ||
                (received && *received == 0))
                co_return fail(make_error_code(Errc::truncated));
            if (!received) co_return fail(received.error());
            co_return fail(make_error_code(Errc::protocol_error));
        }
        auto fed = state.engine.feed(std::span<const std::byte>(state.buffer).first(*received));
        if (!fed || *fed != *received) {
            state.engine.invalidate();
            if (!fed) co_return fail(fed.error());
            co_return fail(make_error_code(Errc::protocol_error));
        }
        co_return Result<void>{};
    }

    static Task<Result<std::size_t>> drive(State& state,
                                           Operation operation,
                                           std::span<std::byte> destination,
                                           std::span<const std::byte> source,
                                           const OperationOptions& options) {
        for (;;) {
            Result<Engine::Step> step = fail(make_error_code(Errc::invalid_state));
            switch (operation) {
            case Operation::handshake:
                step = state.engine.handshake();
                break;
            case Operation::read:
                step = state.engine.read(destination);
                break;
            case Operation::write:
                step = state.engine.write(source);
                break;
            case Operation::shutdown:
                step = state.engine.shutdown();
                break;
            }
            if (!step) {
                const auto error = step.error();
                if (error != make_error_code(Errc::invalid_state)) {
                    // After a fatal error only the already-generated alert is sent;
                    // the SSL I/O must not be driven again. The alert is a closing
                    // action, still bound by the same deadline, with no extra budget.
                    try {
                        (void)co_await flush(state, options);
                    } catch (...) {
                        // A failure to send the alert must not mask the original
                        // TLS error.
                    }
                }
                co_return fail(error);
            }
            auto flushed = co_await flush(state, options);
            if (!flushed) co_return fail(flushed.error());
            switch (step->status) {
            case Engine::Status::complete:
                co_return step->transferred;
            case Engine::Status::eof:
                co_return fail(Mira::Errc::eof);
            case Engine::Status::want_output:
                break;
            case Engine::Status::want_input:
                auto received = co_await receive(state, options);
                if (!received) co_return fail(received.error());
                break;
            }
        }
    }

    static Task<Result<std::size_t>> run(State* state,
                                         Operation operation,
                                         std::span<std::byte> destination,
                                         std::span<const std::byte> source,
                                         OperationOptions options) {
        if (!state) co_return fail(make_error_code(Errc::invalid_state));
        OperationGuard guard(*state);
        if (!guard.acquired) co_return fail(make_error_code(Errc::operation_in_progress));
        auto result = co_await drive(*state, operation, destination, source, options);
        guard.completed = true;
        co_return result;
    }

    static Task<Result<void>>
    run_void(State* state, Operation operation, OperationOptions options) {
        auto result = co_await run(state, operation, {}, {}, std::move(options));
        if (!result) co_return fail(result.error());
        co_return Result<void>{};
    }

    std::unique_ptr<State> state_;
};

}  // namespace Mira::tls
