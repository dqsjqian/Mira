#pragma once

#include "mira/core/resource_budget.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/transport/tcp.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <stop_token>

namespace Mira::transport::tcp {

struct ServeOptions {
    std::size_t max_connections = 256;
    /// Stop accepting on cancellation or expiry. Handlers receive a separate
    /// stop token, without this admission deadline.
    OperationOptions io{};
    /// Drain existing handlers for this long after admission stops, then ask
    /// them to stop and join. Zero preserves immediate cooperative cancellation.
    /// A positive grace period requires the overload taking an EventLoop.
    Clock::duration grace_period = Clock::duration::zero();
    /// Shared connection slots across listeners. Does not charge payload bytes.
    std::optional<ResourceBudget> admission_budget{};
    /// Optional absolute deadline for handlers, independent of admission/grace.
    std::optional<Clock::time_point> handler_deadline{};
};
struct ServeStats {
    std::size_t accepted = 0;
    std::size_t rejected = 0;
    /// All admitted handlers that finished, including exceptions/cancellations.
    std::size_t completed = 0;
    std::size_t failed = 0;
    std::size_t peak_active = 0;
    std::size_t cancelled = 0;
};

namespace detail {
inline void serve_increment(std::size_t& counter) noexcept {
    if (counter != std::numeric_limits<std::size_t>::max()) ++counter;
}

struct ServeState {
    ServeStats stats;
    std::stop_source admission_stop;
    std::stop_source handler_stop;
    Error error;
    std::exception_ptr exception;

    void cancel_handlers() noexcept {
        auto source = handler_stop;
        source.request_stop();
    }
    void record_exception(std::exception_ptr value) noexcept {
        if (!error && !exception) exception = std::move(value);
        auto admission = admission_stop;
        auto handlers = handler_stop;
        admission.request_stop();
        handlers.request_stop();
    }
};

template<class Handler>
Task<void> serve_admitted(Socket socket, std::shared_ptr<Handler> handler,
                          ResourceBudget::Reservation reservation,
                          ResourceBudget::Reservation shared_reservation,
                          std::optional<Clock::time_point> deadline, ServeState& state) {
    // Socket and charge outlive every operation, including exceptional unwind.
    (void)reservation;
    (void)shared_reservation;
    try {
        auto result = co_await (*handler)(socket, OperationOptions{.stop = state.handler_stop.get_token(),
                                                                  .deadline = deadline});
        if (!result) {
            if (result.error() == Errc::cancelled) serve_increment(state.stats.cancelled);
            else if (result.error() != Errc::eof) serve_increment(state.stats.failed);
        }
    } catch (...) {
        serve_increment(state.stats.failed);
        state.record_exception(std::current_exception());
    }
    serve_increment(state.stats.completed);
}

inline Task<void> serve_grace_timer(EventLoop& loop, Clock::time_point deadline,
                                    std::stop_token stop, ServeState& state) {
    try {
        auto result = co_await loop.sleep_until(deadline, {.stop = stop});
        // An unrelated loop shutdown also requires cooperative cancellation.
        if (result || !stop.stop_requested()) state.cancel_handlers();
    } catch (...) {
        state.record_exception(std::current_exception());
    }
}

template<class Handler>
Task<Result<ServeStats>> serve_impl(EventLoop* loop, Listener& listener,
                                    Handler handler, ServeOptions options) {
    if (options.max_connections == 0 || options.grace_period < Clock::duration::zero() ||
        (!loop && options.grace_period != Clock::duration::zero()))
        co_return fail(Errc::invalid_argument);
    ResourceBudget slots{options.max_connections};
    ServeState state;
    TaskScope handlers;
    TaskScope watchdog;
    std::stop_source timer_stop;
    auto shared_handler = std::make_shared<Handler>(std::move(handler));
    const auto stop_admission = [source = state.admission_stop]() mutable { source.request_stop(); };
    // External callbacks may run anywhere; only thread-safe stop state is touched.
    const std::stop_callback external_stop{options.io.stop, stop_admission};
    const OperationOptions admission_io{.stop = state.admission_stop.get_token(),
                                        .deadline = options.io.deadline};
    try {
        for (;;) {
            auto accepted = co_await listener.accept(admission_io);
            if (!accepted) {
                if (accepted.error() != Errc::cancelled && accepted.error() != Errc::timed_out &&
                    !state.exception && !state.error)
                    state.error = accepted.error();
                break;
            }
            serve_increment(state.stats.accepted);
            // A completion may win the race with cancellation in the same loop
            // batch. Do not start a handler after the admission signal arrived.
            if (admission_io.stop.stop_requested() ||
                (admission_io.deadline && *admission_io.deadline <= Clock::now())) {
                serve_increment(state.stats.rejected);
                break;
            }
            auto reservation = slots.try_acquire(1);
            if (!reservation) {
                serve_increment(state.stats.rejected);
                accepted->close();
                continue;
            }
            ResourceBudget::Reservation shared_reservation;
            if (options.admission_budget) {
                auto shared = options.admission_budget->try_acquire(1);
                if (!shared) {
                    serve_increment(state.stats.rejected);
                    accepted->close();
                    continue;
                }
                shared_reservation = std::move(*shared);
            }
            state.stats.peak_active = std::max(state.stats.peak_active, slots.used());
            handlers.spawn(serve_admitted(std::move(*accepted), shared_handler,
                                          std::move(*reservation), std::move(shared_reservation),
                                          options.handler_deadline, state));
        }
    } catch (...) {
        state.record_exception(std::current_exception());
    }
    // No pending accept remains here. Closing prevents new connections from
    // sitting in the kernel backlog while admitted handlers drain.
    listener.close();
    if (state.error || state.exception || options.grace_period == Clock::duration::zero()) {
        state.cancel_handlers();
    } else if (handlers.pending() != 0) {
        try {
            const auto now = Clock::now();
            const auto deadline = now + std::min(options.grace_period, Clock::time_point::max() - now);
            watchdog.spawn(serve_grace_timer(*loop, deadline, timer_stop.get_token(), state));
        } catch (...) {
            state.record_exception(std::current_exception());
        }
    }
    try {
        co_await handlers.join();
    } catch (...) {
        state.record_exception(std::current_exception());
    }
    timer_stop.request_stop();
    try {
        co_await watchdog.join();
    } catch (...) {
        state.record_exception(std::current_exception());
    }
    if (state.exception) std::rethrow_exception(state.exception);
    if (state.error) co_return fail(state.error);
    co_return state.stats;
}
}  // namespace detail

/// Admission -> drain -> cooperative cancellation -> join. Closes listener when
/// admission ends. Handler(Socket&, OperationOptions) -> Task<Result<void>> is
/// shared between connections and must finish all its I/O before returning.
/// A handler exception cancels siblings immediately, skips grace and is rethrown
/// after cleanup; ordinary Result errors are counted per connection. An earlier
/// accept error takes precedence over exceptions encountered during cleanup.
/// Statistics saturate rather than wrapping. The EventLoop must be the listener's loop.
///
/// Grace bounds when cancellation is requested, NOT when serve returns: an
/// uncooperative handler is still joined, never destroyed while suspended.
template<class Handler>
Task<Result<ServeStats>> serve(EventLoop& loop, Listener& listener, Handler handler,
                               ServeOptions options = {}) {
    return detail::serve_impl(&loop, listener, std::move(handler), std::move(options));
}

/// Compatibility overload: zero-grace cooperative cancellation. For a positive
/// grace_period use serve(loop, listener, handler, options); otherwise invalid_argument.
template<class Handler>
Task<Result<ServeStats>> serve(Listener& listener, Handler handler, ServeOptions options = {}) {
    return detail::serve_impl(nullptr, listener, std::move(handler), std::move(options));
}

}  // namespace Mira::transport::tcp
