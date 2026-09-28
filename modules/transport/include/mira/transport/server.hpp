#pragma once

#include "mira/core/resource_budget.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/transport/tcp.hpp"

#include <algorithm>
#include <exception>
#include <memory>
#include <stop_token>

namespace Mira::transport::tcp {

struct ServeOptions {
    std::size_t max_connections = 256;
    /// Total lifetime of accept/handlers. Cancellation stops admission, asks
    /// every active handler to stop, then joins them before returning.
    OperationOptions io;
};
struct ServeStats {
    std::size_t accepted = 0;
    std::size_t rejected = 0;
    std::size_t completed = 0;
    std::size_t failed = 0;
    std::size_t peak_active = 0;
};

namespace detail {
template<class Handler>
Task<void> serve_admitted(Socket socket, std::shared_ptr<Handler> handler,
                          ResourceBudget::Reservation reservation, OperationOptions io,
                          ServeStats& stats) {
    // Keep both the socket and its admission charge until the coroutine ends.
    (void)reservation;
    auto result = co_await (*handler)(socket, io);
    if (!result && result.error() != Errc::cancelled && result.error() != Errc::eof)
        ++stats.failed;
    ++stats.completed;
}
}

/// Accept many clients with bounded admission and structured shutdown.
/// Handler(Socket&, OperationOptions) -> Task<Result<void>> must honor io and
/// return only after all socket operations end. It is shared across connections.
/// This provides cooperative shutdown, never destruction of a suspended task.
template<class Handler>
Task<Result<ServeStats>> serve(Listener& listener, Handler handler, ServeOptions options = {}) {
    if (options.max_connections == 0) co_return fail(Errc::invalid_argument);
    ResourceBudget slots{options.max_connections};
    TaskScope scope;
    ServeStats stats;
    auto shared_handler = std::make_shared<Handler>(std::move(handler));
    std::stop_source combined;
    const auto request_stop = [source = combined]() mutable { source.request_stop(); };
    // Stop callbacks may run on arbitrary threads. They touch only the
    // thread-safe source, never the single-threaded TaskScope directly.
    const std::stop_callback external_stop{options.io.stop, request_stop};
    const std::stop_callback child_failure{scope.get_stop_token(), request_stop};
    OperationOptions io{.stop = combined.get_token(), .deadline = options.io.deadline};
    Error accept_error;
    std::exception_ptr exception;
    try {
        for (;;) {
            auto accepted = co_await listener.accept(io);
            if (!accepted) {
                accept_error = accepted.error();
                break;
            }
            ++stats.accepted;
            auto reservation = slots.try_acquire(1);
            if (!reservation) {
                ++stats.rejected;
                accepted->close();
                continue;
            }
            stats.peak_active = std::max(stats.peak_active, slots.used());
            scope.spawn(detail::serve_admitted(std::move(*accepted), shared_handler,
                                               std::move(*reservation), io, stats));
        }
    } catch (...) { exception = std::current_exception(); }
    scope.request_stop();
    co_await scope.join();
    if (exception) std::rethrow_exception(exception);
    if (accept_error && accept_error != Errc::cancelled && accept_error != Errc::timed_out)
        co_return fail(accept_error);
    co_return stats;
}

}  // namespace Mira::transport::tcp
