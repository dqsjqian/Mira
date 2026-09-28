#pragma once
#include "mira/transport/tcp.hpp"
#include <algorithm>
#include <chrono>

namespace Mira::transport::tcp {
struct RetryOptions {
    unsigned attempts = 3;
    Clock::duration initial_delay = std::chrono::milliseconds(100);
    Clock::duration max_delay = std::chrono::seconds(2);
};

/// Retry only establishing a TCP connection, never an application request.
/// All attempts and backoff share the caller's absolute deadline. Each failed
/// attempt owns and closes its socket. Backoff is deterministic and bounded.
inline Task<Result<Socket>> connect_with_retry(EventLoop& loop, Endpoint endpoint,
    RetryOptions retry = {}, ConnectOptions options = {}, OperationOptions io = {}) {
    if (!retry.attempts || retry.attempts > 1000 || retry.initial_delay < Clock::duration::zero() ||
        retry.max_delay < retry.initial_delay) co_return fail(Errc::invalid_argument);
    auto delay = retry.initial_delay;
    Error last;
    for (unsigned attempt = 0; attempt < retry.attempts; ++attempt) {
        auto connected = co_await connect(loop, endpoint, options, io);
        if (connected) co_return std::move(*connected);
        last = connected.error();
        if (last == Errc::cancelled || last == Errc::timed_out ||
            last == Errc::invalid_argument || last == Errc::not_supported ||
            attempt + 1 == retry.attempts) break;
        auto waited = co_await loop.sleep_for(delay, io);
        if (!waited) co_return fail(waited.error());
        delay = delay > retry.max_delay - delay ? retry.max_delay : delay + delay;
    }
    co_return fail(last);
}
}  // namespace Mira::transport::tcp
