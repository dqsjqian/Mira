#pragma once

#include "mira/core/task_scope.hpp"
#include "mira/transport/resolver.hpp"
#include "mira/transport/tcp.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <new>
#include <optional>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace Mira::transport::tcp {

/// Per-dial configuration: io contains one call's cancellation and budget, so
/// refresh it rather than retaining a deadline across separate calls.
struct DialOptions {
    OperationOptions io{};
    ConnectOptions connect{};
    Clock::duration fallback_delay{std::chrono::milliseconds(250)};
    std::size_t max_attempts{8};
    std::size_t max_parallel{2};
};

using DialConnector = std::function<Task<Result<Socket>>(
    EventLoop&, Endpoint, ConnectOptions, OperationOptions)>;

namespace dial_detail {

inline Error preflight(const DialOptions& options) noexcept {
    if (options.io.stop.stop_requested()) return make_error_code(Errc::cancelled);
    if (options.io.deadline && Clock::now() >= *options.io.deadline)
        return make_error_code(Errc::timed_out);
    if (options.fallback_delay < Clock::duration::zero() ||
        options.max_attempts == 0 || options.max_parallel == 0)
        return make_error_code(Errc::invalid_argument);
    return {};
}

struct Candidates {
    std::vector<Endpoint> endpoints;
    bool limited{false};
};

inline Result<Candidates> candidates(std::vector<Endpoint> input, std::size_t limit) {
    if (input.empty()) return fail(Errc::invalid_argument);
    for (const auto& endpoint : input) {
        if (endpoint.address_bytes().empty()) return fail(Errc::invalid_argument);
    }
    Candidates result;
    result.endpoints.reserve(std::min(input.size(), limit));
    std::array<std::size_t, 2> cursors{};
    auto family = input.front().family();
    const auto other = [](Family value) {
        return value == Family::ipv4 ? Family::ipv6 : Family::ipv4;
    };
    const auto next = [&](Family desired) -> std::optional<Endpoint> {
        auto& cursor = cursors[desired == Family::ipv4 ? 0U : 1U];
        while (cursor != input.size()) {
            const auto& endpoint = input[cursor++];
            if (endpoint.family() == desired &&
                std::find(result.endpoints.begin(), result.endpoints.end(), endpoint) ==
                    result.endpoints.end())
                return endpoint;
        }
        return std::nullopt;
    };
    while (result.endpoints.size() < limit) {
        auto endpoint = next(family);
        if (!endpoint) endpoint = next(other(family));
        if (!endpoint) break;
        family = other(endpoint->family());
        result.endpoints.push_back(*endpoint);
    }
    result.limited = std::any_of(input.begin(), input.end(), [&](const Endpoint& endpoint) {
        return std::find(result.endpoints.begin(), result.endpoints.end(), endpoint) ==
               result.endpoints.end();
    });
    return result;
}

struct Race {
    std::stop_source stop;
    std::stop_source wake;
    std::optional<Socket> winner;
    Error last_error{make_error_code(Errc::invalid_argument)};
    Error fatal{};
    std::size_t active{0};
    bool advance{false};
    bool accepting{true};
};

struct ForwardStop {
    std::stop_source source;
    void operator()() noexcept { source.request_stop(); }
};

inline Task<void> attempt(EventLoop& loop, Endpoint endpoint, const DialConnector& connector,
                          ConnectOptions connect_options, OperationOptions io, Race& race) {
    try {
        Result<Socket> result;
        if (connector) result = co_await connector(loop, endpoint, connect_options, io);
        else result = co_await connect(loop, endpoint, connect_options, io);
        if (result && result->valid()) {
            if (race.accepting && !race.winner) {
                race.winner.emplace(std::move(*result));
                race.stop.request_stop();
            }
        } else {
            race.last_error = result ? make_error_code(Errc::invalid_argument) : result.error();
            if (race.last_error == Errc::cancelled || race.last_error == Errc::timed_out)
                race.fatal = race.last_error;
            race.advance = true;
        }
    } catch (const std::bad_alloc&) {
        race.fatal = std::make_error_code(std::errc::not_enough_memory);
    } catch (...) {
        race.fatal = make_error_code(Errc::internal);
    }
    --race.active;
    // The loop queues timer cancellation; it never abandons a pending frame.
    // Copy the source so the notification does not borrow its owner afterward.
    auto wake = race.wake;
    wake.request_stop();
}

inline Clock::time_point add_delay(Clock::time_point now, Clock::duration delay) noexcept {
    return now > Clock::time_point::max() - delay ? Clock::time_point::max() : now + delay;
}

inline Task<Result<Socket>> race(EventLoop& loop, std::vector<Endpoint> endpoints,
                                DialOptions options, DialConnector connector) {
    if (auto error = preflight(options)) co_return fail(error);
    auto ordered = candidates(std::move(endpoints), options.max_attempts);
    if (!ordered) co_return fail(ordered.error());

    Race state;
    TaskScope scope;
    std::stop_callback forward{options.io.stop, ForwardStop{state.stop}};
    std::size_t next = 0;
    auto next_start = Clock::now();
    Error error;
    try {
        for (;;) {
            // An already published connection wins over a same-batch stop.
            if (state.winner) break;
            if (options.io.stop.stop_requested()) { error = make_error_code(Errc::cancelled); break; }
            if (options.io.deadline && Clock::now() >= *options.io.deadline) {
                error = make_error_code(Errc::timed_out);
                break;
            }
            if (state.fatal) { error = state.fatal; break; }
            if (next == ordered->endpoints.size() && state.active == 0) {
                error = ordered->limited ? make_error_code(Errc::limit_exceeded) : state.last_error;
                break;
            }
            if (next < ordered->endpoints.size() && state.active < options.max_parallel &&
                (state.active == 0 || state.advance || Clock::now() >= next_start)) {
                state.advance = false;
                next_start = add_delay(Clock::now(), options.fallback_delay);
                ++state.active;
                scope.spawn(attempt(loop, ordered->endpoints[next++], connector, options.connect,
                    {.stop = state.stop.get_token(), .deadline = options.io.deadline}, state));
                continue;
            }

            // Exactly one scheduler wait, not one sleeping task per candidate.
            // Failed attempts cancel this wait to make room immediately.
            state.wake = std::stop_source{};
            std::stop_callback wake_on_stop{options.io.stop, ForwardStop{state.wake}};
            const auto until = next < ordered->endpoints.size() && state.active < options.max_parallel
                ? next_start : Clock::time_point::max();
            auto waited = co_await loop.sleep_until(until,
                {.stop = state.wake.get_token(), .deadline = options.io.deadline});
            if (!waited && !(waited.error() == Errc::cancelled && state.wake.stop_requested())) {
                if (!state.winner) error = waited.error();
                break;
            }
        }
    } catch (const std::bad_alloc&) {
        error = std::make_error_code(std::errc::not_enough_memory);
    } catch (...) {
        error = make_error_code(Errc::internal);
    }
    state.accepting = false;
    state.stop.request_stop();
    co_await scope.join();
    if (state.winner) co_return std::move(*state.winner);
    co_return fail(error);
}

inline Task<Result<Socket>> resolve_and_race(EventLoop& loop,
    Task<Result<Resolver::Endpoints>> resolution, DialOptions options, DialConnector connector) {
    if (auto error = preflight(options)) co_return fail(error);
    auto endpoints = co_await std::move(resolution);
    if (!endpoints) co_return fail(endpoints.error());
    co_return co_await race(loop, std::move(*endpoints), std::move(options), std::move(connector));
}

}  // namespace dial_detail

/// Race bounded, deduplicated endpoints, alternating address families while
/// preserving the first candidate's family preference and within-family order.
/// A failure advances the next attempt immediately; otherwise fallback_delay
/// separates starts. max_parallel bounds active attempts, max_attempts bounds
/// total attempts. Exhausting a truncated list returns limit_exceeded; exhausting
/// the whole list returns the last connection error. Empty/unset endpoints or
/// zero limits are invalid_argument. A successful connection already delivered
/// on the loop thread wins over a concurrent stop/deadline.
///
/// All children are cancelled and joined before returning, including late
/// successes, whose sockets are closed. Loop and connector dependencies must
/// outlive the task. An injected connector must observe io and return only on
/// the loop thread; a connector that ignores cancellation can delay draining.
/// The callable is owned by the task, including when it is a coroutine lambda.
/// Like other I/O tasks, a started dial must not be abandoned.
[[nodiscard]] inline Task<Result<Socket>> dial(EventLoop& loop, std::vector<Endpoint> endpoints,
    DialOptions options = {}, DialConnector connector = {}) {
    return dial_detail::race(loop, std::move(endpoints), std::move(options), std::move(connector));
}

/// Resolve and connect within the same absolute io.deadline. The Resolver is
/// captured through its lazy resolve task at this call, not borrowed until the
/// dial starts. DNS uses the bounded resolver worker pool, not asynchronous DNS:
/// cancelling ends the wait but cannot interrupt an entered system getaddrinfo.
[[nodiscard]] inline Task<Result<Socket>> dial(EventLoop& loop, Resolver& resolver,
    std::string host, std::string service, DialOptions options = {}, DialConnector connector = {}) {
    auto resolution = resolver.resolve(loop, {std::move(host), std::move(service)}, options.io);
    return dial_detail::resolve_and_race(loop, std::move(resolution),
                                         std::move(options), std::move(connector));
}

[[nodiscard]] inline Task<Result<Socket>> dial(EventLoop& loop, Resolver& resolver,
    std::string host, std::uint16_t port, DialOptions options = {}, DialConnector connector = {}) {
    return dial(loop, resolver, std::move(host), std::to_string(port),
                std::move(options), std::move(connector));
}

}  // namespace Mira::transport::tcp
