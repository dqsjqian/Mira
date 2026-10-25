#pragma once

// MQTT automatic reconnection with backoff.
//
// Client::reconnect is manual: the caller notices a dead connection, dials a
// fresh stream, and calls reconnect on it. This helper owns that loop: it
// dials through a caller-supplied connector, runs a caller-supplied body on
// each live connection, and, whenever the body reports the connection lost,
// drops the dead stream, sleeps with exponential backoff, and reconnects —
// preserving the session, so unacknowledged publishes are resent when
// clean_start is false, exactly as manual reconnect does.
//
// The connector returns an OWNED stream; the helper destroys it when moving
// to the next attempt, so the body must not keep the stream past its return.
// The client object survives across attempts (Session::connect is defined
// for any old state), but its borrowed stream pointer dangles between the
// stream's destruction and the next reconnect — nothing touches the client
// in that window by construction.
//
// The body decides the outcome of each connection:
//  * stop: clean end; the helper returns success. The body owns graceful
//    shutdown — call disconnect() first if a DISCONNECT packet is wanted.
//  * reconnect: the connection is dead; back off and try again. Drain
//    receive() before returning, or buffered events may leave the next
//    handshake short of room and fail with would_block.
//  * an error result: fatal; it propagates immediately with no retry.
// Cancellation and the caller's absolute deadline end the loop at the next
// attempt boundary (or inside the backoff sleep) as cancelled/timed_out.
// Only truncation-free connect failures and body-reported losses consume
// attempts: max_attempts counts dial+handshake tries, 0 means retry until
// the caller stops the loop, and exhaustion fails with limit_exceeded.
//
// Backoff: delays start at initial_delay, multiply by multiplier per failed
// attempt, and cap at max_delay. A connection that lives at least
// stable_for resets the sequence to initial_delay when it is lost, so a
// transient drop after hours uptime does not inherit the maximum delay,
// while a flapping connection keeps backing off. No jitter is added: a
// caller with many clients behind one broker adds its own.

#include "mira/core/observe.hpp"
#include "mira/mqtt/client.hpp"

#include <chrono>
#include <optional>
#include <type_traits>
#include <utility>

namespace Mira::mqtt {

namespace detail {
template<class T>
struct reconnect_stream;
template<class S>
struct reconnect_stream<Task<Result<S>>> {
    using type = S;
};
template<class T>
using reconnect_stream_t = typename reconnect_stream<T>::type;
}  // namespace detail

struct ReconnectPolicy {
    std::chrono::milliseconds initial_delay{100};
    std::chrono::milliseconds max_delay{30000};
    std::uint32_t multiplier = 2;
    /// Attempts (dial+handshake tries) before giving up; 0 retries forever.
    std::size_t max_attempts = 0;
    /// Uptime after which losing the connection resets the delay sequence.
    std::chrono::milliseconds stable_for{30000};
};

/// The delay sequence of a ReconnectPolicy, separated from the loop so it
/// can be reasoned about (and tested) without sleeping.
class ReconnectBackoff {
public:
    explicit ReconnectBackoff(ReconnectPolicy policy)
        : policy_(policy),
          current_(policy.initial_delay < policy.max_delay ? policy.initial_delay : policy.max_delay) {}
    /// The delay for the next sleep, advancing the sequence behind it.
    [[nodiscard]] std::chrono::milliseconds next() noexcept {
        const auto delay = current_;
        if (policy_.multiplier > 1) {
            const auto cap = policy_.max_delay.count();
            const auto scaled = current_.count() > cap / static_cast<std::int64_t>(policy_.multiplier)
                                    ? cap
                                    : current_.count() * static_cast<std::int64_t>(policy_.multiplier);
            current_ = std::chrono::milliseconds{scaled};
        }
        return delay;
    }
    void reset() noexcept { current_ = policy_.initial_delay < policy_.max_delay
                                          ? policy_.initial_delay
                                          : policy_.max_delay; }
    /// Call when an attempt connects, before the body runs.
    void note_connected() noexcept { connected_at_ = Clock::now(); }
    /// Call when the body reports the connection lost. Resets the sequence
    /// only if the connection lived at least stable_for.
    void note_lost() noexcept {
        if (connected_at_ && Clock::now() - *connected_at_ >= policy_.stable_for) reset();
        connected_at_.reset();
    }

private:
    ReconnectPolicy policy_;
    std::chrono::milliseconds current_;
    std::optional<Clock::time_point> connected_at_;
};

enum class ReconnectAction { stop, reconnect };

template<class Connector, class Body,
         class Stream = detail::reconnect_stream_t<std::invoke_result_t<Connector&, OperationOptions>>>
    requires BoundedStream<Stream> &&
             requires(Connector& connector, OperationOptions io, Client<Stream>& client, Body& body) {
                 { connector(io) } -> std::same_as<Task<Result<Stream>>>;
                 { body(client, io) } -> std::same_as<Task<Result<ReconnectAction>>>;
             }
[[nodiscard]] Task<Result<void>> run_with_reconnect(EventLoop& loop, ClientOptions options,
                                                    Connector&& connect, Body&& body,
                                                    ReconnectPolicy policy = {}, OperationOptions io = {},
                                                    typename Client<Stream>::AuthHandler auth_handler = {},
                                                    LogSink* sink = nullptr) {
    if (policy.initial_delay <= std::chrono::milliseconds::zero() ||
        policy.max_delay < policy.initial_delay || policy.multiplier < 1)
        co_return fail(Errc::invalid_argument);
    ReconnectBackoff backoff{policy};
    std::optional<Stream> stream;
    std::optional<Client<Stream>> client;
    std::size_t attempts = 0;
    for (;;) {
        if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (io.deadline && Clock::now() >= *io.deadline) co_return fail(Errc::timed_out);
        if (policy.max_attempts && attempts >= policy.max_attempts) co_return fail(Errc::limit_exceeded);
        ++attempts;
        auto fresh = co_await connect(io);
        if (!fresh) {
            log(sink, LogLevel::warning, "mqtt.reconnect", "connect attempt failed", fresh.error());
            if (policy.max_attempts && attempts >= policy.max_attempts)
                co_return fail(Errc::limit_exceeded);
            auto slept = co_await loop.sleep_for(backoff.next(), io);
            if (!slept) co_return fail(slept.error());
            continue;
        }
        stream.emplace(std::move(*fresh));
        backoff.note_connected();
        Result<void> linked;
        if (!client) {
            auto made = co_await Client<Stream>::connect(*stream, std::move(options), io, auth_handler);
            if (!made) linked = fail(made.error());
            else client.emplace(std::move(*made));
        } else {
            linked = co_await client->reconnect(*stream, io);
        }
        if (!linked) {
            log(sink, LogLevel::warning, "mqtt.reconnect", "handshake failed", linked.error());
            stream.reset();
            if (policy.max_attempts && attempts >= policy.max_attempts)
                co_return fail(Errc::limit_exceeded);
            auto slept = co_await loop.sleep_for(backoff.next(), io);
            if (!slept) co_return fail(slept.error());
            continue;
        }
        auto action = co_await body(*client, io);
        if (!action) co_return fail(action.error());
        if (*action == ReconnectAction::stop) co_return Result<void>{};
        log(sink, LogLevel::warning, "mqtt.reconnect", "connection lost, backing off");
        backoff.note_lost();
        stream.reset();
        if (policy.max_attempts && attempts >= policy.max_attempts)
            co_return fail(Errc::limit_exceeded);
        auto slept = co_await loop.sleep_for(backoff.next(), io);
        if (!slept) co_return fail(slept.error());
    }
}

}  // namespace Mira::mqtt
