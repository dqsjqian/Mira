// MQTT automatic reconnection with backoff, against a small in-test broker.
//
// The broker drops the first connection right after CONNACK and keeps later
// ones open, so the supervision helper must reconnect once and then run
// the body to a clean stop. Backoff sequencing is tested without sleeping.

#include "check.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/mqtt/reconnect.hpp"
#include "mira/transport/tcp.hpp"

#include <array>

using namespace Mira;
using namespace Mira::mqtt;
using namespace Mira::transport;
using namespace std::chrono_literals;
using Socket = tcp::Socket;

namespace {

Bytes text(std::string_view value) {
    const auto view = std::as_bytes(std::span{value.data(), value.size()});
    return Bytes(view.begin(), view.end());
}

OperationOptions budget() { return {.deadline = Clock::now() + 10s}; }

// One connection: answer CONNECT with CONNACK, then either drop (first
// connection) or stay open answering PINGREQ and discarding the rest.
Task<void> broker(Socket peer, bool drop) {
    Version version = Version::v5;
    Bytes pending;
    const auto send = [&](const Packet& packet) -> Task<Result<void>> {
        auto wire = encode(packet, version);
        if (!wire) co_return fail(wire.error());
        co_return co_await write_all(peer, std::span<const std::byte>{*wire}, OperationOptions{});
    };
    std::array<std::byte, 4096> buffer{};
    for (;;) {
        auto n = co_await peer.read_some(std::span<std::byte>{buffer}, {.deadline = Clock::now() + 10s});
        if (!n || *n == 0) co_return;
        pending.insert(pending.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*n));
        for (;;) {
            auto decoded = decode(pending, version, Role::server);
            if (!decoded || !decoded->packet) break;
            pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(decoded->consumed));
            auto& packet = *decoded->packet;
            if (auto* c = std::get_if<Connect>(&packet)) {
                version = c->version;
                auto sent = co_await send(Connack{false, 0, {}});
                CHECK(sent.has_value());
                if (drop) co_return;
            } else if (std::holds_alternative<Pingreq>(packet)) {
                auto sent = co_await send(Pingresp{});
                CHECK(sent.has_value());
            } else if (std::holds_alternative<Disconnect>(packet)) {
                co_return;
            }
        }
    }
}

Task<void> accept_loop(tcp::Listener& listener, std::stop_source& stop) {
    TaskScope children;
    int connections = 0;
    for (;;) {
        auto peer = co_await listener.accept({.stop = stop.get_token()});
        if (!peer) break;
        children.spawn(broker(std::move(*peer), connections++ == 0));
    }
    co_await children.join();
}

void backoff_checks() {
    test::section("backoff sequence, cap, reset, and stable-for reset rule");
    ReconnectBackoff backoff{ReconnectPolicy{.initial_delay = 100ms, .max_delay = 1000ms, .multiplier = 2}};
    CHECK(backoff.next() == 100ms);
    CHECK(backoff.next() == 200ms);
    CHECK(backoff.next() == 400ms);
    CHECK(backoff.next() == 800ms);
    CHECK(backoff.next() == 1000ms);
    CHECK(backoff.next() == 1000ms);
    backoff.reset();
    CHECK(backoff.next() == 100ms);
    ReconnectBackoff fresh{ReconnectPolicy{.initial_delay = 100ms, .max_delay = 1000ms, .multiplier = 2,
                                           .stable_for = 0ms}};
    CHECK(fresh.next() == 100ms);
    fresh.note_connected();
    fresh.note_lost();
    CHECK(fresh.next() == 100ms);
    ReconnectBackoff steady{ReconnectPolicy{.initial_delay = 100ms, .max_delay = 1000ms, .multiplier = 2,
                                            .stable_for = 24h}};
    CHECK(steady.next() == 100ms);
    steady.note_connected();
    steady.note_lost();
    CHECK(steady.next() == 200ms);
}

Task<void> exercise(EventLoop& loop) {
    backoff_checks();

    test::section("drop after CONNACK reconnects once, then the body stops cleanly");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    std::stop_source stop;
    TaskScope scope;
    scope.spawn(accept_loop(*listener, stop));
    int body_runs = 0;
    auto connector = [&](OperationOptions io) -> Task<Result<Socket>> {
        co_return co_await tcp::connect(loop, listener->local_endpoint(), {}, io);
    };
    auto body = [&](Client<Socket>& client, OperationOptions io) -> Task<Result<ReconnectAction>> {
        ++body_runs;
        if (body_runs == 1) {
            auto events = co_await client.receive(io);
            CHECK(!events && events.error() == Errc::eof);
            co_return ReconnectAction::reconnect;
        }
        auto id = co_await client.publish("t", text("hi"), QoS::at_most_once, false, {}, io);
        CHECK(id.has_value());
        co_return ReconnectAction::stop;
    };
    const auto supervised = co_await run_with_reconnect(
        loop, ClientOptions{}, connector, body,
        ReconnectPolicy{.initial_delay = 1ms, .max_delay = 5ms, .multiplier = 2, .max_attempts = 10},
        budget());
    CHECK(supervised.has_value());
    CHECK(body_runs == 2);

    test::section("exhausted attempts fail with limit_exceeded, not the last dial error");
    int tries = 0;
    auto refuse = [&](OperationOptions) -> Task<Result<Socket>> {
        ++tries;
        co_return fail(std::make_error_code(std::errc::connection_refused));
    };
    bool body_called = false;
    auto never = [&](Client<Socket>&, OperationOptions) -> Task<Result<ReconnectAction>> {
        body_called = true;
        co_return ReconnectAction::stop;
    };
    const auto denied = co_await run_with_reconnect(
        loop, ClientOptions{}, refuse, never,
        ReconnectPolicy{.initial_delay = 1ms, .max_delay = 2ms, .multiplier = 2, .max_attempts = 3},
        budget());
    CHECK(!denied && denied.error() == Errc::limit_exceeded);
    CHECK(tries == 3);
    CHECK(!body_called);

    test::section("invalid policy fails before dialing; stop ends an unbounded loop");
    int dials = 0;
    auto counting_refuse = [&](OperationOptions) -> Task<Result<Socket>> {
        ++dials;
        co_return fail(std::make_error_code(std::errc::connection_refused));
    };
    const auto invalid = co_await run_with_reconnect(
        loop, ClientOptions{}, counting_refuse, never,
        ReconnectPolicy{.initial_delay = 0ms, .max_delay = 2ms, .multiplier = 2, .max_attempts = 3},
        budget());
    CHECK(!invalid && invalid.error() == Errc::invalid_argument);
    CHECK(dials == 0);
    std::stop_source cancel;
    TaskScope watch;
    // The closure must outlive the spawned coroutine (see TaskScope's
    // header): a temporary lambda would die while its frame is suspended.
    auto stopper = [&]() -> Task<void> {
        static_cast<void>(co_await loop.sleep_for(5ms));
        cancel.request_stop();
        co_return;
    };
    watch.spawn(stopper());
    const auto stopped = co_await run_with_reconnect(
        loop, ClientOptions{}, counting_refuse, never,
        ReconnectPolicy{.initial_delay = 1ms, .max_delay = 2ms, .multiplier = 2, .max_attempts = 0},
        {.stop = cancel.get_token()});
    CHECK(!stopped && stopped.error() == Errc::cancelled);
    co_await watch.join();

    stop.request_stop();
    co_await scope.join();
}

Task<void> root(EventLoop& loop) { co_await exercise(loop); }

}  // namespace

int main() {
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (loop) {
        CHECK(loop->run_until_complete(root(*loop)).has_value());
        CHECK(loop->outstanding() == 0);
    }
    return test::summary();
}
