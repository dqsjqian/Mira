#include "check.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/dns/query.hpp"
#include "mira/transport/tcp.hpp"
#include "mira/transport/udp.hpp"

#include <memory>

using namespace Mira;
using namespace Mira::dns;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {
OperationOptions budget() { return {.deadline = Clock::now() + 2s}; }
Message question() { return make_query(Name::parse("example.test").value(), type::a).value(); }
Message answer(Message query) {
    query.header.qr = true;
    query.answers.push_back({query.questions.front().name, type::a, class_in, 30,
                             AData{{127, 0, 0, 1}}});
    return query;
}

Task<void> udp_server(EventLoop& loop, udp::Socket& socket, int mode) {
    std::array<std::byte, 2048> buffer{};
    const auto received = co_await socket.receive_from(buffer, budget());
    CHECK(received.has_value());
    if (!received) co_return;
    auto response = answer(decode(std::span<const std::byte>{buffer}.first(received->size)).value());
    if (mode == 0) {
        auto rogue = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
        auto wire = encode(response).value();
        CHECK((co_await rogue.send_to(wire, received->peer, budget())).has_value());
        ++response.header.id;
        wire = encode(response).value();
        CHECK((co_await socket.send_to(wire, received->peer, budget())).has_value());
        --response.header.id;
        const auto original = response.questions.front().name;
        response.questions.front().name = Name::parse("other.test").value();
        wire = encode(response).value();
        CHECK((co_await socket.send_to(wire, received->peer, budget())).has_value());
        response.questions.front().name = original;
    }
    if (mode == 1) response.header.tc = true;
    if (mode == 2) { response.header.rcode = rcode::nxdomain; response.answers.clear(); }
    if (mode == 3) ++response.header.id;
    auto wire = encode(response).value();
    CHECK((co_await socket.send_to(wire, received->peer, budget())).has_value());
}

Task<void> udp_exchanges(EventLoop& loop) {
    test::section("Async UDP DNS: peer, ID and question matching, TC and NXDOMAIN");
    for (int mode = 0; mode < 4; ++mode) {
        auto server = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
        auto client = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
        TaskScope scope;
        scope.spawn(udp_server(loop, server, mode));
        const auto response = co_await query_udp(client, server.local_endpoint().value(), question(), budget(),
            {.max_discarded_packets = mode == 3 ? std::size_t{0} : std::size_t{16}});
        if (mode == 0) CHECK(response.has_value() && response->answers.size() == 1);
        if (mode == 1) CHECK(!response && response.error() == DnsError::truncated);
        if (mode == 2) CHECK(response.has_value() && response->header.rcode == rcode::nxdomain);
        if (mode == 3) CHECK(!response && response.error() == DnsError::mismatched_response);
        co_await scope.join();
    }
}

Task<void> stop_soon(EventLoop& loop, std::stop_source& stop) {
    CHECK((co_await loop.sleep_for(2ms)).has_value());
    stop.request_stop();
}

Task<void> udp_cancellation(EventLoop& loop) {
    test::section("UDP DNS cancellation and bounded default wait, without system resolution");
    auto quiet = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    auto client = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    std::stop_source stop;
    TaskScope scope;
    scope.spawn(stop_soon(loop, stop));
    const auto cancelled = co_await query_udp(client, quiet.local_endpoint().value(), question(),
        {.stop = stop.get_token()});
    CHECK(!cancelled && cancelled.error() == Errc::cancelled);
    co_await scope.join();
    const auto timeout = co_await query_udp(client, quiet.local_endpoint().value(), question(), {}, {.timeout = 3ms});
    CHECK(!timeout && timeout.error() == Errc::timed_out);
    const auto invalid = co_await query_udp(client, quiet.local_endpoint().value(), question(), {}, {.timeout = 0ms});
    CHECK(!invalid && invalid.error() == Errc::invalid_argument);
    const auto priority = co_await query_udp(client, quiet.local_endpoint().value(), question(),
        {.stop = stop.get_token()}, {.timeout = 0ms});
    CHECK(!priority && priority.error() == Errc::cancelled);
}

Task<void> receive_then_cancel(tcp::Listener& listener, EventLoop& loop, std::stop_source& stop) {
    auto accepted = co_await listener.accept(budget());
    CHECK(accepted.has_value());
    if (!accepted) co_return;
    std::array<std::byte, 2> prefix{};
    CHECK((co_await dns::detail::read_dns_exact(*accepted, prefix, budget())).has_value());
    const auto size = (std::to_integer<std::size_t>(prefix[0]) << 8) | std::to_integer<std::size_t>(prefix[1]);
    std::vector<std::byte> input(size);
    CHECK((co_await dns::detail::read_dns_exact(*accepted, input, budget())).has_value());
    stop.request_stop();
    CHECK((co_await loop.sleep_for(10ms)).has_value());
}

Task<void> tcp_cancellation(EventLoop& loop) {
    test::section("TCP DNS receive cancellation and connection cleanup");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0)).value();
    std::stop_source stop;
    TaskScope scope;
    scope.spawn(receive_then_cancel(listener, loop, stop));
    auto client = co_await tcp::connect(loop, listener.local_endpoint(), {}, budget());
    CHECK(client.has_value());
    if (client) {
        const auto result = co_await query_tcp(*client, question(), {.stop = stop.get_token()});
        CHECK(!result && result.error() == Errc::cancelled);
        client->close();
    }
    co_await scope.join();
}

struct Detached {
    struct promise_type {
        Detached get_return_object() noexcept { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::terminate(); }
    };
};

Detached close_after_shutdown(udp::Socket& client, udp::Socket& server, bool& done) {
    const auto result = co_await query_udp(client, server.local_endpoint().value(), question());
    CHECK(!result && result.error() == Errc::cancelled);
    client.close();
    server.close();
    done = true;
}

void udp_shutdown() {
    test::section("UDP DNS cancels on EventLoop destruction without resolver thread joins");
    auto loop = std::make_unique<EventLoop>(EventLoop::create().value());
    auto client = udp::Socket::bind(*loop, Endpoint::loopback(0)).value();
    auto server = udp::Socket::bind(*loop, Endpoint::loopback(0)).value();
    bool done = false;
    close_after_shutdown(client, server, done);
    CHECK(!done && loop->outstanding() != 0);
    loop.reset();
    CHECK(done);
    CHECK(!client.is_open() && !server.is_open());
}

Task<void> tcp_server(tcp::Listener& listener, int mode) {
    auto accepted = co_await listener.accept(budget());
    CHECK(accepted.has_value());
    if (!accepted) co_return;
    std::array<std::byte, 2> prefix{};
    CHECK((co_await dns::detail::read_dns_exact(*accepted, prefix, budget())).has_value());
    const auto size = (std::to_integer<std::size_t>(prefix[0]) << 8) | std::to_integer<std::size_t>(prefix[1]);
    std::vector<std::byte> input(size);
    CHECK((co_await dns::detail::read_dns_exact(*accepted, input, budget())).has_value());
    auto response = answer(decode(input).value());
    if (mode == 1) ++response.header.id;
    if (mode == 2) {
        const std::array<std::byte, 2> excessive{std::byte{0xff}, std::byte{0xff}};
        CHECK((co_await write_all(*accepted, excessive, budget())).has_value());
        co_return;
    }
    if (mode == 3) co_return;
    const auto wire = encode(response).value();
    prefix[0] = static_cast<std::byte>(wire.size() >> 8);
    prefix[1] = static_cast<std::byte>(wire.size() & 255U);
    // Fragment both prefix and body: read_some must not be assumed to fill either.
    for (const auto& byte : prefix)
        CHECK((co_await write_all(*accepted, std::span{&byte, 1}, budget())).has_value());
    for (const auto& byte : wire)
        CHECK((co_await write_all(*accepted, std::span{&byte, 1}, budget())).has_value());
}

Task<void> tcp_exchanges(EventLoop& loop) {
    test::section("Async TCP DNS: framing, fragmentation, wrong ID, capacity and EOF");
    for (int mode = 0; mode < 4; ++mode) {
        auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0)).value();
        TaskScope scope;
        scope.spawn(tcp_server(listener, mode));
        auto client = co_await tcp::connect(loop, listener.local_endpoint(), {}, budget());
        CHECK(client.has_value());
        if (client) {
            const auto response = co_await query_tcp(*client, question(), budget(),
                {.limits = {.max_message_size = 4096}});
            if (mode == 0) CHECK(response.has_value() && response->answers.size() == 1);
            if (mode == 1) CHECK(!response && response.error() == DnsError::mismatched_response);
            if (mode == 2) CHECK(!response && response.error() == DnsError::too_large);
            if (mode == 3) CHECK(!response && response.error() == Errc::eof);
            client->close();
        }
        co_await scope.join();
    }
}
}  // namespace

int main() {
    auto loop = EventLoop::create().value();
    CHECK(loop.run_until_complete(udp_exchanges(loop)).has_value());
    CHECK(loop.run_until_complete(udp_cancellation(loop)).has_value());
    CHECK(loop.run_until_complete(tcp_exchanges(loop)).has_value());
    CHECK(loop.run_until_complete(tcp_cancellation(loop)).has_value());
    CHECK(loop.outstanding() == 0);
    udp_shutdown();
    return test::summary();
}
