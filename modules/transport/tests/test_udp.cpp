#include "check.hpp"
#include "mira/core/stream.hpp"
#include "mira/transport/udp.hpp"

#include <array>
#include <chrono>
#include <coroutine>
#include <memory>
#include <optional>
#include <stop_token>
#include <string_view>
#include <thread>
#include <vector>

#if MIRA_HAS_READINESS_API
    #include <poll.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
#endif

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {
static_assert(!AsyncStream<udp::Socket>);

std::span<const std::byte> bytes(std::string_view text) {
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}
OperationOptions budget() {
    return {.deadline = EventLoop::Clock::now() + 2s};
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
template<class T>
Detached collect(Task<T> task, std::optional<T>& result) {
    result.emplace(co_await std::move(task));
}
void drain(EventLoop& loop) {
    const auto end = EventLoop::Clock::now() + 3s;
    while (loop.outstanding() && EventLoop::Clock::now() < end)
        CHECK(loop.run_once(10ms).has_value());
    CHECK(loop.outstanding() == 0);
}

Task<void> packets(EventLoop& loop, Family family) {
    auto a = udp::Socket::bind(loop, Endpoint::loopback(0, family));
    auto b = udp::Socket::bind(loop, Endpoint::loopback(0, family));
    CHECK(a.has_value());
    CHECK(b.has_value());
    if (!a || !b) co_return;
    const Endpoint peer = b->local_endpoint().value();
    CHECK(peer.port() != 0);
    CHECK(peer.family() == family);
    auto duplicate = udp::Socket::bind(loop, peer);
    CHECK(!duplicate);
    if (!duplicate) CHECK(duplicate.error() == std::errc::address_in_use);
    auto wildcard = udp::Socket::bind(loop, Endpoint::any(peer.port(), family));
    CHECK(!wildcard);

    // A lazily started task must retain the peer value, not reference the
    // caller's temporary endpoint.
    Endpoint mutable_peer = peer;
    auto delayed = a->send_to(bytes("first"), mutable_peer, budget());
    mutable_peer = Endpoint::loopback(0, family);
    CHECK((co_await std::move(delayed)).value() == 5);
    CHECK((co_await a->send_to(bytes("second"), peer, budget())).value() == 6);
    std::array<std::byte, 32> buffer{};
    auto one = co_await b->receive_from(buffer, budget());
    CHECK(one.has_value());
    if (one) {
        CHECK(one->size == 5);
        CHECK(one->peer.to_string() == a->local_endpoint()->to_string());
        CHECK(std::string_view(reinterpret_cast<char*>(buffer.data()), one->size) == "first");
    }
    auto two = co_await b->receive_from(buffer, budget());
    CHECK(two.has_value() && two->size == 6);
    CHECK(std::string_view(reinterpret_cast<char*>(buffer.data()), 6) == "second");

    CHECK((co_await a->send_to({}, peer, budget())).value() == 0);
    const auto empty = co_await b->receive_from(buffer, budget());
    CHECK(empty.has_value() && empty->size == 0);
    CHECK((co_await a->send_to({}, peer, budget())).value() == 0);
    const auto empty_buffer = co_await b->receive_from({}, budget());
    CHECK(empty_buffer.has_value() && empty_buffer->size == 0);

    for (const std::size_t capacity : {std::size_t{2}, std::size_t{0}}) {
        CHECK((co_await a->send_to(bytes("truncated"), peer, budget())).value() == 9);
        CHECK((co_await a->send_to(bytes("next"), peer, budget())).value() == 4);
        const auto short_packet =
            co_await b->receive_from(std::span{buffer}.first(capacity), budget());
        CHECK(!short_packet);
        if (!short_packet) CHECK(short_packet.error() == std::errc::message_size);
        const auto next = co_await b->receive_from(buffer, budget());
        CHECK(next.has_value() && next->size == 4);
        CHECK(std::string_view(reinterpret_cast<char*>(buffer.data()), 4) == "next");
    }

    std::stop_source stopped;
    stopped.request_stop();
    CHECK((co_await a->send_to(bytes("queued"), peer, budget())).has_value());
#if MIRA_HAS_READINESS_API
    pollfd queued{b->native_handle(), POLLIN, 0};
    CHECK(::poll(&queued, 1, 1000) == 1);
#endif
    const auto rejected = co_await b->receive_from(buffer, {.stop = stopped.get_token()});
    CHECK(!rejected && rejected.error() == Errc::cancelled);
    const auto expired =
        co_await b->receive_from(buffer, {.deadline = EventLoop::Clock::now() - 1ms});
    CHECK(!expired && expired.error() == Errc::timed_out);
    CHECK((co_await b->receive_from(buffer, budget())).value().size == 6);
    const auto no_send = co_await a->send_to({}, peer, {.stop = stopped.get_token()});
    CHECK(!no_send && no_send.error() == Errc::cancelled);
    const auto no_send_deadline =
        co_await a->send_to(bytes("x"), peer, {.deadline = EventLoop::Clock::now() - 1ms});
    CHECK(!no_send_deadline && no_send_deadline.error() == Errc::timed_out);
    const auto none = co_await b->receive_from(buffer, {.deadline = EventLoop::Clock::now() + 5ms});
    CHECK(!none && none.error() == Errc::timed_out);
    std::vector<std::byte> oversized(65536);
    const auto too_large = co_await a->send_to(oversized, peer, budget());
    CHECK(!too_large && too_large.error() == std::errc::message_size);
    b->close();
    CHECK(!b->is_open());
    CHECK(!b->local_endpoint());
    CHECK(!(co_await b->receive_from(buffer)));
    auto rebound = udp::Socket::bind(loop, peer);
    CHECK(rebound.has_value());
}

void concurrency_and_cancel() {
    test::section("same-direction rejection, full duplex, and cancel drain");
    auto created = EventLoop::create();
    auto& loop = created.value();
    auto a = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    auto b = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    std::array<std::byte, 32> first{}, second{};
    std::optional<Result<udp::Datagram>> pending, conflict;
    std::stop_source stop;
    collect(a.receive_from(first, {.stop = stop.get_token()}), pending);
    // With data already queued, a new operation still cannot overtake the
    // older one; busyness must not be judged only when suspended on readiness.
    std::optional<Result<std::size_t>> sent;
    collect(b.send_to(bytes("keep"), a.local_endpoint().value(), budget()), sent);
#if MIRA_HAS_READINESS_API
    pollfd queued{a.native_handle(), POLLIN, 0};
    CHECK(::poll(&queued, 1, 1000) == 1);
#endif
#if MIRA_PLATFORM_WINDOWS
    while (!sent)
        CHECK(loop.run_once(10ms).has_value());
    // IOCP may complete the receive in the same batch; suspend one more
    // receive and then verify the direction limit.
    if (pending) {
        pending.reset();
        collect(a.receive_from(first, {.stop = stop.get_token()}), pending);
    }
#endif
    collect(a.receive_from(second, budget()), conflict);
    CHECK(conflict.has_value());
    CHECK(conflict && !*conflict && conflict->error() == Errc::invalid_argument);
    std::optional<Result<std::size_t>> outgoing;
    collect(a.send_to(bytes("duplex"), b.local_endpoint().value(), budget()), outgoing);
    std::optional<Result<udp::Datagram>> incoming;
    collect(b.receive_from(second, budget()), incoming);
    std::thread cancel([&] { stop.request_stop(); });
    cancel.join();
    drain(loop);
    CHECK(pending.has_value());
    // A datagram completed in the same batch may win over cancellation; pure
    // cancellation is verified separately afterwards.
    CHECK(pending && (pending->has_value() || pending->error() == Errc::cancelled));
    CHECK(outgoing && outgoing->has_value() && **outgoing == 6);
    CHECK(incoming && incoming->has_value() && (*incoming)->size == 6);

    auto c = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    pending.reset();
    std::stop_source quiet;
    collect(c.receive_from(first, {.stop = quiet.get_token()}), pending);
    quiet.request_stop();
    drain(loop);
    CHECK(pending && !*pending && pending->error() == Errc::cancelled);
    pending.reset();
    collect(c.receive_from({}, {.deadline = EventLoop::Clock::now() + 5ms}), pending);
    drain(loop);
    CHECK(pending && !*pending && pending->error() == Errc::timed_out);

#if MIRA_PLATFORM_WINDOWS
    // Even when a send completes immediately, IOCP must still wait for the
    // completion packet; the direction slot must not be released early.
    std::optional<Result<std::size_t>> send_one, send_two;
    collect(c.send_to(bytes("one"), b.local_endpoint().value(), budget()), send_one);
    collect(c.send_to(bytes("two"), b.local_endpoint().value(), budget()), send_two);
    CHECK(!send_one);
    CHECK(send_two && !*send_two && send_two->error() == Errc::invalid_argument);
    drain(loop);
    CHECK(send_one && send_one->has_value());
    pending.reset();
    send_one.reset();
    collect(c.receive_from(first), pending);
    collect(c.send_to(bytes("close"), b.local_endpoint().value()), send_one);
    c.close();
    // Borrows remain valid after close; only after draining may first and the
    // source buffer be released.
    CHECK(!pending);
    drain(loop);
    CHECK(pending && !*pending && pending->error() == Errc::cancelled);
    CHECK(send_one && !*send_one && send_one->error() == Errc::cancelled);
#endif
}

Detached receive_and_destroy(Task<Result<udp::Datagram>> task,
                             std::unique_ptr<udp::Socket>& socket,
                             bool& done) {
    const auto result = co_await std::move(task);
    CHECK(!result && result.error() == Errc::cancelled);
    socket.reset();
    done = true;
}
Detached receive_then_close(Task<Result<udp::Datagram>> task,
                            udp::Socket& other,
                            int& success,
                            int& cancelled) {
    const auto result = co_await std::move(task);
    if (result) {
        ++success;
        other.close();
    } else {
        CHECK(result.error() == Errc::cancelled);
        ++cancelled;
    }
}

void close_ready_batch() {
    test::section("closing the other datagram operation within the same ready batch");
    auto created = EventLoop::create();
    auto& loop = created.value();
    auto a = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    auto b = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    auto sender_a = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    auto sender_b = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    std::array<std::byte, 16> first{}, second{};
    int success = 0, cancelled = 0;
    receive_then_close(a.receive_from(first, budget()), b, success, cancelled);
    receive_then_close(b.receive_from(second, budget()), a, success, cancelled);
    std::optional<Result<std::size_t>> sent_a, sent_b;
    collect(sender_a.send_to(bytes("a"), a.local_endpoint().value()), sent_a);
    collect(sender_b.send_to(bytes("b"), b.local_endpoint().value()), sent_b);
#if MIRA_HAS_READINESS_API
    // Without driving the loop, first confirm both fds are ready, ensuring
    // the test truly covers a same-batch close.
    pollfd readiness[2]{{a.native_handle(), POLLIN, 0}, {b.native_handle(), POLLIN, 0}};
    CHECK(::poll(&readiness[0], 1, 1000) == 1);
    CHECK(::poll(&readiness[1], 1, 1000) == 1);
#endif
    drain(loop);
#if MIRA_PLATFORM_WINDOWS
    // A classified IOCP completion can succeed; closing an unclassified one
    // returns cancelled.
    CHECK(success >= 1);
    CHECK(success + cancelled == 2);
#else
    CHECK(success == 1);
    CHECK(cancelled == 1);
#endif
}

void close_lifetimes() {
    test::section("close, move, and reentrant wrapper destruction");
    auto created = EventLoop::create();
    auto& loop = created.value();
    auto socket =
        std::make_unique<udp::Socket>(udp::Socket::bind(loop, Endpoint::loopback(0)).value());
    std::array<std::byte, 32> buffer{};
    bool done = false;
    receive_and_destroy(socket->receive_from(buffer), socket, done);
    socket->close();
    drain(loop);
    CHECK(done);
    CHECK(!socket);

    auto original = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    const auto endpoint = original.local_endpoint().value();
    std::optional<Result<udp::Datagram>> received;
    collect(original.receive_from(buffer, budget()), received);
    auto moved = std::move(original);
    CHECK(!original.is_open());
    CHECK(moved.is_open());
    auto sender = udp::Socket::bind(loop, Endpoint::loopback(0)).value();
    std::optional<Result<std::size_t>> sent;
    collect(sender.send_to(bytes("moved"), endpoint, budget()), sent);
    drain(loop);
    CHECK(received && received->has_value() && (*received)->size == 5);

    // The regular entry point copies state immediately; a not-yet-started
    // Task never stores a dangling this.
    auto lazy = moved.receive_from(buffer);
    moved.close();
    received.reset();
    collect(std::move(lazy), received);
    CHECK(received && !*received && received->error() == Errc::invalid_argument);
    drain(loop);

    // Loop destruction drains kernel borrows first, then resumes coroutines;
    // the resume path may close and destroy the socket.
    auto shutdown_loop = std::make_unique<EventLoop>(EventLoop::create().value());
    auto shutdown_socket = std::make_unique<udp::Socket>(
        udp::Socket::bind(*shutdown_loop, Endpoint::loopback(0)).value());
    bool shutdown_done = false;
    receive_and_destroy(shutdown_socket->receive_from(buffer), shutdown_socket, shutdown_done);
    shutdown_loop.reset();
    CHECK(shutdown_done);
    CHECK(!shutdown_socket);
}
Task<void> packet_metadata_test(EventLoop& loop, Family family) {
    test::section("UDP pktinfo, traffic class, kernel timestamp and per-packet source");
    auto receiver = udp::Socket::bind(loop, Endpoint::any(0, family),
        {.receive_packet_info = true, .receive_traffic_class = true, .receive_timestamp = true});
#if MIRA_PLATFORM_WINDOWS
    CHECK(!receiver && receiver.error() == std::errc::not_supported);
    auto sender = udp::Socket::bind(loop, Endpoint::any(0, family)).value();
    const auto unsupported = co_await sender.send_message(bytes("x"), Endpoint::loopback(9, family),
        {.source = Endpoint::loopback(0, family)}, budget());
    CHECK(!unsupported && unsupported.error() == std::errc::not_supported);
#else
    CHECK(receiver.has_value());
    if (!receiver) co_return;
    auto sender = udp::Socket::bind(loop, Endpoint::any(0, family)).value();
    const auto peer = Endpoint::loopback(receiver->local_endpoint()->port(), family);
    const auto before = std::chrono::system_clock::now();
    const auto sent = co_await sender.send_message(bytes("metadata"), peer,
        {.source = Endpoint::loopback(0, family), .traffic_class = std::uint8_t{0x2a}}, budget());
    CHECK(sent.has_value());
    if (!sent) co_return;
    std::array<std::byte, 32> buffer{};
    const auto packet = co_await receiver->receive_from(buffer, budget());
    CHECK(packet.has_value());
    if (!packet) co_return;
    CHECK(packet->size == 8);
    CHECK(packet->peer == Endpoint::loopback(sender.local_endpoint()->port(), family));
    CHECK(packet->metadata.destination == peer);
    CHECK(packet->metadata.interface_index && *packet->metadata.interface_index > 0);
    CHECK(packet->metadata.traffic_class == std::uint8_t{0x2a});
    CHECK(packet->metadata.timestamp.has_value());
    CHECK(packet->metadata.timestamp && *packet->metadata.timestamp >= before - 1s);
    CHECK(packet->metadata.timestamp && *packet->metadata.timestamp <= std::chrono::system_clock::now() + 1s);
    CHECK(!packet->metadata.truncated);
    const auto reply = co_await receiver->send_message(bytes("reply"), packet->peer,
        {.source = Endpoint::loopback(0, family),
         .interface_index = *packet->metadata.interface_index}, budget());
    CHECK(reply.has_value());
    CHECK((co_await sender.receive_from(buffer, budget())).has_value());
    const auto invalid = co_await sender.send_message(bytes("x"), peer,
        {.source = Endpoint::loopback(9, family)}, budget());
    CHECK(!invalid && invalid.error() == Errc::invalid_argument);
#endif
}

void multicast_ipv6_options(EventLoop& loop) {
    test::section("UDP IPv6 multicast interface, hop limit and membership");
    auto socket = udp::Socket::bind(loop, Endpoint::any(0, Family::ipv6)).value();
    CHECK(socket.set_multicast_hops(7).has_value());
    CHECK(socket.set_multicast_loopback(false).has_value());
#if MIRA_HAS_READINESS_API
    int hops = -1;
    socklen_t size = sizeof(hops);
    CHECK(::getsockopt(socket.native_handle(), IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, &size) == 0);
    CHECK(hops == 7);
    unsigned enabled = 1;
    size = sizeof(enabled);
    CHECK(::getsockopt(socket.native_handle(), IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &enabled, &size) == 0);
    CHECK(enabled == 0);
    auto index = ::if_nametoindex("lo0");
    if (index == 0) index = ::if_nametoindex("lo");
    CHECK(index != 0);
    if (index != 0) {
        udp::MulticastInterface interface{.ipv6_index = index};
        CHECK(socket.set_multicast_interface(interface).has_value());
        const auto group = Endpoint::parse("ff02::114", 0).value();
        CHECK(socket.join_multicast(group, interface).has_value());
        CHECK(socket.leave_multicast(group, interface).has_value());
    }
#endif
}

Task<void> multicast_test(EventLoop& loop) {
    test::section("UDP IPv4 multicast membership, outgoing interface, TTL and leave");
    auto receiver = udp::Socket::bind(loop, Endpoint::any(0), {.reuse_address = true}).value();
    const auto group = Endpoint::parse("239.255.42.99", receiver.local_endpoint()->port()).value();
    udp::MulticastInterface interface{.ipv4_address = Endpoint::loopback(0)};
    CHECK(!receiver.join_multicast(Endpoint::loopback(0), interface));
    CHECK(!receiver.set_multicast_hops(256));
    CHECK(receiver.join_multicast(group, interface).has_value());
    auto sender = udp::Socket::bind(loop, Endpoint::any(0)).value();
    CHECK(sender.set_multicast_interface(interface).has_value());
    CHECK(sender.set_multicast_hops(0).has_value());
    CHECK(sender.set_multicast_loopback(true).has_value());
#if MIRA_HAS_READINESS_API
    unsigned char hops = 255;
    socklen_t size = sizeof(hops);
    CHECK(::getsockopt(sender.native_handle(), IPPROTO_IP, IP_MULTICAST_TTL, &hops, &size) == 0);
    CHECK(hops == 0);
    in_addr selected{};
    size = sizeof(selected);
    CHECK(::getsockopt(sender.native_handle(), IPPROTO_IP, IP_MULTICAST_IF, &selected, &size) == 0);
    CHECK(ntohl(selected.s_addr) == 0x7f000001U);
#endif
    CHECK((co_await sender.send_to(bytes("group"), group, budget())).has_value());
    std::array<std::byte, 32> buffer{};
    const auto packet = co_await receiver.receive_from(buffer, budget());
    CHECK(packet.has_value() && packet->size == 5);
    CHECK(receiver.leave_multicast(group, interface).has_value());
    CHECK((co_await sender.send_to(bytes("left"), group, budget())).has_value());
    const auto left = co_await receiver.receive_from(buffer, {.deadline = Clock::now() + 20ms});
    CHECK(!left && left.error() == Errc::timed_out);
}

}  // namespace

int main() {
    // A runtime probe, not a build-time guess: sandboxes and some CI runners
    // have no IPv6 at all, and there is no code path to test when the kernel
    // refuses the very first bind. Skipping loudly beats failing on hardware
    // the library never promised.
    bool ipv6_usable = false;
    {
        auto probe = EventLoop::create();
        if (probe) {
            const auto bound = udp::Socket::bind(*probe, Endpoint::loopback(0, Family::ipv6));
            ipv6_usable = bound.has_value();
        }
    }

    for (const auto family : {Family::ipv4, Family::ipv6}) {
        if (family == Family::ipv6 && !ipv6_usable) {
            test::section("IPv6 datagrams (no IPv6 in this environment, skipped)");
            continue;
        }
        test::section(family == Family::ipv4 ? "IPv4 datagrams" : "IPv6 datagrams");
        auto created = EventLoop::create();
        auto& loop = created.value();
        CHECK(loop.run_until_complete(packets(loop, family)).has_value());
        CHECK(loop.run_until_complete(packet_metadata_test(loop, family)).has_value());
        CHECK(loop.outstanding() == 0);
    }
    {
        auto loop = EventLoop::create().value();
        CHECK(loop.run_until_complete(multicast_test(loop)).has_value());
        if (ipv6_usable) multicast_ipv6_options(loop);
    }
    concurrency_and_cancel();
    close_lifetimes();
    close_ready_batch();
    return test::summary();
}
