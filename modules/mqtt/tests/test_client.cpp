// mqtt::Client over real TCP loopback against a small broker written in this
// test on top of the server-role codec: CONNECT/CONNACK, subscription routing
// with QoS downgrade, both QoS 2 directions, PINGREQ accounting, 3.1.1 and 5.0,
// refusal, and keep-alive running as a concurrent writer beside a reader.

#include "check.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/mqtt/client.hpp"
#include "mira/transport/tcp.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <map>
#include <string>
#include <vector>

using namespace Mira;
using namespace Mira::mqtt;
using namespace std::chrono_literals;
using Socket = transport::tcp::Socket;

namespace {

Bytes text(std::string_view value) {
    const auto view = std::as_bytes(std::span{value.data(), value.size()});
    return Bytes(view.begin(), view.end());
}
std::string str(const Bytes& bytes) { return {reinterpret_cast<const char*>(bytes.data()), bytes.size()}; }

struct BrokerStats {
    int pings = 0;
    int publishes = 0;
    bool disconnected = false;
    std::optional<Version> version;
};

// One client, one connection; routes publishes back to matching subscriptions.
Task<void> broker(Socket peer, BrokerStats& stats, std::uint8_t refuse = 0, std::uint16_t server_keep_alive = 0) {
    Version version = Version::v5;
    Bytes pending;
    std::map<std::string, QoS> subscriptions;
    std::uint16_t next_id = 1;
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
            CHECK(decoded.has_value());
            if (!decoded || !decoded->packet) break;
            pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(decoded->consumed));
            auto& packet = *decoded->packet;
            std::vector<Packet> replies;
            if (auto* c = std::get_if<Connect>(&packet)) {
                version = c->version;
                stats.version = version;
                Connack ack{false, refuse, {}};
                if (version == Version::v5 && !refuse) {
                    if (c->client_id.empty()) ack.properties.assigned_client_identifier = "assigned-1";
                    if (server_keep_alive) ack.properties.server_keep_alive = server_keep_alive;
                }
                replies.push_back(ack);
            } else if (auto* s = std::get_if<Subscribe>(&packet)) {
                Suback ack{s->packet_id, {}, {}};
                for (const auto& sub : s->subscriptions) {
                    subscriptions[sub.filter] = sub.qos;
                    ack.reasons.push_back(static_cast<std::uint8_t>(sub.qos));
                }
                replies.push_back(ack);
            } else if (auto* u = std::get_if<Unsubscribe>(&packet)) {
                Unsuback ack{u->packet_id, {}, {}};
                for (const auto& filter : u->filters) {
                    subscriptions.erase(filter);
                    if (version == Version::v5) ack.reasons.push_back(reason::success);
                }
                replies.push_back(ack);
            } else if (auto* p = std::get_if<Publish>(&packet)) {
                ++stats.publishes;
                if (p->qos == QoS::at_least_once) replies.push_back(Ack{PacketType::puback, p->packet_id, reason::success, {}});
                if (p->qos == QoS::exactly_once) replies.push_back(Ack{PacketType::pubrec, p->packet_id, reason::success, {}});
                for (const auto& [filter, granted] : subscriptions) {
                    if (!topic_matches(filter, p->topic)) continue;
                    Publish out;
                    out.topic = p->topic;
                    out.payload = p->payload;
                    out.qos = std::min(p->qos, granted);
                    if (out.qos != QoS::at_most_once) out.packet_id = next_id++;
                    replies.push_back(out);
                }
            } else if (auto* a = std::get_if<Ack>(&packet)) {
                if (a->type == PacketType::pubrel) replies.push_back(Ack{PacketType::pubcomp, a->packet_id, reason::success, {}});
                if (a->type == PacketType::pubrec) replies.push_back(Ack{PacketType::pubrel, a->packet_id, reason::success, {}});
            } else if (std::holds_alternative<Pingreq>(packet)) {
                ++stats.pings;
                replies.push_back(Pingresp{});
            } else if (std::holds_alternative<Disconnect>(packet)) {
                stats.disconnected = true;
                co_return;
            }
            for (const auto& reply : replies) {
                auto sent = co_await send(reply);
                if (!sent) co_return;
            }
            if (refuse) co_return;
        }
    }
}

Task<void> exchange(EventLoop& loop, Version version) {
    test::section(version == Version::v5 ? "5.0 publish/subscribe over TCP" : "3.1.1 publish/subscribe over TCP");
    auto listener = transport::tcp::Listener::bind(loop, transport::Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    BrokerStats stats;
    TaskScope scope;
    auto serve = [&]() -> Task<void> {
        auto peer = co_await listener->accept();
        if (peer) co_await broker(std::move(*peer), stats);
    };
    scope.spawn(serve());
    auto stream = co_await transport::tcp::connect(loop, listener->local_endpoint());
    CHECK(stream.has_value());
    if (!stream) co_return;
    ClientOptions options;
    options.version = version;
    options.client_id = version == Version::v5 ? "" : "v3-client";
    options.keep_alive = 0;
    const OperationOptions io{.deadline = Clock::now() + 10s};
    auto connected = co_await Client<Socket>::connect(*stream, options, io);
    CHECK(connected.has_value());
    if (!connected) co_return;
    auto& client = *connected;
    CHECK(stats.version == version);
    if (version == Version::v5) CHECK(client.session().client_id() == "assigned-1");
    // Braced arguments stay out of co_await expressions: GCC 13/14 ICE on them.
    const Properties none;
    std::vector<Subscription> filters(2);
    filters[0] = {"test/+", QoS::exactly_once, false, false, 0};
    filters[1] = {"other/#", QoS::at_least_once, false, false, 0};
    auto sub = co_await client.subscribe(std::move(filters), none, io);
    CHECK(sub.has_value());
    auto granted = co_await client.wait_for(*sub, io);
    CHECK(granted && granted->kind == Event::Kind::subscribed &&
          granted->reasons == std::vector<std::uint8_t>({2, 1}));
    std::vector<std::uint16_t> ids;
    for (const auto qos : {QoS::at_most_once, QoS::at_least_once, QoS::exactly_once}) {
        auto payload = text("qos" + std::to_string(static_cast<int>(qos)));
        auto id = co_await client.publish("test/a", std::move(payload), qos, false, none, io);
        CHECK(id.has_value());
        if (id && *id) ids.push_back(*id);
    }
    auto downgraded = text("downgraded");
    auto other = co_await client.publish("other/x/y", std::move(downgraded), QoS::exactly_once, false, none, io);
    CHECK(other.has_value());
    if (other) ids.push_back(*other);
    for (const auto id : ids) {
        auto done = co_await client.wait_for(id, io);
        CHECK(done && done->kind == Event::Kind::published && done->reason == reason::success);
    }
    std::map<std::string, QoS> received;
    while (received.size() < 4) {
        auto events = co_await client.receive(io);
        CHECK(events.has_value());
        if (!events) break;
        for (const auto& event : *events)
            if (event.kind == Event::Kind::message) received[str(event.message.payload)] = event.message.qos;
    }
    CHECK(received["qos0"] == QoS::at_most_once && received["qos1"] == QoS::at_least_once &&
          received["qos2"] == QoS::exactly_once && received["downgraded"] == QoS::at_least_once);
    CHECK(client.session().inflight() == 0);
    std::vector<std::string> removed_filters(1, "test/+");
    auto unsub = co_await client.unsubscribe(std::move(removed_filters), none, io);
    CHECK(unsub.has_value());
    auto removed = co_await client.wait_for(*unsub, io);
    CHECK(removed && removed->kind == Event::Kind::unsubscribed);
    auto bye = co_await client.disconnect(reason::success, none, io);
    CHECK(bye.has_value() && client.closed());
    co_await scope.join();
    CHECK(stats.disconnected && stats.publishes == 4);
}

Task<void> keep_alive(EventLoop& loop) {
    test::section("keep-alive writer beside a blocked reader (server keep-alive 1 s)");
    auto listener = transport::tcp::Listener::bind(loop, transport::Endpoint::loopback(0));
    if (!listener) co_return;
    BrokerStats stats;
    TaskScope scope;
    auto serve = [&]() -> Task<void> {
        auto peer = co_await listener->accept();
        if (peer) co_await broker(std::move(*peer), stats, 0, 1);
    };
    scope.spawn(serve());
    auto stream = co_await transport::tcp::connect(loop, listener->local_endpoint());
    if (!stream) co_return;
    ClientOptions options;
    options.client_id = "pinger";
    options.keep_alive = 30;  // The server's keep-alive overrides it.
    auto connected = co_await Client<Socket>::connect(*stream, options, {.deadline = Clock::now() + 10s});
    CHECK(connected.has_value());
    if (!connected) co_return;
    auto& client = *connected;
    CHECK(client.session().keep_alive() == 1);
    std::stop_source stop;
    Result<void> kept;
    Result<std::vector<Event>> read;
    TaskScope duplex;
    auto keeper = [&]() -> Task<void> { kept = co_await client.keep_alive(loop, {.stop = stop.get_token()}); };
    auto reader = [&]() -> Task<void> { read = co_await client.receive({.stop = stop.get_token()}); };
    duplex.spawn(keeper());
    duplex.spawn(reader());
    auto slept = co_await loop.sleep_for(2600ms);
    CHECK(slept.has_value());
    stop.request_stop();
    co_await duplex.join();
    CHECK(stats.pings >= 2);
    CHECK(!kept && kept.error() == Errc::cancelled);
    CHECK(!read && read.error() == Errc::cancelled);
    CHECK(!client.closed());
    const Properties none;
    const OperationOptions finish{.deadline = Clock::now() + 5s};
    auto bye = co_await client.disconnect(reason::success, none, finish);
    CHECK(bye.has_value());
    co_await scope.join();
    CHECK(stats.disconnected);
}

Task<void> refusal(EventLoop& loop) {
    test::section("refused CONNECT");
    auto listener = transport::tcp::Listener::bind(loop, transport::Endpoint::loopback(0));
    if (!listener) co_return;
    BrokerStats stats;
    TaskScope scope;
    auto serve = [&]() -> Task<void> {
        auto peer = co_await listener->accept();
        if (peer) co_await broker(std::move(*peer), stats, reason::bad_user_name_or_password);
    };
    scope.spawn(serve());
    auto stream = co_await transport::tcp::connect(loop, listener->local_endpoint());
    if (!stream) co_return;
    ClientOptions options;
    options.client_id = "nope";
    options.username = "u";
    options.password = text("wrong");
    auto connected = co_await Client<Socket>::connect(*stream, options, {.deadline = Clock::now() + 10s});
    CHECK(!connected && connected.error() == MqttError::refused);
    co_await scope.join();
}

Task<void> run(EventLoop& loop) {
    co_await exchange(loop, Version::v5);
    co_await exchange(loop, Version::v311);
    co_await keep_alive(loop);
    co_await refusal(loop);
}

}  // namespace

int main() {
    auto loop = EventLoop::create();
    if (!loop) return 1;
    if (!loop->run_until_complete(run(*loop))) return 1;
    return test::summary();
}
