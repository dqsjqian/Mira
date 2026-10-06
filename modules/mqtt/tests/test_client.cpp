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
#include <stdexcept>
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

struct IoGate {
    std::coroutine_handle<> waiter;
    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept { waiter = handle; }
    void await_resume() const noexcept {}
    void release() { std::exchange(waiter, {}).resume(); }
};

struct ScriptedBroker {
    std::deque<Bytes> input;
    Bytes output;
    std::optional<std::size_t> write_budget;
    bool throw_write = false;
    bool throw_read = false;
    std::size_t reads = 0;
    std::size_t writes = 0;
    IoGate* read_gate = nullptr;
    IoGate* write_gate = nullptr;
    Task<Result<std::size_t>> read_some(std::span<std::byte> out, OperationOptions = {}) {
        ++reads;
        // The controller may clear the member while this operation is parked.
        // Keep the awaited gate's identity in the coroutine frame through resume.
        if (auto* const gate = read_gate) co_await *gate;
        if (throw_read) throw std::runtime_error("scripted read failure");
        if (input.empty()) co_return fail(Errc::timed_out);
        const auto n = std::min(out.size(), input.front().size());
        std::copy_n(input.front().begin(), n, out.begin());
        input.front().erase(input.front().begin(), input.front().begin() + static_cast<std::ptrdiff_t>(n));
        if (input.front().empty()) input.pop_front();
        co_return n;
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes, OperationOptions = {}) {
        ++writes;
        if (auto* const gate = write_gate) co_await *gate;
        if (write_budget) {
            if (*write_budget == 0) {
                if (throw_write) throw std::runtime_error("scripted write failure");
                co_return fail(Errc::timed_out);
            }
            bytes = bytes.first(std::min(bytes.size(), *write_budget));
            *write_budget -= bytes.size();
        }
        output.insert(output.end(), bytes.begin(), bytes.end());
        co_return bytes.size();
    }
};
Task<void> bounded_events_and_auth() {
    ScriptedBroker broker;
    broker.input.push_back(*encode(Connack{}, Version::v5));
    ClientOptions options;
    options.client_id = "bounded";
    options.max_events = 1;
    auto client = co_await Client<ScriptedBroker>::connect(broker, options);
    CHECK(client.has_value());
    if (!client) co_return;
    Publish message;
    message.topic = "flood";
    message.payload = text("x");
    for (int i = 0; i < 1000; ++i) broker.input.push_back(*encode(message, Version::v5));
    auto wait = co_await client->wait_for(42);
    CHECK(!wait && wait.error() == Errc::limit_exceeded);
    CHECK(client->closed());
    auto buffered = co_await client->receive();
    CHECK(buffered && buffered->size() == 1);

    ScriptedBroker authenticated;
    Auth challenge;
    challenge.reason = 0x18;
    challenge.properties.authentication_method = "test";
    authenticated.input.push_back(*encode(challenge, Version::v5));
    Connack authenticated_ack;
    authenticated_ack.properties.authentication_method = "test";
    authenticated.input.push_back(*encode(authenticated_ack, Version::v5));
    options.max_events = 4;
    options.properties.authentication_method = "test";
    bool called = false;
    auto answer = [&called](const Event& event, OperationOptions) -> Task<Result<Auth>> {
        called = true;
        CHECK(event.kind == Event::Kind::auth && event.reason == 0x18);
        Auth response;
        response.reason = 0x18;
        response.properties.authentication_method = "test";
        response.properties.authentication_data = text("proof");
        co_return response;
    };
    auto connected = co_await Client<ScriptedBroker>::connect(authenticated, options, {}, answer);
    CHECK(connected.has_value() && called);
    auto first = decode(authenticated.output, Version::v5, Role::server);
    CHECK(first && first->packet && std::holds_alternative<Connect>(*first->packet));
    if (first) {
        auto second_packet = decode(std::span<const std::byte>(authenticated.output).subspan(first->consumed),
                                    Version::v5, Role::server);
        CHECK(second_packet && second_packet->packet && std::holds_alternative<Auth>(*second_packet->packet));
    }

    // Reconnect must account for already buffered client events before it
    // clears outstanding publishes or writes CONNECT to the fresh transport.
    ScriptedBroker previous;
    previous.input.push_back(*encode(Connack{}, Version::v5));
    ClientOptions reconnect_options;
    reconnect_options.client_id = "reconnect-budget";
    reconnect_options.max_events = 1;
    auto pending = co_await Client<ScriptedBroker>::connect(previous, reconnect_options);
    CHECK(pending.has_value());
    if (!pending) co_return;
    CHECK((co_await pending->publish("pending", text("payload"), QoS::at_least_once)).has_value());
    previous.input.push_back(*encode(message, Version::v5));
    CHECK(!(co_await pending->wait_for(42)));
    ScriptedBroker fresh;
    fresh.input.push_back(*encode(Connack{}, Version::v5));
    auto retried = co_await pending->reconnect(fresh);
    CHECK(!retried && retried.error() == Errc::would_block);
    CHECK(fresh.output.empty() && pending->session().inflight() == 1);
    auto preserved = co_await pending->receive();
    CHECK(preserved && preserved->size() == 1 && preserved->front().kind == Event::Kind::message);
    const auto old_size = previous.output.size();
    auto original_transport = co_await pending->publish("still-original", text("x"));
    CHECK(original_transport.has_value());
    CHECK(previous.output.size() > old_size && fresh.output.empty());
}

Task<void> transport_failure_state() {
    test::section("MQTT transport errors are sticky, exceptions preserve resume state");
    for (bool throwing : {false, true}) {
        ScriptedBroker old;
        old.input.push_back(*encode(Connack{}, Version::v5));
        ClientOptions options;
        options.client_id = "failure-state";
        options.clean_start = false;
        auto client = co_await Client<ScriptedBroker>::connect(old, options);
        CHECK(client.has_value());
        if (!client) continue;
        old.write_budget = 1;  // Accept the fixed-header byte, then fail.
        old.throw_write = throwing;
        bool caught = false;
        try {
            auto sent = co_await client->publish("resume", text("payload"), QoS::at_least_once);
            CHECK(!sent && sent.error() == Errc::timed_out && !throwing);
        } catch (const std::runtime_error&) {
            caught = true;
        }
        CHECK(caught == throwing);
        CHECK(client->closed());
        const auto reads_before = old.reads;
        const auto expected = throwing ? Errc::internal : Errc::timed_out;
        auto read = co_await client->receive();
        CHECK(!read && read.error() == expected);
        auto wait = co_await client->wait_for(1);
        CHECK(!wait && wait.error() == expected);
        CHECK(old.reads == reads_before);
        old.write_budget.reset();
        const auto bytes_before = old.output.size();
        auto rejected = co_await client->publish("later", text("x"));
        CHECK(!rejected && rejected.error() == expected);
        CHECK(old.output.size() == bytes_before);

        ScriptedBroker fresh;
        Connack resumed;
        resumed.session_present = true;
        fresh.input.push_back(*encode(resumed, Version::v5));
        auto recovered = co_await client->reconnect(fresh);
        CHECK(recovered.has_value());
        auto connect_packet = decode(fresh.output, Version::v5, Role::server);
        CHECK(connect_packet && connect_packet->packet);
        if (connect_packet && connect_packet->packet) {
            auto replay = decode(std::span<const std::byte>{fresh.output}.subspan(connect_packet->consumed),
                                 Version::v5, Role::server);
            CHECK(replay && replay->packet && std::holds_alternative<Publish>(*replay->packet));
            if (replay && replay->packet && std::holds_alternative<Publish>(*replay->packet)) {
                const auto& p = std::get<Publish>(*replay->packet);
                CHECK(p.dup && p.topic == "resume" && str(p.payload) == "payload");
            }
        }
    }
    ScriptedBroker old;
    old.input.push_back(*encode(Connack{}, Version::v5));
    ClientOptions options;
    options.client_id = "read-failure";
    auto client = co_await Client<ScriptedBroker>::connect(old, options);
    CHECK(client.has_value());
    if (!client) co_return;
    old.throw_read = true;
    bool caught = false;
    try { static_cast<void>(co_await client->receive()); }
    catch (const std::runtime_error&) { caught = true; }
    CHECK(caught && client->closed());
    old.throw_read = false;
    const auto reads_before = old.reads;
    auto read = co_await client->receive();
    CHECK(!read && read.error() == Errc::internal && old.reads == reads_before);
}

Task<void> duplex_failure_state() {
    test::section("MQTT late I/O completion cannot revive a failed connection");
    for (const bool reading_first : {true, false}) {
        ScriptedBroker broker;
        broker.input.push_back(*encode(Connack{}, Version::v5));
        ClientOptions options;
        options.client_id = "duplex-failure";
        auto client = co_await Client<ScriptedBroker>::connect(broker, options);
        CHECK(client.has_value());
        if (!client) continue;
        TaskScope scope;
        IoGate gate;
        Result<std::vector<Event>> read;
        Result<std::uint16_t> sent;
        auto reader = [&]() -> Task<void> { read = co_await client->receive(); };
        auto writer = [&]() -> Task<void> { sent = co_await client->publish("late", text("payload")); };
        if (reading_first) {
            Publish inbound;
            inbound.topic = "late-inbound";
            inbound.payload = text("payload");
            broker.input.push_back(*encode(inbound, Version::v5));
            broker.read_gate = &gate;
            scope.spawn(reader());
            broker.write_budget = 0;
            broker.throw_write = true;
            bool caught = false;
            try { static_cast<void>(co_await client->publish("fail", text("x"))); }
            catch (const std::runtime_error&) { caught = true; }
            CHECK(caught);
            broker.read_gate = nullptr;
            gate.release();
            co_await scope.join();
            CHECK(!read && read.error() == Errc::internal);
            auto next = co_await client->receive();
            CHECK(!next && next.error() == Errc::internal);  // No late message surfaced.
        } else {
            broker.write_gate = &gate;
            broker.write_budget = 1;
            const auto writes_before = broker.writes;
            scope.spawn(writer());
            broker.throw_read = true;
            bool caught = false;
            try { static_cast<void>(co_await client->receive()); }
            catch (const std::runtime_error&) { caught = true; }
            CHECK(caught);
            broker.write_gate = nullptr;
            gate.release();
            co_await scope.join();
            CHECK(!sent && sent.error() == Errc::internal);
            CHECK(broker.writes == writes_before + 1);  // No second short-write submission.
        }
    }
}

Task<void> persistence_events() {
    test::section("client checkpoints retain delivery events and packet identifiers");
    ClientOptions options;
    options.client_id = "persistent";
    options.clean_start = false;
    auto session = Session::create(options);
    CHECK(session.has_value());
    if (!session) co_return;
    CHECK(session->connect(0).has_value());
    static_cast<void>(session->take_output(0));
    CHECK(session->receive(*encode(Connack{}, Version::v5), 0).has_value());
    static_cast<void>(session->take_events());
    Publish expiring;
    expiring.topic = "expired";
    expiring.qos = QoS::at_least_once;
    expiring.properties.message_expiry_interval = 1;
    CHECK(session->publish(expiring) == 1);
    auto image = session->checkpoint("broker/tenant");
    CHECK(image.has_value());
    if (!image) co_return;
    ScriptedBroker resumed;
    resumed.input.push_back(*encode(Connack{true, 0, {}}, Version::v5));
    auto client = co_await Client<ScriptedBroker>::restore(resumed, options, *image, "broker/tenant", {}, 1);
    CHECK(client.has_value());
    if (!client) co_return;
    auto id = co_await client->publish("new", {}, QoS::at_least_once);
    CHECK(id && *id != 1);
    auto waiting = co_await client->wait_for(*id);
    CHECK(!waiting && waiting.error() == Errc::timed_out);
    CHECK(!client->checkpoint("broker/tenant"));
    auto notices = co_await client->receive();
    CHECK(notices && notices->size() == 1 && notices->front().discarded && notices->front().packet_id == 1);
    CHECK(client->checkpoint("broker/tenant").has_value());
    options.max_events = 1;
    ScriptedBroker tiny;
    tiny.input.push_back(*encode(Connack{true, 0, {}}, Version::v5));
    auto bounded = co_await Client<ScriptedBroker>::restore(tiny, options, *image, "broker/tenant", {}, 1);
    CHECK(bounded.has_value());
    if (bounded) {
        auto events = co_await bounded->receive();
        CHECK(events && events->size() == 1 && events->front().discarded);
    }
    options.max_events = 4;
    ScriptedBroker incoming;
    auto batch = *encode(Connack{}, Version::v5);
    Publish inbound;
    inbound.topic = "unconsumed"; inbound.qos = QoS::exactly_once; inbound.packet_id = 9;
    auto wire = *encode(inbound, Version::v5);
    batch.insert(batch.end(), wire.begin(), wire.end());
    incoming.input.push_back(batch);
    auto owner = co_await Client<ScriptedBroker>::connect(incoming, options);
    CHECK(owner.has_value());
    if (owner) {
        CHECK(owner->checkpoint("broker/tenant").error() == Errc::would_block);
        CHECK(owner->session().checkpoint("broker/tenant").error() == Errc::not_supported);
        auto received = co_await owner->receive();
        CHECK(received && received->size() == 1 && received->front().kind == Event::Kind::message);
        CHECK(owner->checkpoint("broker/tenant").has_value());
    }
}

Task<void> run(EventLoop& loop) {
    co_await persistence_events();
    co_await bounded_events_and_auth();
    co_await transport_failure_state();
    co_await duplex_failure_state();
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
