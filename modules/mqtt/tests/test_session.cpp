// The socket-free session against a scripted broker that speaks through the
// same codec in the server role, so every byte the session emits is also
// validated as a broker would.

#include "check.hpp"
#include "mira/mqtt/session.hpp"

#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>
#include <vector>

using namespace Mira;
using namespace Mira::mqtt;

namespace {

constexpr std::uint64_t second = 1'000'000'000;

Bytes text(std::string_view value) {
    const auto view = std::as_bytes(std::span{value.data(), value.size()});
    return Bytes(view.begin(), view.end());
}

struct Broker {
    Version version = Version::v5;
    Bytes pending;
    // Everything the session wrote, decoded as a server would.
    std::vector<Packet> take(Session& session, std::uint64_t now = 0) {
        const auto out = session.take_output(now);
        pending.insert(pending.end(), out.begin(), out.end());
        std::vector<Packet> packets;
        for (;;) {
            auto decoded = decode(pending, version, Role::server);
            if (!decoded) {
                std::fprintf(stderr, "broker could not decode session output: %s\n", decoded.error().message().c_str());
                ::Mira::test::report(false, "session output decodes", __FILE__, __LINE__);
                pending.clear();
                break;
            }
            if (!decoded->packet) break;
            if (const auto* c = std::get_if<Connect>(&*decoded->packet)) version = c->version;
            packets.push_back(std::move(*decoded->packet));
            pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(decoded->consumed));
        }
        return packets;
    }
    Result<void> send(Session& session, const Packet& packet, std::uint64_t now = 0) {
        auto wire = encode(packet, version);
        if (!wire) return fail(wire.error());
        return session.receive(*wire, now);
    }
};

Session make(ClientOptions options) {
    auto session = Session::create(std::move(options));
    if (!session) {
        std::fprintf(stderr, "create failed: %s\n", session.error().message().c_str());
        std::exit(1);
    }
    return std::move(*session);
}

Session connected(Broker& broker, ClientOptions options, Connack connack = {}) {
    auto session = make(std::move(options));
    CHECK(session.connect(0).has_value());
    broker.take(session);
    CHECK(broker.send(session, connack).has_value());
    CHECK(session.state() == SessionState::connected);
    static_cast<void>(session.take_events());
    return session;
}

Publish publish(std::string topic, QoS qos, std::uint16_t id = 0, std::string_view payload = "x") {
    Publish p;
    p.topic = std::move(topic);
    p.qos = qos;
    p.packet_id = id;
    p.payload = text(payload);
    return p;
}

void connect_limits() {
    test::section("CONNECT advertises our limits, CONNACK imposes the server's");
    Broker broker;
    ClientOptions options;
    options.keep_alive = 10;
    options.receive_maximum = std::uint16_t{2};
    options.topic_alias_maximum = std::uint16_t{2};
    options.maximum_packet_size = 2048;
    options.properties.session_expiry_interval = std::uint32_t{120};
    auto session = make(options);
    CHECK(session.state() == SessionState::idle);
    CHECK(!session.publish(publish("a", QoS::at_most_once)));
    CHECK(session.connect(0).has_value());
    CHECK(!session.publish(publish("a", QoS::at_most_once)));  // Not before CONNACK.
    auto sent = broker.take(session);
    CHECK(sent.size() == 1 && std::holds_alternative<Connect>(sent[0]));
    const auto& connect = std::get<Connect>(sent[0]);
    CHECK(connect.client_id.empty() && connect.clean_start && connect.keep_alive == 10);
    CHECK(connect.properties.receive_maximum == std::uint16_t{2} && connect.properties.maximum_packet_size == std::uint32_t{2048} &&
          connect.properties.topic_alias_maximum == std::uint16_t{2} && connect.properties.session_expiry_interval == std::uint32_t{120});
    Connack ack;
    ack.properties.receive_maximum = std::uint16_t{2};
    ack.properties.maximum_qos = std::uint8_t{1};
    ack.properties.retain_available = std::uint8_t{0};
    ack.properties.server_keep_alive = std::uint16_t{5};
    ack.properties.assigned_client_identifier = "auto-7";
    ack.properties.maximum_packet_size = std::uint32_t{512};
    CHECK(broker.send(session, ack).has_value());
    auto events = session.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::connected && !events[0].session_present &&
          events[0].properties.assigned_client_identifier == "auto-7");
    CHECK(session.client_id() == "auto-7" && session.keep_alive() == 5 && session.server_receive_maximum() == 2);
    CHECK(session.publish(publish("a", QoS::exactly_once)).error() == Errc::not_supported);
    auto retained = publish("a", QoS::at_most_once);
    retained.retain = true;
    CHECK(session.publish(retained).error() == Errc::not_supported);
    CHECK(session.publish(publish("a", QoS::at_most_once, 0, std::string(600, 'x'))).error() ==
          MqttError::packet_too_large);
    const auto first = session.publish(publish("a", QoS::at_least_once));
    const auto second_id = session.publish(publish("b", QoS::at_least_once));
    CHECK(first && second_id && *first != *second_id && session.inflight() == 2);
    CHECK(session.publish(publish("c", QoS::at_least_once)).error() == Errc::would_block);
    sent = broker.take(session);
    CHECK(sent.size() == 2 && std::get<Publish>(sent[0]).packet_id == *first && !std::get<Publish>(sent[0]).dup);
    CHECK(broker.send(session, Ack{PacketType::puback, *first, reason::no_matching_subscribers, {}}).has_value());
    events = session.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::published && events[0].packet_id == *first &&
          events[0].reason == reason::no_matching_subscribers);
    CHECK(session.publish(publish("c", QoS::at_least_once)).has_value());
    CHECK(broker.send(session, Ack{PacketType::puback, *first, reason::success, {}}).has_value());  // Stale: ignored.
    CHECK(session.take_events().empty());
}

void qos2_sender() {
    test::section("QoS 2 sender: PUBREC -> PUBREL -> PUBCOMP, failures and duplicates");
    Broker broker;
    auto session = connected(broker, {});
    const auto id = *session.publish(publish("q2", QoS::exactly_once));
    broker.take(session);
    CHECK(broker.send(session, Ack{PacketType::pubrec, id, reason::success, {}}).has_value());
    auto sent = broker.take(session);
    CHECK(sent.size() == 1 && std::get<Ack>(sent[0]).type == PacketType::pubrel && std::get<Ack>(sent[0]).packet_id == id);
    CHECK(broker.send(session, Ack{PacketType::pubrec, id, reason::success, {}}).has_value());
    sent = broker.take(session);
    CHECK(sent.size() == 1 && std::get<Ack>(sent[0]).type == PacketType::pubrel);
    CHECK(session.take_events().empty());
    CHECK(broker.send(session, Ack{PacketType::pubcomp, id, reason::success, {}}).has_value());
    auto events = session.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::published && events[0].packet_id == id);
    const auto refused = *session.publish(publish("q2", QoS::exactly_once));
    broker.take(session);
    CHECK(broker.send(session, Ack{PacketType::pubrec, refused, reason::not_authorized, {}}).has_value());
    events = session.take_events();
    CHECK(events.size() == 1 && events[0].reason == reason::not_authorized && session.inflight() == 0);
    CHECK(broker.take(session).empty());  // No PUBREL after a failed PUBREC.
    CHECK(broker.send(session, Ack{PacketType::pubrec, 999, reason::success, {}}).has_value());
    sent = broker.take(session);
    CHECK(sent.size() == 1 && std::get<Ack>(sent[0]).reason == reason::packet_identifier_not_found);
}

void inbound() {
    test::section("inbound QoS 1/2, duplicates, receive maximum");
    Broker broker;
    ClientOptions options;
    options.receive_maximum = std::uint16_t{2};
    auto session = connected(broker, options);
    CHECK(broker.send(session, publish("in/1", QoS::at_least_once, 3, "one")).has_value());
    auto events = session.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::message && events[0].message.topic == "in/1" &&
          events[0].message.payload == text("one") && events[0].message.qos == QoS::at_least_once);
    auto sent = broker.take(session);
    CHECK(sent.size() == 1 && std::get<Ack>(sent[0]).type == PacketType::puback && std::get<Ack>(sent[0]).packet_id == 3);
    CHECK(broker.send(session, publish("in/2", QoS::exactly_once, 5)).has_value());
    auto dup = publish("in/2", QoS::exactly_once, 5);
    dup.dup = true;
    CHECK(broker.send(session, dup).has_value());
    CHECK(session.take_events().size() == 1);  // Delivered once.
    sent = broker.take(session);
    CHECK(sent.size() == 2 && std::get<Ack>(sent[0]).type == PacketType::pubrec && std::get<Ack>(sent[1]).type == PacketType::pubrec);
    CHECK(broker.send(session, Ack{PacketType::pubrel, 5, reason::success, {}}).has_value());
    CHECK(broker.send(session, Ack{PacketType::pubrel, 6, reason::success, {}}).has_value());
    sent = broker.take(session);
    CHECK(sent.size() == 2 && std::get<Ack>(sent[0]).type == PacketType::pubcomp && std::get<Ack>(sent[0]).reason == 0 &&
          std::get<Ack>(sent[1]).reason == reason::packet_identifier_not_found);
    CHECK(broker.send(session, publish("in/3", QoS::exactly_once, 10)).has_value());
    CHECK(broker.send(session, publish("in/3", QoS::exactly_once, 11)).has_value());
    auto over = broker.send(session, publish("in/3", QoS::exactly_once, 12));
    CHECK(!over && over.error() == MqttError::receive_maximum_exceeded && session.state() == SessionState::closed);
    sent = broker.take(session);
    CHECK(!sent.empty() && std::holds_alternative<Disconnect>(sent.back()) &&
          std::get<Disconnect>(sent.back()).reason == reason::receive_maximum_exceeded);
    CHECK(session.publish(publish("a", QoS::at_most_once)).error() == Errc::eof);
}

void aliases() {
    test::section("inbound topic aliases");
    Broker broker;
    ClientOptions options;
    options.topic_alias_maximum = std::uint16_t{2};
    auto session = connected(broker, options);
    auto set = publish("alias/topic", QoS::at_most_once);
    set.properties.topic_alias = std::uint16_t{1};
    CHECK(broker.send(session, set).has_value());
    auto use = publish("", QoS::at_most_once);
    use.properties.topic_alias = std::uint16_t{1};
    CHECK(broker.send(session, use).has_value());
    auto events = session.take_events();
    CHECK(events.size() == 2 && events[0].message.topic == "alias/topic" && events[1].message.topic == "alias/topic");
    auto unknown = publish("", QoS::at_most_once);
    unknown.properties.topic_alias = std::uint16_t{2};
    auto failed = broker.send(session, unknown);
    CHECK(!failed && failed.error() == MqttError::topic_alias_invalid);
    auto other = connected(broker, options);
    auto beyond = publish("t", QoS::at_most_once);
    beyond.properties.topic_alias = std::uint16_t{3};
    failed = broker.send(other, beyond);
    CHECK(!failed && failed.error() == MqttError::topic_alias_invalid);
    auto sent = broker.take(other);
    CHECK(!sent.empty() && std::get<Disconnect>(sent.back()).reason == reason::topic_alias_invalid);
}

void subscriptions() {
    test::section("SUBSCRIBE / UNSUBSCRIBE and server capabilities");
    Broker broker;
    Connack ack;
    ack.properties.wildcard_subscription_available = std::uint8_t{0};
    ack.properties.shared_subscription_available = std::uint8_t{0};
    auto session = connected(broker, {}, ack);
    CHECK(session.subscribe({{"a/+", QoS::at_most_once, false, false, 0}}).error() == Errc::not_supported);
    CHECK(session.subscribe({{"$share/g/a", QoS::at_most_once, false, false, 0}}).error() == Errc::not_supported);
    const auto id = session.subscribe({{"a/b", QoS::at_least_once, false, false, 0}, {"c", QoS::exactly_once, false, false, 0}});
    CHECK(id.has_value());
    auto sent = broker.take(session);
    CHECK(sent.size() == 1 && std::get<Subscribe>(sent[0]).subscriptions.size() == 2);
    CHECK(broker.send(session, Suback{*id, {reason::granted_qos_1, reason::not_authorized}, {}}).has_value());
    auto events = session.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::subscribed &&
          events[0].reasons == std::vector<std::uint8_t>({reason::granted_qos_1, reason::not_authorized}));
    const auto unsub = session.unsubscribe({"a/b"});
    CHECK(unsub.has_value());
    broker.take(session);
    CHECK(broker.send(session, Unsuback{*unsub, {reason::success}, {}}).has_value());
    events = session.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::unsubscribed && events[0].packet_id == *unsub);
    const auto mismatch = session.subscribe({{"x", QoS::at_most_once, false, false, 0}});
    broker.take(session);
    auto failed = broker.send(session, Suback{*mismatch, {0, 0}, {}});
    CHECK(!failed && failed.error() == MqttError::protocol_error);
}

void keep_alive() {
    test::section("keep-alive: PINGREQ when idle, timeout without PINGRESP");
    Broker broker;
    ClientOptions options;
    options.keep_alive = 5;
    auto session = connected(broker, options);
    CHECK(session.next_timer() == 5 * second);
    CHECK(session.handle_timer(4 * second).has_value() && !session.has_output());
    CHECK(session.handle_timer(5 * second).has_value());
    auto sent = broker.take(session, 5 * second);
    CHECK(sent.size() == 1 && std::holds_alternative<Pingreq>(sent[0]));
    CHECK(session.next_timer() == 10 * second);
    CHECK(broker.send(session, Pingresp{}).has_value());
    CHECK(session.next_timer() == 10 * second);
    CHECK(session.publish(publish("t", QoS::at_most_once)).has_value());
    broker.take(session, 8 * second);
    CHECK(session.next_timer() == 13 * second);  // Output restarts the idle interval.
    CHECK(session.handle_timer(13 * second).has_value());
    broker.take(session, 13 * second);
    auto timeout = session.handle_timer(18 * second);
    CHECK(!timeout && timeout.error() == MqttError::keep_alive_timeout && session.state() == SessionState::closed);
    ClientOptions off;
    off.keep_alive = 0;
    auto idle = connected(broker, off);
    CHECK(idle.next_timer() == std::numeric_limits<std::uint64_t>::max());
}

void resume() {
    test::section("resumption: resend in order with DUP, or report discarded");
    Broker broker;
    ClientOptions options;
    options.client_id = "resume-me";
    options.clean_start = false;
    auto session = connected(broker, options);
    const auto a = *session.publish(publish("a", QoS::at_least_once));
    const auto b = *session.publish(publish("b", QoS::exactly_once));
    const auto c = *session.publish(publish("c", QoS::exactly_once));
    broker.take(session);
    CHECK(broker.send(session, Ack{PacketType::pubrec, c, reason::success, {}}).has_value());
    const auto pending_sub = *session.subscribe({{"s", QoS::at_most_once, false, false, 0}});
    broker.take(session);
    // The transport dies; a new one carries a fresh CONNECT.
    CHECK(session.connect(0).has_value());
    auto events = session.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::subscribed && events[0].discarded &&
          events[0].packet_id == pending_sub);
    auto sent = broker.take(session);
    CHECK(sent.size() == 1 && !std::get<Connect>(sent[0]).clean_start && std::get<Connect>(sent[0]).client_id == "resume-me");
    CHECK(broker.send(session, Connack{true, reason::success, {}}).has_value());
    sent = broker.take(session);
    CHECK(sent.size() == 3);
    if (sent.size() == 3) {
        const auto& pa = std::get<Publish>(sent[0]);
        const auto& pb = std::get<Publish>(sent[1]);
        const auto& rc = std::get<Ack>(sent[2]);
        CHECK(pa.packet_id == a && pa.dup && pa.payload == text("x"));
        CHECK(pb.packet_id == b && pb.dup && pb.qos == QoS::exactly_once);
        CHECK(rc.type == PacketType::pubrel && rc.packet_id == c);
    }
    CHECK(session.inflight() == 3);
    static_cast<void>(session.take_events());
    CHECK(session.connect(0).has_value());
    broker.take(session);
    CHECK(broker.send(session, Connack{false, reason::success, {}}).has_value());
    events = session.take_events();
    CHECK(events.size() == 4 && events[0].discarded && events[0].packet_id == a && events[1].packet_id == b &&
          events[2].packet_id == c && events[3].kind == Event::Kind::connected);
    CHECK(session.inflight() == 0);
    ClientOptions clean;
    clean.client_id = "clean";
    auto fresh = connected(broker, clean);
    static_cast<void>(fresh.publish(publish("a", QoS::at_least_once)));
    CHECK(fresh.connect(0).has_value());
    events = fresh.take_events();
    CHECK(events.size() == 1 && events[0].discarded && fresh.inflight() == 0);
}

void failures() {
    test::section("refusal, server DISCONNECT, violations, v3.1.1, AUTH");
    Broker v3;
    ClientOptions options;
    options.version = Version::v311;
    options.client_id = "v3";
    auto session = make(options);
    CHECK(session.connect(0).has_value());
    v3.take(session);
    auto refused = v3.send(session, Connack{false, 5, {}});
    CHECK(!refused && refused.error() == MqttError::refused && session.state() == SessionState::closed);
    auto events = session.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::connected && events[0].reason == 5);
    auto v3ok = connected(v3, options);
    const auto unsub = *v3ok.unsubscribe({"a"});
    v3.take(v3ok);
    CHECK(v3.send(v3ok, Unsuback{unsub, {}, {}}).has_value());
    events = v3ok.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::unsubscribed && events[0].reasons.empty());
    CHECK(v3ok.disconnect().has_value());
    auto sent = v3.take(v3ok);
    CHECK(sent.size() == 1 && std::holds_alternative<Disconnect>(sent[0]) && v3ok.state() == SessionState::closed);

    Broker broker;
    auto kicked = connected(broker, {});
    CHECK(broker.send(kicked, Disconnect{reason::session_taken_over, {}}).has_value());
    events = kicked.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::disconnected &&
          events[0].reason == reason::session_taken_over && kicked.state() == SessionState::closed);

    auto early = make({});
    CHECK(early.connect(0).has_value());
    broker.take(early);
    auto premature = broker.send(early, publish("t", QoS::at_most_once));
    CHECK(!premature && premature.error() == MqttError::protocol_error);

    auto liar = make({});
    CHECK(liar.connect(0).has_value());
    broker.take(liar);
    auto present = broker.send(liar, Connack{true, reason::success, {}});
    CHECK(!present && present.error() == MqttError::protocol_error);

    ClientOptions small;
    small.maximum_packet_size = 64;
    auto bounded = connected(broker, small);
    auto big = broker.send(bounded, publish("t", QoS::at_most_once, 0, std::string(100, 'x')));
    CHECK(!big && big.error() == MqttError::packet_too_large);
    sent = broker.take(bounded);
    CHECK(!sent.empty() && std::get<Disconnect>(sent.back()).reason == reason::packet_too_large);

    ClientOptions scram;
    scram.properties.authentication_method = "SCRAM-SHA-256";
    auto authing = make(scram);
    CHECK(authing.connect(0).has_value());
    sent = broker.take(authing);
    CHECK(std::get<Connect>(sent[0]).properties.authentication_method == "SCRAM-SHA-256");
    Auth challenge{reason::continue_authentication, {}};
    challenge.properties.authentication_method = "SCRAM-SHA-256";
    challenge.properties.authentication_data = text("server-first");
    CHECK(broker.send(authing, challenge).has_value());
    events = authing.take_events();
    CHECK(events.size() == 1 && events[0].kind == Event::Kind::auth && events[0].properties.authentication_data == text("server-first"));
    Properties answer;
    answer.authentication_method = "SCRAM-SHA-256";
    answer.authentication_data = text("client-final");
    CHECK(authing.auth(reason::continue_authentication, answer).has_value());
    sent = broker.take(authing);
    CHECK(sent.size() == 1 && std::get<Auth>(sent[0]).properties.authentication_data == text("client-final"));
    Connack authenticated_ack;
    authenticated_ack.properties.authentication_method = "SCRAM-SHA-256";
    CHECK(broker.send(authing, authenticated_ack).has_value() && authing.state() == SessionState::connected);

    ClientOptions invalid;
    invalid.properties.receive_maximum = std::uint16_t{5};
    CHECK(!Session::create(invalid));
    ClientOptions v3_alias;
    v3_alias.version = Version::v311;
    v3_alias.client_id = "c";
    v3_alias.topic_alias_maximum = std::uint16_t{1};
    CHECK(!Session::create(v3_alias));
}

void resume_reduced_limits() {
    Broker broker;
    ClientOptions options;
    options.client_id = "replay";
    options.clean_start = false;
    auto session = connected(broker, options);
    std::vector<std::uint16_t> ids;
    for (int i = 0; i < 3; ++i) ids.push_back(*session.publish(publish("q", QoS::at_least_once)));
    broker.take(session);
    CHECK(session.connect(1).has_value());
    broker.take(session);
    Connack ack{true, reason::success, {}};
    ack.properties.receive_maximum = std::uint16_t{1};
    CHECK(broker.send(session, ack).has_value());
    static_cast<void>(session.take_events());
    for (const auto id : ids) {
        auto batch = broker.take(session);
        CHECK(batch.size() == 1 && std::holds_alternative<Publish>(batch.front()));
        if (batch.size() == 1 && std::holds_alternative<Publish>(batch.front())) {
            CHECK(std::get<Publish>(batch.front()).packet_id == id);
            CHECK(std::get<Publish>(batch.front()).dup);
        }
        CHECK(broker.take(session).empty());
        CHECK(broker.send(session, Ack{PacketType::puback, id, reason::success, {}}).has_value());
        static_cast<void>(session.take_events());
    }
    CHECK(session.inflight() == 0);
    CHECK(session.publish(publish("large", QoS::at_least_once, 0, std::string(50, 'x'))).has_value());
    broker.take(session);
    CHECK(session.connect(2).has_value());
    broker.take(session);
    ack.properties.maximum_packet_size = 20;
    auto resumed = broker.send(session, ack);
    CHECK(!resumed && resumed.error() == MqttError::packet_too_large);
    CHECK(session.inflight() == 1 && session.state() == SessionState::closed);
    for (const auto& packet : broker.take(session)) CHECK(!std::holds_alternative<Publish>(packet));
}

void bounded_lifecycle_and_auth() {
    test::section("event budgets include lifecycle notices and authentication stays bound to CONNECT");
    Broker broker;
    ClientOptions options;
    options.client_id = "bounded-lifecycle";
    options.max_events = 1;
    auto session = connected(broker, options);
    CHECK(broker.send(session, publish("t", QoS::at_most_once)).has_value());
    auto closed = broker.send(session, Disconnect{});
    CHECK(!closed && closed.error() == Errc::limit_exceeded);
    CHECK(session.state() == SessionState::closed && session.take_events().size() == 1);

    auto reconnect = connected(broker, options);
    CHECK(reconnect.publish(publish("t", QoS::at_least_once)).has_value());
    broker.take(reconnect);
    CHECK(broker.send(reconnect, publish("t", QoS::at_most_once)).has_value());
    auto blocked = reconnect.connect(1);
    CHECK(!blocked && blocked.error() == Errc::would_block);
    CHECK(reconnect.inflight() == 1 && reconnect.state() == SessionState::connected);
    CHECK(reconnect.take_events().size() == 1);
    CHECK(reconnect.connect(1).has_value());
    auto notices = reconnect.take_events();
    CHECK(notices.size() == 1 && notices.front().discarded);

    options.clean_start = false;
    auto lost = connected(broker, options);
    CHECK(lost.publish(publish("a", QoS::at_least_once)).has_value());
    CHECK(lost.publish(publish("b", QoS::at_least_once)).has_value());
    broker.take(lost);
    CHECK(lost.connect(1).has_value());
    broker.take(lost);
    auto lost_ack = broker.send(lost, Connack{});
    CHECK(!lost_ack && lost_ack.error() == Errc::limit_exceeded);
    CHECK(lost.state() == SessionState::closed && lost.take_events().empty());

    options.properties.authentication_method = "expected";
    auto authing = make(options);
    CHECK(authing.connect(0).has_value());
    broker.take(authing);
    Properties wrong;
    wrong.authentication_method = "different";
    CHECK(!authing.auth(reason::continue_authentication, wrong));
    CHECK(broker.take(authing).empty());
    auto auth = broker.send(authing, Auth{reason::continue_authentication, wrong});
    CHECK(!auth && auth.error() == MqttError::protocol_error);
    CHECK(authing.state() == SessionState::closed);
    auto missing_method = make(options);
    CHECK(missing_method.connect(0).has_value());
    broker.take(missing_method);
    auto missing = broker.send(missing_method, Connack{});
    CHECK(!missing && missing.error() == MqttError::protocol_error);

    Connack small;
    small.properties.maximum_packet_size = 2;
    auto tiny = connected(broker, {}, small);
    // Even internal acknowledgements must respect the negotiated packet size.
    auto too_big = broker.send(tiny, publish("q", QoS::at_least_once, 7));
    CHECK(!too_big && too_big.error() == MqttError::packet_too_large);
    CHECK(tiny.state() == SessionState::closed);
    CHECK(broker.take(tiny).empty());

    Connack authenticated;
    authenticated.properties.authentication_method = "expected";
    auto established = connected(broker, options, authenticated);
    CHECK(!established.auth(reason::success, options.properties));
    CHECK(broker.take(established).empty());
}

void replay_controls_bypass_publish_quota() {
    test::section("resumed PUBREL bypasses a full PUBLISH quota without reordering PUBLISH");
    Broker broker;
    ClientOptions options;
    options.client_id = "replay-controls";
    options.clean_start = false;
    auto session = connected(broker, options);
    const auto first = *session.publish(publish("first", QoS::at_least_once));
    const auto second_id = *session.publish(publish("second", QoS::at_least_once));
    const auto released = *session.publish(publish("third", QoS::exactly_once));
    broker.take(session);
    CHECK(broker.send(session, Ack{PacketType::pubrec, released, reason::success, {}}).has_value());
    broker.take(session);
    CHECK(session.connect(1).has_value());
    broker.take(session);
    Connack resumed{true, reason::success, {}};
    resumed.properties.receive_maximum = std::uint16_t{1};
    CHECK(broker.send(session, resumed).has_value());
    auto wire = broker.take(session);
    CHECK(wire.size() == 2);
    if (wire.size() == 2) {
        CHECK(std::holds_alternative<Publish>(wire[0]) && std::get<Publish>(wire[0]).packet_id == first);
        CHECK(std::holds_alternative<Ack>(wire[1]) && std::get<Ack>(wire[1]).packet_id == released);
    }
    CHECK(broker.send(session, Ack{PacketType::pubcomp, released, reason::success, {}}).has_value());
    CHECK(broker.take(session).empty());
    CHECK(broker.send(session, Ack{PacketType::puback, first, reason::success, {}}).has_value());
    wire = broker.take(session);
    CHECK(wire.size() == 1 && std::holds_alternative<Publish>(wire[0]) &&
          std::get<Publish>(wire[0]).packet_id == second_id);
}

void identifiers() {
    test::section("packet identifiers skip those in use and wrap");
    Broker broker;
    auto session = connected(broker, {});
    std::vector<std::uint16_t> ids;
    for (int i = 0; i < 3; ++i) ids.push_back(*session.publish(publish("t", QoS::at_least_once)));
    CHECK(ids == std::vector<std::uint16_t>({1, 2, 3}));
    broker.take(session);
    CHECK(broker.send(session, Ack{PacketType::puback, 2, reason::success, {}}).has_value());
    bool unique = true;
    for (int i = 0; i < 65532; ++i) {
        auto id = session.publish(publish("t", QoS::at_least_once));
        if (!id || *id == 1 || *id == 3) unique = false;
        static_cast<void>(session.take_output(0));
    }
    CHECK(unique && session.inflight() == 65534);
    const auto reused = session.publish(publish("t", QoS::at_least_once));
    CHECK(reused && *reused == 2);
    CHECK(session.publish(publish("t", QoS::at_least_once)).error() == Errc::would_block);
}

}  // namespace

int main() {
    connect_limits();
    qos2_sender();
    inbound();
    aliases();
    subscriptions();
    keep_alive();
    resume();
    resume_reduced_limits();
    failures();
    bounded_lifecycle_and_auth();
    replay_controls_bypass_publish_quota();
    identifiers();
    return test::summary();
}
