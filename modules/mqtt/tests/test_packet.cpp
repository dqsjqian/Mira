#include "check.hpp"
#include "mira/mqtt/packet.hpp"

#include <cstdio>
#include <string>
#include <vector>

using namespace Mira;
using namespace Mira::mqtt;

namespace {

Bytes bytes(std::initializer_list<int> values) {
    Bytes out;
    for (const int v : values) out.push_back(static_cast<std::byte>(v));
    return out;
}
Bytes text(std::string_view value) {
    const auto view = std::as_bytes(std::span{value.data(), value.size()});
    return Bytes(view.begin(), view.end());
}
Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
    return out;
}

// Encode, then decode as the receiving role, and require the same value back.
bool round_trip(const Packet& packet, Version version, Role receiver) {
    auto encoded = encode(packet, version);
    if (!encoded) return false;
    auto decoded = decode(*encoded, version, receiver);
    return decoded && decoded->packet && decoded->consumed == encoded->size() && *decoded->packet == packet;
}

std::error_code decode_error(const Bytes& wire, Version version, Role receiver, std::size_t maximum = max_packet_size) {
    auto decoded = decode(wire, version, receiver, maximum);
    if (decoded) return {};
    return decoded.error();
}

Properties rich_publish_properties() {
    Properties p;
    p.payload_format_indicator = std::uint8_t{1};
    p.message_expiry_interval = std::uint32_t{3600};
    p.content_type = "text/plain; charset=utf-8";
    p.response_topic = "reply/here";
    p.correlation_data = bytes({0, 1, 2, 255});
    p.user_properties = {{"k", "v"}, {"k", "again"}, {"名前", "値"}};
    return p;
}

void known_vectors() {
    test::section("specification byte vectors");
    Connect c;
    c.version = Version::v311;
    c.client_id = "abc";
    auto wire = encode(c, Version::v311);
    CHECK(wire && *wire == bytes({0x10, 0x0F, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
                                   0x00, 0x03, 'a', 'b', 'c'}));
    Publish p;
    p.topic = "a/b";
    p.qos = QoS::at_least_once;
    p.packet_id = 10;
    p.payload = text("hi");
    wire = encode(p, Version::v311);
    CHECK(wire && *wire == bytes({0x32, 0x09, 0x00, 0x03, 'a', '/', 'b', 0x00, 0x0A, 'h', 'i'}));
    CHECK(encode(Pingreq{}, Version::v311) == bytes({0xC0, 0x00}));
    CHECK(encode(Pingresp{}, Version::v5) == bytes({0xD0, 0x00}));
    CHECK(encode(Disconnect{}, Version::v311) == bytes({0xE0, 0x00}));
    CHECK(encode(Disconnect{}, Version::v5) == bytes({0xE0, 0x00}));
    CHECK(encode(Ack{PacketType::puback, 7, reason::success, {}}, Version::v5) == bytes({0x40, 0x02, 0x00, 0x07}));
    CHECK(encode(Ack{PacketType::pubrel, 7, reason::success, {}}, Version::v311) == bytes({0x62, 0x02, 0x00, 0x07}));
    CHECK(encode(Ack{PacketType::pubrec, 7, reason::no_matching_subscribers, {}}, Version::v5) ==
          bytes({0x50, 0x03, 0x00, 0x07, 0x10}));
    Subscribe s{1, {{"a/+", QoS::exactly_once, true, true, 2}}, {}};
    CHECK(encode(s, Version::v5) == bytes({0x82, 0x09, 0x00, 0x01, 0x00, 0x00, 0x03, 'a', '/', '+', 0x2E}));
    Connack ok{true, 0, {}};
    CHECK(encode(ok, Version::v311) == bytes({0x20, 0x02, 0x01, 0x00}));
    CHECK(encode(ok, Version::v5) == bytes({0x20, 0x03, 0x01, 0x00, 0x00}));
    // A decoder must accept the short 5.0 acknowledgement forms.
    auto short_ack = decode(bytes({0x40, 0x02, 0x00, 0x07}), Version::v5, Role::client);
    CHECK(short_ack && short_ack->packet && std::get<Ack>(*short_ack->packet).reason == reason::success);
    auto reason_only = decode(bytes({0x40, 0x03, 0x00, 0x07, 0x10}), Version::v5, Role::server);
    CHECK(reason_only && reason_only->packet && std::get<Ack>(*reason_only->packet).reason == 0x10);
    auto disconnect_empty = decode(bytes({0xE0, 0x00}), Version::v5, Role::client);
    CHECK(disconnect_empty && disconnect_empty->packet &&
          std::get<Disconnect>(*disconnect_empty->packet).reason == reason::success);
}

void round_trips() {
    test::section("every packet round-trips in both versions");
    for (const auto version : {Version::v311, Version::v5}) {
        const bool v5 = version == Version::v5;
        Connect c;
        c.version = version;
        c.client_id = "client-1";
        c.clean_start = false;
        c.keep_alive = 30;
        c.username = "user";
        c.password = bytes({0, 1, 2});
        Will will{"will/topic", text("gone"), QoS::exactly_once, true, {}};
        if (v5) {
            will.properties = rich_publish_properties();
            will.properties.will_delay_interval = std::uint32_t{5};
            c.properties.session_expiry_interval = std::uint32_t{60};
            c.properties.receive_maximum = std::uint16_t{10};
            c.properties.maximum_packet_size = std::uint32_t{4096};
            c.properties.topic_alias_maximum = std::uint16_t{8};
            c.properties.request_problem_information = std::uint8_t{0};
            c.properties.request_response_information = std::uint8_t{1};
            c.properties.authentication_method = "SCRAM-SHA-256";
            c.properties.authentication_data = bytes({9, 9});
            c.properties.user_properties = {{"a", "b"}};
        }
        c.will = will;
        CHECK(round_trip(c, version, Role::server));
        Connect bare;
        bare.version = version;
        bare.client_id = v5 ? "" : "x";
        CHECK(round_trip(bare, version, Role::server));

        Connack ack{false, v5 ? reason::not_authorized : std::uint8_t{5}, {}};
        if (v5) {
            ack.properties.session_expiry_interval = std::uint32_t{10};
            ack.properties.assigned_client_identifier = "auto-1";
            ack.properties.server_keep_alive = std::uint16_t{15};
            ack.properties.receive_maximum = std::uint16_t{2};
            ack.properties.maximum_qos = std::uint8_t{1};
            ack.properties.retain_available = std::uint8_t{0};
            ack.properties.maximum_packet_size = std::uint32_t{1000};
            ack.properties.topic_alias_maximum = std::uint16_t{4};
            ack.properties.wildcard_subscription_available = std::uint8_t{0};
            ack.properties.subscription_identifiers_available = std::uint8_t{0};
            ack.properties.shared_subscription_available = std::uint8_t{1};
            ack.properties.response_information = "resp";
            ack.properties.server_reference = "other:1883";
            ack.properties.reason_string = "no";
        }
        CHECK(round_trip(ack, version, Role::client));

        for (const auto qos : {QoS::at_most_once, QoS::at_least_once, QoS::exactly_once}) {
            Publish p;
            p.topic = "sport/tennis/player1";
            p.qos = qos;
            p.retain = true;
            p.dup = qos != QoS::at_most_once;
            p.packet_id = qos == QoS::at_most_once ? 0 : 65535;
            p.payload = Bytes(300, std::byte{0x7A});
            if (v5) {
                p.properties = rich_publish_properties();
                p.properties.topic_alias = std::uint16_t{3};
            }
            CHECK(round_trip(p, version, Role::server));
            if (v5) p.properties.subscription_identifiers = {1, 268'435'455};
            CHECK(round_trip(p, version, Role::client));
        }
        if (v5) {
            Publish aliased;
            aliased.properties.topic_alias = std::uint16_t{1};
            aliased.payload = text("x");
            CHECK(round_trip(aliased, version, Role::client));
        }

        for (const auto type : {PacketType::puback, PacketType::pubrec, PacketType::pubrel, PacketType::pubcomp}) {
            Ack a{type, 42, reason::success, {}};
            CHECK(round_trip(a, version, Role::client));
            CHECK(round_trip(a, version, Role::server));
            if (v5) {
                a.reason = type == PacketType::pubrel || type == PacketType::pubcomp ? reason::packet_identifier_not_found
                                                                                     : reason::quota_exceeded;
                a.properties.reason_string = "why";
                a.properties.user_properties = {{"x", "y"}};
                CHECK(round_trip(a, version, Role::client));
            }
        }

        Subscribe sub{9, {{"a/#", QoS::at_least_once, false, false, 0}, {"+/b", QoS::exactly_once, false, false, 0}}, {}};
        if (v5) {
            sub.subscriptions.push_back({"$share/group/c/+", QoS::at_most_once, false, true, 1});
            sub.subscriptions[0].no_local = true;
            sub.properties.subscription_identifiers = {77};
            sub.properties.user_properties = {{"s", "t"}};
        }
        CHECK(round_trip(sub, version, Role::server));
        Suback suback{9, {0x00, 0x01, 0x02, 0x80}, {}};
        if (v5) {
            suback.reasons.push_back(reason::shared_subscriptions_not_supported);
            suback.properties.reason_string = "partial";
        }
        CHECK(round_trip(suback, version, Role::client));
        Unsubscribe unsub{10, {"a/#", "+/b"}, {}};
        CHECK(round_trip(unsub, version, Role::server));
        Unsuback unsuback{10, {}, {}};
        if (v5) unsuback.reasons = {reason::success, reason::no_subscription_existed};
        CHECK(round_trip(unsuback, version, Role::client));
        CHECK(round_trip(Pingreq{}, version, Role::server));
        CHECK(round_trip(Pingresp{}, version, Role::client));
        CHECK(round_trip(Disconnect{}, version, Role::server));
        if (v5) {
            Disconnect d{reason::session_taken_over, {}};
            d.properties.session_expiry_interval = std::uint32_t{0};
            d.properties.reason_string = "bye";
            d.properties.server_reference = "elsewhere";
            CHECK(round_trip(d, version, Role::client));
            Auth a{reason::continue_authentication, {}};
            a.properties.authentication_method = "SCRAM-SHA-256";
            a.properties.authentication_data = bytes({1, 2, 3});
            CHECK(round_trip(a, version, Role::client));
            CHECK(round_trip(a, version, Role::server));
        }
    }
}

void lengths() {
    test::section("variable byte integer boundaries and incremental input");
    for (const std::size_t size : {std::size_t{0}, std::size_t{119}, std::size_t{120}, std::size_t{16376},
                                   std::size_t{16377}, std::size_t{2097144}, std::size_t{2097145}}) {
        Publish p;
        p.topic = "t";
        p.payload = Bytes(size, std::byte{1});
        auto wire = encode(p, Version::v311);
        CHECK(wire.has_value());
        const auto remaining = size + 3;
        const std::size_t length_bytes = remaining < 128 ? 1 : remaining < 16384 ? 2 : remaining < 2097152 ? 3 : 4;
        CHECK(wire && wire->size() == 1 + length_bytes + remaining);
        CHECK(round_trip(p, Version::v311, Role::client));
    }
    Publish p;
    p.topic = "incremental";
    p.qos = QoS::exactly_once;
    p.packet_id = 5;
    p.payload = text("payload");
    const auto wire = *encode(p, Version::v5);
    bool complete_only_at_end = true;
    for (std::size_t n = 0; n < wire.size(); ++n) {
        auto partial = decode(std::span{wire}.first(n), Version::v5, Role::client);
        complete_only_at_end = complete_only_at_end && partial && !partial->packet && partial->consumed == 0;
    }
    CHECK(complete_only_at_end);
    auto two = cat({wire, *encode(Pingresp{}, Version::v5)});
    auto first = decode(two, Version::v5, Role::client);
    CHECK(first && first->packet && first->consumed == wire.size());
    auto second = decode(std::span{two}.subspan(first->consumed), Version::v5, Role::client);
    CHECK(second && second->packet && std::holds_alternative<Pingresp>(*second->packet));
}

void rejections() {
    test::section("decoder rejects what a peer can get wrong");
    const auto malformed = make_error_code(MqttError::malformed_packet);
    const auto protocol = make_error_code(MqttError::protocol_error);
    // Fixed header.
    CHECK(decode_error(bytes({0x00, 0x00}), Version::v5, Role::client) == malformed);
    CHECK(decode_error(bytes({0xC1, 0x00}), Version::v5, Role::server) == malformed);  // PINGREQ flags
    CHECK(decode_error(bytes({0x60, 0x02, 0x00, 0x01}), Version::v5, Role::client) == malformed);  // PUBREL flags
    CHECK(decode_error(bytes({0x80, 0x02, 0x00, 0x01}), Version::v5, Role::server) == malformed);  // SUBSCRIBE flags
    CHECK(decode_error(bytes({0x36, 0x05, 0x00, 0x01, 't', 0x00, 0x01}), Version::v311, Role::client) == malformed);  // QoS 3
    CHECK(decode_error(bytes({0x38, 0x03, 0x00, 0x01, 't'}), Version::v311, Role::client) == malformed);  // DUP on QoS 0
    CHECK(decode_error(bytes({0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}), Version::v5, Role::client) == malformed);
    CHECK(decode_error(bytes({0xD0, 0x80, 0x00}), Version::v5, Role::client) == malformed);  // non-minimal length
    CHECK(decode_error(bytes({0xD0, 0x01, 0x00}), Version::v5, Role::client) == malformed);  // trailing byte
    // Size is decided from the header alone.
    CHECK(decode_error(bytes({0x30, 0xFF, 0x7F}), Version::v5, Role::client, 1024) ==
          make_error_code(MqttError::packet_too_large));
    // Direction.
    CHECK(decode_error(*encode(Pingreq{}, Version::v5), Version::v5, Role::client) == protocol);
    CHECK(decode_error(*encode(Connack{}, Version::v5), Version::v5, Role::server) == protocol);
    CHECK(decode_error(bytes({0xE0, 0x00}), Version::v311, Role::client) == protocol);  // 3.1.1 server DISCONNECT
    CHECK(decode_error(bytes({0xF0, 0x00}), Version::v311, Role::client) == protocol);  // AUTH before 5.0
    // Packet identifiers and topics.
    CHECK(decode_error(bytes({0x40, 0x02, 0x00, 0x00}), Version::v311, Role::client) == malformed);
    CHECK(decode_error(bytes({0x32, 0x05, 0x00, 0x01, 't', 0x00, 0x00}), Version::v311, Role::client) == malformed);
    CHECK(decode_error(bytes({0x30, 0x03, 0x00, 0x01, '#'}), Version::v311, Role::client) == protocol);
    CHECK(decode_error(bytes({0x30, 0x03, 0x00, 0x00, 0x00}), Version::v5, Role::client) == protocol);  // no topic, no alias
    CHECK(decode_error(bytes({0x30, 0x04, 0x00, 0x02, 'a', 0x00}), Version::v311, Role::client) == malformed);  // U+0000
    CHECK(decode_error(bytes({0x30, 0x04, 0x00, 0x02, 0xC0, 0x80}), Version::v311, Role::client) == malformed);  // overlong
    CHECK(decode_error(bytes({0x30, 0x05, 0x00, 0x03, 0xED, 0xA0, 0x80}), Version::v311, Role::client) == malformed);  // surrogate
    // Properties: not allowed here, duplicated, bad value, subscription id from a client.
    CHECK(decode_error(bytes({0x30, 0x06, 0x00, 0x01, 't', 0x02, 0x24, 0x01}), Version::v5, Role::client) == malformed);
    CHECK(decode_error(bytes({0x30, 0x08, 0x00, 0x01, 't', 0x04, 0x01, 0x00, 0x01, 0x01}), Version::v5, Role::client) == protocol);
    CHECK(decode_error(bytes({0x30, 0x06, 0x00, 0x01, 't', 0x02, 0x01, 0x02}), Version::v5, Role::client) == protocol);
    CHECK(decode_error(bytes({0x30, 0x06, 0x00, 0x01, 't', 0x02, 0x0B, 0x01}), Version::v5, Role::server) == protocol);
    CHECK(decode_error(bytes({0x30, 0x06, 0x00, 0x01, 't', 0x02, 0x0B, 0x00}), Version::v5, Role::client) == protocol);
    CHECK(decode_error(bytes({0x30, 0x06, 0x00, 0x01, 't', 0x02, 0x7F, 0x00}), Version::v5, Role::client) == malformed);
    CHECK(decode_error(bytes({0x30, 0x06, 0x00, 0x01, 't', 0x05, 0x01, 0x00}), Version::v5, Role::client) == malformed);
    // Reason codes per packet and version.
    CHECK(decode_error(bytes({0x20, 0x02, 0x00, 0x06}), Version::v311, Role::client) == malformed);
    CHECK(decode_error(bytes({0x20, 0x02, 0x01, 0x05}), Version::v311, Role::client) == malformed);  // session present on refusal
    CHECK(decode_error(bytes({0x20, 0x03, 0x02, 0x00, 0x00}), Version::v5, Role::client) == malformed);  // reserved flag
    CHECK(decode_error(bytes({0x40, 0x03, 0x00, 0x01, 0x92}), Version::v5, Role::client) == malformed);
    CHECK(decode_error(bytes({0x90, 0x03, 0x00, 0x01, 0x03}), Version::v311, Role::client) == malformed);
    CHECK(decode_error(bytes({0xB0, 0x03, 0x00, 0x01, 0x00}), Version::v311, Role::client) == malformed);
    // SUBSCRIBE payloads.
    CHECK(decode_error(bytes({0x82, 0x03, 0x00, 0x01, 0x00}), Version::v5, Role::server) == protocol);  // no filters
    CHECK(decode_error(bytes({0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'a', '#', 'b', 0x00}), Version::v311, Role::server) == malformed);
    CHECK(decode_error(bytes({0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'a', 0x04}), Version::v311, Role::server) == malformed);
    CHECK(decode_error(bytes({0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'a', 0x30}), Version::v5, Role::server) == malformed);
    // CONNECT header.
    auto connect = *encode(Connect{Version::v311, "c", true, 10, {}, {}, {}, {}}, Version::v311);
    auto bad_level = connect;
    bad_level[8] = std::byte{3};
    CHECK(decode_error(bad_level, Version::v5, Role::server) == make_error_code(MqttError::unsupported_version));
    auto reserved = connect;
    reserved[9] |= std::byte{0x01};
    CHECK(decode_error(reserved, Version::v5, Role::server) == malformed);
    auto password_only = connect;
    password_only[9] |= std::byte{0x40};
    CHECK(decode_error(password_only, Version::v5, Role::server) == malformed);
    auto version = decode(connect, Version::v5, Role::server);
    CHECK(version && version->packet && std::get<Connect>(*version->packet).version == Version::v311);
}

void refusals() {
    test::section("encoder refuses what the decoder would reject");
    Publish wildcard;
    wildcard.topic = "a/+";
    CHECK(!encode(wildcard, Version::v5));
    Publish qos0_id;
    qos0_id.topic = "a";
    qos0_id.packet_id = 1;
    CHECK(!encode(qos0_id, Version::v5));
    Publish no_id;
    no_id.topic = "a";
    no_id.qos = QoS::at_least_once;
    CHECK(!encode(no_id, Version::v5));
    Publish props_v3;
    props_v3.topic = "a";
    props_v3.properties.content_type = "x";
    CHECK(!encode(props_v3, Version::v311));
    Publish forbidden;
    forbidden.topic = "a";
    forbidden.properties.maximum_qos = std::uint8_t{1};
    CHECK(!encode(forbidden, Version::v5));
    Publish bad_value;
    bad_value.topic = "a";
    bad_value.properties.payload_format_indicator = std::uint8_t{2};
    CHECK(!encode(bad_value, Version::v5));
    Connect mismatch;
    mismatch.version = Version::v5;
    CHECK(!encode(mismatch, Version::v311));
    Connect v3_empty;
    v3_empty.version = Version::v311;
    v3_empty.clean_start = false;
    CHECK(!encode(v3_empty, Version::v311));
    Connect v3_password;
    v3_password.version = Version::v311;
    v3_password.client_id = "c";
    v3_password.password = bytes({1});
    CHECK(!encode(v3_password, Version::v311));
    CHECK(!encode(Subscribe{1, {}, {}}, Version::v5));
    CHECK(!encode(Subscribe{0, {{"a", QoS::at_most_once, false, false, 0}}, {}}, Version::v5));
    CHECK(!encode(Subscribe{1, {{"a/#/b", QoS::at_most_once, false, false, 0}}, {}}, Version::v5));
    CHECK(!encode(Subscribe{1, {{"a", QoS::at_most_once, true, false, 0}}, {}}, Version::v311));
    CHECK(!encode(Subscribe{1, {{"$share/g/a", QoS::at_most_once, true, false, 0}}, {}}, Version::v5));
    Properties two_ids;
    two_ids.subscription_identifiers = {1, 2};
    CHECK(!encode(Subscribe{1, {{"a", QoS::at_most_once, false, false, 0}}, two_ids}, Version::v5));
    CHECK(!encode(Unsuback{1, {0}, {}}, Version::v311));
    CHECK(!encode(Unsuback{1, {}, {}}, Version::v5));
    CHECK(!encode(Auth{}, Version::v311));
    CHECK(!encode(Disconnect{reason::server_busy, {}}, Version::v311));
    CHECK(!encode(Ack{PacketType::pubcomp, 1, reason::quota_exceeded, {}}, Version::v5));
    CHECK(!encode(Connack{true, reason::not_authorized, {}}, Version::v5));
    Publish huge_string;
    huge_string.topic = std::string(65536, 'a');
    CHECK(!encode(huge_string, Version::v5));
}

void topics() {
    test::section("topic names, filters and matching (specification 4.7)");
    CHECK(valid_topic_name("sport/tennis/player1"));
    CHECK(valid_topic_name("/"));
    CHECK(!valid_topic_name(""));
    CHECK(!valid_topic_name("sport/+"));
    CHECK(!valid_topic_name("sport/#"));
    for (const auto* good : {"#", "+", "sport/#", "sport/tennis/#", "+/+", "/+", "sport/+/player1", "+/tennis/#"})
        CHECK(valid_topic_filter(good));
    for (const auto* bad : {"", "sport/tennis#", "sport/tennis/#/ranking", "sport+", "a/#b", "$share/", "$share//a",
                            "$share/g+/a", "$share/g/"})
        CHECK(!valid_topic_filter(bad));
    CHECK(valid_topic_filter("$share/group/a/+"));
    CHECK(valid_topic_filter("$share/", Version::v311));  // 3.1.1 has no shared subscriptions.
    CHECK(valid_topic_filter("$share/g/a", Version::v311));
    struct Case {
        std::string_view filter, name;
        bool matches;
    };
    const Case cases[] = {
        {"sport/tennis/player1/#", "sport/tennis/player1", true},
        {"sport/tennis/player1/#", "sport/tennis/player1/ranking", true},
        {"sport/tennis/player1/#", "sport/tennis/player1/score/wimbledon", true},
        {"sport/#", "sport", true},
        {"sport/tennis/+", "sport/tennis/player1", true},
        {"sport/tennis/+", "sport/tennis/player1/ranking", false},
        {"sport/tennis/+", "sport/tennis", false},
        {"sport/+", "sport", false},
        {"sport/+", "sport/", true},
        {"+/+", "/finance", true},
        {"/+", "/finance", true},
        {"+", "/finance", false},
        {"#", "$SYS/uptime", false},
        {"+/monitor/Clients", "$SYS/monitor/Clients", false},
        {"$SYS/#", "$SYS/monitor/Clients", true},
        {"$SYS/monitor/+", "$SYS/monitor/Clients", true},
        {"#", "a/b/c", true},
        {"a/b", "a/b", true},
        {"a/b", "a/bc", false},
        {"$share/g/sport/+", "sport/tennis", true},
    };
    bool all = true;
    for (const auto& c : cases) {
        const bool got = topic_matches(c.filter, c.name);
        if (got != c.matches) std::fprintf(stderr, "match %.*s vs %.*s\n", static_cast<int>(c.filter.size()),
                                           c.filter.data(), static_cast<int>(c.name.size()), c.name.data());
        all = all && got == c.matches;
    }
    CHECK(all);
    CHECK(valid_string("héllo wörld 🌍"));
    CHECK(!valid_string(std::string_view("a\0b", 3)));
    CHECK(!valid_string("\xF5\x80\x80\x80"));
    CHECK(!valid_string("\xE0\x80\x80"));
    CHECK(!valid_string("\xC3"));
}

}  // namespace

int main() {
    known_vectors();
    round_trips();
    lengths();
    rejections();
    refusals();
    topics();
    return test::summary();
}
