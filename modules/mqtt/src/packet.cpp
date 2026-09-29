#include "mira/mqtt/packet.hpp"

#include <algorithm>
#include <array>
#include <initializer_list>
#include <utility>

namespace Mira::mqtt {
namespace {

class MqttCategory final : public std::error_category {
public:
    const char* name() const noexcept override { return "Mira.mqtt"; }
    std::string message(int code) const override {
        switch (static_cast<MqttError>(code)) {
        case MqttError::malformed_packet: return "malformed MQTT packet";
        case MqttError::protocol_error: return "MQTT protocol error";
        case MqttError::packet_too_large: return "MQTT packet exceeds the maximum packet size";
        case MqttError::unsupported_version: return "unsupported MQTT protocol version";
        case MqttError::refused: return "MQTT connection refused";
        case MqttError::disconnected: return "MQTT server disconnected";
        case MqttError::receive_maximum_exceeded: return "MQTT receive maximum exceeded";
        case MqttError::topic_alias_invalid: return "invalid MQTT topic alias";
        case MqttError::keep_alive_timeout: return "MQTT keep-alive timeout";
        }
        return "unknown MQTT error";
    }
};

constexpr std::uint32_t bit(PacketType type) { return 1u << static_cast<unsigned>(type); }
constexpr std::uint32_t will_context = 1u << 16;

bool in(std::uint8_t value, std::initializer_list<std::uint8_t> set) {
    return std::find(set.begin(), set.end(), value) != set.end();
}

// Where each 5.0 property may appear (specification section 2.2.2.2).
bool allowed(std::uint32_t id, std::uint32_t context) {
    using enum PacketType;
    std::uint32_t mask = 0;
    switch (id) {
    case 0x01: case 0x02: case 0x03: case 0x08: case 0x09: mask = bit(publish) | will_context; break;
    case 0x0B: mask = bit(publish) | bit(subscribe); break;
    case 0x11: mask = bit(connect) | bit(connack) | bit(disconnect); break;
    case 0x12: case 0x13: case 0x1A: case 0x24: case 0x25: case 0x28: case 0x29: case 0x2A:
        mask = bit(connack);
        break;
    case 0x15: case 0x16: mask = bit(connect) | bit(connack) | bit(auth); break;
    case 0x17: case 0x19: mask = bit(connect); break;
    case 0x18: mask = will_context; break;
    case 0x1C: mask = bit(connack) | bit(disconnect); break;
    case 0x1F:
        mask = bit(connack) | bit(puback) | bit(pubrec) | bit(pubrel) | bit(pubcomp) | bit(suback) |
               bit(unsuback) | bit(disconnect) | bit(auth);
        break;
    case 0x21: case 0x22: case 0x27: mask = bit(connect) | bit(connack); break;
    case 0x23: mask = bit(publish); break;
    case 0x26: mask = ~0u; break;
    default: return false;
    }
    return (mask & context) != 0;
}

bool empty(const Properties& properties) { return properties == Properties{}; }

bool flag(const std::optional<std::uint8_t>& value) { return !value || *value <= 1; }

// Value rules that make an otherwise well-formed property a protocol error.
bool values_ok(const Properties& p) {
    if (!flag(p.payload_format_indicator) || !flag(p.request_problem_information) ||
        !flag(p.request_response_information) || !flag(p.maximum_qos) || !flag(p.retain_available) ||
        !flag(p.wildcard_subscription_available) || !flag(p.subscription_identifiers_available) ||
        !flag(p.shared_subscription_available))
        return false;
    if ((p.receive_maximum && !*p.receive_maximum) || (p.maximum_packet_size && !*p.maximum_packet_size) ||
        (p.topic_alias && !*p.topic_alias))
        return false;
    for (const auto id : p.subscription_identifiers)
        if (id == 0 || id > max_remaining_length) return false;
    return !p.response_topic || valid_topic_name(*p.response_topic);
}

struct Writer {
    Bytes out;
    void u8(std::uint32_t value) { out.push_back(static_cast<std::byte>(value & 0xFFu)); }
    void u16(std::uint32_t value) {
        u8(value >> 8);
        u8(value);
    }
    void u32(std::uint32_t value) {
        u16(value >> 16);
        u16(value);
    }
    void varint(std::uint32_t value) {
        do {
            std::uint32_t digit = value % 128;
            value /= 128;
            if (value) digit |= 0x80;
            u8(digit);
        } while (value);
    }
    void raw(std::span<const std::byte> bytes) { out.insert(out.end(), bytes.begin(), bytes.end()); }
    // Callers validate lengths first; both forms are at most 65535 bytes.
    void text(std::string_view value) {
        u16(static_cast<std::uint32_t>(value.size()));
        raw(std::as_bytes(std::span{value.data(), value.size()}));
    }
    void binary(std::span<const std::byte> value) {
        u16(static_cast<std::uint32_t>(value.size()));
        raw(value);
    }
};

bool write_properties(Writer& w, const Properties& p, std::uint32_t context) {
    if (!values_ok(p)) return false;
    Writer b;
    bool ok = true;
    const auto byte = [&](std::uint32_t id, const std::optional<std::uint8_t>& v) {
        if (!v) return;
        ok = ok && allowed(id, context);
        b.u8(id);
        b.u8(*v);
    };
    const auto two = [&](std::uint32_t id, const std::optional<std::uint16_t>& v) {
        if (!v) return;
        ok = ok && allowed(id, context);
        b.u8(id);
        b.u16(*v);
    };
    const auto four = [&](std::uint32_t id, const std::optional<std::uint32_t>& v) {
        if (!v) return;
        ok = ok && allowed(id, context);
        b.u8(id);
        b.u32(*v);
    };
    const auto text = [&](std::uint32_t id, const std::optional<std::string>& v) {
        if (!v) return;
        ok = ok && allowed(id, context) && valid_string(*v);
        b.u8(id);
        b.text(*v);
    };
    const auto binary = [&](std::uint32_t id, const std::optional<Bytes>& v) {
        if (!v) return;
        ok = ok && allowed(id, context) && v->size() <= 65535;
        b.u8(id);
        b.binary(*v);
    };
    byte(0x01, p.payload_format_indicator);
    four(0x02, p.message_expiry_interval);
    text(0x03, p.content_type);
    text(0x08, p.response_topic);
    binary(0x09, p.correlation_data);
    if (context == bit(PacketType::subscribe) && p.subscription_identifiers.size() > 1) return false;
    for (const auto id : p.subscription_identifiers) {
        ok = ok && allowed(0x0B, context);
        b.u8(0x0B);
        b.varint(id);
    }
    four(0x11, p.session_expiry_interval);
    text(0x12, p.assigned_client_identifier);
    two(0x13, p.server_keep_alive);
    text(0x15, p.authentication_method);
    binary(0x16, p.authentication_data);
    byte(0x17, p.request_problem_information);
    four(0x18, p.will_delay_interval);
    byte(0x19, p.request_response_information);
    text(0x1A, p.response_information);
    text(0x1C, p.server_reference);
    text(0x1F, p.reason_string);
    two(0x21, p.receive_maximum);
    two(0x22, p.topic_alias_maximum);
    two(0x23, p.topic_alias);
    byte(0x24, p.maximum_qos);
    byte(0x25, p.retain_available);
    for (const auto& [name, value] : p.user_properties) {
        ok = ok && allowed(0x26, context) && valid_string(name) && valid_string(value);
        b.u8(0x26);
        b.text(name);
        b.text(value);
    }
    four(0x27, p.maximum_packet_size);
    byte(0x28, p.wildcard_subscription_available);
    byte(0x29, p.subscription_identifiers_available);
    byte(0x2A, p.shared_subscription_available);
    if (!ok || b.out.size() > max_remaining_length) return false;
    w.varint(static_cast<std::uint32_t>(b.out.size()));
    w.raw(b.out);
    return true;
}

struct Reader {
    std::span<const std::byte> data;
    std::size_t pos = 0;
    bool bad = false;
    std::size_t left() const { return data.size() - pos; }
    std::uint8_t u8() {
        if (!left()) {
            bad = true;
            return 0;
        }
        return std::to_integer<std::uint8_t>(data[pos++]);
    }
    std::uint16_t u16() {
        const std::uint32_t high = u8();
        return static_cast<std::uint16_t>((high << 8) | u8());
    }
    std::uint32_t u32() {
        const std::uint32_t high = u16();
        return (high << 16) | u16();
    }
    std::uint32_t varint() {
        std::uint32_t value = 0, scale = 1;
        for (int i = 0; i < 4; ++i) {
            const std::uint32_t digit = u8();
            if (bad) return 0;
            value += (digit & 0x7F) * scale;
            if (!(digit & 0x80)) {
                if (i > 0 && digit == 0) bad = true;  // Not the minimal encoding.
                return value;
            }
            scale *= 128;
        }
        bad = true;
        return 0;
    }
    std::span<const std::byte> take(std::size_t count) {
        if (left() < count) {
            bad = true;
            return {};
        }
        const auto view = data.subspan(pos, count);
        pos += count;
        return view;
    }
    std::string text() {
        const auto view = take(u16());
        std::string value(reinterpret_cast<const char*>(view.data()), view.size());
        if (!valid_string(value)) bad = true;
        return value;
    }
    Bytes binary() {
        const auto view = take(u16());
        return Bytes(view.begin(), view.end());
    }
};

// Returns 0 on success or the error to report.
MqttError read_properties(Reader& r, Properties& p, std::uint32_t context) {
    const auto length = r.varint();
    const auto view = r.take(length);
    if (r.bad) return MqttError::malformed_packet;
    Reader in{view};
    std::array<bool, 0x2B> seen{};
    while (in.left()) {
        const auto id = in.varint();
        if (in.bad || !allowed(id, context)) return MqttError::malformed_packet;
        const bool repeatable = id == 0x26 || (id == 0x0B && context == bit(PacketType::publish));
        if (seen[id] && !repeatable) return MqttError::protocol_error;
        seen[id] = true;
        switch (id) {
        case 0x01: p.payload_format_indicator = in.u8(); break;
        case 0x02: p.message_expiry_interval = in.u32(); break;
        case 0x03: p.content_type = in.text(); break;
        case 0x08: p.response_topic = in.text(); break;
        case 0x09: p.correlation_data = in.binary(); break;
        case 0x0B: p.subscription_identifiers.push_back(in.varint()); break;
        case 0x11: p.session_expiry_interval = in.u32(); break;
        case 0x12: p.assigned_client_identifier = in.text(); break;
        case 0x13: p.server_keep_alive = in.u16(); break;
        case 0x15: p.authentication_method = in.text(); break;
        case 0x16: p.authentication_data = in.binary(); break;
        case 0x17: p.request_problem_information = in.u8(); break;
        case 0x18: p.will_delay_interval = in.u32(); break;
        case 0x19: p.request_response_information = in.u8(); break;
        case 0x1A: p.response_information = in.text(); break;
        case 0x1C: p.server_reference = in.text(); break;
        case 0x1F: p.reason_string = in.text(); break;
        case 0x21: p.receive_maximum = in.u16(); break;
        case 0x22: p.topic_alias_maximum = in.u16(); break;
        case 0x23: p.topic_alias = in.u16(); break;
        case 0x24: p.maximum_qos = in.u8(); break;
        case 0x25: p.retain_available = in.u8(); break;
        case 0x26: {
            auto name = in.text();
            auto value = in.text();
            p.user_properties.push_back({std::move(name), std::move(value)});
            break;
        }
        case 0x27: p.maximum_packet_size = in.u32(); break;
        case 0x28: p.wildcard_subscription_available = in.u8(); break;
        case 0x29: p.subscription_identifiers_available = in.u8(); break;
        case 0x2A: p.shared_subscription_available = in.u8(); break;
        default: return MqttError::malformed_packet;
        }
        if (in.bad) return MqttError::malformed_packet;
    }
    return values_ok(p) ? MqttError{} : MqttError::protocol_error;
}

std::uint8_t required_flags(PacketType type) {
    return type == PacketType::pubrel || type == PacketType::subscribe || type == PacketType::unsubscribe ? 2 : 0;
}

bool valid_reason(PacketType type, Version version, std::uint8_t code) {
    using enum PacketType;
    const bool v5 = version == Version::v5;
    switch (type) {
    case connack:
        return v5 ? in(code, {0x00, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
                              0x8C, 0x90, 0x95, 0x97, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9F})
                  : code <= 5;
    case puback: case pubrec:
        return v5 ? in(code, {0x00, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99}) : code == 0;
    case pubrel: case pubcomp: return v5 ? in(code, {0x00, 0x92}) : code == 0;
    case suback:
        return v5 ? in(code, {0x00, 0x01, 0x02, 0x80, 0x83, 0x87, 0x8F, 0x91, 0x97, 0x9E, 0xA1, 0xA2})
                  : in(code, {0x00, 0x01, 0x02, 0x80});
    case unsuback: return v5 && in(code, {0x00, 0x11, 0x80, 0x83, 0x87, 0x8F, 0x91});
    case disconnect:
        return v5 ? in(code, {0x00, 0x04, 0x80, 0x81, 0x82, 0x83, 0x87, 0x89, 0x8B, 0x8D, 0x8E, 0x8F,
                              0x90, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
                              0x9E, 0x9F, 0xA0, 0xA1, 0xA2})
                  : code == 0;
    case auth: return v5 && in(code, {0x00, 0x18, 0x19});
    default: return false;
    }
}

bool shared(std::string_view filter) { return filter.starts_with("$share/"); }

bool valid_levels(std::string_view filter) {
    if (filter.empty() || !valid_string(filter)) return false;
    for (std::size_t start = 0;;) {
        const auto end = filter.find('/', start);
        const auto level = filter.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
        if (level.find_first_of("+#") != std::string_view::npos && level.size() != 1) return false;
        if (level == "#" && end != std::string_view::npos) return false;
        if (end == std::string_view::npos) return true;
        start = end + 1;
    }
}

Result<Bytes> frame(PacketType type, std::uint32_t flags, const Bytes& body) {
    if (body.size() > max_remaining_length) return fail(Errc::invalid_argument);
    Writer w;
    w.u8((static_cast<std::uint32_t>(type) << 4) | flags);
    w.varint(static_cast<std::uint32_t>(body.size()));
    w.raw(body);
    return std::move(w.out);
}

// ── encoders: false means the value is not encodable ────────────────────────

bool encode_connect(Writer& w, const Connect& c, Version version) {
    const bool v5 = version == Version::v5;
    if (c.version != version || !valid_string(c.client_id)) return false;
    if (!v5 && ((c.client_id.empty() && !c.clean_start) || (c.password && !c.username) || !empty(c.properties)))
        return false;
    if (c.username && !valid_string(*c.username)) return false;
    if (c.password && c.password->size() > 65535) return false;
    std::uint32_t flags = c.clean_start ? 0x02 : 0x00;
    if (c.will) {
        const auto& will = *c.will;
        if (!valid_topic_name(will.topic) || will.payload.size() > 65535 ||
            static_cast<unsigned>(will.qos) > 2 || (!v5 && !empty(will.properties)))
            return false;
        flags |= 0x04 | (static_cast<std::uint32_t>(will.qos) << 3) | (will.retain ? 0x20 : 0);
    }
    if (c.password) flags |= 0x40;
    if (c.username) flags |= 0x80;
    w.text("MQTT");
    w.u8(static_cast<std::uint32_t>(version));
    w.u8(flags);
    w.u16(c.keep_alive);
    if (v5 && !write_properties(w, c.properties, bit(PacketType::connect))) return false;
    w.text(c.client_id);
    if (c.will) {
        if (v5 && !write_properties(w, c.will->properties, will_context)) return false;
        w.text(c.will->topic);
        w.binary(c.will->payload);
    }
    if (c.username) w.text(*c.username);
    if (c.password) w.binary(*c.password);
    return true;
}

bool encode_publish(Writer& w, const Publish& p, Version version) {
    const bool v5 = version == Version::v5;
    const auto qos = static_cast<unsigned>(p.qos);
    if (qos > 2 || (qos == 0 && (p.packet_id || p.dup)) || (qos > 0 && !p.packet_id)) return false;
    if (p.topic.empty() ? !(v5 && p.properties.topic_alias) : !valid_topic_name(p.topic)) return false;
    if (!v5 && !empty(p.properties)) return false;
    w.text(p.topic);
    if (qos) w.u16(p.packet_id);
    if (v5 && !write_properties(w, p.properties, bit(PacketType::publish))) return false;
    w.raw(p.payload);
    return true;
}

bool encode_ack(Writer& w, const Ack& a, Version version) {
    if (a.type < PacketType::puback || a.type > PacketType::pubcomp || !a.packet_id ||
        !valid_reason(a.type, version, a.reason))
        return false;
    w.u16(a.packet_id);
    if (version == Version::v311) return empty(a.properties);
    if (a.reason == reason::success && empty(a.properties)) return true;
    w.u8(a.reason);
    return empty(a.properties) || write_properties(w, a.properties, bit(a.type));
}

bool encode_subscribe(Writer& w, const Subscribe& s, Version version) {
    const bool v5 = version == Version::v5;
    if (!s.packet_id || s.subscriptions.empty() || (!v5 && !empty(s.properties))) return false;
    w.u16(s.packet_id);
    if (v5 && !write_properties(w, s.properties, bit(PacketType::subscribe))) return false;
    for (const auto& sub : s.subscriptions) {
        const auto qos = static_cast<unsigned>(sub.qos);
        if (!valid_topic_filter(sub.filter, version) || qos > 2) return false;
        if (!v5 && (sub.no_local || sub.retain_as_published || sub.retain_handling)) return false;
        if (sub.retain_handling > 2 || (sub.no_local && shared(sub.filter) && v5)) return false;
        w.text(sub.filter);
        w.u8(qos | (sub.no_local ? 0x04u : 0u) | (sub.retain_as_published ? 0x08u : 0u) |
             (static_cast<std::uint32_t>(sub.retain_handling) << 4));
    }
    return true;
}

bool encode_reasons(Writer& w, PacketType type, std::uint16_t id, const std::vector<std::uint8_t>& reasons,
                    const Properties& properties, Version version) {
    const bool v5 = version == Version::v5;
    if (!id || (!v5 && !empty(properties))) return false;
    w.u16(id);
    if (!v5 && type == PacketType::unsuback) return reasons.empty();
    if (reasons.empty()) return false;
    if (v5 && !write_properties(w, properties, bit(type))) return false;
    for (const auto code : reasons) {
        if (!valid_reason(type, version, code)) return false;
        w.u8(code);
    }
    return true;
}

bool encode_unsubscribe(Writer& w, const Unsubscribe& u, Version version) {
    const bool v5 = version == Version::v5;
    if (!u.packet_id || u.filters.empty() || (!v5 && !empty(u.properties))) return false;
    w.u16(u.packet_id);
    if (v5 && !write_properties(w, u.properties, bit(PacketType::unsubscribe))) return false;
    for (const auto& filter : u.filters) {
        if (!valid_topic_filter(filter, version)) return false;
        w.text(filter);
    }
    return true;
}

// DISCONNECT and AUTH share the optional reason + properties tail.
bool encode_tail(Writer& w, PacketType type, std::uint8_t code, const Properties& properties, Version version) {
    if (version == Version::v311) return type == PacketType::disconnect && code == 0 && empty(properties);
    if (!valid_reason(type, version, code)) return false;
    if (code == reason::success && empty(properties)) return true;
    w.u8(code);
    return empty(properties) || write_properties(w, properties, bit(type));
}

// ── decoders ────────────────────────────────────────────────────────────────

using Outcome = std::variant<Packet, MqttError>;

Outcome finish(Reader& r, Packet packet) {
    if (r.bad || r.left()) return MqttError::malformed_packet;
    return packet;
}

Outcome decode_connect(Reader& r) {
    const auto name = r.text();
    const auto level = r.u8();
    if (r.bad) return MqttError::malformed_packet;
    if (name != "MQTT") return name == "MQIsdp" ? MqttError::unsupported_version : MqttError::malformed_packet;
    if (level != 4 && level != 5) return MqttError::unsupported_version;
    Connect c;
    c.version = static_cast<Version>(level);
    const bool v5 = c.version == Version::v5;
    const auto flags = r.u8();
    const bool will = (flags & 0x04) != 0, password = (flags & 0x40) != 0, username = (flags & 0x80) != 0;
    const auto will_qos = (flags >> 3) & 0x03;
    if ((flags & 0x01) || will_qos == 3 || (!will && (will_qos || (flags & 0x20))) || (!v5 && password && !username))
        return MqttError::malformed_packet;
    c.clean_start = (flags & 0x02) != 0;
    c.keep_alive = r.u16();
    if (v5)
        if (const auto e = read_properties(r, c.properties, bit(PacketType::connect)); e != MqttError{}) return e;
    c.client_id = r.text();
    if (will) {
        Will w;
        if (v5)
            if (const auto e = read_properties(r, w.properties, will_context); e != MqttError{}) return e;
        w.topic = r.text();
        w.payload = r.binary();
        w.qos = static_cast<QoS>(will_qos);
        w.retain = (flags & 0x20) != 0;
        if (!r.bad && !valid_topic_name(w.topic)) return MqttError::malformed_packet;
        c.will = std::move(w);
    }
    if (username) c.username = r.text();
    if (password) c.password = r.binary();
    return finish(r, std::move(c));
}

Outcome decode_connack(Reader& r, Version version) {
    Connack c;
    const auto flags = r.u8();
    c.reason = r.u8();
    c.session_present = (flags & 0x01) != 0;
    if (r.bad || (flags & 0xFE) || !valid_reason(PacketType::connack, version, c.reason) ||
        (c.session_present && c.reason != reason::success))
        return MqttError::malformed_packet;
    if (version == Version::v5)
        if (const auto e = read_properties(r, c.properties, bit(PacketType::connack)); e != MqttError{}) return e;
    return finish(r, std::move(c));
}

Outcome decode_publish(Reader& r, std::uint8_t flags, Version version, Role receiver) {
    Publish p;
    p.dup = (flags & 0x08) != 0;
    p.qos = static_cast<QoS>((flags >> 1) & 0x03);
    p.retain = (flags & 0x01) != 0;
    p.topic = r.text();
    if (p.qos != QoS::at_most_once) {
        p.packet_id = r.u16();
        if (!r.bad && !p.packet_id) return MqttError::malformed_packet;
    } else if (p.dup) {
        return MqttError::malformed_packet;
    }
    if (version == Version::v5) {
        if (const auto e = read_properties(r, p.properties, bit(PacketType::publish)); e != MqttError{}) return e;
        // A client never tags its own PUBLISH with subscription identifiers.
        if (receiver == Role::server && !p.properties.subscription_identifiers.empty())
            return MqttError::protocol_error;
    }
    if (r.bad) return MqttError::malformed_packet;
    if (p.topic.empty() ? !(version == Version::v5 && p.properties.topic_alias) : !valid_topic_name(p.topic))
        return MqttError::protocol_error;
    const auto payload = r.take(r.left());
    p.payload.assign(payload.begin(), payload.end());
    return finish(r, std::move(p));
}

Outcome decode_ack(Reader& r, PacketType type, Version version) {
    Ack a;
    a.type = type;
    a.packet_id = r.u16();
    if (r.bad || !a.packet_id) return MqttError::malformed_packet;
    if (version == Version::v5 && r.left()) {
        a.reason = r.u8();
        if (!valid_reason(type, version, a.reason)) return MqttError::malformed_packet;
        if (r.left())
            if (const auto e = read_properties(r, a.properties, bit(type)); e != MqttError{}) return e;
    }
    return finish(r, std::move(a));
}

Outcome decode_subscribe(Reader& r, Version version) {
    const bool v5 = version == Version::v5;
    Subscribe s;
    s.packet_id = r.u16();
    if (r.bad || !s.packet_id) return MqttError::malformed_packet;
    if (v5)
        if (const auto e = read_properties(r, s.properties, bit(PacketType::subscribe)); e != MqttError{}) return e;
    while (!r.bad && r.left()) {
        Subscription sub;
        sub.filter = r.text();
        const auto options = r.u8();
        if (r.bad) break;
        sub.qos = static_cast<QoS>(options & 0x03);
        sub.no_local = (options & 0x04) != 0;
        sub.retain_as_published = (options & 0x08) != 0;
        sub.retain_handling = static_cast<std::uint8_t>((options >> 4) & 0x03);
        if ((options & 0x03) == 3 || (options & (v5 ? 0xC0 : 0xFC)) || sub.retain_handling == 3 ||
            !valid_topic_filter(sub.filter, version))
            return MqttError::malformed_packet;
        if (v5 && sub.no_local && shared(sub.filter)) return MqttError::protocol_error;
        s.subscriptions.push_back(std::move(sub));
    }
    if (!r.bad && s.subscriptions.empty()) return MqttError::protocol_error;
    return finish(r, std::move(s));
}

template<class Reply>
Outcome decode_reasons(Reader& r, PacketType type, Version version) {
    Reply reply;
    reply.packet_id = r.u16();
    if (r.bad || !reply.packet_id) return MqttError::malformed_packet;
    if (version == Version::v311 && type == PacketType::unsuback) return finish(r, std::move(reply));
    if (version == Version::v5)
        if (const auto e = read_properties(r, reply.properties, bit(type)); e != MqttError{}) return e;
    if (r.bad || !r.left()) return MqttError::malformed_packet;
    while (r.left()) {
        const auto code = r.u8();
        if (!valid_reason(type, version, code)) return MqttError::malformed_packet;
        reply.reasons.push_back(code);
    }
    return finish(r, std::move(reply));
}

Outcome decode_unsubscribe(Reader& r, Version version) {
    Unsubscribe u;
    u.packet_id = r.u16();
    if (r.bad || !u.packet_id) return MqttError::malformed_packet;
    if (version == Version::v5)
        if (const auto e = read_properties(r, u.properties, bit(PacketType::unsubscribe)); e != MqttError{}) return e;
    while (!r.bad && r.left()) {
        auto filter = r.text();
        if (!r.bad && !valid_topic_filter(filter, version)) return MqttError::malformed_packet;
        u.filters.push_back(std::move(filter));
    }
    if (!r.bad && u.filters.empty()) return MqttError::protocol_error;
    return finish(r, std::move(u));
}

template<class Tail>
Outcome decode_tail(Reader& r, PacketType type, Version version) {
    Tail tail;
    if (version == Version::v5 && r.left()) {
        tail.reason = r.u8();
        if (!valid_reason(type, version, tail.reason)) return MqttError::malformed_packet;
        if (r.left())
            if (const auto e = read_properties(r, tail.properties, bit(type)); e != MqttError{}) return e;
    }
    return finish(r, std::move(tail));
}

// Who may send each packet type: bit 0 client, bit 1 server.
unsigned senders(PacketType type, Version version) {
    using enum PacketType;
    switch (type) {
    case connect: case subscribe: case unsubscribe: case pingreq: return 1;
    case connack: case suback: case unsuback: case pingresp: return 2;
    case publish: case puback: case pubrec: case pubrel: case pubcomp: return 3;
    case disconnect: return version == Version::v5 ? 3 : 1;
    case auth: return version == Version::v5 ? 3 : 0;
    }
    return 0;
}

}  // namespace

const std::error_category& mqtt_category() noexcept {
    static const MqttCategory category{};
    return category;
}

std::error_code make_error_code(MqttError error) noexcept {
    return {static_cast<int>(error), mqtt_category()};
}

PacketType type_of(const Packet& packet) noexcept {
    if (const auto* ack = std::get_if<Ack>(&packet)) return ack->type;
    constexpr std::array types{PacketType::connect, PacketType::connack, PacketType::publish, PacketType::puback,
                               PacketType::subscribe, PacketType::suback, PacketType::unsubscribe,
                               PacketType::unsuback, PacketType::pingreq, PacketType::pingresp,
                               PacketType::disconnect, PacketType::auth};
    return types[packet.index()];
}

Result<Bytes> encode(const Packet& packet, Version version) {
    if (version != Version::v311 && version != Version::v5) return fail(Errc::invalid_argument);
    Writer w;
    const auto type = type_of(packet);
    std::uint32_t flags = required_flags(type);
    bool ok = true;
    if (const auto* c = std::get_if<Connect>(&packet)) ok = encode_connect(w, *c, version);
    else if (const auto* ca = std::get_if<Connack>(&packet)) {
        ok = valid_reason(PacketType::connack, version, ca->reason) &&
             !(ca->session_present && ca->reason != reason::success) &&
             (version == Version::v5 || empty(ca->properties));
        w.u8(ca->session_present ? 1 : 0);
        w.u8(ca->reason);
        if (ok && version == Version::v5) ok = write_properties(w, ca->properties, bit(PacketType::connack));
    } else if (const auto* p = std::get_if<Publish>(&packet)) {
        ok = encode_publish(w, *p, version);
        flags = (p->dup ? 0x08u : 0u) | (static_cast<std::uint32_t>(p->qos) << 1) | (p->retain ? 0x01u : 0u);
    } else if (const auto* a = std::get_if<Ack>(&packet)) ok = encode_ack(w, *a, version);
    else if (const auto* s = std::get_if<Subscribe>(&packet)) ok = encode_subscribe(w, *s, version);
    else if (const auto* sa = std::get_if<Suback>(&packet))
        ok = encode_reasons(w, PacketType::suback, sa->packet_id, sa->reasons, sa->properties, version);
    else if (const auto* u = std::get_if<Unsubscribe>(&packet)) ok = encode_unsubscribe(w, *u, version);
    else if (const auto* ua = std::get_if<Unsuback>(&packet))
        ok = encode_reasons(w, PacketType::unsuback, ua->packet_id, ua->reasons, ua->properties, version);
    else if (const auto* d = std::get_if<Disconnect>(&packet))
        ok = encode_tail(w, PacketType::disconnect, d->reason, d->properties, version);
    else if (const auto* au = std::get_if<Auth>(&packet))
        ok = encode_tail(w, PacketType::auth, au->reason, au->properties, version);
    if (!ok) return fail(Errc::invalid_argument);
    return frame(type, flags, w.out);
}

Result<Decoded> decode(std::span<const std::byte> input, Version version, Role receiver, std::size_t maximum) {
    if ((version != Version::v311 && version != Version::v5) || maximum < 2) return fail(Errc::invalid_argument);
    maximum = std::min(maximum, max_packet_size);
    if (input.empty()) return Decoded{};
    const auto first = std::to_integer<std::uint8_t>(input[0]);
    const auto raw_type = first >> 4;
    const auto flags = static_cast<std::uint8_t>(first & 0x0F);
    if (raw_type == 0) return fail(MqttError::malformed_packet);
    const auto type = static_cast<PacketType>(raw_type);
    // A server learns the version from CONNECT itself.
    const auto sender_version = type == PacketType::connect ? Version::v5 : version;
    const unsigned from = receiver == Role::client ? 2 : 1;
    if (!(senders(type, sender_version) & from)) return fail(MqttError::protocol_error);
    if (type == PacketType::publish ? ((flags >> 1) & 0x03) == 3 : flags != required_flags(type))
        return fail(MqttError::malformed_packet);
    std::uint32_t remaining = 0, scale = 1;
    std::size_t header = 1;
    for (;; ++header) {
        if (header > 4) return fail(MqttError::malformed_packet);
        if (header >= input.size()) return Decoded{};
        const auto digit = std::to_integer<std::uint32_t>(input[header]);
        remaining += (digit & 0x7F) * scale;
        if (!(digit & 0x80)) {
            if (header > 1 && digit == 0) return fail(MqttError::malformed_packet);
            break;
        }
        scale *= 128;
    }
    const std::size_t total = header + 1 + remaining;
    if (total > maximum) return fail(MqttError::packet_too_large);
    if (input.size() < total) return Decoded{};
    Reader r{input.subspan(header + 1, remaining)};
    using enum PacketType;
    Outcome outcome = MqttError::malformed_packet;
    switch (type) {
    case connect: outcome = decode_connect(r); break;
    case connack: outcome = decode_connack(r, version); break;
    case publish: outcome = decode_publish(r, flags, version, receiver); break;
    case puback: case pubrec: case pubrel: case pubcomp: outcome = decode_ack(r, type, version); break;
    case subscribe: outcome = decode_subscribe(r, version); break;
    case suback: outcome = decode_reasons<Suback>(r, type, version); break;
    case unsubscribe: outcome = decode_unsubscribe(r, version); break;
    case unsuback: outcome = decode_reasons<Unsuback>(r, type, version); break;
    case pingreq: outcome = finish(r, Pingreq{}); break;
    case pingresp: outcome = finish(r, Pingresp{}); break;
    case disconnect: outcome = decode_tail<Disconnect>(r, type, version); break;
    case auth: outcome = decode_tail<Auth>(r, type, version); break;
    }
    if (const auto* error = std::get_if<MqttError>(&outcome)) return fail(*error);
    return Decoded{std::move(std::get<Packet>(outcome)), total};
}

bool valid_string(std::string_view text) noexcept {
    if (text.size() > 65535) return false;
    for (std::size_t i = 0; i < text.size();) {
        const auto lead = static_cast<unsigned char>(text[i]);
        if (lead == 0) return false;
        if (lead < 0x80) {
            ++i;
            continue;
        }
        std::size_t extra = 0;
        std::uint32_t code = 0;
        if (lead >= 0xC2 && lead <= 0xDF) {
            extra = 1;
            code = lead & 0x1Fu;
        } else if ((lead & 0xF0) == 0xE0) {
            extra = 2;
            code = lead & 0x0Fu;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            extra = 3;
            code = lead & 0x07u;
        } else {
            return false;
        }
        if (text.size() - i <= extra) return false;
        for (std::size_t k = 1; k <= extra; ++k) {
            const auto next = static_cast<unsigned char>(text[i + k]);
            if ((next & 0xC0) != 0x80) return false;
            code = (code << 6) | (next & 0x3Fu);
        }
        if ((extra == 2 && code < 0x800) || (extra == 3 && (code < 0x10000 || code > 0x10FFFF)) ||
            (code >= 0xD800 && code <= 0xDFFF))
            return false;
        i += extra + 1;
    }
    return true;
}

bool valid_topic_name(std::string_view topic) noexcept {
    return !topic.empty() && valid_string(topic) && topic.find_first_of("+#") == std::string_view::npos;
}

bool valid_topic_filter(std::string_view filter, Version version) noexcept {
    if (version == Version::v5 && shared(filter)) {
        const auto rest = filter.substr(7);
        const auto slash = rest.find('/');
        if (slash == std::string_view::npos || slash == 0 ||
            rest.substr(0, slash).find_first_of("+#") != std::string_view::npos)
            return false;
        return valid_string(filter) && valid_levels(rest.substr(slash + 1));
    }
    return valid_levels(filter);
}

bool topic_matches(std::string_view filter, std::string_view name) noexcept {
    if (shared(filter)) {
        const auto slash = filter.find('/', 7);
        if (slash == std::string_view::npos) return false;
        filter = filter.substr(slash + 1);
    }
    if (filter.empty() || name.empty()) return false;
    if (name.front() == '$' && (filter.front() == '+' || filter.front() == '#')) return false;
    std::size_t f = 0, n = 0;
    bool name_done = false;
    for (;;) {
        const auto f_end = std::min(filter.find('/', f), filter.size());
        const auto level = filter.substr(f, f_end - f);
        if (level == "#") return true;
        if (name_done) return false;
        const auto n_end = std::min(name.find('/', n), name.size());
        if (level != "+" && level != name.substr(n, n_end - n)) return false;
        if (f_end == filter.size()) return n_end == name.size();
        f = f_end + 1;
        if (n_end == name.size()) name_done = true;
        else n = n_end + 1;
    }
}

}  // namespace Mira::mqtt
