#include "mira/mqtt/session.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <utility>

namespace Mira::mqtt {
namespace {

constexpr std::uint64_t second = 1'000'000'000;

bool wildcard(std::string_view filter) { return filter.find_first_of("+#") != std::string_view::npos; }

bool failure(Version version, std::uint8_t code) {
    return version == Version::v5 ? code >= 0x80 : code != 0;
}

}  // namespace

struct Session::Impl {
    ClientOptions options;
    SessionState state = SessionState::idle;
    Bytes input, output;
    std::vector<Event> events;

    std::uint16_t server_receive_max = 65535;
    std::size_t server_max_packet = max_packet_size;
    std::uint8_t server_max_qos = 2;
    bool retain_available = true, wildcard_available = true;
    bool identifiers_available = true, shared_available = true;
    std::uint16_t keep_alive = 0;

    enum class Stage { puback, pubrec, pubcomp };
    struct Outgoing {
        Publish publish;
        Stage stage;
        std::uint64_t order;
    };
    std::map<std::uint16_t, Outgoing> outgoing;
    struct Request {
        PacketType type;
        std::size_t filters;
    };
    std::map<std::uint16_t, Request> requests;
    std::set<std::uint16_t> releasing;  // Inbound QoS 2 awaiting PUBREL.
    std::map<std::uint16_t, std::string> aliases;
    std::uint16_t next_id = 1;
    std::uint64_t order = 0;
    std::uint64_t last_sent = 0;
    std::optional<std::uint64_t> ping_sent;

    bool v5() const { return options.version == Version::v5; }

    // Session-originated control packets (acks, PINGREQ, CONNECT, resends).
    Result<void> queue(const Packet& packet) {
        auto bytes = encode(packet, options.version);
        if (!bytes) return fail(bytes.error());
        if (bytes->size() > options.max_output || output.size() > options.max_output - bytes->size())
            return fail(Errc::limit_exceeded);
        output.insert(output.end(), bytes->begin(), bytes->end());
        return {};
    }

    Result<void> close_with(Error error, std::uint8_t code) {
        if (v5() && state == SessionState::connected)
            static_cast<void>(queue(Disconnect{code, {}}));
        state = SessionState::closed;
        return fail(error);
    }

    Result<void> push(Event event) {
        if (events.size() >= options.max_events)
            return close_with(make_error_code(Errc::limit_exceeded), reason::implementation_specific_error);
        events.push_back(std::move(event));
        return {};
    }

    // Abandonment notices are bounded by the state they report.
    void discard(Event::Kind kind, std::uint16_t id) {
        Event event{kind};
        event.packet_id = id;
        event.reason = reason::unspecified_error;
        event.discarded = true;
        events.push_back(std::move(event));
    }

    void discard_session() {
        std::vector<std::pair<std::uint64_t, std::uint16_t>> lost;
        for (const auto& [id, entry] : outgoing) lost.emplace_back(entry.order, id);
        std::sort(lost.begin(), lost.end());
        for (const auto& [unused, id] : lost) discard(Event::Kind::published, id);
        outgoing.clear();
        releasing.clear();
    }

    std::uint16_t allocate() {
        for (std::uint32_t tries = 0; tries < 65535; ++tries) {
            const auto id = next_id;
            next_id = static_cast<std::uint16_t>(next_id == 65535 ? 1 : next_id + 1);
            if (!outgoing.contains(id) && !requests.contains(id)) return id;
        }
        return 0;
    }

    Result<void> connack(const Connack& c) {
        if (state != SessionState::connecting)
            return close_with(make_error_code(MqttError::protocol_error), reason::protocol_error);
        Event event{Event::Kind::connected};
        event.reason = c.reason;
        event.session_present = c.session_present;
        event.properties = c.properties;
        if (failure(options.version, c.reason)) {
            events.push_back(std::move(event));
            state = SessionState::closed;
            return fail(MqttError::refused);
        }
        if (c.session_present && options.clean_start)
            return close_with(make_error_code(MqttError::protocol_error), reason::protocol_error);
        const auto& p = c.properties;
        server_receive_max = p.receive_maximum.value_or(65535);
        server_max_packet = p.maximum_packet_size.value_or(static_cast<std::uint32_t>(max_packet_size));
        server_max_qos = p.maximum_qos.value_or(2);
        retain_available = p.retain_available.value_or(1) != 0;
        wildcard_available = p.wildcard_subscription_available.value_or(1) != 0;
        identifiers_available = p.subscription_identifiers_available.value_or(1) != 0;
        shared_available = p.shared_subscription_available.value_or(1) != 0;
        keep_alive = p.server_keep_alive.value_or(options.keep_alive);
        if (p.assigned_client_identifier) options.client_id = *p.assigned_client_identifier;
        state = SessionState::connected;
        if (!c.session_present) {
            discard_session();
        } else {
            std::vector<std::pair<std::uint64_t, std::uint16_t>> resend;
            for (const auto& [id, entry] : outgoing) resend.emplace_back(entry.order, id);
            std::sort(resend.begin(), resend.end());
            for (const auto& [unused, id] : resend) {
                auto& entry = outgoing.at(id);
                Packet packet = Ack{PacketType::pubrel, id, reason::success, {}};
                if (entry.stage != Stage::pubcomp) {
                    entry.publish.dup = true;
                    packet = entry.publish;
                }
                if (auto r = queue(packet); !r) return close_with(r.error(), reason::implementation_specific_error);
            }
        }
        return push(std::move(event));
    }

    Result<void> publish_in(Publish p) {
        if (state != SessionState::connected)
            return close_with(make_error_code(MqttError::protocol_error), reason::protocol_error);
        if (const auto alias = p.properties.topic_alias) {
            if (*alias > options.topic_alias_maximum)
                return close_with(make_error_code(MqttError::topic_alias_invalid), reason::topic_alias_invalid);
            if (!p.topic.empty()) aliases[*alias] = p.topic;
            else if (const auto it = aliases.find(*alias); it != aliases.end()) p.topic = it->second;
            else return close_with(make_error_code(MqttError::topic_alias_invalid), reason::topic_alias_invalid);
        }
        const auto id = p.packet_id;
        if (p.qos == QoS::exactly_once) {
            if (releasing.contains(id)) return queue(Ack{PacketType::pubrec, id, reason::success, {}});
            if (releasing.size() >= options.receive_maximum)
                return close_with(make_error_code(MqttError::receive_maximum_exceeded),
                                  reason::receive_maximum_exceeded);
        }
        Event event{Event::Kind::message};
        event.message = {std::move(p.topic), std::move(p.payload), p.qos, p.retain, p.dup, std::move(p.properties)};
        if (auto r = push(std::move(event)); !r) return r;
        if (p.qos == QoS::at_least_once) return queue(Ack{PacketType::puback, id, reason::success, {}});
        if (p.qos == QoS::exactly_once) {
            releasing.insert(id);
            return queue(Ack{PacketType::pubrec, id, reason::success, {}});
        }
        return {};
    }

    Result<void> finished(std::uint16_t id, const Ack& a) {
        outgoing.erase(id);
        Event event{Event::Kind::published};
        event.packet_id = id;
        event.reason = a.reason;
        event.properties = a.properties;
        return push(std::move(event));
    }

    Result<void> ack(const Ack& a) {
        if (state != SessionState::connected)
            return close_with(make_error_code(MqttError::protocol_error), reason::protocol_error);
        const auto id = a.packet_id;
        const auto it = outgoing.find(id);
        const bool known = it != outgoing.end();
        switch (a.type) {
        case PacketType::puback:
            if (known && it->second.stage == Stage::puback) return finished(id, a);
            return {};  // Stale acknowledgement from before a resume.
        case PacketType::pubrec:
            if (!known)
                return queue(Ack{PacketType::pubrel, id, v5() ? reason::packet_identifier_not_found : reason::success, {}});
            if (it->second.stage == Stage::puback)
                return close_with(make_error_code(MqttError::protocol_error), reason::protocol_error);
            if (it->second.stage == Stage::pubrec) {
                if (failure(options.version, a.reason)) return finished(id, a);
                it->second.stage = Stage::pubcomp;
                it->second.publish.payload = {};  // Only the identifier is resent from here on.
            }
            return queue(Ack{PacketType::pubrel, id, reason::success, {}});
        case PacketType::pubrel:
            if (releasing.erase(id)) return queue(Ack{PacketType::pubcomp, id, reason::success, {}});
            return queue(Ack{PacketType::pubcomp, id, v5() ? reason::packet_identifier_not_found : reason::success, {}});
        case PacketType::pubcomp:
            if (known && it->second.stage == Stage::pubcomp) return finished(id, a);
            return {};
        default: return close_with(make_error_code(MqttError::protocol_error), reason::protocol_error);
        }
    }

    template<class Reply>
    Result<void> reply(const Reply& r, PacketType request, Event::Kind kind) {
        const auto it = requests.find(r.packet_id);
        if (state != SessionState::connected || it == requests.end() || it->second.type != request ||
            (!(kind == Event::Kind::unsubscribed && !v5()) && r.reasons.size() != it->second.filters))
            return close_with(make_error_code(MqttError::protocol_error), reason::protocol_error);
        requests.erase(it);
        Event event{kind};
        event.packet_id = r.packet_id;
        event.reasons = r.reasons;
        event.properties = r.properties;
        return push(std::move(event));
    }

    Result<void> handle(Packet packet) {
        if (auto* c = std::get_if<Connack>(&packet)) return connack(*c);
        if (state == SessionState::connecting && !std::holds_alternative<Auth>(packet) &&
            !std::holds_alternative<Disconnect>(packet))
            return close_with(make_error_code(MqttError::protocol_error), reason::protocol_error);
        if (auto* p = std::get_if<Publish>(&packet)) return publish_in(std::move(*p));
        if (auto* a = std::get_if<Ack>(&packet)) return ack(*a);
        if (auto* s = std::get_if<Suback>(&packet)) return reply(*s, PacketType::subscribe, Event::Kind::subscribed);
        if (auto* u = std::get_if<Unsuback>(&packet))
            return reply(*u, PacketType::unsubscribe, Event::Kind::unsubscribed);
        if (std::holds_alternative<Pingresp>(packet)) {
            ping_sent.reset();
            return {};
        }
        if (auto* d = std::get_if<Disconnect>(&packet)) {
            Event event{Event::Kind::disconnected};
            event.reason = d->reason;
            event.properties = std::move(d->properties);
            events.push_back(std::move(event));
            state = SessionState::closed;
            return {};
        }
        if (auto* au = std::get_if<Auth>(&packet)) {
            Event event{Event::Kind::auth};
            event.reason = au->reason;
            event.properties = std::move(au->properties);
            return push(std::move(event));
        }
        return close_with(make_error_code(MqttError::protocol_error), reason::protocol_error);
    }

    Result<void> ready_to_send() const {
        if (state == SessionState::closed) return fail(Errc::eof);
        if (state != SessionState::connected) return fail(Errc::invalid_argument);
        return {};
    }

    // Application packets: bounded by the server's maximum and our output budget.
    Result<void> submit(const Packet& packet) {
        auto bytes = encode(packet, options.version);
        if (!bytes) return fail(bytes.error());
        if (bytes->size() > server_max_packet) return fail(MqttError::packet_too_large);
        if (bytes->size() > options.max_output || output.size() > options.max_output - bytes->size())
            return fail(Errc::would_block);
        output.insert(output.end(), bytes->begin(), bytes->end());
        return {};
    }
};

Session::Session(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Session::Session(Session&&) noexcept = default;
Session& Session::operator=(Session&&) noexcept = default;
Session::~Session() = default;

Result<Session> Session::create(ClientOptions options) {
    const auto& p = options.properties;
    if ((options.version != Version::v311 && options.version != Version::v5) || !options.receive_maximum ||
        options.maximum_packet_size < 16 || options.maximum_packet_size > max_packet_size ||
        !options.max_events || options.max_output < 1024 || p.receive_maximum || p.maximum_packet_size ||
        p.topic_alias_maximum || (options.version == Version::v311 && options.topic_alias_maximum))
        return fail(Errc::invalid_argument);
    auto impl = std::make_unique<Impl>();
    impl->options = std::move(options);
    Session session(std::move(impl));
    // Validate the CONNECT this session will send, once, up front.
    if (auto r = session.connect(0); !r) return fail(r.error());
    session.impl_->output.clear();
    session.impl_->state = SessionState::idle;
    return session;
}

Result<void> Session::connect(std::uint64_t now) {
    auto& s = *impl_;
    // Any state: a new CONNECT always means a new transport, whatever the old one knew.
    for (const auto& [id, request] : s.requests)
        s.discard(request.type == PacketType::subscribe ? Event::Kind::subscribed : Event::Kind::unsubscribed, id);
    s.requests.clear();
    if (s.options.clean_start) s.discard_session();
    s.input.clear();
    s.output.clear();
    s.aliases.clear();
    s.ping_sent.reset();
    Connect c;
    c.version = s.options.version;
    c.client_id = s.options.client_id;
    c.clean_start = s.options.clean_start;
    c.keep_alive = s.options.keep_alive;
    c.username = s.options.username;
    c.password = s.options.password;
    c.will = s.options.will;
    c.properties = s.options.properties;
    if (s.v5()) {
        c.properties.receive_maximum = s.options.receive_maximum;
        c.properties.maximum_packet_size = s.options.maximum_packet_size;
        if (s.options.topic_alias_maximum) c.properties.topic_alias_maximum = s.options.topic_alias_maximum;
    }
    if (auto r = s.queue(c); !r) return fail(r.error() == Errc::limit_exceeded ? make_error_code(Errc::invalid_argument) : r.error());
    s.state = SessionState::connecting;
    s.keep_alive = s.options.keep_alive;
    s.last_sent = now;
    return {};
}

Result<void> Session::receive(std::span<const std::byte> bytes, std::uint64_t now) {
    auto& s = *impl_;
    static_cast<void>(now);
    if (s.state != SessionState::connecting && s.state != SessionState::connected)
        return fail(s.state == SessionState::closed ? Errc::eof : Errc::invalid_argument);
    s.input.insert(s.input.end(), bytes.begin(), bytes.end());
    std::size_t offset = 0;
    Result<void> outcome;
    while (s.state == SessionState::connecting || s.state == SessionState::connected) {
        auto decoded = decode(std::span{s.input}.subspan(offset), s.options.version, Role::client,
                              s.options.maximum_packet_size);
        if (!decoded) {
            const auto code = decoded.error() == MqttError::packet_too_large ? reason::packet_too_large
                              : decoded.error() == MqttError::malformed_packet ? reason::malformed_packet
                                                                                 : reason::protocol_error;
            outcome = s.close_with(decoded.error(), code);
            break;
        }
        if (!decoded->packet) break;
        offset += decoded->consumed;
        if (outcome = s.handle(std::move(*decoded->packet)); !outcome) break;
    }
    s.input.erase(s.input.begin(), s.input.begin() + static_cast<std::ptrdiff_t>(offset));
    return outcome;
}

Result<std::uint16_t> Session::publish(Publish message) {
    auto& s = *impl_;
    if (auto r = s.ready_to_send(); !r) return fail(r.error());
    if (static_cast<std::uint8_t>(message.qos) > s.server_max_qos || (message.retain && !s.retain_available) ||
        message.properties.topic_alias)
        return fail(Errc::not_supported);
    if (!message.properties.subscription_identifiers.empty()) return fail(Errc::invalid_argument);
    message.dup = false;
    message.packet_id = 0;
    if (message.qos != QoS::at_most_once) {
        if (s.outgoing.size() >= s.server_receive_max) return fail(Errc::would_block);
        message.packet_id = s.allocate();
        if (!message.packet_id) return fail(Errc::would_block);
    }
    if (auto r = s.submit(message); !r) return fail(r.error());
    const auto id = message.packet_id;
    if (id) {
        const auto stage = message.qos == QoS::at_least_once ? Impl::Stage::puback : Impl::Stage::pubrec;
        s.outgoing.emplace(id, Impl::Outgoing{std::move(message), stage, s.order++});
    }
    return id;
}

Result<std::uint16_t> Session::subscribe(std::vector<Subscription> subscriptions, Properties properties) {
    auto& s = *impl_;
    if (auto r = s.ready_to_send(); !r) return fail(r.error());
    for (const auto& sub : subscriptions)
        if ((!s.wildcard_available && wildcard(sub.filter)) ||
            (!s.shared_available && s.v5() && sub.filter.starts_with("$share/")))
            return fail(Errc::not_supported);
    if (!s.identifiers_available && !properties.subscription_identifiers.empty()) return fail(Errc::not_supported);
    const auto id = s.allocate();
    if (!id) return fail(Errc::would_block);
    const auto count = subscriptions.size();
    if (auto r = s.submit(Subscribe{id, std::move(subscriptions), std::move(properties)}); !r) return fail(r.error());
    s.requests.emplace(id, Impl::Request{PacketType::subscribe, count});
    return id;
}

Result<std::uint16_t> Session::unsubscribe(std::vector<std::string> filters, Properties properties) {
    auto& s = *impl_;
    if (auto r = s.ready_to_send(); !r) return fail(r.error());
    const auto id = s.allocate();
    if (!id) return fail(Errc::would_block);
    const auto count = filters.size();
    if (auto r = s.submit(Unsubscribe{id, std::move(filters), std::move(properties)}); !r) return fail(r.error());
    s.requests.emplace(id, Impl::Request{PacketType::unsubscribe, count});
    return id;
}

Result<void> Session::disconnect(std::uint8_t code, Properties properties) {
    auto& s = *impl_;
    if (s.state != SessionState::connected && s.state != SessionState::connecting) return fail(Errc::invalid_argument);
    if (auto r = s.queue(Disconnect{code, std::move(properties)}); !r)
        return fail(r.error() == Errc::limit_exceeded ? make_error_code(Errc::would_block) : r.error());
    s.state = SessionState::closed;
    return {};
}

Result<void> Session::auth(std::uint8_t code, Properties properties) {
    auto& s = *impl_;
    if (!s.v5() || (s.state != SessionState::connected && s.state != SessionState::connecting))
        return fail(Errc::invalid_argument);
    if (auto r = s.queue(Auth{code, std::move(properties)}); !r)
        return fail(r.error() == Errc::limit_exceeded ? make_error_code(Errc::would_block) : r.error());
    return {};
}

Result<void> Session::handle_timer(std::uint64_t now) {
    auto& s = *impl_;
    if (s.state != SessionState::connected || !s.keep_alive) return {};
    const auto interval = s.keep_alive * second;
    if (s.ping_sent) {
        if (now - *s.ping_sent < interval) return {};
        s.state = SessionState::closed;
        return fail(MqttError::keep_alive_timeout);
    }
    if (now - s.last_sent < interval) return {};
    if (auto r = s.queue(Pingreq{}); !r) return s.close_with(r.error(), reason::implementation_specific_error);
    s.ping_sent = now;
    return {};
}

std::uint64_t Session::next_timer() const noexcept {
    const auto& s = *impl_;
    if (s.state != SessionState::connected || !s.keep_alive) return std::numeric_limits<std::uint64_t>::max();
    return (s.ping_sent ? *s.ping_sent : s.last_sent) + s.keep_alive * second;
}

Bytes Session::take_output(std::uint64_t now) {
    auto& s = *impl_;
    if (!s.output.empty()) s.last_sent = std::max(s.last_sent, now);
    return std::exchange(s.output, {});
}

bool Session::has_output() const noexcept { return !impl_->output.empty(); }
std::vector<Event> Session::take_events() { return std::exchange(impl_->events, {}); }
SessionState Session::state() const noexcept { return impl_->state; }
Version Session::version() const noexcept { return impl_->options.version; }
const std::string& Session::client_id() const noexcept { return impl_->options.client_id; }
std::uint16_t Session::keep_alive() const noexcept { return impl_->keep_alive; }
std::size_t Session::inflight() const noexcept { return impl_->outgoing.size(); }
std::uint16_t Session::server_receive_maximum() const noexcept { return impl_->server_receive_max; }
std::size_t Session::server_maximum_packet_size() const noexcept { return impl_->server_max_packet; }

}  // namespace Mira::mqtt
