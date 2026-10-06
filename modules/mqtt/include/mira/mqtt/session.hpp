#pragma once

// Mira/mqtt/session.hpp — socket-free MQTT client session.
//
// The session owns everything MQTT asks a client to remember and nothing about
// sockets: the caller feeds received bytes, writes `take_output`, and wakes it
// at `next_timer` for keep-alive. Time is monotonic nanoseconds.
//
// It implements the QoS 1/2 sender and receiver flows, packet-identifier
// allocation, the server's CONNACK limits (Receive Maximum, Maximum Packet
// Size, Maximum QoS, Retain/Wildcard/Shared/Subscription-Identifier
// availability, Server Keep Alive, Assigned Client Identifier), inbound topic
// aliases, keep-alive with PINGRESP supervision, and session resumption: a
// later `connect` on a fresh transport resends unacknowledged PUBLISH (DUP)
// and PUBREL in their original order when the server reports a present
// session, and reports them `discarded` when it does not.
//
// Received QoS 1 messages are acknowledged as they are surfaced; QoS 2 ones
// are surfaced once and released on PUBREL. Nothing is queued invisibly:
// exceeding the server's Receive Maximum, a packet-identifier shortage or the
// output bound return `would_block`; peer violations close the session (with a
// 5.0 DISCONNECT carrying the reason) and fail `receive`.

#include "mira/mqtt/packet.hpp"
#include "mira/core/stream.hpp"

#include <limits>
#include <memory>

namespace Mira::mqtt {

template<BoundedStream Stream> class Client;

struct ClientOptions {
    Version version = Version::v5;
    /// Empty: the server assigns one (5.0); 3.1.1 then requires clean_start.
    std::string client_id{};
    bool clean_start = true;
    /// Seconds; 0 disables keep-alive. A 5.0 Server Keep Alive overrides it.
    std::uint16_t keep_alive = 60;
    std::optional<std::string> username{};
    std::optional<Bytes> password{};
    std::optional<Will> will{};
    /// Further 5.0 CONNECT properties (Session Expiry, authentication, user
    /// properties...). Receive Maximum, Maximum Packet Size and Topic Alias
    /// Maximum come from the fields below and must stay unset here.
    Properties properties{};
    /// Largest packet accepted from the server; advertised in 5.0.
    std::uint32_t maximum_packet_size = 1024 * 1024;
    /// Unreleased inbound QoS 2 messages allowed at once; advertised in 5.0.
    std::uint16_t receive_maximum = 64;
    /// Inbound topic aliases accepted (5.0); 0 refuses aliases.
    std::uint16_t topic_alias_maximum = 0;
    /// Undelivered events, including connection and abandonment notices.
    std::size_t max_events = 4096;
    /// Unwritten output bytes.
    std::size_t max_output = 4 * 1024 * 1024;
};

struct Message {
    std::string topic{};
    Bytes payload{};
    QoS qos = QoS::at_most_once;
    bool retain = false;
    bool dup = false;
    Properties properties{};
};

struct Event {
    enum class Kind {
        /// CONNACK: `session_present`, `reason`, `properties`.
        connected,
        /// Application message in `message`.
        message,
        /// A QoS 1/2 publish finished (`packet_id`, final `reason`).
        published,
        /// SUBACK / UNSUBACK: `packet_id`, one reason per filter in `reasons`.
        subscribed,
        unsubscribed,
        /// Server DISCONNECT (5.0): `reason`, `properties`.
        disconnected,
        /// Server AUTH (5.0): `reason`, `properties`; answer with Session::auth.
        auth,
    } kind;
    std::uint16_t packet_id = 0;
    std::uint8_t reason = reason::success;
    std::vector<std::uint8_t> reasons{};
    bool session_present = false;
    /// The operation was never acknowledged and is abandoned: its session was
    /// cleaned or lost, or (subscribe/unsubscribe) its connection ended.
    bool discarded = false;
    Message message{};
    Properties properties{};
};

enum class SessionState { idle, connecting, connected, closed };

class Session {
public:
    static Result<Session> create(ClientOptions options);
    /// Portable versioned checkpoint of pending QoS 1/2 publishes and inbound
    /// QoS 2 release identifiers. The caller owns atomic durable storage and
    /// must bind scope to broker identity + credentials/tenant policy. No secret
    /// credentials are serialized, but message payloads may contain secrets.
    /// Refuses undelivered events or pending subscription requests. Persist
    /// before acknowledging a business transaction; this is not a WAL or an
    /// exactly-once application transaction guarantee. QoS 0 is not persisted.
    [[nodiscard]] Result<Bytes> checkpoint(std::string_view scope,
                                          std::size_t max_bytes = 16 * 1024 * 1024) const;
    /// Restores into idle state, then connect on a fresh transport. Requires
    /// clean_start=false and matching version, client_id and nonempty scope.
    /// Untrusted snapshots are bounded and validated before state is published.
    /// Supply time elapsed since checkpoint for message expiry; expired outgoing
    /// entries are surfaced as discarded events, not replayed. Broker session
    /// expiry is authoritative in CONNACK. The snapshot stores no wall clock.
    [[nodiscard]] static Result<Session> restore(ClientOptions options,
        std::span<const std::byte> checkpoint, std::string_view scope,
        std::size_t max_bytes = 16 * 1024 * 1024,
        std::uint32_t elapsed_seconds = 0);
    Session(Session&&) noexcept;
    Session& operator=(Session&&) noexcept;
    ~Session();

    /// Queue CONNECT for a new transport, discarding anything unsent on the old
    /// one. After a transport loss, call it again to resume (clean_start = false).
    /// Returns would_block without changing state if abandonment notices will
    /// not fit; consume prior events before retrying.
    Result<void> connect(std::uint64_t now, std::size_t externally_buffered_events = 0);
    Result<void> receive(std::span<const std::byte> bytes, std::uint64_t now,
                         std::size_t externally_buffered_events = 0);

    /// Assigns the packet identifier (returned; 0 for QoS 0) and clears DUP.
    Result<std::uint16_t> publish(Publish message, std::span<const std::uint16_t> retained_ids = {});
    Result<std::uint16_t> subscribe(std::vector<Subscription> subscriptions, Properties properties = {},
                                    std::span<const std::uint16_t> retained_ids = {});
    Result<std::uint16_t> unsubscribe(std::vector<std::string> filters, Properties properties = {},
                                      std::span<const std::uint16_t> retained_ids = {});
    /// Queue DISCONNECT and close. Unacknowledged publishes stay for a resume.
    Result<void> disconnect(std::uint8_t reason = reason::success, Properties properties = {});
    Result<void> auth(std::uint8_t reason, Properties properties);

    /// Sends PINGREQ after keep-alive seconds without output; fails with
    /// keep_alive_timeout when no PINGRESP follows within the same interval.
    Result<void> handle_timer(std::uint64_t now);
    /// Next handle_timer deadline; max() when none.
    [[nodiscard]] std::uint64_t next_timer() const noexcept;

    /// Bytes to write. Taking non-empty output at `now` restarts keep-alive.
    [[nodiscard]] Bytes take_output(std::uint64_t now);
    [[nodiscard]] bool has_output() const noexcept;
    [[nodiscard]] std::vector<Event> take_events();

    [[nodiscard]] SessionState state() const noexcept;
    [[nodiscard]] Version version() const noexcept;
    /// Possibly server-assigned.
    [[nodiscard]] const std::string& client_id() const noexcept;
    /// Effective keep-alive in seconds.
    [[nodiscard]] std::uint16_t keep_alive() const noexcept;
    /// Unacknowledged QoS 1/2 publishes.
    [[nodiscard]] std::size_t inflight() const noexcept;
    [[nodiscard]] std::uint16_t server_receive_maximum() const noexcept;
    [[nodiscard]] std::size_t server_maximum_packet_size() const noexcept;

private:
    template<BoundedStream Stream> friend class Client;
    [[nodiscard]] Result<Bytes> checkpoint_impl(std::string_view scope, std::size_t max_bytes) const;
    struct Impl;
    explicit Session(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
    bool client_owned_ = false;
};

}  // namespace Mira::mqtt
