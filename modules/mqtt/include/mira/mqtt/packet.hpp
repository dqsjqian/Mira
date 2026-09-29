#pragma once

// Mira/mqtt/packet.hpp — MQTT 3.1.1 (OASIS 2014) and 5.0 (OASIS 2019) control
// packets: typed values, a strict encoder and a bounded incremental decoder.
//
// Both directions of all fifteen packet types are covered, so the same codec
// serves clients and brokers. The encoder refuses to emit anything the decoder
// would reject, and the decoder enforces the wire rules a peer can break:
// fixed-header flags, minimal Variable Byte Integers, well-formed UTF-8 without
// U+0000, topic name/filter syntax, packet identifiers, reason codes per packet
// and version, and — in 5.0 — which properties each packet may carry, their
// values, and duplicates. Direction is part of decoding: a client never
// accepts CONNECT or SUBSCRIBE, a broker never accepts CONNACK.
//
// Sizes are bounded before allocation: the fixed header alone decides whether
// a packet exceeds the caller's maximum, so an oversized packet fails without
// waiting for (or buffering) its body.

#include "mira/core/error.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>
#include <vector>

namespace Mira::mqtt {

using Bytes = std::vector<std::byte>;

/// Errors a peer (or a local limit) can cause. Caller mistakes when encoding
/// or submitting are reported as `Errc::invalid_argument` instead.
enum class MqttError {
    /// The bytes violate the wire format (5.0 reason 0x81).
    malformed_packet = 1,
    /// Well-formed, but not allowed here (0x82).
    protocol_error,
    /// Larger than the negotiated maximum packet size (0x95).
    packet_too_large,
    /// CONNECT names a protocol level other than 4 (3.1.1) or 5 (5.0).
    unsupported_version,
    /// The server refused the connection; the reason is in the CONNACK event.
    refused,
    /// The server sent DISCONNECT; the reason is in the event.
    disconnected,
    /// More unacknowledged QoS 2 messages than we allowed (0x93).
    receive_maximum_exceeded,
    /// A topic alias outside our advertised maximum, or an unknown one (0x94).
    topic_alias_invalid,
    /// No PINGRESP within the keep-alive interval.
    keep_alive_timeout,
};

[[nodiscard]] const std::error_category& mqtt_category() noexcept;
[[nodiscard]] std::error_code make_error_code(MqttError error) noexcept;

enum class Version : std::uint8_t { v311 = 4, v5 = 5 };
enum class QoS : std::uint8_t { at_most_once = 0, at_least_once = 1, exactly_once = 2 };
enum class PacketType : std::uint8_t {
    connect = 1, connack, publish, puback, pubrec, pubrel, pubcomp,
    subscribe, suback, unsubscribe, unsuback, pingreq, pingresp, disconnect, auth,
};
/// Which side is decoding: packets are only accepted from the opposite role.
enum class Role { client, server };

/// MQTT 5.0 reason codes. 3.1.1 CONNACK carries its raw return code (0-5) in
/// the same field; 3.1.1 SUBACK uses 0x00-0x02 and 0x80.
namespace reason {
inline constexpr std::uint8_t success = 0x00;
inline constexpr std::uint8_t granted_qos_1 = 0x01;
inline constexpr std::uint8_t granted_qos_2 = 0x02;
inline constexpr std::uint8_t disconnect_with_will = 0x04;
inline constexpr std::uint8_t no_matching_subscribers = 0x10;
inline constexpr std::uint8_t no_subscription_existed = 0x11;
inline constexpr std::uint8_t continue_authentication = 0x18;
inline constexpr std::uint8_t reauthenticate = 0x19;
inline constexpr std::uint8_t unspecified_error = 0x80;
inline constexpr std::uint8_t malformed_packet = 0x81;
inline constexpr std::uint8_t protocol_error = 0x82;
inline constexpr std::uint8_t implementation_specific_error = 0x83;
inline constexpr std::uint8_t unsupported_protocol_version = 0x84;
inline constexpr std::uint8_t client_identifier_not_valid = 0x85;
inline constexpr std::uint8_t bad_user_name_or_password = 0x86;
inline constexpr std::uint8_t not_authorized = 0x87;
inline constexpr std::uint8_t server_unavailable = 0x88;
inline constexpr std::uint8_t server_busy = 0x89;
inline constexpr std::uint8_t banned = 0x8A;
inline constexpr std::uint8_t server_shutting_down = 0x8B;
inline constexpr std::uint8_t bad_authentication_method = 0x8C;
inline constexpr std::uint8_t keep_alive_timeout = 0x8D;
inline constexpr std::uint8_t session_taken_over = 0x8E;
inline constexpr std::uint8_t topic_filter_invalid = 0x8F;
inline constexpr std::uint8_t topic_name_invalid = 0x90;
inline constexpr std::uint8_t packet_identifier_in_use = 0x91;
inline constexpr std::uint8_t packet_identifier_not_found = 0x92;
inline constexpr std::uint8_t receive_maximum_exceeded = 0x93;
inline constexpr std::uint8_t topic_alias_invalid = 0x94;
inline constexpr std::uint8_t packet_too_large = 0x95;
inline constexpr std::uint8_t message_rate_too_high = 0x96;
inline constexpr std::uint8_t quota_exceeded = 0x97;
inline constexpr std::uint8_t administrative_action = 0x98;
inline constexpr std::uint8_t payload_format_invalid = 0x99;
inline constexpr std::uint8_t retain_not_supported = 0x9A;
inline constexpr std::uint8_t qos_not_supported = 0x9B;
inline constexpr std::uint8_t use_another_server = 0x9C;
inline constexpr std::uint8_t server_moved = 0x9D;
inline constexpr std::uint8_t shared_subscriptions_not_supported = 0x9E;
inline constexpr std::uint8_t connection_rate_exceeded = 0x9F;
inline constexpr std::uint8_t maximum_connect_time = 0xA0;
inline constexpr std::uint8_t subscription_identifiers_not_supported = 0xA1;
inline constexpr std::uint8_t wildcard_subscriptions_not_supported = 0xA2;
}  // namespace reason

struct UserProperty {
    std::string name{};
    std::string value{};
    friend bool operator==(const UserProperty&, const UserProperty&) = default;
};

/// MQTT 5.0 properties. Each packet (and the Will) may carry only the subset
/// the specification assigns to it; 3.1.1 packets carry none. User properties
/// keep their order and may repeat; a PUBLISH from the server may carry several
/// subscription identifiers, every other property appears at most once.
struct Properties {
    std::optional<std::uint8_t> payload_format_indicator{};            // 0x01: 0 or 1
    std::optional<std::uint32_t> message_expiry_interval{};            // 0x02
    std::optional<std::string> content_type{};                         // 0x03
    std::optional<std::string> response_topic{};                       // 0x08: topic name
    std::optional<Bytes> correlation_data{};                           // 0x09
    std::vector<std::uint32_t> subscription_identifiers{};             // 0x0B: 1..268435455
    std::optional<std::uint32_t> session_expiry_interval{};            // 0x11
    std::optional<std::string> assigned_client_identifier{};           // 0x12
    std::optional<std::uint16_t> server_keep_alive{};                  // 0x13
    std::optional<std::string> authentication_method{};                // 0x15
    std::optional<Bytes> authentication_data{};                        // 0x16
    std::optional<std::uint8_t> request_problem_information{};         // 0x17: 0 or 1
    std::optional<std::uint32_t> will_delay_interval{};                // 0x18
    std::optional<std::uint8_t> request_response_information{};        // 0x19: 0 or 1
    std::optional<std::string> response_information{};                 // 0x1A
    std::optional<std::string> server_reference{};                     // 0x1C
    std::optional<std::string> reason_string{};                        // 0x1F
    std::optional<std::uint16_t> receive_maximum{};                    // 0x21: nonzero
    std::optional<std::uint16_t> topic_alias_maximum{};                // 0x22
    std::optional<std::uint16_t> topic_alias{};                        // 0x23: nonzero
    std::optional<std::uint8_t> maximum_qos{};                         // 0x24: 0 or 1
    std::optional<std::uint8_t> retain_available{};                    // 0x25: 0 or 1
    std::vector<UserProperty> user_properties{};                       // 0x26
    std::optional<std::uint32_t> maximum_packet_size{};                // 0x27: nonzero
    std::optional<std::uint8_t> wildcard_subscription_available{};     // 0x28: 0 or 1
    std::optional<std::uint8_t> subscription_identifiers_available{};  // 0x29: 0 or 1
    std::optional<std::uint8_t> shared_subscription_available{};       // 0x2A: 0 or 1
    friend bool operator==(const Properties&, const Properties&) = default;
};

struct Will {
    std::string topic{};
    Bytes payload{};
    QoS qos = QoS::at_most_once;
    bool retain = false;
    Properties properties{};
    friend bool operator==(const Will&, const Will&) = default;
};

struct Connect {
    /// The protocol level the whole connection speaks.
    Version version = Version::v5;
    /// Empty asks the server to assign one (5.0) and requires clean_start in 3.1.1.
    std::string client_id{};
    bool clean_start = true;
    /// Seconds; 0 disables keep-alive.
    std::uint16_t keep_alive = 60;
    std::optional<std::string> username{};
    std::optional<Bytes> password{};
    std::optional<Will> will{};
    Properties properties{};
    friend bool operator==(const Connect&, const Connect&) = default;
};

struct Connack {
    bool session_present = false;
    std::uint8_t reason = reason::success;
    Properties properties{};
    friend bool operator==(const Connack&, const Connack&) = default;
};

struct Publish {
    /// Empty only in 5.0 with a topic alias.
    std::string topic{};
    Bytes payload{};
    QoS qos = QoS::at_most_once;
    bool retain = false;
    bool dup = false;
    /// Nonzero exactly when qos > 0.
    std::uint16_t packet_id = 0;
    Properties properties{};
    friend bool operator==(const Publish&, const Publish&) = default;
};

/// PUBACK, PUBREC, PUBREL or PUBCOMP.
struct Ack {
    PacketType type = PacketType::puback;
    std::uint16_t packet_id = 0;
    std::uint8_t reason = reason::success;
    Properties properties{};
    friend bool operator==(const Ack&, const Ack&) = default;
};

struct Subscription {
    std::string filter{};
    QoS qos = QoS::at_most_once;
    /// 5.0 subscription options; must stay default in 3.1.1.
    bool no_local = false;
    bool retain_as_published = false;
    /// 0 send retained on subscribe, 1 only if new, 2 never.
    std::uint8_t retain_handling = 0;
    friend bool operator==(const Subscription&, const Subscription&) = default;
};

struct Subscribe {
    std::uint16_t packet_id = 0;
    std::vector<Subscription> subscriptions{};
    Properties properties{};
    friend bool operator==(const Subscribe&, const Subscribe&) = default;
};

struct Suback {
    std::uint16_t packet_id = 0;
    std::vector<std::uint8_t> reasons{};
    Properties properties{};
    friend bool operator==(const Suback&, const Suback&) = default;
};

struct Unsubscribe {
    std::uint16_t packet_id = 0;
    std::vector<std::string> filters{};
    Properties properties{};
    friend bool operator==(const Unsubscribe&, const Unsubscribe&) = default;
};

/// In 3.1.1 an UNSUBACK carries neither reasons nor properties.
struct Unsuback {
    std::uint16_t packet_id = 0;
    std::vector<std::uint8_t> reasons{};
    Properties properties{};
    friend bool operator==(const Unsuback&, const Unsuback&) = default;
};

struct Pingreq {
    friend bool operator==(const Pingreq&, const Pingreq&) = default;
};
struct Pingresp {
    friend bool operator==(const Pingresp&, const Pingresp&) = default;
};

/// In 3.1.1 only the client sends DISCONNECT, and it has no body.
struct Disconnect {
    std::uint8_t reason = reason::success;
    Properties properties{};
    friend bool operator==(const Disconnect&, const Disconnect&) = default;
};

/// 5.0 enhanced authentication.
struct Auth {
    std::uint8_t reason = reason::success;
    Properties properties{};
    friend bool operator==(const Auth&, const Auth&) = default;
};

using Packet = std::variant<Connect, Connack, Publish, Ack, Subscribe, Suback, Unsubscribe, Unsuback,
                            Pingreq, Pingresp, Disconnect, Auth>;

[[nodiscard]] PacketType type_of(const Packet& packet) noexcept;

/// Largest value of a Variable Byte Integer, hence of a remaining length.
inline constexpr std::uint32_t max_remaining_length = 268'435'455;
/// Largest possible packet: fixed header byte, four length bytes, body.
inline constexpr std::size_t max_packet_size = max_remaining_length + 5;

/// Serialize for a connection speaking `version`. A Connect must name the same
/// version. Fails with `invalid_argument` on anything the decoder would reject.
[[nodiscard]] Result<Bytes> encode(const Packet& packet, Version version);

struct Decoded {
    /// Empty when `input` does not yet hold a complete packet.
    std::optional<Packet> packet{};
    /// Bytes to drop from the front of the input; 0 when packet is empty.
    std::size_t consumed = 0;
};

/// Decode the packet at the front of `input`, sent to `receiver` by its peer.
/// CONNECT is parsed at its own protocol level (read the version from it);
/// every other packet at `version`. `maximum` bounds the whole packet and is
/// enforced from the fixed header alone.
[[nodiscard]] Result<Decoded> decode(std::span<const std::byte> input, Version version, Role receiver,
                                     std::size_t maximum = max_packet_size);

/// Well-formed MQTT UTF-8: RFC 3629, no U+0000, at most 65535 bytes.
[[nodiscard]] bool valid_string(std::string_view text) noexcept;
/// Nonempty, no wildcard characters.
[[nodiscard]] bool valid_topic_name(std::string_view topic) noexcept;
/// Nonempty; `#` only as the whole last level, `+` only as a whole level. In
/// 5.0, `$share/<name>/<filter>` requires a nonempty share name without
/// wildcards and a valid filter after it.
[[nodiscard]] bool valid_topic_filter(std::string_view filter, Version version = Version::v5) noexcept;
/// Whether `name` matches `filter` (both assumed valid). A leading wildcard
/// never matches a topic beginning with `$`; a shared subscription matches
/// through its inner filter.
[[nodiscard]] bool topic_matches(std::string_view filter, std::string_view name) noexcept;

}  // namespace Mira::mqtt

namespace std {
template<>
struct is_error_code_enum<Mira::mqtt::MqttError> : true_type {};
}  // namespace std
