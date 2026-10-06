#pragma once

// Mira/socks/socks5.hpp — SOCKS5 (RFC 1928) with username/password
// authentication (RFC 1929), over any bounded stream.
//
// Both directions are here: `connect` negotiates a CONNECT tunnel as a client,
// `accept` + `reply` implement the proxy side. Every message is read with its
// exact length, never more, so once a handshake returns the stream is
// positioned at the first tunnelled byte — a TLS ClientHello or an HTTP
// request can follow on the same stream without a pushback buffer.
//
// Client commands include CONNECT, two-reply BIND and UDP ASSOCIATE.
// Proxy authentication/requests and replies are transport-independent; relay
// policy belongs to the caller. UDP fragmentation is explicitly unsupported.
// No GSSAPI or SOCKS4.
// Username/password travel in clear text (RFC 1929); run the proxy hop over a
// trusted network or inside TLS.

#include "mira/core/error.hpp"
#include "mira/core/operation.hpp"
#include "mira/core/stream.hpp"
#include "mira/core/task.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace Mira::socks {

enum class SocksError {
    /// Malformed or unexpected bytes from the peer.
    protocol_error = 1,
    /// The server accepted none of the offered methods (0xFF).
    no_acceptable_method,
    /// Username/password sub-negotiation failed.
    auth_failed,
    /// REP 0x01..0x08 from the proxy.
    general_failure,
    not_allowed,
    network_unreachable,
    host_unreachable,
    connection_refused,
    ttl_expired,
    command_not_supported,
    address_type_not_supported,
    /// A REP value RFC 1928 does not assign.
    unassigned_reply,
};

[[nodiscard]] const std::error_category& socks_category() noexcept;
[[nodiscard]] std::error_code make_error_code(SocksError error) noexcept;

enum class ReplyCode : std::uint8_t {
    succeeded = 0x00,
    general_failure = 0x01,
    not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

/// Error a client reports for a non-success reply code.
[[nodiscard]] std::error_code reply_error(std::uint8_t code) noexcept;

enum class Command : std::uint8_t { connect = 0x01, bind = 0x02, udp_associate = 0x03 };

/// SOCKS address: IPv4, IPv6 or a domain name the proxy resolves, plus port.
class Address {
public:
    enum class Kind : std::uint8_t { ipv4 = 0x01, domain = 0x03, ipv6 = 0x04 };

    Address() = default;
    [[nodiscard]] static Address ipv4(std::array<std::uint8_t, 4> octets, std::uint16_t port);
    [[nodiscard]] static Address ipv6(std::array<std::uint8_t, 16> octets, std::uint16_t port);
    /// 1..255 bytes, no NUL. The name is sent as-is; the proxy resolves it.
    [[nodiscard]] static Result<Address> domain(std::string_view name, std::uint16_t port);
    /// IPv4 dotted quad, IPv6 text (optionally bracketed, `::` and IPv4 tail
    /// allowed; no zone IDs), otherwise a domain name.
    [[nodiscard]] static Result<Address> parse(std::string_view host, std::uint16_t port);

    [[nodiscard]] Kind kind() const noexcept { return kind_; }
    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
    /// 4 or 16 address bytes; empty for domains.
    [[nodiscard]] std::span<const std::uint8_t> octets() const noexcept;
    [[nodiscard]] std::string_view name() const noexcept { return name_; }
    /// Host without port: dotted quad, RFC 5952 IPv6, or the domain.
    [[nodiscard]] std::string host() const;
    /// Host and port, with IPv6 bracketed.
    [[nodiscard]] std::string to_string() const;
    /// Wire form: ATYP, address, port.
    [[nodiscard]] std::string encode() const;

    friend bool operator==(const Address&, const Address&) = default;

private:
    Kind kind_{Kind::ipv4};
    std::array<std::uint8_t, 16> bytes_{};
    std::string name_;
    std::uint16_t port_{0};
};

struct Credentials {
    std::string username;
    std::string password;
};

struct ClientOptions {
    /// Offer "no authentication".
    bool allow_no_auth = true;
    /// Offer username/password (RFC 1929); each field 1..255 bytes.
    std::optional<Credentials> credentials{};
};

struct Reply {
    ReplyCode code{ReplyCode::succeeded};
    /// BND.ADDR/BND.PORT reported by the proxy.
    Address bound{};
};

struct ServerOptions {
    /// Accept clients that offer "no authentication". When a verifier is also
    /// set and the client offers username/password, credentials are required.
    bool allow_no_auth = false;
    /// Username/password verifier; empty disables the method.
    std::function<bool(std::string_view username, std::string_view password)> verify{};
};

struct Request {
    Command command{Command::connect};
    Address target{};
    /// Username that authenticated, if the password method was used.
    std::optional<std::string> username{};
};

namespace detail {

inline constexpr std::uint8_t version = 0x05;
inline constexpr std::uint8_t method_none = 0x00;
inline constexpr std::uint8_t method_password = 0x02;
inline constexpr std::uint8_t method_refused = 0xFF;

inline std::error_code expired(const OperationOptions& io) {
    if (io.stop.stop_requested()) return Mira::make_error_code(Errc::cancelled);
    if (io.deadline && Clock::now() >= *io.deadline) return Mira::make_error_code(Errc::timed_out);
    return {};
}

inline std::span<const std::byte> view(std::string_view text) {
    return std::as_bytes(std::span{text.data(), text.size()});
}

/// Read exactly `into.size()` bytes — never more, so tunnelled data stays put.
template<BoundedStream Stream>
Task<Result<void>> read_exact(Stream& stream, std::span<std::byte> into, OperationOptions io) {
    while (!into.empty()) {
        if (const auto error = expired(io)) co_return fail(error);
        const auto n = co_await stream.read_some(into, io);
        if (!n) {
            if (n.error() == Errc::eof) co_return fail(make_error_code(SocksError::protocol_error));
            co_return fail(n.error());
        }
        if (*n == 0) co_return fail(make_error_code(SocksError::protocol_error));
        if (*n > into.size()) co_return fail(Errc::invalid_argument);
        into = into.subspan(*n);
    }
    co_return Result<void>{};
}

template<BoundedStream Stream>
Task<Result<void>> write_text(Stream& stream, std::string_view bytes, OperationOptions io) {
    if (const auto error = expired(io)) co_return fail(error);
    co_return co_await write_all(stream, view(bytes), io);
}

/// Read ATYP + address + port following an already-consumed header.
template<BoundedStream Stream>
Task<Result<Address>> read_address(Stream& stream, std::uint8_t atyp, OperationOptions io) {
    std::array<std::byte, 258> buffer{};
    std::size_t length = 0;
    switch (atyp) {
    case 0x01: length = 4; break;
    case 0x04: length = 16; break;
    case 0x03: {
        auto got = co_await read_exact(stream, std::span{buffer}.first(1), io);
        if (!got) co_return fail(got.error());
        length = std::to_integer<std::size_t>(buffer[0]);
        if (length == 0) co_return fail(make_error_code(SocksError::protocol_error));
        break;
    }
    default: co_return fail(make_error_code(SocksError::address_type_not_supported));
    }
    auto got = co_await read_exact(stream, std::span{buffer}.first(length + 2), io);
    if (!got) co_return fail(got.error());
    const auto port = static_cast<std::uint16_t>(
        (std::to_integer<unsigned>(buffer[length]) << 8) | std::to_integer<unsigned>(buffer[length + 1]));
    if (atyp == 0x01) {
        std::array<std::uint8_t, 4> octets{};
        for (std::size_t i = 0; i < 4; ++i) octets[i] = std::to_integer<std::uint8_t>(buffer[i]);
        co_return Address::ipv4(octets, port);
    }
    if (atyp == 0x04) {
        std::array<std::uint8_t, 16> octets{};
        for (std::size_t i = 0; i < 16; ++i) octets[i] = std::to_integer<std::uint8_t>(buffer[i]);
        co_return Address::ipv6(octets, port);
    }
    const std::string_view name{reinterpret_cast<const char*>(buffer.data()), length};
    auto domain = Address::domain(name, port);
    if (!domain) co_return fail(make_error_code(SocksError::protocol_error));
    co_return *domain;
}

bool valid_credential(std::string_view field) noexcept;

}  // namespace detail

/// Read one command response, including BIND's second peer-accepted response.
/// Reads exactly its frame; tunnel bytes remain untouched.
template<BoundedStream Stream>
[[nodiscard]] Task<Result<Reply>> read_reply(Stream& stream, OperationOptions io = {}) {
    std::array<std::byte, 4> head{};
    auto got = co_await detail::read_exact(stream, head, io);
    if (!got) co_return fail(got.error());
    if (head[0] != std::byte{5} || head[2] != std::byte{0})
        co_return fail(make_error_code(SocksError::protocol_error));
    const auto code = std::to_integer<std::uint8_t>(head[1]);
    auto bound = co_await detail::read_address(stream, std::to_integer<std::uint8_t>(head[3]), io);
    if (!bound) co_return fail(bound.error());
    if (code != 0) co_return fail(reply_error(code));
    co_return Reply{ReplyCode::succeeded, std::move(*bound)};
}

/// Negotiate one command. BIND returns its listening response; call read_reply
/// again for the accepted peer. UDP ASSOCIATE's TCP connection must remain alive
/// until all relay operations finish. The caller enforces relay lifetime/policy.
template<BoundedStream Stream>
[[nodiscard]] Task<Result<Reply>> negotiate(Stream& stream, Command command, const Address& target,
                                            const ClientOptions& options, OperationOptions io = {}) {
    if (command != Command::connect && command != Command::bind && command != Command::udp_associate)
        co_return fail(Errc::invalid_argument);
    using detail::version;
    const bool password = options.credentials.has_value();
    if (!options.allow_no_auth && !password) co_return fail(Errc::invalid_argument);
    if (password && (!detail::valid_credential(options.credentials->username) ||
                     !detail::valid_credential(options.credentials->password)))
        co_return fail(Errc::invalid_argument);
    if (target.kind() == Address::Kind::domain && target.name().empty())
        co_return fail(Errc::invalid_argument);

    std::string greeting;
    greeting.push_back(static_cast<char>(version));
    greeting.push_back(static_cast<char>((options.allow_no_auth ? 1 : 0) + (password ? 1 : 0)));
    if (options.allow_no_auth) greeting.push_back(static_cast<char>(detail::method_none));
    if (password) greeting.push_back(static_cast<char>(detail::method_password));
    auto sent = co_await detail::write_text(stream, greeting, io);
    if (!sent) co_return fail(sent.error());

    std::array<std::byte, 4> head{};
    auto got = co_await detail::read_exact(stream, std::span{head}.first(2), io);
    if (!got) co_return fail(got.error());
    if (std::to_integer<std::uint8_t>(head[0]) != version)
        co_return fail(make_error_code(SocksError::protocol_error));
    const auto method = std::to_integer<std::uint8_t>(head[1]);
    if (method == detail::method_refused) co_return fail(make_error_code(SocksError::no_acceptable_method));
    if (!((method == detail::method_none && options.allow_no_auth) ||
          (method == detail::method_password && password)))
        co_return fail(make_error_code(SocksError::protocol_error));

    if (method == detail::method_password) {
        const auto& [username, secret] = *options.credentials;
        std::string auth;
        auth.push_back(0x01);
        auth.push_back(static_cast<char>(username.size()));
        auth += username;
        auth.push_back(static_cast<char>(secret.size()));
        auth += secret;
        sent = co_await detail::write_text(stream, auth, io);
        if (!sent) co_return fail(sent.error());
        got = co_await detail::read_exact(stream, std::span{head}.first(2), io);
        if (!got) co_return fail(got.error());
        if (std::to_integer<std::uint8_t>(head[0]) != 0x01)
            co_return fail(make_error_code(SocksError::protocol_error));
        if (std::to_integer<std::uint8_t>(head[1]) != 0x00)
            co_return fail(make_error_code(SocksError::auth_failed));
    }

    std::string request;
    request.push_back(static_cast<char>(version));
    request.push_back(static_cast<char>(command));
    request.push_back(0x00);
    request += target.encode();
    sent = co_await detail::write_text(stream, request, io);
    if (!sent) co_return fail(sent.error());

    got = co_await detail::read_exact(stream, head, io);
    if (!got) co_return fail(got.error());
    if (std::to_integer<std::uint8_t>(head[0]) != version ||
        std::to_integer<std::uint8_t>(head[2]) != 0x00)
        co_return fail(make_error_code(SocksError::protocol_error));
    const auto code = std::to_integer<std::uint8_t>(head[1]);
    // The address is consumed even on failure, keeping the stream framed.
    auto bound = co_await detail::read_address(stream, std::to_integer<std::uint8_t>(head[3]), io);
    if (!bound) {
        if (bound.error() == make_error_code(SocksError::address_type_not_supported))
            co_return fail(make_error_code(SocksError::protocol_error));
        co_return fail(bound.error());
    }
    if (code != 0x00) co_return fail(reply_error(code));
    co_return Reply{ReplyCode::succeeded, std::move(*bound)};
}

/// CONNECT leaves the stream positioned at the first tunnel byte.
template<BoundedStream Stream>
[[nodiscard]] Task<Result<Reply>> connect(Stream& stream, const Address& target,
                                          const ClientOptions& options, OperationOptions io = {}) {
    co_return co_await negotiate(stream, Command::connect, target, options, io);
}
template<BoundedStream Stream>
[[nodiscard]] Task<Result<Reply>> bind(Stream& stream, const Address& expected_peer,
                                       const ClientOptions& options, OperationOptions io = {}) {
    co_return co_await negotiate(stream, Command::bind, expected_peer, options, io);
}
template<BoundedStream Stream>
[[nodiscard]] Task<Result<Reply>> udp_associate(Stream& control, const Address& local,
                                                const ClientOptions& options, OperationOptions io = {}) {
    co_return co_await negotiate(control, Command::udp_associate, local, options, io);
}

struct UdpPacket {
    Address target;
    std::span<const std::byte> payload;
};
/// RFC 1928 UDP encapsulation. The decoded payload borrows the input. All
/// nonzero FRAG values are refused (no fragment buffering or reassembly).
[[nodiscard]] Result<std::vector<std::byte>> encode_udp(const Address& target,
    std::span<const std::byte> payload, std::size_t max_size = 65507);
[[nodiscard]] Result<UdpPacket> decode_udp(std::span<const std::byte> packet,
    std::size_t max_size = 65507);

/// Proxy side: negotiate a method, authenticate, and read the request. The
/// caller performs the command and answers with `reply`. A client offering no
/// acceptable method receives 0xFF and `no_acceptable_method`; a failed
/// password check receives status 0x01 and `auth_failed`. An unknown address
/// type is answered with REP 0x08 before failing.
template<BoundedStream Stream>
[[nodiscard]] Task<Result<Request>> accept(Stream& stream, const ServerOptions& options,
                                           OperationOptions io = {}) {
    using detail::version;
    const bool password = static_cast<bool>(options.verify);
    if (!password && !options.allow_no_auth) co_return fail(Errc::invalid_argument);
    std::array<std::byte, 256> buffer{};
    auto got = co_await detail::read_exact(stream, std::span{buffer}.first(2), io);
    if (!got) co_return fail(got.error());
    if (std::to_integer<std::uint8_t>(buffer[0]) != version)
        co_return fail(make_error_code(SocksError::protocol_error));
    const auto count = std::to_integer<std::size_t>(buffer[1]);
    if (count == 0) co_return fail(make_error_code(SocksError::protocol_error));
    got = co_await detail::read_exact(stream, std::span{buffer}.first(count), io);
    if (!got) co_return fail(got.error());
    bool offers_none = false, offers_password = false;
    for (std::size_t i = 0; i < count; ++i) {
        const auto method = std::to_integer<std::uint8_t>(buffer[i]);
        offers_none = offers_none || method == detail::method_none;
        offers_password = offers_password || method == detail::method_password;
    }
    std::uint8_t chosen = detail::method_refused;
    if (password && offers_password) chosen = detail::method_password;
    else if (options.allow_no_auth && offers_none) chosen = detail::method_none;
    std::string selection{static_cast<char>(version), static_cast<char>(chosen)};
    auto sent = co_await detail::write_text(stream, selection, io);
    if (!sent) co_return fail(sent.error());
    if (chosen == detail::method_refused) co_return fail(make_error_code(SocksError::no_acceptable_method));

    Request request;
    if (chosen == detail::method_password) {
        got = co_await detail::read_exact(stream, std::span{buffer}.first(2), io);
        if (!got) co_return fail(got.error());
        if (std::to_integer<std::uint8_t>(buffer[0]) != 0x01)
            co_return fail(make_error_code(SocksError::protocol_error));
        const auto user_length = std::to_integer<std::size_t>(buffer[1]);
        if (user_length == 0) co_return fail(make_error_code(SocksError::protocol_error));
        std::string username(user_length, '\0');
        got = co_await detail::read_exact(stream, std::as_writable_bytes(std::span{username}), io);
        if (!got) co_return fail(got.error());
        got = co_await detail::read_exact(stream, std::span{buffer}.first(1), io);
        if (!got) co_return fail(got.error());
        const auto secret_length = std::to_integer<std::size_t>(buffer[0]);
        if (secret_length == 0) co_return fail(make_error_code(SocksError::protocol_error));
        std::string secret(secret_length, '\0');
        got = co_await detail::read_exact(stream, std::as_writable_bytes(std::span{secret}), io);
        if (!got) co_return fail(got.error());
        const bool ok = options.verify(username, secret);
        std::fill(secret.begin(), secret.end(), '\0');
        const std::string status{'\x01', ok ? '\x00' : '\x01'};
        sent = co_await detail::write_text(stream, status, io);
        if (!sent) co_return fail(sent.error());
        if (!ok) co_return fail(make_error_code(SocksError::auth_failed));
        request.username = std::move(username);
    }

    got = co_await detail::read_exact(stream, std::span{buffer}.first(4), io);
    if (!got) co_return fail(got.error());
    const auto command = std::to_integer<std::uint8_t>(buffer[1]);
    if (std::to_integer<std::uint8_t>(buffer[0]) != version ||
        std::to_integer<std::uint8_t>(buffer[2]) != 0x00 || command < 0x01 || command > 0x03)
        co_return fail(make_error_code(SocksError::protocol_error));
    auto target = co_await detail::read_address(stream, std::to_integer<std::uint8_t>(buffer[3]), io);
    if (!target) {
        if (target.error() == make_error_code(SocksError::address_type_not_supported)) {
            // RFC 1928 §6: answer 0x08, then close — the address length is unknown.
            const std::string refusal{'\x05', '\x08', '\x00', '\x01', '\0', '\0', '\0', '\0', '\0', '\0'};
            static_cast<void>(co_await detail::write_text(stream, refusal, io));
        }
        co_return fail(target.error());
    }
    request.command = static_cast<Command>(command);
    request.target = std::move(*target);
    co_return request;
}

/// Answer an accepted request. `bound` is BND.ADDR/BND.PORT (use 0.0.0.0:0
/// when unknown). Only `succeeded` leaves a usable tunnel.
template<BoundedStream Stream>
[[nodiscard]] Task<Result<void>> reply(Stream& stream, ReplyCode code, const Address& bound,
                                       OperationOptions io = {}) {
    std::string message;
    message.push_back(static_cast<char>(detail::version));
    message.push_back(static_cast<char>(code));
    message.push_back(0x00);
    message += bound.encode();
    co_return co_await detail::write_text(stream, message, io);
}

}  // namespace Mira::socks

namespace std {
template<>
struct is_error_code_enum<Mira::socks::SocksError> : true_type {};
}  // namespace std
