#pragma once

// Mira/transport/endpoint.hpp — an IP address and port.
//
// `Endpoint` owns the encoded `sockaddr` bytes and hands them to the event
// loop as an opaque blob. That split is deliberate: `core` performs syscalls
// but knows nothing about address families, and this layer knows about address
// families but performs no I/O.
//
// Numeric parsing only — no DNS. Name resolution blocks, needs its own
// cancellation story, and belongs in a resolver built on the loop rather than
// hidden inside an address type where every construction might take a second.

#include "mira/core/error.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace Mira::transport {

/// IP version of an endpoint.
enum class Family {
    ipv4,
    ipv6,
};

/// An IP address and port, stored as the platform's encoded socket address.
class Endpoint {
public:
    /// Parse a numeric address. Rejects host names — see the header comment.
    ///
    /// Accepts "127.0.0.1", "::1", and numeric IPv6 scopes such as "fe80::1%3".
    /// POSIX also accepts existing interface names ("fe80::1%eth0"). Windows
    /// requires numeric scopes. Empty/unknown scopes and embedded NUL are rejected.
    [[nodiscard]] static Result<Endpoint> parse(std::string_view address, std::uint16_t port);

    /// Loopback: 127.0.0.1 or ::1.
    [[nodiscard]] static Endpoint loopback(std::uint16_t port, Family family = Family::ipv4);

    /// Wildcard: 0.0.0.0 or ::.
    [[nodiscard]] static Endpoint any(std::uint16_t port, Family family = Family::ipv4);

    [[nodiscard]] Family family() const noexcept { return family_; }
    [[nodiscard]] std::uint16_t port() const noexcept;

    /// Numeric form of the address, without the port.
    [[nodiscard]] std::string address() const;

    /// "127.0.0.1:8080" or "[::1]:8080" — the bracketed form for IPv6, so the
    /// result can be fed back to a parser without ambiguity.
    [[nodiscard]] std::string to_string() const;

    /// The encoded `sockaddr`, for handing to the event loop.
    [[nodiscard]] std::span<const std::byte> address_bytes() const noexcept {
        return std::span<const std::byte>{storage_.data(), length_};
    }

    /// The platform's address-family constant (`AF_INET` / `AF_INET6`).
    ///
    /// Needed because IOCP has to pre-create a socket of the right family
    /// before it can submit an accept.
    [[nodiscard]] int native_family() const noexcept;

    /// Build an endpoint from bytes the OS produced (`getsockname`, `accept`).
    [[nodiscard]] static Result<Endpoint> from_bytes(std::span<const std::byte> address);

    /// Same family, address, port and IPv6 scope. OS padding, BSD length
    /// fields and IPv6 flow labels do not participate in endpoint identity.
    /// An unset endpoint compares equal only to another unset endpoint.
    friend bool operator==(const Endpoint& left, const Endpoint& right) noexcept;

    /// An unset endpoint: family ipv4, zero address, zero port.
    ///
    /// Public so that `Listener` can hold one as a member before it binds.
    /// `address_bytes()` is empty until a factory fills it in, which the
    /// loop rejects rather than passing a zero-length sockaddr to a syscall.
    Endpoint() = default;

private:
    /// Large enough for `sockaddr_in6`; sized rather than including
    /// <netinet/in.h> in a public header.
    std::array<std::byte, 128> storage_{};
    std::size_t length_{0};
    Family family_{Family::ipv4};
};

}  // namespace Mira::transport
