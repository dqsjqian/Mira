#include "mira/transport/endpoint.hpp"

#include "socket_compat.hpp"

#include <charconv>
#include <cstdio>

namespace Mira::transport {
namespace {

[[nodiscard]] int to_native_family(Family family) noexcept {
    return family == Family::ipv6 ? AF_INET6 : AF_INET;
}

}  // namespace

Result<Endpoint> Endpoint::parse(std::string_view address, std::uint16_t port) {
    if (address.empty() || address.find('\0') != std::string_view::npos) {
        return fail(Errc::invalid_argument);
    }

    // string_view is not guaranteed null-terminated; inet_pton needs that.
    char text[INET6_ADDRSTRLEN + 32]{};
    if (address.size() >= sizeof(text)) {
        return fail(Errc::invalid_argument);
    }
    std::memcpy(text, address.data(), address.size());

    Endpoint endpoint;

    // An IPv6 literal is anything containing a colon; trying v4 first would
    // misparse "::1" as a failure rather than dispatching correctly.
    if (address.find(':') != std::string_view::npos) {
        sockaddr_in6 v6{};
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(port);

        // Strip a scope id ("fe80::1%eth0") before inet_pton, which rejects it.
        char* const percent = std::strchr(text, '%');
        if (percent != nullptr) {
            *percent = '\0';
            const std::string_view scope(percent + 1);
            if (scope.empty()) return fail(Errc::invalid_argument);
            std::uint32_t index{};
            const auto parsed = std::from_chars(scope.data(), scope.data() + scope.size(), index);
            if (parsed.ec == std::errc{} && parsed.ptr == scope.data() + scope.size()) {
                v6.sin6_scope_id = index;
            } else {
                // A digits-only overflow is not an interface name.
                if (scope.find_first_not_of("0123456789") == std::string_view::npos)
                    return fail(Errc::invalid_argument);
#if MIRA_PLATFORM_WINDOWS
                // Numeric scopes are portable. Interface names are POSIX-only
                // until the Windows adapter-name mapping is implemented.
                return fail(Errc::invalid_argument);
#else
                v6.sin6_scope_id = ::if_nametoindex(percent + 1);
                if (v6.sin6_scope_id == 0) return fail(Errc::invalid_argument);
#endif
            }
        }

        if (::inet_pton(AF_INET6, text, &v6.sin6_addr) != 1) {
            return fail(Errc::invalid_argument);
        }
        std::memcpy(endpoint.storage_.data(), &v6, sizeof(v6));
        endpoint.length_ = sizeof(v6);
        endpoint.family_ = Family::ipv6;
        return endpoint;
    }

    sockaddr_in v4{};
    v4.sin_family = AF_INET;
    v4.sin_port = htons(port);
    if (::inet_pton(AF_INET, text, &v4.sin_addr) != 1) {
        return fail(Errc::invalid_argument);
    }
    std::memcpy(endpoint.storage_.data(), &v4, sizeof(v4));
    endpoint.length_ = sizeof(v4);
    endpoint.family_ = Family::ipv4;
    return endpoint;
}

Endpoint Endpoint::loopback(std::uint16_t port, Family family) {
    Endpoint endpoint;
    if (family == Family::ipv6) {
        sockaddr_in6 v6{};
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(port);
        v6.sin6_addr = in6addr_loopback;
        std::memcpy(endpoint.storage_.data(), &v6, sizeof(v6));
        endpoint.length_ = sizeof(v6);
        endpoint.family_ = Family::ipv6;
        return endpoint;
    }

    sockaddr_in v4{};
    v4.sin_family = AF_INET;
    v4.sin_port = htons(port);
    v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    std::memcpy(endpoint.storage_.data(), &v4, sizeof(v4));
    endpoint.length_ = sizeof(v4);
    endpoint.family_ = Family::ipv4;
    return endpoint;
}

Endpoint Endpoint::any(std::uint16_t port, Family family) {
    Endpoint endpoint;
    if (family == Family::ipv6) {
        sockaddr_in6 v6{};
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(port);
        v6.sin6_addr = in6addr_any;
        std::memcpy(endpoint.storage_.data(), &v6, sizeof(v6));
        endpoint.length_ = sizeof(v6);
        endpoint.family_ = Family::ipv6;
        return endpoint;
    }

    sockaddr_in v4{};
    v4.sin_family = AF_INET;
    v4.sin_port = htons(port);
    v4.sin_addr.s_addr = htonl(INADDR_ANY);
    std::memcpy(endpoint.storage_.data(), &v4, sizeof(v4));
    endpoint.length_ = sizeof(v4);
    endpoint.family_ = Family::ipv4;
    return endpoint;
}

Result<Endpoint> Endpoint::from_bytes(std::span<const std::byte> address) {
    if (address.size() < sizeof(sockaddr) || address.size() > 128) {
        return fail(Errc::invalid_argument);
    }

    sockaddr header{};
    std::memcpy(&header, address.data(), sizeof(header));

    Endpoint endpoint;
    if (header.sa_family == AF_INET6) {
        if (address.size() < sizeof(sockaddr_in6)) {
            return fail(Errc::invalid_argument);
        }
        endpoint.family_ = Family::ipv6;
        endpoint.length_ = sizeof(sockaddr_in6);
    } else if (header.sa_family == AF_INET) {
        if (address.size() < sizeof(sockaddr_in)) {
            return fail(Errc::invalid_argument);
        }
        endpoint.family_ = Family::ipv4;
        endpoint.length_ = sizeof(sockaddr_in);
    } else {
        return fail(Errc::not_supported);
    }

    std::memcpy(endpoint.storage_.data(), address.data(), endpoint.length_);
    return endpoint;
}

bool operator==(const Endpoint& left, const Endpoint& right) noexcept {
    if (left.length_ == 0 || right.length_ == 0) {
        return left.length_ == right.length_;
    }
    if (left.family_ != right.family_) return false;
    if (left.family_ == Family::ipv6) {
        sockaddr_in6 a{}, b{};
        std::memcpy(&a, left.storage_.data(), sizeof(a));
        std::memcpy(&b, right.storage_.data(), sizeof(b));
        return a.sin6_port == b.sin6_port && a.sin6_scope_id == b.sin6_scope_id &&
               std::memcmp(&a.sin6_addr, &b.sin6_addr, sizeof(a.sin6_addr)) == 0;
    }
    sockaddr_in a{}, b{};
    std::memcpy(&a, left.storage_.data(), sizeof(a));
    std::memcpy(&b, right.storage_.data(), sizeof(b));
    return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
}

std::uint16_t Endpoint::port() const noexcept {
    if (family_ == Family::ipv6) {
        sockaddr_in6 v6{};
        std::memcpy(&v6, storage_.data(), sizeof(v6));
        return ntohs(v6.sin6_port);
    }
    sockaddr_in v4{};
    std::memcpy(&v4, storage_.data(), sizeof(v4));
    return ntohs(v4.sin_port);
}

int Endpoint::native_family() const noexcept {
    return to_native_family(family_);
}

std::string Endpoint::address() const {
    char text[INET6_ADDRSTRLEN]{};
    if (family_ == Family::ipv6) {
        sockaddr_in6 v6{};
        std::memcpy(&v6, storage_.data(), sizeof(v6));
        if (::inet_ntop(AF_INET6, &v6.sin6_addr, text, sizeof(text)) == nullptr) {
            return {};
        }
        if (v6.sin6_scope_id != 0)
            return std::string{text} + "%" + std::to_string(v6.sin6_scope_id);
    } else {
        sockaddr_in v4{};
        std::memcpy(&v4, storage_.data(), sizeof(v4));
        if (::inet_ntop(AF_INET, &v4.sin_addr, text, sizeof(text)) == nullptr) {
            return {};
        }
    }
    return std::string{text};
}

std::string Endpoint::to_string() const {
    const std::string host = address();
    const std::string port_text = std::to_string(port());
    // IPv6 gets brackets so the result round-trips through a parser.
    if (family_ == Family::ipv6) {
        return "[" + host + "]:" + port_text;
    }
    return host + ":" + port_text;
}

}  // namespace Mira::transport
