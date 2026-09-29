#include "mira/socks/socks5.hpp"

#include <charconv>
#include <string>

namespace Mira::socks {

namespace {

class Category final : public std::error_category {
public:
    const char* name() const noexcept override { return "Mira.socks"; }
    std::string message(int value) const override {
        switch (static_cast<SocksError>(value)) {
        case SocksError::protocol_error: return "malformed SOCKS5 message";
        case SocksError::no_acceptable_method: return "SOCKS5 proxy accepted no offered method";
        case SocksError::auth_failed: return "SOCKS5 username/password authentication failed";
        case SocksError::general_failure: return "SOCKS5 general server failure";
        case SocksError::not_allowed: return "SOCKS5 connection not allowed by ruleset";
        case SocksError::network_unreachable: return "SOCKS5 network unreachable";
        case SocksError::host_unreachable: return "SOCKS5 host unreachable";
        case SocksError::connection_refused: return "SOCKS5 connection refused";
        case SocksError::ttl_expired: return "SOCKS5 TTL expired";
        case SocksError::command_not_supported: return "SOCKS5 command not supported";
        case SocksError::address_type_not_supported: return "SOCKS5 address type not supported";
        case SocksError::unassigned_reply: return "SOCKS5 unassigned reply code";
        }
        return "unknown SOCKS5 error";
    }
};

bool parse_ipv4(std::string_view text, std::array<std::uint8_t, 4>& out) {
    std::size_t part = 0;
    for (;;) {
        if (part == 4) return false;
        const auto dot = text.find('.');
        const auto field = text.substr(0, dot);
        // Leading zeros are rejected: "010" is octal to some parsers.
        if (field.empty() || field.size() > 3 || (field.size() > 1 && field.front() == '0'))
            return false;
        unsigned value = 0;
        for (const char c : field) {
            if (c < '0' || c > '9') return false;
            value = value * 10 + static_cast<unsigned>(c - '0');
        }
        if (value > 255) return false;
        out[part++] = static_cast<std::uint8_t>(value);
        if (dot == std::string_view::npos) return part == 4;
        text.remove_prefix(dot + 1);
    }
}

bool parse_ipv6(std::string_view text, std::array<std::uint8_t, 16>& out) {
    if (text.size() < 2 || text.size() > 45) return false;
    std::array<std::uint16_t, 8> groups{};
    std::size_t count = 0;
    std::optional<std::size_t> gap;
    if (text.starts_with("::")) {
        gap = 0;
        text.remove_prefix(2);
    } else if (text.front() == ':') {
        return false;
    }
    while (!text.empty()) {
        const auto colon = text.find(':');
        const auto field = text.substr(0, colon);
        if (field.find('.') != std::string_view::npos) {
            // Embedded IPv4 must be the final 32 bits.
            std::array<std::uint8_t, 4> v4{};
            if (colon != std::string_view::npos || count > 6 || !parse_ipv4(field, v4)) return false;
            groups[count++] = static_cast<std::uint16_t>((v4[0] << 8) | v4[1]);
            groups[count++] = static_cast<std::uint16_t>((v4[2] << 8) | v4[3]);
            text = {};
            break;
        }
        if (field.empty() || field.size() > 4 || count == 8) return false;
        unsigned value = 0;
        for (const char c : field) {
            unsigned digit = 0;
            if (c >= '0' && c <= '9') digit = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') digit = static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') digit = static_cast<unsigned>(c - 'A' + 10);
            else return false;
            value = value * 16 + digit;
        }
        groups[count++] = static_cast<std::uint16_t>(value);
        if (colon == std::string_view::npos) {
            text = {};
            break;
        }
        text.remove_prefix(colon + 1);
        if (text.starts_with(":")) {
            if (gap) return false;
            gap = count;
            text.remove_prefix(1);
        } else if (text.empty()) {
            return false;
        }
    }
    if (gap) {
        if (count >= 8) return false;
        const auto tail = count - *gap;
        std::array<std::uint16_t, 8> expanded{};
        for (std::size_t i = 0; i < *gap; ++i) expanded[i] = groups[i];
        for (std::size_t i = 0; i < tail; ++i) expanded[8 - tail + i] = groups[*gap + i];
        groups = expanded;
    } else if (count != 8) {
        return false;
    }
    for (std::size_t i = 0; i < 8; ++i) {
        out[2 * i] = static_cast<std::uint8_t>(groups[i] >> 8);
        out[2 * i + 1] = static_cast<std::uint8_t>(groups[i] & 0xff);
    }
    return true;
}

std::string format_ipv4(std::span<const std::uint8_t> octets) {
    std::string text;
    for (std::size_t i = 0; i < 4; ++i) {
        if (i) text.push_back('.');
        text += std::to_string(octets[i]);
    }
    return text;
}

std::string format_ipv6(std::span<const std::uint8_t> octets) {
    std::array<unsigned, 8> groups{};
    for (std::size_t i = 0; i < 8; ++i)
        groups[i] = (static_cast<unsigned>(octets[2 * i]) << 8) | octets[2 * i + 1];
    // IPv4-mapped addresses keep the dotted tail (RFC 5952 §5).
    if (groups[0] == 0 && groups[1] == 0 && groups[2] == 0 && groups[3] == 0 && groups[4] == 0 &&
        groups[5] == 0xffff)
        return "::ffff:" + format_ipv4(octets.subspan(12));
    std::size_t best = 8, best_length = 0;
    for (std::size_t i = 0; i < 8;) {
        if (groups[i] != 0) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < 8 && groups[j] == 0) ++j;
        if (j - i > best_length) {
            best = i;
            best_length = j - i;
        }
        i = j;
    }
    if (best_length < 2) best = 8;
    std::string text;
    for (std::size_t i = 0; i < 8; ++i) {
        if (i == best) {
            text += "::";
            i += best_length - 1;
            continue;
        }
        if (!text.empty() && !text.ends_with(":")) text.push_back(':');
        std::array<char, 4> hex{};
        const auto end = std::to_chars(hex.data(), hex.data() + hex.size(), groups[i], 16).ptr;
        text.append(hex.data(), end);
    }
    return text;
}

}  // namespace

const std::error_category& socks_category() noexcept {
    static const Category category;
    return category;
}

std::error_code make_error_code(SocksError error) noexcept {
    return {static_cast<int>(error), socks_category()};
}

std::error_code reply_error(std::uint8_t code) noexcept {
    if (code >= 0x01 && code <= 0x08)
        return make_error_code(static_cast<SocksError>(static_cast<int>(SocksError::general_failure) + code - 1));
    return make_error_code(SocksError::unassigned_reply);
}

Address Address::ipv4(std::array<std::uint8_t, 4> octets, std::uint16_t port) {
    Address address;
    address.kind_ = Kind::ipv4;
    std::copy(octets.begin(), octets.end(), address.bytes_.begin());
    address.port_ = port;
    return address;
}

Address Address::ipv6(std::array<std::uint8_t, 16> octets, std::uint16_t port) {
    Address address;
    address.kind_ = Kind::ipv6;
    address.bytes_ = octets;
    address.port_ = port;
    return address;
}

Result<Address> Address::domain(std::string_view name, std::uint16_t port) {
    if (name.empty() || name.size() > 255 || name.find('\0') != std::string_view::npos)
        return fail(Errc::invalid_argument);
    Address address;
    address.kind_ = Kind::domain;
    address.name_ = std::string{name};
    address.port_ = port;
    return address;
}

Result<Address> Address::parse(std::string_view host, std::uint16_t port) {
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        std::array<std::uint8_t, 16> v6{};
        if (!parse_ipv6(host.substr(1, host.size() - 2), v6)) return fail(Errc::invalid_argument);
        return ipv6(v6, port);
    }
    if (host.find(':') != std::string_view::npos) {
        std::array<std::uint8_t, 16> v6{};
        if (!parse_ipv6(host, v6)) return fail(Errc::invalid_argument);
        return ipv6(v6, port);
    }
    if (!host.empty() && host.find_first_not_of("0123456789.") == std::string_view::npos) {
        // All digits and dots: an address or an error, never a domain.
        std::array<std::uint8_t, 4> v4{};
        if (!parse_ipv4(host, v4)) return fail(Errc::invalid_argument);
        return ipv4(v4, port);
    }
    return domain(host, port);
}

std::span<const std::uint8_t> Address::octets() const noexcept {
    switch (kind_) {
    case Kind::ipv4: return std::span{bytes_}.first(4);
    case Kind::ipv6: return std::span{bytes_};
    case Kind::domain: break;
    }
    return {};
}

std::string Address::host() const {
    switch (kind_) {
    case Kind::ipv4: return format_ipv4(octets());
    case Kind::ipv6: return format_ipv6(octets());
    case Kind::domain: break;
    }
    return name_;
}

std::string Address::to_string() const {
    const auto text = host();
    const auto port = std::to_string(port_);
    return kind_ == Kind::ipv6 ? "[" + text + "]:" + port : text + ":" + port;
}

std::string Address::encode() const {
    std::string wire;
    wire.push_back(static_cast<char>(kind_));
    if (kind_ == Kind::domain) {
        wire.push_back(static_cast<char>(name_.size()));
        wire += name_;
    } else {
        for (const auto octet : octets()) wire.push_back(static_cast<char>(octet));
    }
    wire.push_back(static_cast<char>(port_ >> 8));
    wire.push_back(static_cast<char>(port_ & 0xff));
    return wire;
}

namespace detail {
bool valid_credential(std::string_view field) noexcept {
    return !field.empty() && field.size() <= 255;
}
}  // namespace detail

}  // namespace Mira::socks
