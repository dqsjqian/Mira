#include "mira/http/message.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace Mira::http {
namespace {

/// ASCII-only lowercase.
///
/// `std::tolower` is locale-dependent, and a Turkish locale famously maps 'I'
/// to a dotless lowercase i — which would make `Content-Length` stop matching.
/// Protocol text is ASCII by definition, so it gets ASCII rules.
[[nodiscard]] constexpr char ascii_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

struct MethodEntry {
    std::string_view token;
    Method method;
};

constexpr std::array<MethodEntry, 9> kMethods{{
    {"GET", Method::get},
    {"HEAD", Method::head},
    {"POST", Method::post},
    {"PUT", Method::put},
    {"DELETE", Method::delete_},
    {"CONNECT", Method::connect},
    {"OPTIONS", Method::options},
    {"TRACE", Method::trace},
    {"PATCH", Method::patch},
}};

struct ReasonEntry {
    unsigned status;
    std::string_view reason;
};

/// Reason phrases for the codes a server actually emits. The list is short on
/// purpose: an unknown code returns an empty view rather than a guess, and the
/// caller supplies its own phrase.
constexpr std::array<ReasonEntry, 30> kReasons{{
    {100, "Continue"},
    {101, "Switching Protocols"},
    {200, "OK"},
    {201, "Created"},
    {202, "Accepted"},
    {204, "No Content"},
    {206, "Partial Content"},
    {301, "Moved Permanently"},
    {302, "Found"},
    {303, "See Other"},
    {304, "Not Modified"},
    {307, "Temporary Redirect"},
    {308, "Permanent Redirect"},
    {400, "Bad Request"},
    {401, "Unauthorized"},
    {403, "Forbidden"},
    {404, "Not Found"},
    {405, "Method Not Allowed"},
    {408, "Request Timeout"},
    {409, "Conflict"},
    {411, "Length Required"},
    {413, "Content Too Large"},
    {414, "URI Too Long"},
    {415, "Unsupported Media Type"},
    {429, "Too Many Requests"},
    {431, "Request Header Fields Too Large"},
    {500, "Internal Server Error"},
    {501, "Not Implemented"},
    {503, "Service Unavailable"},
    {505, "HTTP Version Not Supported"},
}};

}  // namespace

std::string_view to_string(Method method) noexcept {
    for (const MethodEntry& entry : kMethods) {
        if (entry.method == method) {
            return entry.token;
        }
    }
    return "";  // Method::other has no canonical spelling
}

Method method_from_token(std::string_view token) noexcept {
    // Method names are case-sensitive per RFC 9110 §9.1 — "get" is not "GET".
    for (const MethodEntry& entry : kMethods) {
        if (entry.token == token) {
            return entry.method;
        }
    }
    return Method::other;
}

std::string_view to_string(Version version) noexcept {
    switch (version) {
    case Version::http_1_0:
        return "HTTP/1.0";
    case Version::http_1_1:
        return "HTTP/1.1";
    }
    return "";
}

bool HeaderMap::names_equal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (ascii_lower(a[i]) != ascii_lower(b[i])) {
            return false;
        }
    }
    return true;
}

std::optional<std::string_view> HeaderMap::get(std::string_view name) const noexcept {
    for (const Entry& entry : entries_) {
        if (names_equal(entry.first, name)) {
            return std::string_view{entry.second};
        }
    }
    return std::nullopt;
}

std::vector<std::string_view> HeaderMap::get_all(std::string_view name) const {
    std::vector<std::string_view> found;
    for (const Entry& entry : entries_) {
        if (names_equal(entry.first, name)) {
            found.emplace_back(entry.second);
        }
    }
    return found;
}

std::size_t HeaderMap::count(std::string_view name) const noexcept {
    std::size_t total = 0;
    for (const Entry& entry : entries_) {
        if (names_equal(entry.first, name)) {
            ++total;
        }
    }
    return total;
}

bool valid_request_host(const Request& request) noexcept {
    const auto count = request.headers.count("Host");
    if (count > 1 || (request.version == Version::http_1_1 && count != 1)) return false;
    const auto host = request.headers.get("Host");
    if (!host) return true;
    // Conservative authority subset: ASCII reg-name / bracketed IPv6,
    // plus an optional decimal port. Userinfo and whitespace are forbidden.
    auto authority = *host;
    if (authority.empty()) return false;
    std::string_view port;
    if (authority.front() == '[') {
        const auto end = authority.find(']');
        if (end == std::string_view::npos) return false;
        const auto ip = authority.substr(1, end - 1);
        const auto compression = ip.find("::");
        if (ip.empty() || (ip.front() == ':' && !ip.starts_with("::")) ||
            (ip.back() == ':' && !ip.ends_with("::")) || ip.find(":::") != std::string_view::npos ||
            (compression != std::string_view::npos && ip.find("::", compression + 2) != std::string_view::npos))
            return false;
        std::size_t groups = 0;
        std::string_view hex = ip;
        if (ip.find('.') != std::string_view::npos) {
            // IPv4-embedded IPv6 occupies the final two 16-bit groups.
            const auto colon = ip.rfind(':');
            if (colon == std::string_view::npos) return false;
            auto tail = ip.substr(colon + 1);
            hex = ip.substr(0, colon + 1);
            for (unsigned octet = 0; octet < 4; ++octet) {
                const auto dot = tail.find('.');
                const auto number = tail.substr(0, dot);
                if (number.empty() || number.size() > 3 ||
                    (number.size() > 1 && number.front() == '0')) return false;
                unsigned value = 0;
                for (char c : number) {
                    if (c < '0' || c > '9') return false;
                    value = value * 10 + static_cast<unsigned>(c - '0');
                }
                if (value > 255 || ((octet < 3) != (dot != std::string_view::npos))) return false;
                if (dot != std::string_view::npos) tail.remove_prefix(dot + 1);
            }
            groups = 2;
        }
        std::size_t digits = 0;
        for (char c : hex) {
            if (c == ':') { if (digits) ++groups; digits = 0; }
            else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) ||
                     ++digits > 4) return false;
        }
        if (digits) ++groups;
        if ((compression == std::string_view::npos &&
             (groups != 8 || ip.front() == ':' || ip.back() == ':')) ||
            (compression != std::string_view::npos && groups >= 8)) return false;
        authority.remove_prefix(end + 1);
        if (!authority.empty()) {
            if (authority.front() != ':') return false;
            port = authority.substr(1);
            if (port.empty()) return false;
        }
    } else {
        const auto colon = authority.find(':');
        const auto name = authority.substr(0, colon);
        if (name.empty()) return false;
        for (char c : name) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-')) return false;
        }
        if (colon != std::string_view::npos) {
            port = authority.substr(colon + 1);
            if (port.empty()) return false;
        }
    }
    unsigned port_number = 0;
    for (char c : port) {
        if (c < '0' || c > '9' || port_number > 6553) return false;
        port_number = port_number * 10 + static_cast<unsigned>(c - '0');
    }
    return port_number <= 65535;
}

std::string_view default_reason(unsigned status) noexcept {
    for (const ReasonEntry& entry : kReasons) {
        if (entry.status == status) {
            return entry.reason;
        }
    }
    return "";
}

}  // namespace Mira::http
