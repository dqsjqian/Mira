#include "mira/dns/doh.hpp"

#include <array>

namespace Mira::dns::doh {

namespace {

constexpr std::string_view alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int value_of(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

bool ascii_iequal(std::string_view a, std::string_view b) noexcept {
    return http::HeaderMap::names_equal(a, b);
}

std::string_view trim(std::string_view text) noexcept {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return text;
}

bool is_dns_message(const http::HeaderMap& headers) {
    if (headers.count("Content-Type") != 1) return false;
    auto value = *headers.get("Content-Type");
    const auto semicolon = value.find(';');
    return ascii_iequal(trim(value.substr(0, semicolon)), media_type);
}

Result<void> check_path(std::string_view path) {
    if (path.empty() || path.front() != '/') return fail(Errc::invalid_argument);
    for (const char c : path) {
        const auto byte = static_cast<unsigned char>(c);
        if (byte <= 0x20 || byte >= 0x7F || c == '#') return fail(Errc::invalid_argument);
    }
    return {};
}

}  // namespace

std::string base64url_encode(std::span<const std::byte> data) {
    std::string out;
    out.reserve((data.size() * 4 + 2) / 3);
    std::size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        const auto chunk = (std::to_integer<unsigned>(data[i]) << 16) |
                           (std::to_integer<unsigned>(data[i + 1]) << 8) | std::to_integer<unsigned>(data[i + 2]);
        out.push_back(alphabet[(chunk >> 18) & 63]);
        out.push_back(alphabet[(chunk >> 12) & 63]);
        out.push_back(alphabet[(chunk >> 6) & 63]);
        out.push_back(alphabet[chunk & 63]);
    }
    const auto rest = data.size() - i;
    if (rest == 1) {
        const auto chunk = std::to_integer<unsigned>(data[i]) << 16;
        out.push_back(alphabet[(chunk >> 18) & 63]);
        out.push_back(alphabet[(chunk >> 12) & 63]);
    } else if (rest == 2) {
        const auto chunk = (std::to_integer<unsigned>(data[i]) << 16) | (std::to_integer<unsigned>(data[i + 1]) << 8);
        out.push_back(alphabet[(chunk >> 18) & 63]);
        out.push_back(alphabet[(chunk >> 12) & 63]);
        out.push_back(alphabet[(chunk >> 6) & 63]);
    }
    return out;
}

Result<std::vector<std::byte>> base64url_decode(std::string_view text) {
    if (text.size() % 4 == 1) return fail(DnsError::bad_base64);
    std::vector<std::byte> out;
    out.reserve(text.size() * 3 / 4);
    unsigned buffer = 0;
    int bits = 0;
    for (const char c : text) {
        const int value = value_of(c);
        if (value < 0) return fail(DnsError::bad_base64);
        buffer = (buffer << 6) | static_cast<unsigned>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::byte>((buffer >> bits) & 0xFF));
        }
    }
    // Canonical encodings leave no set bits behind.
    if (bits > 0 && (buffer & ((1u << bits) - 1)) != 0) return fail(DnsError::bad_base64);
    return out;
}

Result<http::Request> make_get(std::string_view authority, std::string_view path,
                               std::span<const std::byte> query) {
    if (auto checked = check_path(path); !checked) return fail(checked.error());
    if (authority.empty() || query.empty() || query.size() > 65535) return fail(Errc::invalid_argument);
    http::Request request;
    request.method = http::Method::get;
    request.target = std::string{path};
    request.target += path.find('?') == std::string_view::npos ? "?dns=" : "&dns=";
    request.target += base64url_encode(query);
    request.headers.append("Host", std::string{authority});
    request.headers.append("Accept", std::string{media_type});
    return request;
}

Result<http::Request> make_post(std::string_view authority, std::string_view path) {
    if (auto checked = check_path(path); !checked) return fail(checked.error());
    if (authority.empty()) return fail(Errc::invalid_argument);
    http::Request request;
    request.method = http::Method::post;
    request.target = std::string{path};
    request.headers.append("Host", std::string{authority});
    request.headers.append("Accept", std::string{media_type});
    request.headers.append("Content-Type", std::string{media_type});
    return request;
}

Result<Message> parse_response(const http::Response& response, std::span<const std::byte> body,
                               const Limits& limits) {
    if (response.status < 200 || response.status > 299) return fail(DnsError::bad_status);
    if (!is_dns_message(response.headers)) return fail(DnsError::bad_media_type);
    if (body.size() > limits.max_message_size) return fail(DnsError::too_large);
    return decode(body, limits);
}

Result<std::vector<std::byte>> decode_request(const http::Request& request,
                                              std::span<const std::byte> body, const Limits& limits) {
    std::vector<std::byte> wire;
    if (request.method == http::Method::get) {
        const auto question = request.target.find('?');
        if (question == std::string::npos) return fail(DnsError::bad_request);
        std::string_view query{request.target};
        query.remove_prefix(question + 1);
        std::optional<std::string_view> encoded;
        for (;;) {
            const auto amp = query.find('&');
            const auto pair = query.substr(0, amp);
            if (pair.starts_with("dns=")) {
                if (encoded) return fail(DnsError::bad_request);
                encoded = pair.substr(4);
            }
            if (amp == std::string_view::npos) break;
            query.remove_prefix(amp + 1);
        }
        if (!encoded || encoded->empty()) return fail(DnsError::bad_request);
        if (encoded->size() > (limits.max_message_size * 4 + 2) / 3) return fail(DnsError::too_large);
        auto decoded = base64url_decode(*encoded);
        if (!decoded) return fail(DnsError::bad_request);
        wire = std::move(*decoded);
    } else if (request.method == http::Method::post) {
        if (!is_dns_message(request.headers)) return fail(DnsError::bad_media_type);
        if (body.size() > limits.max_message_size) return fail(DnsError::too_large);
        wire.assign(body.begin(), body.end());
    } else {
        return fail(DnsError::bad_method);
    }
    if (wire.size() < 12) return fail(DnsError::bad_request);
    if (wire.size() > limits.max_message_size) return fail(DnsError::too_large);
    return wire;
}

unsigned http_status(std::error_code error) noexcept {
    if (error == make_error_code(DnsError::bad_method)) return 405;
    if (error == make_error_code(DnsError::too_large)) return 413;
    if (error == make_error_code(DnsError::bad_media_type)) return 415;
    return 400;
}

}  // namespace Mira::dns::doh
