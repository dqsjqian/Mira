#include "mira/http/serializer.hpp"

#include "grammar.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace Mira::http {
namespace {

void append(Buffer& out, std::string_view text) {
    out.append(
        std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()), text.size()});
}

[[nodiscard]] bool valid_header_name(std::string_view name) noexcept {
    if (name.empty()) {
        return false;
    }
    for (const char c : name) {
        if (!grammar::is_tchar(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool valid_header_value(std::string_view value) noexcept {
    for (const char c : value) {
        if (!grammar::is_field_vchar(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    // Leading or trailing whitespace would be stripped by a recipient anyway,
    // and an all-whitespace value is almost always a bug in the caller.
    return true;
}

[[nodiscard]] std::string_view to_hex(std::uint64_t value, std::array<char, 20>& scratch) {
    static constexpr char digits[] = "0123456789abcdef";
    std::size_t index = scratch.size();
    if (value == 0) {
        scratch[--index] = '0';
    }
    while (value > 0) {
        scratch[--index] = digits[value % 16];
        value /= 16;
    }
    return std::string_view{scratch.data() + index, scratch.size() - index};
}

class SerializeCategory final : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "Mira.http.serialize"; }

    [[nodiscard]] std::string message(int value) const override {
        switch (static_cast<SerializeError>(value)) {
        case SerializeError::invalid_header:
            return "header name or value contains forbidden bytes";
        case SerializeError::framing_conflict:
            return "caller supplied a framing header that the serializer owns";
        case SerializeError::invalid_status:
            return "status code outside 100..999";
        }
        return "unknown http serialize error (" + std::to_string(value) + ")";
    }
};

}  // namespace

const std::error_category& serialize_category() noexcept {
    static const SerializeCategory category{};
    return category;
}

std::error_code make_error_code(SerializeError error) noexcept {
    return {static_cast<int>(error), serialize_category()};
}

bool status_forbids_body(unsigned status) noexcept {
    // RFC 9110 §6.4.1 / §15.3.5 / §15.4.5: informational, No Content, and Not
    // Modified responses have no body, and sending one desynchronises the
    // connection for every request that follows.
    return (status >= 100 && status < 200) || status == 204 || status == 304;
}

bool should_keep_alive(const Request& request) noexcept {
    const auto mentions = [&](std::string_view token) {
        for (const auto& [name, value] : request.headers) {
            if (!HeaderMap::names_equal(name, "Connection")) continue;
            for (const std::string_view item : grammar::split_list(value)) {
                if (HeaderMap::names_equal(item, token)) return true;
            }
        }
        return false;
    };

    if (request.version == Version::http_1_1) {
        return !mentions("close");
    }
    // HTTP/1.0 is close-by-default; persistence is opt-in.
    return mentions("keep-alive") && !mentions("close");
}

Result<void> write_response_head(Buffer& out,
                                 const Response& response,
                                 Framing framing,
                                 std::uint64_t body_size) {
    if (response.version == Version::http_1_0 && framing == Framing::chunked) {
        return fail(Errc::not_supported);
    }
    if (response.status < 100 || response.status > 999) {
        return fail(SerializeError::invalid_status);
    }

    // The serializer owns framing. A caller-supplied Content-Length or
    // Transfer-Encoding is refused rather than dropped: dropping it would make
    // the wire silently disagree with what the caller asked for.
    if (response.headers.contains("Content-Length") ||
        response.headers.contains("Transfer-Encoding")) {
        return fail(SerializeError::framing_conflict);
    }

    for (const auto& [name, value] : response.headers) {
        if (!valid_header_name(name) || !valid_header_value(value)) {
            return fail(SerializeError::invalid_header);
        }
    }

    // One reserve up front beats a dozen growth reallocations on the way to
    // a typical head; the estimate errs high by a few bytes, which is
    // cheaper than guessing low and growing mid-append.
    std::size_t estimated = 32 + response.reason.size() + 32;
    for (const auto& [name, value] : response.headers) {
        estimated += name.size() + value.size() + 4;
    }
    out.reserve(out.size() + estimated);

    // status-line = HTTP-version SP status-code SP [ reason-phrase ]
    append(out, to_string(response.version));
    append(out, " ");
    append(out, std::to_string(response.status));
    append(out, " ");
    if (!response.reason.empty()) {
        if (!valid_header_value(response.reason)) {
            return fail(SerializeError::invalid_header);
        }
        append(out, response.reason);
    } else {
        append(out, default_reason(response.status));
    }
    append(out, "\r\n");

    for (const auto& [name, value] : response.headers) {
        append(out, name);
        append(out, ": ");
        append(out, value);
        append(out, "\r\n");
    }

    // A status that forbids a body gets no framing header at all — writing
    // `Content-Length: 0` on a 304 is a common way to confuse caches.
    if (!status_forbids_body(response.status)) {
        switch (framing) {
        case Framing::content_length:
            append(out, "Content-Length: ");
            append(out, std::to_string(body_size));
            append(out, "\r\n");
            break;
        case Framing::chunked:
            append(out, "Transfer-Encoding: chunked\r\n");
            break;
        case Framing::none:
            // Deliberate: the caller is signalling "no body and no framing",
            // which is only valid when the connection closes afterwards.
            break;
        }
    }

    append(out, "\r\n");
    return Result<void>{};
}

Result<void> write_request_head(Buffer& out, const Request& request,
                                std::uint64_t body_size, Limits limits) {
    return write_request_head(out, request, Framing::content_length, body_size, limits);
}

Result<void> write_request_head(Buffer& out, const Request& request,
                                Framing framing, std::uint64_t body_size, Limits limits,
                                Expectation expectation) {
    if (framing != Framing::content_length && framing != Framing::chunked)
        return fail(Errc::invalid_argument);
    if (expectation != Expectation::none && expectation != Expectation::continue_100)
        return fail(Errc::invalid_argument);
    if (framing == Framing::chunked) {
        if (request.version != Version::http_1_1) return fail(Errc::not_supported);
        if (body_size != 0) return fail(Errc::invalid_argument);
    }
    // RFC 9110 §10.1.1: never in HTTP/1.0, never without content.
    if (expectation == Expectation::continue_100) {
        if (request.version != Version::http_1_1) return fail(Errc::not_supported);
        if (framing == Framing::content_length && body_size == 0) return fail(Errc::invalid_argument);
    }
    if (request.method == Method::connect || request.method == Method::other ||
        request.headers.contains("Upgrade") || request.headers.contains("Expect")) {
        return fail(Errc::not_supported);
    }
    const auto method = to_string(request.method);
    if (method.empty() || (request.version != Version::http_1_0 && request.version != Version::http_1_1)) {
        return fail(Errc::invalid_argument);
    }
    if (request.target.empty() ||
        (request.target.front() != '/' && !(request.method == Method::options && request.target == "*"))) {
        return fail(Errc::invalid_argument);
    }
    for (char c : request.target) {
        const auto byte = static_cast<unsigned char>(c);
        if (byte <= 0x20 || byte >= 0x7f || c == '#') return fail(Errc::invalid_argument);
    }
    if (request.headers.contains("Content-Length") || request.headers.contains("Transfer-Encoding")) {
        return fail(SerializeError::framing_conflict);
    }
    if (request.headers.count("Host") > 1 ||
        (request.version == Version::http_1_1 && request.headers.count("Host") != 1)) {
        return fail(SerializeError::invalid_header);
    }
    if (const auto host = request.headers.get("Host")) {
        // Conservative authority subset: ASCII reg-name / bracketed IPv6,
        // plus an optional decimal port.
        auto authority = *host;
        if (authority.empty()) return fail(SerializeError::invalid_header);
        std::string_view port;
        if (authority.front() == '[') {
            const auto end = authority.find(']');
            if (end == std::string_view::npos) return fail(SerializeError::invalid_header);
            const auto ip = authority.substr(1, end - 1);
            const auto compression = ip.find("::");
            if (ip.empty() || (ip.front() == ':' && !ip.starts_with("::")) ||
                (ip.back() == ':' && !ip.ends_with("::")) || ip.find(":::") != std::string_view::npos ||
                (compression != std::string_view::npos && ip.find("::", compression + 2) != std::string_view::npos)) {
                return fail(SerializeError::invalid_header);
            }
            std::size_t groups = 0;
            std::size_t digits = 0;
            for (char c : ip) {
                if (c == ':') { if (digits) ++groups; digits = 0; }
                else {
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) ||
                        ++digits > 4) return fail(SerializeError::invalid_header);
                }
            }
            if (digits) ++groups;
            if ((compression == std::string_view::npos &&
                 (groups != 8 || ip.front() == ':' || ip.back() == ':')) ||
                (compression != std::string_view::npos && groups >= 8)) return fail(SerializeError::invalid_header);
            authority.remove_prefix(end + 1);
            if (!authority.empty()) {
                if (authority.front() != ':') return fail(SerializeError::invalid_header);
                port = authority.substr(1);
                if (port.empty()) return fail(SerializeError::invalid_header);
            }
        } else {
            const auto colon = authority.find(':');
            const auto name = authority.substr(0, colon);
            if (name.empty()) return fail(SerializeError::invalid_header);
            for (char c : name) {
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '.' || c == '-')) return fail(SerializeError::invalid_header);
            }
            if (colon != std::string_view::npos) {
                port = authority.substr(colon + 1);
                if (port.empty()) return fail(SerializeError::invalid_header);
            }
        }
        unsigned port_number = 0;
        for (char c : port) {
            if (c < '0' || c > '9' || port_number > 6553) return fail(SerializeError::invalid_header);
            port_number = port_number * 10 + static_cast<unsigned>(c - '0');
        }
        if (port_number > 65535) return fail(SerializeError::invalid_header);
    }
    if (request.target.size() > limits.max_start_line ||
        method.size() + 10 > limits.max_start_line - request.target.size() ||
        body_size > limits.max_body_size || request.headers.size() >= limits.max_header_count) {
        return fail(Errc::limit_exceeded);
    }
    std::size_t total = 0;
    for (const auto& [name, value] : request.headers) {
        if (!valid_header_name(name) || !valid_header_value(value)) return fail(SerializeError::invalid_header);
        if (HeaderMap::names_equal(name, "Connection")) {
            for (const auto token : grammar::split_list(value)) {
                if (!HeaderMap::names_equal(token, "close") && !HeaderMap::names_equal(token, "keep-alive")) {
                    return fail(Errc::not_supported);
                }
            }
        }
        if (name.size() > limits.max_header_line || value.size() > limits.max_header_line - name.size() ||
            limits.max_header_line - name.size() - value.size() < 2) return fail(Errc::limit_exceeded);
        const auto size = name.size() + value.size() + 2;
        if (size > limits.max_headers_total - total) return fail(Errc::limit_exceeded);
        total += size;
    }
    const auto framing_line = framing == Framing::chunked
                                  ? std::string{"Transfer-Encoding: chunked"}
                                  : "Content-Length: " + std::to_string(body_size);
    if (framing_line.size() > limits.max_header_line || framing_line.size() > limits.max_headers_total - total) {
        return fail(Errc::limit_exceeded);
    }
    total += framing_line.size();
    constexpr std::string_view expect_line = "Expect: 100-continue";
    const bool expect = expectation == Expectation::continue_100;
    if (expect && (request.headers.size() + 1 >= limits.max_header_count ||
                   expect_line.size() > limits.max_headers_total - total)) {
        return fail(Errc::limit_exceeded);
    }
    // One reserve up front: method + target + version line, every header
    // line (name + ": " + value + CRLF), plus framing and the final CRLF.
    out.reserve(out.size() + method.size() + request.target.size() + 32 +
                total + request.headers.size() * 4 + (expect ? expect_line.size() + 2 : 0) + 4);
    append(out, method); append(out, " "); append(out, request.target);
    append(out, " "); append(out, to_string(request.version)); append(out, "\r\n");
    for (const auto& [name, value] : request.headers) {
        append(out, name); append(out, ": "); append(out, value); append(out, "\r\n");
    }
    if (expect) {
        append(out, expect_line); append(out, "\r\n");
    }
    append(out, framing_line); append(out, "\r\n\r\n");
    return {};
}

Result<void> write_chunk(Buffer& out, std::span<const std::byte> chunk) {
    if (chunk.empty()) {
        // A zero-length chunk *is* the terminator; emitting one here would end
        // the message early and leave the caller writing into a closed body.
        return fail(SerializeError::framing_conflict);
    }

    std::array<char, 20> scratch{};
    append(out, to_hex(chunk.size(), scratch));
    append(out, "\r\n");
    out.append(chunk);
    append(out, "\r\n");
    return Result<void>{};
}

void write_last_chunk(Buffer& out) {
    append(out, "0\r\n\r\n");
}

}  // namespace Mira::http
