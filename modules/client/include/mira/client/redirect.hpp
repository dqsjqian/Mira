#pragma once

// HTTP redirect following for the pooled clients (RFC 9110 §15.4).
//
// ClientConnection deliberately never retries: DNS, pooling, redirects,
// decompression, proxies and upgrades are separate layers. This is the
// redirect layer: request_with_redirects drives a pooled client
// (HttpClient, HttpsClient) through a redirect chain and returns the final
// response body, or stops early where the client cannot follow.
//
// Followed: 301, 302, 303, 307, 308 with a Location header. Anything else
// (300, 304, 305, a 3xx without Location, any non-3xx) is terminal and is
// returned as the final response. Method handling follows the fetch
// standard: 301/302 convert POST to GET; 303 converts everything except
// HEAD to GET; 307/308 preserve method and body. A converted request drops
// its body and every Content-* header; a cross-origin hop additionally
// drops Authorization and Cookie. Host, Content-Length and
// Transfer-Encoding are always left to the session/framing layer, never
// carried across hops.
//
// Safety bounds: at most max_redirects follows (default 10); revisiting an
// absolute URL fails with limit_exceeded instead of looping forever; the
// collected body stays bounded by the connection's own limits. A redirect
// to another scheme stops the chain and reports the absolute target in
// unfollowed_location — the caller re-drives it with a client of that
// scheme. The helper never invents a scheme: the initial scheme must match
// the client ("http" for HttpClient, "https" for HttpsClient).
//
// Targets are origin-form only (the request target must start with '/').
// resolve_redirect_location and next_redirect_method are public and pure,
// so multiplex clients — whose request() already returns a complete
// response — can build their own loop on the same rules, and so the rules
// are unit-testable without a server.

#include "mira/core/error.hpp"
#include "mira/core/operation.hpp"
#include "mira/core/task.hpp"
#include "mira/http/message.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Mira::client {

namespace detail {

inline std::string lower_ascii(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (char c : value) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        result.push_back(c);
    }
    return result;
}

inline std::string_view trim_redirect_ows(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    return value;
}

inline bool is_scheme_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' ||
           c == '-' || c == '.';
}

// RFC 3986 §5.2.4: resolve "." and ".." segments. Operates on the path
// only; the caller splits the query off first.
inline std::string remove_dot_segments(std::string_view path) {
    std::string input{path};
    std::string output;
    while (!input.empty()) {
        if (input.starts_with("../")) {
            input.erase(0, 3);
        } else if (input.starts_with("./")) {
            input.erase(0, 2);
        } else if (input.starts_with("/./")) {
            input.erase(0, 2);
        } else if (input == "/.") {
            input = "/";
        } else if (input.starts_with("/../")) {
            input.erase(0, 3);
            if (const auto slash = output.rfind('/'); slash != std::string::npos)
                output.erase(slash);
        } else if (input == "/..") {
            input = "/";
            if (const auto slash = output.rfind('/'); slash != std::string::npos)
                output.erase(slash);
        } else if (input == "." || input == "..") {
            input.clear();
        } else {
            std::size_t end = 0;
            if (input.front() == '/') {
                end = input.find('/', 1);
            } else {
                end = input.find('/');
            }
            if (end == std::string_view::npos) end = input.size();
            output.append(input.substr(0, end));
            input.erase(0, end);
        }
    }
    return output;
}

inline bool valid_target_chars(std::string_view target) noexcept {
    for (char c : target) {
        const auto byte = static_cast<unsigned char>(c);
        if (byte <= 0x20 || byte >= 0x7f || c == '#') return false;
    }
    return true;
}

}  // namespace detail

/// A resolved redirect destination: always http(s), always origin-form.
struct RedirectTarget {
    std::string scheme;
    std::string host;
    std::uint16_t port = 0;
    std::string target;
    /// Canonical absolute URL, port always present, host bracketed when it
    /// holds a colon. Used for loop detection and unfollowed_location.
    [[nodiscard]] std::string url() const {
        std::string result = scheme + "://";
        if (host.find(':') != std::string::npos) result += "[" + host + "]";
        else result += host;
        result += ":" + std::to_string(port) + target;
        return result;
    }
};

/// Resolve a Location value against the current request URL, per RFC 3986
/// §5.2. Absolute http(s) URIs, scheme-relative ("//host/path"),
/// absolute-path ("/path"), query-only ("?q") and relative ("sib", "../up")
/// references are all handled, dot segments removed, fragments stripped.
/// Anything else fails: another scheme is not_supported (only http/https
/// are representable here), malformed authorities, ports or targets are
/// invalid_argument. An empty Location resolves to the current URL, which
/// the caller's loop detection then rejects as a loop.
[[nodiscard]] inline Result<RedirectTarget> resolve_redirect_location(std::string_view scheme,
                                                                      std::string_view host,
                                                                      std::uint16_t port,
                                                                      std::string_view current_target,
                                                                      std::string_view location) {
    const std::string current_scheme = detail::lower_ascii(scheme);
    const std::string current_host = detail::lower_ascii(host);
    if ((current_scheme != "http" && current_scheme != "https") || port == 0 ||
        current_target.empty() || current_target.front() != '/')
        return fail(Errc::invalid_argument);
    const auto value = detail::trim_redirect_ows(location);
    const auto no_fragment = value.substr(0, value.find('#'));
    if (no_fragment.empty())
        return RedirectTarget{current_scheme, current_host, port, std::string{current_target}};

    std::string target_scheme = current_scheme;
    std::string target_host = current_host;
    std::uint16_t target_port = port;
    std::string_view path_query;
    bool has_authority = false;

    // A scheme is alphabetic, then scheme chars, then ':', appearing before
    // any '/', '?'. (A ':' later than those belongs to a path or port.)
    std::size_t colon = std::string_view::npos;
    for (std::size_t i = 0; i < no_fragment.size(); ++i) {
        const char c = no_fragment[i];
        if (c == ':' && i > 0) {
            colon = i;
            break;
        }
        if (c == '/' || c == '?') break;
        if (!detail::is_scheme_char(c) || (i == 0 && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z'))) break;
    }
    std::string_view rest = no_fragment;
    if (colon != std::string_view::npos) {
        const auto found_scheme = detail::lower_ascii(no_fragment.substr(0, colon));
        if (found_scheme != "http" && found_scheme != "https") return fail(Errc::not_supported);
        rest = no_fragment.substr(colon + 1);
        if (!rest.starts_with("//")) return fail(Errc::invalid_argument);
        target_scheme = found_scheme;
        has_authority = true;
        rest.remove_prefix(2);
        const auto authority_end = std::min(rest.find('/'), rest.find('?'));
        const auto authority = rest.substr(0, authority_end);
        path_query = authority_end == std::string_view::npos ? std::string_view{} : rest.substr(authority_end);
        std::string_view host_port = authority;
        if (host_port.starts_with("[")) {
            const auto close = host_port.find(']');
            if (close == std::string_view::npos) return fail(Errc::invalid_argument);
            target_host = detail::lower_ascii(host_port.substr(1, close - 1));
            host_port.remove_prefix(close + 1);
            if (!host_port.empty()) {
                if (!host_port.starts_with(":")) return fail(Errc::invalid_argument);
                host_port.remove_prefix(1);
            } else {
                host_port = {};
            }
        } else {
            const auto last_colon = host_port.rfind(':');
            if (last_colon != std::string_view::npos) {
                if (host_port.find(':') != last_colon) return fail(Errc::invalid_argument);
                target_host = detail::lower_ascii(host_port.substr(0, last_colon));
                host_port.remove_prefix(last_colon + 1);
            } else {
                target_host = detail::lower_ascii(host_port);
                host_port = {};
            }
        }
        if (target_host.empty()) return fail(Errc::invalid_argument);
        if (!host_port.empty()) {
            unsigned parsed = 0;
            for (char c : host_port) {
                if (c < '0' || c > '9') return fail(Errc::invalid_argument);
                parsed = parsed * 10 + static_cast<unsigned>(c - '0');
                if (parsed > 65535) return fail(Errc::invalid_argument);
            }
            if (parsed == 0) return fail(Errc::invalid_argument);
            target_port = static_cast<std::uint16_t>(parsed);
        } else {
            target_port = target_scheme == "https" ? 443 : 80;
        }
    } else if (rest.starts_with("//")) {
        has_authority = true;
        rest.remove_prefix(2);
        const auto authority_end = std::min(rest.find('/'), rest.find('?'));
        const auto authority = rest.substr(0, authority_end);
        path_query = authority_end == std::string_view::npos ? std::string_view{} : rest.substr(authority_end);
        if (authority.starts_with("[")) {
            const auto close = authority.find(']');
            if (close == std::string_view::npos) return fail(Errc::invalid_argument);
            target_host = detail::lower_ascii(authority.substr(1, close - 1));
            const auto tail = authority.substr(close + 1);
            if (!tail.empty()) {
                if (!tail.starts_with(":")) return fail(Errc::invalid_argument);
                unsigned parsed = 0;
                for (char c : tail.substr(1)) {
                    if (c < '0' || c > '9') return fail(Errc::invalid_argument);
                    parsed = parsed * 10 + static_cast<unsigned>(c - '0');
                    if (parsed > 65535) return fail(Errc::invalid_argument);
                }
                if (parsed == 0) return fail(Errc::invalid_argument);
                target_port = static_cast<std::uint16_t>(parsed);
            } else {
                target_port = target_scheme == "https" ? 443 : 80;
            }
        } else {
            const auto last_colon = authority.rfind(':');
            if (last_colon != std::string_view::npos) {
                if (authority.find(':') != last_colon) return fail(Errc::invalid_argument);
                target_host = detail::lower_ascii(authority.substr(0, last_colon));
                unsigned parsed = 0;
                for (char c : authority.substr(last_colon + 1)) {
                    if (c < '0' || c > '9') return fail(Errc::invalid_argument);
                    parsed = parsed * 10 + static_cast<unsigned>(c - '0');
                    if (parsed > 65535) return fail(Errc::invalid_argument);
                }
                if (parsed == 0) return fail(Errc::invalid_argument);
                target_port = static_cast<std::uint16_t>(parsed);
            } else {
                target_host = detail::lower_ascii(authority);
                target_port = target_scheme == "https" ? 443 : 80;
            }
        }
        if (target_host.empty()) return fail(Errc::invalid_argument);
    } else {
        path_query = rest;
    }

    std::string target;
    const auto query_mark = path_query.find('?');
    const auto path_part = query_mark == std::string_view::npos ? path_query : path_query.substr(0, query_mark);
    const bool has_query = query_mark != std::string_view::npos;
    const auto query_part = has_query ? path_query.substr(query_mark + 1) : std::string_view{};
    if (has_authority || path_part.starts_with("/")) {
        // Absolute URI, scheme-relative URI, or absolute path: the path
        // replaces the base path wholesale (empty means "/").
        target = path_part.empty() ? "/" : detail::remove_dot_segments(path_part);
    } else if (path_part.empty()) {
        // Query-only reference: same path, new query.
        const auto base_path = current_target.substr(0, current_target.find('?'));
        target = std::string{base_path};
    } else {
        // Relative path: merge with the base path's directory, then remove
        // dot segments.
        const auto base_path = current_target.substr(0, current_target.find('?'));
        const auto slash = base_path.rfind('/');
        const auto merged = (slash == std::string_view::npos ? std::string{"/"}
                                                             : std::string{base_path.substr(0, slash + 1)}) +
                            std::string{path_part};
        target = detail::remove_dot_segments(merged);
    }
    if (has_query) {
        target += "?";
        target += query_part;
    }
    if (target.empty() || target.front() != '/' || !detail::valid_target_chars(target))
        return fail(Errc::invalid_argument);
    return RedirectTarget{target_scheme, target_host, target_port, std::move(target)};
}

/// The method (and body fate) of the next hop for a redirect status.
struct RedirectMethod {
    http::Method method;
    bool drop_body;
};

[[nodiscard]] inline RedirectMethod next_redirect_method(unsigned status, http::Method method) noexcept {
    switch (status) {
        case 301:
        case 302:
            if (method == http::Method::post) return {http::Method::get, true};
            return {method, false};
        case 303:
            if (method == http::Method::head) return {method, false};
            return {http::Method::get, true};
        default:  // 307, 308, and anything else: preserve method and body.
            return {method, false};
    }
}

struct RedirectOptions {
    std::size_t max_redirects = 10;
};

struct RedirectResponse {
    unsigned status = 0;
    http::HeaderMap headers{};
    std::vector<std::byte> body{};
    std::size_t redirects_followed = 0;
    /// The URL that produced this response.
    std::string final_scheme;
    std::string final_host;
    std::string final_target;
    std::uint16_t final_port = 0;
    /// Set only when the chain stopped at a cross-scheme redirect: the
    /// absolute target URL, for the caller to re-drive with a client of
    /// that scheme. Empty in every other case.
    std::optional<std::string> unfollowed_location;
};

namespace detail {

inline bool starts_with_ci(std::string_view name, std::string_view prefix) noexcept {
    if (name.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        char a = name[i];
        char b = prefix[i];
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
        if (a != b) return false;
    }
    return true;
}

inline http::HeaderMap filtered_headers(const http::HeaderMap& in, bool cross_origin, bool drop_body) {
    http::HeaderMap out;
    for (const auto& [name, value] : in) {
        if (http::HeaderMap::names_equal(name, "Host")) continue;
        if (http::HeaderMap::names_equal(name, "Content-Length")) continue;
        if (http::HeaderMap::names_equal(name, "Transfer-Encoding")) continue;
        if (drop_body && starts_with_ci(name, "content-")) continue;
        if (cross_origin &&
            (http::HeaderMap::names_equal(name, "Authorization") ||
             http::HeaderMap::names_equal(name, "Cookie")))
            continue;
        out.append(name, value);
    }
    return out;
}

}  // namespace detail

template<class Client>
    requires requires(Client& client, std::string host, std::uint16_t port, OperationOptions io,
                      http::Request request, std::span<const std::byte> body) {
    { client.acquire(std::move(host), port, io) } -> std::same_as<Task<Result<typename Client::SessionType>>>;
    {
        std::declval<typename Client::SessionType&>().start(std::move(request), body)
    } -> std::same_as<Task<Result<void>>>;
    {
        std::declval<typename Client::SessionType&>().read_body()
    } -> std::same_as<Task<Result<std::span<const std::byte>>>>;
    {
        std::declval<const typename Client::SessionType&>().response()
    } -> std::same_as<Result<http::Response>>;
    { std::declval<typename Client::SessionType&>().recycle() } -> std::same_as<Result<void>>;
}
[[nodiscard]] Task<Result<RedirectResponse>> request_with_redirects(Client& client, std::string scheme,
                                                                     std::string host, std::uint16_t port,
                                                                     http::Request request,
                                                                     std::vector<std::byte> body = {},
                                                                     RedirectOptions options = {},
                                                                     OperationOptions io = {}) {
    if (scheme != "http" && scheme != "https") co_return fail(Errc::invalid_argument);
    if (port == 0) co_return fail(Errc::invalid_argument);
    if (request.target.empty() || request.target.front() != '/') co_return fail(Errc::invalid_argument);
    const auto version = request.version;
    std::string current_scheme = detail::lower_ascii(scheme);
    std::string current_host = detail::lower_ascii(host);
    std::uint16_t current_port = port;
    std::string current_target = request.target;
    http::Method current_method = request.method;
    http::HeaderMap current_headers = detail::filtered_headers(request.headers, false, false);
    std::vector<std::byte> current_body = std::move(body);
    std::vector<std::string> visited;
    std::size_t redirects = 0;
    for (;;) {
        RedirectTarget current{current_scheme, current_host, current_port, current_target};
        if (std::find(visited.begin(), visited.end(), current.url()) != visited.end())
            co_return fail(Errc::limit_exceeded);
        visited.push_back(current.url());
        http::Request hop;
        hop.method = current_method;
        hop.target = current_target;
        hop.version = version;
        hop.headers = current_headers;
        auto lease = co_await client.acquire(current_host, current_port, io);
        if (!lease) co_return fail(lease.error());
        auto started = co_await lease->start(std::move(hop), current_body);
        if (!started) co_return fail(started.error());
        std::vector<std::byte> response_body;
        http::Response head;
        bool first = true;
        for (;;) {
            auto part = co_await lease->read_body();
            if (!part) co_return fail(part.error());
            if (first) {
                first = false;
                auto parsed = lease->response();
                if (!parsed) co_return fail(parsed.error());
                head = std::move(*parsed);
            }
            if (part->empty()) break;
            response_body.insert(response_body.end(), part->begin(), part->end());
        }
        // Best effort: a drained keep-alive session returns to the pool
        // for the next hop; failure just closes this connection.
        static_cast<void>(lease->recycle());
        const unsigned status = head.status;
        const bool is_redirect =
            status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
        auto location = head.headers.get("Location");
        if (!is_redirect || !location) {
            co_return RedirectResponse{status, head.headers, std::move(response_body), redirects,
                                       current_scheme, current_host, current_target, current_port,
                                       std::nullopt};
        }
        if (redirects >= options.max_redirects) co_return fail(Errc::limit_exceeded);
        auto next = resolve_redirect_location(current_scheme, current_host, current_port, current_target,
                                              *location);
        if (!next) co_return fail(next.error());
        if (next->scheme != current_scheme) {
            co_return RedirectResponse{status, head.headers, std::move(response_body), redirects,
                                       current_scheme, current_host, current_target, current_port,
                                       next->url()};
        }
        const auto method_change = next_redirect_method(status, current_method);
        const bool cross_origin = next->host != current_host || next->port != current_port;
        current_headers = detail::filtered_headers(current_headers, cross_origin, method_change.drop_body);
        current_method = method_change.method;
        if (method_change.drop_body) current_body.clear();
        current_host = next->host;
        current_port = next->port;
        current_target = next->target;
        ++redirects;
    }
}

}  // namespace Mira::client
