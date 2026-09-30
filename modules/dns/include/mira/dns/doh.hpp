#pragma once

// Mira/dns/doh.hpp — DNS over HTTPS (RFC 8484) request/response mapping.
//
// Transport-agnostic helpers build and validate the HTTP side (GET with a
// base64url `dns` parameter, or POST with an application/dns-message body);
// `query` runs one exchange over an HTTP/1 `ClientConnection`, which may sit on
// TLS. HTTP/2 and HTTP/3 callers use make_get/make_post/parse_response with
// `Mira::http2` / `Mira::http3` streams. Queries use id 0 (RFC 8484 §4.1).
//
// DoH over plain HTTP is supported for tests and trusted links only; RFC 8484
// requires HTTPS. Certificate policy is the TLS layer's.

#include "mira/core/operation.hpp"
#include "mira/core/stream.hpp"
#include "mira/dns/message.hpp"
#include "mira/http/client.hpp"
#include "mira/http/message.hpp"

#include <cstddef>
#include <algorithm>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Mira::dns::doh {

inline constexpr std::string_view media_type = "application/dns-message";

[[nodiscard]] std::string base64url_encode(std::span<const std::byte> data);
/// Strict: unpadded, alphabet `A-Za-z0-9-_`, zero trailing bits.
[[nodiscard]] Result<std::vector<std::byte>> base64url_decode(std::string_view text);

/// GET `path?dns=<base64url>` (appends with `&` when path already has a query).
[[nodiscard]] Result<http::Request> make_get(std::string_view authority, std::string_view path,
                                             std::span<const std::byte> query);
/// POST head; send the encoded query as the body.
[[nodiscard]] Result<http::Request> make_post(std::string_view authority, std::string_view path);

/// 2xx, application/dns-message, bounded body, then decode. Record TTLs are
/// reduced by the HTTP Age field (saturating at zero) before being returned.
[[nodiscard]] Result<Message> parse_response(const http::Response& response,
                                             std::span<const std::byte> body,
                                             const Limits& limits = {});

/// Server side: extract the wire query from GET (`dns` parameter, exactly
/// once, no percent-encoding) or POST (application/dns-message body).
[[nodiscard]] Result<std::vector<std::byte>> decode_request(const http::Request& request,
                                                            std::span<const std::byte> body,
                                                            const Limits& limits = {});
/// HTTP status for a decode_request failure: 405, 413, 415 or 400.
[[nodiscard]] unsigned http_status(std::error_code error) noexcept;

enum class Method { get, post };

/// One DoH exchange over a borrowed HTTP/1 connection. The query is re-encoded
/// with id 0; the response must answer it (question section and id). The
/// response body is drained, so the connection stays reusable when allowed.
template<BoundedStream Stream>
[[nodiscard]] Task<Result<Message>> query(http::ClientConnection<Stream>& connection,
                                          std::string_view authority, std::string_view path,
                                          Message question, Method method = Method::get,
                                          OperationOptions io = {}, Limits limits = {}) {
    limits.max_message_size = (std::min)(limits.max_message_size, std::size_t{65535});
    question.header.id = 0;
    auto wire = encode(question);
    if (!wire) co_return fail(wire.error());
    auto request = method == Method::get ? make_get(authority, path, *wire) : make_post(authority, path);
    if (!request) co_return fail(request.error());
    const std::span<const std::byte> body =
        method == Method::post ? std::span<const std::byte>{*wire} : std::span<const std::byte>{};
    auto started = co_await connection.start(*request, body, io);
    if (!started) co_return fail(started.error());
    // HTTP guards cover its own operations, but collecting a body or creating
    // the next read task can throw between them. End the idle exchange on all
    // such exits so the borrowed connection remains safe to destroy.
    struct ResponseGuard {
        http::ClientConnection<Stream>& connection;
        bool drained = false;
        ~ResponseGuard() noexcept {
            if (!drained) static_cast<void>(connection.abandon());
        }
    } guard{connection};
    std::vector<std::byte> received;
    for (;;) {
        auto chunk = co_await connection.read_body();
        if (!chunk) co_return fail(chunk.error());
        if (chunk->empty()) {
            guard.drained = true;
            break;
        }
        if (chunk->size() > limits.max_message_size - received.size()) {
            co_return fail(DnsError::too_large);
        }
        received.insert(received.end(), chunk->begin(), chunk->end());
    }
    auto response = parse_response(connection.response(), received, limits);
    if (!response) co_return fail(response.error());
    if (!answers(question, *response)) co_return fail(DnsError::mismatched_response);
    co_return std::move(*response);
}

}  // namespace Mira::dns::doh
