#pragma once

// Mira/http/serializer.hpp — turning a response into bytes.
//
// Serialisation is where a server leaks information and breaks framing, so the
// rules are enforced here rather than trusted to callers:
//
//   * A response must have exactly one framing header. `Content-Length` and
//     `Transfer-Encoding` together is the same ambiguity the parser rejects on
//     the way in, and a server that emits it is the *cause* of a smuggling
//     chain rather than a victim.
//   * Header values are validated. A value containing CR or LF would inject a
//     header — or an entire response — into the byte stream, which is how
//     "response splitting" works.
//   * 1xx, 204 and 304 carry no body by definition, so no framing header is
//     written for them regardless of what the caller set.
//
// Writing to a `Buffer` rather than straight to a socket keeps this layer
// synchronous and testable: the bytes can be asserted against a string.

#include "mira/core/buffer.hpp"
#include "mira/core/error.hpp"
#include "mira/http/message.hpp"
#include "mira/http/limits.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace Mira::http {

/// How the body of an outgoing response is framed.
enum class Framing {
    /// `Content-Length: n`. Requires knowing the size up front.
    content_length,
    /// `Transfer-Encoding: chunked`. For bodies of unknown size.
    chunked,
    /// No body at all (1xx / 204 / 304, or a HEAD response).
    none,
};

/// Failure conditions specific to writing a response.
enum class SerializeError {
    /// A header name or value contains bytes that would inject a new header.
    invalid_header = 1,
    /// The caller supplied conflicting framing headers.
    framing_conflict,
    /// A status code outside 100..999.
    invalid_status,
};

[[nodiscard]] const std::error_category& serialize_category() noexcept;
[[nodiscard]] std::error_code make_error_code(SerializeError error) noexcept;

/// Write a response head into `out`.
///
/// Framing headers are written by this function according to `framing`; any
/// `Content-Length` or `Transfer-Encoding` the caller put in `response.headers`
/// is rejected rather than silently dropped, because silently dropping one
/// would make the wire disagree with the caller's intent.
///
/// `body_size` is used only when `framing == content_length`.
[[nodiscard]] Result<void> write_response_head(Buffer& out,
                                               const Response& response,
                                               Framing framing,
                                               std::uint64_t body_size = 0);

/// Requests support only origin-form and OPTIONS *; proxy absolute-form,
/// CONNECT, Upgrade, and Expect are not supported.
/// HTTP/1.1 requires exactly one valid Host; framing is owned entirely by
/// the serializer.
[[nodiscard]] Result<void> write_request_head(Buffer& out, const Request& request,
                                              std::uint64_t body_size = 0,
                                              Limits limits = {});
[[nodiscard]] Result<void> write_request_head(Buffer& out, const Request& request,
                                              Framing framing, std::uint64_t body_size = 0,
                                              Limits limits = {});

/// Write one chunk of a chunked body, including its size line and trailing CRLF.
///
/// A zero-length span would encode the terminating chunk and end the message
/// prematurely, so it is rejected — use `write_last_chunk` for that.
[[nodiscard]] Result<void> write_chunk(Buffer& out, std::span<const std::byte> chunk);

/// Write the terminating zero-length chunk and the (empty) trailer section.
void write_last_chunk(Buffer& out);

/// Whether the connection should stay open after this exchange.
///
/// Follows RFC 9112 §9.3: HTTP/1.1 keeps the connection unless asked to close;
/// HTTP/1.0 closes unless explicitly asked to keep it.
[[nodiscard]] bool should_keep_alive(const Request& request) noexcept;

/// Whether a status code forbids a body regardless of what the handler wants.
[[nodiscard]] bool status_forbids_body(unsigned status) noexcept;

}  // namespace Mira::http

namespace std {
template<>
struct is_error_code_enum<Mira::http::SerializeError> : true_type {};
}  // namespace std
