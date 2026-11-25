#pragma once

// Mira/http/parser.hpp — incremental HTTP/1.1 message parsing.
//
// Two properties drive the whole design.
//
// **Incremental.** Bytes arrive in whatever slices the network produces. The
// parser is fed a `Buffer`, consumes what it can, and says what it needs next.
// A message split across a hundred reads parses identically to one that
// arrives whole — the tests assert exactly that, byte by byte.
//
// **Strict.** The value of a protocol parser is concentrated in its negative
// space: the completeness with which it rejects. This one does not guess.
// A `Content-Length` that contradicts a `Transfer-Encoding` is an error, not a
// heuristic; whitespace before a header colon is an error; obsolete line
// folding is an error. Every one of those is a documented request-smuggling
// vector, and every one of them exists because two parsers disagreed.
//
// Usage:
//
//     RequestParser parser;
//     for (;;) {
//         Result<ParseStep> step = parser.parse(buffer);
//         if (!step) { /* protocol error — close the connection */ }
//         switch (*step) {
//         case ParseStep::need_more:  // read more bytes into `buffer`
//         case ParseStep::head:       // parser.request() is ready to route
//         case ParseStep::body:       // parser.body() holds the next slice
//         case ParseStep::complete:   // message finished
//         }
//     }

#include "mira/core/buffer.hpp"
#include "mira/core/error.hpp"
#include "mira/http/limits.hpp"
#include "mira/http/message.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace Mira::http {

/// What the parser did, and what it wants next.
enum class ParseStep {
    /// Genuinely out of bytes: read more from the stream and call again.
    ///
    /// This means *only* that. The parser advances its own state machine
    /// internally, so receiving `need_more` while the buffer still holds a
    /// complete message is not possible.
    need_more,
    /// Start line and headers are parsed; the head is ready to inspect.
    head,
    /// A body slice is available from `body()`, valid until the next call.
    body,
    /// The message is complete. Call `reset()` before the next one.
    complete,
};

/// HTTP-specific failure conditions.
///
/// These are *protocol* errors, distinct from the transport errors in
/// `Mira::Errc`. They exist as named values because "400 Bad Request" is
/// not a diagnosis — a log line that says `framing_conflict` tells an operator
/// what a peer actually did.
enum class ParseError {
    malformed_start_line = 1,
    unsupported_version,
    malformed_header,
    /// Whitespace between a header name and its colon (smuggling vector).
    whitespace_before_colon,
    /// Obsolete line folding, rejected unless explicitly allowed.
    obsolete_line_folding,
    /// Both `Content-Length` and `Transfer-Encoding` present.
    framing_conflict,
    /// Repeated `Content-Length` values that disagree.
    inconsistent_content_length,
    malformed_content_length,
    /// `chunked` present but not the final coding, or an unknown coding.
    invalid_transfer_encoding,
    malformed_chunk,
    /// A line ended with a lone CR, or a bare LF where CRLF is required.
    bad_line_ending,
    limit_exceeded,
};

/// Error category for `ParseError`.
[[nodiscard]] const std::error_category& parse_category() noexcept;

[[nodiscard]] std::error_code make_error_code(ParseError error) noexcept;

/// Incremental parser for HTTP/1.1 requests.
class RequestParser {
public:
    RequestParser() = default;
    explicit RequestParser(Limits limits) noexcept : limits_(limits) {}

    /// Consume bytes from `input` and report progress.
    ///
    /// Consumed bytes are removed from `input`; bytes belonging to the next
    /// message are left in place, so a pipelined connection works by calling
    /// `reset()` and parsing again.
    [[nodiscard]] Result<ParseStep> parse(Buffer& input);

    /// The parsed head. Meaningful once `parse` has returned `head`.
    [[nodiscard]] const Request& request() const noexcept { return request_; }

    /// The most recent body slice.
    ///
    /// Points into the caller's buffer and stays valid until the next `parse`
    /// call — those bytes are deliberately left in the buffer and consumed at
    /// the start of the following call, so the slice cannot dangle while the
    /// caller is still reading it. Copy it if it must outlive that.
    ///
    /// Consequence worth knowing: keep calling `parse` until it reports
    /// `complete`. Stopping at the last `body` step leaves those bytes
    /// unconsumed, which matters on a pipelined connection.
    [[nodiscard]] std::span<const std::byte> body() const noexcept { return body_; }

    /// Total body bytes emitted for the current message.
    [[nodiscard]] std::uint64_t body_bytes_seen() const noexcept { return body_seen_; }

    /// Trailer fields from a chunked body; empty until `complete`.
    [[nodiscard]] const HeaderMap& trailers() const noexcept { return trailers_; }

    /// True once the current message is fully parsed.
    [[nodiscard]] bool done() const noexcept { return state_ == State::done; }

    /// Prepare for the next message on the same connection.
    void reset();

    [[nodiscard]] const Limits& limits() const noexcept { return limits_; }

private:
    enum class State {
        start_line,
        after_leading_crlf,
        headers,
        body_length,
        body_chunk_header,
        body_chunk_data,
        body_chunk_trailer,
        done,
    };

    /// Outcome of one internal state-machine step.
    ///
    /// Distinct from `ParseStep` on purpose: `advanced` means "state moved,
    /// keep going without reading", which the public API deliberately does not
    /// expose. Conflating it with `need_more` is what made callers read on a
    /// buffer that already held a complete request.
    enum class Progress {
        need_data,
        advanced,
        emitted_body,
        finished,
    };

    /// Parse the request line. Returns false when more bytes are needed.
    [[nodiscard]] Result<bool> parse_start_line(Buffer& input);
    [[nodiscard]] Result<bool> parse_headers(Buffer& input);
    [[nodiscard]] Result<void> decide_framing();
    [[nodiscard]] Result<ParseStep> read_length_body(Buffer& input);
    [[nodiscard]] Result<Progress> read_chunk_header(Buffer& input);
    [[nodiscard]] Result<Progress> read_chunk_data(Buffer& input);
    [[nodiscard]] Result<Progress> read_chunk_trailer(Buffer& input);

    Limits limits_{};
    State state_{State::start_line};
    Request request_{};
    HeaderMap trailers_{};

    std::span<const std::byte> body_{};
    std::uint64_t body_seen_{0};
    std::uint64_t body_remaining_{0};
    std::uint64_t chunk_remaining_{0};
    std::size_t headers_total_{0};
    /// Body bytes handed to the caller but not yet removed from the buffer.
    std::size_t pending_consume_{0};
    bool saw_last_chunk_{false};
};

}  // namespace Mira::http

namespace std {
template<>
struct is_error_code_enum<Mira::http::ParseError> : true_type {};
}  // namespace std
