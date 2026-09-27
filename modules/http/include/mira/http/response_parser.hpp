#pragma once

#include "mira/http/parser.hpp"

namespace Mira::http {

/// Standalone incremental response parser. Each 1xx is itself a complete
/// message; parsing of the final response continues only after a reset.
/// 101 and a 2xx to CONNECT return not_supported, without consuming tunnel bytes.
/// Strictly rejects obs-fold (even when the Limits compatibility switch is on),
/// non-chunked transfer encodings, and ambiguous framing.
/// The header count/total from limits is shared between headers and trailers.
class ResponseParser {
public:
    explicit ResponseParser(Method method = Method::get, Limits limits = {}) noexcept
        : limits_(limits), method_(method) {}

    /// eof=true means no more bytes follow the input. A premature EOF on
    /// fixed-length/chunked returns Errc::eof.
    [[nodiscard]] Result<ParseStep> parse(Buffer& input, bool eof = false);
    /// Reset only after complete has been fully consumed. Do not modify input
    /// while a body span is still in use.
    void reset(Method method = Method::get);
    [[nodiscard]] const Response& response() const noexcept { return response_; }
    /// Points into input; valid until the next parse/reset or until the caller
    /// modifies input.
    [[nodiscard]] std::span<const std::byte> body() const noexcept { return body_; }
    [[nodiscard]] const HeaderMap& trailers() const noexcept { return trailers_; }
    [[nodiscard]] std::uint64_t body_bytes_seen() const noexcept { return seen_; }
    [[nodiscard]] bool done() const noexcept { return state_ == State::done && pending_ == 0; }

private:
    enum class State {
        start,
        headers,
        length,
        chunk_size,
        chunk_data,
        chunk_end,
        trailers,
        eof_body,
        done
    };
    [[nodiscard]] Result<ParseStep> advance(Buffer& input, bool eof);
    [[nodiscard]] Result<void> framing();
    [[nodiscard]] Result<void> field(std::string_view text, bool trailer);
    Limits limits_;
    Method method_;
    State state_{State::start};
    Response response_{};
    HeaderMap trailers_{};
    std::span<const std::byte> body_{};
    std::uint64_t seen_{0};
    std::uint64_t remaining_{0};
    std::size_t pending_{0};
    std::size_t header_bytes_{0};
    Error error_{};
};

}  // namespace Mira::http
