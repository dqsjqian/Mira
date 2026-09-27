#include "mira/http/response_parser.hpp"

#include "mira/http/serializer.hpp"
#include "grammar.hpp"

#include <algorithm>
#include <charconv>

namespace Mira::http {
namespace {
struct Line {
    std::string_view text;
    std::size_t consumed;
};
Result<std::optional<Line>> line(Buffer& input, std::size_t limit, bool bare_lf) {
    const auto bytes = input.readable();
    const std::string_view text{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    const auto lf = text.find('\n');
    if (lf == std::string_view::npos) {
        // Allow a CR sitting exactly at the boundary to wait for the next LF.
        const auto size = text.size() - (!text.empty() && text.back() == '\r' ? 1u : 0u);
        if (size > limit) return fail(ParseError::limit_exceeded);
        return std::optional<Line>{};
    }
    const bool cr = lf > 0 && text[lf - 1] == '\r';
    if (!cr && !bare_lf) return fail(ParseError::bad_line_ending);
    const auto content = text.substr(0, lf - (cr ? 1u : 0u));
    if (content.find('\r') != std::string_view::npos) return fail(ParseError::bad_line_ending);
    if (content.size() > limit) return fail(ParseError::limit_exceeded);
    return std::optional<Line>{Line{content, lf + 1}};
}
std::optional<std::uint64_t> number(std::string_view value, int base) {
    if (value.empty()) return {};
    std::uint64_t result{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result, base);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) return {};
    return result;
}
}  // namespace

void ResponseParser::reset(Method method) {
    *this = ResponseParser{method, limits_};
}

Result<void> ResponseParser::field(std::string_view text, bool trailer) {
    if (grammar::is_ows(text.front())) return fail(ParseError::obsolete_line_folding);
    const auto colon = text.find(':');
    if (colon == 0 || colon == std::string_view::npos) return fail(ParseError::malformed_header);
    const auto name = text.substr(0, colon);
    if (grammar::is_ows(name.back())) return fail(ParseError::whitespace_before_colon);
    for (char c : name) {
        if (!grammar::is_tchar(static_cast<unsigned char>(c)))
            return fail(ParseError::malformed_header);
    }
    const auto value = grammar::trim_ows(text.substr(colon + 1));
    for (char c : value) {
        if (!grammar::is_field_vchar(static_cast<unsigned char>(c)))
            return fail(ParseError::malformed_header);
    }
    if (trailer &&
        (HeaderMap::names_equal(name, "Content-Length") ||
         HeaderMap::names_equal(name, "Transfer-Encoding") ||
         HeaderMap::names_equal(name, "Host") || HeaderMap::names_equal(name, "Connection") ||
         HeaderMap::names_equal(name, "Trailer")))
        return fail(ParseError::framing_conflict);
    if (response_.headers.size() + trailers_.size() >= limits_.max_header_count ||
        text.size() > limits_.max_headers_total - header_bytes_)
        return fail(ParseError::limit_exceeded);
    header_bytes_ += text.size();
    (trailer ? trailers_ : response_.headers).append(std::string{name}, std::string{value});
    return {};
}

Result<void> ResponseParser::framing() {
    const auto& headers = response_.headers;
    const bool te = headers.contains("Transfer-Encoding");
    const bool cl = headers.contains("Content-Length");
    if (te && cl) return fail(ParseError::framing_conflict);
    if (response_.status == 101 ||
        (method_ == Method::connect && response_.status >= 200 && response_.status < 300)) {
        return fail(Errc::not_supported);
    }
    std::optional<std::uint64_t> length;
    if (cl) {
        for (auto value : headers.get_all("Content-Length")) {
            // Empty list items are not tolerated, to avoid parsers
            // disagreeing on framing.
            for (;;) {
                const auto comma = value.find(',');
                const auto n = number(grammar::trim_ows(value.substr(0, comma)), 10);
                if (!n) return fail(ParseError::malformed_content_length);
                if (length && *length != *n) return fail(ParseError::inconsistent_content_length);
                length = *n;
                if (comma == std::string_view::npos) break;
                value.remove_prefix(comma + 1);
            }
        }
    }
    if (te && (response_.version == Version::http_1_0 || headers.count("Transfer-Encoding") != 1 ||
               !HeaderMap::names_equal(*headers.get("Transfer-Encoding"), "chunked"))) {
        return fail(ParseError::invalid_transfer_encoding);
    }
    if ((response_.status < 200 || response_.status == 204) && (te || cl)) {
        return fail(ParseError::framing_conflict);
    }
    if (length) response_.content_length = *length;
    if (method_ == Method::head || status_forbids_body(response_.status)) {
        response_.body_kind = BodyKind::none;
        state_ = State::done;
    } else if (te) {
        response_.body_kind = BodyKind::chunked;
        state_ = State::chunk_size;
    } else if (length) {
        if (*length > limits_.max_body_size) return fail(ParseError::limit_exceeded);
        response_.body_kind = BodyKind::length;
        remaining_ = *length;
        state_ = remaining_ ? State::length : State::done;
    } else {
        response_.body_kind = BodyKind::close_delimited;
        state_ = State::eof_body;
    }
    return {};
}

Result<ParseStep> ResponseParser::parse(Buffer& input, bool eof) {
    if (error_) return fail(error_);
    if (pending_) {
        input.consume(pending_);
        pending_ = 0;
    }
    body_ = {};
    auto result = advance(input, eof);
    if (!result) error_ = result.error();
    return result;
}

Result<ParseStep> ResponseParser::advance(Buffer& input, bool eof) {
    for (;;) {
        if (state_ == State::done) return ParseStep::complete;
        if (state_ == State::length || state_ == State::chunk_data || state_ == State::eof_body) {
            if (input.empty()) {
                if (eof && state_ == State::eof_body) {
                    state_ = State::done;
                    return ParseStep::complete;
                }
                if (eof) return fail(Errc::eof);
                return ParseStep::need_more;
            }
            const auto count =
                state_ == State::eof_body
                    ? input.size()
                    : static_cast<std::size_t>(std::min<std::uint64_t>(remaining_, input.size()));
            if (count > limits_.max_body_size - seen_) return fail(ParseError::limit_exceeded);
            body_ = input.readable().first(count);
            pending_ = count;
            seen_ += count;
            if (state_ != State::eof_body) {
                remaining_ -= count;
                if (remaining_ == 0)
                    state_ = state_ == State::length ? State::done : State::chunk_end;
            }
            return ParseStep::body;
        }
        std::size_t cap = limits_.max_header_line;
        if (state_ == State::start) cap = limits_.max_start_line;
        if (state_ == State::chunk_size) {
            cap = limits_.max_chunk_extension > SIZE_MAX - 32 ? SIZE_MAX
                                                              : limits_.max_chunk_extension + 32;
        }
        if (state_ == State::chunk_end) cap = 0;
        auto found = line(input, cap, limits_.allow_bare_lf);
        if (!found) return fail(found.error());
        if (!*found) {
            if (eof) return fail(Errc::eof);
            return ParseStep::need_more;
        }
        const auto text = (**found).text;
        const auto consumed = (**found).consumed;
        switch (state_) {
        case State::start: {
            if (text.size() < 13 || text[8] != ' ' || text[12] != ' ')
                return fail(ParseError::malformed_start_line);
            const auto version = text.substr(0, 8);
            if (version == "HTTP/1.1")
                response_.version = Version::http_1_1;
            else if (version == "HTTP/1.0")
                response_.version = Version::http_1_0;
            else
                return fail(ParseError::unsupported_version);
            const auto status = number(text.substr(9, 3), 10);
            if (!status || *status < 100 || *status > 599)
                return fail(ParseError::malformed_start_line);
            for (char c : text.substr(13)) {
                if (!grammar::is_field_vchar(static_cast<unsigned char>(c)))
                    return fail(ParseError::malformed_start_line);
            }
            response_.status = static_cast<unsigned>(*status);
            response_.reason.assign(text.substr(13));
            state_ = State::headers;
            break;
        }
        case State::headers:
        case State::trailers:
            if (text.empty()) {
                const bool trailer = state_ == State::trailers;
                input.consume(consumed);
                if (trailer) {
                    state_ = State::done;
                    return ParseStep::complete;
                }
                auto result = framing();
                if (!result) return fail(result.error());
                return ParseStep::head;
            } else {
                auto result = field(text, state_ == State::trailers);
                if (!result) return fail(result.error());
            }
            break;
        case State::chunk_size: {
            const auto semicolon = text.find(';');
            const auto n = number(text.substr(0, semicolon), 16);
            if (!n) return fail(ParseError::malformed_chunk);
            if (semicolon != std::string_view::npos) {
                const auto ext = text.substr(semicolon + 1);
                if (ext.size() > limits_.max_chunk_extension)
                    return fail(ParseError::limit_exceeded);
                for (char c : ext) {
                    if (!grammar::is_field_vchar(static_cast<unsigned char>(c)))
                        return fail(ParseError::malformed_chunk);
                }
            }
            if (*n > limits_.max_chunk_size || *n > limits_.max_body_size - seen_)
                return fail(ParseError::limit_exceeded);
            remaining_ = *n;
            state_ = *n ? State::chunk_data : State::trailers;
            break;
        }
        case State::chunk_end:
            state_ = State::chunk_size;
            break;
        default:
            return fail(Errc::invalid_argument);
        }
        input.consume(consumed);
    }
}

}  // namespace Mira::http
