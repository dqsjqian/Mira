// HTTP/1.1 parser tests.
//
// Two halves, and the second one matters more.
//
// The positive half checks that well-formed messages parse — including when
// fed one byte at a time, because the network decides the slicing, not the
// sender.
//
// The negative half is the real product. Every case there is a published
// request-smuggling or header-injection vector: CL.TE conflicts, whitespace
// before a colon, obsolete line folding, `chunked` in a non-final position,
// disagreeing duplicate Content-Length. A parser that "handles" these by
// picking an interpretation is how a front-end and a back-end end up seeing
// two different requests in one byte stream.

#include "check.hpp"
#include "mira/core/buffer.hpp"
#include "mira/http/parser.hpp"

#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace Mira;
using namespace Mira::http;

namespace {

void feed(Buffer& buffer, std::string_view text) {
    buffer.append(
        std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()), text.size()});
}

/// Outcome of driving the parser to completion or failure.
struct Outcome {
    bool ok{false};
    Error error{};
    std::string body{};
    bool head_seen{false};
    bool complete{false};
};

/// Drive a parser over a buffer until it finishes, fails, or wants more.
Outcome drive(RequestParser& parser, Buffer& buffer) {
    Outcome outcome;
    for (int guard = 0; guard < 10000; ++guard) {
        const Result<ParseStep> step = parser.parse(buffer);
        if (!step) {
            outcome.error = step.error();
            return outcome;
        }
        switch (*step) {
        case ParseStep::need_more:
            // Run dry only counts as "waiting" while the message is unfinished;
            // a finished parser still owes one call to release its last slice.
            if (buffer.empty() && !parser.done()) {
                outcome.ok = true;
                return outcome;
            }
            break;
        case ParseStep::head:
            outcome.head_seen = true;
            break;
        case ParseStep::body: {
            const std::span<const std::byte> slice = parser.body();
            outcome.body.append(reinterpret_cast<const char*>(slice.data()), slice.size());
            break;
        }
        case ParseStep::complete:
            outcome.ok = true;
            outcome.complete = true;
            return outcome;
        }
    }
    outcome.error = make_error_code(ParseError::malformed_start_line);
    return outcome;
}

/// Parse a whole message from one string.
Outcome parse_all(std::string_view text, Limits limits = {}) {
    RequestParser parser{limits};
    Buffer buffer;
    feed(buffer, text);
    return drive(parser, buffer);
}

/// Parse the same message one byte at a time.
///
/// Any state the parser keeps across calls is exercised here; a parser that
/// only works on whole messages fails this and nothing else.
Outcome parse_byte_by_byte(std::string_view text, Limits limits = {}) {
    RequestParser parser{limits};
    Buffer buffer;
    Outcome outcome;

    for (const char c : text) {
        feed(buffer, std::string_view{&c, 1});
        for (;;) {
            const Result<ParseStep> step = parser.parse(buffer);
            if (!step) {
                outcome.error = step.error();
                return outcome;
            }
            if (*step == ParseStep::head) {
                outcome.head_seen = true;
                continue;
            }
            if (*step == ParseStep::body) {
                const std::span<const std::byte> slice = parser.body();
                outcome.body.append(reinterpret_cast<const char*>(slice.data()), slice.size());
                continue;
            }
            if (*step == ParseStep::complete) {
                outcome.ok = true;
                outcome.complete = true;
                return outcome;
            }
            break;  // need_more
        }
    }
    outcome.ok = true;
    return outcome;
}

// ── positive cases ───────────────────────────────────────────────────────────

void test_simple_request() {
    test::section("well-formed requests");

    RequestParser parser;
    Buffer buffer;
    feed(buffer, "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");

    const Outcome outcome = drive(parser, buffer);
    CHECK(outcome.ok);
    CHECK(outcome.complete);
    CHECK(parser.request().method == Method::get);
    CHECK(parser.request().target == "/index.html");
    CHECK(parser.request().version == Version::http_1_1);
    CHECK(parser.request().headers.size() == 1);
    CHECK(parser.request().headers.get("host").value_or("") == "example.com");
    CHECK(parser.request().body_kind == BodyKind::none);

    // Case-insensitive lookup, value whitespace trimmed.
    CHECK(parser.request().headers.get("HOST").has_value());
    CHECK(parser.request().headers.get("Missing").has_value() == false);
}

void test_content_length_body() {
    test::section("Content-Length body");

    const Outcome whole =
        parse_all("POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world");
    CHECK(whole.ok);
    CHECK(whole.complete);
    CHECK(whole.head_seen);
    CHECK(whole.body == "hello world");

    // Identical result when the network delivers it one byte at a time.
    const Outcome dripped = parse_byte_by_byte(
        "POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world");
    CHECK(dripped.ok);
    CHECK(dripped.complete);
    CHECK(dripped.body == "hello world");

    // Zero-length body completes immediately.
    const Outcome empty = parse_all("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    CHECK(empty.ok);
    CHECK(empty.complete);
    CHECK(empty.body.empty());
}

void test_chunked_body() {
    test::section("chunked body");

    const Outcome whole = parse_all("POST /upload HTTP/1.1\r\n"
                                    "Transfer-Encoding: chunked\r\n"
                                    "\r\n"
                                    "5\r\nhello\r\n"
                                    "6\r\n world\r\n"
                                    "0\r\n"
                                    "\r\n");
    CHECK(whole.ok);
    CHECK(whole.complete);
    CHECK(whole.body == "hello world");

    const Outcome dripped = parse_byte_by_byte("POST /upload HTTP/1.1\r\n"
                                               "Transfer-Encoding: chunked\r\n"
                                               "\r\n"
                                               "5\r\nhello\r\n"
                                               "6\r\n world\r\n"
                                               "0\r\n"
                                               "\r\n");
    CHECK(dripped.ok);
    CHECK(dripped.complete);
    CHECK(dripped.body == "hello world");

    // Chunk extensions are tolerated and ignored.
    const Outcome extended = parse_all("POST / HTTP/1.1\r\n"
                                       "Transfer-Encoding: chunked\r\n"
                                       "\r\n"
                                       "3;name=value\r\nabc\r\n"
                                       "0\r\n\r\n");
    CHECK(extended.ok);
    CHECK(extended.body == "abc");

    // Hex sizes are case-insensitive.
    const Outcome hex = parse_all("POST / HTTP/1.1\r\n"
                                  "Transfer-Encoding: chunked\r\n"
                                  "\r\n"
                                  "A\r\n0123456789\r\n"
                                  "0\r\n\r\n");
    CHECK(hex.ok);
    CHECK(hex.body == "0123456789");
}

void test_chunk_data_terminator() {
    test::section("chunk data terminator rejects invalid prefixes without waiting for LF");

    for (const bool bare_lf : {false, true}) {
        Limits limits;
        limits.allow_bare_lf = bare_lf;
        const std::vector<std::string> invalid{
            "X", "\rX", "\r\r", "X\r", std::string(65536, 'X')};
        for (const auto& suffix : invalid) {
            for (const bool split_cr : {false, true}) {
                RequestParser parser{limits};
                Buffer buffer;
                feed(buffer, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na");
                CHECK(parser.parse(buffer) == ParseStep::head);
                CHECK(parser.parse(buffer) == ParseStep::body);
                CHECK(parser.body().size() == 1);
                CHECK(parser.body().data() == buffer.readable().data());
                CHECK(buffer.size() == 1);
                CHECK(parser.body().front() == std::byte{'a'});
                CHECK(parser.parse(buffer) == ParseStep::need_more);
                CHECK(buffer.empty());
                if (split_cr) {
                    feed(buffer, "\r");
                    CHECK(parser.parse(buffer) == ParseStep::need_more);
                    CHECK(buffer.size() == 1);
                }
                feed(buffer, suffix);
                const auto step = parser.parse(buffer);
                CHECK(!step.has_value());
                if (!step) {
                    CHECK(step.error() == (split_cr || suffix.front() == '\r'
                                               ? ParseError::bad_line_ending
                                               : ParseError::malformed_chunk));
                }
            }
        }

        RequestParser parser{limits};
        Buffer buffer;
        feed(buffer, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na");
        CHECK(parser.parse(buffer) == ParseStep::head);
        CHECK(parser.parse(buffer) == ParseStep::body);
        CHECK(parser.body().front() == std::byte{'a'});
        CHECK(buffer.size() == 1);
        CHECK(parser.parse(buffer) == ParseStep::need_more);
        feed(buffer, "\r");
        CHECK(parser.parse(buffer) == ParseStep::need_more);
        CHECK(parser.parse(buffer) == ParseStep::need_more);
        CHECK(buffer.size() == 1);
        feed(buffer, "\n1\r\nb\r\n0\r\n\r\nGET /next HTTP/1.1\r\n\r\n");
        CHECK(parser.parse(buffer) == ParseStep::body);
        CHECK(parser.body().front() == std::byte{'b'});
        CHECK(parser.parse(buffer) == ParseStep::complete);
        parser.reset();
        CHECK(parser.parse(buffer) == ParseStep::head);
        CHECK(parser.request().target == "/next");
        CHECK(parser.parse(buffer) == ParseStep::complete);
        CHECK(buffer.empty());

        const auto lf = parse_byte_by_byte(
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\n0\r\n\r\n", limits);
        CHECK(lf.complete == bare_lf);
        CHECK(lf.body == "a");
        if (!bare_lf) CHECK(lf.error == ParseError::bad_line_ending);
    }
}

void test_chunked_trailers() {
    test::section("chunked trailers");

    RequestParser parser;
    Buffer buffer;
    feed(buffer,
         "POST / HTTP/1.1\r\n"
         "Transfer-Encoding: chunked\r\n"
         "\r\n"
         "4\r\ndata\r\n"
         "0\r\n"
         "X-Checksum: abc123\r\n"
         "\r\n");

    const Outcome outcome = drive(parser, buffer);
    CHECK(outcome.ok);
    CHECK(outcome.complete);
    CHECK(outcome.body == "data");
    CHECK(parser.trailers().size() == 1);
    CHECK(parser.trailers().get("x-checksum").value_or("") == "abc123");
}

void test_pipelining_and_reset() {
    test::section("pipelining");

    RequestParser parser;
    Buffer buffer;
    // Two requests in one buffer: the parser must leave the second alone.
    feed(buffer, "GET /first HTTP/1.1\r\nHost: a\r\n\r\nGET /second HTTP/1.1\r\nHost: b\r\n\r\n");

    const Outcome first = drive(parser, buffer);
    CHECK(first.ok);
    CHECK(first.complete);
    CHECK(parser.request().target == "/first");
    CHECK(!buffer.empty());  // second request still queued

    parser.reset();
    const Outcome second = drive(parser, buffer);
    CHECK(second.ok);
    CHECK(second.complete);
    CHECK(parser.request().target == "/second");
    CHECK(buffer.empty());
}

void test_methods_and_versions() {
    test::section("methods and versions");

    CHECK(parse_all("HEAD / HTTP/1.0\r\n\r\n").complete);
    CHECK(method_from_token("PATCH") == Method::patch);
    CHECK(method_from_token("get") == Method::other);  // case-sensitive
    CHECK(to_string(Method::delete_) == "DELETE");
    CHECK(to_string(Version::http_1_0) == "HTTP/1.0");

    // An extension method is preserved, not rejected: whether to allow it is
    // application policy.
    RequestParser parser;
    Buffer buffer;
    feed(buffer, "PROPFIND /dav HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK(drive(parser, buffer).complete);
    CHECK(parser.request().method == Method::other);

    CHECK(default_reason(404) == "Not Found");
    CHECK(default_reason(799).empty());
}

// ── negative cases: smuggling and injection vectors ──────────────────────────

void test_framing_conflict_rejected() {
    test::section("CL + TE conflict rejected");

    // The canonical CL.TE / TE.CL smuggling setup. Honouring either header
    // makes this parser disagree with some other parser in the chain, and the
    // gap between them is the attack.
    const Outcome both = parse_all("POST / HTTP/1.1\r\n"
                                   "Host: x\r\n"
                                   "Content-Length: 6\r\n"
                                   "Transfer-Encoding: chunked\r\n"
                                   "\r\n"
                                   "0\r\n\r\n");
    CHECK(!both.ok);
    CHECK(both.error == ParseError::framing_conflict);

    // Order must not matter.
    const Outcome reversed = parse_all("POST / HTTP/1.1\r\n"
                                       "Transfer-Encoding: chunked\r\n"
                                       "Content-Length: 6\r\n"
                                       "\r\n"
                                       "0\r\n\r\n");
    CHECK(!reversed.ok);
    CHECK(reversed.error == ParseError::framing_conflict);
}

void test_duplicate_content_length() {
    test::section("duplicate Content-Length");

    // Disagreeing duplicates are unanswerable.
    const Outcome conflicting = parse_all("POST / HTTP/1.1\r\n"
                                          "Content-Length: 5\r\n"
                                          "Content-Length: 6\r\n"
                                          "\r\nhello");
    CHECK(!conflicting.ok);
    CHECK(conflicting.error == ParseError::inconsistent_content_length);

    // A list inside one field is treated the same way.
    const Outcome list = parse_all("POST / HTTP/1.1\r\nContent-Length: 5, 6\r\n\r\nhello");
    CHECK(!list.ok);
    CHECK(list.error == ParseError::inconsistent_content_length);

    // Agreeing duplicates are acceptable (RFC 9110 §8.6).
    const Outcome agreeing =
        parse_all("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello");
    CHECK(agreeing.ok);
    CHECK(agreeing.body == "hello");
}

void test_malformed_content_length() {
    test::section("malformed Content-Length");

    // A sign, whitespace inside, hex, or an empty value would each make some
    // other parser compute a different length.
    for (const std::string_view value : {"+5", "-5", "5x", "0x5", "", " 5 5"}) {
        const std::string message =
            std::string{"POST / HTTP/1.1\r\nContent-Length: "} + std::string{value} + "\r\n\r\n";
        const Outcome outcome = parse_all(message);
        CHECK(!outcome.ok);
    }

    // Overflow must be rejected, not wrapped.
    const Outcome overflow =
        parse_all("POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n");
    CHECK(!overflow.ok);
    CHECK(overflow.error == ParseError::malformed_content_length);
}

void test_header_injection_vectors() {
    test::section("header injection vectors");

    // "Header : value" — a server MUST reject (RFC 9112 §5.1). Intermediaries
    // disagree about whether the name includes the trailing space.
    const Outcome space_before_colon =
        parse_all("GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\nhello");
    CHECK(!space_before_colon.ok);
    CHECK(space_before_colon.error == ParseError::whitespace_before_colon);

    // A field name must be a token; embedded space or control chars are out.
    CHECK(!parse_all("GET / HTTP/1.1\r\nBad Name: x\r\n\r\n").ok);
    CHECK(!parse_all("GET / HTTP/1.1\r\nBad\tName: x\r\n\r\n").ok);
    CHECK(!parse_all("GET / HTTP/1.1\r\n: empty\r\n\r\n").ok);

    // Obsolete line folding — rejected by default.
    const Outcome folded = parse_all("GET / HTTP/1.1\r\nHost: a\r\n  continued\r\n\r\n");
    CHECK(!folded.ok);
    CHECK(folded.error == ParseError::obsolete_line_folding);

    // ... and accepted only when explicitly opted into.
    Limits permissive;
    permissive.allow_obsolete_line_folding = true;
    CHECK(parse_all("GET / HTTP/1.1\r\nHost: a\r\n  continued\r\n\r\n", permissive).ok);
}

void test_line_ending_strictness() {
    test::section("line ending strictness");

    // A bare LF is refused by default: a front-end that accepts it while a
    // back-end does not is a smuggling differential.
    const Outcome bare_lf = parse_all("GET / HTTP/1.1\nHost: x\n\n");
    CHECK(!bare_lf.ok);
    CHECK(bare_lf.error == ParseError::bad_line_ending);

    // Opt in explicitly and it parses.
    Limits lenient;
    lenient.allow_bare_lf = true;
    CHECK(parse_all("GET / HTTP/1.1\nHost: x\n\n", lenient).complete);

    // A CR inside a line is injection regardless of policy.
    CHECK(!parse_all("GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n").ok);
    CHECK(!parse_all("GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n", lenient).ok);
}

void test_start_line_strictness() {
    test::section("start line strictness");

    CHECK(!parse_all("GET\r\n\r\n").ok);                   // no target or version
    CHECK(!parse_all("GET /\r\n\r\n").ok);                 // no version
    CHECK(!parse_all("GET  / HTTP/1.1\r\n\r\n").ok);       // double space
    CHECK(!parse_all("GET /  HTTP/1.1\r\n\r\n").ok);       // double space
    CHECK(!parse_all(" GET / HTTP/1.1\r\n\r\n").ok);       // leading space
    CHECK(!parse_all("GET / HTTP/1.1 extra\r\n\r\n").ok);  // trailing junk
    CHECK(!parse_all("GE T / HTTP/1.1\r\n\r\n").ok);       // space in method

    // Versions this parser does not speak must be refused, not guessed at.
    const Outcome old_version = parse_all("GET / HTTP/0.9\r\n\r\n");
    CHECK(!old_version.ok);
    CHECK(old_version.error == ParseError::unsupported_version);
    CHECK(!parse_all("GET / HTTP/2.0\r\n\r\n").ok);
    CHECK(!parse_all("GET / HTTP/1.2\r\n\r\n").ok);
}

void test_transfer_encoding_strictness() {
    test::section("Transfer-Encoding strictness");

    // `chunked` must be the final coding (RFC 9112 §6.3).
    const Outcome not_last = parse_all("POST / HTTP/1.1\r\n"
                                       "Transfer-Encoding: chunked, gzip\r\n"
                                       "\r\n0\r\n\r\n");
    CHECK(!not_last.ok);
    CHECK(not_last.error == ParseError::invalid_transfer_encoding);

    // Repeated `chunked` leaves the length undeterminable.
    CHECK(!parse_all("POST / HTTP/1.1\r\n"
                     "Transfer-Encoding: chunked\r\n"
                     "Transfer-Encoding: chunked\r\n"
                     "\r\n0\r\n\r\n")
               .ok);

    // A coding this parser does not apply is refused rather than passed
    // through as if it were plaintext.
    CHECK(!parse_all("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n").ok);

    // An empty Transfer-Encoding is malformed.
    CHECK(!parse_all("POST / HTTP/1.1\r\nTransfer-Encoding: \r\n\r\n").ok);
}

void test_malformed_chunks() {
    test::section("malformed chunks");

    const auto chunked = [](std::string_view body) {
        return std::string{"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"} +
               std::string{body};
    };

    CHECK(!parse_all(chunked("zz\r\nab\r\n0\r\n\r\n")).ok);      // non-hex size
    CHECK(!parse_all(chunked("-1\r\nab\r\n0\r\n\r\n")).ok);      // signed size
    CHECK(!parse_all(chunked(" 5\r\nhello\r\n0\r\n\r\n")).ok);   // leading space
    CHECK(!parse_all(chunked("5\r\nhelloXX\r\n0\r\n\r\n")).ok);  // data not followed by CRLF

    // Size overflow must be rejected, not wrapped.
    CHECK(!parse_all(chunked("FFFFFFFFFFFFFFFFFF\r\n")).ok);
}

void test_limits_enforced() {
    test::section("limits enforced");

    Limits tight;
    tight.max_header_count = 2;
    tight.max_body_size = 8;
    tight.max_start_line = 40;
    tight.max_chunk_size = 4;

    // Too many headers.
    const Outcome too_many = parse_all("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n", tight);
    CHECK(!too_many.ok);
    CHECK(too_many.error == ParseError::limit_exceeded);

    // Declared body larger than allowed is refused up front, before a single
    // body byte is buffered.
    const Outcome too_big = parse_all("POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\n", tight);
    CHECK(!too_big.ok);
    CHECK(too_big.error == ParseError::limit_exceeded);

    // Over-long start line.
    const Outcome long_line =
        parse_all("GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n\r\n", tight);
    CHECK(!long_line.ok);
    CHECK(long_line.error == ParseError::limit_exceeded);

    // An over-sized chunk is refused at its header.
    const Outcome big_chunk =
        parse_all("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n", tight);
    CHECK(!big_chunk.ok);
    CHECK(big_chunk.error == ParseError::limit_exceeded);

    // An unterminated start line must not buffer without bound.
    RequestParser parser{tight};
    Buffer buffer;
    feed(buffer, std::string(200, 'x'));
    const Result<ParseStep> step = parser.parse(buffer);
    CHECK(!step.has_value());
    CHECK(step.error() == ParseError::limit_exceeded);
}

void test_error_reporting() {
    test::section("error reporting");

    // Protocol errors carry their own category, so a log line names the actual
    // violation instead of just "400".
    const Error error = make_error_code(ParseError::framing_conflict);
    CHECK(error.category() == parse_category());
    CHECK(std::string_view{error.category().name()} == "Mira.http");
    CHECK(error.message() == "Content-Length conflicts with Transfer-Encoding");

    // Implicit conversion through is_error_code_enum.
    const Error implicit = ParseError::malformed_chunk;
    CHECK(implicit == ParseError::malformed_chunk);

    // Distinct from transport errors.
    CHECK(make_error_code(ParseError::limit_exceeded) != make_error_code(Errc::limit_exceeded));
}

}  // namespace

int main() {
    test_simple_request();
    test_content_length_body();
    test_chunked_body();
    test_chunk_data_terminator();
    test_chunked_trailers();
    test_pipelining_and_reset();
    test_methods_and_versions();

    test_framing_conflict_rejected();
    test_duplicate_content_length();
    test_malformed_content_length();
    test_header_injection_vectors();
    test_line_ending_strictness();
    test_start_line_strictness();
    test_transfer_encoding_strictness();
    test_malformed_chunks();
    test_limits_enforced();
    test_error_reporting();

    return test::summary();
}
