#include "check.hpp"
#include "mira/http/response_parser.hpp"
#include "mira/http/serializer.hpp"

#include <string>
#include <vector>

#define CHECK_VALUE(expr) CHECK(static_cast<bool>(expr))

using namespace Mira;
using namespace Mira::http;

namespace {
std::span<const std::byte> bytes(std::string_view text) {
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}
std::string text(std::span<const std::byte> data) {
    return {reinterpret_cast<const char*>(data.data()), data.size()};
}
struct Parsed {
    Response response;
    HeaderMap trailers;
    std::string body;
    Error error;
    bool done{false};
};
Parsed parse(std::string_view wire,
             std::size_t fragment = SIZE_MAX,
             Method method = Method::get,
             Limits limits = {}) {
    ResponseParser parser{method, limits};
    Buffer input;
    Parsed result;
    std::size_t offset = 0;
    for (;;) {
        auto step = parser.parse(input, offset == wire.size());
        if (!step) {
            result.error = step.error();
            return result;
        }
        if (*step == ParseStep::need_more) {
            const auto n = std::min(fragment, wire.size() - offset);
            input.append(bytes(wire.substr(offset, n)));
            offset += n;
        } else if (*step == ParseStep::head)
            result.response = parser.response();
        else if (*step == ParseStep::body)
            result.body += text(parser.body());
        else {
            result.trailers = parser.trailers();
            result.done = true;
            return result;
        }
    }
}
void test_incremental() {
    test::section("response incremental framing and span lifetime");
    const std::vector<std::string> messages{
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: "
        "chunked\r\n\r\n2;x=y\r\nab\r\n4\r\ncdef\r\n0\r\nX-End: yes\r\n\r\n",
        "HTTP/1.0 200 OK\r\n\r\nabcdef"};
    for (const auto& wire : messages) {
        for (std::size_t fragment = 1; fragment <= wire.size(); ++fragment) {
            const auto result = parse(wire, fragment);
            CHECK_VALUE(!result.error);
            CHECK_VALUE(result.done);
            CHECK_VALUE(result.body == "abcdef");
        }
    }
    ResponseParser parser;
    Buffer input;
    input.append(bytes(messages[0] + "HTTP/1.1 204 No Content\r\n\r\n"));
    CHECK_VALUE(parser.parse(input) == ParseStep::head);
    CHECK_VALUE(parser.parse(input) == ParseStep::body);
    CHECK_VALUE(text(parser.body()) == "abcdef");
    CHECK_VALUE(input.size() > 6);
    CHECK_VALUE(parser.body().data() == input.readable().data());
    CHECK_VALUE(!parser.done());
    CHECK_VALUE(parser.parse(input) == ParseStep::complete);
    CHECK_VALUE(parser.done());
    parser.reset();
    CHECK_VALUE(parser.parse(input) == ParseStep::head);
    CHECK_VALUE(parser.response().status == 204);
    CHECK_VALUE(parser.parse(input) == ParseStep::complete);
    CHECK_VALUE(input.empty());

    Buffer exact;
    exact.append(bytes(messages[0]));
    parser.reset();
    CHECK_VALUE(parser.parse(exact) == ParseStep::head);
    CHECK_VALUE(parser.parse(exact) == ParseStep::body);
    CHECK_VALUE(text(parser.body()) == "abcdef");  // ASan check: the underlying vector must not be cleared early.
    CHECK_VALUE(exact.size() == 6);
    CHECK_VALUE(parser.parse(exact) == ParseStep::complete);
    CHECK_VALUE(exact.empty());
}
void test_chunk_data_terminator() {
    test::section("response chunk terminator rejects invalid prefixes without waiting for LF");
    for (const bool bare_lf : {false, true}) {
        Limits limits;
        limits.allow_bare_lf = bare_lf;
        const std::vector<std::string> invalid{
            "X", "\rX", "\r\r", "X\r", std::string(65536, 'X')};
        for (const auto& suffix : invalid) {
            for (const bool split_cr : {false, true}) {
                ResponseParser parser{Method::get, limits};
                Buffer input;
                input.append(bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na"));
                CHECK_VALUE(parser.parse(input) == ParseStep::head);
                CHECK_VALUE(parser.parse(input) == ParseStep::body);
                CHECK_VALUE(text(parser.body()) == "a");
                CHECK_VALUE(parser.body().data() == input.readable().data());
                CHECK_VALUE(input.size() == 1);
                CHECK_VALUE(parser.parse(input) == ParseStep::need_more);
                CHECK_VALUE(input.empty());
                if (split_cr) {
                    input.append(bytes("\r"));
                    CHECK_VALUE(parser.parse(input) == ParseStep::need_more);
                    CHECK_VALUE(input.size() == 1);
                }
                input.append(bytes(suffix));
                CHECK_VALUE(!parser.parse(input));
            }
        }

        ResponseParser parser{Method::get, limits};
        Buffer input;
        input.append(bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na"));
        CHECK_VALUE(parser.parse(input) == ParseStep::head);
        CHECK_VALUE(parser.parse(input) == ParseStep::body);
        CHECK_VALUE(text(parser.body()) == "a");
        CHECK_VALUE(input.size() == 1);
        CHECK_VALUE(parser.parse(input) == ParseStep::need_more);
        input.append(bytes("\r"));
        CHECK_VALUE(parser.parse(input) == ParseStep::need_more);
        CHECK_VALUE(parser.parse(input) == ParseStep::need_more);
        CHECK_VALUE(input.size() == 1);
        input.append(bytes("\n1\r\nb\r\n0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"));
        CHECK_VALUE(parser.parse(input) == ParseStep::body);
        CHECK_VALUE(text(parser.body()) == "b");
        CHECK_VALUE(parser.parse(input) == ParseStep::complete);
        parser.reset();
        CHECK_VALUE(parser.parse(input) == ParseStep::head);
        CHECK_VALUE(parser.response().status == 204);
        CHECK_VALUE(parser.parse(input) == ParseStep::complete);
        CHECK_VALUE(input.empty());

        const auto lf = parse(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\n0\r\n\r\n",
            1, Method::get, limits);
        CHECK_VALUE(lf.done == bare_lf);
        CHECK_VALUE(lf.body == "a");
        if (!bare_lf) CHECK_VALUE(lf.error == ParseError::bad_line_ending);
    }
}

void test_semantics() {
    test::section("HEAD / 1xx / 204 / 304 / EOF / tunnel boundaries");
    for (unsigned status : {100u, 103u, 199u, 204u, 304u}) {
        auto result = parse("HTTP/1.1 " + std::to_string(status) + " X\r\n\r\n", 1);
        CHECK_VALUE(result.done);
        CHECK_VALUE(result.response.body_kind == BodyKind::none);
        CHECK_VALUE(result.body.empty());
    }
    Limits small;
    small.max_body_size = 1;
    auto head = parse("HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n", 1, Method::head, small);
    CHECK_VALUE(head.done);
    CHECK_VALUE(head.response.content_length == 99999);
    CHECK_VALUE(head.body.empty());
    auto cached = parse("HTTP/1.1 304 X\r\nContent-Length: 99999\r\n\r\n", 1, Method::get, small);
    CHECK_VALUE(cached.done);
    CHECK_VALUE(cached.body.empty());
    CHECK_VALUE(parse("HTTP/1.1 200 OK\r\n\r\n").done);
    CHECK_VALUE(parse("HTTP/1.1 200 OK\r\n\r\na").body == "a");
    CHECK_VALUE(
        parse("HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\nContent-Length: 2\r\n\r\nok", 1).body ==
        "ok");
    for (auto method : {Method::get, Method::connect}) {
        Buffer input;
        input.append(bytes(method == Method::get ? "HTTP/1.1 101 Switching Protocols\r\n\r\ntunnel"
                                                 : "HTTP/1.1 200 Connected\r\n\r\ntunnel"));
        ResponseParser parser{method};
        auto result = parser.parse(input);
        CHECK_VALUE(!result);
        CHECK_VALUE(result.error() == Errc::not_supported);
        CHECK_VALUE(text(input.readable()) == "tunnel");
    }
    CHECK_VALUE(
        parse("HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno", 1, Method::connect).body ==
        "no");
}
void test_negative() {
    test::section("response smuggling, truncation, and resource limit negative tests");
    CHECK_VALUE(
        parse("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
              1)
            .error == ParseError::framing_conflict);
    CHECK_VALUE(parse("HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 1).error ==
                ParseError::invalid_transfer_encoding);
    const std::vector<std::string> bad{
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 1,\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 204 X\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 100 X\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX : y\r\n\r\n",
        "HTTP/1.1 200 OK\r\n X: y\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n",
        "HTTP/1.1 200 OK\n\n",
        "HTTP/2.0 200 OK\r\n\r\n",
        "HTTP/1.1 20 OK\r\n\r\n",
        "HTTP/1.1 600 X\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+1\r\na\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naX\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 3\r\n\r\n",
        std::string{"HTTP/1.1 200 OK\r\nX: a"} + char(0) + "b\r\n\r\n"};
    for (const auto& wire : bad) {
        CHECK_VALUE(parse(wire, 1).error);
        CHECK_VALUE(parse(wire).error);
    }
    const std::vector<std::string> complete{
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\nX: y\r\n\r\n"};
    for (const auto& wire : complete) {
        for (std::size_t n = 0; n < wire.size(); ++n)
            CHECK_VALUE(parse(wire.substr(0, n), 1).error == Errc::eof);
    }
    Limits limits;
    limits.max_body_size = 3;
    CHECK_VALUE(parse(complete[0], 1, Method::get, limits).error == ParseError::limit_exceeded);
    CHECK_VALUE(parse(complete[1], 1, Method::get, limits).error == ParseError::limit_exceeded);
    CHECK_VALUE(parse("HTTP/1.1 200 OK\r\n\r\nbody", 1, Method::get, limits).error ==
                ParseError::limit_exceeded);
    limits = {};
    limits.max_chunk_size = 3;
    CHECK_VALUE(parse(complete[1], 1, Method::get, limits).error == ParseError::limit_exceeded);
    limits = {};
    limits.max_start_line = 15;
    CHECK_VALUE(parse("HTTP/1.1 200 OK\r\n\r\n", 1, Method::get, limits).done);
    limits.max_start_line = 14;
    CHECK_VALUE(parse("HTTP/1.1 200 OK\r\n\r\n", 1, Method::get, limits).error ==
                ParseError::limit_exceeded);
    limits = {};
    limits.max_header_line = 3;
    CHECK_VALUE(parse("HTTP/1.1 200 OK\r\nX: y\r\n\r\n", 1, Method::get, limits).error ==
                ParseError::limit_exceeded);
    limits = {};
    limits.max_header_count = 1;
    CHECK_VALUE(parse(complete[1], 1, Method::get, limits).error == ParseError::limit_exceeded);
    limits = {};
    limits.max_headers_total = 29;  // TE 26 + trailer 4; the running total exceeds the budget.
    CHECK_VALUE(parse(complete[1], 1, Method::get, limits).error == ParseError::limit_exceeded);
    limits = {};
    limits.max_chunk_extension = 2;
    CHECK_VALUE(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0;abc\r\n\r\n",
                      1,
                      Method::get,
                      limits)
                    .error == ParseError::limit_exceeded);
    limits = {};
    limits.max_body_size = UINT64_MAX;
    limits.max_chunk_size = UINT64_MAX;
    CHECK_VALUE(
        parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nffffffffffffffff\r\n",
              1,
              Method::get,
              limits)
            .error == ParseError::limit_exceeded);
}
void test_request_serialization() {
    test::section("request serialization and Host validation");
    Request request;
    request.target = "/a?b=c";
    request.headers.append("Host", "example.com:8080");
    Buffer out;
    CHECK_VALUE(write_request_head(out, request, 4));
    CHECK_VALUE(text(out.readable()) ==
                "GET /a?b=c HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 4\r\n\r\n");
    const std::vector<std::string> bad_hosts{"",
                                             "a b",
                                             "a\r\nX: y",
                                             "user@host",
                                             "a/path",
                                             "a:65536",
                                             "a:-1",
                                             "a:",
                                             "a:12x",
                                             "[bad]",
                                             "[::1",
                                             "::1",
                                             "[:::1]",
                                             "[::ffff:127.0.0.256]",
                                             "[::ffff:127.00.0.1]",
                                             "[::ffff:127.0.0]",
                                             "[1:2:3:4:5:6::127.0.0.1]"};
    for (const auto& host : bad_hosts) {
        request.headers.clear();
        request.headers.append("Host", host);
        out.clear();
        CHECK_VALUE(!write_request_head(out, request));
        CHECK_VALUE(out.empty());
    }
    for (const auto& host : {"localhost", "127.0.0.1", "[::1]:443", "[2001:db8::1]",
                              "[::ffff:127.0.0.1]:443", "[1:2:3:4:5:6:127.0.0.1]"}) {
        request.headers.clear();
        request.headers.append("Host", host);
        out.clear();
        CHECK_VALUE(write_request_head(out, request));
    }
    request.headers.append("host", "duplicate");
    out.clear();
    CHECK_VALUE(!write_request_head(out, request));
    request.headers.clear();
    CHECK_VALUE(!write_request_head(out, request));
    request.headers.append("Host", "x");
    for (const auto& target : {"", "/a b", "/a\r\nX:y", "http://x/a", "/a#fragment"}) {
        request.target = target;
        CHECK_VALUE(!write_request_head(out, request));
    }
    request.target = "/";
    for (const auto& field : {"Content-Length", "Transfer-Encoding", "Upgrade", "Expect"}) {
        Request copy = request;
        copy.headers.append(field, "x");
        CHECK_VALUE(!write_request_head(out, copy));
    }
    request.method = Method::connect;
    CHECK_VALUE(!write_request_head(out, request));
    request.method = Method::other;
    CHECK_VALUE(!write_request_head(out, request));
    request.method = Method::get;
    Limits limits;
    limits.max_body_size = 1;
    CHECK_VALUE(!write_request_head(out, request, 2, limits));
    limits = {};
    limits.max_header_count = 1;
    CHECK_VALUE(!write_request_head(out, request, 0, limits));
    Response response;
    response.version = Version::http_1_0;
    CHECK_VALUE(!write_response_head(out, response, Framing::chunked));
    Buffer input;
    input.append(bytes("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"));
    RequestParser parser;
    auto result = parser.parse(input);
    CHECK_VALUE(!result);
    CHECK_VALUE(result.error() == ParseError::invalid_transfer_encoding);
}
}  // namespace
int main() {
    test_incremental();
    test_chunk_data_terminator();
    test_semantics();
    test_negative();
    test_request_serialization();
    return test::summary();
}
