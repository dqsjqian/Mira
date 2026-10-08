// Mira/http tests/streaming.cpp — the streaming request-body contract.
//
// The buffered path is what most of test_server.cpp covers. These tests pin
// the other half of the deal: a handler that takes a `RequestBodyReader`
// gets the body slice by slice while it runs, the connection stays correct
// no matter how the handler stops reading, and neither path regresses when
// the other is used on the same connection.

#include "check.hpp"

#include "mira/core/stream.hpp"
#include "mira/core/task.hpp"
#include "mira/http/connection.hpp"
#include "mira/http/message.hpp"
#include "mira/http/parser.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace Mira;
namespace http = Mira::http;
using http::RequestParser;
using http::RequestBodyReader;
using http::ResponseWriter;
using http::ServerOptions;

namespace {

/// A one-shot in-memory stream: writes are recorded, reads are served from a
/// fixed script of byte chunks. Reads past the script return EOF. Nothing
/// here allocates per operation beyond the recorded output.
class ScriptStream {
public:
    explicit ScriptStream(std::vector<std::vector<std::byte>> reads) : reads_(std::move(reads)) {}

    [[nodiscard]] Task<Result<std::size_t>> read_some(std::span<std::byte> out,
                                                      OperationOptions = {}) {
        if (next_read_ >= reads_.size()) {
            co_return std::unexpected(make_error_code(Errc::eof));
        }
        const std::span<const std::byte> chunk = reads_[next_read_];
        if (chunk.empty()) {
            ++next_read_;
            co_return std::unexpected(make_error_code(Errc::eof));
        }
        const std::size_t n = std::min(chunk.size(), out.size());
        std::memcpy(out.data(), chunk.data(), n);
        if (n < chunk.size()) {
            // Split delivery: put the remainder back for the next call.
            reads_[next_read_] =
                std::vector<std::byte>(chunk.begin() + static_cast<std::ptrdiff_t>(n), chunk.end());
        } else {
            ++next_read_;
        }
        co_return n;
    }

    [[nodiscard]] Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes,
                                                       OperationOptions = {}) {
        written_.insert(written_.end(), bytes.begin(), bytes.end());
        co_return bytes.size();
    }

    [[nodiscard]] std::string written() const {
        return std::string{reinterpret_cast<const char*>(written_.data()), written_.size()};
    }

private:
    std::vector<std::vector<std::byte>> reads_;
    std::vector<std::byte> written_{};
    std::size_t next_read_{0};
};

std::vector<std::byte> bytes(std::string_view text) {
    return {reinterpret_cast<const std::byte*>(text.data()),
            reinterpret_cast<const std::byte*>(text.data()) + text.size()};
}

}  // namespace

static void test_streaming_body_slices_arrive_in_order() {
    test::section("streaming slices arrive in order across split reads");
    // One request whose body arrives in three awkward splits.
    ScriptStream stream{{bytes("POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n"
                              "01234"),
                        bytes("567"),
                        bytes("89")}};

    std::string collected;
    auto handler = [&](const http::Request&, auto&, auto& reader) -> Task<Result<void>> {
        std::array<std::byte, 4> chunk{};  // deliberately smaller than the reads above
        for (;;) {
            Result<std::size_t> n = co_await reader.read(chunk);
            if (!n) co_return fail(n.error());
            if (*n == 0) break;
            collected.append(reinterpret_cast<const char*>(chunk.data()), *n);
        }
        co_return Result<void>{};
    };

    ServerOptions options;
    options.max_requests_per_connection = 1;
    const Result<void> served = http::serve_connection(stream, handler, options).sync_get();
    CHECK(served.has_value());
    CHECK(collected == "0123456789");
}

static void test_streaming_handler_that_never_reads_gets_its_body_drained() {
    test::section("unread streaming body is drained; pipelined request still parses");
    ScriptStream stream{{bytes("POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n"
                              "HELLO"
                              "GET /b HTTP/1.1\r\nHost: x\r\n\r\n"),
                        std::vector<std::byte>{}}};

    int seen = 0;
    auto streaming_handler = [&](const http::Request&, auto& writer,
                                 auto&) -> Task<Result<void>> {
        ++seen;
        http::Response response;
        response.status = 200;
        co_return co_await writer.send(response);
    };

    ServerOptions options;
    const Result<void> served =
        http::serve_connection(stream, streaming_handler, options).sync_get();
    CHECK(served.has_value());
    CHECK(seen == 2);  // the drained POST, then the pipelined GET
    // Both responses on the wire, in order.
    const std::string wire = stream.written();
    const std::size_t first = wire.find("HTTP/1.1 200");
    CHECK(first != std::string::npos);
    CHECK(wire.find("HTTP/1.1 200", first + 1) != std::string::npos);
}

static void test_streaming_chunked_body_with_trailers() {
    test::section("chunked body with trailers via streaming read");
    ScriptStream stream{{bytes("POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                              "5\r\nHELLO\r\n"
                              "3\r\nOK!\r\n"
                              "0\r\nX-Sum: 8\r\n\r\n")}};

    std::string collected;
    bool has_trailer = false;
    std::string trailer_value;
    auto handler = [&](const http::Request&, auto&, auto& reader) -> Task<Result<void>> {
        std::array<std::byte, 64> chunk{};
        for (;;) {
            Result<std::size_t> n = co_await reader.read(chunk);
            if (!n) co_return fail(n.error());
            if (*n == 0) {
                // The trailers borrow the parser's storage, which dies with
                // serve_connection; copy the value out while it is alive.
                const auto& trailers = reader.trailers();
                const auto found = trailers.get("x-sum");
                has_trailer = found.has_value();
                if (has_trailer) {
                    trailer_value = *found;
                }
                break;
            }
            collected.append(reinterpret_cast<const char*>(chunk.data()), *n);
        }
        co_return Result<void>{};
    };

    ServerOptions options;
    options.max_requests_per_connection = 1;
    const Result<void> served = http::serve_connection(stream, handler, options).sync_get();
    CHECK(served.has_value());
    CHECK(collected == "HELLOOK!");
    CHECK(has_trailer);
    CHECK(trailer_value == "8");
}

static void test_forbidden_trailer_stops_streaming_pipeline() {
    test::section("body reads and automatic drains reject forbidden trailers before pipelining");
    for (const bool reads_body : {false, true}) {
        ScriptStream stream{{bytes("POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                                   "4\r\ndata\r\n0\r\nhOsT: other.test\r\n\r\n"
                                   "GET /next HTTP/1.1\r\nHost: x\r\n\r\n")}};
        unsigned calls = 0;
        Error read_error;
        auto handler = [&](const http::Request&, auto& writer, auto& reader) -> Task<Result<void>> {
            ++calls;
            if (reads_body) {
                const auto body = co_await reader.read_all();
                if (!body) read_error = body.error();
                CHECK(reader.trailers().empty());
            }
            co_return co_await writer.send(http::Response{});
        };
        const auto result = http::serve_connection(stream, handler).sync_get();
        CHECK(!result);
        if (!result) CHECK(result.error() == http::ParseError::framing_conflict);
        CHECK(calls == 1);
        if (reads_body) CHECK(read_error == http::ParseError::framing_conflict);
        const auto sent = stream.written();
        CHECK(sent.find("HTTP/1.1 200 ") == 0);
        CHECK(sent.find("HTTP/1.1 200 ", 1) == std::string::npos);
    }
}

static void test_streaming_read_all_matches_buffered_path() {
    test::section("read_all matches the buffered path");
    const std::string payload(4096, 'x');
    ScriptStream stream{{
        bytes("POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: " +
              std::to_string(payload.size()) + "\r\n\r\n" + payload),
    }};

    std::size_t total = 0;
    auto handler = [&](const http::Request&, auto&, auto& reader) -> Task<Result<void>> {
        Result<std::vector<std::byte>> whole = co_await reader.read_all();
        if (!whole) co_return fail(whole.error());
        total = whole->size();
        co_return Result<void>{};
    };

    ServerOptions options;
    options.max_requests_per_connection = 1;
    const Result<void> served = http::serve_connection(stream, handler, options).sync_get();
    CHECK(served.has_value());
    CHECK(total == payload.size());
}

static void test_streaming_body_over_budget_fails_and_closes() {
    test::section("body over budget fails the read and closes the connection");
    // A length-delimited body over budget is refused at the head (413) before
    // any handler runs — covered by the buffered-path tests. Chunked framing
    // is the case streaming handlers actually meet: the budget is exceeded
    // mid-body, so the failure surfaces through the reader.
    ScriptStream stream{{bytes("POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                              "400001\r\n")}};

    bool read_failed = false;
    auto handler = [&](const http::Request&, auto&, auto& reader) -> Task<Result<void>> {
        std::array<std::byte, 16> chunk{};
        Result<std::size_t> n = co_await reader.read(chunk);
        read_failed = !n.has_value();
        co_return Result<void>{};  // the handler itself "succeeds"
    };

    ServerOptions options;
    options.max_requests_per_connection = 1;
    options.limits.max_body_size = 1024 * 1024;
    const Result<void> served = http::serve_connection(stream, handler, options).sync_get();
    // The handler reported success, but the drain the loop performs after it
    // hits the same parser budget: the connection must not stay open.
    CHECK(!served.has_value());
    CHECK(read_failed);
}

static void test_buffered_handler_still_gets_whole_body() {
    test::section("buffered (span) handler keeps working alongside streaming");
    ScriptStream stream{{bytes("POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n"
                              "abc"
                              "GET /b HTTP/1.1\r\nHost: x\r\n\r\n")}};

    std::vector<std::string> bodies;
    int count = 0;
    auto handler = [&](const http::Request&, auto& writer,
                       std::span<const std::byte> body) -> Task<Result<void>> {
        ++count;
        bodies.emplace_back(reinterpret_cast<const char*>(body.data()), body.size());
        http::Response response;
        response.status = 200;
        co_return co_await writer.send(response);
    };

    ServerOptions options;
    const Result<void> served = http::serve_connection(stream, handler, options).sync_get();
    CHECK(served.has_value());
    CHECK(count == 2);
    CHECK(bodies.size() == 2);
    CHECK(bodies[0] == "abc");  // the POST's body
    CHECK(bodies[1].empty());   // the GET's (no body)
}

int main() {
    test_streaming_body_slices_arrive_in_order();
    test_streaming_handler_that_never_reads_gets_its_body_drained();
    test_streaming_chunked_body_with_trailers();
    test_forbidden_trailer_stops_streaming_pipeline();
    test_streaming_read_all_matches_buffered_path();
    test_streaming_body_over_budget_fails_and_closes();
    test_buffered_handler_still_gets_whole_body();
    return Mira::test::summary();
}
