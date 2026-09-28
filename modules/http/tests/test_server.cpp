// Response serialisation and the connection loop.
//
// Two layers of testing, both necessary:
//
//   * Serialisation is checked byte-for-byte against a string. Anything less
//     specific would let a stray space or a missing CRLF through, and both
//     break real clients in ways that are tedious to diagnose.
//   * The connection loop is driven over a scripted in-memory stream, which
//     makes keep-alive, pipelining, and body-draining deterministic. A real
//     TCP end-to-end test lives in the transport suite; here the point is to
//     control exactly what bytes arrive and when.
//
// The negative cases matter most again: response splitting via header
// injection, framing supplied twice, and a handler that ignores the request
// body — that last one corrupts the *next* request rather than the current
// one, which is why it needs a test rather than a comment.

#include "check.hpp"
#include "mira/core/buffer.hpp"
#include "mira/http/connection.hpp"
#include "mira/http/serializer.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace Mira;
using namespace Mira::http;

namespace {

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

std::string text_of(std::span<const std::byte> bytes) {
    return std::string{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

// ── serialisation ────────────────────────────────────────────────────────────

void test_response_head() {
    test::section("response head");

    Response response;
    response.status = 200;
    response.headers.append("Content-Type", "text/plain");

    Buffer out;
    CHECK(write_response_head(out, response, Framing::content_length, 5).has_value());
    CHECK(text_of(out.readable()) ==
          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n");

    // A missing reason phrase is filled in from the status code.
    Buffer implied;
    Response not_found;
    not_found.status = 404;
    CHECK(write_response_head(implied, not_found, Framing::content_length, 0).has_value());
    CHECK(text_of(implied.readable()) == "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");

    // An explicit reason wins.
    Buffer custom;
    Response teapot;
    teapot.status = 418;
    teapot.reason = "I am a teapot";
    CHECK(write_response_head(custom, teapot, Framing::none).has_value());
    CHECK(text_of(custom.readable()) == "HTTP/1.1 418 I am a teapot\r\n\r\n");

    // Chunked framing.
    Buffer streamed;
    Response ok;
    ok.status = 200;
    CHECK(write_response_head(streamed, ok, Framing::chunked).has_value());
    CHECK(text_of(streamed.readable()) == "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
}

void test_bodyless_statuses() {
    test::section("body-less statuses");

    // 204 and 304 must carry no framing header at all. `Content-Length: 0` on
    // a 304 is a well-known way to confuse caches.
    for (const unsigned status : {204u, 304u, 100u}) {
        Buffer out;
        Response response;
        response.status = status;
        CHECK(write_response_head(out, response, Framing::content_length, 99).has_value());
        const std::string text = text_of(out.readable());
        CHECK(text.find("Content-Length") == std::string::npos);
        CHECK(text.find("Transfer-Encoding") == std::string::npos);
        CHECK(status_forbids_body(status));
    }

    CHECK(!status_forbids_body(200));
    CHECK(!status_forbids_body(404));
}

void test_response_splitting_rejected() {
    test::section("response splitting rejected");

    // A CR or LF in a value would inject headers — or a whole second response —
    // into the stream. This is the serialiser's most important refusal.
    for (const std::string_view value : {"a\r\nX-Evil: 1", "a\nX-Evil: 1", "a\rb"}) {
        Buffer out;
        Response response;
        response.status = 200;
        response.headers.append("X-Test", std::string{value});
        const Result<void> written = write_response_head(out, response, Framing::content_length, 0);
        CHECK(!written.has_value());
        if (!written.has_value()) {
            CHECK(written.error() == SerializeError::invalid_header);
        }
    }

    // A non-token field name is refused for the same reason.
    for (const std::string_view name : {"Bad Name", "Bad:Name", "Bad\tName", ""}) {
        Buffer out;
        Response response;
        response.status = 200;
        response.headers.append(std::string{name}, "x");
        CHECK(!write_response_head(out, response, Framing::content_length, 0).has_value());
    }

    // So is an injected reason phrase.
    Buffer out;
    Response response;
    response.status = 200;
    response.reason = "OK\r\nX-Evil: 1";
    CHECK(!write_response_head(out, response, Framing::content_length, 0).has_value());
}

void test_serializer_owns_framing() {
    test::section("serializer owns framing");

    // A caller-supplied framing header is refused, not silently dropped:
    // dropping it would make the wire disagree with the caller's intent.
    Buffer out;
    Response response;
    response.status = 200;
    response.headers.append("Content-Length", "5");
    const Result<void> written = write_response_head(out, response, Framing::content_length, 5);
    CHECK(!written.has_value());
    CHECK(written.error() == SerializeError::framing_conflict);

    Buffer other;
    Response chunked;
    chunked.status = 200;
    chunked.headers.append("Transfer-Encoding", "chunked");
    CHECK(!write_response_head(other, chunked, Framing::chunked).has_value());

    // Out-of-range status codes.
    Buffer bad;
    Response invalid;
    invalid.status = 99;
    CHECK(!write_response_head(bad, invalid, Framing::none).has_value());
    invalid.status = 1000;
    CHECK(!write_response_head(bad, invalid, Framing::none).has_value());
}

void test_chunk_framing() {
    test::section("chunk framing");

    Buffer out;
    CHECK(write_chunk(out, bytes_of("hello")).has_value());
    CHECK(text_of(out.readable()) == "5\r\nhello\r\n");

    // Sizes are lower-case hex.
    Buffer big;
    const std::string payload(255, 'x');
    CHECK(write_chunk(big, bytes_of(payload)).has_value());
    CHECK(text_of(big.readable()).starts_with("ff\r\n"));

    // An empty chunk is the terminator; writing one as data would end the
    // message early.
    Buffer empty;
    CHECK(!write_chunk(empty, {}).has_value());

    Buffer last;
    write_last_chunk(last);
    CHECK(text_of(last.readable()) == "0\r\n\r\n");
}

void test_keep_alive_rules() {
    test::section("keep-alive rules");

    const auto request_with = [](Version version, std::string_view connection) {
        Request request;
        request.version = version;
        if (!connection.empty()) {
            request.headers.append("Connection", std::string{connection});
        }
        return request;
    };

    // HTTP/1.1 persists unless told otherwise.
    CHECK(should_keep_alive(request_with(Version::http_1_1, "")));
    CHECK(!should_keep_alive(request_with(Version::http_1_1, "close")));
    CHECK(!should_keep_alive(request_with(Version::http_1_1, "Close")));
    CHECK(!should_keep_alive(request_with(Version::http_1_1, "keep-alive, close")));
    CHECK(should_keep_alive(request_with(Version::http_1_1, "keep-alive")));

    // HTTP/1.0 closes unless persistence is requested.
    CHECK(!should_keep_alive(request_with(Version::http_1_0, "")));
    CHECK(should_keep_alive(request_with(Version::http_1_0, "keep-alive")));
    CHECK(should_keep_alive(request_with(Version::http_1_0, "Keep-Alive")));
    CHECK(!should_keep_alive(request_with(Version::http_1_0, "close")));
}

// ── scripted stream ──────────────────────────────────────────────────────────

/// A stream that replays a script of incoming bytes and records what is sent.
///
/// `chunk_limit` forces short reads and short writes so the loop's handling of
/// partial transfers is exercised rather than assumed.
class ScriptedStream {
public:
    explicit ScriptedStream(std::string incoming, std::size_t chunk_limit = 64)
        : incoming_(std::move(incoming)), chunk_limit_(chunk_limit) {}

    /// `options` is accepted and ignored, which is honest for this stream
    /// rather than a shortcut: it moves bytes already in memory, so it never
    /// waits, and a stop token or deadline has nothing to interrupt. Accepting
    /// them is what makes it a `BoundedStream`, so that code under test can be
    /// the same code that runs over a socket.
    Task<Result<std::size_t>> read_some(std::span<std::byte> destination,
                                       OperationOptions = {}) {
        if (read_pos_ >= incoming_.size()) {
            co_return fail(Errc::eof);
        }
        const std::size_t available = incoming_.size() - read_pos_;
        const std::size_t n = std::min({available, destination.size(), chunk_limit_});
        std::memcpy(destination.data(), incoming_.data() + read_pos_, n);
        read_pos_ += n;
        co_return n;
    }

    Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                        OperationOptions = {}) {
        const std::size_t n = std::min(source.size(), chunk_limit_);
        outgoing_.append(reinterpret_cast<const char*>(source.data()), n);
        co_return n;
    }

    [[nodiscard]] const std::string& sent() const noexcept { return outgoing_; }
    [[nodiscard]] std::size_t unread() const noexcept { return incoming_.size() - read_pos_; }

private:
    std::string incoming_;
    std::string outgoing_{};
    std::size_t read_pos_{0};
    std::size_t chunk_limit_;
};

static_assert(AsyncStream<ScriptedStream>);

/// Count how many times `needle` occurs in `haystack`.
std::size_t count_occurrences(std::string_view haystack, std::string_view needle) {
    std::size_t total = 0;
    std::size_t at = haystack.find(needle);
    while (at != std::string_view::npos) {
        ++total;
        at = haystack.find(needle, at + needle.size());
    }
    return total;
}

// ── connection loop ──────────────────────────────────────────────────────────

void test_shared_buffer_budget() {
    test::section("shared server input and request body budget");
    ResourceBudget budget{256};
    ServerOptions options;
    options.max_buffer_size = 128;
    options.limits.max_body_size = 128;
    options.buffer_budget = budget;
    auto handler = [&budget](const Request&, auto& writer, std::span<const std::byte> body)
        -> Task<Result<void>> {
        CHECK(budget.used() == 256);
        CHECK(text_of(body) == "test");
        auto extra = budget.try_acquire(1);
        CHECK(!extra && extra.error() == Errc::would_block);
        Response response;
        co_return co_await writer.send(response);
    };
    ScriptedStream stream{"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest"};
    CHECK(serve_connection(stream, handler, options).sync_get().has_value());
    CHECK(budget.used() == 0);
    auto occupied = budget.try_acquire(1);
    CHECK(occupied.has_value());
    ScriptedStream rejected{"GET / HTTP/1.1\r\nHost: x\r\n\r\n"};
    const auto untouched = rejected.unread();
    auto result = serve_connection(rejected, handler, options).sync_get();
    CHECK(!result && result.error() == Errc::would_block);
    CHECK(rejected.unread() == untouched && rejected.sent().empty());
    CHECK(budget.used() == 1);
    occupied->reset();
    ScriptedStream too_long{"GET /" + std::string(150, 'x') + " HTTP/1.1\r\n\r\n", 4096};
    result = serve_connection(too_long, handler, options).sync_get();
    CHECK(!result && result.error() == Errc::limit_exceeded);
    CHECK(budget.used() == 0);
    options.request_timeout = -std::chrono::seconds(1);
    ScriptedStream invalid{""};
    result = serve_connection(invalid, handler, options).sync_get();
    CHECK(!result && result.error() == Errc::invalid_argument);
    CHECK(budget.used() == 0);
}

void test_single_exchange() {
    test::section("single exchange");

    ScriptedStream stream{"GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"};

    std::string seen_target;
    auto handler = [&seen_target](const Request& request,
                                  auto& writer,
                                  std::span<const std::byte>) -> Task<Result<void>> {
        seen_target = request.target;
        Response response;
        response.status = 200;
        response.headers.append("Content-Type", "text/plain");
        co_return co_await writer.send(response, bytes_of("hi"));
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(served.has_value());
    CHECK(seen_target == "/hello");
    CHECK(stream.sent() == "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                           "Content-Length: 2\r\n\r\nhi");
}

void test_keep_alive_pipeline() {
    test::section("keep-alive and pipelining");

    // Two requests arriving together: both must be served on one connection,
    // in order.
    ScriptedStream stream{"GET /one HTTP/1.1\r\nHost: x\r\n\r\n"
                          "GET /two HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"};

    std::vector<std::string> targets;
    auto handler = [&targets](const Request& request,
                              auto& writer,
                              std::span<const std::byte>) -> Task<Result<void>> {
        targets.push_back(request.target);
        Response response;
        response.status = 200;
        co_return co_await writer.send(response, bytes_of("ok"));
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(served.has_value());
    CHECK(targets.size() == 2);
    if (targets.size() == 2) {
        CHECK(targets[0] == "/one");
        CHECK(targets[1] == "/two");
    }
    CHECK(count_occurrences(stream.sent(), "HTTP/1.1 200 OK") == 2);
}

void test_handler_exception_is_contained() {
    test::section("a throwing handler gets a 500 or a close, never an escape");

    // Branch 1: std::exception before anything was sent → 500 + fail(internal).
    {
        ScriptedStream stream{"GET /boom HTTP/1.1\r\nHost: x\r\n\r\n"};
        auto handler = [](const Request&, auto&, std::span<const std::byte>)
            -> Task<Result<void>> { throw std::runtime_error("handler exploded"); };

        const Result<void> served = serve_connection(stream, handler).sync_get();
        CHECK(!served.has_value());
        CHECK(served.error() == Errc::internal);
        CHECK(stream.sent().starts_with("HTTP/1.1 500 Internal Server Error"));
    }

    // Branch 2: a non-std exception type — the catch must be catch-all.
    {
        ScriptedStream stream{"GET /alien HTTP/1.1\r\nHost: x\r\n\r\n"};
        struct Alien {};
        auto handler = [](const Request&, auto&, std::span<const std::byte>)
            -> Task<Result<void>> { throw Alien{}; };

        const Result<void> served = serve_connection(stream, handler).sync_get();
        CHECK(!served.has_value());
        CHECK(served.error() == Errc::internal);
        CHECK(stream.sent().starts_with("HTTP/1.1 500 Internal Server Error"));
    }

    // Branch 3: throw *after* the head is on the wire → no second response,
    // the half-written exchange is abandoned.
    {
        ScriptedStream stream{"GET /half HTTP/1.1\r\nHost: x\r\n\r\n"};
        auto handler = [](const Request&, auto& writer, std::span<const std::byte>)
            -> Task<Result<void>> {
            Response response;
            response.status = 200;
            if (const Result<void> head = co_await writer.send_head_chunked(response);
                !head) {
                co_return fail(head.error());
            }
            throw std::runtime_error("mid-stream explosion");
        };

        const Result<void> served = serve_connection(stream, handler).sync_get();
        CHECK(!served.has_value());
        CHECK(served.error() == Errc::internal);
        // Exactly one status line ever: the 500 must not stack on the 200.
        CHECK(count_occurrences(stream.sent(), "HTTP/1.1") == 1);
        CHECK(stream.sent().starts_with("HTTP/1.1 200 OK"));
    }
}

void test_body_is_drained_even_if_ignored() {
    test::section("request body always drained");

    // The handler below never looks at the body. If the loop did not drain it,
    // "payload" would be parsed as the start of the second request and the
    // second exchange would fail — corrupting a request the handler never saw.
    ScriptedStream stream{"POST /first HTTP/1.1\r\nHost: x\r\nContent-Length: 7\r\n\r\npayload"
                          "GET /second HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"};

    std::vector<std::string> targets;
    auto handler = [&targets](const Request& request,
                              auto& writer,
                              std::span<const std::byte>) -> Task<Result<void>> {
        targets.push_back(request.target);
        Response response;
        response.status = 204;
        co_return co_await writer.send(response);
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(served.has_value());
    CHECK(targets.size() == 2);
    if (targets.size() == 2) {
        CHECK(targets[1] == "/second");
    }
}

void test_body_delivered_to_handler() {
    test::section("body delivered to handler");

    ScriptedStream stream{"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n"
                          "Connection: close\r\n\r\nhello world"};

    std::string received;
    auto handler = [&received](const Request&,
                               auto& writer,
                               std::span<const std::byte> body) -> Task<Result<void>> {
        received = text_of(body);
        Response response;
        response.status = 200;
        co_return co_await writer.send(response, body);
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(served.has_value());
    CHECK(received == "hello world");
    CHECK(stream.sent().ends_with("hello world"));
    CHECK(stream.sent().find("Content-Length: 11") != std::string::npos);
}

void test_chunked_request_body() {
    test::section("chunked request body");

    ScriptedStream stream{"POST /upload HTTP/1.1\r\nHost: x\r\n"
                          "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                          "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"};

    std::string received;
    auto handler = [&received](const Request&,
                               auto& writer,
                               std::span<const std::byte> body) -> Task<Result<void>> {
        received = text_of(body);
        Response response;
        response.status = 200;
        co_return co_await writer.send(response);
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(served.has_value());
    // The handler sees the decoded body, not the chunk framing.
    CHECK(received == "hello world");
}

void test_head_request_withholds_body() {
    test::section("HEAD withholds body");

    ScriptedStream stream{"HEAD /page HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"};

    auto handler =
        [](const Request&, auto& writer, std::span<const std::byte>) -> Task<Result<void>> {
        Response response;
        response.status = 200;
        // The handler does not branch on HEAD; the writer withholds the bytes.
        co_return co_await writer.send(response, bytes_of("body-not-sent"));
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(served.has_value());
    // Content-Length still describes what a GET would return — that is the
    // point of HEAD — but no body bytes follow.
    CHECK(stream.sent() == "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n");
    CHECK(stream.sent().find("body-not-sent") == std::string::npos);
}

void test_streaming_response() {
    test::section("streaming response");

    ScriptedStream stream{"GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"};

    auto handler =
        [](const Request&, auto& writer, std::span<const std::byte>) -> Task<Result<void>> {
        Response response;
        response.status = 200;
        Result<void> head = co_await writer.send_head_chunked(response);
        if (!head) {
            co_return fail(head.error());
        }
        for (const std::string_view piece : {"alpha", "beta"}) {
            Result<void> written = co_await writer.write(bytes_of(piece));
            if (!written) {
                co_return fail(written.error());
            }
        }
        co_return Result<void>{};  // loop terminates the body
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(served.has_value());
    CHECK(stream.sent() == "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                           "5\r\nalpha\r\n4\r\nbeta\r\n0\r\n\r\n");
}

void test_malformed_request_gets_400_then_closes() {
    test::section("malformed request");

    // A framing conflict: the loop must answer once and stop, because the
    // stream position is no longer trustworthy.
    ScriptedStream stream{"POST / HTTP/1.1\r\nHost: x\r\n"
                          "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                          "GET /never-served HTTP/1.1\r\n\r\n"};

    int calls = 0;
    auto handler =
        [&calls](const Request&, auto& writer, std::span<const std::byte>) -> Task<Result<void>> {
        ++calls;
        Response response;
        response.status = 200;
        co_return co_await writer.send(response);
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(!served.has_value());
    CHECK(served.error() == ParseError::framing_conflict);
    CHECK(calls == 0);  // the handler never sees an untrustworthy request
    CHECK(stream.sent().starts_with("HTTP/1.1 400 Bad Request"));
    CHECK(stream.sent().find("Connection: close") != std::string::npos);
}

void test_handler_failure_becomes_500() {
    test::section("handler failure");

    ScriptedStream stream{"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"};

    auto handler = [](const Request&, auto&, std::span<const std::byte>) -> Task<Result<void>> {
        co_return fail(Errc::not_supported);
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(!served.has_value());
    CHECK(stream.sent().starts_with("HTTP/1.1 500 Internal Server Error"));
}

void test_clean_close_between_requests() {
    test::section("clean close between requests");

    // One request, then the peer hangs up without sending another. That is how
    // a keep-alive connection normally ends and must not be an error.
    ScriptedStream stream{"GET /only HTTP/1.1\r\nHost: x\r\n\r\n"};

    int calls = 0;
    auto handler =
        [&calls](const Request&, auto& writer, std::span<const std::byte>) -> Task<Result<void>> {
        ++calls;
        Response response;
        response.status = 200;
        co_return co_await writer.send(response, bytes_of("ok"));
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(served.has_value());
    CHECK(calls == 1);
}

void test_request_limit_closes_connection() {
    test::section("per-connection request limit");

    ServerOptions options;
    options.max_requests_per_connection = 2;

    std::string script;
    for (int i = 0; i < 5; ++i) {
        script += "GET /r HTTP/1.1\r\nHost: x\r\n\r\n";
    }
    ScriptedStream stream{script};

    int calls = 0;
    auto handler =
        [&calls](const Request&, auto& writer, std::span<const std::byte>) -> Task<Result<void>> {
        ++calls;
        Response response;
        response.status = 200;
        co_return co_await writer.send(response);
    };

    const Result<void> served = serve_connection(stream, handler, options).sync_get();
    CHECK(served.has_value());
    // An unbounded keep-alive connection is a resource one client can hold
    // forever, so the limit is enforced rather than advisory.
    CHECK(calls == 2);
    CHECK(stream.unread() > 0);
}

void test_double_send_refused() {
    test::section("one response per request");

    ScriptedStream stream{"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"};

    bool second_refused = false;
    auto handler = [&second_refused](const Request&,
                                     auto& writer,
                                     std::span<const std::byte>) -> Task<Result<void>> {
        Response response;
        response.status = 200;
        Result<void> first = co_await writer.send(response, bytes_of("a"));
        if (!first) {
            co_return fail(first.error());
        }
        // A second response would desynchronise the connection for good.
        Result<void> second = co_await writer.send(response, bytes_of("b"));
        second_refused = !second.has_value();
        co_return Result<void>{};
    };

    const Result<void> served = serve_connection(stream, handler).sync_get();
    CHECK(served.has_value());
    CHECK(second_refused);
    CHECK(count_occurrences(stream.sent(), "HTTP/1.1 200 OK") == 1);
}

void test_truncated_head_and_zero_read_policy() {
    test::section("truncated heads are not clean idle closes");
    int calls = 0;
    auto handler =
        [&calls](const Request&, auto& writer, std::span<const std::byte>) -> Task<Result<void>> {
        ++calls;
        co_return co_await writer.send(Response{});
    };
    for (const std::string_view partial :
         {"G", "GET / HTTP/1.1\r\n", "GET / HTTP/1.1\r\nHost: x\r\n"}) {
        ScriptedStream stream{std::string{partial}};
        const auto result = serve_connection(stream, handler).sync_get();
        CHECK(!result);
        CHECK(result.error() == Errc::eof);
    }
    CHECK(calls == 0);
    ScriptedStream idle{""};
    CHECK(serve_connection(idle, handler).sync_get().has_value());
    ScriptedStream pipeline{"GET / HTTP/1.1\r\nHost: x\r\n\r\nGET /incomplete HTTP/1.1\r\n"};
    CHECK(!serve_connection(pipeline, handler).sync_get());
    CHECK(calls == 1);
    ServerOptions options;
    options.read_chunk = 0;
    ScriptedStream empty{""};
    const auto invalid = serve_connection(empty, handler, options).sync_get();
    CHECK(!invalid);
    CHECK(invalid.error() == Errc::invalid_argument);
}

// ── timeouts ─────────────────────────────────────────────────────────────────

/// A stream that reports a timeout instead of producing bytes.
///
/// `serve_connection` turns its configured windows into deadlines and hands
/// them to the stream; whether the deadline is actually enforced is the event
/// loop's job and is tested there. What has to be tested *here* is the part
/// only this layer decides: which expiry is an ordinary end of connection and
/// which is a failure.
class TimingOutStream {
public:
    explicit TimingOutStream(std::string incoming) : incoming_(std::move(incoming)) {}

    Task<Result<std::size_t>> read_some(std::span<std::byte> destination,
                                        OperationOptions options = {}) {
        // Every read the connection loop issues must carry a deadline when one
        // is configured; a window that never reaches the stream is a window
        // that does nothing.
        saw_deadline_ = saw_deadline_ || options.deadline.has_value();
        if (read_pos_ >= incoming_.size()) {
            co_return fail(Errc::timed_out);
        }
        const std::size_t available = incoming_.size() - read_pos_;
        const std::size_t n = std::min(available, destination.size());
        std::memcpy(destination.data(), incoming_.data() + read_pos_, n);
        read_pos_ += n;
        co_return n;
    }

    Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                         OperationOptions = {}) {
        outgoing_.append(reinterpret_cast<const char*>(source.data()), source.size());
        co_return source.size();
    }

    [[nodiscard]] bool saw_deadline() const noexcept { return saw_deadline_; }
    [[nodiscard]] const std::string& sent() const noexcept { return outgoing_; }

private:
    std::string incoming_;
    std::string outgoing_;
    std::size_t read_pos_ = 0;
    bool saw_deadline_ = false;
};

void test_timeout_windows() {
    test::section("idle expiry ends a connection; request expiry fails it");

    auto handler =
        [](const Request&, auto& writer, std::span<const std::byte>) -> Task<Result<void>> {
        co_return co_await writer.send(Response{});
    };

    ServerOptions options;
    options.idle_timeout = std::chrono::seconds{30};
    options.request_timeout = std::chrono::seconds{30};

    // Nothing ever arrives. An idle keep-alive connection that goes quiet and
    // is closed is how one normally ends, so this succeeds — the same answer a
    // polite close gets.
    TimingOutStream idle{""};
    const Result<void> idle_result = serve_connection(idle, handler, options).sync_get();
    CHECK(idle_result.has_value());
    CHECK(idle.saw_deadline());

    // A request that begins and then stalls is a different thing: the peer ran
    // out of time mid-message, and the message is now truncated.
    TimingOutStream stalled{"GET / HTTP/1.1\r\nHost: x\r\n"};
    const Result<void> stalled_result = serve_connection(stalled, handler, options).sync_get();
    CHECK(!stalled_result);
    CHECK(stalled_result.error() == Errc::timed_out);
    // No 408: writing one needs the stream under the deadline that just
    // expired, so the attempt could only fail.
    CHECK(stalled.sent().empty());

    // The same stall, with the windows disabled, is indistinguishable from any
    // other stream error — the timeout is the stream's, not the server's.
    ServerOptions unbounded;
    TimingOutStream no_windows{"GET / HTTP/1.1\r\nHost: x\r\n"};
    const Result<void> unbounded_result =
        serve_connection(no_windows, handler, unbounded).sync_get();
    CHECK(!unbounded_result);
    CHECK(unbounded_result.error() == Errc::timed_out);
    CHECK(!no_windows.saw_deadline());
}

/// Logs the deadline handed to every single read and write.
///
/// One byte per read on purpose: a request that arrives in one read never
/// exercises the transition from the idle window to the request window,
/// because the transition happens *after* the first byte.
class RecordingStream {
public:
    RecordingStream(std::string incoming,
                    std::vector<std::optional<Clock::time_point>>& reads,
                    std::vector<std::optional<Clock::time_point>>& writes)
        : incoming_(std::move(incoming)), reads_(&reads), writes_(&writes) {}

    Task<Result<std::size_t>> read_some(std::span<std::byte> destination,
                                        OperationOptions options = {}) {
        reads_->push_back(options.deadline);
        if (read_pos_ >= incoming_.size() || destination.empty()) {
            co_return fail(Errc::eof);
        }
        destination[0] = static_cast<std::byte>(incoming_[read_pos_]);
        ++read_pos_;
        co_return std::size_t{1};
    }

    Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                         OperationOptions options = {}) {
        writes_->push_back(options.deadline);
        co_return source.size();
    }

private:
    std::string incoming_;
    std::vector<std::optional<Clock::time_point>>* reads_;
    std::vector<std::optional<Clock::time_point>>* writes_;
    std::size_t read_pos_ = 0;
};

void test_request_budget_is_per_request() {
    test::section("the idle window covers waiting; the request window covers the exchange");

    // Deliberately far apart, so that which window produced a given deadline
    // can be read off its magnitude. Equal windows would make the two
    // indistinguishable and the test would pass whatever the code did.
    const auto idle = std::chrono::hours{1};
    const auto request = std::chrono::hours{5};
    const auto boundary = Clock::now() + std::chrono::hours{3};

    std::vector<std::optional<Clock::time_point>> reads;
    std::vector<std::optional<Clock::time_point>> writes;

    auto handler =
        [](const Request&, auto& writer, std::span<const std::byte>) -> Task<Result<void>> {
        co_return co_await writer.send(Response{});
    };

    ServerOptions options;
    options.idle_timeout = idle;
    options.request_timeout = request;

    RecordingStream stream{"GET /one HTTP/1.1\r\nHost: x\r\n\r\n", reads, writes};
    const Result<void> served = serve_connection(stream, handler, options).sync_get();
    CHECK(served.has_value());

    CHECK(reads.size() > 1);
    CHECK(!writes.empty());

    // Every operation carries a deadline: a configured window that fails to
    // reach the stream is a window that does nothing.
    bool all_reads_bounded = !reads.empty();
    for (const auto& deadline : reads) {
        all_reads_bounded = all_reads_bounded && deadline.has_value();
    }
    CHECK(all_reads_bounded);

    bool all_writes_bounded = !writes.empty();
    for (const auto& deadline : writes) {
        all_writes_bounded = all_writes_bounded && deadline.has_value();
    }
    CHECK(all_writes_bounded);

    // The first read is the connection waiting, so it is on the idle window.
    CHECK(reads.front().has_value());
    if (reads.front()) {
        CHECK(*reads.front() < boundary);
    }

    // Once a byte has arrived the request's own window takes over — which is
    // the whole reason these are durations rather than one deadline for the
    // connection.
    bool some_read_on_request_window = false;
    for (const auto& deadline : reads) {
        some_read_on_request_window = some_read_on_request_window || (deadline && *deadline > boundary);
    }
    CHECK(some_read_on_request_window);

    // And the response is part of that same exchange: a budget that bounded
    // the reading but not the writing would bound half of it.
    bool writes_on_request_window = !writes.empty();
    for (const auto& deadline : writes) {
        writes_on_request_window = writes_on_request_window && deadline && *deadline > boundary;
    }
    CHECK(writes_on_request_window);
}

}  // namespace

int main() {
    test_response_head();
    test_bodyless_statuses();
    test_response_splitting_rejected();
    test_serializer_owns_framing();
    test_chunk_framing();
    test_keep_alive_rules();

    test_shared_buffer_budget();
    test_single_exchange();
    test_keep_alive_pipeline();
    test_handler_exception_is_contained();
    test_body_is_drained_even_if_ignored();
    test_body_delivered_to_handler();
    test_chunked_request_body();
    test_head_request_withholds_body();
    test_streaming_response();
    test_malformed_request_gets_400_then_closes();
    test_handler_failure_becomes_500();
    test_clean_close_between_requests();
    test_request_limit_closes_connection();
    test_double_send_refused();
    test_truncated_head_and_zero_read_policy();
    test_timeout_windows();
    test_request_budget_is_per_request();

    return test::summary();
}