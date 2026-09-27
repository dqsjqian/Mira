#include "check.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/http/client.hpp"
#include "mira/http/connection.hpp"
#include "mira/transport/tcp.hpp"

#include <array>
#include <cstring>
#include <string>
#include <vector>

#define CHECK_VALUE(expr) CHECK(static_cast<bool>(expr))

using namespace Mira;
using namespace Mira::http;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {
std::span<const std::byte> bytes(std::string_view value) {
    return {reinterpret_cast<const std::byte*>(value.data()), value.size()};
}
std::string text(std::span<const std::byte> value) {
    return {reinterpret_cast<const char*>(value.data()), value.size()};
}
Request request(Method method = Method::get) {
    Request result;
    result.method = method;
    result.target = "/test";
    result.headers.append("Host", "localhost");
    return result;
}
struct Script {
    std::string input;
    std::string output;
    std::size_t offset{0};
    std::size_t chunk{1};
    std::size_t max_read{0};
    std::vector<OperationOptions> seen;
    Task<Result<std::size_t>> read_some(std::span<std::byte> dest, OperationOptions io = {}) {
        seen.push_back(io);
        max_read = std::max(max_read, dest.size());
        if (offset == input.size()) co_return fail(Errc::eof);
        const auto count = std::min({dest.size(), input.size() - offset, chunk});
        std::memcpy(dest.data(), input.data() + offset, count);
        offset += count;
        co_return count;
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> src, OperationOptions io = {}) {
        seen.push_back(io);
        const auto count = std::min(src.size(), chunk);
        output += text(src.first(count));
        co_return count;
    }
};
Task<void> scripted() {
    test::section("short reads and writes, 1xx, true streaming reads, absolute deadlines");
    Script stream;
    stream.input = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nX: y\r\n\r\n"
                   "HTTP/1.1 200 OK\r\nTransfer-Encoding: "
                   "chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\nX-End: yes\r\n\r\n";
    std::stop_source stop;
    const auto deadline = Clock::now() + 10s;
    ClientConnection client{stream};
    auto req = request(Method::post);
    auto started = co_await client.start(
        req, bytes("upload"), {.stop = stop.get_token(), .deadline = deadline});
    CHECK_VALUE(started);
    CHECK_VALUE(client.response().status == 200);
    CHECK_VALUE(stream.offset < stream.input.size());
    CHECK_VALUE(stream.output ==
                "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\n\r\nupload");
    CHECK_VALUE(!(co_await client.start(req)));
    std::string body;
    for (;;) {
        auto piece = co_await client.read_body();
        CHECK_VALUE(piece);
        if (!piece || piece->empty()) break;
        CHECK_VALUE(piece->size() == 1);
        body += text(*piece);
    }
    CHECK_VALUE(body == "abcdef");
    CHECK_VALUE(client.trailers().get("X-End") == "yes");
    CHECK_VALUE(client.reusable());
    for (const auto& io : stream.seen) {
        CHECK_VALUE(io.deadline == deadline);
        CHECK_VALUE(io.stop == stop.get_token());
    }

    test::section("sequential reuse and HEAD framing");
    stream.input += "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n";
    req.method = Method::head;
    CHECK_VALUE(co_await client.start(req));
    auto piece = co_await client.read_body();
    CHECK_VALUE(piece && piece->empty());
    CHECK_VALUE(client.reusable());
    stream.input +=
        "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n";
    CHECK_VALUE(co_await client.start(req));
    piece = co_await client.read_body();
    CHECK_VALUE(piece && piece->empty());
    CHECK_VALUE(!client.reusable());
    CHECK_VALUE(!(co_await client.start(req)));
}
Task<void> limits_and_errors() {
    test::section("no reuse after error, EOF, cancellation, and all resource budgets");
    const std::vector<std::string> broken{
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
        "HTTP/1.1 101 Switching Protocols\r\n\r\ntunnel",
        "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n"};
    auto req = request();
    for (const auto& input : broken) {
        Script stream;
        stream.input = input;
        ClientConnection client{stream};
        auto result = co_await client.start(req);
        bool error = !result;
        while (result) {
            auto piece = co_await client.read_body();
            if (!piece) {
                error = true;
                break;
            }
            if (piece->empty()) break;
        }
        CHECK_VALUE(error);
        CHECK_VALUE(!client.reusable());
        CHECK_VALUE(!(co_await client.start(req)));
    }
    Script stream;
    stream.input = "HTTP/1.0 200 OK\r\n\r\neof body";
    ClientConnection client{stream};
    CHECK_VALUE(co_await client.start(req));
    std::string body;
    for (;;) {
        auto piece = co_await client.read_body();
        CHECK_VALUE(piece);
        if (!piece || piece->empty()) break;
        body += text(*piece);
    }
    CHECK_VALUE(body == "eof body");
    CHECK_VALUE(!client.reusable());

    Script limited;
    limited.input = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n";
    ClientOptions options;
    options.max_informational_responses = 1;
    ClientConnection infos{limited, options};
    auto result = co_await infos.start(req);
    CHECK_VALUE(!result && result.error() == Errc::limit_exceeded);

    Script big;
    big.input = "HTTP/1.1 200 " + std::string(1000, 'x');
    big.chunk = 1000;
    options = {};
    options.max_buffer_size = 32;
    options.read_chunk = 4096;
    ClientConnection bounded{big, options};
    result = co_await bounded.start(req);
    CHECK_VALUE(!result && result.error() == Errc::limit_exceeded);
    CHECK_VALUE(big.max_read <= 32);
    CHECK_VALUE(big.offset == 32);

    Script pending;
    pending.input = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    pending.chunk = 4096;
    std::stop_source stop;
    ClientConnection cancelled{pending};
    CHECK_VALUE(co_await cancelled.start(req, {}, {.stop = stop.get_token()}));
    stop.request_stop();
    auto piece = co_await cancelled.read_body();
    CHECK_VALUE(!piece && piece.error() == Errc::cancelled);
    CHECK_VALUE(!cancelled.reusable());

    Script stopped;
    ClientConnection pre_cancelled{stopped};
    result = co_await pre_cancelled.start(req, {}, {.stop = stop.get_token()});
    CHECK_VALUE(!result && result.error() == Errc::cancelled);
    CHECK_VALUE(stopped.output.empty());
    ClientConnection expired{stopped};
    result = co_await expired.start(req, {}, {.deadline = Clock::now() - 1s});
    CHECK_VALUE(!result && result.error() == Errc::timed_out);
    CHECK_VALUE(stopped.output.empty());

    Script timed;
    timed.input = "HTTP/1.1 204 X\r\n\r\n";
    options = {};
    options.request_timeout = 1s;
    ClientConnection timed_client{timed, options};
    const auto earlier = Clock::now();
    CHECK_VALUE(co_await timed_client.start(req, {}, {.deadline = earlier + 10s}));
    CHECK_VALUE(!timed.seen.empty());
    CHECK_VALUE(timed.seen.front().deadline <= earlier + 2s);
    for (const auto& io : timed.seen)
        CHECK_VALUE(io.deadline == timed.seen.front().deadline);
    CHECK_VALUE(co_await timed_client.read_body());

    Script early;
    early.input = "HTTP/1.1 204 X\r\n\r\n";
    ClientConnection earlier_client{early, options};
    const auto short_deadline = Clock::now() + 500ms;
    CHECK_VALUE(co_await earlier_client.start(req, {}, {.deadline = short_deadline}));
    for (const auto& io : early.seen)
        CHECK_VALUE(io.deadline == short_deadline);
    CHECK_VALUE(co_await earlier_client.read_body());

    Script overflow;
    overflow.chunk = 4096;
    overflow.input = "HTTP/1.1 204 X\r\n\r\nHTTP/1.1 200 injected\r\n\r\n";
    ClientConnection unexpected{overflow};
    CHECK_VALUE(co_await unexpected.start(req));
    CHECK_VALUE(co_await unexpected.read_body());
    CHECK_VALUE(!unexpected.reusable());
}

struct FragmentedSocket {
    tcp::Socket& socket;
    Task<Result<std::size_t>> read_some(std::span<std::byte> dst, OperationOptions io = {}) {
        co_return co_await socket.read_some(dst.first(std::min<std::size_t>(dst.size(), 3)), io);
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> src, OperationOptions io = {}) {
        co_return co_await socket.write_some(src.first(std::min<std::size_t>(src.size(), 2)), io);
    }
};
Task<void> loopback(EventLoop& loop) {
    test::section("real TCP client/server, deterministic fragmentation, and keep-alive");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK_VALUE(listener);
    if (!listener) co_return;
    const auto deadline = Clock::now() + 5s;
    auto server = [&]() -> Task<void> {
        auto accepted = co_await listener->accept({.deadline = deadline});
        CHECK_VALUE(accepted);
        if (!accepted) co_return;
        FragmentedSocket peer{*accepted};
        auto handler = [](const Request& req,
                          auto& writer,
                          std::span<const std::byte> body) -> Task<Result<void>> {
            CHECK_VALUE(req.target == "/test");
            Response response;
            if (req.method == Method::post) {
                CHECK_VALUE(text(body) == "upload");
                co_return co_await writer.send(response, bytes("posted"));
            }
            if (req.method == Method::head)
                co_return co_await writer.send(response, bytes("hidden"));
            auto result = co_await writer.send_head_chunked(response);
            if (!result) co_return result;
            result = co_await writer.write(bytes("chunk1"));
            if (!result) co_return result;
            co_return co_await writer.write(bytes("chunk2"));
        };
        ServerOptions options;
        options.max_requests_per_connection = 3;
        options.request_timeout = 5s;
        CHECK_VALUE(co_await serve_connection(peer, handler, options));
    };
    auto client = [&]() -> Task<void> {
        auto connected =
            co_await tcp::connect(loop, listener->local_endpoint(), {}, {.deadline = deadline});
        CHECK_VALUE(connected);
        if (!connected) co_return;
        FragmentedSocket peer{*connected};
        ClientConnection connection{peer};
        for (auto method : {Method::post, Method::head, Method::get}) {
            auto req = request(method);
            CHECK_VALUE(co_await connection.start(
                req, method == Method::post ? bytes("upload") : bytes(""), {.deadline = deadline}));
            std::string body;
            for (;;) {
                auto piece = co_await connection.read_body();
                CHECK_VALUE(piece);
                if (!piece || piece->empty()) break;
                body += text(*piece);
            }
            CHECK_VALUE(body == (method == Method::post   ? "posted"
                                 : method == Method::head ? ""
                                                          : "chunk1chunk2"));
        }
    };
    TaskScope scope;
    scope.spawn(server());
    scope.spawn(client());
    co_await scope.join();
}
Task<void> tcp_cancel(EventLoop& loop, bool timeout, bool server_side) {
    test::section(server_side ? "server-side external cancellation"
                  : timeout   ? "TCP pending-read overall deadline"
                              : "TCP pending-read active cancellation");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK_VALUE(listener);
    if (!listener) co_return;
    std::stop_source stop;
    std::stop_source release;
    auto server = [&]() -> Task<void> {
        auto accepted = co_await listener->accept({.deadline = Clock::now() + 5s});
        CHECK_VALUE(accepted);
        if (!accepted) co_return;
        if (server_side) {
            auto handler =
                [](const Request&, auto&, std::span<const std::byte>) -> Task<Result<void>> {
                co_return Result<void>{};
            };
            ServerOptions options;
            options.stop = stop.get_token();
            auto result = co_await serve_connection(*accepted, handler, options);
            CHECK_VALUE(!result && result.error() == Errc::cancelled);
        } else {
            std::array<std::byte, 1024> buffer;
            std::string request_bytes;
            while (request_bytes.find("\r\n\r\n") == std::string::npos) {
                auto n = co_await accepted->read_some(buffer, {.deadline = Clock::now() + 5s});
                CHECK_VALUE(n);
                if (!n) co_return;
                request_bytes += text(std::span<const std::byte>{buffer}.first(*n));
            }
            CHECK_VALUE(co_await write_all(*accepted,
                                           bytes("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")));
            static_cast<void>(co_await loop.sleep_for(5s, {.stop = release.get_token()}));
        }
    };
    auto client = [&]() -> Task<void> {
        auto connected = co_await tcp::connect(loop, listener->local_endpoint());
        CHECK_VALUE(connected);
        if (!connected) co_return;
        if (server_side) {
            CHECK_VALUE(co_await loop.sleep_for(10ms));
            stop.request_stop();
            // Keep the connection open until the server has observed the
            // cancellation. Ending the coroutine right away destroys the
            // socket, and on Linux epoll the resulting EOF can be delivered
            // to the parked server read *before* the cancellation, which
            // turns the external stop into an ordinary between-requests
            // close — a valid outcome, but not the one under test.
            static_cast<void>(co_await loop.sleep_for(100ms));
        } else {
            ClientConnection connection{*connected};
            auto req = request();
            CHECK_VALUE(co_await connection.start(
                req,
                {},
                {.stop = stop.get_token(), .deadline = Clock::now() + (timeout ? 30ms : 5s)}));
            TaskScope cancel_scope;
            auto cancel = [&]() -> Task<void> {
                CHECK_VALUE(co_await loop.sleep_for(10ms));
                stop.request_stop();
            };
            if (!timeout) cancel_scope.spawn(cancel());
            auto piece = co_await connection.read_body();
            CHECK_VALUE(!piece && piece.error() == (timeout ? Errc::timed_out : Errc::cancelled));
            CHECK_VALUE(!connection.reusable());
            release.request_stop();
            co_await cancel_scope.join();
        }
    };
    TaskScope scope;
    scope.spawn(server());
    scope.spawn(client());
    co_await scope.join();
}
Task<void> raw_loopback(EventLoop& loop) {
    test::section("real TCP raw response interop and negative tests");
    const std::vector<std::string> wires{
        "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.0 200 OK\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n"};
    for (std::size_t index = 0; index < wires.size(); ++index) {
        auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
        CHECK_VALUE(listener);
        if (!listener) co_return;
        const auto deadline = Clock::now() + 5s;
        auto server = [&]() -> Task<void> {
            auto accepted = co_await listener->accept({.deadline = deadline});
            CHECK_VALUE(accepted);
            if (!accepted) co_return;
            std::string input;
            std::array<std::byte, 256> scratch;
            while (input.find("\r\n\r\n") == std::string::npos) {
                auto n = co_await accepted->read_some(scratch, {.deadline = deadline});
                CHECK_VALUE(n);
                if (!n) co_return;
                input += text(std::span<const std::byte>{scratch}.first(*n));
            }
            CHECK_VALUE(co_await write_all(*accepted, bytes(wires[index]), {.deadline = deadline}));
        };
        auto client = [&]() -> Task<void> {
            auto connected =
                co_await tcp::connect(loop, listener->local_endpoint(), {}, {.deadline = deadline});
            CHECK_VALUE(connected);
            if (!connected) co_return;
            FragmentedSocket fragmented{*connected};
            ClientOptions options;
            options.limits.max_body_size = 16;
            ClientConnection connection{fragmented, options};
            auto req = request();
            auto result = co_await connection.start(req, {}, {.deadline = deadline});
            Error error = result ? Error{} : result.error();
            std::string body;
            while (!error) {
                auto piece = co_await connection.read_body();
                if (!piece) {
                    error = piece.error();
                    break;
                }
                if (piece->empty()) break;
                body += text(*piece);
            }
            if (index < 2) {
                CHECK_VALUE(!error);
                CHECK_VALUE(body == "ok");
            } else if (index < 4) {
                CHECK_VALUE(error == Errc::eof);
                CHECK_VALUE(!connection.reusable());
            } else {
                CHECK_VALUE(error == ParseError::limit_exceeded);
                CHECK_VALUE(!connection.reusable());
            }
        };
        TaskScope scope;
        scope.spawn(server());
        scope.spawn(client());
        co_await scope.join();
    }
}
Task<void> root(EventLoop& loop) {
    co_await raw_loopback(loop);
    co_await scripted();
    co_await limits_and_errors();
    co_await loopback(loop);
    co_await tcp_cancel(loop, false, false);
    co_await tcp_cancel(loop, true, false);
    co_await tcp_cancel(loop, false, true);
}
}  // namespace
int main() {
    auto loop = EventLoop::create();
    CHECK_VALUE(loop);
    if (loop) CHECK_VALUE(loop->run_until_complete(root(*loop)));
    return test::summary();
}
