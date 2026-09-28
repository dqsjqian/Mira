#include <mira/core/event_loop.hpp>
#include <mira/core/stream.hpp>
#include <mira/core/task_scope.hpp>
#include <mira/http/client.hpp>
#include <mira/http/connection.hpp>
#include <mira/transport/tcp.hpp>
#include <mira/transport/udp.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>

namespace {
using Mira::Result;
using Mira::Task;
using Mira::transport::Endpoint;
using namespace std::chrono_literals;
namespace tcp = Mira::transport::tcp;
namespace udp = Mira::transport::udp;

constexpr std::string_view payload = "Mira device loopback smoke";

const char* platform_name() {
#if defined(MIRA_PLATFORM_IOS)
#if TARGET_OS_SIMULATOR
    return "ios-simulator";
#else
    return "ios-device";
#endif
#elif defined(MIRA_PLATFORM_MACOS)
    return "macos";
#elif defined(MIRA_PLATFORM_ANDROID)
    return "android";
#elif defined(MIRA_PLATFORM_WINDOWS)
    return "windows";
#else
    return "posix";
#endif
}

std::span<const std::byte> bytes(std::string_view text) {
    return std::as_bytes(std::span{text.data(), text.size()});
}

Mira::OperationOptions budget() {
    return {.deadline = Mira::Clock::now() + 3s};
}

Task<Result<void>> expect_payload(tcp::Socket& socket, Mira::OperationOptions io) {
    std::array<std::byte, payload.size()> buffer{};
    std::size_t used = 0;
    while (used < buffer.size()) {
        const auto read = co_await socket.read_some(std::span{buffer}.subspan(used), io);
        if (!read) co_return Mira::fail(read.error());
        if (*read == 0) co_return Mira::fail(Mira::Errc::eof);
        used += *read;
    }
    if (std::string_view{reinterpret_cast<const char*>(buffer.data()), used} != payload)
        co_return Mira::fail(Mira::Errc::invalid_argument);
    co_return Result<void>{};
}

Task<Result<void>> tcp_loopback(Mira::EventLoop& loop) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    if (!listener) co_return Mira::fail(listener.error());
    const auto io = budget();
    auto client = co_await tcp::connect(loop, listener->local_endpoint(), {}, io);
    if (!client) co_return Mira::fail(client.error());
    auto server = co_await listener->accept(io);
    if (!server) co_return Mira::fail(server.error());
    auto result = co_await Mira::write_all(*client, bytes(payload), io);
    if (!result) co_return result;
    result = co_await expect_payload(*server, io);
    if (!result) co_return result;
    result = co_await Mira::write_all(*server, bytes(payload), io);
    if (!result) co_return result;
    result = co_await expect_payload(*client, io);
    if (!result) co_return result;
    result = client->shutdown_send();
    if (!result) co_return result;
    std::array<std::byte, 1> buffer{};
    const auto eof = co_await server->read_some(buffer, io);
    if (eof || eof.error() != Mira::Errc::eof)
        co_return Mira::fail(Mira::Errc::invalid_argument);
    co_return Result<void>{};
}

Task<Result<void>> udp_loopback(Mira::EventLoop& loop) {
    auto client = udp::Socket::bind(loop, Endpoint::loopback(0));
    auto server = udp::Socket::bind(loop, Endpoint::loopback(0));
    if (!client) co_return Mira::fail(client.error());
    if (!server) co_return Mira::fail(server.error());
    const auto client_address = client->local_endpoint();
    const auto server_address = server->local_endpoint();
    if (!client_address) co_return Mira::fail(client_address.error());
    if (!server_address) co_return Mira::fail(server_address.error());
    const auto io = budget();
    for (const auto message : {payload, std::string_view{}}) {
        const auto sent = co_await client->send_to(bytes(message), *server_address, io);
        if (!sent) co_return Mira::fail(sent.error());
        if (*sent != message.size()) co_return Mira::fail(Mira::Errc::invalid_argument);
        std::array<std::byte, 128> buffer{};
        const auto received = co_await server->receive_from(buffer, io);
        if (!received) co_return Mira::fail(received.error());
        if (received->peer != *client_address || received->size != message.size() ||
            std::string_view{reinterpret_cast<const char*>(buffer.data()), received->size} != message)
            co_return Mira::fail(Mira::Errc::invalid_argument);
        const auto echoed = co_await server->send_to(
            std::span{buffer}.first(received->size), received->peer, io);
        if (!echoed) co_return Mira::fail(echoed.error());
        if (*echoed != message.size()) co_return Mira::fail(Mira::Errc::invalid_argument);
        const auto reply = co_await client->receive_from(buffer, io);
        if (!reply) co_return Mira::fail(reply.error());
        if (reply->peer != *server_address || reply->size != message.size() ||
            std::string_view{reinterpret_cast<const char*>(buffer.data()), reply->size} != message)
            co_return Mira::fail(Mira::Errc::invalid_argument);
    }
    co_return Result<void>{};
}

struct HttpHandler {
    unsigned* requests;

    Task<Result<void>> operator()(const Mira::http::Request& request,
                                 Mira::http::ResponseWriter<tcp::Socket>& writer,
                                 std::span<const std::byte> body) const {
        if (request.target != "/device-smoke" || !body.empty())
            co_return Mira::fail(Mira::Errc::invalid_argument);
        ++*requests;
        Mira::http::Response response;
        response.status = 200;
        co_return co_await writer.send(response, bytes(payload));
    }
};

Task<void> http_server(tcp::Listener& listener, Mira::OperationOptions io,
                       Result<void>& result, unsigned& requests) {
    auto socket = co_await listener.accept(io);
    if (!socket) {
        result = Mira::fail(socket.error());
        co_return;
    }
    Mira::http::ServerOptions options;
    options.max_requests_per_connection = 3;
    options.idle_timeout = 3s;
    options.request_timeout = 3s;
    result = co_await Mira::http::serve_connection(*socket, HttpHandler{&requests}, options);
}

Task<Result<void>> http_client(Mira::EventLoop& loop, Endpoint address,
                               Mira::OperationOptions io) {
    auto socket = co_await tcp::connect(loop, address, {}, io);
    if (!socket) co_return Mira::fail(socket.error());
    Mira::http::ClientConnection client{*socket};
    for (unsigned index = 0; index < 2; ++index) {
        Mira::http::Request request;
        request.target = "/device-smoke";
        request.headers.append("Host", address.to_string());
        const auto started = co_await client.start(request, {}, io);
        if (!started) co_return Mira::fail(started.error());
        std::string body;
        for (;;) {
            const auto chunk = co_await client.read_body();
            if (!chunk) co_return Mira::fail(chunk.error());
            if (chunk->empty()) break;
            if (chunk->size() > payload.size() - body.size())
                co_return Mira::fail(Mira::Errc::limit_exceeded);
            body.append(reinterpret_cast<const char*>(chunk->data()), chunk->size());
        }
        if (client.response().status != 200 || body != payload || !client.reusable())
            co_return Mira::fail(Mira::Errc::invalid_argument);
    }
    co_return Result<void>{};
}

Task<Result<void>> http_loopback(Mira::EventLoop& loop) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    if (!listener) co_return Mira::fail(listener.error());
    const auto io = budget();
    Result<void> server_result = Mira::fail(Mira::Errc::internal);
    unsigned requests = 0;
    Mira::TaskScope scope;
    scope.spawn(http_server(*listener, io, server_result, requests));
    const auto client_result = co_await http_client(loop, listener->local_endpoint(), io);
    co_await scope.join();
    if (!client_result) co_return client_result;
    if (!server_result) co_return server_result;
    if (requests != 2) co_return Mira::fail(Mira::Errc::invalid_argument);
    co_return Result<void>{};
}

Task<void> cancel_after(Mira::EventLoop& loop, std::stop_source source,
                        Result<void>& result) {
    result = co_await loop.sleep_for(20ms, budget());
    source.request_stop();
}

Task<Result<void>> pending_cancel(Mira::EventLoop& loop) {
    auto socket = udp::Socket::bind(loop, Endpoint::loopback(0));
    if (!socket) co_return Mira::fail(socket.error());
    std::stop_source source;
    Result<void> timer_result = Mira::fail(Mira::Errc::internal);
    Mira::TaskScope scope;
    scope.spawn(cancel_after(loop, source, timer_result));
    std::array<std::byte, 1> buffer{};
    const auto started = Mira::Clock::now();
    const Mira::OperationOptions io{.stop = source.get_token(), .deadline = started + 1s};
    const auto received = co_await socket->receive_from(buffer, io);
    co_await scope.join();
    if (!timer_result) co_return timer_result;
    if (received || received.error() != Mira::Errc::cancelled ||
        Mira::Clock::now() - started >= 1s)
        co_return Mira::fail(Mira::Errc::invalid_argument);
    co_return Result<void>{};
}

Task<Result<void>> accept_deadline(Mira::EventLoop& loop) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    if (!listener) co_return Mira::fail(listener.error());
    const auto started = Mira::Clock::now();
    const auto deadline = started + 20ms;
    const auto accepted = co_await listener->accept({.deadline = deadline});
    const auto finished = Mira::Clock::now();
    if (accepted || accepted.error() != Mira::Errc::timed_out ||
        finished < deadline || finished - started >= 1s)
        co_return Mira::fail(Mira::Errc::invalid_argument);
    co_return Result<void>{};
}

struct SmokeCase {
    const char* name;
    Task<Result<void>> (*run)(Mira::EventLoop&);
};

Task<void> run_cases(Mira::EventLoop& loop, unsigned& passed, unsigned& failed) {
    constexpr SmokeCase cases[] = {
        {"tcp_loopback", tcp_loopback},
        {"udp_loopback_and_empty_datagram", udp_loopback},
        {"http1_keepalive", http_loopback},
        {"pending_io_cancellation", pending_cancel},
        {"accept_deadline", accept_deadline},
    };
    for (const auto& test : cases) {
        const auto result = co_await test.run(loop);
        if (result) {
            ++passed;
            std::printf("MIRA_SMOKE_CASE %s PASS\n", test.name);
        } else {
            ++failed;
            std::printf("MIRA_SMOKE_CASE %s FAIL %s\n", test.name,
                        result.error().message().c_str());
        }
        std::fflush(stdout);
    }
}
}

extern "C" int mira_device_smoke() {
    unsigned passed = 0;
    unsigned failed = 0;
    try {
        auto loop = Mira::EventLoop::create();
        if (!loop) {
            ++failed;
            std::fprintf(stderr, "event loop: %s\n", loop.error().message().c_str());
        } else {
            const auto result = loop->run_until_complete(run_cases(*loop, passed, failed));
            if (!result || loop->outstanding() != 0) {
                ++failed;
                std::fprintf(stderr, "event loop failed or leaked outstanding work\n");
            }
        }
    } catch (const std::exception& error) {
        ++failed;
        std::fprintf(stderr, "smoke exception: %s\n", error.what());
    }
    std::printf("MIRA_DEVICE_SMOKE {\"platform\":\"%s\",\"backend\":\"%s\","
                "\"passed\":%u,\"failed\":%u}\n",
                platform_name(), Mira::io_backend_name(), passed, failed);
    std::fflush(stdout);
    return failed == 0 && passed == 5 ? 0 : 1;
}

#ifndef MIRA_DEVICE_SMOKE_EMBEDDED
int main() { return mira_device_smoke(); }
#endif
