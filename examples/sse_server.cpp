// Finite Server-Sent Events over existing chunked HTTP, not a new transport.
// Usage: mira_sse_server [port=0] [connections=0]; zero connections serves forever.
#include <mira/core/event_loop.hpp>
#include <mira/http/connection.hpp>
#include <mira/transport/tcp.hpp>

#include <charconv>
#include <chrono>
#include <cstdio>
#include <string>
#include <string_view>

using namespace std::chrono_literals;
namespace {
std::span<const std::byte> bytes(std::string_view text) {
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}
Mira::Task<Mira::Result<void>> events(Mira::EventLoop& loop,
    const Mira::http::Request& request, auto& writer, std::span<const std::byte>) {
    Mira::http::Response response;
    if (request.method != Mira::http::Method::get || request.target != "/events") {
        response.status = 404;
        co_return co_await writer.send(response, bytes("not found"));
    }
    unsigned last = 0;
    if (auto value = request.headers.get("Last-Event-ID")) {
        const auto [end, error] = std::from_chars(value->data(), value->data() + value->size(), last);
        if (error != std::errc{} || end != value->data() + value->size() || last > 1000000) {
            response.status = 400;
            co_return co_await writer.send(response, bytes("invalid Last-Event-ID"));
        }
    }
    response.headers.append("Content-Type", "text/event-stream; charset=utf-8");
    response.headers.append("Cache-Control", "no-cache");
    auto head = co_await writer.send_head_chunked(response);
    if (!head) co_return head;
    auto retry = co_await writer.write(bytes("retry: 1000\n: connected\n\n"));
    if (!retry) co_return retry;
    for (unsigned i = 1; i <= 3; ++i) {
        const auto id = std::to_string(last + i);
        const std::string event = "id: " + id + "\nevent: tick\ndata: event " + id + "\n\n";
        auto sent = co_await writer.write(bytes(event));
        if (!sent) co_return sent;
        auto paused = co_await loop.sleep_for(20ms);
        if (!paused) co_return paused;
    }
    co_return co_await writer.finish();
}
Mira::Task<void> run(Mira::EventLoop& loop, Mira::transport::tcp::Listener& listener,
                     unsigned connections, int& status) {
    for (unsigned served = 0; !connections || served < connections; ++served) {
        auto accepted = co_await listener.accept({.deadline = Mira::Clock::now() + 30s});
        if (!accepted) {
            std::fprintf(stderr, "accept: %s\n", accepted.error().message().c_str());
            co_return;
        }
        auto handler = [&loop](const Mira::http::Request& request, auto& writer,
                              std::span<const std::byte> body) {
            // Non-coroutine lambda: the named coroutine owns all borrowed parameters.
            return events(loop, request, writer, body);
        };
        Mira::http::ServerOptions options;
        options.idle_timeout = 2s;
        options.request_timeout = 5s;
        const auto result = co_await Mira::http::serve_connection(*accepted, handler, options);
        if (!result) {
            std::fprintf(stderr, "HTTP: %s\n", result.error().message().c_str());
            co_return;
        }
    }
    status = 0;
}
}
int main(int argc, char** argv) {
    unsigned values[]{0, 0};
    if (argc > 3) return 2;
    for (int i = 1; i < argc; ++i) {
        const std::string_view text{argv[i]};
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), values[i - 1]);
        if (error != std::errc{} || end != text.data() + text.size()) return 2;
    }
    if (values[0] > 65535 || values[1] > 1000000) return 2;
    auto loop = Mira::EventLoop::create();
    if (!loop) return 1;
    auto listener = Mira::transport::tcp::Listener::bind(
        *loop, Mira::transport::Endpoint::loopback(static_cast<std::uint16_t>(values[0])));
    if (!listener) return 1;
    std::printf("PORT=%u\n", static_cast<unsigned>(listener->local_endpoint().port()));
    std::fflush(stdout);
    int status = 1;
    auto result = loop->run_until_complete(run(*loop, *listener, values[1], status));
    return result ? status : 1;
}
