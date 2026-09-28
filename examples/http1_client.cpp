// Usage: mira_http1_client <port> [timeout-ms]
// Pairs with mira_hello_world_server for two HTTP/1.1 requests on one TCP connection.
#include <mira/core/event_loop.hpp>
#include <mira/http/client.hpp>
#include <mira/transport/tcp.hpp>

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <system_error>

namespace tcp = Mira::transport::tcp;
using Mira::Result;
using Mira::Task;

namespace {
template <typename Integer>
bool parse_number(std::string_view text, Integer& value) {
    if (text.empty()) return false;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc{} && end == text.data() + text.size();
}

Task<Result<void>> exchange(Mira::EventLoop& loop, std::uint16_t port, unsigned timeout_ms) {
    const auto endpoint = Mira::transport::Endpoint::loopback(port);
    const Mira::OperationOptions io{
        .deadline = Mira::Clock::now() + std::chrono::milliseconds(timeout_ms)};
    auto socket = co_await tcp::connect(loop, endpoint, {}, io);
    if (!socket) co_return Mira::fail(socket.error());
    Mira::http::ClientConnection client{*socket};
    for (unsigned index = 1; index <= 2; ++index) {
        Mira::http::Request request;
        request.target = "/";
        request.headers.append("Host", endpoint.to_string());
        const auto started = co_await client.start(request, {}, io);
        if (!started) co_return Mira::fail(started.error());
        const auto status = client.response().status;
        std::string body;
        // Drain to an empty chunk before reusing or destroying ClientConnection.
        for (;;) {
            const auto chunk = co_await client.read_body();
            if (!chunk) co_return Mira::fail(chunk.error());
            if (chunk->empty()) break;
            body.append(reinterpret_cast<const char*>(chunk->data()), chunk->size());
        }
        if (status != 200 || body != "hello from Mira's HTTP server" || !client.reusable()) {
            std::fprintf(stderr, "HTTP response mismatch or connection not reusable\n");
            co_return Mira::fail(Mira::Errc::invalid_argument);
        }
        std::printf("HTTP/1.1 response %u: %u; body=%s\n", index, status, body.c_str());
    }
    std::printf("HTTP/1.1 keep-alive OK: 2 requests on one connection\n");
    co_return Result<void>{};
}

Task<void> run(Mira::EventLoop& loop, std::uint16_t port, unsigned timeout_ms,
               Result<void>& result) {
    result = co_await exchange(loop, port, timeout_ms);
}
}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    unsigned timeout_ms = 3000;
    if (argc < 2 || argc > 3 || !parse_number(argv[1], port) || port == 0 ||
        (argc > 2 && (!parse_number(argv[2], timeout_ms) || timeout_ms == 0 ||
                      timeout_ms > 600000))) {
        std::fprintf(stderr, "usage: %s <port: 1..65535> [timeout-ms: 1..600000]\n", argv[0]);
        return 2;
    }
#ifdef SIGPIPE
    if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        std::fprintf(stderr, "could not ignore SIGPIPE\n");
        return 1;
    }
#endif
    auto loop = Mira::EventLoop::create();
    if (!loop) {
        std::fprintf(stderr, "event loop: %s\n", loop.error().message().c_str());
        return 1;
    }
    Result<void> result;
    const auto ran = loop->run_until_complete(run(*loop, port, timeout_ms, result));
    if (!ran || !result) {
        std::fprintf(stderr, "HTTP client: %s\n", (!ran ? ran.error() : result.error()).message().c_str());
        return 1;
    }
    return 0;
}
