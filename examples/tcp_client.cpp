// Usage: mira_tcp_client <port> [message] [timeout-ms]
// Pairs with mira_echo_server; connect, send and read share one absolute deadline.
#include <mira/core/event_loop.hpp>
#include <mira/core/stream.hpp>
#include <mira/transport/tcp.hpp>

#include <array>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
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

Task<Result<void>> exchange(Mira::EventLoop& loop, std::uint16_t port,
                            std::string_view message, unsigned timeout_ms) {
    const Mira::OperationOptions io{
        .deadline = Mira::Clock::now() + std::chrono::milliseconds(timeout_ms)};
    auto socket = co_await tcp::connect(loop, Mira::transport::Endpoint::loopback(port), {}, io);
    if (!socket) co_return Mira::fail(socket.error());
    const auto sent = co_await Mira::write_all(
        *socket, std::as_bytes(std::span{message.data(), message.size()}), io);
    if (!sent) co_return Mira::fail(sent.error());
    const auto shutdown = socket->shutdown_send();
    if (!shutdown) co_return Mira::fail(shutdown.error());

    std::array<std::byte, 4096> buffer{};
    std::size_t received = 0;
    for (;;) {
        const auto read = co_await socket->read_some(buffer, io);
        if (!read) {
            if (read.error() == Mira::Errc::eof) break;
            co_return Mira::fail(read.error());
        }
        const std::string_view chunk{reinterpret_cast<const char*>(buffer.data()), *read};
        if (chunk != message.substr(received, chunk.size())) {
            std::fprintf(stderr, "TCP echo mismatch\n");
            co_return Mira::fail(Mira::Errc::invalid_argument);
        }
        received += *read;
    }
    if (received != message.size()) {
        std::fprintf(stderr, "TCP echo was incomplete\n");
        co_return Mira::fail(Mira::Errc::eof);
    }
    std::printf("TCP echo OK: %zu bytes\n", received);
    co_return Result<void>{};
}

Task<void> run(Mira::EventLoop& loop, std::uint16_t port, std::string_view message,
               unsigned timeout_ms, Result<void>& result) {
    result = co_await exchange(loop, port, message, timeout_ms);
}
}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    unsigned timeout_ms = 3000;
    if (argc < 2 || argc > 4 || !parse_number(argv[1], port) || port == 0 ||
        (argc > 3 && (!parse_number(argv[3], timeout_ms) || timeout_ms == 0 ||
                      timeout_ms > 600000))) {
        std::fprintf(stderr, "usage: %s <port: 1..65535> [message] [timeout-ms: 1..600000]\n",
                     argv[0]);
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
    const std::string_view message = argc > 2 ? argv[2] : "hello from Mira TCP client";
    Result<void> result;
    const auto ran = loop->run_until_complete(run(*loop, port, message, timeout_ms, result));
    if (!ran || !result) {
        std::fprintf(stderr, "TCP client: %s\n", (!ran ? ran.error() : result.error()).message().c_str());
        return 1;
    }
    return 0;
}
