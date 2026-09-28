// Usage: mira_udp_client <port> [message] [timeout-ms]
// An empty message tests zero-byte UDP datagrams; UDP has no EOF semantics.
#include <mira/core/event_loop.hpp>
#include <mira/transport/udp.hpp>

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>
#include <system_error>

namespace udp = Mira::transport::udp;
using Mira::Result;
using Mira::Task;

namespace {
template <typename Integer>
bool parse_number(std::string_view text, Integer& value) {
    if (text.empty()) return false;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc{} && end == text.data() + text.size();
}

Task<Result<void>> exchange(udp::Socket& socket, std::uint16_t port,
                            std::string_view message, unsigned timeout_ms) {
    const auto peer = Mira::transport::Endpoint::loopback(port);
    const Mira::OperationOptions io{
        .deadline = Mira::Clock::now() + std::chrono::milliseconds(timeout_ms)};
    const auto sent = co_await socket.send_to(
        std::as_bytes(std::span{message.data(), message.size()}), peer, io);
    if (!sent) co_return Mira::fail(sent.error());
    if (*sent != message.size()) co_return Mira::fail(Mira::Errc::invalid_argument);
    std::array<std::byte, 65507> buffer{};
    const auto received = co_await socket.receive_from(buffer, io);
    if (!received) co_return Mira::fail(received.error());
    const std::string_view response{reinterpret_cast<const char*>(buffer.data()), received->size};
    if (received->peer != peer || response != message) {
        std::fprintf(stderr, "UDP echo mismatch (peer or payload)\n");
        co_return Mira::fail(Mira::Errc::invalid_argument);
    }
    std::printf("UDP echo OK: %zu bytes; response=", response.size());
    if (!response.empty()) std::fwrite(response.data(), 1, response.size(), stdout);
    std::putchar('\n');
    co_return Result<void>{};
}

Task<void> run(udp::Socket& socket, std::uint16_t port, std::string_view message,
               unsigned timeout_ms, Result<void>& result) {
    result = co_await exchange(socket, port, message, timeout_ms);
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
    const std::string_view message = argc > 2 ? argv[2] : "hello from Mira UDP client";
    if (message.size() > 65507) {
        std::fprintf(stderr, "message exceeds the IPv4 UDP payload limit (65507 bytes)\n");
        return 2;
    }
    auto loop = Mira::EventLoop::create();
    if (!loop) {
        std::fprintf(stderr, "event loop: %s\n", loop.error().message().c_str());
        return 1;
    }
    auto socket = udp::Socket::bind(*loop, Mira::transport::Endpoint::loopback(0));
    if (!socket) {
        std::fprintf(stderr, "bind: %s\n", socket.error().message().c_str());
        return 1;
    }
    Result<void> result;
    const auto ran = loop->run_until_complete(run(*socket, port, message, timeout_ms, result));
    if (!ran || !result) {
        std::fprintf(stderr, "UDP client: %s\n", (!ran ? ran.error() : result.error()).message().c_str());
        return 1;
    }
    return 0;
}
