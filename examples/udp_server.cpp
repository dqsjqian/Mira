// Usage: mira_udp_server [port] [datagram-limit] [timeout-ms]
// Loopback only; a zero datagram limit serves continuously, with per-datagram deadlines.
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

Task<Result<void>> serve(udp::Socket& socket, std::size_t limit, unsigned timeout_ms) {
    std::array<std::byte, 65507> buffer{};
    std::size_t served = 0;
    do {
        const Mira::OperationOptions io{
            .deadline = Mira::Clock::now() + std::chrono::milliseconds(timeout_ms)};
        const auto datagram = co_await socket.receive_from(buffer, io);
        if (!datagram) co_return Mira::fail(datagram.error());
        // size == 0 is a valid datagram and must receive a zero-byte reply.
        const auto sent = co_await socket.send_to(
            std::span{buffer}.first(datagram->size), datagram->peer, io);
        if (!sent) co_return Mira::fail(sent.error());
        if (*sent != datagram->size) co_return Mira::fail(Mira::Errc::invalid_argument);
        ++served;
    } while (limit == 0 || served < limit);
    std::printf("UDP server OK: %zu datagrams\n", served);
    co_return Result<void>{};
}

Task<void> run(udp::Socket& socket, std::size_t limit, unsigned timeout_ms,
               Result<void>& result) {
    result = co_await serve(socket, limit, timeout_ms);
}
}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    std::size_t limit = 0;
    unsigned timeout_ms = 30000;
    if (argc > 4 || (argc > 1 && !parse_number(argv[1], port)) ||
        (argc > 2 && !parse_number(argv[2], limit)) ||
        (argc > 3 && (!parse_number(argv[3], timeout_ms) || timeout_ms == 0 ||
                      timeout_ms > 600000))) {
        std::fprintf(stderr, "usage: %s [port: 0..65535] [datagram-limit] [timeout-ms: 1..600000]\n",
                     argv[0]);
        return 2;
    }
    auto loop = Mira::EventLoop::create();
    if (!loop) {
        std::fprintf(stderr, "event loop: %s\n", loop.error().message().c_str());
        return 1;
    }
    auto socket = udp::Socket::bind(*loop, Mira::transport::Endpoint::loopback(port));
    if (!socket) {
        std::fprintf(stderr, "bind: %s\n", socket.error().message().c_str());
        return 1;
    }
    const auto endpoint = socket->local_endpoint();
    if (!endpoint) {
        std::fprintf(stderr, "local endpoint: %s\n", endpoint.error().message().c_str());
        return 1;
    }
    std::printf("PORT=%u\n", static_cast<unsigned>(endpoint->port()));
    std::fflush(stdout);
    Result<void> result;
    const auto ran = loop->run_until_complete(run(*socket, limit, timeout_ms, result));
    if (!ran || !result) {
        std::fprintf(stderr, "UDP server: %s\n", (!ran ? ran.error() : result.error()).message().c_str());
        return 1;
    }
    return 0;
}
