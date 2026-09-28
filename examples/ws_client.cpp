#include <mira/core/event_loop.hpp>
#include <mira/transport/tcp.hpp>
#include <mira/ws/connection.hpp>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <string_view>

namespace {
Mira::Task<void> run(Mira::EventLoop& loop, Mira::transport::Endpoint endpoint, int& status) {
    Mira::OperationOptions options{.deadline = Mira::Clock::now() + std::chrono::seconds(10)};
    auto connected = co_await Mira::transport::tcp::connect(loop, endpoint, {}, options);
    if (!connected) co_return;
    auto socket = std::move(*connected);
    Mira::ws::Connection connection(socket, Mira::ws::Role::client);
    auto handshake = co_await connection.handshake(endpoint.to_string(), "/echo", options);
    if (!handshake) {
        std::fprintf(stderr, "ws handshake: %s\n", handshake.error().message().c_str());
        co_return;
    }
    std::string_view text = "Mira WebSocket echo";
    auto bytes = std::as_bytes(std::span(text.data(), text.size()));
    Mira::ws::Frame frame{Mira::ws::Opcode::text, true, {bytes.begin(), bytes.end()}};
    auto sent = co_await connection.send(frame, options);
    if (!sent) co_return;
    auto received = co_await connection.read_message(options);
    if (!received || received->opcode != frame.opcode || received->payload != frame.payload) co_return;
    auto closed = co_await connection.close(1000, options);
    if (!closed) co_return;
    std::printf("ws client echo verified\n");
    status = 0;
}
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    std::uint16_t port = 0;
    std::string_view text(argv[1]);
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
    if (error != std::errc{} || end != text.data() + text.size() || port == 0) return 2;
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto loop = Mira::EventLoop::create();
    auto endpoint = Mira::transport::Endpoint::parse("127.0.0.1", port);
    if (!loop || !endpoint) return 1;
    int status = 1;
    auto ran = loop->run_until_complete(run(*loop, *endpoint, status));
    return ran ? status : 1;
}
