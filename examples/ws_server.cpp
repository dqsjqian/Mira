#include <mira/core/event_loop.hpp>
#include <mira/transport/tcp.hpp>
#include <mira/ws/connection.hpp>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <string_view>

namespace {
Mira::Task<void> serve(Mira::transport::tcp::Listener& listener, int& status) {
    Mira::OperationOptions options{.deadline = Mira::Clock::now() + std::chrono::seconds(15)};
    auto accepted = co_await listener.accept(options);
    if (!accepted) co_return;
    auto socket = std::move(*accepted);
    Mira::ws::Connection connection(socket, Mira::ws::Role::server);
    auto handshake = co_await connection.handshake({}, "/", options);
    if (!handshake) {
        std::fprintf(stderr, "ws handshake: %s\n", handshake.error().message().c_str());
        co_return;
    }
    while (!connection.closed()) {
        auto message = co_await connection.read_message(options);
        if (!message) {
            std::fprintf(stderr, "ws read: %s\n", message.error().message().c_str());
            co_return;
        }
        if (message->opcode == Mira::ws::Opcode::close) break;
        auto sent = co_await connection.send(std::move(*message), options);
        if (!sent) co_return;
    }
    status = 0;
}
}
int main(int argc, char** argv) {
    std::uint16_t port = 0;
    if (argc > 2) return 2;
    if (argc == 2) {
        std::string_view text(argv[1]);
        auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
        if (error != std::errc{} || end != text.data() + text.size()) return 2;
    }
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto loop = Mira::EventLoop::create();
    auto endpoint = Mira::transport::Endpoint::parse("127.0.0.1", port);
    if (!loop || !endpoint) return 1;
    auto listener = Mira::transport::tcp::Listener::bind(*loop, *endpoint);
    if (!listener) return 1;
    std::printf("ws listening %u\n", listener->local_endpoint().port());
    std::fflush(stdout);
    int status = 1;
    auto ran = loop->run_until_complete(serve(*listener, status));
    return ran ? status : 1;
}
