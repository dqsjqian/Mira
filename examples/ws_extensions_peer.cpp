#include <mira/core/event_loop.hpp>
#include <mira/transport/tcp.hpp>
#include <mira/ws/connection.hpp>

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

namespace {
Mira::Task<void> session(Mira::transport::tcp::Socket& socket, Mira::ws::Role role,
                         Mira::ws::HandshakeOptions handshake_options, int& status) {
    Mira::OperationOptions options{.deadline = Mira::Clock::now() + std::chrono::seconds(15)};
    Mira::ws::Limits limits{.max_frame = 65536, .max_message = 65536};
    Mira::ws::Connection connection(socket, role, limits, std::move(handshake_options));
    auto handshake = co_await connection.handshake("localhost", "/extensions", options);
    if (!handshake) {
        std::fprintf(stderr, "ws handshake: %s\n", handshake.error().message().c_str());
        co_return;
    }
    const auto& compression = connection.compression_parameters();
    const std::string protocol(connection.subprotocol());
    std::printf("NEGOTIATED protocol=%s compression=%d server_no_context=%d client_no_context=%d "
                "server_window=%u client_window=%u\n",
                protocol.empty() ? "-" : protocol.c_str(), compression.enabled,
                compression.server_no_context_takeover, compression.client_no_context_takeover,
                compression.server_max_window_bits, compression.client_max_window_bits);
    std::fflush(stdout);
    while (!connection.closed()) {
        auto message = co_await connection.read_message(options);
        if (!message) {
            std::fprintf(stderr, "ws read: %s\n", message.error().message().c_str());
            co_return;
        }
        if (message->opcode == Mira::ws::Opcode::close) break;
        if (message->payload.empty()) {
            if (!(co_await connection.send(std::move(*message), options))) co_return;
            continue;
        }
        // Split after one byte so the peer checks UTF-8, RSV1 and interleaved controls.
        Mira::ws::Frame first{message->opcode, false, {message->payload.front()}};
        if (!(co_await connection.send(std::move(first), options))) co_return;
        const std::string_view ping = "mira-fragment";
        auto ping_bytes = std::as_bytes(std::span(ping.data(), ping.size()));
        Mira::ws::Frame control{Mira::ws::Opcode::ping, true, {ping_bytes.begin(), ping_bytes.end()}};
        if (!(co_await connection.send(std::move(control), options))) co_return;
        Mira::ws::Frame rest{Mira::ws::Opcode::continuation, true,
                             {message->payload.begin() + 1, message->payload.end()}};
        if (!(co_await connection.send(std::move(rest), options))) co_return;
    }
    status = 0;
}

Mira::Task<void> serve(Mira::transport::tcp::Listener& listener,
                       Mira::ws::HandshakeOptions options, int& status) {
    auto accepted = co_await listener.accept({.deadline = Mira::Clock::now() + std::chrono::seconds(15)});
    if (!accepted) co_return;
    auto socket = std::move(*accepted);
    co_await session(socket, Mira::ws::Role::server, std::move(options), status);
}

Mira::Task<void> connect(Mira::EventLoop& loop, std::uint16_t port,
                         Mira::ws::HandshakeOptions options, int& status) {
    auto connected = co_await Mira::transport::tcp::connect(loop, Mira::transport::Endpoint::loopback(port), {},
        {.deadline = Mira::Clock::now() + std::chrono::seconds(15)});
    if (!connected) co_return;
    auto socket = std::move(*connected);
    co_await session(socket, Mira::ws::Role::client, std::move(options), status);
}
}

int main(int argc, char** argv) {
    if (argc != 5) return 2;
    const std::string_view role(argv[1]), mode(argv[3]), protocol_mode(argv[4]);
    if (role != "server" && role != "client") return 2;
    const std::string_view port_text(argv[2]);
    std::uint16_t port = 0;
    auto [end, error] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (error != std::errc{} || end != port_text.data() + port_text.size() || (!port && role == "client"))
        return 2;
    if (mode != "context" && mode != "no-context" && mode != "server-no-context" &&
        mode != "client-no-context" && mode != "window9" && mode != "disabled") return 2;
    if (protocol_mode != "optional" && protocol_mode != "required" && protocol_mode != "none") return 2;
    Mira::ws::HandshakeOptions options;
    if (protocol_mode != "none") {
        options.subprotocols = role == "server" ? std::vector<std::string>{"mira.v2", "mira.v1"}
                                                : std::vector<std::string>{"mira.v1", "mira.v2"};
    }
    options.require_subprotocol = protocol_mode == "required";
    options.compression.enabled = mode != "disabled";
    options.compression.server_no_context_takeover = mode == "no-context" || mode == "server-no-context";
    options.compression.client_no_context_takeover = mode == "no-context" || mode == "client-no-context";
    if (mode == "window9") {
        options.compression.server_max_window_bits = 9;
        options.compression.client_max_window_bits = 9;
    }
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto loop = Mira::EventLoop::create();
    if (!loop) return 1;
    int status = 1;
    if (role == "client") {
        auto ran = loop->run_until_complete(connect(*loop, port, std::move(options), status));
        return ran ? status : 1;
    }
    auto listener = Mira::transport::tcp::Listener::bind(*loop, Mira::transport::Endpoint::loopback(port));
    if (!listener) return 1;
    std::printf("ws listening %u\n", static_cast<unsigned>(listener->local_endpoint().port()));
    std::fflush(stdout);
    auto ran = loop->run_until_complete(serve(*listener, std::move(options), status));
    return ran ? status : 1;
}
