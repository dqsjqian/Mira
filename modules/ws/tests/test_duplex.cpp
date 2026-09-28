#include "mira/ws/connection.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/transport/tcp.hpp"
#include "check.hpp"
#include <chrono>

using namespace Mira;
using namespace std::chrono_literals;
namespace tcp = transport::tcp;
using Ws = ws::Connection<tcp::Socket>;
std::vector<std::byte> bytes(std::string_view text) {
    auto span = std::as_bytes(std::span(text.data(), text.size()));
    return {span.begin(), span.end()};
}
Task<void> reader(Ws& connection, OperationOptions io) {
    auto message = co_await connection.read_message(io);
    CHECK(message && message->payload == bytes("reply"));
}
ws::HandshakeOptions extensions(bool compression, bool no_takeover) {
    ws::HandshakeOptions result;
    result.subprotocols = {"chat.v2", "chat.v1"};
    result.require_subprotocol = true;
    result.compression.enabled = compression;
    result.compression.client_no_context_takeover = no_takeover;
    result.compression.server_no_context_takeover = no_takeover;
    return result;
}
Task<void> client(EventLoop& loop, transport::Endpoint endpoint, bool compression, bool no_takeover) {
    OperationOptions io{.deadline = Clock::now() + 3s};
    auto socket = co_await tcp::connect(loop, endpoint, {}, io);
    CHECK(socket.has_value());
    if (!socket) co_return;
    Ws connection(*socket, ws::Role::client, {}, extensions(compression, no_takeover));
    CHECK((co_await connection.handshake("localhost", "/", io)).has_value());
    CHECK(connection.subprotocol() == "chat.v2");
    CHECK(connection.compression_parameters().enabled == compression);
    TaskScope scope;
    scope.spawn(reader(connection, io)); // Waiting for peer data must not block a local send.
    co_await loop.yield();
    ws::Frame message{ws::Opcode::binary, true, bytes("request")};
    CHECK((co_await connection.send(message, io)).has_value());
    co_await scope.join();
    for (unsigned i = 0; i < 3; ++i) {
        ws::Frame first{ws::Opcode::text, false, bytes("split ")};
        CHECK((co_await connection.send(std::move(first), io)).has_value());
        ws::Frame middle{ws::Opcode::ping, true, bytes("control")};
        CHECK((co_await connection.send(std::move(middle), io)).has_value());
        ws::Frame last{ws::Opcode::continuation, true, bytes("message")};
        CHECK((co_await connection.send(std::move(last), io)).has_value());
        auto echoed = co_await connection.read_message(io);
        CHECK(echoed && echoed->opcode == ws::Opcode::text && echoed->payload == bytes("split message"));
    }
    CHECK((co_await connection.close(1000, io)).has_value());
}
Task<void> server(tcp::Listener& listener, bool compression, bool no_takeover) {
    OperationOptions io{.deadline = Clock::now() + 3s};
    auto socket = co_await listener.accept(io);
    CHECK(socket.has_value());
    if (!socket) co_return;
    Ws connection(*socket, ws::Role::server, {}, extensions(compression, no_takeover));
    CHECK((co_await connection.handshake({}, "/", io)).has_value());
    CHECK(connection.subprotocol() == "chat.v2");
    CHECK(connection.compression_parameters().enabled == compression);
    auto message = co_await connection.read_message(io);
    CHECK(message && message->payload == bytes("request"));
    ws::Frame ping{ws::Opcode::ping, true, bytes("ping")};
    CHECK((co_await connection.send(ping, io)).has_value());
    ws::Frame response{ws::Opcode::binary, true, bytes("reply")};
    CHECK((co_await connection.send(response, io)).has_value());
    for (unsigned i = 0; i < 3; ++i) {
        auto fragment = co_await connection.read_message(io);
        CHECK(fragment && fragment->opcode == ws::Opcode::text && fragment->payload == bytes("split message"));
        if (!fragment) co_return;
        CHECK((co_await connection.send(std::move(*fragment), io)).has_value());
    }
    auto close = co_await connection.read_message(io);
    CHECK(close && close->opcode == ws::Opcode::close);
}
Task<void> run(EventLoop& loop) {
    auto listener = tcp::Listener::bind(loop, transport::Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    for (unsigned mode = 0; mode < 3; ++mode) {
        TaskScope scope;
        scope.spawn(server(*listener, mode != 0, mode == 2));
        scope.spawn(client(loop, listener->local_endpoint(), mode != 0, mode == 2));
        co_await scope.join();
    }
}
int main() {
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (loop) CHECK(loop->run_until_complete(run(*loop)).has_value());
    return test::summary();
}
