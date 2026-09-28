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
Task<void> client(EventLoop& loop, transport::Endpoint endpoint) {
    OperationOptions io{.deadline = Clock::now() + 3s};
    auto socket = co_await tcp::connect(loop, endpoint, {}, io);
    CHECK(socket.has_value());
    if (!socket) co_return;
    Ws connection(*socket, ws::Role::client);
    CHECK((co_await connection.handshake("localhost", "/", io)).has_value());
    TaskScope scope;
    scope.spawn(reader(connection, io)); // Waiting for peer data must not block a local send.
    co_await loop.yield();
    ws::Frame message{ws::Opcode::binary, true, bytes("request")};
    CHECK((co_await connection.send(message, io)).has_value());
    co_await scope.join();
    CHECK((co_await connection.close(1000, io)).has_value());
}
Task<void> server(tcp::Listener& listener) {
    OperationOptions io{.deadline = Clock::now() + 3s};
    auto socket = co_await listener.accept(io);
    CHECK(socket.has_value());
    if (!socket) co_return;
    Ws connection(*socket, ws::Role::server);
    CHECK((co_await connection.handshake({}, "/", io)).has_value());
    auto message = co_await connection.read_message(io);
    CHECK(message && message->payload == bytes("request"));
    ws::Frame ping{ws::Opcode::ping, true, bytes("ping")};
    CHECK((co_await connection.send(ping, io)).has_value());
    ws::Frame response{ws::Opcode::binary, true, bytes("reply")};
    CHECK((co_await connection.send(response, io)).has_value());
    auto close = co_await connection.read_message(io);
    CHECK(close && close->opcode == ws::Opcode::close);
}
Task<void> run(EventLoop& loop) {
    auto listener = tcp::Listener::bind(loop, transport::Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    TaskScope scope;
    scope.spawn(server(*listener));
    scope.spawn(client(loop, listener->local_endpoint()));
    co_await scope.join();
}
int main() {
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (loop) CHECK(loop->run_until_complete(run(*loop)).has_value());
    return test::summary();
}
