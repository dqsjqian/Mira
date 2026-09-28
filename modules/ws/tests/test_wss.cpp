#include "mira/ws/connection.hpp"
#include "mira/tls/stream.hpp"
#include "mira/transport/tcp.hpp"
#include "mira/core/task_scope.hpp"
#include "check.hpp"
#include <chrono>
#include <string>

using namespace Mira;
namespace {
Task<void> server(transport::tcp::Listener& listener, tls::Context& context, bool& done) {
    OperationOptions options{.deadline = Clock::now() + std::chrono::seconds(10)};
    auto accepted = co_await listener.accept(options);
    CHECK(accepted.has_value());
    if (!accepted) co_return;
    auto secure = tls::Stream<transport::tcp::Socket>::create(*accepted, context);
    CHECK(secure.has_value());
    if (!secure) co_return;
    auto tls_handshake = co_await secure->handshake(options);
    CHECK(tls_handshake.has_value());
    if (!tls_handshake) co_return;
    ws::Connection connection(*secure, ws::Role::server);
    auto handshake = co_await connection.handshake({}, "/", options);
    CHECK(handshake.has_value());
    if (!handshake) co_return;
    auto message = co_await connection.read_message(options);
    CHECK(message.has_value());
    if (!message) co_return;
    auto sent = co_await connection.send(std::move(*message), options);
    CHECK(sent.has_value());
    auto closing = co_await connection.read_message(options);
    CHECK(closing && closing->opcode == ws::Opcode::close);
    done = closing.has_value();
}
Task<void> client(EventLoop& loop, transport::Endpoint endpoint, tls::Context& context, bool& done) {
    OperationOptions options{.deadline = Clock::now() + std::chrono::seconds(10)};
    auto socket = co_await transport::tcp::connect(loop, endpoint, {}, options);
    CHECK(socket.has_value());
    if (!socket) co_return;
    auto secure = tls::Stream<transport::tcp::Socket>::create(*socket, context, "localhost");
    CHECK(secure.has_value());
    if (!secure) co_return;
    auto tls_handshake = co_await secure->handshake(options);
    CHECK(tls_handshake.has_value());
    if (!tls_handshake) co_return;
    ws::Connection connection(*secure, ws::Role::client);
    auto handshake = co_await connection.handshake("localhost", "/", options);
    CHECK(handshake.has_value());
    if (!handshake) co_return;
    ws::Frame frame{ws::Opcode::binary, true, std::vector<std::byte>(65536, std::byte{0xa5})};
    auto sent = co_await connection.send(frame, options);
    CHECK(sent.has_value());
    if (!sent) co_return;
    auto message = co_await connection.read_message(options);
    CHECK(message && message->payload == frame.payload);
    auto closed = co_await connection.close(1000, options);
    CHECK(closed.has_value());
    done = closed.has_value();
}
Task<void> run(EventLoop& loop, transport::tcp::Listener& listener, tls::Context& server_context,
               tls::Context& client_context) {
    bool server_done = false, client_done = false;
    TaskScope scope;
    scope.spawn(server(listener, server_context, server_done));
    scope.spawn(client(loop, listener.local_endpoint(), client_context, client_done));
    co_await scope.join();
    CHECK(server_done && client_done);
}
}
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    auto server_context = tls::Context::server(argv[1], argv[2]);
    auto client_context = tls::Context::client(argv[1]);
    CHECK(server_context.has_value()); CHECK(client_context.has_value());
    auto loop = EventLoop::create();
    auto endpoint = transport::Endpoint::parse("127.0.0.1", 0);
    if (!server_context || !client_context || !loop || !endpoint) return 1;
    auto listener = transport::tcp::Listener::bind(*loop, *endpoint);
    if (!listener) return 1;
    CHECK(loop->run_until_complete(run(*loop, *listener, *server_context, *client_context)).has_value());
    return test::summary();
}
