#include "mira/ws/connection.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/transport/tcp.hpp"
#include "check.hpp"
#include <chrono>
#include <stdexcept>

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
struct PausedWriter {
    struct Gate {
        std::coroutine_handle<> waiter;
        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> continuation) noexcept { waiter = continuation; }
        void await_resume() const noexcept {}
        void release() { auto continuation = std::exchange(waiter, {}); CHECK(static_cast<bool>(continuation)); if (continuation) continuation.resume(); }
    } gate;
    std::vector<std::byte> input;
    std::vector<std::byte> output;
    std::size_t position = 0;
    unsigned writes = 0;
    unsigned paused_writes = 2;
    std::size_t write_limit = static_cast<std::size_t>(-1);
    Task<Result<std::size_t>> read_some(std::span<std::byte> out, OperationOptions = {}) {
        if (position == input.size()) co_return fail(Errc::eof);
        const auto count = std::min(out.size(), input.size() - position);
        std::copy_n(input.data() + position, count, out.data());
        position += count;
        co_return count;
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> in, OperationOptions = {}) {
        const auto count = std::min(in.size(), write_limit);
        output.insert(output.end(), in.begin(), in.begin() + static_cast<std::ptrdiff_t>(count));
        if (++writes <= paused_writes) co_await gate;
        co_return count;
    }
};
Task<void> queued_pong_during_pong_write() {
    test::section("Pong queued while prior Pong write is parked is flushed");
    PausedWriter stream;
    for (const auto text : {"first", "second"}) {
        auto wire = ws::serialize(ws::Frame{ws::Opcode::ping, true, bytes(text)}, ws::Role::client,
                                  std::array<std::byte, 4>{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}});
        CHECK(wire.has_value());
        if (wire) stream.input.insert(stream.input.end(), wire->begin(), wire->end());
    }
    ws::Connection connection(stream, ws::Role::server);
    CHECK(connection.adopt_extended_connect("websocket", 200).has_value());
    TaskScope scope;
    auto writer = [&]() -> Task<void> {
        CHECK((co_await connection.send(ws::Frame{ws::Opcode::text, true, bytes("data")})).has_value());
    };
    scope.spawn(writer()); // Application write is held; Ping A queues Pong A.
    auto first = co_await connection.read_frame();
    CHECK(first && first->opcode == ws::Opcode::ping);
    stream.gate.release(); // Application finishes; Pong A is now held.
    CHECK(stream.writes == 2);
    auto second = co_await connection.read_frame();
    CHECK(second && second->opcode == ws::Opcode::ping);
    stream.gate.release(); // Pong B must leave even with no further application send.
    co_await scope.join();
    CHECK(stream.writes == 3);
    ws::FrameParser parser(ws::Role::client);
    std::size_t position = 0;
    unsigned pongs = 0;
    while (position < stream.output.size()) {
        auto parsed = parser.feed(std::span<const std::byte>{stream.output}.subspan(position));
        CHECK(parsed.has_value());
        if (!parsed || parsed->consumed == 0) break;
        position += parsed->consumed;
        if (parsed->frame && parsed->frame->opcode == ws::Opcode::pong) {
            CHECK(parsed->frame->payload == bytes(pongs == 0 ? "first" : "second"));
            ++pongs;
        }
    }
    CHECK(pongs == 2);
}

Task<void> close_completes_with_queued_pong() {
    test::section("peer Close supersedes Pong queued behind our Close write");
    PausedWriter stream;
    stream.paused_writes = 1;
    const auto mask = std::array<std::byte, 4>{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    auto payload = ws::close_payload(1000);
    CHECK(payload.has_value());
    for (auto frame : {ws::Frame{ws::Opcode::ping, true, bytes("queued")},
                       ws::Frame{ws::Opcode::close, true, *payload}}) {
        auto wire = ws::serialize(frame, ws::Role::client, mask);
        CHECK(wire.has_value());
        if (wire) stream.input.insert(stream.input.end(), wire->begin(), wire->end());
    }
    ws::Connection connection(stream, ws::Role::server);
    CHECK(connection.adopt_extended_connect("websocket", 200).has_value());
    TaskScope scope;
    Result<void> sent = fail(Errc::internal);
    auto writer = [&]() -> Task<void> {
        sent = co_await connection.send(ws::Frame{ws::Opcode::close, true, *payload});
    };
    scope.spawn(writer());
    auto ping = co_await connection.read_frame();
    CHECK(ping && ping->opcode == ws::Opcode::ping);
    auto close = co_await connection.read_frame();
    CHECK(close && close->opcode == ws::Opcode::close);
    stream.gate.release();
    co_await scope.join();
    CHECK(sent.has_value());
    CHECK(connection.closed());
    CHECK(stream.writes == 1);
}

struct ThrowingReader : PausedWriter {
    bool closed = false;
    Task<Result<std::size_t>> read_some(std::span<std::byte>, OperationOptions = {}) {
        throw std::runtime_error("reader fault");
        co_return std::size_t{0};
    }
    void close() noexcept {
        closed = true;
        if (gate.waiter) gate.release();
    }
};
Task<void> reader_exception_releases_writer() {
    test::section("reader exception closes transport and releases a parked writer");
    ThrowingReader stream;
    stream.paused_writes = 1;
    stream.write_limit = 1;
    ws::Connection connection(stream, ws::Role::server);
    CHECK(connection.adopt_extended_connect("websocket", 200).has_value());
    Result<void> sent;
    TaskScope scope;
    auto writer = [&]() -> Task<void> {
        sent = co_await connection.send(ws::Frame{ws::Opcode::text, true, bytes("blocked")});
    };
    scope.spawn(writer());
    bool caught = false;
    try { static_cast<void>(co_await connection.read_frame()); }
    catch (const std::runtime_error&) { caught = true; }
    CHECK(caught && stream.closed);
    CHECK(!stream.gate.waiter);
    // Keep the regression bounded on the unfixed implementation.
    if (stream.gate.waiter) stream.gate.release();
    co_await scope.join();
    CHECK(!sent && sent.error() == ws::make_error_code(ws::Errc::closed));
    CHECK(stream.writes == 1);
    CHECK(connection.closed());
}

struct ThrowingWriter : PausedWriter {
    bool closed = false;
    Task<Result<std::size_t>> read_some(std::span<std::byte> out, OperationOptions = {}) {
        CHECK(input.size() <= out.size());
        std::copy(input.begin(), input.end(), out.begin());
        co_await gate;
        co_return input.size();
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte>, OperationOptions = {}) {
        throw std::runtime_error("writer fault");
        co_return std::size_t{0};
    }
    void close() noexcept {
        closed = true;
        if (gate.waiter) gate.release();
    }
};
Task<void> writer_exception_discards_late_read() {
    test::section("writer exception rejects a successful read completion arriving after failure");
    ThrowingWriter stream;
    auto wire = ws::serialize(ws::Frame{ws::Opcode::text, true, bytes("late")}, ws::Role::client,
                              std::array<std::byte, 4>{});
    CHECK(wire.has_value());
    if (wire) stream.input = std::move(*wire);
    ws::Connection connection(stream, ws::Role::server);
    CHECK(connection.adopt_extended_connect("websocket", 200).has_value());
    Result<ws::Frame> received = fail(Errc::internal);
    TaskScope scope;
    auto reader = [&]() -> Task<void> { received = co_await connection.read_frame(); };
    scope.spawn(reader());
    bool caught = false;
    try { static_cast<void>(co_await connection.send(ws::Frame{ws::Opcode::text, true, bytes("fault")})); }
    catch (const std::runtime_error&) { caught = true; }
    CHECK(caught && stream.closed);
    if (stream.gate.waiter) stream.gate.release();
    co_await scope.join();
    CHECK(!received && received.error() == ws::make_error_code(ws::Errc::closed));
    CHECK(connection.closed());
}

Task<void> run(EventLoop& loop) {
    co_await queued_pong_during_pong_write();
    co_await close_completes_with_queued_pong();
    co_await reader_exception_releases_writer();
    co_await writer_exception_discards_late_read();
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
