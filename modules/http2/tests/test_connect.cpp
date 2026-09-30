#include "mira/http2/connect_stream.hpp"
#include "mira/ws/connection.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace Mira;
using Bytes = std::vector<std::byte>;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class T> T require(Result<T> result) {
    if (!result) throw std::runtime_error(result.error().message());
    return std::move(*result);
}
void require(Result<void> result) {
    if (!result) throw std::runtime_error(result.error().message());
}
Bytes bytes(std::string_view text) {
    const auto view = std::as_bytes(std::span(text));
    return {view.begin(), view.end()};
}
http2::Headers request_headers() {
    return {{":method", "CONNECT"}, {":scheme", "https"}, {":authority", "localhost"},
            {":path", "/chat"}, {":protocol", "websocket"}, {"sec-websocket-version", "13"}};
}
http2::Session session(http2::Role role, bool enable) {
    http2::Limits limits;
    limits.enable_connect_protocol = enable;
    limits.max_body_bytes = 16384;
    limits.max_queued_body_bytes = 32768;
    return require(http2::Session::create(role, limits));
}
struct Driver {
    http2::Session& client;
    http2::Session& server;
    int progress_count = 0;
    static bool transfer(http2::Session& from, http2::Session& to) {
        auto output = require(from.output());
        for (std::size_t offset = 0; offset < output.size();) {
            const auto size = std::min<std::size_t>(19, output.size() - offset);
            require(to.receive(std::span(output).subspan(offset, size)));
            offset += size;
        }
        return !output.empty();
    }
    void drive() {
        for (int round = 0; round < 1000; ++round) {
            const bool a = transfer(client, server), b = transfer(server, client);
            if (!a && !b) return;
        }
        throw std::runtime_error("H2 progress did not quiesce");
    }
    Task<Result<void>> flush(OperationOptions options) {
        if (options.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (options.deadline && *options.deadline <= Clock::now()) co_return fail(Errc::timed_out);
        drive();
        co_return Result<void>{};
    }
    Task<Result<void>> progress(OperationOptions options) {
        check(++progress_count < 1000, "H2 driver progress stalled");
        co_return co_await flush(options);
    }
};
static_assert(BoundedStream<http2::ConnectStream<Driver>>);

void websocket_roundtrip(bool compression) {
    auto client = session(http2::Role::client, true), server = session(http2::Role::server, true);
    Driver driver{client, server};
    check(!client.peer_connect_protocol_enabled() && !server.local_connect_protocol_enabled(), "SETTINGS optimistic");
    check(!client.request_stream(request_headers()), "CONNECT before SETTINGS");
    driver.drive();
    check(client.peer_connect_protocol_enabled() && server.peer_connect_protocol_enabled(), "SETTINGS missing");
    check(client.local_connect_protocol_acknowledged() && server.local_connect_protocol_acknowledged(), "SETTINGS ACK missing");
    ws::HandshakeOptions options;
    options.compression.enabled = compression;
    options.subprotocols = {"chat.v2", "chat.v1"};
    options.require_subprotocol = true;
    auto headers = request_headers();
    headers.pop_back();
    auto offered = require(ws::extended_connect_offer(options));
    headers.insert(headers.end(), offered.begin(), offered.end());
    const auto id = require(client.request_stream(headers));
    driver.drive();
    check(require(server.connect_state(id)).protocol == "websocket", "protocol lost");
    check(!require(client.connect_state(id)).accepted, "optimistic acceptance");
    auto selected = require(ws::negotiate_extended_server(server.stream(id)->headers, options));
    http2::Headers response{{":status", "201"}};
    response.insert(response.end(), selected.fields.begin(), selected.fields.end());
    require(server.respond_stream(id, response));
    driver.drive();
    check(require(client.connect_state(id)).accepted, "2xx acceptance missing");
    http2::ConnectStream inbound{server, id, driver}, outbound{client, id, driver};
    auto negotiated = require(ws::negotiate_extended_client(201, client.stream(id)->headers, options));
    check(negotiated.subprotocol == "chat.v2" && negotiated.compression.enabled == compression,
          "extended handshake negotiation mismatch");
    ws::Connection client_ws{outbound, ws::Role::client, ws::Limits{}, options};
    ws::Connection server_ws{inbound, ws::Role::server, ws::Limits{}, options};
    require(client_ws.adopt_extended_connect("websocket", 201, negotiated));
    require(server_ws.adopt_extended_connect("websocket", 201, negotiated));
    check(!client_ws.handshake("localhost").sync_get(), "adopt still allowed H1 Upgrade");
    for (int round = 0; round < 20; ++round) {
        auto payload = bytes(std::string(2048, static_cast<char>('a' + round)));
        const auto op = round % 2 ? ws::Opcode::text : ws::Opcode::binary;
        require(client_ws.send({op, false, Bytes(payload.begin(), payload.begin() + 1000)}).sync_get());
        require(client_ws.send({ws::Opcode::ping, true, bytes("probe")}).sync_get());
        require(client_ws.send({ws::Opcode::continuation, true, Bytes(payload.begin() + 1000, payload.end())}).sync_get());
        auto message = require(server_ws.read_message().sync_get());
        check(message.opcode == op && message.payload == payload, "client fragmented payload");
        require(server_ws.send({op, false, Bytes(payload.begin(), payload.begin() + 1000)}).sync_get());
        require(server_ws.send({ws::Opcode::ping, true, bytes("server-probe")}).sync_get());
        require(server_ws.send({ws::Opcode::continuation, true, Bytes(payload.begin() + 1000, payload.end())}).sync_get());
        auto echo = require(client_ws.read_message().sync_get());
        check(echo.opcode == op && echo.payload == payload, "server payload");
    }
    require(client_ws.send({ws::Opcode::close, true, require(ws::close_payload())}).sync_get());
    auto server_close = require(server_ws.read_message().sync_get());
    if (server_close.opcode != ws::Opcode::close)
        throw std::runtime_error("server close opcode=" + std::to_string(static_cast<unsigned>(server_close.opcode)) +
                                 " bytes=" + std::to_string(server_close.payload.size()));
    check(require(client_ws.read_message().sync_get()).opcode == ws::Opcode::close, "client close");
    require(outbound.finish().sync_get());
    check(require(server.connect_state(id)).remote_end && !require(server.connect_state(id)).local_end, "half-close lost");
    require(inbound.finish().sync_get());
    check(client.stream(id)->closed && server.stream(id)->closed, "FIN did not close");
    require(client.release(id)); require(server.release(id));
}

void lifecycle_and_validation() {
    auto client = session(http2::Role::client, false), server = session(http2::Role::server, false);
    Driver driver{client, server};
    driver.drive();
    check(!client.request_stream(request_headers()), "unsupported CONNECT accepted");
    auto c = session(http2::Role::client, false), s = session(http2::Role::server, true);
    Driver d{c, s}; d.drive();
    for (int mutation = 0; mutation < 7; ++mutation) {
        auto h = request_headers();
        if (mutation == 0) h[0].value = "GET";
        if (mutation == 1) h[4].value = "bad protocol";
        if (mutation == 2) h.erase(h.begin() + 1);
        if (mutation == 3) h.erase(h.begin() + 4);
        if (mutation == 4) h.insert(h.begin() + 5, {":protocol", "websocket"});
        if (mutation == 5) h.push_back({"connection", "Upgrade"});
        if (mutation == 6) h.push_back({"content-length", "0"});
        check(!c.request_stream(h), "invalid pseudo-header accepted");
    }
    check(!c.request(request_headers()), "fixed CONNECT body accepted");
    const auto rejected = require(c.request_stream(request_headers()));
    const auto id = require(c.request_stream(request_headers()));
    d.drive();
    require(s.respond(rejected, {{":status", "403"}}, bytes("no")));
    auto unsupported = s.respond_stream(id, {{":status", "204"}});
    check(!unsupported && unsupported.error() == Errc::not_supported, "204 dependency limitation hidden");
    check(!s.respond_stream(id, {{":status", "200"}, {"content-length", "0"}}), "tunnel content-length accepted");
    require(s.respond_stream(id, {{":status", "200"}})); d.drive();
    check(!require(c.connect_state(rejected)).accepted, "403 adopted");
    std::array<std::byte, 8192> read{};
    check(!c.read_connect(rejected, read), "rejected stream readable as tunnel");
    check(!s.respond_stream(id, {{":status", "200"}}), "duplicate response");
    const Bytes block(8192, std::byte{0x42});
    for (int n = 0; n < 4; ++n) require(c.write_body(id, block));
    auto blocked = c.write_connect(id, block);
    check(!blocked && blocked.error() == Errc::would_block, "backpressure not atomic");
    // Reset this saturated stream; unrelated streams must still complete.
    require(c.cancel(id)); d.drive();
    check(require(s.connect_state(id)).error == Errc::cancelled, "peer reset lost");
    const auto ordinary = require(c.request({{":method", "GET"}, {":scheme", "https"},
                                            {":authority", "localhost"}, {":path", "/other"}}));
    d.drive(); require(s.respond(ordinary, {{":status", "200"}}, bytes("ok"))); d.drive();
    check(require(c.take_body(ordinary)) == bytes("ok"), "other stream disrupted");
    const auto half = require(c.request_stream(request_headers())); d.drive();
    require(s.respond_stream(half, {{":status", "200"}})); d.drive();
    require(c.finish_body(half)); d.drive();
    check(require(s.connect_state(half)).remote_end, "half-close invisible");
    require(s.write_connect(half, bytes("after-fin"))); d.drive();
    check(require(c.read_connect(half, read)) == 9, "reverse direction closed by FIN");
    http2::ConnectStream adapter{c, half, d};
    std::stop_source stop; stop.request_stop();
    auto cancelled = adapter.read_some(read, {.stop = stop.get_token()}).sync_get();
    check(!cancelled && cancelled.error() == Errc::cancelled, "stream cancellation not observed");
    d.drive();
    check(s.state() == http2::State::open, "cancellation killed connection");
}

Bytes raw_headers(http2::Headers headers) {
    nghttp2_hd_deflater* raw = nullptr;
    check(nghttp2_hd_deflate_new(&raw, 4096) == 0, "deflater");
    std::unique_ptr<nghttp2_hd_deflater, decltype(&nghttp2_hd_deflate_del)> deflater(raw, nghttp2_hd_deflate_del);
    std::vector<nghttp2_nv> nv;
    for (auto& h : headers) nv.push_back({reinterpret_cast<std::uint8_t*>(h.name.data()),
        reinterpret_cast<std::uint8_t*>(h.value.data()), h.name.size(), h.value.size(), NGHTTP2_NV_FLAG_NONE});
    Bytes payload(nghttp2_hd_deflate_bound(raw, nv.data(), nv.size()));
    const auto count = nghttp2_hd_deflate_hd2(raw, reinterpret_cast<std::uint8_t*>(payload.data()), payload.size(), nv.data(), nv.size());
    check(count >= 0, "HPACK encode"); payload.resize(static_cast<std::size_t>(count));
    Bytes frame(9);
    frame[0] = std::byte((payload.size() >> 16) & 255); frame[1] = std::byte((payload.size() >> 8) & 255);
    frame[2] = std::byte(payload.size() & 255); frame[3] = std::byte{NGHTTP2_HEADERS};
    frame[4] = std::byte{NGHTTP2_FLAG_END_HEADERS}; frame[8] = std::byte{1};
    frame.insert(frame.end(), payload.begin(), payload.end()); return frame;
}
void wire_validation() {
    for (int mutation = 0; mutation < 4; ++mutation) {
        auto client = session(http2::Role::client, false), server = session(http2::Role::server, mutation != 0);
        Driver driver{client, server}; driver.drive();
        auto fields = request_headers();
        if (mutation == 1) fields[4].value = "bad protocol";
        if (mutation == 2) fields[0].value = "GET";
        if (mutation == 3) fields.erase(fields.begin() + 1);
        require(server.receive(raw_headers(fields))); require(server.output());
        check(server.stream(1) && server.stream(1)->error, "malformed wire CONNECT not reset");
        check(server.state() == http2::State::open, "malformed stream killed connection");
    }
}
void rejected_streaming_length() {
    auto c = session(http2::Role::client, true), s = session(http2::Role::server, true);
    Driver d{c, s}; d.drive();
    const auto id = require(c.request_stream(request_headers())); d.drive();
    require(s.respond_stream(id, {{":status", "403"}, {"content-length", "3"}}));
    require(s.write_body(id, bytes("ab"))); d.drive();
    check(!s.write_body(id, bytes("cd")), "rejected CONNECT exceeded content-length");
    require(s.write_body(id, bytes("c"), true)); d.drive();
    check(c.stream(id)->remote_end && !c.stream(id)->error && c.stream(id)->body == bytes("abc"),
          "rejected CONNECT lost incremental body");
    const auto limited = require(c.request_stream(request_headers())); d.drive();
    require(s.respond_stream(limited, {{":status", "403"}}));
    const Bytes block(8192, std::byte{'x'});
    require(s.write_body(limited, block)); d.drive();
    require(c.take_body(limited));
    require(s.write_body(limited, block)); d.drive();
    const auto exceeded = s.write_body(limited, bytes("x"));
    check(!exceeded && exceeded.error() == Errc::limit_exceeded,
          "rejected CONNECT bypassed cumulative body limit");
}

void rejected_wire_length() {
    for (const std::string payload : {"ab", "abcd"}) {
        auto c = session(http2::Role::client, true), s = session(http2::Role::server, true);
        Driver d{c, s}; d.drive();
        check(require(c.request_stream(request_headers())) == 1, "first stream ID"); d.drive();
        auto head = raw_headers({{":status", "403"}, {"content-length", "3"}});
        require(c.receive(head));
        Bytes data(9);
        data[2] = static_cast<std::byte>(payload.size());
        data[3] = std::byte{NGHTTP2_DATA}; data[4] = std::byte{NGHTTP2_FLAG_END_STREAM};
        data[8] = std::byte{1};
        const auto body = bytes(payload); data.insert(data.end(), body.begin(), body.end());
        require(c.receive(data)); require(c.output());
        check(c.stream(1)->error && c.state() == http2::State::open,
              "malformed rejected CONNECT body did not reset only the stream");
    }
}
struct WaitingDriver {
    EventLoop& loop;
    Driver& wire;
    Task<Result<void>> flush(OperationOptions options) { co_return co_await wire.flush(options); }
    Task<Result<void>> progress(OperationOptions options) {
        auto wait = co_await loop.sleep_for(std::chrono::milliseconds(1), options);
        if (!wait) co_return wait;
        co_return co_await wire.flush(options);
    }
};
Task<void> pending_read(http2::ConnectStream<WaitingDriver>& stream, bool& done) {
    std::array<std::byte, 10> buffer{};
    auto result = co_await stream.read_some(buffer, {.deadline = Clock::now() + std::chrono::seconds(1)});
    check(result && *result == 4, "suspended read not driven"); done = true;
}
Task<void> pending_cancel(http2::ConnectStream<WaitingDriver>& stream, std::stop_token stop, bool& done) {
    std::array<std::byte, 1> buffer{};
    auto result = co_await stream.read_some(buffer, {.stop = stop});
    check(!result && result.error() == Errc::cancelled, "pending cancellation failed"); done = true;
}
Task<void> async_lifecycle(EventLoop& loop) {
    auto c = session(http2::Role::client, false), s = session(http2::Role::server, true);
    Driver wire{c, s}; wire.drive();
    auto id = require(c.request_stream(request_headers())); wire.drive();
    require(s.respond_stream(id, {{":status", "200"}})); wire.drive();
    WaitingDriver driver{loop, wire}; http2::ConnectStream stream{c, id, driver};
    bool done = false;
    TaskScope scope; scope.spawn(pending_read(stream, done));
    check(!done, "read did not suspend");
    std::array<std::byte, 1> buffer{};
    auto overlapping = co_await stream.read_some(buffer);
    check(!overlapping && overlapping.error() == Errc::invalid_argument, "overlapping read accepted");
    require(s.write_connect(id, bytes("wake")));
    co_await scope.join(); check(done, "read not completed");
    std::stop_source stop; done = false;
    TaskScope cancelled; cancelled.spawn(pending_cancel(stream, stop.get_token(), done));
    check(!done, "cancel read did not suspend"); stop.request_stop();
    co_await cancelled.join(); check(done, "cancel did not complete");
    wire.drive(); check(s.state() == http2::State::open, "pending cancellation closed connection");
}
int main() {
    try {
        websocket_roundtrip(false); websocket_roundtrip(true);
        lifecycle_and_validation(); wire_validation();
        rejected_streaming_length(); rejected_wire_length();
        auto loop = require(EventLoop::create()); require(loop.run_until_complete(async_lifecycle(loop)));
        std::cout << "HTTP/2 Extended CONNECT passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
