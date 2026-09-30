#include "mira/http3/connect_stream.hpp"
#include "mira/ws/connection.hpp"

#include <nghttp3/nghttp3.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <source_location>
#include <string>

using namespace Mira;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class T> T require(Result<T> result, std::source_location location = std::source_location::current()) {
    if (!result) throw std::runtime_error(result.error().message() + " at " + std::to_string(location.line()));
    return std::move(*result);
}
void require(Result<void> result, std::source_location location = std::source_location::current()) {
    if (!result) throw std::runtime_error(result.error().message() + " at " + std::to_string(location.line()));
}
quic::Bytes bytes(std::string_view text) {
    const auto view = std::as_bytes(std::span(text));
    return {view.begin(), view.end()};
}
http3::Headers request_headers() {
    return {{":method", "CONNECT"}, {":scheme", "https"}, {":authority", "localhost"},
            {":path", "/chat"}, {":protocol", "websocket"}, {"sec-websocket-version", "13"}};
}
struct Driver {
    http3::Engine& client;
    http3::Engine& server;
    std::uint64_t now = 1'000'000'000;
    int rounds = 0;
    void drive() {
        check(rounds < 20000, "HTTP3 driver progress stalled");
        for (int k = 0; k < 32; ++k) {
            auto packet = require(client.poll(now));
            if (packet.empty()) break;
            require(server.receive(packet, now));
        }
        for (int k = 0; k < 32; ++k) {
            auto packet = require(server.poll(now));
            if (packet.empty()) break;
            require(client.receive(packet, now));
        }
        now += 1'000'000;
        if (client.expiry() <= now) require(client.handle_expiry(now));
        if (server.expiry() <= now) require(server.handle_expiry(now));
        ++rounds;
    }
    void settle() { for (int i = 0; i < 40; ++i) drive(); }
    Task<Result<void>> flush(OperationOptions options) {
        if (options.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (options.deadline && *options.deadline <= Clock::now()) co_return fail(Errc::timed_out);
        drive();
        co_return Result<void>{};
    }
    Task<Result<void>> progress(OperationOptions options) { co_return co_await flush(options); }
};
static_assert(BoundedStream<http3::ConnectStream<Driver>>);
struct Pair {
    http3::Engine client;
    http3::Engine server;
    static Pair create(const char* cert, const char* key, bool enabled, std::size_t event_limit = 4096) {
        quic::Options co, so;
        co.local = transport::Endpoint::loopback(44330); co.remote = transport::Endpoint::loopback(44331);
        co.ca_file = cert; co.peer_name = "localhost";
        so.local = co.remote; so.remote = co.local; so.certificate_file = cert; so.private_key_file = key;
        auto cq = require(quic::Engine::client(co, 1'000'000'000));
        auto initial = require(cq.poll(1'000'000'000));
        auto sq = require(quic::Engine::accept(so, initial, 1'000'000'000));
        http3::Limits limits; limits.enable_connect_protocol = enabled; limits.max_buffered_body = 32768;
        limits.max_events = event_limit;
        return {require(http3::Engine::create(std::move(cq), false, limits)),
                require(http3::Engine::create(std::move(sq), true, limits))};
    }
};
void ready(Driver& driver) {
    for (int i = 0; i < 1000 && !(driver.client.ready() && driver.server.ready()); ++i) driver.drive();
    check(driver.client.ready() && driver.server.ready(), "HTTP3 handshake");
    driver.settle();
}
void websocket_roundtrip(const char* cert, const char* key, bool compression) {
    auto pair = Pair::create(cert, key, true);
    auto& client = pair.client; auto& server = pair.server;
    Driver driver{client, server};
    check(!client.peer_connect_protocol_enabled(), "optimistic SETTINGS");
    check(!client.request_stream(request_headers()), "CONNECT before SETTINGS");
    ready(driver);
    check(client.peer_connect_protocol_enabled() && server.local_connect_protocol_enabled(), "SETTINGS missing");
    check(!server.peer_connect_protocol_enabled() && !client.local_connect_protocol_enabled(), "client advertised H3 CONNECT");
    ws::HandshakeOptions options;
    options.compression.enabled = compression;
    options.subprotocols = {"chat.v2", "chat.v1"};
    options.require_subprotocol = true;
    auto fields = request_headers();
    fields.pop_back();
    auto offered = require(ws::extended_connect_offer(options));
    fields.insert(fields.end(), offered.begin(), offered.end());
    const auto id = require(client.request_stream(fields)); driver.settle();
    check(require(server.connect_state(id)).protocol == "websocket", "protocol missing");
    http3::Headers received_request;
    for (const auto& event : server.take_events())
        if (event.kind == http3::Event::Kind::headers && event.stream_id == id) received_request = event.fields;
    auto selected = require(ws::negotiate_extended_server(received_request, options));
    http3::Headers response{{":status", "201"}};
    response.insert(response.end(), selected.fields.begin(), selected.fields.end());
    require(server.respond_stream(id, response)); driver.settle();
    check(require(client.connect_state(id)).accepted, "2xx acceptance");
    http3::ConnectStream outbound{client, id, driver}, inbound{server, id, driver};
    http3::Headers received_response;
    for (const auto& event : client.take_events())
        if (event.kind == http3::Event::Kind::headers && event.stream_id == id) received_response = event.fields;
    auto negotiated = require(ws::negotiate_extended_client(201, received_response, options));
    check(negotiated.subprotocol == "chat.v2" && negotiated.compression.enabled == compression,
          "extended handshake negotiation mismatch");
    ws::Connection client_ws{outbound, ws::Role::client, ws::Limits{}, options};
    ws::Connection server_ws{inbound, ws::Role::server, ws::Limits{}, options};
    require(client_ws.adopt_extended_connect("websocket", 201, negotiated));
    require(server_ws.adopt_extended_connect("websocket", 201, negotiated));
    check(!client_ws.handshake("localhost").sync_get(), "H1 Upgrade after adoption");
    for (int round = 0; round < 20; ++round) {
        auto payload = bytes(std::string(2048, static_cast<char>('a' + round)));
        const auto op = round % 2 ? ws::Opcode::text : ws::Opcode::binary;
        require(client_ws.send({op, false, quic::Bytes(payload.begin(), payload.begin() + 1000)}).sync_get());
        require(client_ws.send({ws::Opcode::ping, true, bytes("probe")}).sync_get());
        require(client_ws.send({ws::Opcode::continuation, true, quic::Bytes(payload.begin() + 1000, payload.end())}).sync_get());
        auto message = require(server_ws.read_message().sync_get());
        check(message.opcode == op && message.payload == payload, "client fragmented payload");
        require(server_ws.send({op, false, quic::Bytes(payload.begin(), payload.begin() + 1000)}).sync_get());
        require(server_ws.send({ws::Opcode::ping, true, bytes("server-probe")}).sync_get());
        require(server_ws.send({ws::Opcode::continuation, true, quic::Bytes(payload.begin() + 1000, payload.end())}).sync_get());
        auto echo = require(client_ws.read_message().sync_get());
        check(echo.opcode == op && echo.payload == payload, "server payload");
    }
    require(client_ws.send({ws::Opcode::close, true, require(ws::close_payload())}).sync_get());
    auto server_close = require(server_ws.read_message().sync_get());
    if (server_close.opcode != ws::Opcode::close)
        throw std::runtime_error("server close opcode=" + std::to_string(static_cast<unsigned>(server_close.opcode)) +
                                 " bytes=" + std::to_string(server_close.payload.size()));
    check(require(client_ws.read_message().sync_get()).opcode == ws::Opcode::close, "client close");
    require(outbound.finish().sync_get()); driver.settle();
    check(require(server.connect_state(id)).remote_end && !require(server.connect_state(id)).local_end, "half-close lost");
    require(inbound.finish().sync_get()); driver.settle();
    check(require(client.connect_state(id)).closed && require(server.connect_state(id)).closed, "FIN did not close");
    require(client.release_connect(id)); require(server.release_connect(id));
}
void lifecycle(const char* cert, const char* key) {
    auto disabled = Pair::create(cert, key, false);
    Driver disabled_driver{disabled.client, disabled.server}; ready(disabled_driver);
    check(!disabled.client.request_stream(request_headers()), "CONNECT without SETTINGS accepted");
    auto pair = Pair::create(cert, key, true); auto& c = pair.client; auto& s = pair.server;
    Driver d{c, s}; ready(d);
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
    check(!c.request(request_headers()), "fixed CONNECT accepted");
    auto rejected = require(c.request_stream(request_headers()));
    auto id = require(c.request_stream(request_headers())); d.settle();
    require(s.respond(rejected, {{":status", "403"}}, bytes("no")));
    auto unsupported = s.respond_stream(id, {{":status", "204"}});
    check(!unsupported && unsupported.error() == Errc::not_supported, "204 dependency limitation hidden");
    check(!s.respond_stream(id, {{":status", "200"}, {"content-length", "0"}}), "tunnel content-length accepted");
    require(s.respond_stream(id, {{":status", "200"}})); d.settle();
    check(!require(c.connect_state(rejected)).accepted, "403 adopted");
    std::array<std::byte, 8192> buffer{};
    check(!c.read_connect(rejected, buffer), "rejected stream readable");
    bool rejected_body = false;
    for (auto& event : c.take_events()) if (event.kind == http3::Event::Kind::body && event.stream_id == rejected) {
        rejected_body = event.data == bytes("no"); require(c.consume(rejected, event.data.size()));
    }
    check(rejected_body, "rejected response body lost");
    quic::Bytes block(8192, std::byte{0x42});
    for (int k = 0; k < 4; ++k) require(c.write_connect(id, block));
    auto blocked = c.write_connect(id, block);
    check(!blocked && blocked.error() == Errc::would_block && c.queued_body_bytes() == 32768, "backpressure not atomic");
    d.settle();
    for (int k = 0; k < 4; ++k) {
        std::size_t consumed = 0;
        const auto deadline_round = d.rounds + 1000;
        while (consumed < block.size()) {
            auto received = s.read_connect(id, std::span(buffer).first(block.size() - consumed));
            if (!received && received.error() == Errc::would_block) {
                check(d.rounds < deadline_round, "receive window did not resume CONNECT data");
                d.drive(); // Deliver the WINDOW_UPDATE/ACK generated by consumption.
                continue;
            }
            const auto count = require(std::move(received));
            check(count != 0 && std::all_of(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(count),
                                          [](std::byte value) { return value == std::byte{0x42}; }),
                  "CONNECT flow-controlled payload corrupted");
            consumed += count;
        }
    }
    d.settle();
    require(c.write_connect(id, bytes("more"))); d.settle();
    check(require(s.read_connect(id, buffer)) == 4, "ACK did not resume output");
    require(c.finish_body(id)); d.settle();
    check(require(s.connect_state(id)).remote_end, "half-close invisible");
    require(s.write_connect(id, bytes("after-fin"))); d.settle();
    check(require(c.read_connect(id, buffer)) == 9, "FIN closed reverse direction");
    http3::ConnectStream adapter{c, id, d};
    std::stop_source stop; stop.request_stop();
    auto cancelled = adapter.read_some(buffer, {.stop = stop.get_token()}).sync_get();
    check(!cancelled && cancelled.error() == Errc::cancelled, "cancel not observed");
    d.settle();
    check(static_cast<bool>(require(s.connect_state(id)).error), "peer reset invisible");
    const auto other = require(c.request({{":method", "GET"}, {":scheme", "https"},
                                         {":authority", "localhost"}, {":path", "/other"}}));
    d.settle(); require(s.respond(other, {{":status", "200"}}, bytes("ok"))); d.settle();
    bool found = false;
    for (auto& e : c.take_events()) if (e.kind == http3::Event::Kind::body && e.stream_id == other) {
        found = e.data == bytes("ok"); require(c.consume(other, e.data.size()));
    }
    check(found && c.ready() && s.ready(), "reset disrupted another stream");
}
void rejected_streaming_length(const char* cert, const char* key) {
    auto pair = Pair::create(cert, key, true);
    auto& c = pair.client; auto& s = pair.server;
    Driver d{c, s}; ready(d);
    const auto id = require(c.request_stream(request_headers())); d.settle();
    require(s.respond_stream(id, {{":status", "403"}, {"content-length", "3"}}));
    require(s.write_body(id, bytes("ab"))); d.settle();
    check(!s.write_body(id, bytes("cd")), "rejected CONNECT exceeded content-length");
    require(s.write_body(id, bytes("c"), true)); d.settle();
    quic::Bytes body;
    bool ended = false;
    for (auto& event : c.take_events()) {
        check(event.kind != http3::Event::Kind::reset, "valid rejected body was reset");
        if (event.kind == http3::Event::Kind::body) {
            body.insert(body.end(), event.data.begin(), event.data.end());
            require(c.consume(id, event.data.size()));
        }
        if (event.kind == http3::Event::Kind::end) ended = true;
    }
    check(ended && body == bytes("abc"), "rejected CONNECT lost incremental body");
}

void shared_tunnel_budget(const char* cert, const char* key) {
    auto pair = Pair::create(cert, key, true, 4);
    auto& c = pair.client; auto& s = pair.server;
    Driver d{c, s}; ready(d);
    const auto a = require(c.request_stream(request_headers()));
    const auto b = require(c.request_stream(request_headers())); d.settle();
    static_cast<void>(s.take_events());
    require(s.respond_stream(a, {{":status", "200"}}));
    require(s.respond_stream(b, {{":status", "200"}})); d.settle();
    static_cast<void>(c.take_events());
    for (const auto id : {a, b, a, b}) {
        require(c.write_connect(id, bytes("x"))); d.settle();
    }
    std::array<std::byte, 1> buffer{};
    check(require(s.read_connect(a, buffer)) == 1, "tunnel input missing");
    require(c.write_connect(b, bytes("y"))); d.settle();
    require(c.write_connect(a, bytes("z")));
    bool rejected = false;
    for (int round = 0; round < 100 && !rejected; ++round) {
        const auto packet = require(c.poll(d.now));
        if (!packet.empty()) rejected = !s.receive(packet, d.now);
        d.now += 1'000'000;
    }
    check(rejected && s.closed(), "separate tunnels bypassed connection-wide chunk budget");
}
quic::Bytes raw_headers(http3::Headers fields, std::int64_t id) {
    nghttp3_qpack_encoder* encoder = nullptr;
    check(nghttp3_qpack_encoder_new(&encoder, 0, nghttp3_mem_default()) == 0, "QPACK encoder");
    std::vector<nghttp3_nv> nv;
    for (auto& h : fields) nv.push_back({reinterpret_cast<std::uint8_t*>(h.name.data()),
        reinterpret_cast<std::uint8_t*>(h.value.data()), h.name.size(), h.value.size(), NGHTTP3_NV_FLAG_NONE});
    nghttp3_buf prefix{}, payload{}, instructions{};
    const int result = nghttp3_qpack_encoder_encode(encoder, &prefix, &payload, &instructions, id, nv.data(), nv.size());
    const auto size = nghttp3_buf_len(&prefix) + nghttp3_buf_len(&payload);
    quic::Bytes frame{std::byte{1}, std::byte{static_cast<unsigned char>(0x40 | (size >> 8))}, std::byte(size & 255)};
    if (result == 0) {
        frame.insert(frame.end(), reinterpret_cast<std::byte*>(prefix.pos), reinterpret_cast<std::byte*>(prefix.last));
        frame.insert(frame.end(), reinterpret_cast<std::byte*>(payload.pos), reinterpret_cast<std::byte*>(payload.last));
    }
    nghttp3_buf_free(&prefix, nghttp3_mem_default()); nghttp3_buf_free(&payload, nghttp3_mem_default());
    nghttp3_buf_free(&instructions, nghttp3_mem_default()); nghttp3_qpack_encoder_del(encoder);
    check(result == 0 && size < 16384, "QPACK encode");
    return frame;
}
void wire_validation(const char* cert, const char* key) {
    for (int mutation = 0; mutation < 4; ++mutation) {
        auto pair = Pair::create(cert, key, mutation != 0); Driver d{pair.client, pair.server}; ready(d);
        auto fields = request_headers();
        if (mutation == 1) fields[4].value = "bad protocol";
        if (mutation == 2) fields[0].value = "GET";
        if (mutation == 3) fields.erase(fields.begin() + 1);
        auto& raw = pair.client.transport();
        const auto id = require(raw.open_stream());
        require(raw.write(id, raw_headers(fields, id), false));
        bool connection_rejected = false;
        auto exchange = [&] {
            for (int n = 0; n < 80; ++n) {
                auto sent = require(raw.poll(d.now));
                if (!sent.empty()) {
                    auto result = pair.server.receive(sent, d.now);
                    if (!result) {
                        // nghttp3's read_stream2 contract makes a negative parser
                        // return connection-fatal. Never drive that parser again.
                        check(result.error() == http3::http3_error(NGHTTP3_ERR_MALFORMED_HTTP_HEADER) ||
                              result.error() == http3::http3_error(NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING),
                              "unexpected malformed-header failure");
                        check(pair.server.closed() && !pair.server.ready(), "failed parser remained usable");
                        check(!pair.server.poll(d.now), "failed parser produced application data");
                        connection_rejected = true;
                        return;
                    }
                }
                auto reply = require(pair.server.poll(d.now));
                if (!reply.empty()) require(raw.receive(reply, d.now));
                d.now += 1'000'000;
                if (raw.expiry() <= d.now) require(raw.handle_expiry(d.now));
                if (pair.server.expiry() <= d.now) require(pair.server.handle_expiry(d.now));
            }
        };
        exchange();
        if (connection_rejected) {
            // This fixed nghttp3 version may reject malformed/unsupported
            // pseudo-headers before application callbacks. Its negative result
            // poisons the connection; normal application resets are tested above.
            continue;
        }
        bool reset = false;
        for (auto& event : pair.server.take_events())
            if (event.stream_id == id && event.kind == http3::Event::Kind::reset) reset = true;
        check(reset && pair.server.ready(), "malformed CONNECT did not reset only stream");
        const auto other = require(raw.open_stream());
        require(raw.write(other, raw_headers({{":method", "GET"}, {":scheme", "https"},
            {":authority", "localhost"}, {":path", "/other"}}, other), true));
        exchange();
        bool received = false;
        for (auto& event : pair.server.take_events())
            if (event.stream_id == other && event.kind == http3::Event::Kind::headers) received = true;
        check(received, "malformed CONNECT damaged another stream");
    }
}
void rejected_wire_length(const char* cert, const char* key) {
    for (const std::string payload : {"ab", "abcd"}) {
        auto pair = Pair::create(cert, key, true);
        auto& c = pair.client; auto& s = pair.server;
        Driver d{c, s}; ready(d);
        const auto id = require(c.request_stream(request_headers())); d.settle();
        auto wire = raw_headers({{":status", "403"}, {"content-length", "3"}}, id);
        wire.push_back(std::byte{0});
        wire.push_back(static_cast<std::byte>(payload.size()));
        const auto data = bytes(payload); wire.insert(wire.end(), data.begin(), data.end());
        require(s.transport().write(id, wire, true)); d.settle();
        bool reset = false;
        for (auto& event : c.take_events()) {
            reset |= event.kind == http3::Event::Kind::reset && event.stream_id == id;
            if (event.kind == http3::Event::Kind::body) require(c.consume(id, event.data.size()));
        }
        check(reset && c.ready(), "malformed rejected CONNECT body did not reset the stream");
    }
}
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    try {
        websocket_roundtrip(argv[1], argv[2], false); websocket_roundtrip(argv[1], argv[2], true);
        lifecycle(argv[1], argv[2]); wire_validation(argv[1], argv[2]);
        rejected_streaming_length(argv[1], argv[2]);
        rejected_wire_length(argv[1], argv[2]);
        shared_tunnel_budget(argv[1], argv[2]);
        std::cout << "HTTP/3 Extended CONNECT passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
