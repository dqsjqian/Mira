#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/http2/connect_stream.hpp"
#include "mira/http3/connect_stream.hpp"
#include "mira/transport/tcp.hpp"
#include "mira/transport/udp.hpp"
#include "mira/ws/connection.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <source_location>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

using namespace Mira;
using namespace std::chrono_literals;
using Bytes = std::vector<std::byte>;
using transport::Endpoint;

namespace {
constexpr std::size_t body_budget = 8192;
constexpr int message_rounds = 20;

void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
template<class T>
T require(Result<T> result, std::source_location where = std::source_location::current()) {
    if (!result) throw std::runtime_error(result.error().message() + " at " + std::to_string(where.line()));
    return std::move(*result);
}
void require(Result<void> result, std::source_location where = std::source_location::current()) {
    if (!result) throw std::runtime_error(result.error().message() + " at " + std::to_string(where.line()));
}
Bytes bytes(std::string_view text) {
    const auto data = std::as_bytes(std::span(text));
    return {data.begin(), data.end()};
}
std::string_view field(const http::Headers& fields, std::string_view name) {
    for (const auto& item : fields) if (item.name == name) return item.value;
    return {};
}
ws::HandshakeOptions websocket_options(bool compression) {
    ws::HandshakeOptions result;
    result.subprotocols = {"mira.echo"};
    result.require_subprotocol = true;
    result.compression.enabled = compression;
    return result;
}
http::Headers request_headers(std::string path, const ws::HandshakeOptions& options) {
    http::Headers fields{{":method", "CONNECT"}, {":scheme", "https"},
                        {":authority", "localhost"}, {":path", std::move(path)},
                        {":protocol", "websocket"}};
    auto offer = require(ws::extended_connect_offer(options));
    fields.insert(fields.end(), offer.begin(), offer.end());
    return fields;
}
http::Headers get_headers(std::string path) {
    return {{":method", "GET"}, {":scheme", "https"},
            {":authority", "localhost"}, {":path", std::move(path)}};
}
ws::ConnectHandshake negotiate_request(const http::Headers& fields, const ws::HandshakeOptions& options) {
    check(field(fields, ":method") == "CONNECT" && field(fields, ":protocol") == "websocket",
          "wire CONNECT pseudo-headers missing");
    check(field(fields, ":authority") == "localhost" && field(fields, ":scheme") == "https",
          "wire CONNECT authority/scheme missing");
    check(field(fields, "sec-websocket-version") == "13", "wire WebSocket version missing");
    check(field(fields, "sec-websocket-protocol") == "mira.echo", "wire subprotocol missing");
    check(field(fields, "sec-websocket-extensions").empty() != options.compression.enabled,
          "wire extension offer mismatch");
    auto result = require(ws::negotiate_extended_server(fields, options));
    check(result.negotiated.compression.enabled == options.compression.enabled, "server compression mismatch");
    check(result.negotiated.subprotocol == "mira.echo", "server subprotocol mismatch");
    result.fields.insert(result.fields.begin(), {":status", "200"});
    return result;
}
ws::Negotiated negotiate_response(const http::Headers& fields, const ws::HandshakeOptions& options) {
    check(field(fields, ":status") == "200", "wire CONNECT status missing");
    check(field(fields, "sec-websocket-protocol") == "mira.echo", "wire selected subprotocol missing");
    check(field(fields, "sec-websocket-extensions").empty() != options.compression.enabled,
          "wire selected extension mismatch");
    auto result = require(ws::negotiate_extended_client(200, fields, options));
    check(result.compression.enabled == options.compression.enabled, "client compression mismatch");
    return result;
}
Bytes payload(int round) {
    Bytes result(2048);
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = std::byte{static_cast<unsigned char>('a' + (i + static_cast<std::size_t>(round)) % 23)};
    if (round % 2 == 0) { result[11] = std::byte{0}; result[1010] = std::byte{0xff}; }
    return result;
}
struct Controls { int ping = 0; int pong = 0; };

template<class Stream>
Task<void> send_fragmented(ws::Connection<Stream>& websocket, int round, OperationOptions io) {
    auto body = payload(round);
    ws::Frame first{round % 2 ? ws::Opcode::text : ws::Opcode::binary, false,
                    Bytes(body.begin(), body.begin() + 1000)};
    ws::Frame ping{ws::Opcode::ping, true, bytes("loopback-probe")};
    ws::Frame last{ws::Opcode::continuation, true, Bytes(body.begin() + 1000, body.end())};
    require(co_await websocket.send(std::move(first), io));
    require(co_await websocket.send(std::move(ping), io));
    require(co_await websocket.send(std::move(last), io));
}

template<class Stream>
Task<void> read_fragmented(ws::Connection<Stream>& websocket, int round, Controls& controls, OperationOptions io) {
    Bytes received;
    int fragments = 0;
    for (;;) {
        auto frame = require(co_await websocket.read_frame(io));
        if (frame.opcode == ws::Opcode::ping || frame.opcode == ws::Opcode::pong) {
            check(frame.payload == bytes("loopback-probe"), "control payload mismatch");
            if (frame.opcode == ws::Opcode::ping) ++controls.ping;
            else ++controls.pong;
            continue;
        }
        check(frame.opcode == (fragments == 0 ? (round % 2 ? ws::Opcode::text : ws::Opcode::binary)
                                             : ws::Opcode::continuation), "fragment opcode mismatch");
        ++fragments;
        check(received.size() + frame.payload.size() <= 2048, "unbounded WebSocket reassembly");
        received.insert(received.end(), frame.payload.begin(), frame.payload.end());
        if (frame.final) break;
    }
    check(fragments == 2 && received == payload(round), "fragmented WebSocket payload mismatch");
}

template<class Stream>
Task<void> websocket_dialog(Stream& stream, bool client, const ws::HandshakeOptions& options,
                            ws::Negotiated negotiated, OperationOptions io) {
    ws::Connection websocket{stream, client ? ws::Role::client : ws::Role::server, ws::Limits{}, options};
    require(websocket.adopt_extended_connect("websocket", 200, std::move(negotiated)));
    check(websocket.subprotocol() == "mira.echo" &&
          websocket.compression_parameters().enabled == options.compression.enabled, "adoption lost negotiation");
    Controls controls;
    for (int round = 0; round < message_rounds; ++round) {
        if (client) co_await send_fragmented(websocket, round, io);
        co_await read_fragmented(websocket, round, controls, io);
        if (!client) co_await send_fragmented(websocket, round, io);
    }
    if (client) {
        require(co_await websocket.close(1000, io));
    } else {
        for (;;) {
            auto frame = require(co_await websocket.read_frame(io));
            if (frame.opcode == ws::Opcode::pong) {
                check(frame.payload == bytes("loopback-probe"), "final pong mismatch");
                ++controls.pong;
                continue;
            }
            check(frame.opcode == ws::Opcode::close && frame.payload == require(ws::close_payload(1000)),
                  "close handshake mismatch");
            break;
        }
    }
    check(controls.ping == message_rounds && controls.pong == message_rounds,
          "bidirectional ping/pong was lost");
    check(websocket.closed(), "WebSocket close handshake incomplete");
    std::array<std::byte, 1> buffer{};
    if (client) require(co_await stream.finish(io));
    auto eof = co_await stream.read_some(buffer, io);
    check(!eof && eof.error() == Errc::eof, "CONNECT peer FIN missing");
    if (!client) require(co_await stream.finish(io));
}

struct TcpDriver {
    transport::tcp::Socket& socket;
    http2::Session& engine;
    std::size_t received = 0;
    std::size_t sent = 0;
    Task<Result<void>> flush(OperationOptions io) {
        if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (io.deadline && *io.deadline <= Clock::now()) co_return fail(Errc::timed_out);
        auto output = engine.output();
        if (!output) co_return fail(output.error());
        std::span<const std::byte> pending(*output);
        while (!pending.empty()) {
            auto size = co_await socket.write_some(pending.first(std::min<std::size_t>(251, pending.size())), io);
            if (!size) co_return fail(size.error());
            if (*size == 0) co_return fail(Errc::eof);
            sent += *size;
            pending = pending.subspan(*size);
        }
        co_return Result<void>{};
    }
    Task<Result<void>> progress(OperationOptions io) {
        if (auto result = co_await flush(io); !result) co_return result;
        std::array<std::byte, 137> buffer{};
        auto size = co_await socket.read_some(buffer, io);
        if (!size) co_return fail(size.error());
        received += *size;
        if (auto fed = engine.receive(std::span(buffer).first(*size)); !fed) co_return fed;
        for (auto id : engine.streams())
            check(engine.stream(id)->body.size() <= body_budget, "H2 receive buffer exceeded its budget");
        check(engine.queued_body_bytes() <= body_budget, "H2 output buffer exceeded its budget");
        co_return co_await flush(io);
    }
};
static_assert(BoundedStream<http2::ConnectStream<TcpDriver>>);

http2::Session h2_session(bool server) {
    http2::Limits limits;
    limits.enable_connect_protocol = true;
    limits.max_body_bytes = body_budget;
    limits.max_queued_body_bytes = body_budget;
    return require(http2::Session::create(server ? http2::Role::server : http2::Role::client, limits));
}

Task<void> h2_server(EventLoop& loop, transport::tcp::Listener& listener, bool compression,
                     bool& done, OperationOptions io) {
    (void)loop;
    auto socket = require(co_await listener.accept(io));
    auto engine = h2_session(true);
    TcpDriver driver{socket, engine};
    auto options = websocket_options(compression);
    std::int32_t tunnel = 0, reset = 0;
    ws::Negotiated negotiated;
    bool before = false, after = false;
    for (;;) {
        require(co_await driver.progress(io));
        for (auto id : engine.streams()) {
            const auto* record = engine.stream(id);
            if (!record->headers_received || record->error) continue;
            const auto path = field(record->headers, ":path");
            if (path == "/chat" && tunnel == 0) {
                auto accepted = negotiate_request(record->headers, options);
                require(engine.respond_stream(id, accepted.fields));
                negotiated = std::move(accepted.negotiated);
                tunnel = id;
            } else if (path == "/reset" && reset == 0) {
                auto accepted = negotiate_request(record->headers, options);
                require(engine.respond_stream(id, accepted.fields));
                reset = id;
            } else if ((path == "/before" && !before) || (path == "/after" && !after)) {
                require(engine.respond(id, {{":status", "200"}}, bytes(path)));
                if (path == "/before") before = true;
                else after = true;
            }
        }
        require(co_await driver.flush(io));
        if (tunnel && reset && before && after && require(engine.connect_state(reset)).error) break;
    }
    check(engine.state() == http2::State::open, "H2 reset closed the connection");
    http2::ConnectStream stream{engine, tunnel, driver};
    co_await websocket_dialog(stream, false, options, std::move(negotiated), io);
    auto state = require(engine.connect_state(tunnel));
    check(state.remote_end && state.local_end && !state.error, "H2 FIN state mismatch");
    check(driver.received > 0 && driver.sent > 0, "H2 server bypassed TCP");
    require(socket.shutdown_send());
    std::array<std::byte, 4096> remaining{};
    for (;;) {
        auto read = co_await socket.read_some(remaining, io);
        if (!read) { check(read.error() == Errc::eof, "H2 transport drain failed"); break; }
    }
    done = true;
}

Task<void> h2_client(EventLoop& loop, Endpoint endpoint, bool compression, bool& done, OperationOptions io) {
    auto socket = require(co_await transport::tcp::connect(loop, endpoint, {}, io));
    auto engine = h2_session(false);
    TcpDriver driver{socket, engine};
    auto options = websocket_options(compression);
    const auto headers = request_headers("/chat", options);
    check(!engine.request_stream(headers), "H2 CONNECT allowed before peer SETTINGS");
    while (!engine.peer_connect_protocol_enabled() || !engine.local_connect_protocol_acknowledged())
        require(co_await driver.progress(io));
    const auto tunnel = require(engine.request_stream(headers));
    const auto reset = require(engine.request_stream(request_headers("/reset", options)));
    const auto before = require(engine.request(get_headers("/before")));
    require(co_await driver.flush(io));
    while (!require(engine.connect_state(tunnel)).accepted || !require(engine.connect_state(reset)).accepted ||
           !engine.stream(before)->remote_end) require(co_await driver.progress(io));
    auto negotiated = negotiate_response(engine.stream(tunnel)->headers, options);
    static_cast<void>(negotiate_response(engine.stream(reset)->headers, options));
    check(require(engine.take_body(before)) == bytes("/before"), "H2 ordinary stream body lost");
    Bytes queued(body_budget, std::byte{0x42});
    check(require(engine.write_connect(reset, queued)) == queued.size(), "H2 bounded enqueue was short");
    auto blocked = engine.write_connect(reset, queued);
    check(!blocked && blocked.error() == Errc::would_block && engine.queued_body_bytes() == body_budget,
          "H2 output exceeded the configured budget");
    http2::ConnectStream cancelled{engine, reset, driver};
    std::stop_source stop;
    stop.request_stop();
    std::array<std::byte, 1> buffer{};
    const auto received_before_cancel = driver.received;
    const auto sent_before_cancel = driver.sent;
    auto cancelled_read = co_await cancelled.read_some(buffer, {.stop = stop.get_token()});
    check(driver.received == received_before_cancel && driver.sent == sent_before_cancel,
          "pre-cancel touched the underlying socket");
    check(!cancelled_read && cancelled_read.error() == Errc::cancelled, "H2 pre-cancel not observed");
    require(co_await driver.flush(io));
    const auto after = require(engine.request(get_headers("/after")));
    require(co_await driver.flush(io));
    while (!engine.stream(after)->remote_end) require(co_await driver.progress(io));
    check(require(engine.take_body(after)) == bytes("/after") && engine.state() == http2::State::open,
          "H2 stream cancellation damaged ordinary requests");
    http2::ConnectStream stream{engine, tunnel, driver};
    co_await websocket_dialog(stream, true, options, std::move(negotiated), io);
    auto state = require(engine.connect_state(tunnel));
    check(state.remote_end && state.local_end && !state.error, "H2 FIN state mismatch");
    check(driver.received > 0 && driver.sent > 0, "H2 client bypassed TCP");
    done = true;
}

Task<void> h2_scenario(EventLoop& loop, bool compression) {
    auto listener = require(transport::tcp::Listener::bind(loop, Endpoint::loopback(0)));
    bool server = false, client = false;
    TaskScope scope;
    OperationOptions io{.stop = scope.get_stop_token(), .deadline = Clock::now() + 15s};
    scope.spawn(h2_server(loop, listener, compression, server, io));
    scope.spawn(h2_client(loop, listener.local_endpoint(), compression, client, io));
    co_await scope.join();
    check(server && client, "H2 socket tasks did not complete");
}

struct UdpDriver {
    transport::udp::Socket& socket;
    http3::Engine& engine;
    Endpoint peer;
    bool drop_initial_flight = false;
    std::size_t received = 0;
    std::size_t sent = 0;
    std::size_t timer_fires = 0;
    Task<Result<void>> flush(OperationOptions io) {
        if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (io.deadline && *io.deadline <= Clock::now()) co_return fail(Errc::timed_out);
        for (int round = 0; round < 64; ++round) {
            auto packet = engine.poll(quic::detail::now_ns());
            if (!packet) co_return fail(packet.error());
            if (packet->empty()) break;
            if (drop_initial_flight) continue;
            auto size = co_await socket.send_to(*packet, peer, io);
            if (!size) co_return fail(size.error());
            if (*size != packet->size()) co_return fail(std::make_error_code(std::errc::io_error));
            ++sent;
        }
        drop_initial_flight = false;
        co_return Result<void>{};
    }
    Task<Result<void>> progress(OperationOptions io) {
        if (auto result = co_await flush(io); !result) co_return result;
        OperationOptions wait = io;
        bool engine_timer = false;
        const auto expiry = engine.expiry();
        if (expiry != std::numeric_limits<std::uint64_t>::max()) {
            const auto now = quic::detail::now_ns();
            if (expiry <= now) {
                ++timer_fires;
                if (auto result = engine.handle_expiry(now); !result) co_return result;
                co_return co_await flush(io);
            }
            const auto deadline = Clock::time_point{std::chrono::duration_cast<Clock::duration>(
                std::chrono::nanoseconds{static_cast<std::int64_t>(expiry)})};
            if (!wait.deadline || deadline < *wait.deadline) { wait.deadline = deadline; engine_timer = true; }
        }
        std::array<std::byte, 65536> buffer{};
        auto datagram = co_await socket.receive_from(buffer, wait);
        if (!datagram) {
            if (datagram.error() != Errc::timed_out || !engine_timer ||
                (io.deadline && *io.deadline <= Clock::now())) co_return fail(datagram.error());
            if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
            ++timer_fires;
            if (auto result = engine.handle_expiry(quic::detail::now_ns()); !result) co_return result;
        } else if (datagram->peer == peer) {
            ++received;
            if (auto result = engine.receive(std::span(buffer).first(datagram->size), quic::detail::now_ns()); !result)
                co_return result;
        }
        co_return co_await flush(io);
    }
};
static_assert(BoundedStream<http3::ConnectStream<UdpDriver>>);

http3::Limits h3_limits() {
    http3::Limits limits;
    limits.enable_connect_protocol = true;
    limits.max_buffered_body = body_budget;
    return limits;
}
struct Observed {
    http::Headers fields;
    Bytes body;
    bool end = false;
};
void collect(http3::Engine& engine, std::map<std::int64_t, Observed>& records) {
    for (auto& event : engine.take_events()) {
        check(records.size() < 8 || records.contains(event.stream_id), "unbounded test event queue");
        auto& record = records[event.stream_id];
        if (event.kind == http3::Event::Kind::headers) record.fields = std::move(event.fields);
        if (event.kind == http3::Event::Kind::end) record.end = true;
        if (event.kind == http3::Event::Kind::body) {
            check(record.body.size() + event.data.size() <= body_budget, "unbounded ordinary body queue");
            record.body.insert(record.body.end(), event.data.begin(), event.data.end());
            require(engine.consume(event.stream_id, event.data.size()));
        }
    }
}

Task<void> h3_server(transport::udp::Socket& socket, const char* certificate, const char* key,
                     bool compression, bool& done, OperationOptions io) {
    std::array<std::byte, 65536> buffer{};
    auto initial = require(co_await socket.receive_from(buffer, io));
    quic::Options transport_options;
    transport_options.local = require(socket.local_endpoint());
    transport_options.remote = initial.peer;
    transport_options.certificate_file = certificate;
    transport_options.private_key_file = key;
    auto transport_engine = require(quic::Engine::accept(transport_options,
        std::span(buffer).first(initial.size), quic::detail::now_ns()));
    auto engine = require(http3::Engine::create(std::move(transport_engine), true, h3_limits()));
    UdpDriver driver{socket, engine, initial.peer};
    auto options = websocket_options(compression);
    std::map<std::int64_t, Observed> records;
    std::int64_t tunnel = -1, reset = -1;
    ws::Negotiated negotiated;
    bool before = false, after = false;
    for (;;) {
        require(co_await driver.progress(io));
        collect(engine, records);
        for (const auto& [id, record] : records) {
            const auto path = field(record.fields, ":path");
            if (path == "/chat" && tunnel == -1) {
                auto accepted = negotiate_request(record.fields, options);
                require(engine.respond_stream(id, accepted.fields));
                negotiated = std::move(accepted.negotiated);
                tunnel = id;
            } else if (path == "/reset" && reset == -1) {
                auto accepted = negotiate_request(record.fields, options);
                require(engine.respond_stream(id, accepted.fields));
                reset = id;
            } else if ((path == "/before" && !before) || (path == "/after" && !after)) {
                require(engine.respond(id, {{":status", "200"}}, bytes(path)));
                if (path == "/before") before = true;
                else after = true;
            }
        }
        require(co_await driver.flush(io));
        if (tunnel != -1 && reset != -1 && before && after && require(engine.connect_state(reset)).error) break;
    }
    check(engine.ready() && !engine.closed(), "H3 reset closed the connection");
    http3::ConnectStream stream{engine, tunnel, driver};
    co_await websocket_dialog(stream, false, options, std::move(negotiated), io);
    auto state = require(engine.connect_state(tunnel));
    check(state.remote_end && state.local_end && !state.error, "H3 FIN state mismatch");
    check(driver.received > 0 && driver.sent > 0, "H3 server bypassed UDP");
    done = true;
}

Task<void> h3_client(EventLoop& loop, Endpoint peer, const char* certificate, bool compression,
                     bool& done, OperationOptions io) {
    auto socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    quic::Options transport_options;
    transport_options.local = require(socket.local_endpoint());
    transport_options.remote = peer;
    transport_options.ca_file = certificate;
    transport_options.peer_name = "localhost";
    auto transport_engine = require(quic::Engine::client(transport_options, quic::detail::now_ns()));
    auto engine = require(http3::Engine::create(std::move(transport_engine), false, h3_limits()));
    UdpDriver driver{socket, engine, peer};
    auto options = websocket_options(compression);
    const auto headers = request_headers("/chat", options);
    check(!engine.request_stream(headers), "H3 CONNECT allowed before peer SETTINGS");
    while (!engine.ready() || !engine.peer_connect_protocol_enabled()) require(co_await driver.progress(io));
    check(driver.received > 0 && driver.sent > 0, "QUIC handshake bypassed UDP");
    const auto tunnel = require(engine.request_stream(headers));
    const auto reset = require(engine.request_stream(request_headers("/reset", options)));
    const auto before = require(engine.request(get_headers("/before")));
    require(co_await driver.flush(io));
    std::map<std::int64_t, Observed> records;
    while (!require(engine.connect_state(tunnel)).accepted || !require(engine.connect_state(reset)).accepted ||
           !records[before].end) {
        require(co_await driver.progress(io));
        collect(engine, records);
    }
    auto negotiated = negotiate_response(records[tunnel].fields, options);
    static_cast<void>(negotiate_response(records[reset].fields, options));
    check(records[before].body == bytes("/before"), "H3 ordinary stream body lost");
    Bytes queued(body_budget, std::byte{0x42});
    check(require(engine.write_connect(reset, queued)) == queued.size(), "H3 bounded enqueue was short");
    auto blocked = engine.write_connect(reset, queued);
    check(!blocked && blocked.error() == Errc::would_block && engine.queued_body_bytes() == body_budget,
          "H3 output exceeded the configured budget");
    http3::ConnectStream cancelled{engine, reset, driver};
    std::stop_source stop;
    stop.request_stop();
    std::array<std::byte, 1> buffer{};
    const auto received_before_cancel = driver.received;
    const auto sent_before_cancel = driver.sent;
    auto cancelled_read = co_await cancelled.read_some(buffer, {.stop = stop.get_token()});
    check(driver.received == received_before_cancel && driver.sent == sent_before_cancel,
          "pre-cancel touched the underlying socket");
    check(!cancelled_read && cancelled_read.error() == Errc::cancelled, "H3 pre-cancel not observed");
    require(co_await driver.flush(io));
    const auto after = require(engine.request(get_headers("/after")));
    require(co_await driver.flush(io));
    while (!records[after].end) {
        require(co_await driver.progress(io));
        collect(engine, records);
    }
    check(records[after].body == bytes("/after") && engine.ready(),
          "H3 stream cancellation damaged ordinary requests");
    http3::ConnectStream stream{engine, tunnel, driver};
    co_await websocket_dialog(stream, true, options, std::move(negotiated), io);
    auto state = require(engine.connect_state(tunnel));
    check(state.remote_end && state.local_end && !state.error, "H3 FIN state mismatch");
    check(driver.received > 0 && driver.sent > 0, "H3 client bypassed UDP");
    done = true;
}

Task<void> h3_scenario(EventLoop& loop, const char* certificate, const char* key, bool compression) {
    auto socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    const auto peer = require(socket.local_endpoint());
    bool server = false, client = false;
    TaskScope scope;
    OperationOptions io{.stop = scope.get_stop_token(), .deadline = Clock::now() + 15s};
    scope.spawn(h3_server(socket, certificate, key, compression, server, io));
    scope.spawn(h3_client(loop, peer, certificate, compression, client, io));
    co_await scope.join();
    check(server && client, "H3 socket tasks did not complete");
}
}

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    try {
        auto loop = require(EventLoop::create());
        for (bool compression : {false, true}) {
            require(loop.run_until_complete(h2_scenario(loop, compression)));
            std::cout << "H2 TCP Extended CONNECT compression=" << compression << " passed\n";
            require(loop.run_until_complete(h3_scenario(loop, argv[1], argv[2], compression)));
            std::cout << "H3 UDP Extended CONNECT compression=" << compression << " passed\n";
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
