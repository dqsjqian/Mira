// Loopback-only independent-stack conformance peer, not a production server.
#include "mira/http3/server.hpp"
#include "mira/transport/udp.hpp"
#include "mira/ws/extended_connect.hpp"
#include "mira/ws/frame.hpp"

#include <array>
#include <iostream>
#include <map>
#include <stdexcept>

using namespace Mira;
using namespace std::chrono_literals;
namespace {
template<class T> T require(Result<T> value) {
    if (!value) throw std::runtime_error(value.error().message());
    return std::move(*value);
}
void require(Result<void> value) { if (!value) throw std::runtime_error(value.error().message()); }
struct Request { bool early = false; };
struct Tunnel {
    ws::FrameParser parser{ws::Role::server};
    std::vector<std::byte> output;
    std::size_t offset = 0;
    bool close = false;
};
Task<void> serve(EventLoop& loop, const char* certificate, const char* key) {
    auto socket = require(transport::udp::Socket::bind(loop, transport::Endpoint::loopback(0)));
    quic::Options options;
    options.local = require(socket.local_endpoint());
    options.certificate_file = certificate;
    options.private_key_file = key;
    options.service_scope = "cross-stack-interop";
    options.early_data = quic::EarlyDataPolicy::replay_safe;
    // First early handshake is accepted; subsequent new early handshakes are
    // refused once the store is full, exercising independent-client fallback.
    options.replay_store = require(quic::MemoryReplayStore::create(1));
    http3::Limits limits;
    limits.enable_connect_protocol = true;
    options.early_data_context = http3::early_data_context(limits);
    options.server_context = require(quic::ServerContext::create(options));
    auto server = require(http3::make_server(options, {}, limits));
    std::map<std::pair<quic::Listener::Id, std::int64_t>, Request> requests;
    std::map<std::pair<quic::Listener::Id, std::int64_t>, Tunnel> tunnels;
    std::cout << "PORT=" << options.local.port() << '\n' << std::flush;
    std::array<std::byte, 65536> input{};
    const auto end = Clock::now() + 90s;
    while (Clock::now() < end) {
        require(server.handle_expiry(quic::detail::now_ns()));
        std::erase_if(requests, [&](const auto& item) { return !server.connection(item.first.first); });
        std::erase_if(tunnels, [&](const auto& item) { return !server.connection(item.first.first); });
        for (const auto id : server.connections()) {
            auto& engine = *server.connection(id);
            for (auto& event : engine.take_events()) {
                const auto token = std::pair{id, event.stream_id};
                if (event.kind == http3::Event::Kind::headers) {
                    const auto protocol = std::find_if(event.fields.begin(), event.fields.end(),
                        [](const auto& field) { return field.name == ":protocol"; });
                    if (protocol != event.fields.end()) {
                        ws::HandshakeOptions handshake;
                        handshake.subprotocols = {"interop"};
                        handshake.require_subprotocol = true;
                        auto negotiated = require(ws::negotiate_extended_server(event.fields, handshake));
                        negotiated.fields.insert(negotiated.fields.begin(), {":status", "200"});
                        require(engine.respond_stream(event.stream_id, negotiated.fields));
                        tunnels.try_emplace(token);
                    } else {
                        if (requests.size() >= 128) throw std::runtime_error("request capacity");
                        requests.emplace(token, Request{event.early_data});
                    }
                } else if (event.kind == http3::Event::Kind::body) {
                    require(engine.consume(event.stream_id, event.data.size()));
                } else if (event.kind == http3::Event::Kind::end && requests.contains(token)) {
                    const auto early = requests.at(token).early;
                    const std::string text = early ? "early" : "one-rtt";
                    http3::Headers headers{{":status", "200"}, {"x-mira-early", early ? "1" : "0"},
                                           {"content-length", std::to_string(text.size())}};
                    require(engine.respond(event.stream_id, headers, std::as_bytes(std::span(text))));
                    requests.erase(token);
                } else if (event.kind == http3::Event::Kind::reset) {
                    requests.erase(token);
                    tunnels.erase(token);
                }
            }
        }
        for (auto it = tunnels.begin(); it != tunnels.end();) {
            auto& [token, tunnel] = *it;
            auto* engine = server.connection(token.first);
            if (!engine) { it = tunnels.erase(it); continue; }
            const auto stream = token.second;
            if (tunnel.offset == tunnel.output.size() && !tunnel.close) {
                std::array<std::byte, 4096> bytes{};
                auto read = engine->read_connect(stream, bytes);
                if (read) {
                    std::size_t consumed = 0;
                    while (consumed < *read) {
                        auto frame = require(tunnel.parser.feed(std::span<const std::byte>{bytes}.subspan(consumed, *read - consumed)));
                        if (!frame.consumed) throw std::runtime_error("WebSocket parser stalled");
                        consumed += frame.consumed;
                        if (!frame.frame) continue;
                        auto response = std::move(*frame.frame);
                        if (response.opcode == ws::Opcode::pong) continue;
                        if (response.opcode == ws::Opcode::ping) response.opcode = ws::Opcode::pong;
                        if (response.opcode == ws::Opcode::close) tunnel.close = true;
                        auto wire = require(ws::serialize(response, ws::Role::server));
                        if (wire.size() > 65536 - tunnel.output.size()) throw std::runtime_error("tunnel output capacity");
                        tunnel.output.insert(tunnel.output.end(), wire.begin(), wire.end());
                    }
                } else if (read.error() != Errc::would_block) {
                    static_cast<void>(engine->cancel(stream));
                    static_cast<void>(engine->release_connect(stream));
                    it = tunnels.erase(it);
                    continue;
                }
            }
            if (tunnel.offset != tunnel.output.size()) {
                auto written = engine->write_connect(stream, std::span<const std::byte>{tunnel.output}.subspan(tunnel.offset));
                if (written) tunnel.offset += *written;
                else if (written.error() != Errc::would_block) throw std::runtime_error(written.error().message());
            }
            if (tunnel.offset == tunnel.output.size()) {
                tunnel.output.clear(); tunnel.offset = 0;
                if (tunnel.close) {
                    require(engine->finish_body(stream));
                    it = tunnels.erase(it);
                    continue;
                }
            }
            ++it;
        }
        for (int burst = 0; burst < 64; ++burst) {
            auto packet = server.poll(quic::detail::now_ns());
            if (!packet) continue; // Dispatcher isolates failed peers.
            if (!*packet) break;
            auto& out = **packet;
            require(co_await socket.send_to(out.data, out.peer, {.deadline = Clock::now() + 1s}));
        }
        auto packet = co_await socket.receive_from(input, {.deadline = Clock::now() + 1ms});
        if (!packet) {
            if (packet.error() == Errc::timed_out) continue;
            throw std::runtime_error(packet.error().message());
        }
        auto ingested = server.ingest(packet->peer, std::span<const std::byte>{input}.first(packet->size), quic::detail::now_ns());
        if (!ingested) std::cerr << "peer rejected: " << ingested.error().message() << '\n';
    }
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 3) return 2;
        auto loop = require(EventLoop::create());
        require(loop.run_until_complete(serve(loop, argv[1], argv[2])));
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
