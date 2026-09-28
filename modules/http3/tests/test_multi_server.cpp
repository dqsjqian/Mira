#include "mira/http3/server.hpp"
#include "mira/transport/udp.hpp"

#include <array>
#include <chrono>
#include <iostream>
#include <map>
#include <stdexcept>
#include <source_location>

using namespace Mira;
using namespace std::chrono_literals;
using transport::Endpoint;
using quic::Bytes;

namespace {
template<class T> T require(Result<T> value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error(value.error().message() + " at " + std::to_string(location.line()));
    return std::move(*value);
}
void require(Result<void> value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error(value.error().message() + " at " + std::to_string(location.line()));
}
void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
std::uint64_t now() { return quic::detail::now_ns(); }

Task<void> run(EventLoop& loop, const char* certificate, const char* key) {
    auto socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    auto local = require(socket.local_endpoint());
    quic::Options options;
    options.local = local;
    options.certificate_file = certificate;
    options.private_key_file = key;
    options.max_buffered_bytes = 16384;
    options.idle_timeout_ns = 2'000'000'000;
    http3::Limits h3;
    h3.max_buffered_body = 16384;
    h3.max_header_bytes = 4096;
    h3.max_streams = 8;
    h3.max_events = 64;
    quic::ListenerLimits admission;
    admission.max_connections = 3;
    auto server = require(http3::make_server(options, admission, h3));
    std::vector<transport::udp::Socket> sockets;
    std::vector<http3::Engine> clients;
    std::vector<Endpoint> peers;
    std::vector<Bytes> initials;
    std::array<bool, 4> submitted{}, done{};
    std::array<Bytes, 4> received;
    std::array<http3::Server::Id, 4> ids{};
    std::array<std::byte, 65536> buffer{};
    for (int i = 0; i < 4; ++i) {
        sockets.push_back(require(transport::udp::Socket::bind(loop, Endpoint::loopback(0))));
        peers.push_back(require(sockets.back().local_endpoint()));
        quic::Options client_options;
        client_options.local = peers.back();
        client_options.remote = local;
        client_options.ca_file = certificate;
        client_options.peer_name = "localhost";
        client_options.max_buffered_bytes = 16384;
        auto transport = require(quic::Engine::client(client_options, now()));
        clients.push_back(require(http3::Engine::create(std::move(transport), false, h3)));
        initials.push_back(require(clients.back().poll(now())));
        check(!initials.back().empty(), "missing client Initial");
        require(co_await sockets.back().send_to(initials.back(), local));
        auto input = require(co_await socket.receive_from(buffer, {.deadline = Clock::now() + 1s}));
        auto result = require(server.ingest(input.peer, std::span(buffer).first(input.size), now()));
        if (i < 3) {
            check(result.kind == http3::Server::Ingest::Kind::admitted, "connection not admitted");
            ids[static_cast<std::size_t>(i)] = result.connection_id;
        } else check(result.kind == http3::Server::Ingest::Kind::dropped, "connection cap ignored");
    }
    check(server.size() == 3, "incorrect connection count");
    auto reserved = server.reserved_payload_bytes();
    const auto queue_reserved = server.reserved_queue_entries();
    auto route_count = server.route_count();
    auto duplicate = require(server.ingest(peers[0], initials[0], now()));
    check(duplicate.connection_id == ids[0] && server.size() == 3, "Initial retransmit duplicated connection");
    auto alien = require(server.ingest(peers[1], initials[0], now()));
    check(alien.kind == http3::Server::Ingest::Kind::dropped, "foreign sender accepted");
    Bytes garbage{std::byte{0x40}};
    check(require(server.ingest(peers[0], garbage, now())).kind == http3::Server::Ingest::Kind::dropped,
          "malformed packet accepted");
    garbage.resize(50, std::byte{0x5a});
    check(require(server.ingest(peers[0], garbage, now())).kind == http3::Server::Ingest::Kind::dropped,
          "unknown short CID accepted");
    check(server.route_count() == route_count && server.reserved_payload_bytes() == reserved,
          "unknown packets polluted state");

    // A second dispatcher proves that equal peer endpoints still yield distinct CID routes.
    auto same_peer = require(http3::make_server(options, admission, h3));
    auto first = require(same_peer.ingest(peers[0], initials[0], now()));
    auto second = require(same_peer.ingest(peers[0], initials[1], now()));
    check(first.connection_id != second.connection_id && same_peer.size() == 2,
          "routing is peer-only rather than CID-based");
    check(require(same_peer.ingest(peers[0], initials[0], now())).connection_id == first.connection_id,
          "same-peer CID lookup selected wrong engine");
    auto fair_first = require(same_peer.poll(now()));
    auto fair_second = require(same_peer.poll(now()));
    check(fair_first && fair_second && fair_first->connection_id != fair_second->connection_id,
          "busy connection monopolized round-robin output");
    same_peer.remove(first.connection_id);
    same_peer.remove(second.connection_id);
    check(same_peer.route_count() == 0 && same_peer.reserved_payload_bytes() == 0,
          "explicit removal leaked reservation or routes");

    // Admission reserves entire payload/event ceilings, including idle connections.
    auto limited = admission;
    limited.max_payload_bytes = reserved / 3;
    auto budget = require(http3::make_server(options, limited, h3));
    require(budget.ingest(peers[0], initials[0], now()));
    check(require(budget.ingest(peers[1], initials[1], now())).kind == http3::Server::Ingest::Kind::dropped,
          "global payload budget ignored");
    limited = admission;
    limited.max_queue_entries = queue_reserved / 3;
    auto event_budget = require(http3::make_server(options, limited, h3));
    require(event_budget.ingest(peers[0], initials[0], now()));
    check(require(event_budget.ingest(peers[1], initials[1], now())).kind == http3::Server::Ingest::Kind::dropped,
          "global event budget ignored");

    std::map<std::pair<http3::Server::Id, std::int64_t>, Bytes> bodies;
    bool replacement = false;
    const auto deadline = Clock::now() + 15s;
    while (!done[3] || !done[1] || !done[2]) {
        check(Clock::now() < deadline, "multi-client progress deadline");
        for (std::size_t i = 0; i < clients.size(); ++i) {
            if ((i == 3 && !replacement) || (i == 0 && replacement)) continue;
            auto& client = clients[i];
            if (client.ready() && !submitted[i]) {
                Bytes payload(7000, static_cast<std::byte>(i + 1));
                http3::Headers fields{{":method", "POST"}, {":scheme", "https"},
                                     {":authority", "localhost"}, {":path", "/echo"}};
                require(client.request(fields, payload));
                submitted[i] = true;
            }
            for (int burst = 0; burst < 16; ++burst) {
                auto packet = require(client.poll(now()));
                if (packet.empty()) break;
                require(co_await sockets[i].send_to(packet, local));
            }
        }
        for (int burst = 0; burst < 64; ++burst) {
            auto input = co_await socket.receive_from(buffer, {.deadline = Clock::now() + 100us});
            if (!input) {
                check(input.error() == Errc::timed_out, "UDP receive failed");
                break;
            }
            require(server.ingest(input->peer, std::span(buffer).first(input->size), now()));
        }
        for (auto id : server.connections()) {
            auto* engine = server.connection(id);
            for (auto& event : engine->take_events()) {
                auto stream = std::pair{id, event.stream_id};
                if (event.kind == http3::Event::Kind::body) {
                    auto& body = bodies[stream];
                    body.insert(body.end(), event.data.begin(), event.data.end());
                    require(engine->consume(event.stream_id, event.data.size()));
                } else if (event.kind == http3::Event::Kind::end) {
                    http3::Headers fields{{":status", "200"}};
                    require(engine->respond(event.stream_id, fields, bodies[stream]));
                    bodies.erase(stream);
                }
            }
        }
        for (int burst = 0; burst < 64; ++burst) {
            auto output = require(server.poll(now()));
            if (!output) break;
            require(co_await socket.send_to(output->data, output->peer));
        }
        for (std::size_t i = 0; i < clients.size(); ++i) {
            if ((i == 3 && !replacement) || (i == 0 && replacement)) continue;
            auto& client = clients[i];
            for (int burst = 0; burst < 32; ++burst) {
                auto input = co_await sockets[i].receive_from(buffer, {.deadline = Clock::now() + 100us});
                if (!input) {
                    check(input.error() == Errc::timed_out, "client receive failed");
                    break;
                }
                require(client.receive(std::span(buffer).first(input->size), now()));
            }
            for (auto& event : client.take_events()) {
                if (event.kind == http3::Event::Kind::body) {
                    received[i].insert(received[i].end(), event.data.begin(), event.data.end());
                    require(client.consume(event.stream_id, event.data.size()));
                } else if (event.kind == http3::Event::Kind::end) done[i] = true;
            }
            if (client.expiry() <= now()) require(client.handle_expiry(now()));
        }
        require(server.handle_expiry(now()));
        if (done[0] && done[1] && done[2] && !replacement) {
            auto packet = require(clients[0].close(0, now()));
            require(co_await sockets[0].send_to(packet, local));
            auto input = require(co_await socket.receive_from(buffer, {.deadline = Clock::now() + 1s}));
            require(server.ingest(input.peer, std::span(buffer).first(input.size), now()));
            // Drain packets that might precede the close datagram.
            while (server.connection(ids[0])) {
                input = require(co_await socket.receive_from(buffer, {.deadline = Clock::now() + 1s}));
                require(server.ingest(input.peer, std::span(buffer).first(input.size), now()));
            }
            check(server.size() == 2 && server.tombstone_count() == 1 &&
                      server.reserved_payload_bytes() == reserved / 3 * 2,
                  "peer drain did not release engine admission");
            auto replay = require(server.ingest(peers[0], initials[0], now()));
            check(replay.kind == http3::Server::Ingest::Kind::dropped && replay.connection_id == ids[0],
                  "HTTP/3 draining Initial was re-admitted");
            check(require(server.ingest(peers[1], initials[0], now())).kind ==
                      http3::Server::Ingest::Kind::dropped, "draining changed fixed peer");
            for (int burst = 0; burst < 64; ++burst) {
                auto output = require(server.poll(now()));
                if (!output) break;
                check(output->connection_id != ids[0], "peer draining emitted a close response");
                require(co_await socket.send_to(output->data, output->peer));
            }
            require(co_await sockets[3].send_to(initials[3], local));
            for (;;) {
                input = require(co_await socket.receive_from(buffer, {.deadline = Clock::now() + 1s}));
                auto admitted = require(server.ingest(input.peer, std::span(buffer).first(input.size), now()));
                if (input.peer != peers[3]) continue;
                check(admitted.kind == http3::Server::Ingest::Kind::admitted, "released slot not reusable");
                break;
            }
            replacement = true;
        }
    }
    for (std::size_t i = 0; i < received.size(); ++i)
        check(received[i] == Bytes(7000, static_cast<std::byte>(i + 1)), "cross-client body corruption");
    for (auto id : server.connections())
        check(server.connection(id)->transport().local_connection_ids().size() >= 2,
              "newly issued server CID was not exposed");
    check(server.route_count() >= server.size() * 3, "new CID routing was not refreshed");
    auto future = now() + 60'000'000'000;
    require(server.handle_expiry(future));
    check(server.size() == 0 && server.tombstone_count() == 3 &&
              server.route_count() >= 9 && server.reserved_payload_bytes() == 0,
          "idle timeout lost CID protection or retained payload");
    check(!require(server.poll(future)), "idle timeout sent a close packet");
    require(server.handle_expiry(future + 60'000'000'000));
    check(server.tombstone_count() == 0 && server.route_count() == 0,
          "idle tombstones did not expire");
    check(!server.handle_expiry(future - 1), "backwards time accepted");
}
}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    try {
        auto loop = require(EventLoop::create());
        require(loop.run_until_complete(run(loop, argv[1], argv[2])));
        std::cout << "single-port HTTP/3: CID routing, 3 clients, admission, close, expiry and budgets passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
