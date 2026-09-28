#include "mira/http3/server.hpp"
#include "mira/transport/udp.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

using namespace Mira;
using namespace std::chrono_literals;
using quic::Bytes;
using transport::Endpoint;

namespace {
void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
template<class T> T require(Result<T> value, std::string_view context) {
    if (!value) throw std::runtime_error(std::string(context) + ": " + value.error().message());
    return std::move(*value);
}
void require(Result<void> value, std::string_view context) {
    if (!value) throw std::runtime_error(std::string(context) + ": " + value.error().message());
}
std::uint64_t now() { return quic::detail::now_ns(); }

Task<Bytes> wire(transport::udp::Socket& sender, transport::udp::Socket& receiver,
                 const Endpoint& source, const Endpoint& destination, std::span<const std::byte> data) {
    std::array<std::byte, 65536> buffer{};
    auto sent = require(co_await sender.send_to(data, destination,
        {.deadline = Clock::now() + 1s}), "UDP send");
    auto packet = require(co_await receiver.receive_from(buffer,
        {.deadline = Clock::now() + 1s}), "UDP receive");
    check(sent == data.size() && packet.size == data.size() && packet.peer == source,
          "UDP payload size or fixed peer mismatch");
    check(std::equal(data.begin(), data.end(), buffer.begin()), "UDP content mismatch");
    co_return Bytes(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(packet.size));
}

Task<void> run(EventLoop& loop, const char* certificate, const char* key) {
    auto socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)), "server bind");
    const auto local = require(socket.local_endpoint(), "server address");
    quic::Options options;
    options.local = local;
    options.certificate_file = certificate;
    options.private_key_file = key;
    options.max_buffered_bytes = 16384;
    http3::Limits h3;
    h3.max_buffered_body = 16384;
    h3.max_header_bytes = 4096;
    h3.max_streams = 8;
    h3.max_events = 128;
    quic::ListenerLimits admission;
    admission.max_connections = 2;
    admission.max_closing_connections = 2;
    quic::RetryOptions retry;
    retry.policy = quic::RetryPolicy::required;
    retry.max_replies_per_window = 8;
    ResourceBudget budget(1024 * 1024);
    auto server = require(http3::make_server(options, admission, h3, budget, retry), "HTTP/3 listener");

    std::vector<transport::udp::Socket> sockets;
    std::vector<Endpoint> peers;
    std::vector<http3::Engine> clients;
    std::array<http3::Server::Id, 2> ids{};
    std::array<std::int64_t, 2> streams{-1, -1};
    std::array<Bytes, 2> uploaded, downloaded, retried_initials;
    std::array<bool, 2> done{}, headers{};
    Bytes body(12000);
    for (std::size_t i = 0; i < body.size(); ++i) body[i] = static_cast<std::byte>((i * 31 + i / 257) & 255);

    sockets.reserve(2);
    peers.reserve(2);
    clients.reserve(2);
    for (std::size_t i = 0; i < 2; ++i) {
        sockets.push_back(require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)), "client bind"));
        peers.push_back(require(sockets.back().local_endpoint(), "client address"));
        auto client_options = options;
        client_options.certificate_file.clear();
        client_options.private_key_file.clear();
        client_options.local = peers.back();
        client_options.remote = local;
        client_options.ca_file = certificate;
        client_options.peer_name = "localhost";
        auto transport = require(quic::Engine::client(client_options, now()), "QUIC client");
        clients.push_back(require(http3::Engine::create(std::move(transport), false, h3), "HTTP/3 client"));
        auto initial = require(clients.back().poll(now()), "client Initial");
        check(initial.size() >= 1200, "Initial not padded");
        auto input = co_await wire(sockets.back(), socket, peers.back(), local, initial);
        const auto before_size = server.size();
        const auto before_routes = server.route_count();
        const auto before_reserved = server.reserved_payload_bytes();
        auto result = require(server.ingest(peers.back(), input, now()), "Initial ingest");
        check(result.kind == http3::Server::Ingest::Kind::retry && result.connection_id == 0 &&
                  result.reply && result.reply->connection_id == 0 && result.reply->peer == peers.back(),
              "required Retry was not returned statelessly");
        check(result.reply->data.size() <= initial.size() && server.size() == before_size &&
                  server.route_count() == before_routes && server.reserved_payload_bytes() == before_reserved &&
                  budget.used() == before_reserved, "unvalidated Initial allocated connection state");
        auto response = co_await wire(socket, sockets.back(), local, peers.back(), result.reply->data);
        require(clients.back().receive(response, now()), "Retry receive");
        auto retried = require(clients.back().poll(now()), "retried Initial");
        check(!retried.empty(), "Retry did not restart Initial");
        retried_initials[i] = retried;
        if (i == 0) {
            auto alien_socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)), "alien bind");
            const auto alien_peer = require(alien_socket.local_endpoint(), "alien address");
            check(alien_peer != peers.back() && server.size() == 0 && server.route_count() == 0 &&
                      server.tombstone_count() == 0 && budget.used() == 0,
                  "changed-peer token test requires unallocated admission capacity");
            auto alien_input = co_await wire(alien_socket, socket, alien_peer, local, retried);
            auto rejected = require(server.ingest(alien_peer, alien_input, now()), "changed-peer token ingest");
            check(rejected.kind == http3::Server::Ingest::Kind::dropped && !rejected.reply &&
                      !rejected.connection_id && server.size() == 0 && server.route_count() == 0 &&
                      server.reserved_payload_bytes() == 0 && server.reserved_queue_entries() == 0 &&
                      server.reserved_close_bytes() == 0 && budget.used() == 0,
                  "token from another UDP peer allocated connection state before admission");
        }
        input = co_await wire(sockets.back(), socket, peers.back(), local, retried);
        result = require(server.ingest(peers.back(), input, now()), "validated Initial ingest");
        check(result.kind == http3::Server::Ingest::Kind::admitted && result.connection_id != 0,
              "valid token did not admit HTTP/3 connection");
        ids[i] = result.connection_id;
    }
    check(ids[0] != ids[1] && server.size() == 2, "clients shared a connection");

    const auto deadline = Clock::now() + 10s;
    while (!done[0] || !done[1]) {
        check(Clock::now() < deadline, "Retry HTTP/3 request deadline");
        for (std::size_t i = 0; i < 2; ++i) {
            if (clients[i].ready() && streams[i] == -1) {
                http3::Headers fields{{":method", "POST"}, {":scheme", "https"},
                                     {":authority", "localhost"}, {":path", "/retry"},
                                     {"content-length", std::to_string(body.size())}};
                streams[i] = require(clients[i].request(fields, body), "POST request");
            }
            for (unsigned burst = 0; burst < 8; ++burst) {
                auto packet = require(clients[i].poll(now()), "client poll");
                if (packet.empty()) break;
                auto input = co_await wire(sockets[i], socket, peers[i], local, packet);
                auto result = require(server.ingest(peers[i], input, now()), "server ingest");
                check(result.kind == http3::Server::Ingest::Kind::delivered, "established CID not delivered");
            }
        }
        for (std::size_t i = 0; i < 2; ++i) {
            auto* engine = server.connection(ids[i]);
            check(engine != nullptr, "Retry connection disappeared");
            for (const auto& event : engine->take_events()) {
                if (event.kind == http3::Event::Kind::body) {
                    check(event.stream_id == streams[i] && event.data.size() <= body.size() - uploaded[i].size(),
                          "cross-client or oversized request body");
                    uploaded[i].insert(uploaded[i].end(), event.data.begin(), event.data.end());
                    require(engine->consume(event.stream_id, event.data.size()), "server consume");
                } else if (event.kind == http3::Event::Kind::end) {
                    check(uploaded[i] == body, "POST bytes corrupted after Retry");
                    require(engine->respond(event.stream_id,
                        {{":status", "200"}, {"content-length", std::to_string(body.size())}}, body), "response");
                } else check(event.kind == http3::Event::Kind::headers, "unexpected request event");
            }
        }
        for (unsigned burst = 0; burst < 16; ++burst) {
            auto packet = require(server.poll(now()), "server poll");
            if (!packet) break;
            const std::size_t i = packet->connection_id == ids[0] ? 0 : 1;
            check(packet->connection_id == ids[i] && packet->peer == peers[i], "response peer changed");
            auto input = co_await wire(socket, sockets[i], local, peers[i], packet->data);
            require(clients[i].receive(input, now()), "client receive");
        }
        for (std::size_t i = 0; i < 2; ++i) {
            for (const auto& event : clients[i].take_events()) {
                check(event.stream_id == streams[i], "wrong response stream");
                if (event.kind == http3::Event::Kind::headers) {
                    check(!headers[i], "duplicate response headers");
                    for (const auto& item : event.fields)
                        if (item.name == ":status" && item.value == "200") headers[i] = true;
                    check(headers[i], "wrong response status");
                } else if (event.kind == http3::Event::Kind::body) {
                    check(event.data.size() <= body.size() - downloaded[i].size(), "oversized response");
                    downloaded[i].insert(downloaded[i].end(), event.data.begin(), event.data.end());
                    require(clients[i].consume(event.stream_id, event.data.size()), "client consume");
                } else if (event.kind == http3::Event::Kind::end) {
                    check(headers[i] && !done[i] && downloaded[i] == body, "response bytes corrupted");
                    done[i] = true;
                } else throw std::runtime_error("unexpected response event");
            }
            if (clients[i].expiry() <= now()) require(clients[i].handle_expiry(now()), "client expiry");
        }
        require(server.handle_expiry(now()), "server expiry");
        require(co_await loop.sleep_for(1ms, {.deadline = Clock::now() + 1s}), "pump timer");
    }
    for (std::size_t i = 0; i < 2; ++i) {
        auto packet = require(server.close(ids[i], 0, now()), "close server");
        auto input = co_await wire(socket, sockets[i], local, peers[i], packet.data);
        require(clients[i].receive(input, now()), "receive close");
        check(clients[i].closed(), "client did not enter drain");
        auto replay = co_await wire(sockets[i], socket, peers[i], local, retried_initials[i]);
        auto result = require(server.ingest(peers[i], replay, now()), "draining replay");
        check(result.kind == http3::Server::Ingest::Kind::dropped && result.connection_id == ids[i],
              "token-bearing Initial reopened a tombstone");
    }
    check(server.size() == 0 && server.tombstone_count() == 2 &&
              server.reserved_payload_bytes() == server.reserved_close_bytes() &&
              server.reserved_queue_entries() == 0, "close retained application reservations");
    const auto drain_deadline = Clock::now() + 10s;
    while (server.tombstone_count()) {
        check(Clock::now() < drain_deadline, "closing tombstone expiry deadline");
        require(server.handle_expiry(now()), "drain expiry");
        require(co_await loop.sleep_for(1ms, {.deadline = Clock::now() + 1s}), "drain timer");
    }
    check(server.route_count() == 0 && server.reserved_payload_bytes() == 0 && budget.used() == 0,
          "Retry UDP test leaked routes or reservations");
}
}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    try {
        auto loop = require(EventLoop::create(), "event loop");
        require(loop.run_until_complete(run(loop, argv[1], argv[2])), "run Retry UDP test");
        std::cout << "HTTP/3 Retry over UDP: two fixed peers, stateless admission, byte-exact POST, close and drain passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
