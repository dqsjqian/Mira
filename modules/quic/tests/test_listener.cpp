#include "mira/quic/listener.hpp"

#include <array>
#include <iostream>
#include <stdexcept>

using namespace Mira;
namespace {
template<class T> T require(Result<T> result) {
    if (!result) throw std::runtime_error(result.error().message());
    return std::move(*result);
}
void require(Result<void> result) {
    if (!result) throw std::runtime_error(result.error().message());
}
void check(bool result, const char* text) {
    if (!result) throw std::runtime_error(text);
}
}
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    try {
        quic::Options co;
        co.local = transport::Endpoint::loopback(14444);
        co.remote = transport::Endpoint::loopback(14445);
        co.ca_file = argv[1];
        co.peer_name = "localhost";
        co.max_buffered_bytes = 65536;
        auto so = co;
        so.local = co.remote;
        so.certificate_file = argv[1];
        so.private_key_file = argv[2];
        auto listener = require(quic::Listener::create(so));
        std::uint64_t now = 1'000'000'000;
        auto client = require(quic::Engine::client(co, now));
        auto initial = require(client.poll(now));
        auto bad_initial = initial;
        bad_initial[5] = std::byte{0xff};
        check(require(listener.ingest(co.local, bad_initial, now)).kind ==
                  quic::Listener::Ingest::Kind::dropped && listener.size() == 0,
              "malformed long CID polluted admission");
        bad_initial = initial;
        bad_initial.resize(100);
        check(require(listener.ingest(co.local, bad_initial, now)).kind ==
                  quic::Listener::Ingest::Kind::dropped && listener.route_count() == 0,
              "undersized Initial was admitted");
        quic::ListenerLimits tiny_routes;
        tiny_routes.max_connection_ids = 1;
        auto insufficient_routes = require(quic::Listener::create(so, tiny_routes));
        check(!insufficient_routes.ingest(co.local, initial, now) &&
                  insufficient_routes.size() == 0 && insufficient_routes.route_count() == 0 &&
                  insufficient_routes.reserved_payload_bytes() == 0,
              "CID budget overflow did not roll back admission");
        auto expired = require(quic::Listener::create(so));
        require(expired.ingest(co.local, initial, now));
        require(expired.handle_expiry(now + 11'000'000'000));
        check(expired.size() == 0 && expired.route_count() == 0,
              "handshake expiry retained connection");
        ResourceBudget shared_payload{2 * so.max_buffered_bytes};
        auto one = require(quic::Listener::create(so, {}, {}, 0, 0, shared_payload));
        auto two = require(quic::Listener::create(so, {}, {}, 0, 0, shared_payload));
        auto charged = require(one.ingest(co.local, initial, now));
        check(charged.kind == quic::Listener::Ingest::Kind::admitted && shared_payload.used() == shared_payload.limit(),
              "shared listener payload budget not reserved");
        check(require(two.ingest(co.local, initial, now)).kind == quic::Listener::Ingest::Kind::dropped,
              "second listener oversubscribed shared process accounting");
        check(one.remove(charged.connection_id) && shared_payload.used() == 0,
              "listener removal did not release shared reservation");
        auto admitted_again = require(two.ingest(co.local, initial, now));
        check(admitted_again.kind == quic::Listener::Ingest::Kind::admitted,
              "released shared capacity did not admit another listener");
        check(two.remove(admitted_again.connection_id), "shared test cleanup failed");
        auto accepted = require(listener.ingest(co.local, initial, now));
        check(accepted.kind == quic::Listener::Ingest::Kind::admitted, "initial not admitted");
        auto id = accepted.connection_id;
        auto drive = [&] {
            now += 1'000'000;
            if (client.expiry() <= now) require(client.handle_expiry(now));
            require(listener.handle_expiry(now));
            for (int n = 0; n < 32; ++n) {
                auto packet = require(client.poll(now));
                if (packet.empty()) break;
                require(listener.ingest(co.local, packet, now));
            }
            for (int n = 0; n < 32; ++n) {
                auto packet = require(listener.poll(now));
                if (!packet) break;
                check(packet->peer == co.local && packet->connection_id == id, "incorrect route");
                require(client.receive(packet->data, now));
            }
        };
        for (int n = 0; n < 2000 && !client.handshake_complete(); ++n) drive();
        check(client.handshake_complete(), "handshake timeout");
        for (int n = 0; n < 10; ++n) drive();
        auto* server = listener.connection(id);
        check(server && server->local_connection_ids().size() >= 2, "new CIDs missing");
        // A known CID with a foreign sender is rejected before reaching the engine.
        auto cid = server->local_connection_ids().front();
        quic::Bytes packet{std::byte{0x40}};
        packet.insert(packet.end(), cid.begin(), cid.end());
        packet.resize(80, std::byte{0});
        auto foreign = require(listener.ingest(transport::Endpoint::loopback(14446), packet, now));
        check(foreign.kind == quic::Listener::Ingest::Kind::dropped && !server->closed(),
              "foreign sender altered connection");
        // Every live CID resolves, including IDs issued after the handshake.
        // Authentication still belongs to ngtcp2; bogus ciphertext has no effect.
        for (const auto& local_cid : server->local_connection_ids()) {
            quic::Bytes probe{std::byte{0x40}};
            probe.insert(probe.end(), local_cid.begin(), local_cid.end());
            probe.resize(80, std::byte{0});
            auto routed = require(listener.ingest(co.local, probe, now));
            check(routed.kind == quic::Listener::Ingest::Kind::delivered &&
                      routed.connection_id == id && !server->closed(), "issued CID not routed");
        }
        auto a = require(client.open_stream());
        auto b = require(client.open_stream());
        std::array<std::byte, 1> byte{std::byte{0x41}};
        for (int n = 0; n < 4096; ++n) require(client.write(n % 2 ? a : b, byte, false));
        check(!client.write(a, byte, false), "cross-stream chunk budget not enforced");
        std::size_t consumed = 0;
        for (int n = 0; n < 5000 && (consumed < 4096 || client.write_capacity() != 65536); ++n) {
            drive();
            (void)client.take_events();
            for (auto& event : server->take_events()) {
                if (event.kind == quic::Event::Kind::data) {
                    consumed += event.data.size();
                    require(server->consume(event.stream_id, event.data.size()));
                }
            }
        }
        check(consumed == 4096 && client.write_capacity() == 65536, "ACK did not release budget");
        require(client.write(a, byte, false));
        check(!listener.close(id, std::uint64_t{1} << 62, now) && listener.size() == 1,
              "invalid close mutated admission");
        auto closed = require(listener.close(id, 0, now));
        check(!closed.data.empty() && listener.size() == 0 && listener.route_count() == 0 &&
                  listener.reserved_queue_entries() == 0, "local close leaked state");
        require(client.receive(closed.data, now));
        check(client.closed(), "client did not observe close");
        check(!listener.close(id, 0, now), "duplicate close accepted");
        std::cout << "QUIC listener CID lifecycle and aggregate queue budget passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
