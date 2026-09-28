#include "mira/quic/listener.hpp"

#include <array>
#include <iostream>
#include <stdexcept>
#include <source_location>

using namespace Mira;
namespace {
template<class T> T require(Result<T> result, std::source_location location = std::source_location::current()) {
    if (!result) throw std::runtime_error(result.error().message() + " at " + std::to_string(location.line()));
    return std::move(*result);
}
void require(Result<void> result, std::source_location location = std::source_location::current()) {
    if (!result) throw std::runtime_error(result.error().message() + " at " + std::to_string(location.line()));
}
void check(bool result, const char* text) {
    if (!result) throw std::runtime_error(text);
}
void handshake(quic::Listener& listener, quic::Engine& client, quic::Listener::Id id,
               const transport::Endpoint& peer, std::uint64_t& now) {
    for (int n = 0; n < 3000; ++n) {
        now += 1'000'000;
        require(listener.handle_expiry(now));
        if (client.expiry() <= now) require(client.handle_expiry(now));
        for (int burst = 0; burst < 32; ++burst) {
            auto packet = require(client.poll(now));
            if (packet.empty()) break;
            require(listener.ingest(peer, packet, now));
        }
        for (int burst = 0; burst < 32; ++burst) {
            auto packet = require(listener.poll(now));
            if (!packet) break;
            check(packet->connection_id == id && packet->peer == peer, "handshake route mismatch");
            require(client.receive(packet->data, now));
        }
        auto* server = listener.connection(id);
        check(server, "handshake lost server");
        if (n > 20 && client.handshake_complete() && server->handshake_complete()) return;
    }
    throw std::runtime_error("handshake deadline");
}
void saturated_deadline(const quic::Options& co, const quic::Options& so) {
    auto listener = require(quic::Listener::create(so));
    std::uint64_t now = 1'000'000'000;
    auto client = require(quic::Engine::client(co, now));
    auto initial = require(client.poll(now));
    auto id = require(listener.ingest(co.local, initial, now)).connection_id;
    // Advance closing time only, without invoking ngtcp2 timers outside their normal range.
    now = std::numeric_limits<std::uint64_t>::max() - 1;
    require(listener.close(id, 0, now));
    check(listener.expiry() == std::numeric_limits<std::uint64_t>::max(),
          "near-maximum close deadline wrapped");
    ++now;
    require(listener.handle_expiry(now));
    auto replay = require(listener.ingest(co.local, initial, now));
    check(listener.tombstone_count() == 1 && replay.kind == quic::Listener::Ingest::Kind::dropped &&
              !require(listener.poll(now)), "saturated clock discarded CID or bypassed PTO pacing");
    check(listener.remove(id), "saturated tombstone could not be explicitly purged");
}
void cid_exhaustion(const quic::Options& co, const quic::Options& so) {
    auto factory = [first = true](quic::Options options, std::span<const std::byte> input,
                                  std::uint64_t now) mutable -> Result<quic::Engine> {
        if (std::exchange(first, false)) options.max_connection_ids = 2;
        return quic::Engine::accept(std::move(options), input, now);
    };
    auto listener = require(quic::Listener::create(so, {}, std::move(factory)));
    std::uint64_t now = 1'000'000'000;
    auto client = require(quic::Engine::client(co, now));
    auto initial = require(client.poll(now));
    auto id = require(listener.ingest(co.local, initial, now)).connection_id;
    auto other_options = co;
    other_options.local = transport::Endpoint::loopback(14448);
    auto other = require(quic::Engine::client(other_options, now));
    auto other_initial = require(other.poll(now));
    auto other_id = require(listener.ingest(other_options.local, other_initial, now)).connection_id;
    bool error_seen = false;
    for (int n = 0; n < 3000 && !error_seen; ++n) {
        now += 1'000'000;
        for (int burst = 0; burst < 32; ++burst) {
            auto packet = require(client.poll(now));
            if (packet.empty()) break;
            if (!listener.ingest(co.local, packet, now)) { error_seen = true; break; }
        }
        if (error_seen) break;
        for (int burst = 0; burst < 32; ++burst) {
            auto packet = listener.poll(now);
            if (!packet) { error_seen = true; break; }
            if (!*packet) break;
            if ((*packet)->connection_id == id) require(client.receive((*packet)->data, now));
            else require(other.receive((*packet)->data, now));
        }
    }
    check(error_seen && listener.size() == 1 && listener.tombstone_count() == 1 &&
              !listener.connection(id) && listener.route_count() >= 4,
          "CID exhaustion evicted an issued CID or damaged another connection");
    check(require(listener.ingest(co.local, initial, now)).connection_id == id,
          "CID exhaustion forgot original Initial");
    unsigned terminal_packets = 0;
    for (int n = 0; n < 32; ++n) {
        auto packet = require(listener.poll(now));
        if (!packet) break;
        if (packet->connection_id == id) {
            check(!packet->data.empty(), "automatic failure produced no encrypted close");
            ++terminal_packets;
        } else require(other.receive(packet->data, now));
    }
    check(terminal_packets == 1, "automatic failure repeatedly polled close or produced none");
    handshake(listener, other, other_id, other_options.local, now);
    check(listener.size() == 1 && listener.connection(other_id)->handshake_complete(),
          "one connection failure poisoned another handshake");
}
void draining_and_quota(const quic::Options& co, const quic::Options& so) {
    auto ceiling = 2 * so.max_buffered_bytes + quic::detail::kClosePacket;
    ResourceBudget shared{ceiling};
    quic::ListenerLimits limits;
    limits.max_closing_connections = 1;
    auto listener = require(quic::Listener::create(so, limits, {}, 0, 0, shared));
    std::uint64_t now = 1'000'000'000;
    auto client = require(quic::Engine::client(co, now));
    auto initial = require(client.poll(now));
    auto id = require(listener.ingest(co.local, initial, now)).connection_id;
    auto other_options = co;
    other_options.local = transport::Endpoint::loopback(14447);
    auto other = require(quic::Engine::client(other_options, now));
    auto other_initial = require(other.poll(now));
    check(require(listener.ingest(other_options.local, other_initial, now)).kind ==
              quic::Listener::Ingest::Kind::dropped, "active connection did not reserve closing slot");
    handshake(listener, client, id, co.local, now);
    const auto retained = listener.connection(id)->retained_connection_ids();
    const auto pto = listener.connection(id)->pto();
    auto close = require(client.close(0, now));
    auto closed = require(listener.ingest(co.local, close, now));
    check(closed.kind == quic::Listener::Ingest::Kind::removed && listener.size() == 0 &&
              listener.tombstone_count() == 1 && listener.route_count() == retained.size() &&
              listener.expiry() >= now + 3 * pto && shared.used() == 0 &&
              listener.reserved_close_bytes() == 0 && listener.reserved_queue_entries() == 0,
          "draining did not retain metadata and release shared payload");
    auto deadline = listener.expiry();
    check(require(listener.ingest(other_options.local, other_initial, now)).kind ==
              quic::Listener::Ingest::Kind::dropped, "full closing quota admitted a new connection");
    for (int n = 0; n < 4; ++n) {
        now += pto / 2;
        require(listener.ingest(co.local, initial, now));
        require(listener.ingest(co.local, close, now));
        require(listener.ingest(other_options.local, initial, now));
        require(listener.handle_expiry(now));
        check(!require(listener.poll(now)), "draining sent a datagram");
    }
    require(listener.handle_expiry(deadline - 1));
    check(listener.tombstone_count() == 1, "draining expired too early");
    require(listener.handle_expiry(deadline));
    auto admitted = require(listener.ingest(other_options.local, other_initial, deadline));
    check(admitted.kind == quic::Listener::Ingest::Kind::admitted && shared.used() == ceiling,
          "expired draining did not release metadata quota");
    check(listener.remove(admitted.connection_id) && shared.used() == 0, "quota cleanup failed");

    auto closing = require(quic::Listener::create(so, limits, {}, 0, 0, shared));
    now = deadline;
    id = require(closing.ingest(co.local, initial, now)).connection_id;
    auto packet = require(closing.close(id, 0, now));
    check(!packet.data.empty() && shared.used() == quic::detail::kClosePacket &&
              closing.reserved_close_bytes() == shared.used(), "closing cache was not charged");
    check(require(closing.ingest(other_options.local, other_initial, now)).kind ==
              quic::Listener::Ingest::Kind::dropped, "closing quota evicted a protected CID");
    auto competitor = require(quic::Listener::create(so, {}, {}, 0, 0, shared));
    check(require(competitor.ingest(other_options.local, other_initial, now)).kind ==
              quic::Listener::Ingest::Kind::dropped && shared.used() == quic::detail::kClosePacket,
          "partial shared admission leaked or oversubscribed close-cache budget");
    deadline = closing.expiry();
    require(closing.handle_expiry(deadline));
    check(shared.used() == 0 && closing.route_count() == 0, "closing shared cache leaked at expiry");
    auto fresh = require(competitor.ingest(other_options.local, other_initial, deadline));
    check(fresh.kind == quic::Listener::Ingest::Kind::admitted, "shared capacity was not released");
    check(competitor.remove(fresh.connection_id) && shared.used() == 0, "shared cleanup failed");
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
        draining_and_quota(co, so);
        cid_exhaustion(co, so);
        saturated_deadline(co, so);
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
        check(!quic::Listener::create(so, tiny_routes), "unprotectable CID quota accepted");
        auto maximum = std::numeric_limits<std::uint64_t>::max();
        check(quic::detail::closing_deadline(17, 11) == 50 &&
                  quic::detail::closing_deadline(maximum - 1, 1) == maximum &&
                  quic::detail::closing_deadline(1, maximum) == maximum,
              "closing deadline wrapped");
        auto expired = require(quic::Listener::create(so));
        require(expired.ingest(co.local, initial, now));
        require(expired.handle_expiry(now + 11'000'000'000));
        check(expired.size() == 0 && expired.route_count() >= 2 && expired.tombstone_count() == 1,
              "handshake expiry forgot protected CIDs");
        check(require(expired.ingest(co.local, initial, now + 11'000'000'000)).kind ==
                  quic::Listener::Ingest::Kind::dropped, "expired handshake re-admitted Initial");
        (void)require(expired.poll(now + 11'000'000'000));
        require(expired.handle_expiry(expired.expiry()));
        check(expired.route_count() == 0 && expired.reserved_payload_bytes() == 0,
              "handshake tombstone did not expire");
        ResourceBudget shared_payload{2 * so.max_buffered_bytes + quic::detail::kClosePacket};
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
        auto retained = server->retained_connection_ids();
        auto pto = server->pto();
        check(pto > 0 && pto < 10'000'000'000, "invalid ngtcp2 PTO");
        auto closed = require(listener.close(id, 0, now));
        auto close_time = now;
        check(!closed.data.empty() && listener.size() == 0 &&
                  listener.route_count() == retained.size() && listener.tombstone_count() == 1 &&
                  listener.reserved_payload_bytes() == quic::detail::kClosePacket &&
                  listener.reserved_queue_entries() == 0 && !listener.connection(id),
              "local close did not shed engine while protecting CID cache");
        check(listener.expiry() == close_time + 3 * pto, "close lifetime did not use ngtcp2 PTO");
        check(!require(listener.poll(now)), "close retransmitted without input");
        check(!listener.close(id, 0, now), "duplicate close accepted");
        check(require(listener.ingest(co.local, initial, now)).kind ==
                  quic::Listener::Ingest::Kind::dropped, "Initial re-admitted during closing");
        check(!require(listener.poll(now)), "close repeated before one PTO");
        now += pto;
        check(!require(listener.poll(now)), "timer-only close retransmission");
        check(require(listener.ingest(transport::Endpoint::loopback(14446), initial, now)).kind ==
                  quic::Listener::Ingest::Kind::dropped && !require(listener.poll(now)),
              "foreign peer triggered reflected close");
        auto unknown = packet;
        unknown[1] ^= std::byte{0xff};
        require(listener.ingest(co.local, unknown, now));
        check(!require(listener.poll(now)), "unknown CID triggered reflected close");
        auto too_small = packet;
        too_small.resize(17);
        require(listener.ingest(co.local, too_small, now));
        check(!require(listener.poll(now)), "close response amplified a tiny packet");
        require(listener.ingest(co.local, initial, now));
        auto resend = require(listener.poll(now));
        check(resend && resend->data == closed.data && resend->peer == co.local,
              "lost initial close was not retransmitted");
        require(listener.ingest(co.local, initial, now));
        check(!require(listener.poll(now)), "repeated input bypassed PTO pacing");
        now += pto;
        for (const auto& protected_cid : retained) {
            quic::Bytes probe{std::byte{0x40}};
            probe.insert(probe.end(), protected_cid.begin(), protected_cid.end());
            probe.resize(1200);
            auto dropped = require(listener.ingest(co.local, probe, now));
            check(dropped.kind == quic::Listener::Ingest::Kind::dropped &&
                      dropped.connection_id == id, "tombstone lost an issued CID");
        }
        auto resend_again = require(listener.poll(now));
        check(resend_again && resend_again->data == closed.data,
              "second lost close could not be retransmitted");
        require(client.receive(resend_again->data, now));
        check(client.closed() && client.draining(), "client did not enter silent draining");
        require(listener.ingest(co.local, initial, now));
        check(!require(listener.poll(now)), "close transmission cap ignored");
        require(listener.handle_expiry(close_time + 3 * pto - 1));
        check(listener.tombstone_count() == 1, "tombstone expired before three PTOs");
        now = close_time + 3 * pto;
        require(listener.handle_expiry(now));
        check(listener.tombstone_count() == 0 && listener.route_count() == 0 &&
                  listener.reserved_payload_bytes() == 0, "closing expiry leaked reservations");
        auto readmitted = require(listener.ingest(co.local, initial, now));
        check(readmitted.kind == quic::Listener::Ingest::Kind::admitted,
              "expired closing did not release admission");
        check(listener.remove(readmitted.connection_id), "explicit purge failed");
        std::cout << "QUIC listener CID lifecycle and aggregate queue budget passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
