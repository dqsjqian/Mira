#include "mira/quic/engine.hpp"

#include <ngtcp2/ngtcp2.h>

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <stdexcept>
using namespace Mira;
using quic::Engine;
template<class T>
T require(quic::Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message() + " (" + std::to_string(value.error().value()) +
                                 ")");
    return std::move(*value);
}
void require(quic::Result<void> value) {
    if (!value) throw std::runtime_error(value.error().message());
}
/// Test payloads are library-typed (`std::byte`) end to end; `wire` is a
/// plain span view, kept so call sites read uniformly.
std::span<const std::byte> wire(const quic::Bytes& bytes) {
    return {bytes.data(), bytes.size()};
}
void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}
struct ReplayProbe final : quic::ReplayStore {
    std::shared_ptr<quic::MemoryReplayStore> memory = require(quic::MemoryReplayStore::create());
    unsigned calls = 0;
    bool claim(const std::array<std::byte, 32>& key, std::uint64_t now, std::uint64_t expires) noexcept override {
        ++calls;
        return memory->claim(key, now, expires);
    }
};
void sessions(const char* certificate, const char* key) {
    quic::Options co, so;
    co.local = transport::Endpoint::loopback(44120);
    co.remote = transport::Endpoint::loopback(44121);
    co.peer_name = "localhost";
    co.ca_file = certificate;
    co.service_scope = "session-test";
    co.session_cache = require(quic::SessionCache::create({.max_entries = 1, .max_bytes = 8192}));
    so.local = co.remote;
    so.remote = co.local;
    so.certificate_file = certificate;
    so.private_key_file = key;
    so.service_scope = co.service_scope;
    so.early_data = quic::EarlyDataPolicy::replay_safe;
    so.early_data_context = "app-settings-v1";
    const auto replay_probe = std::make_shared<ReplayProbe>();
    so.replay_store = replay_probe;
    so.server_context = require(quic::ServerContext::create(so));
    std::uint64_t now = 1'000'000'000;
    {
        auto probe = co;
        probe.session_cache.reset();
        auto drifted = so;
        drifted.early_data_context = "app-settings-v2";
        auto initial = require(require(Engine::client(probe, now)).poll(now));
        check(!Engine::accept(drifted, initial, now), "engine accepted a context its ticket domain did not pin");
        drifted.early_data_context.assign(1025, 'x');
        drifted.server_context.reset();
        check(!quic::ServerContext::create(drifted), "oversized early-data context accepted");
    }
    for (int attempt = 0; attempt < 6; ++attempt) {
        co.early_data = attempt >= 2 ? quic::EarlyDataPolicy::replay_safe : quic::EarlyDataPolicy::disabled;
        if (attempt == 3) so.early_data = quic::EarlyDataPolicy::disabled;
        if (attempt == 4) co.service_scope = "other-service";
        if (attempt == 5) now += 3'600'000'000'000;
        auto client = require(Engine::client(co, now));
        const bool early = attempt == 2 || attempt == 3;
        check((client.early_data_status() == quic::EarlyDataStatus::pending) == early,
              "early data gate ignored cache/policy/scope/expiry");
        const quic::Bytes payload(1024, std::byte{0x61});
        if (early) {
            const auto stream = require(client.open_early_stream());
            check(!client.write(stream, payload, true), "ordinary write sent early data");
            require(client.write_early(stream, payload, true));
        } else check(!client.open_early_stream(), "default-off early stream accepted");
        auto initial = require(client.poll(now));
        auto server = require(Engine::accept(so, initial, now));
        std::vector<quic::Bytes> captured_flight;
        std::size_t delivered = 0;
        bool before_handshake = false;
        for (int n = 0; n < 400; ++n) {
            now += 1'000'000;
            for (auto* sender : {&client, &server}) {
                auto& receiver = sender == &client ? server : client;
                if (sender->expiry() <= now) require(sender->handle_expiry(now));
                for (int burst = 0; burst < 32; ++burst) {
                    auto packet = require(sender->poll(now));
                    if (packet.empty()) break;
                    if (attempt == 2 && sender == &client && replay_probe->calls == 0)
                        captured_flight.push_back(packet);
                    require(receiver.receive(packet, now));
                    for (auto& event : server.take_events()) {
                        if (event.kind != quic::Event::Kind::data) continue;
                        delivered += event.data.size();
                        before_handshake |= event.early_data;
                        require(server.consume(event.stream_id, event.data.size()));
                    }
                }
            }
        }
        check(client.handshake_complete() && server.handshake_complete(), "resumption handshake failed");
        check(client.session_reused() == (attempt == 1 || early), "TLS session reuse mismatch");
        check((server.early_data_status() == quic::EarlyDataStatus::accepted) == (attempt == 2),
              "server early-data status does not match what TLS accepted");
        if (attempt == 2) {
            check(delivered == payload.size() && before_handshake &&
                client.early_data_status() == quic::EarlyDataStatus::accepted, "real 0RTT was not accepted");
            check(replay_probe->calls == 1 && replay_probe->memory->size() == 1,
                  "authenticated early flight never reached replay store");
            auto replay = require(Engine::accept(so, initial, now));
            for (const auto& captured : captured_flight) require(replay.receive(captured, now));
            // Exact captured early flight, new connection but same ticket domain.
            // Flush TLS acceptance decisions without ever delivering fresh client data.
            for (int flight = 0; flight < 32; ++flight) {
                auto reply = require(replay.poll(now));
                if (reply.empty()) break;
            }
            check(replay_probe->calls == 2, "captured early flight did not exercise replay admission");
            check(replay.early_data_status() != quic::EarlyDataStatus::accepted,
                  "captured 0RTT flight was accepted twice");
            for (auto& event : replay.take_events())
                check(event.kind != quic::Event::Kind::data, "replayed early application bytes escaped");
        }
        else check(delivered == 0, "rejected/default-off early data was delivered or replayed");
        if (attempt == 3) check(client.early_data_status() == quic::EarlyDataStatus::rejected &&
            client.write_capacity() == co.max_buffered_bytes, "early rejection retained retry payload");
        check(co.session_cache->size() == 1 && co.session_cache->bytes() <= 8192,
              "session ticket cache exceeded bound or failed to retain ticket");
    }
    co.session_cache->clear();
    check(co.session_cache->bytes() == 0 && co.session_cache->size() == 0, "ticket clear leaked budget");
}
void trust_rotation(const char* certificate, const char* key, const char* other_ca,
                    const std::string& mode) {
    const bool system_trust = mode == "system-cache";
    const bool allow_early = mode != "ca-rotation";
    const auto trust_file = std::filesystem::path(certificate).parent_path() / (mode + "-trust.pem");
    std::filesystem::copy_file(certificate, trust_file, std::filesystem::copy_options::overwrite_existing);
    quic::Options co, so;
    co.local = transport::Endpoint::loopback(44122);
    co.remote = transport::Endpoint::loopback(44123);
    co.peer_name = "localhost";
    if (!system_trust) co.ca_file = trust_file.string();
    co.service_scope = "trust-rotation";
    co.session_cache = require(quic::SessionCache::create());
    co.early_data = allow_early ? quic::EarlyDataPolicy::replay_safe : quic::EarlyDataPolicy::disabled;
    so.local = co.remote;
    so.remote = co.local;
    so.certificate_file = certificate;
    so.private_key_file = key;
    so.service_scope = co.service_scope;
    so.early_data = quic::EarlyDataPolicy::replay_safe;
    so.server_context = require(quic::ServerContext::create(so));
    std::uint64_t now = 1'000'000'000;
    for (int attempt = 0; attempt < (system_trust ? 2 : 3); ++attempt) {
        const bool changed = attempt == 2;
        if (changed) std::filesystem::copy_file(other_ca, trust_file,
            std::filesystem::copy_options::overwrite_existing);
        auto client = require(Engine::client(co, now));
        const bool early = client.early_data_status() == quic::EarlyDataStatus::pending;
        if (early) require(client.write_early(require(client.open_early_stream()),
            quic::Bytes(32, std::byte{0x61}), true));
        auto server = require(Engine::accept(so, require(client.poll(now)), now));
        bool rejected = false;
        std::size_t delivered = 0;
        for (int n = 0; n < 400 && !rejected; ++n) {
            now += 1'000'000;
            for (auto* sender : {&client, &server}) {
                auto& receiver = sender == &client ? server : client;
                if (sender->expiry() <= now) require(sender->handle_expiry(now));
                for (int burst = 0; burst < 32; ++burst) {
                    auto packet = require(sender->poll(now));
                    if (packet.empty()) break;
                    if (!receiver.receive(packet, now)) { rejected = true; break; }
                    for (auto& event : server.take_events()) {
                        if (event.kind != quic::Event::Kind::data) continue;
                        delivered += event.data.size();
                        require(server.consume(event.stream_id, event.data.size()));
                    }
                }
                if (rejected) break;
            }
        }
        if (changed) {
            std::cout << "changed CA: rejected=" << rejected << " reused=" << client.session_reused()
                      << " early=" << early << " delivered=" << delivered << '\n';
            check(rejected && !client.handshake_complete() && !client.session_reused(),
                  "changed CA at the same path resumed the old trust domain");
            check(!early && delivered == 0, "changed trust enabled or delivered 0RTT");
        } else {
            check(!rejected && client.handshake_complete() && server.handshake_complete(),
                  "trusted session setup failed");
            check(client.session_reused() == (!system_trust && attempt == 1),
                  "unchanged explicit trust did not resume, or default trust resumed");
            check(co.session_cache->size() == (system_trust ? 0U : 1U),
                  "unfingerprinted default trust retained a ticket or explicit trust lost one");
            if (system_trust) check(!early && delivered == 0,
                "default trust enabled or delivered early data without a snapshot");
        }
    }
    co.session_cache->clear();
    check(co.session_cache->bytes() == 0, "trust cache clear leaked budget");
    std::cout << mode << " passed\n";
}
int main(int argc, char** argv) {
    std::string mode = argc > 3 ? argv[3] : "normal";
    bool negative = mode == "bad-host" || mode == "untrusted" || mode == "bad-alpn";
    bool handshake_phase = true;
    try {
        if (argc < 3) return 2;
        if (mode == "ca-rotation" || mode == "ca-rotation-early" ||
            mode == "ca-aux" || mode == "system-cache") {
            if (argc < 5) return 2;
            trust_rotation(argv[1], argv[2], argv[4], mode);
            return 0;
        }
        if (mode == "normal") sessions(argv[1], argv[2]);
        quic::Options co, so;
        co.local = transport::Endpoint::loopback(44330);
        co.remote = transport::Endpoint::loopback(44331);
        co.ca_file = argv[1];
        co.peer_name = mode == "bad-host" ? "wrong.example" : "localhost";
        if (mode == "untrusted") co.ca_file.clear();
        if (mode == "bad-alpn") co.alpn = "not-h3";
        if (mode == "stream-limit") so.max_streams = 1;
        so.local = co.remote;
        so.remote = co.local;
        so.certificate_file = argv[1];
        so.private_key_file = argv[2];
        std::uint64_t now = 1'000'000'000;
        auto client = require(Engine::client(co, now));
        auto packet = require(client.poll(now));
        check(!packet.empty(), "missing initial");
        auto server = require(Engine::accept(so, packet, now));
        int counter = 0, dropped = 0;
        bool dropped_handshake = false;
        auto drive = [&] {
            std::vector<quic::Bytes> cp, sp;
            for (int k = 0; k < 32; ++k) {
                auto p = require(client.poll(now));
                if (p.empty()) break;
                cp.push_back(std::move(p));
            }
            for (int k = 0; k < 32; ++k) {
                auto p = require(server.poll(now));
                if (p.empty()) break;
                sp.push_back(std::move(p));
            }
            if (mode == "chaos") {
                std::reverse(cp.begin(), cp.end());
                std::reverse(sp.begin(), sp.end());
            }
            auto deliver = [&](Engine& peer, std::vector<quic::Bytes>& packets) {
                for (auto& p : packets) {
                    if (mode == "chaos" && ++counter % 17 == 0 && dropped < 10) {
                        ++dropped;
                        continue;
                    }
                    require(peer.receive(p, now));
                    if (mode == "chaos" && counter % 13 == 0) require(peer.receive(p, now));
                }
            };
            deliver(server, cp);
            if (mode == "chaos" && !dropped_handshake && !sp.empty()) {
                sp.clear();
                dropped_handshake = true;
                ++dropped;
            }
            deliver(client, sp);
            now += 1'000'000;
            if (client.expiry() <= now) require(client.handle_expiry(now));
            if (server.expiry() <= now) require(server.handle_expiry(now));
        };
        for (int i = 0; i < 10000 && !(client.handshake_complete() && server.handshake_complete());
             ++i)
            drive();
        check(client.handshake_complete() && server.handshake_complete(), "handshake incomplete");
        handshake_phase = false;
        check(!negative, "bad certificate/ALPN unexpectedly completed the handshake");
        check(client.negotiated_protocol() == "h3" && server.negotiated_protocol() == "h3",
              "wrong ALPN");
        if (mode == "stream-limit") {
            // The server admits only 1 bidi stream. After both FINs the stream closes, but while
            // the record is retained for unconsumed received data the peer's credit must not be
            // returned; only after consume drains the record is MAX_STREAMS re-issued.
            auto first = require(client.open_stream());
            quic::Bytes small(1024, std::byte{0xa5});
            require(client.write(first, wire(small), true));
            bool fin = false;
            std::size_t got = 0;
            for (int i = 0; i < 10000 && !fin; ++i) {
                drive();
                for (auto& e : server.take_events())
                    if (e.kind == quic::Event::Kind::data) {
                        got += e.data.size();
                        fin |= e.fin;  // Deliberately no consume: record retained, credit not returned.
                    }
                client.take_events();
            }
            check(fin && got == small.size(), "first stream did not fully arrive");
            require(server.write(first, {}, true));  // Send FIN back, closing stream 0 in both directions.
            for (int i = 0; i < 2000; ++i) drive();  // Wait for the ACK that triggers stream_close.
            auto blocked = client.open_stream();
            check(!blocked && blocked.error().value() == NGTCP2_ERR_STREAM_ID_BLOCKED,
                  "unconsumed closed stream already returned the peer's credit");
            require(server.consume(first, got));  // Drain the record, triggering the deferred credit.
            bool reopened = false;
            for (int i = 0; i < 2000 && !reopened; ++i) {
                drive();
                reopened = client.open_stream().has_value();
            }
            check(reopened, "peer credit did not recover after consume");
            std::cout << "QUIC stream-limit deferred credit return passed\n";
            return 0;
        }
        auto id = require(client.open_stream());
        quic::Bytes data(200000, std::byte{0x5a});
        require(client.write(id, wire(data), true));
        check(!client.write(id, data, false), "write after FIN succeeded");
        std::size_t total = 0;
        bool fin = false;
        for (int i = 0; i < 10000 && !fin; ++i) {
            drive();
            for (auto& e : server.take_events())
                if (e.kind == quic::Event::Kind::data) {
                    check(
                        std::all_of(e.data.begin(), e.data.end(), [](std::byte b) { return b == std::byte{0x5a}; }),
                        "payload corrupted");
                    total += e.data.size();
                    fin |= e.fin;
                    require(server.consume(e.stream_id, e.data.size()));
                }
            client.take_events();
        }
        check(total == data.size() && fin, "stream incomplete");
        require(server.write(id, wire(data), true));
        total = 0;
        fin = false;
        for (int i = 0; i < 10000 && !fin; ++i) {
            drive();
            for (auto& e : client.take_events())
                if (e.kind == quic::Event::Kind::data) {
                    check(
                        std::all_of(e.data.begin(), e.data.end(), [](std::byte b) { return b == std::byte{0x5a}; }),
                        "response corrupted");
                    total += e.data.size();
                    fin |= e.fin;
                    require(client.consume(e.stream_id, e.data.size()));
                }
            server.take_events();
        }
        check(total == data.size() && fin, "response incomplete");
        auto cancel_id = require(client.open_stream());
        require(client.write(cancel_id, wire(data), false));
        drive();
        for (auto& e : server.take_events())
            if (e.kind == quic::Event::Kind::data)
                require(server.consume(e.stream_id, e.data.size()));
        require(client.cancel(cancel_id, 0x10c));
        check(!client.write(cancel_id, {}, true), "write after cancel succeeded");
        bool reset = false;
        for (int i = 0; i < 2000 && !reset; ++i) {
            drive();
            client.take_events();
            for (auto& e : server.take_events()) {
                if (e.kind == quic::Event::Kind::data)
                    require(server.consume(e.stream_id, e.data.size()));
                if (e.kind == quic::Event::Kind::reset && e.stream_id == cancel_id &&
                    e.value == 0x10c)
                    reset = true;
            }
        }
        check(reset, "RESET_STREAM did not arrive");
        auto other = require(client.open_stream());
        require(client.write(other, {}, true));
        // A receive-only stream can close in the same datagram as an empty
        // FIN. The application still consumes every delivered data event,
        // including the zero-byte terminal event after its record is retired.
        const auto empty_uni = require(client.open_stream(true));
        require(client.write(empty_uni, {}, true));
        bool empty_fin = false;
        for (int i = 0; i < 2000 && !empty_fin; ++i) {
            drive();
            client.take_events();
            for (auto& e : server.take_events()) {
                if (e.kind != quic::Event::Kind::data) continue;
                auto consumed = server.consume(e.stream_id, e.data.size());
                if (!consumed) throw std::runtime_error("empty FIN consume failed: stream=" +
                    std::to_string(e.stream_id) + " bytes=" + std::to_string(e.data.size()) +
                    " " + consumed.error().message());
                if (e.stream_id == empty_uni) empty_fin = e.fin && e.data.empty();
            }
        }
        check(empty_fin, "empty unidirectional FIN did not arrive");
        check(!server.consume(empty_uni, 1), "retired stream accepted nonexistent receive credit");
        auto over = require(client.open_stream());
        quic::Bytes huge(co.max_buffered_bytes + 1);
        check(!client.write(over, wire(huge), false), "send budget not enforced");
        auto close = require(client.close(0, now));
        check(!close.empty(), "close produced no datagram");
        require(server.receive(close, now));
        check(server.closed(), "remote did not enter draining");
        check(!client.poll(now), "send after close succeeded");
        if (mode == "chaos") check(dropped > 0, "packet-drop injection never triggered");
        std::cout << "QUIC " << mode << " TLS1.3 200KB bidirectional, cancel, budget, close passed\n";
    } catch (const std::exception& ex) {
        if (negative && handshake_phase &&
            std::string(ex.what()).find("ERR_CRYPTO") != std::string::npos) {
            std::cout << "QUIC " << mode << " rejected handshake: " << ex.what() << '\n';
            return 0;
        }
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
