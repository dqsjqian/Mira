// Put arbitrary HTTP/3 stream bytes inside authentic QUIC packets. Fuzzing
// random encrypted UDP alone cannot reach QPACK or HTTP/3 stream parsing.
#include <mira/http3/engine.hpp>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <utility>

namespace {
struct Pair {
    Mira::quic::Engine client;
    Mira::http3::Engine server;
    std::uint64_t now = 1'000'000'000;
    bool pump() {
        for (int i = 0; i < 16; ++i) {
            auto packet = client.poll(now);
            if (!packet) return false;
            if (packet->empty()) break;
            if (!server.receive(*packet, now)) return false;
        }
        for (int i = 0; i < 16; ++i) {
            auto packet = server.poll(now);
            if (!packet) return false;
            if (packet->empty()) break;
            if (!client.receive(*packet, now)) return false;
        }
        for (const auto& event : client.take_events())
            if (event.kind == Mira::quic::Event::Kind::data)
                static_cast<void>(client.consume(event.stream_id, event.data.size()));
        for (const auto& event : server.take_events())
            if (event.kind == Mira::http3::Event::Kind::body)
                static_cast<void>(server.consume(event.stream_id, event.data.size()));
        now += 1'000'000;
        if (client.expiry() <= now && !client.handle_expiry(now)) return false;
        if (server.expiry() <= now && !server.handle_expiry(now)) return false;
        return true;
    }
};
}
static void drive(const std::uint8_t* data, std::size_t size, bool uni) {
    Mira::quic::Options co, so;
    co.local = Mira::transport::Endpoint::loopback(44330);
    co.remote = Mira::transport::Endpoint::loopback(44331);
    co.ca_file = MIRA_FUZZ_CERT;
    co.peer_name = "localhost";
    so.local = co.remote;
    so.remote = co.local;
    so.certificate_file = MIRA_FUZZ_CERT;
    so.private_key_file = MIRA_FUZZ_KEY;
    auto client = Mira::quic::Engine::client(co, 1'000'000'000);
    if (!client) std::abort();  // A missing fixture is not a passing fuzz run.
    auto initial = client->poll(1'000'000'000);
    if (!initial || initial->empty()) std::abort();
    auto transport = Mira::quic::Engine::accept(so, *initial, 1'000'000'000);
    if (!transport) std::abort();
    Mira::http3::Limits limits;
    limits.max_streams = 8;
    limits.max_header_bytes = 4096;
    limits.max_buffered_body = 16384;
    limits.max_events = 64;
    limits.enable_connect_protocol = true;
    auto server = Mira::http3::Engine::create(std::move(*transport), true, limits);
    if (!server) std::abort();
    Pair pair{std::move(*client), std::move(*server)};
    for (int i = 0; i < 100 && !(pair.client.handshake_complete() && pair.server.ready()); ++i)
        if (!pair.pump()) std::abort();
    if (!pair.client.handshake_complete() || !pair.server.ready()) std::abort();
    auto id = pair.client.open_stream(uni);
    if (!id) return;
    const auto bytes = std::span{reinterpret_cast<const std::byte*>(data), size};
    if (!pair.client.write(*id, bytes, !uni)) return;
    for (int i = 0; i < 12; ++i)
        if (!pair.pump()) return;  // Protocol rejection is expected.
}
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0 || size > 8192) return 0;
    // Use independent connections: malformed request bytes must not prevent
    // the same input from reaching control/QPACK stream decoding.
    drive(data, size, false);
    drive(data, size, true);
    return 0;
}
