#include "mira/quic/listener.hpp"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <source_location>
#include <stdexcept>

using namespace Mira;
namespace {
using Listener = quic::Listener;
using Kind = Listener::Ingest::Kind;
constexpr std::uint64_t start = 1'000'000'000;
template<class T>
T require(Result<T> result, std::source_location where = std::source_location::current()) {
    if (!result) throw std::runtime_error(result.error().message() + " at " + std::to_string(where.line()));
    return std::move(*result);
}
void require(Result<void> result, std::source_location where = std::source_location::current()) {
    if (!result) throw std::runtime_error(result.error().message() + " at " + std::to_string(where.line()));
}
void check(bool ok, const char* message, std::source_location where = std::source_location::current()) {
    if (!ok) throw std::runtime_error(std::string(message) + " at " + std::to_string(where.line()));
}
quic::RetryKey random_key() {
    quic::RetryKey key{};
    check(quic::fill_random(key.data(), key.size()), "random key failed");
    return key;
}
quic::RetryOptions policy() {
    quic::RetryOptions result;
    result.policy = quic::RetryPolicy::required;
    result.current_key = random_key();
    result.scope = "Mira Retry test";
    return result;
}
Listener listener(const quic::Options& so, const quic::RetryOptions& retry) {
    return require(Listener::create(so, {}, {}, 0, 0, {}, retry));
}
ngtcp2_pkt_hd header(const quic::Bytes& bytes) {
    ngtcp2_pkt_hd hd{};
    check(ngtcp2_pkt_decode_hd_long(&hd, reinterpret_cast<const std::uint8_t*>(bytes.data()),
                                    bytes.size()) >= 0, "long header decode failed");
    return hd;
}
quic::Bytes token(const quic::Bytes& packet) {
    const auto hd = header(packet);
    const auto* bytes = reinterpret_cast<const std::byte*>(hd.token);
    return quic::Bytes(bytes, bytes + hd.tokenlen);
}
quic::Bytes replace_token(const quic::Bytes& packet, const quic::Bytes& replacement) {
    const auto hd = header(packet);
    const auto offset = 7 + hd.dcid.datalen + hd.scid.datalen;
    quic::Bytes result(packet.begin(), packet.begin() + static_cast<std::ptrdiff_t>(offset));
    check(replacement.size() < 16384, "test token too long");
    if (replacement.size() < 64) result.push_back(static_cast<std::byte>(replacement.size()));
    else {
        result.push_back(static_cast<std::byte>(0x40 | (replacement.size() >> 8)));
        result.push_back(static_cast<std::byte>(replacement.size() & 255));
    }
    result.insert(result.end(), replacement.begin(), replacement.end());
    const auto* rest = reinterpret_cast<const std::byte*>(hd.token) + hd.tokenlen;
    result.insert(result.end(), rest, packet.data() + packet.size());
    result.resize(std::max<std::size_t>(1200, result.size()));
    return result;
}
void silent(Listener& server, const transport::Endpoint& peer, const quic::Bytes& input,
            std::uint64_t now) {
    const auto size = server.size(), routes = server.route_count();
    const auto bytes = server.reserved_payload_bytes(), queues = server.reserved_queue_entries();
    auto result = require(server.ingest(peer, input, now));
    check(result.kind == Kind::dropped && !result.reply && server.size() == size &&
              server.route_count() == routes && server.reserved_payload_bytes() == bytes &&
              server.reserved_queue_entries() == queues, "invalid input allocated state or replied");
}
struct Flight {
    quic::Engine client;
    quic::Bytes original, retry, validated;
};
Flight flight(const quic::Options& co, Listener& issuer, std::uint64_t now) {
    auto client = require(quic::Engine::client(co, now));
    auto original = require(client.poll(now));
    auto result = require(issuer.ingest(co.local, original, now));
    check(result.kind == Kind::retry && result.connection_id == 0 && result.reply &&
              result.reply->connection_id == 0 && result.reply->peer == co.local &&
              result.reply->data.size() <= original.size() && issuer.size() == 0 &&
              issuer.route_count() == 0 && issuer.reserved_payload_bytes() == 0 &&
              issuer.reserved_queue_entries() == 0 && !require(issuer.poll(now)),
          "Retry reserved state, queued output or amplified its trigger");
    auto retry = std::move(result.reply->data);
    require(client.receive(retry, now));
    auto validated = require(client.poll(now));
    check(validated.size() >= 1200 && !token(validated).empty(), "client did not echo Retry token");
    return {std::move(client), std::move(original), std::move(retry), std::move(validated)};
}
void handshake(Listener& server, quic::Engine& client, Listener::Id id,
               const transport::Endpoint& peer, std::uint64_t& now,
               const quic::Bytes* noise = nullptr) {
    for (int tick = 0; tick < 4000; ++tick) {
        now += 1'000'000;
        require(server.handle_expiry(now));
        if (client.expiry() <= now) require(client.handle_expiry(now));
        if (noise) for (int i = 0; i < 24; ++i) {
            auto result = require(server.ingest(transport::Endpoint::loopback(18000), *noise, now));
            check(result.kind == Kind::retry || result.kind == Kind::dropped,
                  "unvalidated noise was admitted");
        }
        for (int burst = 0; burst < 32; ++burst) {
            auto packet = require(client.poll(now));
            if (packet.empty()) break;
            auto result = require(server.ingest(peer, packet, now));
            check(!result.reply, "validated client re-entered Retry");
        }
        for (int burst = 0; burst < 32; ++burst) {
            auto packet = require(server.poll(now));
            if (!packet) break;
            check(packet->connection_id == id && packet->peer == peer, "Retry disturbed poll fairness");
            require(client.receive(packet->data, now));
        }
        auto* accepted = server.connection(id);
        check(accepted, "Retry handshake lost connection");
        if (tick > 20 && client.handshake_complete() && accepted->handshake_complete()) return;
    }
    throw std::runtime_error("Retry handshake deadline");
}
void roundtrip(const quic::Options& co, const quic::Options& so) {
    auto retry = policy();
    auto server = listener(so, retry);
    auto f = flight(co, server, start);
    check(!quic::Engine::accept(so, f.validated, start), "unverified direct accept trusted token");
    auto admitted = require(server.ingest(co.local, f.validated, start));
    check(admitted.kind == Kind::admitted && !admitted.reply && server.size() == 1,
          "verified Initial did not admit");
    auto* accepted = server.connection(admitted.connection_id);
    auto original = header(f.original).dcid;
    auto retry_cid = header(f.retry).scid;
    auto retained = accepted->retained_connection_ids();
    auto has = [&](const ngtcp2_cid& cid) {
        const auto* begin = reinterpret_cast<const std::byte*>(cid.data);
        return std::find(retained.begin(), retained.end(), quic::Bytes(begin, begin + cid.datalen)) != retained.end();
    };
    check(retained.size() == 3 && has(original) && has(retry_cid), "original or Retry CID not retained");
    const auto* original_bytes = reinterpret_cast<const std::byte*>(original.data);
    const quic::Bytes original_id(original_bytes, original_bytes + original.datalen);
    check(accepted->initial_destination_cid() == original_id &&
              f.client.initial_destination_cid() == original_id, "Retry changed original CID accessor");
    std::uint64_t now = start;
    handshake(server, f.client, admitted.connection_id, co.local, now);
    auto stream = require(f.client.open_stream());
    quic::Bytes request(7000, std::byte{0x71});
    require(f.client.write(stream, request, true));
    std::size_t received = 0;
    bool request_fin = false, response_fin = false;
    for (int tick = 0; tick < 4000 && !response_fin; ++tick) {
        now += 1'000'000;
        require(server.handle_expiry(now));
        if (f.client.expiry() <= now) require(f.client.handle_expiry(now));
        for (int burst = 0; burst < 32; ++burst) {
            auto packet = require(f.client.poll(now));
            if (packet.empty()) break;
            require(server.ingest(co.local, packet, now));
        }
        for (auto& event : accepted->take_events()) if (event.kind == quic::Event::Kind::data) {
            received += event.data.size();
            require(accepted->consume(event.stream_id, event.data.size()));
            request_fin |= event.fin;
            require(accepted->write(event.stream_id, event.data, event.fin));
        }
        for (int burst = 0; burst < 32; ++burst) {
            auto packet = require(server.poll(now));
            if (!packet) break;
            require(f.client.receive(packet->data, now));
        }
        for (auto& event : f.client.take_events()) if (event.kind == quic::Event::Kind::data) {
            check(std::all_of(event.data.begin(), event.data.end(), [](auto b) { return b == std::byte{0x71}; }),
                  "Retry application data corrupted");
            require(f.client.consume(event.stream_id, event.data.size()));
            response_fin |= event.fin;
        }
    }
    check(received == request.size() && request_fin && response_fin, "Retry stream roundtrip incomplete");
    retained = accepted->retained_connection_ids();
    require(server.close(admitted.connection_id, 0, now));
    check(server.route_count() == retained.size() && server.tombstone_count() == 1,
          "Retry close did not retain all CIDs");
    for (const auto& cid : retained) {
        quic::Bytes probe{std::byte{0x40}};
        probe.insert(probe.end(), cid.begin(), cid.end());
        probe.resize(1200);
        const auto result = require(server.ingest(co.local, probe, now));
        check(result.kind == Kind::dropped && result.connection_id == admitted.connection_id && !result.reply,
              "Retry tombstone lost CID");
    }
    silent(server, co.local, f.original, now);
    silent(server, co.local, f.validated, now);
}
void lost_retry(const quic::Options& co, const quic::Options& so) {
    auto server = listener(so, policy());
    auto client = require(quic::Engine::client(co, start));
    auto initial = require(client.poll(start));
    auto lost = require(server.ingest(co.local, initial, start));
    check(lost.kind == Kind::retry && lost.reply, "missing lost Retry");
    std::uint64_t now = client.expiry();
    check(now > start && now < start + 10'000'000'000, "invalid Initial PTO");
    require(client.handle_expiry(now));
    auto retransmission = require(client.poll(now));
    check(!retransmission.empty(), "client did not retransmit Initial after lost Retry");
    auto retry = require(server.ingest(co.local, retransmission, now));
    check(retry.kind == Kind::retry && retry.reply && server.size() == 0, "lost Retry retained state");
    require(client.receive(retry.reply->data, now));
    auto second = require(client.poll(now));
    auto admitted = require(server.ingest(co.local, second, now));
    check(admitted.kind == Kind::admitted, "lost Retry recovery not admitted");
    handshake(server, client, admitted.connection_id, co.local, now);
}
void malformed(const quic::Options& co, const quic::Options& so) {
    auto retry = policy();
    auto issuer = listener(so, retry);
    auto f = flight(co, issuer, start);
    auto verifier = listener(so, retry);
    auto bytes = token(f.validated);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        auto corrupted = bytes;
        corrupted[i] ^= std::byte{1};
        silent(verifier, co.local, replace_token(f.validated, corrupted), start);
    }
    for (std::size_t n = 1; n < bytes.size(); ++n) {
        quic::Bytes truncated(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(n));
        silent(verifier, co.local, replace_token(f.validated, truncated), start);
    }
    bytes.push_back(std::byte{0});
    silent(verifier, co.local, replace_token(f.validated, bytes), start);
    auto bad = f.validated;
    bad[4] ^= std::byte{3};
    silent(verifier, co.local, bad, start);
    bad = f.validated;
    bad[6] ^= std::byte{1};
    silent(verifier, co.local, bad, start);
    bad = f.original;
    bad[5] = std::byte{21};
    silent(verifier, co.local, bad, start);
    bad = f.original;
    bad[5] = std::byte{7};
    silent(verifier, co.local, bad, start);
    bad = f.original;
    bad[0] &= std::byte{0xbf};
    silent(verifier, co.local, bad, start);
    bad = f.original;
    bad.resize(1199);
    silent(verifier, co.local, bad, start);
    bad = f.original;
    // Replace the Initial length by an eight-byte maximum varint.
    auto hd = header(bad);
    const auto length_offset = 8 + hd.dcid.datalen + hd.scid.datalen;
    std::fill_n(bad.begin() + static_cast<std::ptrdiff_t>(length_offset), 8, std::byte{0xff});
    silent(verifier, co.local, bad, start);
    silent(verifier, transport::Endpoint::loopback(static_cast<std::uint16_t>(co.local.port() + 1)), f.validated, start);
    silent(verifier, require(transport::Endpoint::parse("127.0.0.2", co.local.port())), f.validated, start);
    check(require(verifier.ingest(co.local, f.validated, start)).kind == Kind::admitted,
          "malformed traffic poisoned later validation");
}
void lifetimes_and_keys(const quic::Options& co, const quic::Options& so) {
    auto retry = policy();
    auto issuer = listener(so, retry);
    auto f = flight(co, issuer, start);
    auto expired = listener(so, retry);
    silent(expired, co.local, f.validated, start + retry.token_lifetime_ns);
    auto boundary = listener(so, retry);
    check(require(boundary.ingest(co.local, f.validated, start + retry.token_lifetime_ns - 1)).kind == Kind::admitted,
          "unexpired token rejected");
    auto future = listener(so, retry);
    silent(future, co.local, f.validated, start - 1);
    check(!future.ingest(co.local, f.original, start - 2), "backward time accepted");
    check(require(future.ingest(co.local, f.validated, start)).kind == Kind::admitted,
          "future token rejection poisoned normal time");
    auto wrong = retry;
    wrong.current_key = random_key();
    auto other = listener(so, wrong);
    silent(other, co.local, f.validated, start);
    auto previous = wrong;
    previous.previous_key = retry.current_key;
    auto old = listener(so, previous);
    check(require(old.ingest(co.local, f.validated, start)).kind == Kind::admitted, "previous key rejected");
    auto rotated = listener(so, retry);
    require(rotated.rotate_retry_key(*wrong.current_key));
    check(require(rotated.ingest(co.local, f.validated, start)).kind == Kind::admitted, "rotated key rejected");
    auto post_rotation = listener(so, retry);
    require(post_rotation.rotate_retry_key(*wrong.current_key));
    auto new_flight = flight(co, post_rotation, start);
    auto new_key_verifier = listener(so, wrong);
    check(require(new_key_verifier.ingest(co.local, new_flight.validated, start)).kind == Kind::admitted,
          "rotation did not issue tokens under current key");
    auto discarded = listener(so, retry);
    require(discarded.rotate_retry_key(*wrong.current_key));
    discarded.discard_previous_retry_key();
    silent(discarded, co.local, f.validated, start);
    auto twice = listener(so, retry);
    require(twice.rotate_retry_key(*wrong.current_key));
    require(twice.rotate_retry_key(random_key()));
    silent(twice, co.local, f.validated, start);
    auto different_scope = retry;
    different_scope.scope += " other";
    auto scoped = listener(so, different_scope);
    silent(scoped, co.local, f.validated, start);
    auto local = so;
    local.local = transport::Endpoint::loopback(static_cast<std::uint16_t>(so.local.port() + 1));
    auto different_local = listener(local, retry);
    silent(different_local, co.local, f.validated, start);
    local = so;
    local.alpn = "other";
    auto different_protocol = listener(local, retry);
    silent(different_protocol, co.local, f.validated, start);
    auto automatic = retry;
    automatic.current_key.reset();
    automatic.scope.clear();
    auto first_random = listener(so, automatic);
    auto random_flight = flight(co, first_random, start);
    auto second_random = listener(so, automatic);
    silent(second_random, co.local, random_flight.validated, start);
    auto identical_rotation_key = random_key();
    require(first_random.rotate_retry_key(identical_rotation_key));
    require(second_random.rotate_retry_key(identical_rotation_key));
    auto isolated = flight(co, first_random, start);
    silent(second_random, co.local, isolated.validated, start);
    auto near_max = listener(so, retry);
    silent(near_max, co.local, f.original, std::numeric_limits<std::uint64_t>::max());
}
void budget_and_proof(const quic::Options& co, const quic::Options& so) {
    auto retry = policy();
    retry.max_replies_per_window = 4;
    auto issuer = listener(so, retry);
    auto f = flight(co, issuer, start);
    ResourceBudget shared{2 * so.max_buffered_bytes + quic::detail::kClosePacket};
    unsigned calls = 0;
    auto factory = [&](quic::Options options, std::span<const std::byte> input,
                       std::uint64_t now) -> Result<quic::Engine> {
        ++calls;
        check(bool(options.retry_validation), "factory did not receive opaque proof");
        auto changed = options;
        changed.remote = transport::Endpoint::loopback(18001);
        check(!quic::Engine::accept(changed, input, now), "proof accepted different remote");
        changed = options;
        changed.local = transport::Endpoint::loopback(18002);
        check(!quic::Engine::accept(changed, input, now), "proof accepted different local");
        changed = options;
        changed.alpn = "other";
        check(!quic::Engine::accept(changed, input, now), "proof accepted different ALPN");
        check(!quic::Engine::accept(options, input, now + 1), "proof accepted another timestamp");
        auto packet = quic::Bytes(input.begin(), input.end());
        packet[6] ^= std::byte{1};
        check(!quic::Engine::accept(options, packet, now), "proof accepted another DCID");
        packet = quic::Bytes(input.begin(), input.end());
        auto hd = header(packet);
        auto token_offset = reinterpret_cast<const std::byte*>(hd.token) - packet.data();
        packet[static_cast<std::size_t>(token_offset)] ^= std::byte{1};
        check(!quic::Engine::accept(options, packet, now), "proof accepted another token");
        return quic::Engine::accept(std::move(options), input, now);
    };
    auto server = require(Listener::create(so, {}, factory, 0, 0, shared, retry));
    unsigned replies = 0;
    for (int n = 0; n < 2000; ++n) {
        auto result = require(server.ingest(co.local, f.original, start));
        replies += result.reply.has_value();
        check(result.kind == (n < 4 ? Kind::retry : Kind::dropped), "Retry fixed-window limit bypassed");
    }
    check(replies == 4 && calls == 0 && shared.used() == 0 && server.route_count() == 0 &&
              !require(server.poll(start)), "Retry flood consumed connection budget or queued output");
    require(server.rotate_retry_key(random_key()));
    silent(server, co.local, f.original, start + retry.window_ns - 1);
    auto admitted = require(server.ingest(co.local, f.validated, start + retry.window_ns - 1));
    check(admitted.kind == Kind::admitted && calls == 1 && shared.used() == shared.limit(),
          "reply limiter blocked verified admission or quota was not charged");
    auto competitor_options = co;
    competitor_options.local = transport::Endpoint::loopback(18003);
    auto competitor = require(quic::Engine::client(competitor_options, start));
    auto noise = require(competitor.poll(start));
    auto competing_server = require(Listener::create(so, {}, {}, 0, 0, shared, retry));
    auto competing_initial = require(competing_server.ingest(competitor_options.local, noise,
                                                              start + retry.window_ns - 1));
    check(competing_initial.kind == Kind::retry && competing_initial.reply &&
              competing_server.size() == 0 && shared.used() == shared.limit(),
          "stateless Retry borrowed exhausted shared payload");
    require(competitor.receive(competing_initial.reply->data, start + retry.window_ns - 1));
    auto competing_validated = require(competitor.poll(start + retry.window_ns - 1));
    silent(competing_server, competitor_options.local, competing_validated, start + retry.window_ns - 1);
    // Existing connection work stays in poll, never behind a stateless Retry queue.
    std::uint64_t now = start + retry.window_ns - 1;
    handshake(server, f.client, admitted.connection_id, co.local, now, &noise);
    check(calls == 1 && server.size() == 1, "noise reached connection factory");
    check(server.remove(admitted.connection_id) && shared.used() == 0, "validated quota leaked");
    auto renewed = require(server.ingest(co.local, f.original, now));
    check(renewed.kind == Kind::retry || renewed.kind == Kind::dropped, "limiter state invalid");
    auto window = listener(so, retry);
    for (int n = 0; n < 4; ++n) check(require(window.ingest(co.local, f.original, start)).reply.has_value(), "window did not fill");
    silent(window, co.local, f.original, start + retry.window_ns - 1);
    check(require(window.ingest(co.local, f.original, start + retry.window_ns)).reply.has_value(),
          "window did not refill at boundary");
}
void ipv6_and_padding(quic::Options co, quic::Options so) {
    co.local = transport::Endpoint::loopback(18888, transport::Family::ipv6);
    co.remote = transport::Endpoint::loopback(18889, transport::Family::ipv6);
    so.local = co.remote;
    so.remote = co.local;
    auto retry = policy();
    auto issuer = listener(so, retry);
    auto f = flight(co, issuer, start);
    auto verifier = listener(so, retry);
    silent(verifier, require(transport::Endpoint::parse("::2", co.local.port())), f.validated, start);
    silent(verifier, transport::Endpoint::loopback(18890, transport::Family::ipv6), f.validated, start);
    ngtcp2_sockaddr_in6 address{};
    std::memcpy(&address, co.local.address_bytes().data(), sizeof(address));
    address.sin6_scope_id = 2;
    auto scoped = require(transport::Endpoint::from_bytes(std::as_bytes(std::span(&address, 1))));
    silent(verifier, scoped, f.validated, start);
    address.sin6_scope_id = 0;
    address.sin6_flowinfo = 12345;
    auto padded = require(transport::Endpoint::from_bytes(std::as_bytes(std::span(&address, 1))));
    auto result = require(verifier.ingest(padded, f.validated, start));
    check(result.kind == Kind::admitted, "IPv6 flow label broke token identity");
    std::uint64_t now = start;
    handshake(verifier, f.client, result.connection_id, co.local, now);
}
void invalid_options(const quic::Options& so) {
    auto retry = policy();
    retry.current_key = quic::RetryKey{};
    check(!Listener::create(so, {}, {}, 0, 0, {}, retry), "zero key accepted");
    retry = policy();
    retry.scope.clear();
    check(!Listener::create(so, {}, {}, 0, 0, {}, retry), "injected key missing scope accepted");
    retry = policy();
    retry.token_lifetime_ns = 0;
    check(!Listener::create(so, {}, {}, 0, 0, {}, retry), "zero token lifetime accepted");
    retry.token_lifetime_ns = std::numeric_limits<std::uint64_t>::max();
    check(!Listener::create(so, {}, {}, 0, 0, {}, retry), "unbounded token lifetime accepted");
    retry = policy();
    retry.max_replies_per_window = 0;
    check(!Listener::create(so, {}, {}, 0, 0, {}, retry), "zero reply ceiling accepted");
    retry = policy();
    retry.window_ns = 0;
    check(!Listener::create(so, {}, {}, 0, 0, {}, retry), "zero window accepted");
    retry = policy();
    retry.previous_key = retry.current_key;
    retry.current_key.reset();
    check(!Listener::create(so, {}, {}, 0, 0, {}, retry), "previous-only key accepted");
    retry = policy();
    quic::ListenerLimits limits;
    limits.max_connection_ids = 2;
    check(!Listener::create(so, limits, {}, 0, 0, {}, retry), "insufficient Retry CID cap accepted");
}
}  // namespace
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    try {
        quic::Options co;
        co.local = transport::Endpoint::loopback(17777);
        co.remote = transport::Endpoint::loopback(17778);
        co.ca_file = argv[1];
        co.peer_name = "localhost";
        co.max_buffered_bytes = 65536;
        auto so = co;
        so.local = co.remote;
        so.remote = co.local;
        so.certificate_file = argv[1];
        so.private_key_file = argv[2];
        invalid_options(so);
        roundtrip(co, so);
        lost_retry(co, so);
        malformed(co, so);
        lifetimes_and_keys(co, so);
        budget_and_proof(co, so);
        ipv6_and_padding(co, so);
        std::cout << "QUIC required Retry handshake, tokens, rotation, quota and flood fairness passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
