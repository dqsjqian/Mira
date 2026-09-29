// HTTP/3 0-RTT over in-memory QUIC engines, delivered in whole flights so the
// test can count round trips: accepted early requests must be answered within
// the server's first flight, rejected ones must be resubmitted transparently on
// the same stream IDs, and unsafe early requests must never reach the server
// application.

#include "mira/http3/engine.hpp"
#include "mira/http3/server.hpp"

#include <algorithm>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace Mira;

namespace {

template<class T>
T require(Result<T> value, const char* what) {
    if (!value)
        throw std::runtime_error(std::string(what) + ": " + value.error().message() + " (" +
                                 std::to_string(value.error().value()) + ")");
    return std::move(*value);
}
void require(Result<void> value, const char* what) {
    if (!value) throw std::runtime_error(std::string(what) + ": " + value.error().message());
}
void check(bool ok, const std::string& message) {
    if (!ok) throw std::runtime_error(message);
}

std::string status_of(const http3::Headers& fields) {
    for (const auto& [name, value] : fields)
        if (name == ":status") return value;
    return {};
}
http3::Headers get(std::string path, std::string method = "GET") {
    return {{":method", std::move(method)}, {":scheme", "https"}, {":authority", "localhost"},
            {":path", std::move(path)}};
}

struct Setup {
    quic::Options client, server;
    http3::Limits limits;
    std::uint64_t now = 1'000'000'000;
};

Setup make_setup(const char* certificate, const char* key) {
    Setup s;
    s.limits.max_buffered_body = 64 * 1024;
    s.client.local = transport::Endpoint::loopback(45330);
    s.client.remote = transport::Endpoint::loopback(45331);
    s.client.ca_file = certificate;
    s.client.peer_name = "localhost";
    s.client.service_scope = "h3-early";
    s.client.early_data = quic::EarlyDataPolicy::replay_safe;
    s.client.session_cache = require(quic::SessionCache::create(), "session cache");
    s.server.local = s.client.remote;
    s.server.remote = s.client.local;
    s.server.certificate_file = certificate;
    s.server.private_key_file = key;
    s.server.service_scope = s.client.service_scope;
    s.server.early_data = quic::EarlyDataPolicy::replay_safe;
    s.server.early_data_context = http3::early_data_context(s.limits);
    s.server.server_context = require(quic::ServerContext::create(s.server), "server context");
    return s;
}

// Everything `from` sends without further input, as one flight. ngtcp2 paces
// packets, so the clock advances in 5 ms steps for up to 100 ms of silence —
// far below the initial ~1 s PTO, so no timer-driven retransmission can occur.
template<class Engine>
std::vector<quic::Bytes> flight(Engine& from, std::uint64_t& now) {
    std::vector<quic::Bytes> packets;
    for (int idle = 0; idle < 20 && packets.size() < 256;) {
        auto packet = require(from.poll(now), "poll");
        if (!packet.empty()) {
            packets.push_back(std::move(packet));
            idle = 0;
            continue;
        }
        now += 5'000'000;
        ++idle;
    }
    return packets;
}
void deliver(http3::Engine& to, const std::vector<quic::Bytes>& packets, std::uint64_t now) {
    for (const auto& packet : packets) require(to.receive(packet, now), "receive");
}

struct Peer {
    std::map<std::int64_t, int> heads;
    std::map<std::int64_t, bool> early;
    std::map<std::int64_t, std::string> status;
    std::map<std::int64_t, std::size_t> body;
    std::map<std::int64_t, bool> ended;
    std::vector<std::int64_t> finished;  // Request ends (server) in arrival order.
};
void observe(http3::Engine& engine, Peer& peer) {
    for (auto& event : engine.take_events()) {
        const auto id = event.stream_id;
        switch (event.kind) {
        case http3::Event::Kind::headers:
            ++peer.heads[id];
            peer.early[id] = event.early_data;
            peer.status[id] = status_of(event.fields);
            break;
        case http3::Event::Kind::body:
            peer.body[id] += event.data.size();
            require(engine.consume(id, event.data.size()), "consume");
            break;
        case http3::Event::Kind::end:
            peer.ended[id] = true;
            peer.finished.push_back(id);
            break;
        case http3::Event::Kind::reset:
            throw std::runtime_error("unexpected reset on stream " + std::to_string(id));
        case http3::Event::Kind::goaway:
            break;
        }
    }
}
void answer(http3::Engine& server, Peer& peer, const quic::Bytes& body) {
    for (const auto id : std::exchange(peer.finished, {}))
        require(server.respond(id, {{":status", "200"}, {"content-length", std::to_string(body.size())}},
                               body),
                "respond");
}

// Drive both engines until `done`, answering every finished request.
template<class Done>
void drive(Setup& s, http3::Engine& client, http3::Engine& server, Peer& cp, Peer& sp,
           const quic::Bytes& body, Done done) {
    for (int round = 0; round < 2000 && !done(); ++round) {
        s.now += 1'000'000;
        for (auto* engine : {&client, &server})
            if (engine->expiry() <= s.now) require(engine->handle_expiry(s.now), "expiry");
        deliver(server, flight(client, s.now), s.now);
        observe(server, sp);
        answer(server, sp, body);
        deliver(client, flight(server, s.now), s.now);
        observe(client, cp);
    }
    check(done(), "exchange did not finish");
}

// Settle the ticket the server issues after each handshake.
void await_ticket(Setup& s, http3::Engine& client, http3::Engine& server) {
    Peer cp, sp;
    drive(s, client, server, cp, sp, {}, [&] {
        return client.ready() && server.ready() && s.client.session_cache->size() == 1;
    });
}

void full_handshake(Setup& s) {
    auto quic_client = require(quic::Engine::client(s.client, s.now), "client");
    check(quic_client.early_data_status() == quic::EarlyDataStatus::not_attempted,
          "first connection attempted 0-RTT without a ticket");
    auto client = require(http3::Engine::create(std::move(quic_client), false, s.limits), "h3 client");
    check(!client.early_ready() && !client.ready(), "ticketless client claimed readiness");
    auto first = flight(client, s.now);
    auto server = require(http3::Engine::create(
        require(quic::Engine::accept(s.server, first.front(), s.now), "accept"), true, s.limits), "h3 server");
    check(!server.ready(), "server without 0-RTT was ready before the handshake");
    deliver(server, {first.begin() + 1, first.end()}, s.now);
    Peer cp, sp;
    drive(s, client, server, cp, sp, {}, [&] { return client.ready() && server.ready(); });
    const auto id = require(client.request(get("/full")), "full request");
    drive(s, client, server, cp, sp, quic::Bytes(5, std::byte{0x46}), [&] { return cp.ended[id]; });
    check(!cp.early[id] && !sp.early[id] && cp.status[id] == "200", "1-RTT request flagged early");
    await_ticket(s, client, server);
    std::cout << "full handshake stored a ticket\n";
}

void accepted(Setup& s) {
    auto client = require(http3::Engine::create(
        require(quic::Engine::client(s.client, s.now), "client"), false, s.limits), "h3 client");
    check(client.early_ready() && !client.ready(), "ticketed client not early-ready");
    auto post = client.request(get("/unsafe", "POST"));
    check(!post && post.error() == Errc::not_supported, "unsafe method accepted for 0-RTT");
    auto streaming = client.request_stream(get("/stream"));
    check(!streaming && streaming.error() == Errc::not_supported, "streaming accepted for 0-RTT");
    check(!client.cancel(0), "cancel accepted before 1-RTT");
    const auto id = require(client.request(get("/early")), "early request");
    const auto head = require(client.request(get("/early-head", "HEAD")), "early HEAD");

    // Client flight 1: Initial plus 0-RTT carrying both requests.
    auto first = flight(client, s.now);
    auto server = require(http3::Engine::create(
        require(quic::Engine::accept(s.server, first.front(), s.now), "accept"), true, s.limits), "h3 server");
    // A hybrid post-quantum ClientHello may span several Initials; keys follow the last one.
    deliver(server, {first.begin() + 1, first.end()}, s.now);
    check(server.transport().early_data_status() == quic::EarlyDataStatus::accepted,
          "server did not accept 0-RTT");
    check(server.ready() && !server.transport().handshake_complete(), "server not ready for 0.5-RTT");
    // Server flight 1, part one: handshake and 0.5-RTT SETTINGS; polling also processes 0-RTT.
    auto reply = flight(server, s.now);
    Peer cp, sp;
    observe(server, sp);
    check(sp.heads[id] == 1 && sp.early[id] && sp.ended[id] && sp.heads[head] == 1 && sp.early[head],
          "early requests were not surfaced before the handshake completed");
    check(!server.transport().handshake_complete(), "server handshake completed without the client");
    const quic::Bytes body(1500, std::byte{0x45});
    answer(server, sp, body);
    // Part two, still before any client packet: the 0.5-RTT responses. One round trip in total.
    for (auto& packet : flight(server, s.now)) reply.push_back(std::move(packet));
    deliver(client, reply, s.now);
    observe(client, cp);
    check(client.ready() && client.transport().early_data_status() == quic::EarlyDataStatus::accepted,
          "client did not settle accepted 0-RTT");
    check(client.transport().session_reused(), "0-RTT without resumption");
    check(cp.status[id] == "200" && cp.early[id] && cp.body[id] == body.size() && cp.ended[id],
          "early response did not arrive within the first round trip");
    check(cp.status[head] == "200" && cp.body[head] == 0 && cp.ended[head], "early HEAD response lost");

    drive(s, client, server, cp, sp, body, [&] { return server.transport().handshake_complete(); });
    const auto later = require(client.request(get("/later", "POST"), quic::Bytes(3, std::byte{1})), "1-RTT POST");
    drive(s, client, server, cp, sp, body, [&] { return cp.ended[later]; });
    check(!sp.early[later] && !cp.early[later] && sp.body[later] == 3, "1-RTT request flagged early");
    check(sp.heads[id] == 1 && sp.heads[head] == 1, "early request surfaced twice");
    await_ticket(s, client, server);
    std::cout << "accepted 0-RTT answered within one round trip\n";
}

void rejected(Setup& s) {
    auto refusing = s.server;
    refusing.early_data = quic::EarlyDataPolicy::disabled;  // Same ticket domain, 0-RTT refused.
    auto client = require(http3::Engine::create(
        require(quic::Engine::client(s.client, s.now), "client"), false, s.limits), "h3 client");
    check(client.early_ready(), "ticketed client not early-ready");
    const auto id = require(client.request(get("/replay")), "early request");
    const auto other = require(client.request(get("/replay-2"), quic::Bytes(700, std::byte{2})), "early request 2");
    auto first = flight(client, s.now);
    auto server = require(http3::Engine::create(
        require(quic::Engine::accept(refusing, first.front(), s.now), "accept"), true, s.limits), "h3 server");
    check(!server.ready(), "refusing server became ready early");
    deliver(server, {first.begin() + 1, first.end()}, s.now);
    auto reply = flight(server, s.now);
    Peer cp, sp;
    observe(server, sp);
    check(sp.heads.empty(), "rejected 0-RTT reached the server application");
    deliver(client, reply, s.now);
    observe(client, cp);
    check(cp.heads.empty(), "rejected requests produced responses before resubmission");
    const quic::Bytes body(900, std::byte{0x52});
    drive(s, client, server, cp, sp, body, [&] { return cp.ended[id] && cp.ended[other]; });
    check(client.transport().early_data_status() == quic::EarlyDataStatus::rejected &&
          client.transport().session_reused(), "0-RTT was not rejected on a resumed session");
    check(sp.heads[id] == 1 && sp.heads[other] == 1 && !sp.early[id] && !sp.early[other],
          "rejected requests were not resubmitted exactly once in 1-RTT");
    check(sp.body[other] == 700, "resubmitted body lost");
    check(cp.status[id] == "200" && cp.body[id] == body.size() && !cp.early[id],
          "resubmitted response lost or flagged early");
    check(cp.status[other] == "200" && cp.body[other] == body.size(), "second resubmission lost");
    await_ticket(s, client, server);
    std::cout << "rejected 0-RTT resubmitted on the same stream IDs\n";
}

// A hand-built HTTP/3 client sends an unsafe POST in 0-RTT; our own client refuses to.
void too_early(Setup& s) {
    auto raw = require(quic::Engine::client(s.client, s.now), "raw client");
    check(raw.early_data_status() == quic::EarlyDataStatus::pending, "raw client has no ticket");
    const auto control = require(raw.open_early_stream(true), "control stream");
    const quic::Bytes settings{std::byte{0x00}, std::byte{0x04}, std::byte{0x00}};
    require(raw.write_early(control, settings, false), "SETTINGS");
    const auto request = require(raw.open_early_stream(), "request stream");
    quic::Bytes headers{std::byte{0x01}, std::byte{0x10}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0xd4}, std::byte{0xd7}, std::byte{0xc1}, std::byte{0x50},
                        std::byte{0x09}};  // POST https / localhost, static QPACK only.
    for (char c : std::string("localhost")) headers.push_back(static_cast<std::byte>(c));
    require(raw.write_early(request, headers, true), "HEADERS");
    auto first = flight(raw, s.now);
    auto server = require(http3::Engine::create(
        require(quic::Engine::accept(s.server, first.front(), s.now), "accept"), true, s.limits), "h3 server");
    deliver(server, {first.begin() + 1, first.end()}, s.now);
    check(server.ready(), "server did not accept raw 0-RTT");
    quic::Bytes response;
    bool fin = false, surfaced = false;
    for (int round = 0; round < 400 && !(fin && s.client.session_cache->size() == 1); ++round) {
        s.now += 1'000'000;
        for (int k = 0; k < 64; ++k) {
            auto packet = require(raw.poll(s.now), "raw poll");
            if (packet.empty()) break;
            require(server.receive(packet, s.now), "server receive");
        }
        surfaced |= !server.take_events().empty();
        for (int k = 0; k < 64; ++k) {
            auto packet = require(server.poll(s.now), "server poll");
            if (packet.empty()) break;
            require(raw.receive(packet, s.now), "raw receive");
        }
        for (auto& event : raw.take_events()) {
            check(event.kind != quic::Event::Kind::reset, "425 path reset the request");
            if (event.kind != quic::Event::Kind::data) continue;
            require(raw.consume(event.stream_id, event.data.size()), "raw consume");
            if (event.stream_id != request) continue;
            response.insert(response.end(), event.data.begin(), event.data.end());
            fin |= event.fin;
        }
        if (raw.expiry() <= s.now) require(raw.handle_expiry(s.now), "raw expiry");
        if (server.expiry() <= s.now) require(server.handle_expiry(s.now), "server expiry");
    }
    check(fin && !response.empty() && response.front() == std::byte{0x01}, "no complete 425 response");
    const quic::Bytes status_425{std::byte{0xff}, std::byte{0x07}};  // QPACK static index 70.
    check(std::search(response.begin(), response.end(), status_425.begin(), status_425.end()) !=
              response.end(), "response was not 425 Too Early");
    check(!surfaced, "unsafe 0-RTT request reached the server application");
    std::cout << "unsafe 0-RTT request answered 425 without surfacing\n";
}

void configuration(Setup& s) {
    auto other = s.limits;
    other.max_header_bytes = 1234;
    check(http3::early_data_context(other) != http3::early_data_context(s.limits), "context ignores SETTINGS");
    auto server = http3::make_server(s.server, {}, other);
    check(!server && server.error() == Errc::invalid_argument, "mismatched server SETTINGS accepted");
    check(http3::make_server(s.server, {}, s.limits).has_value(), "matching server SETTINGS refused");
    auto fresh = s.client;
    fresh.session_cache.reset();
    fresh.early_data = quic::EarlyDataPolicy::disabled;
    auto initial = require(require(quic::Engine::client(fresh, s.now), "client").poll(s.now), "initial");
    auto drifted = s.server;
    drifted.early_data_context = http3::early_data_context(other);
    check(!quic::Engine::accept(drifted, initial, s.now), "engine context differing from ServerContext accepted");
    auto engine = require(quic::Engine::accept(s.server, initial, s.now), "accept");
    auto h3 = http3::Engine::create(std::move(engine), true, other);
    check(!h3 && h3.error() == Errc::invalid_argument, "HTTP/3 SETTINGS differing from the ticket domain accepted");
    std::cout << "0-RTT SETTINGS binding enforced\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) return 2;
    try {
        auto s = make_setup(argv[1], argv[2]);
        configuration(s);
        full_handshake(s);
        accepted(s);
        rejected(s);
        too_early(s);
        accepted(s);
        std::cout << "HTTP/3 0-RTT accepted/rejected/425/SETTINGS binding passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
