// Mira/bench/h2_roundtrip.cpp — HTTP/2 concurrent streams, one connection.
//
// What this measures: the per-stream cost of the HTTP/2 path — HPACK reuse
// across a long connection, stream bookkeeping with several streams in
// flight, frame parse/serialise — over one loopback TCP connection.
// Numbers are relative: compare two commits, not Mira vs wrk.
//
// Usage: bench_h2_roundtrip [streams=20000] [concurrency=16]

#include "mira/core/event_loop.hpp"
#include "mira/core/task.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/http2/connection.hpp"
#include "mira/http2/headers.hpp"
#include "mira/http2/session.hpp"
#include "mira/transport/endpoint.hpp"
#include "mira/transport/tcp.hpp"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;
using LoopClock = EventLoop::Clock;

namespace {

struct Counters {
    std::uint64_t opened = 0;
    std::uint64_t answered = 0;
};

Task<void> h2_server(tcp::Listener listener, std::uint64_t target) {
    Result<tcp::Socket> accepted = co_await listener.accept();
    if (!accepted) co_return;
    tcp::Socket peer = std::move(*accepted);

    Result<http2::Session> created = http2::Session::create(http2::Role::server);
    if (!created) co_return;
    http2::Connection<tcp::Socket> connection(peer, std::move(*created));

    std::uint64_t answered = 0;
    std::set<std::int32_t> responded;
    // The server ends on the client's GOAWAY (state leaves open) or the
    // read loop's eof; it never races the client's own completion count.
    while (connection.session().state() == http2::State::open && answered < target) {
        if (const Result<void> round = co_await connection.pump(); !round) break;
        for (const std::int32_t id : connection.session().streams()) {
            const http2::Stream* stream = connection.session().stream(id);
            if (stream == nullptr) continue;
            if (!connection.session().take_body(id)) co_return;
            if (stream->closed) {
                if (!connection.session().release(id)) co_return;
                responded.erase(id);
                continue;
            }
            if (stream->error || responded.contains(id) || !stream->remote_end) continue;
            if (connection.session().respond(id, {{":status", "200"}}, {}).has_value()) {
                responded.insert(id);
                answered += 1;
            }
        }
        if (const Result<void> flushed = co_await connection.flush(); !flushed) break;
        for (const auto id : connection.session().streams()) {
            if (connection.session().stream(id)->closed) {
                if (!connection.session().release(id)) co_return;
                responded.erase(id);
            }
        }
    }
    static_cast<void>(co_await connection.flush());
    // Closing the socket is what ends the client's read loop: without eof
    // the peer's pump() parks forever on a connection nobody will write.
    peer.close();
}

Task<void> h2_client(EventLoop& loop, const Endpoint& address, std::uint64_t streams,
                     std::uint64_t concurrency, Counters& counters, bool& done) {
    Result<tcp::Socket> connected = co_await tcp::connect(loop, address);
    if (!connected) {
        done = true;
        co_return;
    }
    tcp::Socket socket = std::move(*connected);
    Result<http2::Session> created = http2::Session::create(http2::Role::client);
    if (!created) {
        done = true;
        co_return;
    }
    http2::Connection<tcp::Socket> connection(socket, std::move(*created));

    const http2::Headers request{{":method", "GET"},
                                 {":scheme", "http"},
                                 {":authority", "localhost"},
                                 {":path", "/bench"}};

    int rounds = 0;
    while (counters.answered < streams && rounds < 100000) {
        // Keep up to `concurrency` streams in flight — the pattern the h2
        // machinery exists for.
        while (counters.opened < streams && counters.opened - counters.answered < concurrency) {
            if (!connection.session().request(request).has_value()) break;
            ++counters.opened;
        }
        if (const Result<void> round = co_await connection.pump(); !round) break;
        ++rounds;
        for (const std::int32_t id : connection.session().streams()) {
            const http2::Stream* stream = connection.session().stream(id);
            if (stream == nullptr) continue;
            if (!connection.session().take_body(id)) co_return;
            if (!stream->closed) continue;
            if (stream->error || !stream->remote_end) co_return;
            if (!connection.session().release(id)) co_return;
            counters.answered += 1;
        }
        if (const Result<void> flushed = co_await connection.flush(); !flushed) break;
    }
    static_cast<void>(connection.session().goaway());
    static_cast<void>(co_await connection.flush());
    done = true;
}

bool parse_number(std::string_view text, std::uint64_t& value) {
    if (text.empty()) return false;
    return std::from_chars(text.data(), text.data() + text.size(), value).ec == std::errc{};
}

}  // namespace

int main(int argc, char** argv) {
    std::uint64_t streams = 20000;
    std::uint64_t concurrency = 16;
    if (argc > 1 && !parse_number(argv[1], streams)) {
        std::fprintf(stderr, "usage: %s [streams] [concurrency]\n", argv[0]);
        return 2;
    }
    if (argc > 2 && !parse_number(argv[2], concurrency)) {
        std::fprintf(stderr, "usage: %s [streams] [concurrency]\n", argv[0]);
        return 2;
    }

    Result<EventLoop> created = EventLoop::create();
    if (!created) {
        std::fprintf(stderr, "loop create failed: %s\n", created.error().message().c_str());
        return 1;
    }
    EventLoop& loop = *created;

    Result<tcp::Listener> bound = tcp::Listener::bind(loop, Endpoint::loopback(0));
    if (!bound) {
        std::fprintf(stderr, "bind failed: %s\n", bound.error().message().c_str());
        return 1;
    }
    const Endpoint address = bound->local_endpoint();

    Counters counters;
    bool done = false;

    TaskScope tasks;
    tasks.spawn(h2_server(std::move(*bound), streams));
    tasks.spawn(h2_client(loop, address, streams, concurrency, counters, done));

    const auto started = LoopClock::now();
    const Result<void> joined = loop.run_until_complete(tasks.join());
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();

    if (!joined) {
        std::fprintf(stderr, "bench join: %s\n", joined.error().message().c_str());
        return 1;
    }
    const double per_second =
        elapsed > 0 ? static_cast<double>(counters.answered) * 1000.0 /
                          static_cast<double>(elapsed)
                    : 0.0;
    std::printf("h2 roundtrip: %llu streams in %lldms (%.0f stream/s), concurrency %llu\n",
                static_cast<unsigned long long>(counters.answered),
                static_cast<long long>(elapsed), per_second,
                static_cast<unsigned long long>(concurrency));
    return counters.answered == streams ? 0 : 1;
}
