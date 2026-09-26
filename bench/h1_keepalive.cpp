// Mira/bench/h1_keepalive.cpp — HTTP/1.1 keep-alive, small responses.
//
// What this measures: the per-exchange cost of the whole HTTP/1.1 path —
// parse a request, run a handler, serialise a small response, writev it
// out — over a loopback TCP connection with keep-alive. Numbers are
// relative: compare two commits of Mira, not Mira against wrk (an external
// load generator measures sockets, not the machinery under change).
//
// In-process by design: server and client coroutines share one event loop,
// so a regression in parsing, framing, or allocation churn shows up in the
// number, and nothing external has to be installed to see it.
//
// Usage: bench_h1_keepalive [requests=200000]
//
// The exit code is 0 only when the client completed every exchange; a
// broken run fails loudly instead of reporting a suspiciously fast zero.

#include <mira/core/event_loop.hpp>
#include <mira/core/task.hpp>
#include <mira/core/task_scope.hpp>
#include <mira/http/connection.hpp>
#include <mira/transport/tcp.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <utility>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;
using LoopClock = EventLoop::Clock;

namespace {

struct Counters {
    std::uint64_t completed = 0;  // client: completed exchanges
    bool client_ok = false;       // client ran to its planned end
};

// One keep-alive connection, one small JSON body. The handler deliberately
// skips Content-Length: serve_connection owns framing. The per-connection
// request cap is raised to the bench target — the default of 100 is exactly
// what a conservative server should ship, and it would end the connection
// one percent into the run.
Task<void> serve_one(tcp::Listener& listener, std::uint64_t requests) {
    auto accepted = co_await listener.accept();
    if (!accepted) co_return;
    tcp::Socket peer = std::move(*accepted);
    auto handler = [](const http::Request&, auto& writer,
                      std::span<const std::byte>) -> Task<Result<void>> {
        static constexpr char body[] = "{\"ok\":true}";
        const std::span payload{reinterpret_cast<const std::byte*>(body), sizeof(body) - 1};
        http::Response response;
        response.status = 200;
        response.headers.append("content-type", "application/json");
        co_return co_await writer.send(response, payload);
    };
    http::ServerOptions options;
    options.max_requests_per_connection = static_cast<std::uint32_t>(requests);
    // serve_connection runs the connection to exhaustion: until the client
    // hangs up, a limit fires, or the exchange decides to close. Its return
    // drives the server task — one connection, per-exchange cost, not
    // accept concurrency.
    static_cast<void>(co_await http::serve_connection(peer, std::move(handler), options));
}

Task<void> server_task(tcp::Listener& listener, std::uint64_t requests) {
    co_await serve_one(listener, requests);
}

Task<void> client_task(EventLoop& loop, const Endpoint& address, std::uint64_t requests,
                       Counters& counters) {
    auto connected = co_await tcp::connect(loop, address);
    if (!connected) {
        std::fprintf(stderr, "bench: connect failed: %s\n",
                     connected.error().message().c_str());
        co_return;
    }
    tcp::Socket socket = std::move(*connected);

    static constexpr char request[] =
        "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: mira-bench\r\n\r\n";
    const std::span wire{reinterpret_cast<const std::byte*>(request), sizeof(request) - 1};

    // Read cursor: responses can arrive split across reads, so the body
    // terminator is scanned over a sliding window and the tail is kept as
    // the start of the next response. Per-exchange cadence means one read
    // cannot span two responses' beginnings, but a single response can
    // absolutely span several reads.
    std::array<std::byte, 8192> buffer{};
    std::size_t pending = 0;
    for (std::uint64_t i = 0; i < requests; ++i) {
        if (!co_await write_all(socket, wire)) co_return;
        bool whole = false;
        while (!whole) {
            if (pending > 0) {
                const std::span window{buffer.data(), pending};
                for (std::size_t k = 0; k + 11 <= window.size(); ++k) {
                    if (std::memcmp(window.data() + k, "{\"ok\":true}", 11) == 0) {
                        whole = true;
                        break;
                    }
                }
            }
            if (whole) break;
            if (pending == buffer.size()) co_return;  // response larger than budget
            const auto read =
                co_await socket.read_some(std::span<std::byte>{buffer.data() + pending,
                                                               buffer.size() - pending});
            if (!read || *read == 0) co_return;
            pending += *read;
        }
        // The whole response is consumed; drop the scanned bytes and keep
        // any tail that arrived past the terminator for the next exchange.
        // A strict scan never over-reads past the terminator on the wire,
        // but the kernel may deliver more in one segment than this response
        // needs; per-exchange cadence makes that impossible in practice, and
        // if it ever happened the scan restarts on stale bytes — so the
        // honest cursor is to reset after every completed exchange.
        pending = 0;
        ++counters.completed;
    }
    counters.client_ok = true;
}

}  // namespace

int main(int argc, char** argv) {
    const std::uint64_t requests = argc > 1 ? std::stoull(argv[1]) : 200000;

    Result<EventLoop> created = EventLoop::create();
    if (!created) {
        std::fprintf(stderr, "bench: no event loop: %s\n", created.error().message().c_str());
        return 1;
    }
    EventLoop& loop = created.value();

    auto bound = tcp::Listener::bind(loop, Endpoint::loopback(0));
    if (!bound) {
        std::fprintf(stderr, "bench: bind failed: %s\n", bound.error().message().c_str());
        return 1;
    }
    const Endpoint address = bound->local_endpoint();

    Counters counters{};
    TaskScope tasks;
    tasks.spawn(server_task(*bound, requests));
    tasks.spawn(client_task(loop, address, requests, counters));

    const auto started = LoopClock::now();
    // run_until_complete drives the join: both children must finish (the
    // server only returns once serve_connection sees the client hang up).
    const Result<void> joined = loop.run_until_complete(tasks.join());
    const auto elapsed = Clock::now() - started;

    if (!joined) {
        std::fprintf(stderr, "bench: tasks did not finish cleanly: %s\n",
                     joined.error().message().c_str());
        return 1;
    }
    if (!counters.client_ok || counters.completed != requests) {
        std::fprintf(stderr, "bench: incomplete run (%llu/%llu exchanges)\n",
                     static_cast<unsigned long long>(counters.completed),
                     static_cast<unsigned long long>(requests));
        return 1;
    }
    const double seconds = std::chrono::duration<double>(elapsed).count();
    const double rps = seconds > 0 ? static_cast<double>(counters.completed) / seconds : 0.0;
    std::printf("h1_keepalive: %llu exchanges in %.3fs -> %.0f req/s\n",
                static_cast<unsigned long long>(counters.completed), seconds, rps);
    return 0;
}
