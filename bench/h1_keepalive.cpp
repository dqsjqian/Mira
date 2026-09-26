// Mira/bench/h1_keepalive.cpp — HTTP/1.1 keep-alive, small responses.
//
// What this measures: the per-request cost of the whole HTTP/1.1 path —
// parse a request, run a handler, serialise a small response, writev it
// out — over one loopback TCP connection with keep-alive, N requests per
// connection. Numbers are relative: compare two commits, not Mira vs wrk.

#include "mira/core/event_loop.hpp"
#include "mira/core/task.hpp"
#include "mira/http/connection.hpp"
#include "mira/transport/endpoint.hpp"
#include "mira/transport/tcp.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

using namespace Mira;
using namespace std::chrono_literals;
using Clock = EventLoop::Clock;

namespace {

struct Counters {
    std::uint64_t requests = 0;
    std::uint64_t bytes = 0;
};

Task<void> serve_one(EventLoop& loop, tcp::Socket socket, Counters& counters) {
    // The echo-style handler: one small JSON-ish body, keep-alive on.
    co_await http::serve_connection(
        socket,
        [](const http::Request&, http::ResponseWriter<tcp::Socket>& writer,
           std::span<const std::byte>) -> Task<Result<void>> {
            static const char body[] = "{\"ok\":true}";
            const std::span<const std::byte> payload{
                reinterpret_cast<const std::byte*>(body), sizeof(body) - 1};
            http::Response response;
            response.status = 200;
            response.reason = "OK";
            response.headers.append("content-type", "application/json");
            response.headers.append("content-length", std::to_string(payload.size()));
            co_return co_await writer.send(response, payload);
        },
        {});
}

Task<void> server(EventLoop& loop, tcp::Listener listener, std::uint64_t target,
                  Counters& counters, bool& done) {
    while (counters.requests < target) {
        auto accepted = co_await listener.accept();
        if (!accepted) break;
        // One connection at a time: the bench is per-request cost, not
        // concurrency. serve_connection handles keep-alive until the peer
        // closes or the counter is satisfied.
        auto result = co_await serve_one(loop, std::move(*accepted), counters);
        (void)result;
    }
    done = true;
    loop.stop();
}

Task<void> client(EventLoop& loop, const Endpoint& address, std::uint64_t requests,
                  Counters& counters) {
    auto connected = co_await tcp::Socket::connect(loop, address);
    if (!connected) {
        std::fprintf(stderr, "connect failed: %s\n", connected.error().message().c_str());
        co_return;
    }
    tcp::Socket socket = std::move(*connected);

    static const char request[] =
        "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: mira-bench\r\n\r\n";
    const std::span<const std::byte> wire{reinterpret_cast<const std::byte*>(request),
                                           sizeof(request) - 1};
    std::array<std::byte, 4096> read_buffer{};

    // keep-alive: the server closes when the bench is over, so a read
    // failure/EOF after enough responses is the normal exit.
    for (std::uint64_t i = 0; i < requests; ++i) {
        auto written = co_await write_all(socket, wire);
        if (!written) co_return;
        // Response = head + tiny body; read until this response is whole.
        // The small fixed body makes one read per response the common case;
        // a partial read just loops, same as any real client.
        std::size_t got = 0;
        while (got < read_buffer.size()) {
            auto read = co_await socket.read_some(read_buffer);
            if (!read || *read == 0) co_return;
            got += *read;
            // Cheap completeness check: the body terminator of our fixed
            // JSON body ends the response.
            const std::span<const std::byte> window = std::span{read_buffer.data(), got};
            for (std::size_t k = 0; k + 7 < window.size(); ++k) {
                if (std::memcmp(window.data() + k, "\"ok\":true}", 10) == 0) {
                    goto response_done;
                }
            }
        }
    response_done:
        counters.requests += 1;
        counters.bytes += got;
    }
}

}  // namespace

int main(int argc, char** argv) {
    const std::uint64_t requests = argc > 1 ? std::stoull(argv[1]) : 200000;
    const std::uint64_t target = requests;  // server stops after this many

    EventLoop loop;
    auto bound = tcp::Listener::bind(loop, Endpoint::loopback(0));
    if (!bound) {
        std::fprintf(stderr, "bind failed: %s\n", bound.error().message().c_str());
        return 1;
    }
    const Endpoint address = *bound->local_endpoint();

    Counters counters{};
    bool done = false;
    // Server task runs until `target` responses were served; the client
    // drives exactly `requests` of them. run_until_complete bounds the
    // whole exchange.
    loop.post([&loop, &bound, target, &counters, &done]() mutable {
        auto task = server(loop, std::move(*bound), target, counters, done);
        loop.post([task = std::move(task)]() mutable {
            // Detached: the loop's lifetime is the task's lifetime here.
            (void)task;
        });
    });
    // Client: start after one turn so the listener task is queued first.
    loop.post([&loop, &address, requests, &counters]() mutable {
        auto task = client(loop, address, requests, counters);
        loop.post([task = std::move(task)]() mutable { (void)task; });
    });

    const auto started = Clock::now();
    while (!done) {
        loop.run_once();
    }
    const auto elapsed = Clock::now() - started;

    const double seconds = std::chrono::duration<double>(elapsed).count();
    const double rps = seconds > 0 ? static_cast<double>(counters.requests) / seconds : 0.0;
    std::printf("h1_keepalive: %llu requests in %.3fs -> %.0f req/s (%.1f MiB handled)\n",
                static_cast<unsigned long long>(counters.requests), seconds, rps,
                static_cast<double>(counters.bytes) / (1024.0 * 1024.0));
    return 0;
}
