// Mira/bench/h1_overload.cpp — backpressure under a small read window.
//
// What this measures: the cost of *not* being able to slurp. A real server
// facing a large upload does not own the peer's send rate; backpressure is
// the mechanism by which a slow consumer slows the whole pipeline instead of
// buffering without bound. This bench drives request/response exchanges over
// a socket whose reads are deliberately tiny (`ServerOptions::read_chunk`
// set to a fraction of the body size), so every exchange crosses the
// read-window boundary many times.
//
// Comparing this number against `h1_keepalive` at the same exchange size
// prices the per-syscall overhead of chunked delivery: the parser rolling
// the input buffer, the state machine restarting between reads, and the
// loop waking for every fragment.
//
// In-process by design; the small window is configured, not simulated, so
// the code path under test is the production path.
//
// Usage: bench_h1_overload [exchanges=50000] [response_read_chunk=4096]

#include <mira/core/event_loop.hpp>
#include <mira/core/task.hpp>
#include <mira/core/task_scope.hpp>
#include <mira/http/connection.hpp>
#include <mira/transport/tcp.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <utility>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;
using LoopClock = EventLoop::Clock;

namespace {

struct Counters {
    std::uint64_t completed = 0;
    bool client_ok = false;
};

// One keep-alive connection whose requests carry a body several times the
// server's read window: the parser rolls the buffer across many reads per
// request, which is exactly the backpressure path.
Task<void> serve_one(tcp::Listener& listener, std::uint64_t requests) {
    auto accepted = co_await listener.accept();
    if (!accepted) co_return;
    tcp::Socket peer = std::move(*accepted);
    auto handler = [](const http::Request&, auto& writer,
                      std::span<const std::byte> body) -> Task<Result<void>> {
        static constexpr char body_tag[] = "accepted";
        http::Response response;
        response.status = 200;
        response.headers.append("x-body-bytes", std::to_string(body.size()));
        const std::span payload{reinterpret_cast<const std::byte*>(body_tag),
                                sizeof(body_tag) - 1};
        co_return co_await writer.send(response, payload);
    };
    http::ServerOptions options;
    options.read_chunk = 512;  // the whole point: a fraction of the body
    options.max_requests_per_connection = static_cast<std::uint32_t>(requests);
    static_cast<void>(co_await http::serve_connection(peer, std::move(handler), options));
}

Task<void> server_task(tcp::Listener& listener, std::uint64_t requests) {
    co_await serve_one(listener, requests);
}

Task<void> client_task(EventLoop& loop, const Endpoint& address, std::uint64_t requests,
                       std::size_t response_read_chunk, Counters& counters) {
    auto connected = co_await tcp::connect(loop, address);
    if (!connected) {
        std::fprintf(stderr, "bench: connect failed: %s\n",
                     connected.error().message().c_str());
        co_return;
    }
    tcp::Socket socket = std::move(*connected);

    // 4 KiB body: eight read-window crossings per request at read_chunk=512.
    const std::string body(4096, 'x');
    const std::string request_head =
        "POST /up HTTP/1.1\r\nHost: localhost\r\nUser-Agent: mira-bench\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    const std::span head{reinterpret_cast<const std::byte*>(request_head.data()),
                         request_head.size()};
    const std::span body_span{reinterpret_cast<const std::byte*>(body.data()), body.size()};

    std::array<std::byte, 4096> buffer{};
    for (std::uint64_t i = 0; i < requests; ++i) {
        if (!co_await write_all(socket, head)) co_return;
        if (!co_await write_all(socket, body_span)) co_return;

        // One response per request; it fits in the buffer, so scan for the
        // body tag that certifies the server saw the whole upload.
        std::size_t pending = 0;
        bool whole = false;
        while (!whole) {
            const auto read = co_await socket.read_some(std::span<std::byte>{
                buffer.data() + pending, std::min(response_read_chunk, buffer.size() - pending)});
            if (!read || *read == 0) co_return;
            pending += *read;
            std::string_view text{reinterpret_cast<const char*>(buffer.data()), pending};
            if (text.find("HTTP/1.1 200") != std::string_view::npos &&
                text.find("accepted") != std::string_view::npos) {
                whole = true;
            }
            if (pending == buffer.size() && !whole) co_return;
        }
        ++counters.completed;
    }
    counters.client_ok = true;
}

}  // namespace

int main(int argc, char** argv) {
    const std::uint64_t requests = argc > 1 ? std::stoull(argv[1]) : 50000;
    const std::size_t response_read_chunk = argc > 2 ? std::stoull(argv[2]) : 4096;
    if (response_read_chunk == 0 || response_read_chunk > 4096) {
        std::fprintf(stderr, "bench: response_read_chunk must be between 1 and 4096\n");
        return 1;
    }

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
    tasks.spawn(client_task(loop, address, requests, response_read_chunk, counters));

    const auto started = LoopClock::now();
    const Result<void> joined = loop.run_until_complete(tasks.join());
    const auto elapsed = LoopClock::now() - started;

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
    std::printf("h1_overload: %llu exchanges (4KiB bodies, 512B read window, %zuB response reads)"
                " in %.3fs -> %.0f req/s\n",
                static_cast<unsigned long long>(counters.completed), response_read_chunk,
                seconds, rps);
    return 0;
}
