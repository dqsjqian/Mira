// Mira/bench/h1_churn.cpp — HTTP/1.1 connection churn.
//
// What this measures: the cost of a whole connection lifetime minus the
// exchange — accept, serve one small request, close — repeated as fast as the
// loop can spin. Keep-alive measures the per-exchange cost once the parties
// are set up; churn measures everything the setup itself costs: descriptor
// accept/release, parser construction, the handshake bytes, teardown. A
// server that leaks or hoards per-connection state shows up here as a number
// that sags while `h1_keepalive` stays flat.
//
// In-process by design, same as the other benches: client and server share
// one event loop, so nothing external has to be installed to see it.
//
// Usage: bench_h1_churn [connections=20000]
//
// The exit code is 0 only when every connection completed one exchange; a
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
#include <span>
#include <string>
#include <utility>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;
using LoopClock = EventLoop::Clock;

namespace {

struct Counters {
    std::uint64_t completed = 0;   // connections that finished one exchange
    bool client_ok = false;        // client ran to its planned end
};

std::uint64_t g_accepted = 0;

Task<void> serve_one_exchange(tcp::Listener& listener) {
    auto accepted = co_await listener.accept();
    if (!accepted) co_return;
    ++g_accepted;
    tcp::Socket peer = std::move(*accepted);
    auto handler = [](const http::Request&, auto& writer,
                      std::span<const std::byte>) -> Task<Result<void>> {
        static constexpr char body[] = "{\"ok\":true}";
        const std::span payload{reinterpret_cast<const std::byte*>(body), sizeof(body) - 1};
        http::Response response;
        response.status = 200;
        response.headers.append("content-type", "application/json");
        response.headers.append("connection", "close");
        co_return co_await writer.send(response, payload);
    };
    http::ServerOptions options;
    options.max_requests_per_connection = 1;  // churn: one exchange per connection
    static_cast<void>(co_await http::serve_connection(peer, std::move(handler), options));
}

Task<void> server_task(tcp::Listener& listener, std::uint64_t connections) {
    for (std::uint64_t i = 0; i < connections; ++i) {
        co_await serve_one_exchange(listener);
    }
}

Task<void> client_task(EventLoop& loop, const Endpoint& address, std::uint64_t connections,
                       Counters& counters) {
    static constexpr char request[] =
        "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: mira-bench\r\n\r\n";
    const std::span wire{reinterpret_cast<const std::byte*>(request), sizeof(request) - 1};
    static constexpr char tail[] = "{\"ok\":true}";

    std::array<std::byte, 2048> buffer{};
    std::string response;
    for (std::uint64_t i = 0; i < connections; ++i) {
        auto connected = co_await tcp::connect(loop, address);
        if (!connected) {
            std::fprintf(stderr, "bench: connect failed: %s\n",
                         connected.error().message().c_str());
            co_return;
        }
        tcp::Socket socket = std::move(*connected);
        if (!co_await write_all(socket, wire)) co_return;

        // Read to EOF: the server hangs up after one response by policy, and
        // the response is small enough to fit any sane socket buffer.
        response.clear();
        for (;;) {
            const auto read = co_await socket.read_some(buffer);
            if (!read) break;  // eof or error ends this connection's read
            if (*read == 0) break;
            response.append(reinterpret_cast<const char*>(buffer.data()), *read);
        }
        if (response.find(tail) == std::string::npos) co_return;
        ++counters.completed;
    }
    counters.client_ok = true;
}

}  // namespace

int main(int argc, char** argv) {
    const std::uint64_t connections = argc > 1 ? std::stoull(argv[1]) : 20000;

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
    tasks.spawn(server_task(*bound, connections));
    tasks.spawn(client_task(loop, address, connections, counters));

    const auto started = LoopClock::now();
    const Result<void> joined = loop.run_until_complete(tasks.join());
    const auto elapsed = LoopClock::now() - started;

    if (!joined) {
        std::fprintf(stderr, "bench: tasks did not finish cleanly: %s\n",
                     joined.error().message().c_str());
        return 1;
    }
    if (!counters.client_ok || counters.completed != connections) {
        std::fprintf(stderr, "bench: incomplete run (%llu/%llu connections)\n",
                     static_cast<unsigned long long>(counters.completed),
                     static_cast<unsigned long long>(connections));
        return 1;
    }
    const double seconds = std::chrono::duration<double>(elapsed).count();
    const double cps = seconds > 0 ? static_cast<double>(counters.completed) / seconds : 0.0;
    std::printf("h1_churn: %llu connections in %.3fs -> %.0f conn/s (%llu accepted)\n",
                static_cast<unsigned long long>(counters.completed), seconds, cps,
                static_cast<unsigned long long>(g_accepted));
    return 0;
}
