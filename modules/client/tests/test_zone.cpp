// IPv6 zone ids through the pooled client.
//
// A zone id routes the connection; it is not origin identity. So:
//  * "fe80::1%eth0" and "fe80::1%<ifindex>" canonicalize to one pool,
//  * different zones stay separate pools (no cross-zone connection reuse),
//  * the Host header on the wire carries the bare address, never the zone,
//  * unknown interfaces and malformed scopes fail as invalid_argument,
//    never as not_supported.
//
// The resolver backend maps every host to loopback, so these cases prove
// normalize + authority + session handling without needing a real
// link-local peer. A real link-local dial is verified separately by hand
// (see the P2-8 report note): the sandbox has no stable link-local address
// to bind in CI.

#include "check.hpp"
#include "mira/client/http.hpp"
#include "mira/core/task_scope.hpp"

#include <array>
#include <charconv>
#include <string>

#if !MIRA_PLATFORM_WINDOWS
#include <net/if.h>
#endif

#define CHECK_VALUE(expr) CHECK(static_cast<bool>(expr))
using namespace Mira;
using namespace Mira::client;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {

std::span<const std::byte> bytes(std::string_view value) {
    return std::as_bytes(std::span{value.data(), value.size()});
}

struct Server {
    EventLoop& loop;
    tcp::Listener listener;
    std::stop_source stop;
    std::size_t accepted = 0;
    std::vector<std::string> hosts{};
    Task<void> serve(tcp::Socket socket) {
        std::array<std::byte, 4096> buffer{};
        std::string pending;
        const OperationOptions io{.stop = stop.get_token(), .deadline = Clock::now() + 10s};
        for (;;) {
            while (pending.find("\r\n\r\n") == std::string::npos) {
                auto read = co_await socket.read_some(buffer, io);
                if (!read) co_return;
                pending.append(reinterpret_cast<const char*>(buffer.data()), *read);
                if (pending.size() > 8192) co_return;
            }
            const auto end = pending.find("\r\n\r\n") + 4;
            const auto head = pending.substr(0, end);
            pending.erase(0, end);
            std::size_t pos = 0;
            while (pos < head.size()) {
                const auto line_end = head.find("\r\n", pos);
                const auto line = head.substr(pos, line_end == std::string::npos
                                                       ? std::string::npos
                                                       : line_end - pos);
                if (line.starts_with("Host:")) {
                    auto value = line.substr(5);
                    while (!value.empty() && value.front() == ' ') value.erase(0, 1);
                    hosts.push_back(std::string{value});
                }
                if (line_end == std::string::npos) break;
                pos = line_end + 2;
            }
            static_cast<void>(co_await write_all(
                socket, bytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), io));
        }
    }
    Task<void> run() {
        TaskScope children;
        for (;;) {
            auto socket = co_await listener.accept({.stop = stop.get_token()});
            if (!socket) break;
            ++accepted;
            children.spawn(serve(std::move(*socket)));
        }
        co_await children.join();
    }
};

template<typename S>
Task<std::string> drain(S& session) {
    std::string body;
    for (;;) {
        auto part = co_await session.read_body();
        CHECK_VALUE(part);
        if (!part || part->empty()) break;
        body.append(reinterpret_cast<const char*>(part->data()), part->size());
    }
    co_return body;
}

http::Request request() {
    http::Request result;
    result.target = "/";
    return result;
}

Task<bool> round_trip(HttpClient& client, std::string host, std::uint16_t port) {
    auto lease = co_await client.acquire(std::move(host), port);
    if (!lease) co_return false;
    if (!(co_await lease->start(request()))) co_return false;
    if ((co_await drain(*lease)) != "ok") co_return false;
    co_return lease->recycle();
}

Task<void> exercise(EventLoop& loop, Server& server) {
    auto backend = [](const ResolveQuery& query, std::size_t) -> Result<Resolver::Endpoints> {
        unsigned port = 0;
        const auto parsed = std::from_chars(query.service.data(), query.service.data() + query.service.size(), port);
        if (parsed.ec != std::errc{} || port > 65535) return fail(Errc::invalid_argument);
        return Resolver::Endpoints{Endpoint::loopback(static_cast<std::uint16_t>(port))};
    };
    Options options;
    options.http.request_timeout = 5s;
    auto client = HttpClient::create(loop, {}, options, {}, backend);
    CHECK_VALUE(client);
    if (!client) co_return;
    const auto port = server.listener.local_endpoint().port();

    // Numeric scope: accepted (this used to be not_supported), and the
    // Host header on the wire carries the bare address, never the zone.
    CHECK_VALUE(co_await round_trip(*client, "fe80::1%1", port));
    CHECK_VALUE(!server.hosts.empty());
    CHECK_VALUE(server.hosts.back() == "[fe80::1]:" + std::to_string(port));

    // A different zone is a different origin: it must not reuse the
    // zone-1 connection.
    const auto accepted_before = server.accepted;
    CHECK_VALUE(co_await round_trip(*client, "fe80::1%2", port));
    CHECK_VALUE(server.accepted == accepted_before + 1);
    CHECK_VALUE(server.hosts.back() == "[fe80::1]:" + std::to_string(port));

#if !MIRA_PLATFORM_WINDOWS
    // An interface name canonicalizes to its numeric scope, so the name
    // spelling and the numeric spelling share one pool.
    const unsigned lo = if_nametoindex("lo");
    if (lo != 0) {
        // The name spelling may reuse an idle connection from an earlier
        // case when lo's index coincides with an already-used zone, so the
        // invariant is stated on the second spelling: it must never open
        // a connection of its own, because it names the same pool.
        const auto before_named = server.accepted;
        CHECK_VALUE(co_await round_trip(*client, "fe80::1%lo", port));
        const auto after_named = server.accepted;
        CHECK_VALUE(after_named == before_named || after_named == before_named + 1);
        CHECK_VALUE(co_await round_trip(*client, "fe80::1%" + std::to_string(lo), port));
        CHECK_VALUE(server.accepted == after_named);
        CHECK_VALUE(server.hosts.back() == "[fe80::1]:" + std::to_string(port));
    }
#endif

    // Unknown interfaces and malformed scopes fail fast as
    // invalid_argument, before any dial is attempted.
    {
        auto bad = co_await client->acquire("fe80::1%no-such-interface-xyz", port);
        CHECK_VALUE(!bad && bad.error() == Errc::invalid_argument);
    }
    {
        auto bad = co_await client->acquire("fe80::1%", port);
        CHECK_VALUE(!bad && bad.error() == Errc::invalid_argument);
    }
    {
        auto bad = co_await client->acquire("fe80::1%1%2", port);
        CHECK_VALUE(!bad && bad.error() == Errc::invalid_argument);
    }
}

Task<void> root(EventLoop& loop) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK_VALUE(listener);
    if (!listener) co_return;
    Server server{loop, std::move(*listener), {}};
    TaskScope tasks;
    tasks.spawn(server.run());
    co_await exercise(loop, server);
    server.stop.request_stop();
    co_await tasks.join();
}

}  // namespace

int main() {
    auto loop = EventLoop::create();
    CHECK_VALUE(loop);
    if (loop) {
        CHECK_VALUE(loop->run_until_complete(root(*loop)));
        CHECK_VALUE(loop->outstanding() == 0);
    }
    return test::summary();
}
