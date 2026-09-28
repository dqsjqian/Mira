#include "check.hpp"
#include "mira/client/http.hpp"
#include "mira/core/task_scope.hpp"

#include <array>
#include <charconv>
#include <string>

#define CHECK_VALUE(expr) CHECK(static_cast<bool>(expr))
using namespace Mira;
using namespace Mira::client;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {
std::span<const std::byte> bytes(std::string_view value) {
    return std::as_bytes(std::span{value.data(), value.size()});
}
http::Request request(std::string path = "/") {
    http::Request result;
    result.target = std::move(path);
    return result;
}
struct Server {
    EventLoop& loop;
    tcp::Listener listener;
    std::stop_source stop;
    std::size_t accepted = 0;
    std::size_t requests = 0;
    Task<void> serve(tcp::Socket socket, std::size_t id) {
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
            ++requests;
            const auto end = pending.find("\r\n\r\n") + 4;
            const auto head = pending.substr(0, end);
            pending.erase(0, end);
            if (head.starts_with("GET /bad ")) {
                static_cast<void>(co_await write_all(socket,
                    bytes("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"), io));
                co_return;
            }
            if (head.starts_with("GET /stall ")) {
                static_cast<void>(co_await write_all(socket,
                    bytes("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n"), io));
                static_cast<void>(co_await loop.sleep_for(10s, io));
                co_return;
            }
            const auto wire = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Id: " +
                              std::to_string(id) + "\r\n\r\nok";
            const auto sent = co_await write_all(socket, bytes(wire), io);
            if (!sent || head.starts_with("GET /stale ")) co_return;
        }
    }
    Task<void> run() {
        TaskScope children;
        for (;;) {
            auto socket = co_await listener.accept({.stop = stop.get_token()});
            if (!socket) break;
            children.spawn(serve(std::move(*socket), ++accepted));
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
Task<void> exercise(EventLoop& loop, Server& server) {
    Options options;
    options.max_connections_per_origin = 1;
    options.max_origins = 2;
    options.idle_timeout = 40ms;
    options.http.request_timeout = 5s;
    auto backend = [](const ResolveQuery& query, std::size_t) -> Result<Resolver::Endpoints> {
        unsigned port = 0;
        const auto parsed = std::from_chars(query.service.data(), query.service.data() + query.service.size(), port);
        if (parsed.ec != std::errc{} || port > 65535) return fail(Errc::invalid_argument);
        return Resolver::Endpoints{Endpoint::loopback(static_cast<std::uint16_t>(port))};
    };
    ResourceBudget admission{2};
    ResourceBudget buffers{2 * options.http.max_buffer_size};
    options.admission_budget = admission;
    options.http.input_budget = buffers;
    auto client = HttpClient::create(loop, {}, options, {}, backend);
    CHECK_VALUE(client);
    if (!client) co_return;
    const auto port = server.listener.local_endpoint().port();
    {
        auto held = admission.try_acquire(2).value();
        const auto refused = co_await client->acquire("a.test", port);
        CHECK_VALUE(!refused && refused.error() == Errc::would_block);
        CHECK_VALUE(admission.used() == 2 && server.accepted == 0);
    }
    auto lease = co_await client->acquire("A.TEST", port);
    if (!lease) std::fprintf(stderr, "acquire: %s / %d / %s\n", lease.error().category().name(),
                             lease.error().value(), lease.error().message().c_str());
    CHECK_VALUE(lease);
    if (!lease) co_return;
    auto full = co_await client->acquire("a.test", port);
    CHECK_VALUE(!full && full.error() == Errc::would_block);
    auto wrong_host = request();
    wrong_host.headers.append("Host", "wrong.test");
    CHECK_VALUE(!(co_await lease->start(wrong_host)));
    CHECK_VALUE(server.requests == 0);
    auto pending = lease->start(request());
    auto moved = std::move(*lease);
    CHECK_VALUE(co_await std::move(pending));
    CHECK_VALUE(!moved.recycle());
    CHECK_VALUE((co_await drain(moved)) == "ok");
    const auto first = moved.response();
    CHECK_VALUE(first);
    const auto first_id = std::string{*first->headers.get("X-Id")};
    {
        auto unconsumed = moved.start(request());
        CHECK_VALUE(!moved.recycle());
    }
    CHECK_VALUE(moved.recycle());
    CHECK_VALUE(client->idle() == 1);
    lease = co_await client->acquire("a.test", port);
    CHECK_VALUE(lease);
    CHECK_VALUE(co_await lease->start(request()));
    CHECK_VALUE((co_await drain(*lease)) == "ok");
    CHECK_VALUE(lease->response()->headers.get("X-Id") == first_id);
    CHECK_VALUE(lease->recycle());
    const auto accepted_first = server.accepted;
    {
        auto held = co_await client->acquire("a.test", port);
        CHECK_VALUE(held);
        auto other = co_await client->acquire("b.test", port);
        CHECK_VALUE(other);
        CHECK_VALUE(co_await other->start(request()));
        CHECK_VALUE((co_await drain(*other)) == "ok");
        CHECK_VALUE(other->response()->headers.get("X-Id") != first_id);
        auto capped = co_await client->acquire("c.test", port);
        CHECK_VALUE(!capped && capped.error() == Errc::would_block);
        CHECK_VALUE(held->recycle());
    }
    CHECK_VALUE(server.accepted == accepted_first + 1);
    CHECK_VALUE(co_await loop.sleep_for(60ms));
    lease = co_await client->acquire("a.test", port);
    CHECK_VALUE(lease);
    CHECK_VALUE(co_await lease->start(request()));
    CHECK_VALUE((co_await drain(*lease)) == "ok");
    CHECK_VALUE(lease->response()->headers.get("X-Id") != first_id);
    CHECK_VALUE(lease->recycle());
    {
        auto bad = co_await client->acquire("a.test", port);
        CHECK_VALUE(bad);
        CHECK_VALUE(co_await bad->start(request("/bad")));
        Error error;
        for (;;) {
            auto part = co_await bad->read_body();
            if (!part) { error = part.error(); break; }
            if (part->empty()) break;
        }
        CHECK_VALUE(error == Errc::eof);
        CHECK_VALUE(!bad->recycle());
    }
    {
        auto abandoned = co_await client->acquire("a.test", port);
        CHECK_VALUE(abandoned);
        CHECK_VALUE(co_await abandoned->start(request()));
        CHECK_VALUE(!abandoned->recycle());
    }
    CHECK_VALUE(client->active_and_idle() == 0);
    {
        std::stop_source stop;
        auto cancelled = co_await client->acquire("a.test", port, {.stop = stop.get_token()});
        CHECK_VALUE(cancelled);
        CHECK_VALUE(co_await cancelled->start(request("/stall")));
        std::optional<HttpClient::SessionType> moved_active;
        auto cancel = [&]() -> Task<void> {
            CHECK_VALUE(co_await loop.sleep_for(5ms));
            moved_active.emplace(std::move(*cancelled));
            CHECK_VALUE(!moved_active->recycle());
            stop.request_stop();
        };
        TaskScope tasks;
        tasks.spawn(cancel());
        auto body = co_await cancelled->read_body();
        CHECK_VALUE(!body && body.error() == Errc::cancelled);
        co_await tasks.join();
        CHECK_VALUE(!moved_active->recycle());
    }
    {
        std::stop_source stop;
        stop.request_stop();
        auto cancelled = co_await client->acquire("a.test", port, {.stop = stop.get_token()});
        CHECK_VALUE(!cancelled && cancelled.error() == Errc::cancelled);
        auto expired = co_await client->acquire("a.test", port, {.deadline = Clock::now() - 1s});
        CHECK_VALUE(!expired && expired.error() == Errc::timed_out);
    }
    {
        auto stale = co_await client->acquire("a.test", port);
        CHECK_VALUE(stale);
        CHECK_VALUE(co_await stale->start(request("/stale")));
        CHECK_VALUE((co_await drain(*stale)) == "ok");
        CHECK_VALUE(stale->recycle());
        CHECK_VALUE(co_await loop.sleep_for(5ms));
        const auto before = server.accepted;
        stale = co_await client->acquire("a.test", port);
        CHECK_VALUE(stale);
        CHECK_VALUE(!(co_await stale->start(request())));
        CHECK_VALUE(server.accepted == before);
    }
    {
        auto retained = co_await client->acquire("a.test", port);
        CHECK_VALUE(retained);
        auto lazy = retained->start(request());
        retained->discard();
        CHECK_VALUE(co_await std::move(lazy));
        CHECK_VALUE(client->active_and_idle() == 0);
    }
    {
        auto retained = co_await client->acquire("a.test", port);
        CHECK_VALUE(retained);
        CHECK_VALUE(co_await retained->start(request()));
        auto unsafe = retained->read_body();
        retained->discard();
        const auto part = co_await std::move(unsafe);
        CHECK_VALUE(!part && part.error() == Errc::invalid_argument);
        CHECK_VALUE(client->active_and_idle() == 0);
    }
    {
        std::stop_source stop;
        auto detached = co_await client->acquire("a.test", port, {.stop = stop.get_token()});
        CHECK_VALUE(detached);
        CHECK_VALUE(co_await detached->start(request("/stall")));
        auto release = [&]() -> Task<void> {
            CHECK_VALUE(co_await loop.sleep_for(5ms));
            detached->discard();
            stop.request_stop();
        };
        TaskScope tasks;
        tasks.spawn(release());
        const auto piece = co_await detached->read_body();
        CHECK_VALUE(!piece && piece.error() == Errc::invalid_argument);
        co_await tasks.join();
        CHECK_VALUE(client->active_and_idle() == 0);
    }
    {
        auto timed_options = options;
        timed_options.http.request_timeout = 30ms;
        auto timed = HttpClient::create(loop, {}, timed_options, {}, backend);
        CHECK_VALUE(timed);
        auto acquired = co_await timed->acquire("a.test", port);
        CHECK_VALUE(acquired);
        CHECK_VALUE(co_await loop.sleep_for(40ms));
        const auto result = co_await acquired->start(request());
        CHECK_VALUE(!result && result.error() == Errc::timed_out);
    }
    {
        auto isolated_options = options;
        isolated_options.max_origins = 1;
        auto isolated = HttpClient::create(loop, {}, isolated_options, {}, backend);
        CHECK_VALUE(isolated);
        auto first_origin = co_await isolated->acquire("one.test", port);
        CHECK_VALUE(first_origin);
        CHECK_VALUE(first_origin->recycle());
        auto replacement = co_await isolated->acquire("two.test", port);
        CHECK_VALUE(replacement);
        CHECK_VALUE(isolated->active_and_idle() == 1);
    }
    {
        auto retained = co_await client->acquire("a.test", port);
        CHECK_VALUE(retained);
        client->close();
        CHECK_VALUE(co_await retained->start(request()));
        CHECK_VALUE((co_await drain(*retained)) == "ok");
        CHECK_VALUE(retained->recycle());
        CHECK_VALUE(client->active_and_idle() == 0);
        CHECK_VALUE(admission.used() == 0 && buffers.used() == 0);
        auto stopped = co_await client->acquire("a.test", port);
        CHECK_VALUE(!stopped && stopped.error() == Errc::cancelled);
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
}
int main() {
    auto loop = EventLoop::create();
    CHECK_VALUE(loop);
    if (loop) {
        CHECK_VALUE(loop->run_until_complete(root(*loop)));
        CHECK_VALUE(loop->outstanding() == 0);
    }
    return test::summary();
}
