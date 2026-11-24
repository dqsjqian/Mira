#include "mira/core/task_scope.hpp"
#if defined(MIRA_TEST_H2)
#include "mira/client/http2.hpp"
#else
#include "mira/client/http3.hpp"
#endif

#include <array>
#include <atomic>
#include <coroutine>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <map>
#include <source_location>
#include <string_view>
#include <vector>

using namespace Mira;
using namespace std::chrono_literals;
namespace {
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class T> T require(Result<T> result, std::source_location where = std::source_location::current()) {
    if (!result) throw std::runtime_error(result.error().message() + " at " + std::to_string(where.line()));
    return std::move(*result);
}
void require(Result<void> result) { if (!result) throw std::runtime_error(result.error().message()); }
http::Headers headers(std::string path = "/echo") {
    return {{":method", "POST"}, {":scheme", "https"}, {":path", std::move(path)}};
}
struct Stats { unsigned accepted = 0, requests = 0; };
#if defined(MIRA_TEST_H2)
using Client = client::Http2Client;
using Listener = transport::tcp::Listener;
Result<Listener> bind(EventLoop& loop) { return Listener::bind(loop, transport::Endpoint::loopback(0)); }
std::uint16_t port(const Listener& listener) { return listener.local_endpoint().port(); }
auto factory(const char* ca) { return require(client::Http2Factory::create({.ca_file = ca})); }
Task<void> serve(EventLoop& loop, Listener& listener, const char* cert, const char* key,
                  Stats& stats, std::stop_token stop, bool alpn = true) {
    auto accepted = co_await listener.accept({.stop = stop});
    if (!accepted) co_return;
    ++stats.accepted;
    auto context = require(tls::Context::server(cert, key, alpn ? "h2" : ""));
    auto tls = require(tls::Stream<transport::tcp::Socket>::create(loop, *accepted, context));
    auto ready = co_await tls.handshake({.stop = stop, .deadline = Clock::now() + 5s});
    if (!ready || !alpn) co_return;
    auto engine = require(http2::Session::create(http2::Role::server));
    http2::SessionDriver driver{loop, tls, engine};
    std::map<std::int32_t, std::vector<std::byte>> bodies;
    std::map<std::int32_t, bool> replied;
    std::exception_ptr exception;
    try {
        while (!stop.stop_requested()) {
            bool pending = false;
            for (const auto id : engine.streams()) {
                const auto* stream = engine.stream(id);
                if (stream->error || replied[id]) continue;
                bool wait = false;
                for (const auto& field : stream->headers) if (field.name == ":path" && field.value == "/wait") wait = true;
                if (wait) continue;
                auto chunk = require(engine.take_body(id));
                auto& body = bodies[id];
                body.insert(body.end(), chunk.begin(), chunk.end());
                pending |= !chunk.empty();
                if (stream->remote_end) {
                    require(engine.respond(id, {{":status", "200"}}, body));
                    ++stats.requests;
                    replied[id] = true;
                    pending = true;
                }
            }
            if (pending) driver.notify();
            if (auto progress = co_await driver.progress({.stop = stop}); !progress) break;
        }
    } catch (...) { exception = std::current_exception(); }
    co_await driver.join();
    if (exception) std::rethrow_exception(exception);
}
#else
using Client = client::Http3Client;
using Listener = transport::udp::Socket;
Result<Listener> bind(EventLoop& loop) { return Listener::bind(loop, transport::Endpoint::loopback(0)); }
std::uint16_t port(const Listener& listener) { return require(listener.local_endpoint()).port(); }
auto factory(const char* ca) { return client::Http3Factory{{.ca_file = ca}}; }
Task<void> serve(EventLoop& loop, Listener& socket, const char* cert, const char* key,
                  Stats& stats, std::stop_token stop, bool = true) {
    std::array<std::byte, 65536> bytes{};
    auto initial = co_await socket.receive_from(bytes, {.stop = stop});
    if (!initial) co_return;
    quic::Options options;
    options.local = require(socket.local_endpoint()); options.remote = initial->peer;
    options.certificate_file = cert; options.private_key_file = key;
    auto transport = quic::Engine::accept(options, std::span<const std::byte>(bytes).first(initial->size), quic::detail::now_ns());
    if (!transport) co_return;
    ++stats.accepted;
    auto engine = require(http3::Engine::create(std::move(*transport), true));
    http3::SessionDriver driver{loop, socket, engine, initial->peer};
    std::map<std::int64_t, std::vector<std::byte>> bodies;
    std::map<std::int64_t, bool> waits;
    std::exception_ptr exception;
    try {
        while (!stop.stop_requested()) {
            bool pending = false;
            for (auto& event : engine.take_events()) {
                if (event.kind == http3::Event::Kind::headers)
                    for (const auto& field : event.fields)
                        if (field.name == ":path" && field.value == "/wait") waits[event.stream_id] = true;
                if (event.kind == http3::Event::Kind::body) {
                    auto& body = bodies[event.stream_id];
                    body.insert(body.end(), event.data.begin(), event.data.end());
                    require(engine.consume(event.stream_id, event.data.size()));
                    pending = true;
                }
                if (event.kind == http3::Event::Kind::end && !waits[event.stream_id]) {
                    require(engine.respond(event.stream_id, {{":status", "200"}}, bodies[event.stream_id]));
                    ++stats.requests;
                    pending = true;
                }
            }
            if (pending) driver.notify();
            if (auto progress = co_await driver.progress({.stop = stop}); !progress) break;
        }
    } catch (...) { exception = std::current_exception(); }
    co_await driver.join();
    if (exception) std::rethrow_exception(exception);
}
#endif
transport::Resolver::Backend backend(std::atomic<unsigned>& resolutions) {
    return [&resolutions](const transport::ResolveQuery& query, std::size_t) -> Result<transport::Resolver::Endpoints> {
        ++resolutions;
        return transport::Resolver::Endpoints{transport::Endpoint::loopback(static_cast<std::uint16_t>(std::stoul(query.service)))};
    };
}
Task<void> query(Client& client, std::uint16_t remote, unsigned& done, std::byte value) {
    const std::vector<std::byte> data(128 * 1024, value);
    auto result = require(co_await client.request("localhost", remote, headers(), data, {.deadline = Clock::now() + 10s}));
    check(result.body == data, "owned multiplexed responses cross-contaminated or over-window data missing");
    ++done;
}
Task<void> cancelled_query(Client& client, std::uint16_t remote, std::stop_token stop, Error& error) {
    auto result = co_await client.request("localhost", remote, headers("/wait"), {},
                                         {.stop = stop, .deadline = Clock::now() + 10s});
    check(!result, "cancelled request must not succeed"); error = result.error();
}
Task<void> run(EventLoop& loop, const char* cert, const char* key) {
    auto listener = require(bind(loop));
    const auto remote = port(listener);
    std::atomic<unsigned> resolutions{0};
    client::MultiplexOptions options; options.max_origins = 1; options.max_active = 3;
    auto client = require(Client::create(loop, factory(cert), options, {}, backend(resolutions)));
    std::stop_source service_stop, request_stop;
    Stats stats;
    TaskScope service, requests;
    service.spawn(serve(loop, listener, cert, key, stats, service_stop.get_token()));
    Error cancelled;
    unsigned done = 0;
    requests.spawn(cancelled_query(client, remote, request_stop.get_token(), cancelled));
    requests.spawn(query(client, remote, done, std::byte{1}));
    requests.spawn(query(client, remote, done, std::byte{2}));
    std::exception_ptr exception;
    try {
        check(client.active() == 3 && client.origins() == 1, "wrong origin/active quotas while connecting");
        auto full = co_await client.request("localhost", remote, headers());
        check(!full && full.error() == Errc::would_block, "max_active did not reject");
        require(co_await loop.sleep_for(2ms));
        request_stop.request_stop();
    } catch (...) { exception = std::current_exception(); request_stop.request_stop(); }
    try { co_await requests.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
    if (!exception) {
        try {
            check(cancelled == Errc::cancelled && done == 2, "single-request cancellation contaminated other streams");
            check(stats.accepted == 1 && resolutions == 1, "concurrent same-origin requests dialed twice");
            auto full = co_await client.request("127.0.0.1", remote, headers());
            check(!full && full.error() == Errc::would_block, "max_origins did not reject the second origin");
            auto mismatch = headers(); mismatch.insert(mismatch.begin() + 2, {":authority", "evil.invalid"});
            auto rejected = co_await client.request("localhost", remote, mismatch);
            check(!rejected && rejected.error() == Errc::invalid_argument, "authority mismatch with target was not rejected");
            co_await query(client, remote, done, std::byte{3});
            check(stats.accepted == 1 && resolutions == 1, "established connection was not reused");
        } catch (...) { exception = std::current_exception(); }
    }
    TaskScope closing;
    Error closed;
    if (!exception) closing.spawn(cancelled_query(client, remote, {}, closed));
    try { co_await client.close(); } catch (...) { if (!exception) exception = std::current_exception(); }
    try { co_await closing.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
    service_stop.request_stop();
    try { co_await service.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
    check(client.origins() == 0 && client.active() == 0, "close did not drain owned objects");
    if (exception) std::rethrow_exception(exception);
    check(closed == Errc::cancelled, "close did not cancel pending requests");
}
Task<void> rejected(EventLoop& loop, const char* cert, const char* key, const char* other, bool alpn) {
    auto listener = require(bind(loop));
    std::atomic<unsigned> resolutions{0};
    auto client = require(Client::create(loop, factory(alpn ? other : cert), {}, {}, backend(resolutions)));
    Stats stats;
    std::stop_source stop;
    TaskScope service;
    service.spawn(serve(loop, listener, cert, key, stats, stop.get_token(), alpn));
    auto response = co_await client.request("localhost", port(listener), headers(), {}, {.deadline = Clock::now() + 3s});
    const bool rolled_back = client.origins() == 0 && client.active() == 0;
    co_await client.close();
    stop.request_stop();
    co_await service.join();
    check(!response && response.error() != Errc::timed_out, "untrusted certificate or missing ALPN did not fail immediately");
    check(rolled_back && client.origins() == 0, "failed establishment did not roll back the origin before close");
}
Task<void> close_dial(EventLoop& loop, const char* cert) {
    auto listener = require(bind(loop));
    std::atomic<unsigned> resolutions{0};
    auto client = require(Client::create(loop, factory(cert), {}, {}, backend(resolutions)));
    TaskScope request;
    Error error;
    request.spawn(cancelled_query(client, port(listener), {}, error));
    co_await client.close();
    co_await request.join();
    check(error == Errc::cancelled && client.origins() == 0 && client.active() == 0, "close did not drain in-flight dials");
}
struct FakeConnection {
    unsigned& destroyed;
    bool joined = false;
    explicit FakeConnection(unsigned& count) : destroyed(count) {}
    ~FakeConnection() { if (!joined) std::terminate(); ++destroyed; }
    Task<Result<int>> request(http::Headers, std::vector<std::byte>, OperationOptions) {
        throw std::runtime_error("request exception");
        co_return 0;
    }
    void stop() noexcept {}
    Task<void> join() { joined = true; co_return; }
};
struct FakeFactory {
    using Connection = FakeConnection;
    using Response = int;
    unsigned& connects;
    unsigned& destroyed;
    Task<Result<std::unique_ptr<Connection>>> connect(EventLoop& loop, transport::Resolver&,
        const std::string&, std::uint16_t, std::size_t, OperationOptions) {
        co_await loop.yield();
        if (++connects == 1) throw std::runtime_error("connect exception");
        co_return std::make_unique<Connection>(destroyed);
    }
};
Task<void> exceptions(EventLoop& loop) {
    unsigned connects = 0, destroyed = 0;
    auto pool = require(client::MultiplexClient<FakeFactory>::create(loop, {connects, destroyed}));
    bool dial_threw = false, request_threw = false;
    try { static_cast<void>(co_await pool.request("localhost", 443, headers())); }
    catch (const std::runtime_error&) { dial_threw = true; }
    const bool rollback = pool.origins() == 0 && pool.active() == 0;
    try { static_cast<void>(co_await pool.request("localhost", 443, headers())); }
    catch (const std::runtime_error&) { request_threw = true; }
    // This factory has no usable() hook: the pool itself knows it stopped
    // the previous connection and must not send another request to it.
    try { static_cast<void>(co_await pool.request("localhost", 443, headers())); }
    catch (const std::runtime_error&) {}
    co_await pool.close();
    check(dial_threw && request_threw && rollback && connects == 3 && destroyed == 2,
          "a connection stopped after a request exception was reused or not joined");
    Task<Result<int>> late;
    {
        auto idle = require(client::MultiplexClient<FakeFactory>::create(loop, {connects, destroyed}));
        late = idle.request("localhost", 443, headers());
    }
    auto cancelled = co_await std::move(late);
    check(!cancelled && cancelled.error() == Errc::cancelled, "unstarted request dialed after pool destruction");
}
struct RetiringConnection {
    unsigned& destroyed;
    bool healthy = true;  // cleared to model a peer GOAWAY
    bool stopped = false;
    bool joined = false;
    bool hold = false;
    std::coroutine_handle<> pending{};
    explicit RetiringConnection(unsigned& count) : destroyed(count) {}
    ~RetiringConnection() { if (!joined) std::terminate(); ++destroyed; }
    struct Hold {
        RetiringConnection& self;
        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> caller) noexcept { self.pending = caller; }
        void await_resume() const noexcept {}
    };
    void release() { if (auto caller = std::exchange(pending, {})) caller.resume(); }
    Task<Result<int>> request(http::Headers, std::vector<std::byte>, OperationOptions) {
        if (std::exchange(hold, false)) co_await Hold{*this};
        if (stopped) co_return fail(Errc::cancelled);
        co_return 7;
    }
    void stop() noexcept { stopped = true; release(); }
    Task<void> join() { joined = true; co_return; }
    [[nodiscard]] bool usable() const noexcept { return healthy && !stopped; }
};
struct RetiringFactory {
    using Connection = RetiringConnection;
    using Response = int;
    unsigned& connects;
    unsigned& destroyed;
    std::vector<Connection*>& made;
    Task<Result<std::unique_ptr<Connection>>> connect(EventLoop& loop, transport::Resolver&,
        const std::string&, std::uint16_t, std::size_t, OperationOptions) {
        co_await loop.yield();
        ++connects;
        auto connection = std::make_unique<Connection>(destroyed);
        made.push_back(connection.get());
        co_return connection;
    }
};
Task<void> retirement(EventLoop& loop) {
    unsigned connects = 0, destroyed = 0;
    std::vector<RetiringConnection*> made;
    client::MultiplexOptions options;
    options.max_origins = 1;
    auto pool = require(client::MultiplexClient<RetiringFactory>::create(loop, {connects, destroyed, made}, options));
    check(require(co_await pool.request("localhost", 443, headers())) == 7, "first request failed");
    check(require(co_await pool.request("localhost", 443, headers())) == 7 && connects == 1,
          "a usable connection was not reused");
    auto* first = made.back();
    first->hold = true;
    Result<int> outstanding = fail(Errc::internal);
    TaskScope requests;
    auto accepted = [&]() -> Task<void> { outstanding = co_await pool.request("localhost", 443, headers()); };
    requests.spawn(accepted());
    first->healthy = false;  // peer GOAWAY still permits the accepted stream to finish
    const auto next = co_await pool.request("localhost", 443, headers());
    const bool drained_naturally = requests.pending() == 1 && destroyed == 0;
    if (requests.pending() != 0) first->release();
    co_await requests.join();
    const bool replaced = next && *next == 7 && connects == 2 && pool.origins() == 1;
    made.back()->healthy = false;
    const auto another = co_await pool.request("other.test", 443, headers());
    const bool reused_quota = another && *another == 7 && connects == 3 && pool.origins() == 1;
    co_await pool.close();
    check(drained_naturally && outstanding && *outstanding == 7, "retiring a session cancelled an accepted stream");
    check(replaced, "an unusable connection was not replaced within max_origins");
    check(reused_quota, "a dead entry blocked a different origin at max_origins");
    check(destroyed == 3 && pool.origins() == 0, "close did not join retired connections");
}
Task<void> shutdown_draining_session(EventLoop& loop) {
    unsigned connects = 0, destroyed = 0;
    std::vector<RetiringConnection*> made;
    auto pool = require(client::MultiplexClient<RetiringFactory>::create(loop, {connects, destroyed, made}));
    require(co_await pool.request("localhost", 443, headers()));
    auto* old = made.back();
    old->hold = true;
    TaskScope requests;
    Result<int> result = fail(Errc::internal);
    auto request = [&]() -> Task<void> { result = co_await pool.request("localhost", 443, headers()); };
    requests.spawn(request());
    old->healthy = false;
    const auto replacement = co_await pool.request("localhost", 443, headers());
    pool.stop();
    const bool stopped = requests.pending() == 0;
    if (!stopped) old->release();
    co_await requests.join();
    co_await pool.join();
    check(replacement && stopped && !result && result.error() == Errc::cancelled && destroyed == 2,
          "explicit shutdown failed to stop and join a retired session");
}
Task<void> abandoned(EventLoop& loop, const char* cert) {
    auto listener = require(bind(loop));
    std::atomic<unsigned> resolutions{0};
    auto pool = std::make_unique<Client>(require(Client::create(loop, factory(cert), {}, {}, backend(resolutions))));
    TaskScope pending;
    Error error;
    pending.spawn(cancelled_query(*pool, port(listener), {}, error));
    require(co_await loop.sleep_for(2ms));
    check(pool->active() == 1, "death contract lacked a real pending request");
    pool.reset();
    co_await pending.join();
}
Task<void> all(EventLoop& loop, const char* cert, const char* key, const char* other) {
    co_await run(loop, cert, key);
    co_await rejected(loop, cert, key, other, true);
#if defined(MIRA_TEST_H2)
    co_await rejected(loop, cert, key, other, false);
#endif
    co_await close_dial(loop, cert);
    co_await exceptions(loop);
    co_await retirement(loop);
    co_await shutdown_draining_session(loop);
}
} // namespace
int main(int argc, char** argv) {
    if (argc != 4 && argc != 5) return 2;
    try {
        auto loop = require(EventLoop::create());
        if (argc == 5 && std::string_view(argv[4]) == "--death") {
            std::set_terminate([] { std::fputs("pending pool destruction rejected\n", stderr); std::_Exit(73); });
            require(loop.run_until_complete(abandoned(loop, argv[1])));
            return 0;
        }
        require(loop.run_until_complete(all(loop, argv[1], argv[2], argv[3])));
        check(loop.outstanding() == 0, "owned pool left I/O or callbacks outstanding");
        std::cout << "owning multiplex client passed\n";
    } catch (const std::exception& ex) { std::cerr << ex.what() << '\n'; return 1; }
}
