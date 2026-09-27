// TCP transport tests — real sockets, real loopback connections.
//
// This file is also what finally exercises the Windows backend properly. The
// event-loop tests use socketpair(), which Winsock does not have, so every
// socket case there was skipped on Windows and IOCP's read/write path was
// never actually run. A loopback TCP connection works on all three backends,
// so from here on "Windows is supported" is a claim with evidence behind it.
//
// Nothing here branches on the platform. If a test needed a `#if`, that would
// mean the public API leaked a platform detail.

#include "check.hpp"
#include "mira/core/stream.hpp"
#include "mira/transport/tcp.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

/// tcp::Socket must satisfy the stream concepts, or protocols cannot take it.
static_assert(AsyncReadStream<tcp::Socket>);
static_assert(AsyncWriteStream<tcp::Socket>);
static_assert(AsyncStream<tcp::Socket>);

// ── deterministic driver ─────────────────────────────────────────────────────

/// Fire-and-forget coroutine that owns its frame until the body returns.
struct DetachedTask {
    struct promise_type {
        DetachedTask get_return_object() noexcept { return DetachedTask{}; }
        std::suspend_never initial_suspend() noexcept { return {}; }

        struct FinalAwaiter {
            [[nodiscard]] bool await_ready() const noexcept { return false; }
            void await_suspend(std::coroutine_handle<promise_type> self) const noexcept {
                self.destroy();
            }
            void await_resume() const noexcept {}
        };

        FinalAwaiter final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::terminate(); }
    };
};

/// Pump the loop until `done` flips or the budget runs out.
///
/// Bounded so a hung expectation fails the test instead of hanging CI.
bool pump_until(EventLoop& loop, const std::atomic<int>& done, int target, int budget = 400) {
    for (int i = 0; i < budget && done.load(std::memory_order_acquire) < target; ++i) {
        if (!loop.run_once(25ms)) {
            return false;
        }
    }
    return done.load(std::memory_order_acquire) >= target;
}

// ── endpoint ─────────────────────────────────────────────────────────────────

void test_endpoint() {
    test::section("endpoint");

    const Result<Endpoint> v4 = Endpoint::parse("127.0.0.1", 8080);
    CHECK(v4.has_value());
    CHECK(v4->family() == Family::ipv4);
    CHECK(v4->port() == 8080);
    CHECK(v4->address() == "127.0.0.1");
    CHECK(v4->to_string() == "127.0.0.1:8080");

    const Result<Endpoint> v6 = Endpoint::parse("::1", 443);
    CHECK(v6.has_value());
    CHECK(v6->family() == Family::ipv6);
    CHECK(v6->port() == 443);
    // Bracketed so the result can be parsed again without ambiguity.
    CHECK(v6->to_string() == "[::1]:443");

    CHECK(Endpoint::loopback(1234).address() == "127.0.0.1");
    CHECK(Endpoint::any(1234).address() == "0.0.0.0");
    CHECK(Endpoint::loopback(1234, Family::ipv6).address() == "::1");

    // Host names are refused: DNS blocks, and hiding it inside a constructor
    // would make every address construction a potential stall.
    CHECK(!Endpoint::parse("localhost", 80).has_value());
    CHECK(!Endpoint::parse("example.com", 80).has_value());
    CHECK(!Endpoint::parse("", 80).has_value());
    CHECK(!Endpoint::parse("999.1.1.1", 80).has_value());
    CHECK(!Endpoint::parse("127.0.0.1 ", 80).has_value());
    CHECK(!Endpoint::parse(std::string_view{"127.0.0.1\0bad", 13}, 80));
    CHECK(!Endpoint::parse(std::string_view{"::1\0bad", 7}, 80));
    CHECK(!Endpoint::parse("fe80::1%", 80));
    CHECK(!Endpoint::parse("fe80::1%4294967296", 80));
    CHECK(!Endpoint::parse("fe80::1%invalid%scope", 80));
    const auto scoped = Endpoint::parse("fe80::1%42", 443);
    CHECK(scoped.has_value());
    if (scoped) {
        CHECK(scoped->address() == "fe80::1%42");
        CHECK(scoped->to_string() == "[fe80::1%42]:443");
        const auto scoped_restored = Endpoint::from_bytes(scoped->address_bytes());
        CHECK(scoped_restored && scoped_restored->address() == "fe80::1%42");
    }

    // Round-trip through the raw bytes the OS would hand back.
    const Result<Endpoint> restored = Endpoint::from_bytes(v4->address_bytes());
    CHECK(restored.has_value());
    CHECK(restored->to_string() == "127.0.0.1:8080");
}

// ── bind semantics: the reason this project exists ───────────────────────────

void test_exclusive_bind_is_uniform() {
    test::section("exclusive bind");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    // Port 0 lets the OS pick, and local_endpoint() reports what it picked —
    // no guessing at a free port, so this test cannot flake.
    Result<tcp::Listener> first = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(first.has_value());
    const std::uint16_t port = first->local_endpoint().port();
    CHECK(port != 0);

    // The whole point: a second bind to a live port must fail on *every*
    // platform. On Windows, the default SO_REUSEADDR behaviour would let this
    // succeed and silently split incoming connections between two servers.
    Result<tcp::Listener> second = tcp::Listener::bind(loop, Endpoint::loopback(port));
    CHECK(!second.has_value());
    if (!second.has_value()) {
        CHECK(second.error() == std::errc::address_in_use);
    }

    // Releasing the port makes it bindable again.
    first->close();
    Result<tcp::Listener> rebound = tcp::Listener::bind(loop, Endpoint::loopback(port));
    CHECK(rebound.has_value());
}

// ── round trip ───────────────────────────────────────────────────────────────

void test_accept_connect_round_trip() {
    test::section("accept / connect round trip");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    Result<tcp::Listener> listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    const Endpoint target = listener->local_endpoint();

    std::atomic<int> done{0};
    std::string server_received;
    std::string client_received;
    Error server_error{};
    Error client_error{};

    // Server: accept one connection, echo the request back uppercased.
    struct Server {
        static DetachedTask run(tcp::Listener& listening,
                                std::string& sink,
                                Error& failure,
                                std::atomic<int>& counter) {
            Result<tcp::Socket> accepted = co_await listening.accept();
            if (!accepted) {
                failure = accepted.error();
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }

            tcp::Socket peer = std::move(*accepted);

            // The peer address is real, not a placeholder.
            const Result<Endpoint> remote = peer.peer_endpoint();
            if (remote) {
                sink.append("[from ").append(remote->address()).append("] ");
            }

            std::array<std::byte, 128> scratch{};
            Result<std::size_t> read = co_await peer.read_some(scratch);
            if (!read) {
                failure = read.error();
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }
            sink.append(reinterpret_cast<const char*>(scratch.data()), *read);

            std::string reply{"PONG"};
            const Result<void> written = co_await write_all(
                peer,
                std::span<const std::byte>{reinterpret_cast<const std::byte*>(reply.data()),
                                           reply.size()});
            if (!written) {
                failure = written.error();
            }

            // Half-close so the client sees a clean end without losing the
            // data still in flight.
            static_cast<void>(peer.shutdown_send());
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    // Client: connect, send, read the reply, then read again to observe eof.
    struct Client {
        static DetachedTask run(EventLoop& target_loop,
                                Endpoint where,
                                std::string& sink,
                                Error& failure,
                                std::atomic<int>& counter) {
            Result<tcp::Socket> connected = co_await tcp::connect(target_loop, where);
            if (!connected) {
                failure = connected.error();
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }

            tcp::Socket socket = std::move(*connected);

            const Result<void> written = co_await write_all(socket, bytes_of("ping"));
            if (!written) {
                failure = written.error();
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }

            std::array<std::byte, 128> scratch{};
            Result<std::size_t> read = co_await socket.read_some(scratch);
            if (!read) {
                failure = read.error();
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }
            sink.append(reinterpret_cast<const char*>(scratch.data()), *read);

            // The server half-closed, so the next read must report eof rather
            // than a zero-length success.
            Result<std::size_t> after = co_await socket.read_some(scratch);
            if (!after && after.error() == Errc::eof) {
                sink.append("|eof");
            }

            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    Server::run(*listener, server_received, server_error, done);
    Client::run(loop, target, client_received, client_error, done);

    CHECK(pump_until(loop, done, 2));
    CHECK(!server_error);
    CHECK(!client_error);
    CHECK(server_received.find("ping") != std::string::npos);
    CHECK(server_received.find("[from 127.0.0.1]") != std::string::npos);
    CHECK(client_received == "PONG|eof");
}

void test_larger_transfer() {
    test::section("larger transfer");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    Result<tcp::Listener> listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    const Endpoint target = listener->local_endpoint();

    // Large enough to exceed the socket buffers, so write_all must loop and
    // the reader must handle short reads — the paths a small payload skips.
    const std::string payload(256 * 1024, 'x');

    std::atomic<int> done{0};
    std::size_t received_total = 0;
    Error failure{};

    struct Sink {
        static DetachedTask
        run(tcp::Listener& listening, std::size_t& total, Error& error, std::atomic<int>& counter) {
            Result<tcp::Socket> accepted = co_await listening.accept();
            if (!accepted) {
                error = accepted.error();
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }
            tcp::Socket peer = std::move(*accepted);

            std::array<std::byte, 8192> scratch{};
            for (;;) {
                Result<std::size_t> read = co_await peer.read_some(scratch);
                if (!read) {
                    if (read.error() != Errc::eof) {
                        error = read.error();
                    }
                    break;
                }
                total += *read;
            }
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    struct Source {
        static DetachedTask run(EventLoop& target_loop,
                                Endpoint where,
                                const std::string& data,
                                Error& error,
                                std::atomic<int>& counter) {
            Result<tcp::Socket> connected = co_await tcp::connect(target_loop, where);
            if (!connected) {
                error = connected.error();
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }
            tcp::Socket socket = std::move(*connected);

            const Result<void> written = co_await write_all(socket, bytes_of(data));
            if (!written) {
                error = written.error();
            }
            static_cast<void>(socket.shutdown_send());
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    Sink::run(*listener, received_total, failure, done);
    Source::run(loop, target, payload, failure, done);

    CHECK(pump_until(loop, done, 2, 4000));
    CHECK(!failure);
    CHECK(received_total == payload.size());
}

void test_connection_refused() {
    test::section("connection refused");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    // Bind then release, so the port is almost certainly unused.
    std::uint16_t dead_port = 0;
    {
        Result<tcp::Listener> temporary = tcp::Listener::bind(loop, Endpoint::loopback(0));
        CHECK(temporary.has_value());
        dead_port = temporary->local_endpoint().port();
    }

    std::atomic<int> done{0};
    Error failure{};
    bool succeeded = false;

    struct Attempt {
        static DetachedTask run(EventLoop& target_loop,
                                Endpoint where,
                                Error& error,
                                bool& ok,
                                std::atomic<int>& counter) {
            Result<tcp::Socket> connected = co_await tcp::connect(target_loop, where);
            if (connected) {
                ok = true;
            } else {
                error = connected.error();
            }
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    Attempt::run(loop, Endpoint::loopback(dead_port), failure, succeeded, done);
    CHECK(pump_until(loop, done, 1));

    // A refused connection must surface as an error. A writable socket alone
    // does not mean success — SO_ERROR has to be checked, and a backend that
    // skips it reports a phantom connection.
    CHECK(!succeeded);
    CHECK(failure == std::errc::connection_refused);
}

void test_socket_move_and_close() {
    test::section("socket ownership");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    Result<tcp::Listener> listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());

    // Moving a listener must not close the underlying socket.
    const std::uint16_t port = listener->local_endpoint().port();
    tcp::Listener moved = std::move(*listener);
    CHECK(moved.local_endpoint().port() == port);

    // Default-constructed sockets are inert rather than dangerous.
    tcp::Socket empty;
    CHECK(!empty.valid());
    CHECK(!static_cast<bool>(empty));
    CHECK(!empty.peer_endpoint().has_value());
    empty.close();  // must be safe

    // Double close is safe too.
    moved.close();
    moved.close();
}

void test_pending_accept_close(bool destroy_owner) {
    test::section(destroy_owner ? "pending accept close / destroy owner"
                                : "pending accept close / reentrant close");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    if (!created) {
        return;
    }
    EventLoop& loop = *created;
    Result<tcp::Listener> bound = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(bound.has_value());
    if (!bound) {
        return;
    }
    auto listener = std::make_unique<tcp::Listener>(std::move(*bound));
    std::atomic<int> done{0};
    Error failure{};

    struct Accept {
        static DetachedTask run(std::unique_ptr<tcp::Listener>& owner,
                                bool destroy,
                                Error& error,
                                std::atomic<int>& counter) {
            Result<tcp::Socket> accepted = co_await owner->accept();
            CHECK(!accepted.has_value());
            if (!accepted) {
                error = accepted.error();
            }
            // detach may synchronously resume the continuation; the outer
            // close must have already given up handle ownership.
            CHECK(owner->native_handle() == invalid_handle);
            owner->close();
            if (destroy) {
                owner.reset();
            } else {
                Result<tcp::Socket> again = co_await owner->accept();
                CHECK(!again.has_value());
                CHECK(!again && again.error() == Errc::invalid_argument);
            }
            counter.fetch_add(1, std::memory_order_release);
        }
    };

    Accept::run(listener, destroy_owner, failure, done);
    CHECK(done.load() == 0);
    CHECK(loop.outstanding() == 1);
    listener->close();
    const bool completed = pump_until(loop, done, 1);
    CHECK(completed);
    if (!completed) {
        std::terminate();
    }
    CHECK(failure == Errc::cancelled);
    CHECK(loop.outstanding() == 0);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(done.load() == 1);
    CHECK(destroy_owner ? !listener : listener->native_handle() == invalid_handle);
}

struct LoopbackPair {
    tcp::Socket server;
    tcp::Socket client;

    static DetachedTask
    accept(tcp::Listener& listener, tcp::Socket& socket, std::atomic<int>& done) {
        Result<tcp::Socket> accepted = co_await listener.accept();
        CHECK(accepted.has_value());
        if (accepted) {
            socket = std::move(*accepted);
        }
        done.fetch_add(1, std::memory_order_release);
    }

    static DetachedTask
    connect(EventLoop& loop, Endpoint endpoint, tcp::Socket& socket, std::atomic<int>& done) {
        Result<tcp::Socket> connected = co_await tcp::connect(loop, endpoint);
        CHECK(connected.has_value());
        if (connected) {
            socket = std::move(*connected);
        }
        done.fetch_add(1, std::memory_order_release);
    }

    bool open(EventLoop& loop) {
        Result<tcp::Listener> listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
        CHECK(listener.has_value());
        if (!listener) {
            return false;
        }
        std::atomic<int> done{0};
        accept(*listener, server, done);
        connect(loop, listener->local_endpoint(), client, done);
        const bool completed = pump_until(loop, done, 2);
        CHECK(completed);
        if (!completed) {
            // After a timeout, suspended tasks must not keep referencing
            // destroyed local state.
            std::terminate();
        }
        return server.valid() && client.valid();
    }
};

void test_pending_read_close(bool destroy_owner) {
    test::section(destroy_owner ? "pending read close / destroy owner"
                                : "pending read close / reentrant close");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    if (!created) {
        return;
    }
    EventLoop& loop = *created;
    LoopbackPair pair;
    if (!pair.open(loop)) {
        return;
    }
    auto socket = std::make_unique<tcp::Socket>(std::move(pair.server));
    std::atomic<int> done{0};
    Error failure{};

    struct Read {
        static DetachedTask run(std::unique_ptr<tcp::Socket>& owner,
                                bool destroy,
                                Error& error,
                                std::atomic<int>& counter) {
            std::array<std::byte, 32> buffer{};
            Result<std::size_t> read = co_await owner->read_some(buffer);
            CHECK(!read.has_value());
            if (!read) {
                error = read.error();
            }
            CHECK(!owner->valid());
            CHECK(owner->native_handle() == invalid_handle);
            owner->close();
            if (destroy) {
                // The continuation may destroy the object executing close; the
                // outer close must not read this afterwards.
                owner.reset();
            } else {
                Result<std::size_t> again = co_await owner->read_some(buffer);
                CHECK(!again && again.error() == Errc::invalid_argument);
                Result<std::size_t> written = co_await owner->write_some(bytes_of("closed"));
                CHECK(!written && written.error() == Errc::invalid_argument);
            }
            counter.fetch_add(1, std::memory_order_release);
        }
    };

    Read::run(socket, destroy_owner, failure, done);
    CHECK(done.load() == 0);
    CHECK(loop.outstanding() == 1);
    socket->close();
    const bool completed = pump_until(loop, done, 1);
    CHECK(completed);
    if (!completed) {
        std::terminate();
    }
    CHECK(failure == Errc::cancelled);
    CHECK(loop.outstanding() == 0);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(done.load() == 1);
    CHECK(destroy_owner ? !socket : !socket->valid());
}

void test_loop_destruction_pending_accept() {
    test::section("loop destruction / pending accept");

    std::atomic<int> done{0};
    Error failure{};
    struct Accept {
        static DetachedTask run(tcp::Listener listener, Error& error, std::atomic<int>& counter) {
            Result<tcp::Socket> accepted = co_await listener.accept();
            CHECK(!accepted.has_value());
            if (!accepted) {
                error = accepted.error();
            }
            listener.close();
            CHECK(listener.native_handle() == invalid_handle);
            counter.fetch_add(1, std::memory_order_release);
        }
    };

    {
        Result<EventLoop> created = EventLoop::create();
        CHECK(created.has_value());
        if (!created) {
            return;
        }
        Result<tcp::Listener> listener = tcp::Listener::bind(*created, Endpoint::loopback(0));
        CHECK(listener.has_value());
        if (!listener) {
            return;
        }
        Accept::run(std::move(*listener), failure, done);
        CHECK(done.load() == 0);
        CHECK(created->outstanding() == 1);
    }
    CHECK(done.load() == 1);
    CHECK(failure == Errc::cancelled);
}

void test_loop_destruction_pending_read() {
    test::section("loop destruction / pending read");

    std::atomic<int> done{0};
    Error failure{};
    struct Read {
        static DetachedTask
        run(tcp::Socket socket, tcp::Socket peer, Error& error, std::atomic<int>& counter) {
            std::array<std::byte, 32> buffer{};
            Result<std::size_t> read = co_await socket.read_some(buffer);
            CHECK(!read.has_value());
            if (!read) {
                error = read.error();
            }
            socket.close();
            peer.close();
            CHECK(!socket.valid());
            CHECK(!peer.valid());
            counter.fetch_add(1, std::memory_order_release);
        }
    };

    {
        Result<EventLoop> created = EventLoop::create();
        CHECK(created.has_value());
        if (!created) {
            return;
        }
        LoopbackPair pair;
        if (!pair.open(*created)) {
            return;
        }
        Read::run(std::move(pair.server), std::move(pair.client), failure, done);
        CHECK(done.load() == 0);
        CHECK(created->outstanding() == 1);
    }
    CHECK(done.load() == 1);
    CHECK(failure == Errc::cancelled);
}

void test_lazy_connect_owns_endpoint() {
    test::section("lazy connect owns its endpoint before execution");
    auto created = EventLoop::create();
    CHECK(created.has_value());
    if (!created) return;
    auto& loop = *created;
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) return;
    auto endpoint = listener->local_endpoint();
    auto pending = tcp::connect(loop, endpoint, {}, {.deadline = Clock::now() + 2s});
    // Mutation is deterministic: a reference-taking lazy coroutine would now
    // see this invalid endpoint instead of the address present at invocation.
    endpoint = Endpoint{};
    struct Driver {
        static Task<void> run(Task<Result<tcp::Socket>> task) {
            const auto socket = co_await std::move(task);
            CHECK(socket.has_value());
        }
    };
    CHECK(loop.run_until_complete(Driver::run(std::move(pending))).has_value());
    CHECK(loop.outstanding() == 0);
}

// ── options travel from the socket down to the loop ──────────────────────────

void test_socket_forwards_options() {
    test::section("a socket's read honours a deadline and a stop token");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    if (!created) {
        return;
    }
    EventLoop& loop = *created;

    LoopbackPair pair;
    if (!pair.open(loop)) {
        return;
    }

    struct Read {
        static DetachedTask run(tcp::Socket& socket,
                                OperationOptions options,
                                Result<std::size_t>& slot,
                                std::atomic<int>& done) {
            std::array<std::byte, 64> scratch{};
            slot = co_await socket.read_some(scratch, std::move(options));
            done.fetch_add(1, std::memory_order_release);
        }
    };

    // A deadline that has already passed is refused before any syscall, so the
    // loop never takes the operation on. That this arrives as `timed_out`
    // rather than as a blocked read is the whole point of the pass-through:
    // `tcp::Socket` adds nothing to the rules in `operation.hpp`, it forwards.
    std::atomic<int> done{0};
    Result<std::size_t> expired = std::size_t{999};
    Read::run(pair.server, {.deadline = Clock::now() - std::chrono::milliseconds{1}}, expired,
              done);
    CHECK(done.load(std::memory_order_acquire) == 1);
    CHECK(!expired.has_value());
    CHECK(expired.error() == Errc::timed_out);
    CHECK(loop.outstanding() == 0);

    // A live deadline suspends, and the peer sending nothing lets it expire —
    // which requires the timer to have reached the loop through two layers.
    std::atomic<int> timed{0};
    Result<std::size_t> late = std::size_t{999};
    const auto started = Clock::now();
    Read::run(pair.server, {.deadline = started + std::chrono::milliseconds{20}}, late, timed);
    CHECK(loop.run_once(std::chrono::milliseconds{0}).has_value());
    CHECK(timed.load(std::memory_order_acquire) == 0);
    // One outstanding operation, not two: the deadline indexes the read.
    CHECK(loop.outstanding() == 1);
    for (int i = 0; i < 200 && timed.load(std::memory_order_acquire) == 0; ++i) {
        CHECK(loop.run_once(std::chrono::milliseconds{50}).has_value());
    }
    CHECK(timed.load(std::memory_order_acquire) == 1);
    CHECK(!late.has_value());
    CHECK(late.error() == Errc::timed_out);
    CHECK(Clock::now() - started >= std::chrono::milliseconds{20});

    // And a stop token cuts a suspended read short.
    std::stop_source source;
    std::atomic<int> stopped{0};
    Result<std::size_t> cancelled = std::size_t{999};
    Read::run(pair.server, {.stop = source.get_token()}, cancelled, stopped);
    CHECK(loop.run_once(std::chrono::milliseconds{0}).has_value());
    CHECK(stopped.load(std::memory_order_acquire) == 0);
    source.request_stop();
    CHECK(loop.run_once(EventLoop::Duration::min()).has_value());
    CHECK(stopped.load(std::memory_order_acquire) == 1);
    CHECK(!cancelled.has_value());
    CHECK(cancelled.error() == Errc::cancelled);
    CHECK(loop.outstanding() == 0);
}

void test_accept_and_connect_forward_options() {
    test::section("accept and connect honour a deadline");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    if (!created) {
        return;
    }
    EventLoop& loop = *created;

    Result<tcp::Listener> listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) {
        return;
    }

    struct Accept {
        static DetachedTask
        run(tcp::Listener& listening, OperationOptions options, Error& failure,
            std::atomic<int>& done) {
            Result<tcp::Socket> accepted = co_await listening.accept(std::move(options));
            CHECK(!accepted);
            if (!accepted) {
                failure = accepted.error();
            }
            // A timed-out accept must produce no socket: anything the kernel
            // had already prepared is closed rather than handed over or leaked.
            done.fetch_add(1, std::memory_order_release);
        }
    };

    std::atomic<int> done{0};
    Error failure{};
    const auto started = Clock::now();
    Accept::run(*listener, {.deadline = started + std::chrono::milliseconds{20}}, failure, done);
    for (int i = 0; i < 200 && done.load(std::memory_order_acquire) == 0; ++i) {
        CHECK(loop.run_once(std::chrono::milliseconds{50}).has_value());
    }
    CHECK(done.load(std::memory_order_acquire) == 1);
    CHECK(failure == Errc::timed_out);
    CHECK(Clock::now() - started >= std::chrono::milliseconds{20});
    CHECK(loop.outstanding() == 0);

    // A connect whose deadline has already passed never reaches the kernel, so
    // there is nothing left half-open for the caller to wonder about.
    struct Connect {
        static DetachedTask
        run(EventLoop& target, Endpoint endpoint, OperationOptions io, Error& failure,
            std::atomic<int>& done) {
            Result<tcp::Socket> connected =
                co_await tcp::connect(target, endpoint, {}, std::move(io));
            CHECK(!connected);
            if (!connected) {
                failure = connected.error();
            }
            done.fetch_add(1, std::memory_order_release);
        }
    };

    std::atomic<int> connect_done{0};
    Error connect_failure{};
    Connect::run(loop,
                 listener->local_endpoint(),
                 {.deadline = Clock::now() - std::chrono::milliseconds{1}},
                 connect_failure,
                 connect_done);
    CHECK(connect_done.load(std::memory_order_acquire) == 1);
    CHECK(connect_failure == Errc::timed_out);
    CHECK(loop.outstanding() == 0);
}

}  // namespace

int main() {
    std::printf("backend: %s\n", io_backend_name());

    test_endpoint();
    test_lazy_connect_owns_endpoint();
    test_exclusive_bind_is_uniform();
    test_accept_connect_round_trip();
    test_larger_transfer();
    test_connection_refused();
    test_socket_move_and_close();
    test_pending_accept_close(false);
    test_pending_accept_close(true);
    test_pending_read_close(false);
    test_pending_read_close(true);
    test_loop_destruction_pending_accept();
    test_loop_destruction_pending_read();
    test_socket_forwards_options();
    test_accept_and_connect_forward_options();

    return test::summary();
}
