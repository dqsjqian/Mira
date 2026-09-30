// End-to-end: a real HTTP exchange over a real TCP connection.
//
// Everything else in this repository tests one layer. This file is the only
// place where the whole stack runs at once — event loop, TCP transport,
// parser, connection loop, serializer — against a socket rather than a
// scripted buffer. If the layers disagree about anything, this is where it
// shows up.
//
// It lives in the http test suite rather than the library: `Mira::http`
// links only against `Mira::core` and must never depend on transport. A
// test binary linking both is fine — the *library* boundary is what matters.

#include "check.hpp"
#include "mira/http/connection.hpp"
#include "mira/transport/tcp.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <span>
#include <string>
#include <string_view>

using namespace Mira;
using namespace Mira::http;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

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

bool pump_until(EventLoop& loop, const std::atomic<int>& done, int target, int budget = 600) {
    for (int i = 0; i < budget && done.load(std::memory_order_acquire) < target; ++i) {
        if (!loop.run_once(25ms)) {
            return false;
        }
    }
    return done.load(std::memory_order_acquire) >= target;
}

void test_http_over_tcp() {
    test::section("HTTP over real TCP");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    Result<tcp::Listener> listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    const Endpoint where = listener->local_endpoint();

    std::atomic<int> done{0};
    std::string server_saw_target;
    std::string server_saw_body;
    Error server_error{};
    std::string client_response;
    Error client_error{};

    // Server: accept one connection and serve requests on it with the real
    // connection loop — no scripted stream anywhere in this path.
    struct Server {
        static DetachedTask run(tcp::Listener& listening,
                                std::string& target,
                                std::string& body,
                                Error& failure,
                                std::atomic<int>& counter) {
            Result<tcp::Socket> accepted = co_await listening.accept();
            if (!accepted) {
                failure = accepted.error();
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }
            tcp::Socket peer = std::move(*accepted);

            auto handler = [&target,
                            &body](const Request& request,
                                   auto& writer,
                                   std::span<const std::byte> request_body) -> Task<Result<void>> {
                target = request.target;
                body.assign(reinterpret_cast<const char*>(request_body.data()),
                            request_body.size());

                Response response;
                response.status = 200;
                response.headers.append("Content-Type", "text/plain");
                co_return co_await writer.send(response, bytes_of("pong"));
            };

            const Result<void> served = co_await serve_connection(peer, handler);
            if (!served) {
                failure = served.error();
            }
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    // Client: a hand-written HTTP request, so the server is tested against
    // bytes rather than against our own serializer's assumptions.
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

            const std::string request = "POST /submit HTTP/1.1\r\n"
                                        "Host: localhost\r\n"
                                        "Content-Length: 4\r\n"
                                        "Connection: close\r\n"
                                        "\r\n"
                                        "ping";
            const Result<void> written = co_await write_all(socket, bytes_of(request));
            if (!written) {
                failure = written.error();
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }

            // Read until the server closes, which is what Connection: close
            // promises.
            std::array<std::byte, 512> scratch{};
            for (;;) {
                Result<std::size_t> read = co_await socket.read_some(scratch);
                if (!read) {
                    if (read.error() != Errc::eof) {
                        failure = read.error();
                    }
                    break;
                }
                sink.append(reinterpret_cast<const char*>(scratch.data()), *read);
            }
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    Server::run(*listener, server_saw_target, server_saw_body, server_error, done);
    Client::run(loop, where, client_response, client_error, done);

    CHECK(pump_until(loop, done, 2));
    CHECK(!server_error);
    CHECK(!client_error);

    // The server parsed a real request off the wire.
    CHECK(server_saw_target == "/submit");
    CHECK(server_saw_body == "ping");

    // The client got a well-formed response off the wire.
    CHECK(client_response == "HTTP/1.1 200 OK\r\n"
                             "Content-Type: text/plain\r\n"
                             "Connection: close\r\n"
                             "Content-Length: 4\r\n"
                             "\r\n"
                             "pong");
}

void test_keep_alive_over_tcp() {
    test::section("keep-alive over real TCP");

    Result<EventLoop> created = EventLoop::create();
    CHECK(created.has_value());
    EventLoop& loop = created.value();

    Result<tcp::Listener> listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    const Endpoint where = listener->local_endpoint();

    std::atomic<int> done{0};
    int requests_served = 0;
    std::string client_response;

    struct Server {
        static DetachedTask run(tcp::Listener& listening, int& served, std::atomic<int>& counter) {
            Result<tcp::Socket> accepted = co_await listening.accept();
            if (!accepted) {
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }
            tcp::Socket peer = std::move(*accepted);

            auto handler = [&served](const Request&,
                                     auto& writer,
                                     std::span<const std::byte>) -> Task<Result<void>> {
                ++served;
                Response response;
                response.status = 200;
                co_return co_await writer.send(response, bytes_of("ok"));
            };

            static_cast<void>(co_await serve_connection(peer, handler));
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    struct Client {
        static DetachedTask
        run(EventLoop& target_loop, Endpoint where, std::string& sink, std::atomic<int>& counter) {
            Result<tcp::Socket> connected = co_await tcp::connect(target_loop, where);
            if (!connected) {
                counter.fetch_add(1, std::memory_order_release);
                co_return;
            }
            tcp::Socket socket = std::move(*connected);

            // Two requests on one connection; the second closes it. Sent as a
            // single write so the server also has to handle pipelining.
            const std::string requests = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
                                         "GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
            static_cast<void>(co_await write_all(socket, bytes_of(requests)));

            std::array<std::byte, 512> scratch{};
            for (;;) {
                Result<std::size_t> read = co_await socket.read_some(scratch);
                if (!read) {
                    break;
                }
                sink.append(reinterpret_cast<const char*>(scratch.data()), *read);
            }
            counter.fetch_add(1, std::memory_order_release);
            co_return;
        }
    };

    Server::run(*listener, requests_served, done);
    Client::run(loop, where, client_response, done);

    CHECK(pump_until(loop, done, 2));
    CHECK(requests_served == 2);

    // Two complete responses arrived on one connection.
    std::size_t responses = 0;
    std::size_t at = client_response.find("HTTP/1.1 200 OK");
    while (at != std::string::npos) {
        ++responses;
        at = client_response.find("HTTP/1.1 200 OK", at + 1);
    }
    CHECK(responses == 2);
}

}  // namespace

int main() {
    std::printf("backend: %s\n", io_backend_name());
    test_http_over_tcp();
    test_keep_alive_over_tcp();
    return test::summary();
}
