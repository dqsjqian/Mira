// A three-step HTTP server, in the shape Mira intends.
//
// This is the smallest honest server the library supports: one listener,
// one TaskScope, one handler that answers every request the same way. No
// routing, no bodies to stream, no graceful-shutdown choreography — the
// pieces a newcomer needs to recognise before any of that makes sense.
//
// The three steps:
//
//   1. `serve_connection` turns one accepted socket into HTTP: it parses,
//      calls the handler per request, writes the response, keeps the
//      connection alive or closes it as the request dictates.
//   2. `TaskScope` owns the per-connection coroutines. Connections
//      outlive the `accept` that produced them, but never the scope.
//   3. `run_until_complete` bridges sync main to the coroutine world.
//
// Usage: mira_hello_world_server [port]
//   port  0 (the default) binds an ephemeral loopback port
// Interruption uses the default signal behavior, not graceful shutdown.

#include <mira/core/event_loop.hpp>
#include <mira/core/task.hpp>
#include <mira/core/task_scope.hpp>
#include <mira/http/connection.hpp>
#include <mira/transport/tcp.hpp>

#include <charconv>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <span>
#include <string_view>
#include <system_error>

using Mira::EventLoop;
using Mira::Result;
using Mira::Task;
using Mira::TaskScope;
using Mira::http::Request;
using Mira::http::Response;
using Mira::http::serve_connection;
namespace tcp = Mira::transport::tcp;

namespace {

template <typename Integer>
bool parse_number(std::string_view text, Integer& value) {
    if (text.empty()) {
        return false;
    }
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc{} && end == text.data() + text.size();
}

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

/// Answer every request the same way — a newcomer's first handler.
Task<Result<void>> answer(const Request&, auto& writer, std::span<const std::byte>) {
    Response response;
    response.status = 200;
    response.headers.append("Content-Type", "text/plain");
    co_return co_await writer.send(response, bytes_of("hello from Mira's HTTP server"));
}

/// `serve_connection` yields `Task<Result<void>>`; `TaskScope::spawn` takes
/// `Task<void>`. Wrap and log: one sick connection must not end the server.
Task<void> serve_one(tcp::Socket socket) {
    const Result<void> served = co_await serve_connection(
        socket,
        [](const Request& request, auto& writer, std::span<const std::byte> body)
            -> Task<Result<void>> {
            co_return co_await answer(request, writer, body);
        });
    if (!served && served.error() != Mira::Errc::eof) {
        std::fprintf(stderr, "connection ended: %s\n", served.error().message().c_str());
    }
}

/// Accept until the listener dies, serving HTTP on every connection.
Task<void> serve(tcp::Listener& listener) {
    TaskScope scope;

    for (;;) {
        Result<tcp::Socket> accepted = co_await listener.accept();
        if (!accepted) {
            std::fprintf(stderr, "accept: %s\n", accepted.error().message().c_str());
            scope.request_stop();
            break;
        }
        tcp::Socket socket = std::move(*accepted);
        scope.spawn(serve_one(std::move(socket)));
    }
    co_await scope.join();
}

}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    if (argc > 2 || (argc > 1 && !parse_number(argv[1], port))) {
        std::fprintf(stderr, "usage: %s [port: 0..65535]\n", argv[0]);
        return 2;
    }

#ifdef SIGPIPE
    if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        std::fprintf(stderr, "could not ignore SIGPIPE\n");
        return 1;
    }
#endif

    Result<EventLoop> created = EventLoop::create();
    if (!created) {
        std::fprintf(stderr, "event loop: %s\n", created.error().message().c_str());
        return 1;
    }
    EventLoop& loop = created.value();

    Result<tcp::Listener> listener =
        tcp::Listener::bind(loop, Mira::transport::Endpoint::loopback(port));
    if (!listener) {
        std::fprintf(stderr, "bind: %s\n", listener.error().message().c_str());
        return 1;
    }

    std::printf("hello world server listening on %s\n",
                listener->local_endpoint().to_string().c_str());
    std::fflush(stdout);

    const Result<void> ran = loop.run_until_complete(serve(*listener));
    if (!ran) {
        std::fprintf(stderr, "run: %s\n", ran.error().message().c_str());
        return 1;
    }
    return 0;
}
