// An HTTP/3 prior-knowledge server — the QUIC twin of the h2 example.
//
// HTTP/3 has no plain-text mode: QUIC mandates TLS 1.3 with ALPN "h3", so
// "prior knowledge" here means the certificate is generated at startup and
// handed to curl via --cacert. That is the thinnest honest demonstration
// of the http3 layer: one UDP socket, `Connection::serve` for the
// handshake, then the explicit pump answering requests.
//
// The shape, step by step:
//
//   1. Generate a self-signed localhost certificate (openssl CLI, same
//      shape the QUIC tests use) and bind a UDP socket.
//   2. Receive the first datagram — the QUIC Initial — and hand it to
//      `Connection::serve`, which drives the handshake to completion.
//   3. Requests arrive on server streams starting at id 0 (one stream per
//      request, `await_head` + `read_body` + `respond`), the body consumed
//      through `consume` to keep flow-control credit flowing.
//
// One connection per process — a listener that routes many clients by
// connection id is future work (see ARCHITECTURE.md); curl's single
// request is exactly what this shape demonstrates. The server exits when
// the client closes the connection.
//
// Usage: mira_h3_server [port]
//   port  0 (the default) binds an ephemeral loopback port
// The certificate path is printed on startup for --cacert.

#include <mira/core/event_loop.hpp>
#include <mira/core/task.hpp>
#include <mira/core/task_scope.hpp>
#include <mira/http3/connection.hpp>
#include <mira/transport/udp.hpp>

#include <array>
#include <charconv>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using Mira::EventLoop;
using Mira::Result;
using Mira::Task;
using Mira::TaskScope;
namespace transport = Mira::transport;
using H3Connection = Mira::http3::Connection<transport::udp::Socket>;
using Mira::http3::Headers;

namespace {

template <typename Integer>
bool parse_number(std::string_view text, Integer& value) {
    if (text.empty()) {
        return false;
    }
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc{} && end == text.data() + text.size();
}

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()),
                                      text.size()};
}

/// Run `openssl req` to make a throwaway localhost certificate.
/// Returns the (cert, key) pair; empty strings mean failure.
std::pair<std::string, std::string> make_certificate(const std::string& directory) {
    const std::string cert = directory + "/cert.pem";
    const std::string key = directory + "/key.pem";
    const std::string command =
        "openssl req -x509 -newkey rsa:2048 -nodes -keyout '" + key +
        "' -out '" + cert + "' -days 2 -subj /CN=localhost"
        " -addext subjectAltName=DNS:localhost >/dev/null 2>&1";
    if (std::system(command.c_str()) != 0) {
        return {};
    }
    return {cert, key};
}

/// Answer every request stream the client opens, in arrival order.
/// Server request streams start at 0 and count up; `await_head` pumps
/// until each stream's headers arrive. When the client closes the
/// connection (curl answers one request and quits), the next `await_head`
/// fails with the QUIC teardown status instead of `eof` — both mean
/// "client hung up", so neither is an error here.
Task<Result<void>> serve_requests(H3Connection& server) {
    for (std::int64_t stream = 0;; ++stream) {
        const auto head = co_await server.await_head(
            stream, {.deadline = Mira::Clock::now() + std::chrono::seconds(30)});
        if (!head) {
            co_return Result<void>{};
        }
        if (head->fields.empty()) {
            // A reset stream surfaces as an empty head; nothing to answer.
            continue;
        }

        // Drain the request body (GETs carry none), keeping flow-control
        // credit flowing as the bytes are consumed.
        bool fin = false;
        while (!fin) {
            const auto chunk = co_await server.read_body(
                stream, {.deadline = Mira::Clock::now() + std::chrono::seconds(30)});
            if (!chunk) co_return Mira::fail(chunk.error());
            if (chunk->data.empty() && chunk->fin) break;
            if (!server.consume(stream, chunk->data.size())) {
                co_return Mira::fail(Mira::Errc::internal);
            }
            fin = chunk->fin;
        }

        Headers fields;
        fields.emplace_back(":status", "200");
        fields.emplace_back("content-type", "text/plain");
        std::string body{"served by Mira's HTTP/3 server, stream "};
        body += std::to_string(stream);
        const auto sent =
            co_await server.respond(stream, fields, bytes_of(body));
        if (!sent) co_return Mira::fail(sent.error());
    }
}

Task<void> serve(transport::udp::Socket socket,
                 const std::string& cert, const std::string& key) {
    const transport::Endpoint local = socket.local_endpoint().value_or(
        transport::Endpoint::loopback(0));
    std::printf("h3 server listening on %s\n", local.to_string().c_str());
    std::printf("certificate: %s\n", cert.c_str());
    std::fflush(stdout);

    // The QUIC Initial: take it off the wire, then hand the socket and the
    // datagram to the engine's accept path.
    std::array<std::byte, 65536> initial_buffer{};
    const auto datagram = co_await socket.receive_from(initial_buffer);
    if (!datagram) {
        std::fprintf(stderr, "receive: %s\n", datagram.error().message().c_str());
        co_return;
    }

    Mira::quic::Options options;
    options.local = local;
    options.remote = datagram->peer;
    options.certificate_file = cert;
    options.private_key_file = key;
    options.alpn = "h3";

    std::vector<std::byte> initial(initial_buffer.data(),
                                   initial_buffer.data() + datagram->size);
    auto served = co_await H3Connection::serve(
        std::move(socket), std::move(options), Mira::http3::Limits{},
        initial, {.deadline = Mira::Clock::now() + std::chrono::seconds(30)});
    if (!served) {
        std::fprintf(stderr, "handshake: %s\n", served.error().message().c_str());
        co_return;
    }

    H3Connection server = std::move(*served);
    const auto answered = co_await serve_requests(server);
    if (!answered && answered.error() != Mira::Errc::eof) {
        std::fprintf(stderr, "serve: %s\n", answered.error().message().c_str());
        co_return;
    }

    // Deliver what is still unacknowledged before letting go: destroying
    // the connection now would drop response datagrams the client has not
    // confirmed (the same rule the QUIC tests teach).
    while (!server.closed()) {
        const auto round =
            co_await server.pump({.deadline = Mira::Clock::now() + std::chrono::seconds(30)});
        if (!round) break;
    }
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

    const char* runtime_dir = std::getenv("RUNTIME_DIRECTORY");
    const std::string directory =
        runtime_dir != nullptr ? std::string{runtime_dir} : std::string{"/tmp"};
    const auto [cert, key] = make_certificate(directory);
    if (cert.empty()) {
        std::fprintf(stderr, "could not generate a certificate in %s\n", directory.c_str());
        return 1;
    }

    Result<EventLoop> created = EventLoop::create();
    if (!created) {
        std::fprintf(stderr, "event loop: %s\n", created.error().message().c_str());
        return 1;
    }
    EventLoop& loop = created.value();

    Result<transport::udp::Socket> bound =
        transport::udp::Socket::bind(loop, transport::Endpoint::loopback(port));
    if (!bound) {
        std::fprintf(stderr, "bind: %s\n", bound.error().message().c_str());
        return 1;
    }

    const Result<void> ran =
        loop.run_until_complete(serve(std::move(*bound), cert, key));
    if (!ran) {
        std::fprintf(stderr, "run: %s\n", ran.error().message().c_str());
        return 1;
    }
    return 0;
}
