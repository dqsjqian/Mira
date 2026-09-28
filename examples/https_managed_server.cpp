// Managed HTTPS composition: TCP admission, bounded TLS handshakes, ALPN dispatch
// and cooperative shutdown. Each connection serves one request (one H2 batch).
// Usage: mira_https_managed_server cert.pem key.pem [port=0] [max-connections=64]
//        [max-handshakes=16] [lifetime-ms=5000] [handshake-ms=1000] [grace-ms=1000]
#include <mira/http/connection.hpp>
#include <mira/http2/connection.hpp>
#include <mira/tls/stream.hpp>
#include <mira/transport/server.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <limits>
#include <string_view>

namespace {
using Mira::Result;
using Mira::Task;
namespace tcp = Mira::transport::tcp;
using TlsStream = Mira::tls::Stream<tcp::Socket>;

std::span<const std::byte> bytes(std::string_view text) {
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

Task<Result<void>> serve_h1(TlsStream& stream, Mira::OperationOptions io) {
    auto reply = [](const Mira::http::Request&, Mira::http::ResponseWriter<TlsStream>& writer,
                    std::span<const std::byte>) -> Task<Result<void>> {
        Mira::http::Response response;
        response.status = 200;
        response.headers.append("Content-Type", "text/plain");
        co_return co_await writer.send(response, bytes("managed HTTPS: http/1.1\n"));
    };
    Mira::http::ServerOptions options;
    options.stop = io.stop;
    options.force_close = true;
    options.max_requests_per_connection = 1;
    options.idle_timeout = std::chrono::seconds(5);
    options.request_timeout = std::chrono::seconds(5);
    co_return co_await Mira::http::serve_connection(stream, reply, options);
}

Task<Result<void>> serve_h2(TlsStream& stream, Mira::OperationOptions io) {
    auto session = Mira::http2::Session::create(Mira::http2::Role::server,
                                               {.max_streams = 8, .max_body_bytes = 64 * 1024});
    if (!session) co_return Mira::fail(session.error());
    Mira::http2::Connection connection{stream, std::move(*session)};
    io.deadline = Mira::Clock::now() + std::chrono::seconds(5);
    for (;;) {
        auto pumped = co_await connection.pump(io);
        if (!pumped) co_return pumped;
        bool replied = false;
        for (const auto id : connection.session().streams()) {
            const auto* request = connection.session().stream(id);
            if (!request || !request->headers_received || !request->remote_end || request->closed)
                continue;
            Mira::http2::Headers headers{{":status", "200"}, {"content-type", "text/plain"}};
            auto result = connection.session().respond(id, headers, bytes("managed HTTPS: h2\n"));
            if (!result) co_return result;
            replied = true;
        }
        if (replied) {
            auto flushed = co_await connection.flush(io);
            if (!flushed) co_return flushed;
            for (const auto id : connection.session().streams()) {
                const auto* request = connection.session().stream(id);
                if (request && request->closed) {
                    auto body = connection.session().take_body(id);
                    if (!body) co_return Mira::fail(body.error());
                    auto released = connection.session().release(id);
                    if (!released) co_return released;
                }
            }
            auto goodbye = connection.session().goaway();
            if (!goodbye) co_return goodbye;
            co_return co_await connection.flush(io);
        }
        if (connection.session().state() == Mira::http2::State::closed)
            co_return Result<void>{};
    }
}

struct HttpsHandler {
    Mira::EventLoop& loop;
    const Mira::tls::Context& context;
    Mira::ResourceBudget handshakes;
    Mira::Clock::duration handshake_timeout;
    std::size_t handshake_rejected = 0;
    std::size_t handshake_timeouts = 0;
    std::size_t handshake_completed = 0;
    std::size_t peak_handshakes = 0;
    std::size_t h1 = 0;
    std::size_t h2 = 0;
    std::size_t alpn_rejected = 0;

    static void count(std::size_t& value) noexcept {
        if (value != std::numeric_limits<std::size_t>::max()) ++value;
    }

    Task<Result<void>> operator()(tcp::Socket& socket, Mira::OperationOptions io) {
        auto slot = handshakes.try_acquire(1);
        if (!slot) {
            count(handshake_rejected);
            std::printf("HANDSHAKE_REJECTED\n");
            std::fflush(stdout);
            co_return Mira::fail(slot.error());
        }
        peak_handshakes = std::max(peak_handshakes, handshakes.used());
        std::printf("HANDSHAKE_START active=%zu\n", handshakes.used());
        std::fflush(stdout);
        auto stream = TlsStream::create(loop, socket, context);
        if (!stream) co_return Mira::fail(stream.error());
        // One absolute deadline covers the entire handshake, including every
        // ciphertext transfer. Admission's deadline is deliberately separate.
        auto established = co_await stream->handshake(
            {.stop = io.stop, .deadline = Mira::Clock::now() + handshake_timeout});
        slot->reset();
        if (!established) {
            if (established.error() == Mira::Errc::timed_out) {
                ++handshake_timeouts;
                std::printf("HANDSHAKE_TIMEOUT\n");
                std::fflush(stdout);
            }
            co_return established;
        }
        ++handshake_completed;
        std::printf("HANDSHAKE_READY\n");
        std::fflush(stdout);
        Result<void> served;
        const auto protocol = stream->negotiated_protocol();
        if (protocol == "h2") {
            ++h2;
            served = co_await serve_h2(*stream, io);
        } else if (protocol == "http/1.1") {
            ++h1;
            served = co_await serve_h1(*stream, io);
        } else {
            // Missing ALPN is refused too: no sniffing, h2c or implicit downgrade.
            ++alpn_rejected;
            co_return Mira::fail(std::make_error_code(std::errc::protocol_error));
        }
        if (!served) co_return served;
        io.deadline = Mira::Clock::now() + std::chrono::seconds(1);
        co_return co_await stream->shutdown(io);
    }
};

Task<void> run(Mira::EventLoop& loop, tcp::Listener& listener, HttpsHandler& handler,
               unsigned maximum, unsigned lifetime, unsigned grace, int& status) {
    tcp::ServeOptions options;
    options.max_connections = maximum;
    options.io.deadline = Mira::Clock::now() + std::chrono::milliseconds(lifetime);
    options.grace_period = std::chrono::milliseconds(grace);
    auto call = [&handler](tcp::Socket& socket, Mira::OperationOptions io) {
        return handler(socket, io);
    };
    auto result = co_await tcp::serve(loop, listener, call, options);
    if (!result) {
        std::fprintf(stderr, "serve: %s\n", result.error().message().c_str());
        co_return;
    }
    std::printf("accepted=%zu rejected=%zu completed=%zu failed=%zu cancelled=%zu peak_active=%zu "
                "handshake_rejected=%zu handshake_timeouts=%zu handshake_completed=%zu "
                "peak_handshakes=%zu h1=%zu h2=%zu alpn_rejected=%zu\n",
                result->accepted, result->rejected, result->completed, result->failed,
                result->cancelled, result->peak_active, handler.handshake_rejected,
                handler.handshake_timeouts, handler.handshake_completed, handler.peak_handshakes,
                handler.h1, handler.h2, handler.alpn_rejected);
    status = 0;
}
}  // namespace

int main(int argc, char** argv) {
    unsigned values[]{0, 64, 16, 5000, 1000, 1000};
    if (argc < 3 || argc > 9) return 2;
    for (int i = 3; i < argc; ++i) {
        const std::string_view text{argv[i]};
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), values[i - 3]);
        if (error != std::errc{} || end != text.data() + text.size()) return 2;
    }
    if (values[0] > 65535 || !values[1] || values[1] > 65536 || !values[2] ||
        values[2] > values[1] || !values[3] || values[3] > 3600000 || !values[4] ||
        values[4] > 3600000 || values[5] > 3600000) return 2;
#ifdef SIGPIPE
    if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 1;
#endif
    const std::array<std::string_view, 2> protocols{"h2", "http/1.1"};
    auto context = Mira::tls::Context::server_alpn(argv[1], argv[2], protocols);
    if (!context) {
        std::fprintf(stderr, "TLS configuration: %s\n", context.error().message().c_str());
        return 1;
    }
    auto loop = Mira::EventLoop::create();
    if (!loop) return 1;
    auto listener = tcp::Listener::bind(
        *loop, Mira::transport::Endpoint::loopback(static_cast<std::uint16_t>(values[0])));
    if (!listener) return 1;
    HttpsHandler handler{*loop, *context, Mira::ResourceBudget{values[2]},
                         std::chrono::milliseconds(values[4])};
    std::printf("PORT=%u\n", static_cast<unsigned>(listener->local_endpoint().port()));
    std::fflush(stdout);
    int status = 1;
    auto result = loop->run_until_complete(run(*loop, *listener, handler, values[1], values[3],
                                               values[5], status));
    return result ? status : 1;
}
