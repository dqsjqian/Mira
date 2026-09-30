// Loopback DNS-over-HTTPS responder (RFC 8484) for a static zone.
// Usage: mira_doh_server <port> <lifetime-ms> [cert.pem key.pem] name=address...
//
// Prints "PORT=<n>". Serves GET and POST at /dns-query over HTTPS (ALPN
// http/1.1) when a certificate is given and TLS is built, otherwise plain HTTP
// for local testing. A/AAAA come from the zone arguments (TTL 60); an owner
// with no record of the asked type gets NOERROR/NODATA, anything else
// NXDOMAIN. Cache-Control carries the minimum TTL (RFC 8484 §5.1).
#include <mira/dns/doh.hpp>
#include <mira/http/connection.hpp>
#include <mira/socks/socks5.hpp>
#include <mira/transport/server.hpp>
#if MIRA_EXAMPLE_TLS
#include <mira/tls/stream.hpp>
#endif

#include <algorithm>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace dns = Mira::dns;
namespace tcp = Mira::transport::tcp;
using namespace std::chrono_literals;

namespace {

struct Entry {
    dns::Name name;
    std::uint16_t type;
    dns::Rdata data;
};
std::vector<Entry> zone;
#if MIRA_EXAMPLE_TLS
Mira::EventLoop* event_loop = nullptr;
std::optional<Mira::tls::Context> tls_context;
#endif

bool add_entry(std::string_view argument) {
    const auto equals = argument.find('=');
    if (equals == std::string_view::npos) return false;
    auto name = dns::Name::parse(argument.substr(0, equals));
    // Numeric parsing only: a domain on the right-hand side is rejected.
    auto address = Mira::socks::Address::parse(argument.substr(equals + 1), 0);
    if (!name || !address || address->kind() == Mira::socks::Address::Kind::domain) return false;
    const auto octets = address->octets();
    if (address->kind() == Mira::socks::Address::Kind::ipv4) {
        dns::AData data;
        std::copy(octets.begin(), octets.end(), data.address.begin());
        zone.push_back({*name, dns::type::a, data});
    } else {
        dns::AaaaData data;
        std::copy(octets.begin(), octets.end(), data.address.begin());
        zone.push_back({*name, dns::type::aaaa, data});
    }
    return true;
}

template<typename Writer>
Mira::Task<Mira::Result<void>> answer(const Mira::http::Request& request, Writer& writer,
                                      std::span<const std::byte> body) {
    Mira::http::Response response;
    const auto path = std::string_view{request.target}.substr(0, request.target.find('?'));
    if (path != "/dns-query") {
        response.status = 404;
        co_return co_await writer.send(response);
    }
    auto wire = dns::doh::decode_request(request, body);
    if (!wire) {
        response.status = dns::doh::http_status(wire.error());
        co_return co_await writer.send(response);
    }
    auto query = dns::decode(*wire);
    if (!query || query->header.qr || query->questions.size() != 1) {
        response.status = 400;
        co_return co_await writer.send(response);
    }
    dns::Message reply;
    reply.header = query->header;
    reply.header.qr = true;
    reply.header.ra = true;
    reply.header.aa = true;
    reply.header.rcode = dns::rcode::nxdomain;
    reply.questions = query->questions;
    if (query->edns) reply.edns = dns::Edns{};
    const auto& question = query->questions[0];
    for (const auto& entry : zone) {
        if (!(entry.name == question.name)) continue;
        reply.header.rcode = dns::rcode::noerror;  // owner exists: NODATA at worst
        if (entry.type == question.type || question.type == dns::type::any)
            reply.answers.push_back({question.name, entry.type, dns::class_in, 60, entry.data});
    }
    auto encoded = dns::encode(reply);
    if (!encoded) co_return Mira::fail(encoded.error());
    response.status = 200;
    response.headers.append("Content-Type", std::string{dns::doh::media_type});
    response.headers.append("Cache-Control",
                            "max-age=" + std::to_string(dns::min_ttl(reply).value_or(0)));
    co_return co_await writer.send(response, *encoded);
}

template<typename Stream>
Mira::Task<Mira::Result<void>> serve_http(Stream& stream, Mira::OperationOptions io) {
    Mira::http::ServerOptions options;
    options.stop = io.stop;
    options.idle_timeout = 5s;
    options.request_timeout = 5s;
    co_return co_await Mira::http::serve_connection(
        stream,
        [](const Mira::http::Request& request, auto& writer, std::span<const std::byte> body) {
            return answer(request, writer, body);
        },
        options);
}

Mira::Task<Mira::Result<void>> handle(tcp::Socket& socket, Mira::OperationOptions io) {
#if MIRA_EXAMPLE_TLS
    if (tls_context) {
        auto stream = Mira::tls::Stream<tcp::Socket>::create(*event_loop, socket, *tls_context);
        if (!stream) co_return Mira::fail(stream.error());
        auto established = co_await stream->handshake({.stop = io.stop, .deadline = Mira::Clock::now() + 5s});
        if (!established) co_return established;
        auto served = co_await serve_http(*stream, io);
        static_cast<void>(co_await stream->shutdown({.deadline = Mira::Clock::now() + 1s}));
        co_return served;
    }
#endif
    co_return co_await serve_http(socket, io);
}

Mira::Task<void> run(tcp::Listener& listener, unsigned lifetime, int& status) {
    tcp::ServeOptions options;
    options.max_connections = 64;
    options.io.deadline = Mira::Clock::now() + std::chrono::milliseconds(lifetime);
    auto served = co_await tcp::serve(listener, &handle, options);
    if (!served) {
        std::fprintf(stderr, "serve: %s\n", served.error().message().c_str());
        co_return;
    }
    status = 0;
}

}  // namespace

int main(int argc, char** argv) {
    unsigned port = 0, lifetime = 0;
    const auto number = [](std::string_view text, unsigned& value) {
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
        return error == std::errc{} && end == text.data() + text.size();
    };
    if (argc < 3 || !number(argv[1], port) || !number(argv[2], lifetime) || port > 65535 ||
        lifetime == 0 || lifetime > 3600000) {
        std::fprintf(stderr, "usage: %s <port> <lifetime-ms> [cert key] name=address...\n", argv[0]);
        return 2;
    }
    std::vector<std::string_view> files;
    for (int i = 3; i < argc; ++i) {
        const std::string_view argument{argv[i]};
        if (argument.find('=') == std::string_view::npos) {
            files.push_back(argument);
        } else if (!add_entry(argument)) {
            std::fprintf(stderr, "bad zone entry: %s\n", argv[i]);
            return 2;
        }
    }
    if (!files.empty() && files.size() != 2) return 2;
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto loop = Mira::EventLoop::create();
    if (!loop) return 1;
#if MIRA_EXAMPLE_TLS
    event_loop = &*loop;
#endif
    if (files.size() == 2) {
#if MIRA_EXAMPLE_TLS
        auto context = Mira::tls::Context::server(files[0], files[1], "http/1.1");
        if (!context) {
            std::fprintf(stderr, "tls: %s\n", context.error().message().c_str());
            return 1;
        }
        tls_context.emplace(std::move(*context));
#else
        std::fprintf(stderr, "built without TLS\n");
        return 2;
#endif
    }
    auto listener = tcp::Listener::bind(*loop, Mira::transport::Endpoint::loopback(static_cast<std::uint16_t>(port)));
    if (!listener) return 1;
    std::printf("PORT=%u\n", static_cast<unsigned>(listener->local_endpoint().port()));
    std::fflush(stdout);
    int status = 1;
    const auto ran = loop->run_until_complete(run(*listener, lifetime, status));
    return ran ? status : 1;
}
