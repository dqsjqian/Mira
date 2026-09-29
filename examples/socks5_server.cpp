// Loopback SOCKS5 CONNECT proxy (RFC 1928/1929) built on Mira::socks.
// Usage: mira_socks5_server [port=0] [lifetime-ms=60000] [username password]
//
// Prints "PORT=<n>". Each client is authenticated (username/password when
// given, otherwise no-auth), the target is resolved by the proxy and dialled
// with one deadline, the dial outcome is mapped to a SOCKS reply, and the two
// sockets are relayed until both directions finish. BIND/UDP ASSOCIATE are
// refused with REP 0x07. Admission is bounded; this is a demonstration, not a
// hardened public proxy (no ACLs, no per-user quotas).
#include <mira/core/stream.hpp>
#include <mira/core/task_scope.hpp>
#include <mira/socks/socks5.hpp>
#include <mira/transport/dial.hpp>
#include <mira/transport/resolver.hpp>
#include <mira/transport/server.hpp>

#include <array>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>

namespace tcp = Mira::transport::tcp;
namespace socks = Mira::socks;
using namespace std::chrono_literals;

namespace {

struct Config {
    std::optional<socks::Credentials> credentials;
    Mira::transport::Resolver* resolver = nullptr;
    Mira::EventLoop* loop = nullptr;
};
Config config;

socks::ReplyCode reply_for(const Mira::Error& error) {
    if (error == Mira::Errc::timed_out) return socks::ReplyCode::ttl_expired;
    if (error == std::errc::connection_refused) return socks::ReplyCode::connection_refused;
    if (error == std::errc::network_unreachable) return socks::ReplyCode::network_unreachable;
    if (error == std::errc::host_unreachable) return socks::ReplyCode::host_unreachable;
    return socks::ReplyCode::host_unreachable;
}

/// Copy one direction until EOF, then half-close the destination.
Mira::Task<void> pump(tcp::Socket& from, tcp::Socket& to, Mira::OperationOptions io,
                      std::stop_source& abort) {
    std::array<std::byte, 16384> buffer{};
    for (;;) {
        auto n = co_await from.read_some(buffer, io);
        if (!n) {
            if (n.error() == Mira::Errc::eof) static_cast<void>(to.shutdown_send());
            else abort.request_stop();
            co_return;
        }
        auto sent = co_await Mira::write_all(to, std::span<const std::byte>{buffer}.first(*n), io);
        if (!sent) {
            abort.request_stop();
            co_return;
        }
    }
}

Mira::Task<Mira::Result<void>> handle(tcp::Socket& client, Mira::OperationOptions io) {
    socks::ServerOptions options;
    options.allow_no_auth = !config.credentials;
    if (config.credentials) {
        options.verify = [](std::string_view user, std::string_view pass) {
            return user == config.credentials->username && pass == config.credentials->password;
        };
    }
    auto handshake_io = io;
    handshake_io.deadline = Mira::Clock::now() + 10s;
    auto request = co_await socks::accept(client, options, handshake_io);
    if (!request) co_return Mira::fail(request.error());
    if (request->command != socks::Command::connect) {
        static_cast<void>(co_await socks::reply(client, socks::ReplyCode::command_not_supported, {},
                                                handshake_io));
        co_return Mira::Result<void>{};
    }
    tcp::DialOptions dial;
    dial.io = handshake_io;
    auto upstream = co_await tcp::dial(*config.loop, *config.resolver, request->target.host(),
                                       request->target.port(), dial);
    if (!upstream) {
        static_cast<void>(co_await socks::reply(client, reply_for(upstream.error()), {}, handshake_io));
        co_return Mira::Result<void>{};
    }
    socks::Address bound;
    if (auto local = upstream->local_endpoint()) {
        if (auto parsed = socks::Address::parse(local->address(), local->port())) bound = *parsed;
    }
    auto replied = co_await socks::reply(client, socks::ReplyCode::succeeded, bound, handshake_io);
    if (!replied) co_return Mira::fail(replied.error());

    // Either direction failing cancels the other; EOF only half-closes.
    std::stop_source abort;
    std::stop_callback forward{io.stop, [&abort] { abort.request_stop(); }};
    const Mira::OperationOptions relay{.stop = abort.get_token(), .deadline = io.deadline};
    Mira::TaskScope scope;
    scope.spawn(pump(client, *upstream, relay, abort));
    scope.spawn(pump(*upstream, client, relay, abort));
    co_await scope.join();
    co_return Mira::Result<void>{};
}

Mira::Task<void> run(tcp::Listener& listener, unsigned lifetime_ms, int& status) {
    tcp::ServeOptions options;
    options.max_connections = 64;
    options.io.deadline = Mira::Clock::now() + std::chrono::milliseconds(lifetime_ms);
    auto served = co_await tcp::serve(listener, &handle, options);
    if (!served) {
        std::fprintf(stderr, "serve: %s\n", served.error().message().c_str());
        co_return;
    }
    status = 0;
}

}  // namespace

int main(int argc, char** argv) {
    unsigned port = 0, lifetime = 60000;
    const auto number = [](std::string_view text, unsigned& value) {
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
        return error == std::errc{} && end == text.data() + text.size();
    };
    if (argc > 5 || argc == 4 || (argc > 1 && !number(argv[1], port)) ||
        (argc > 2 && !number(argv[2], lifetime)) || port > 65535 || lifetime == 0 ||
        lifetime > 3600000) {
        std::fprintf(stderr, "usage: %s [port] [lifetime-ms] [username password]\n", argv[0]);
        return 2;
    }
    if (argc == 5) {
        config.credentials = socks::Credentials{argv[3], argv[4]};
        if (config.credentials->username.empty() || config.credentials->username.size() > 255 ||
            config.credentials->password.empty() || config.credentials->password.size() > 255) {
            std::fprintf(stderr, "credentials must be 1..255 bytes\n");
            return 2;
        }
    }
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto loop = Mira::EventLoop::create();
    auto resolver = Mira::transport::Resolver::create();
    if (!loop || !resolver) return 1;
    config.loop = &*loop;
    config.resolver = &*resolver;
    auto listener = tcp::Listener::bind(
        *loop, Mira::transport::Endpoint::loopback(static_cast<std::uint16_t>(port)));
    if (!listener) {
        std::fprintf(stderr, "bind: %s\n", listener.error().message().c_str());
        return 1;
    }
    std::printf("PORT=%u\n", static_cast<unsigned>(listener->local_endpoint().port()));
    std::fflush(stdout);
    int status = 1;
    const auto ran = loop->run_until_complete(run(*listener, lifetime, status));
    return ran ? status : 1;
}
