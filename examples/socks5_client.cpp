// HTTP/1.1 GET through a SOCKS5 proxy with Mira::client::dial_via_socks5.
// Usage: mira_socks5_client <proxy-port> <target-host> <target-port> [username password]
//
// The proxy is 127.0.0.1:<proxy-port>; the target host is sent to the proxy
// unresolved (domain) or as an address literal. Exits 0 only for a 2xx
// response whose body was fully read, within a 5 s total deadline.
#include <mira/client/socks5.hpp>
#include <mira/core/event_loop.hpp>
#include <mira/http/client.hpp>

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <string>
#include <string_view>

namespace socks = Mira::socks;
using namespace std::chrono_literals;

namespace {

Mira::Task<Mira::Result<std::string>> fetch(Mira::EventLoop& loop, Mira::transport::Resolver& resolver,
                                            std::uint16_t proxy_port, socks::Address target,
                                            socks::ClientOptions options) {
    Mira::transport::tcp::DialOptions dial;
    dial.io.deadline = Mira::Clock::now() + 5s;
    const auto io = dial.io;
    auto tunnel = co_await Mira::client::dial_via_socks5(loop, resolver, "127.0.0.1", proxy_port,
                                                         target, options, dial);
    if (!tunnel) co_return Mira::fail(tunnel.error());
    Mira::http::ClientConnection client{tunnel->socket};
    Mira::http::Request request;
    request.target = "/";
    request.headers.append("Host", target.kind() == socks::Address::Kind::ipv6
                                       ? "[" + target.host() + "]"
                                       : target.host());
    request.headers.append("Connection", "close");
    auto started = co_await client.start(request, {}, io);
    if (!started) co_return Mira::fail(started.error());
    std::string body;
    for (;;) {
        auto chunk = co_await client.read_body();
        if (!chunk) co_return Mira::fail(chunk.error());
        if (chunk->empty()) break;
        body.append(reinterpret_cast<const char*>(chunk->data()), chunk->size());
    }
    const auto status = client.response().status;
    tunnel->socket.close();
    if (status < 200 || status > 299) co_return Mira::fail(Mira::Errc::invalid_argument);
    co_return body;
}

Mira::Task<void> run(Mira::EventLoop& loop, Mira::transport::Resolver& resolver, std::uint16_t port,
                     socks::Address target, socks::ClientOptions options, int& status) {
    auto body = co_await fetch(loop, resolver, port, std::move(target), std::move(options));
    if (!body) {
        std::fprintf(stderr, "socks5 fetch failed: %s\n", body.error().message().c_str());
        co_return;
    }
    std::printf("SOCKS5 OK: %s\n", body->c_str());
    status = 0;
}

}  // namespace

int main(int argc, char** argv) {
    unsigned proxy = 0, port = 0;
    const auto number = [](std::string_view text, unsigned& value) {
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
        return error == std::errc{} && end == text.data() + text.size();
    };
    if ((argc != 4 && argc != 6) || !number(argv[1], proxy) || !number(argv[3], port) ||
        proxy == 0 || proxy > 65535 || port == 0 || port > 65535) {
        std::fprintf(stderr, "usage: %s <proxy-port> <target-host> <target-port> [user pass]\n",
                     argv[0]);
        return 2;
    }
    auto target = socks::Address::parse(argv[2], static_cast<std::uint16_t>(port));
    if (!target) {
        std::fprintf(stderr, "invalid target host\n");
        return 2;
    }
    socks::ClientOptions options;
    if (argc == 6) {
        options.allow_no_auth = false;
        options.credentials = socks::Credentials{argv[4], argv[5]};
    }
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto loop = Mira::EventLoop::create();
    auto resolver = Mira::transport::Resolver::create();
    if (!loop || !resolver) return 1;
    int status = 1;
    const auto ran = loop->run_until_complete(
        run(*loop, *resolver, static_cast<std::uint16_t>(proxy), std::move(*target), options, status));
    return ran ? status : 1;
}
