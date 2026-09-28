// Submit two concurrent requests over one CA- and hostname-verified QUIC connection.
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <mira/core/event_loop.hpp>
#include <mira/http3/connection.hpp>
#include <mira/transport/udp.hpp>
#include <stdexcept>
#include <string>
#include <string_view>

using H3Connection = Mira::http3::Connection<Mira::transport::udp::Socket>;
using namespace std::chrono_literals;

namespace {
template<class T>
T require(Mira::Result<T> result) {
    if (!result) throw std::runtime_error(result.error().message());
    return std::move(*result);
}
void require(Mira::Result<void> result) {
    if (!result) throw std::runtime_error(result.error().message());
}

Mira::Task<void> run(Mira::EventLoop& loop, std::uint16_t port, std::string ca) {
    const Mira::OperationOptions io{.deadline = Mira::Clock::now() + 20s};
    Mira::quic::Options options;
    options.local = Mira::transport::Endpoint::loopback(0);
    options.remote = Mira::transport::Endpoint::loopback(port);
    options.ca_file = ca;
    options.peer_name = "localhost";
    options.alpn = "h3";
    auto client = require(co_await H3Connection::connect(loop, options, {}, io));
    const std::array<std::string, 2> paths{"/first", "/second"};
    std::array<std::int64_t, 2> streams{};
    for (std::size_t i = 0; i < paths.size(); ++i) {
        Mira::http3::Headers headers{{":method", "GET"},
                                     {":scheme", "https"},
                                     {":authority", "localhost"},
                                     {":path", paths[i]}};
        streams[i] = require(co_await client.request(headers));
    }
    for (std::size_t i = 0; i < paths.size(); ++i) {
        auto head = require(co_await client.await_head(streams[i], io));
        bool ok = false;
        for (const auto& [name, value] : head.fields)
            if (name == ":status" && value == "200") ok = true;
        if (!ok) throw std::runtime_error("unexpected HTTP status");
        std::string body;
        for (;;) {
            auto chunk = require(co_await client.read_body(streams[i], io));
            if (!chunk.data.empty())
                body.append(reinterpret_cast<const char*>(chunk.data.data()), chunk.data.size());
            require(client.consume(streams[i], chunk.data.size()));
            if (chunk.fin) break;
        }
        const std::string expected = "served by Mira's HTTP/3 server, stream " +
                                     std::to_string(streams[i]) + ", path " + paths[i];
        if (body != expected) throw std::runtime_error("response body mismatch: " + body);
        std::printf("h3 response stream=%lld path=%s status=200 verified\n",
                    static_cast<long long>(streams[i]),
                    paths[i].c_str());
    }
    require(co_await client.close(0, io));
    std::puts("h3 client: ok (2 requests, verified localhost certificate)");
}
}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <port: 1..65535> <ca.pem>\n", argv[0]);
        return 2;
    }
    std::uint16_t port = 0;
    const std::string_view text{argv[1]};
    const auto [end, parse_error] = std::from_chars(text.data(), text.data() + text.size(), port);
    if (parse_error != std::errc{} || end != text.data() + text.size() || !port) return 2;
    try {
        auto loop = require(Mira::EventLoop::create());
        require(loop.run_until_complete(run(loop, port, argv[2])));
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "h3 client: %s\n", error.what());
        return 1;
    }
}
