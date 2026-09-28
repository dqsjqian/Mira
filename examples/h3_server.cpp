// Single-connection HTTP/3 example with a caller-provided localhost certificate.
// Usage: mira_h3_server <port: 0..65535> <certificate.pem> <private-key.pem>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <map>
#include <mira/core/event_loop.hpp>
#include <mira/http3/connection.hpp>
#include <mira/transport/udp.hpp>
#include <string>
#include <string_view>

using H3Connection = Mira::http3::Connection<Mira::transport::udp::Socket>;
using namespace std::chrono_literals;

namespace {
std::span<const std::byte> bytes_of(std::string_view text) {
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

Mira::Task<void>
serve(Mira::transport::udp::Socket socket, std::string cert, std::string key, int& status) {
    const auto local = socket.local_endpoint();
    if (!local) co_return;
    std::printf(
        "h3 server listening on %s\ncertificate: %s\n", local->to_string().c_str(), cert.c_str());
    std::fflush(stdout);
    // One budget covers Initial, handshake, requests and shutdown. Continuous
    // input cannot extend the lifetime indefinitely.
    const Mira::OperationOptions io{.deadline = Mira::Clock::now() + 30s};
    std::array<std::byte, 65536> initial{};
    auto datagram = co_await socket.receive_from(initial, io);
    if (!datagram) {
        std::fprintf(stderr, "receive: %s\n", datagram.error().message().c_str());
        co_return;
    }
    Mira::quic::Options options;
    options.local = *local;
    options.remote = datagram->peer;
    options.certificate_file = cert;
    options.private_key_file = key;
    options.alpn = "h3";
    auto accepted = co_await H3Connection::serve(
        std::move(socket), std::move(options), {}, {initial.data(), datagram->size}, io);
    if (!accepted) {
        std::fprintf(stderr, "handshake: %s\n", accepted.error().message().c_str());
        co_return;
    }
    auto server = std::move(*accepted);
    std::map<std::int64_t, std::string> paths;
    std::size_t answered = 0;
    for (;;) {
        auto events = co_await server.receive_events(io);
        if (!events) {
            if (answered && events.error() == Mira::Errc::eof)
                status = 0;
            else
                std::fprintf(stderr, "serve: %s\n", events.error().message().c_str());
            co_return;
        }
        for (const auto& event : *events) {
            using Kind = Mira::http3::Event::Kind;
            switch (event.kind) {
            case Kind::headers:
                for (const auto& [name, value] : event.fields) {
                    if (name == ":path") {
                        if (!paths.contains(event.stream_id) && paths.size() >= 64) {
                            std::fprintf(stderr, "too many unfinished requests\n");
                            co_return;
                        }
                        paths[event.stream_id] = value;
                    }
                }
                break;
            case Kind::body:
                if (auto consumed = server.consume(event.stream_id, event.data.size()); !consumed) {
                    std::fprintf(stderr, "consume: %s\n", consumed.error().message().c_str());
                    co_return;
                }
                break;
            case Kind::end: {
                auto path = paths.find(event.stream_id);
                if (path == paths.end()) {
                    std::fprintf(stderr, "request has no path\n");
                    co_return;
                }
                const std::string body = "served by Mira's HTTP/3 server, stream " +
                                         std::to_string(event.stream_id) + ", path " + path->second;
                Mira::http3::Headers fields{{":status", "200"},
                                            {"content-type", "text/plain"},
                                            {"content-length", std::to_string(body.size())}};
                auto sent = co_await server.respond(event.stream_id, fields, bytes_of(body), io);
                if (!sent) {
                    std::fprintf(stderr, "respond: %s\n", sent.error().message().c_str());
                    co_return;
                }
                paths.erase(path);
                ++answered;
                break;
            }
            case Kind::reset:
                paths.erase(event.stream_id);
                break;
            case Kind::goaway:
                break;
            }
        }
    }
}
}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    if (argc != 4) {
        std::fprintf(
            stderr, "usage: %s <port: 0..65535> <certificate.pem> <private-key.pem>\n", argv[0]);
        return 2;
    }
    const std::string_view text{argv[1]};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
    if (error != std::errc{} || end != text.data() + text.size()) return 2;
    auto loop = Mira::EventLoop::create();
    if (!loop) return 1;
    auto socket =
        Mira::transport::udp::Socket::bind(*loop, Mira::transport::Endpoint::loopback(port));
    if (!socket) return 1;
    int status = 1;
    auto ran = loop->run_until_complete(serve(std::move(*socket), argv[2], argv[3], status));
    if (!ran) {
        std::fprintf(stderr, "run: %s\n", ran.error().message().c_str());
        return 1;
    }
    return status;
}
