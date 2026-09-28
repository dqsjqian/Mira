#include "mira/http3/server.hpp"
#include "mira/transport/udp.hpp"

#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>

using namespace Mira;
using namespace std::chrono_literals;

namespace {
template<class T> T require(Result<T> result) {
    if (!result) throw std::runtime_error(result.error().message());
    return std::move(*result);
}
void require(Result<void> result) {
    if (!result) throw std::runtime_error(result.error().message());
}

Task<void> serve(EventLoop& loop, const char* cert, const char* key, std::uint16_t port) {
    auto socket = require(transport::udp::Socket::bind(loop, transport::Endpoint::loopback(port)));
    quic::Options options;
    options.local = require(socket.local_endpoint());
    options.certificate_file = cert;
    options.private_key_file = key;
    options.max_buffered_bytes = 64 * 1024;
    http3::Limits limits;
    limits.max_buffered_body = 64 * 1024;
    limits.max_header_bytes = 16 * 1024;
    limits.max_streams = 16;
    auto server = require(http3::make_server(options, {}, limits));
    std::cout << "HTTP/3 multi-client server on " << options.local.to_string() << '\n';
    std::array<std::byte, 65536> buffer{};
    for (;;) {
        auto now = quic::detail::now_ns();
        require(server.handle_expiry(now));
        for (auto id : server.connections()) {
            auto* engine = server.connection(id);
            for (auto& event : engine->take_events()) {
                if (event.kind == http3::Event::Kind::body) {
                    require(engine->consume(event.stream_id, event.data.size()));
                } else if (event.kind == http3::Event::Kind::end) {
                    const http3::Headers fields{{":status", "200"}, {"content-type", "text/plain"}};
                    const std::string text = "Mira HTTP/3 connection " + std::to_string(id) + "\n";
                    auto body = std::as_bytes(std::span(text));
                    auto response = engine->respond(event.stream_id, fields, body);
                    if (!response) (void)engine->cancel(event.stream_id);
                }
            }
        }
        // Await each send before polling again: no unbounded wire output queue.
        for (int burst = 0; burst < 64; ++burst) {
            auto result = server.poll(quic::detail::now_ns());
            if (!result) {
                std::cerr << "connection removed: " << result.error().message() << '\n';
                continue;
            }
            if (!*result) break;
            auto& packet = **result;
            auto sent = co_await socket.send_to(packet.data, packet.peer,
                                                {.deadline = Clock::now() + 1s});
            if (!sent) std::cerr << "UDP send: " << sent.error().message() << '\n';
        }
        now = quic::detail::now_ns();
        const auto expiry = server.expiry();
        const auto wait = std::min<std::uint64_t>(expiry > now ? expiry - now : 0, 10'000'000);
        auto deadline = Clock::now() + std::chrono::nanoseconds(wait);
        auto packet = co_await socket.receive_from(buffer, {.deadline = deadline});
        if (!packet) {
            if (packet.error() == Errc::timed_out) continue;
            throw std::runtime_error(packet.error().message());
        }
        auto received = server.ingest(packet->peer, std::span(buffer).first(packet->size),
                                       quic::detail::now_ns());
        if (!received) std::cerr << "packet rejected: " << received.error().message() << '\n';
    }
}
}  // namespace

int main(int argc, char** argv) {
    if (argc < 3 || argc > 4) {
        std::cerr << "usage: mira_h3_multi_server certificate.pem key.pem [port]\n";
        return 2;
    }
    try {
        auto port = argc == 4 ? std::stoul(argv[3]) : 4433;
        if (!port || port > 65535) throw std::runtime_error("invalid port");
        auto loop = require(EventLoop::create());
        require(loop.run_until_complete(serve(loop, argv[1], argv[2], static_cast<std::uint16_t>(port))));
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
