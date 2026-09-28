// Admission-bounded TCP service with deadline-driven graceful shutdown.
// Usage: mira_managed_echo_server [port=0] [max-connections=64] [lifetime-ms=5000]
#include <mira/core/stream.hpp>
#include <mira/transport/server.hpp>

#include <array>
#include <charconv>
#include <cstdio>
#include <string_view>

namespace {
Mira::Task<Mira::Result<void>> echo(Mira::transport::tcp::Socket& socket, Mira::OperationOptions io) {
    std::array<std::byte, 16384> buffer{};
    for (;;) {
        auto n = co_await socket.read_some(buffer, io);
        if (!n) {
            if (n.error() == Mira::Errc::eof) co_return Mira::Result<void>{};
            co_return Mira::fail(n.error());
        }
        auto sent = co_await Mira::write_all(socket, std::span<const std::byte>(buffer).first(*n), io);
        if (!sent) co_return sent;
    }
}
Mira::Task<void> run(Mira::transport::tcp::Listener& listener, unsigned maximum,
                     unsigned lifetime, int& status) {
    Mira::transport::tcp::ServeOptions options;
    options.max_connections = maximum;
    options.io.deadline = Mira::Clock::now() + std::chrono::milliseconds(lifetime);
    auto result = co_await Mira::transport::tcp::serve(listener, &echo, options);
    if (!result) {
        std::fprintf(stderr, "serve: %s\n", result.error().message().c_str());
        co_return;
    }
    std::printf("accepted=%zu rejected=%zu completed=%zu failed=%zu peak_active=%zu\n",
                result->accepted, result->rejected, result->completed, result->failed,
                result->peak_active);
    status = 0;
}
}
int main(int argc, char** argv) {
    unsigned values[]{0, 64, 5000};
    if (argc > 4) return 2;
    for (int i = 1; i < argc; ++i) {
        const std::string_view text{argv[i]};
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), values[i - 1]);
        if (error != std::errc{} || end != text.data() + text.size()) return 2;
    }
    if (values[0] > 65535 || !values[1] || values[1] > 65536 || !values[2] || values[2] > 3600000)
        return 2;
    auto loop = Mira::EventLoop::create();
    if (!loop) return 1;
    auto listener = Mira::transport::tcp::Listener::bind(
        *loop, Mira::transport::Endpoint::loopback(static_cast<std::uint16_t>(values[0])));
    if (!listener) return 1;
    std::printf("PORT=%u\n", static_cast<unsigned>(listener->local_endpoint().port()));
    std::fflush(stdout);
    int status = 1;
    auto result = loop->run_until_complete(run(*listener, values[1], values[2], status));
    return result ? status : 1;
}
