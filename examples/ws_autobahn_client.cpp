#include <mira/core/event_loop.hpp>
#include <mira/transport/tcp.hpp>
#include <mira/ws/connection.hpp>

#include <charconv>
#include <csignal>
#include <cstdio>
#include <string_view>

namespace {
Mira::OperationOptions deadline(unsigned seconds) {
    return {.deadline = Mira::Clock::now() + std::chrono::seconds(seconds)};
}

Mira::Task<Mira::Result<std::string>> session(
    Mira::EventLoop& loop, Mira::transport::Endpoint endpoint, std::string target,
    bool echo, unsigned timeout) {
    auto options = deadline(timeout);
    auto connected = co_await Mira::transport::tcp::connect(loop, endpoint, {}, options);
    if (!connected) co_return Mira::fail(connected.error());
    auto socket = std::move(*connected);
    // Raise harness limits for official large-message cases without changing library defaults.
    Mira::ws::Limits limits{.max_frame = 64 * 1024 * 1024, .max_message = 64 * 1024 * 1024};
    Mira::ws::Connection connection(socket, Mira::ws::Role::client, limits);
    auto handshake = co_await connection.handshake(endpoint.to_string(), std::move(target), options);
    if (!handshake) co_return Mira::fail(handshake.error());
    std::string response;
    for (;;) {
        auto message = co_await connection.read_message(options);
        if (!message) {
            // Official reports decide malformed-frame and peer-disconnect outcomes, not the harness.
            if (echo && message.error() != Mira::Errc::timed_out && message.error() != Mira::Errc::cancelled)
                co_return response;
            co_return Mira::fail(message.error());
        }
        if (message->opcode == Mira::ws::Opcode::close) {
            // Let the server close TCP first so a valid RFC6455 close is not reported as premature.
            std::array<std::byte, 1024> discarded{};
            auto closing = deadline(5);
            while (co_await socket.read_some(discarded, closing)) {}
            co_return response;
        }
        if (echo) {
            auto sent = co_await connection.send(std::move(*message), options);
            if (!sent) co_return Mira::fail(sent.error());
        } else {
            if (response.size() + message->payload.size() > 65536)
                co_return Mira::fail(Mira::Errc::limit_exceeded);
            response.append(reinterpret_cast<const char*>(message->payload.data()), message->payload.size());
        }
    }
}

Mira::Task<void> run(Mira::EventLoop& loop, Mira::transport::Endpoint endpoint,
                     unsigned timeout, bool query, std::string target, int& status) {
    if (query) {
        auto response = co_await session(loop, endpoint, std::move(target), false, timeout);
        if (!response) {
            std::fprintf(stderr, "control request: %s\n", response.error().message().c_str());
            co_return;
        }
        std::printf("%s\n", response->c_str());
        status = 0;
        co_return;
    }
    auto response = co_await session(loop, endpoint, "/getCaseCount", false, timeout);
    if (!response) co_return;
    unsigned count = 0;
    auto [end, error] = std::from_chars(response->data(), response->data() + response->size(), count);
    if (error != std::errc{} || end != response->data() + response->size() || !count || count > 10000)
        co_return;
    std::printf("CASE_COUNT=%u\n", count);
    std::fflush(stdout);
    unsigned errors = 0;
    for (unsigned index = 1; index <= count; ++index) {
        auto result = co_await session(loop, endpoint,
            "/runCase?case=" + std::to_string(index) + "&agent=Mira-client", true, timeout);
        std::printf("CASE=%u/%u harness=%s\n", index, count, result ? "completed" : "error");
        std::fflush(stdout);
        if (!result) {
            ++errors;
            std::fprintf(stderr, "case %u: %s\n", index, result.error().message().c_str());
        }
    }
    auto reports = co_await session(loop, endpoint, "/updateReports?agent=Mira-client", false, timeout);
    if (!reports) co_return;
    std::printf("HARNESS_ERRORS=%u\n", errors);
    status = errors == 0 ? 0 : 1;
}
}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 4) return 2;
    std::uint16_t port = 0;
    const std::string_view text(argv[1]);
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
    if (error != std::errc{} || end != text.data() + text.size() || !port) return 2;
    unsigned timeout = 300;
    const bool query = argc == 4 && std::string_view(argv[2]) == "--query";
    if (argc == 4 && !query) return 2;
    if (argc == 3) {
        const std::string_view seconds(argv[2]);
        auto [last, err] = std::from_chars(seconds.data(), seconds.data() + seconds.size(), timeout);
        if (err != std::errc{} || last != seconds.data() + seconds.size() || !timeout || timeout > 3600)
            return 2;
    }
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto loop = Mira::EventLoop::create();
    if (!loop) return 1;
    int status = 1;
    auto ran = loop->run_until_complete(run(*loop, Mira::transport::Endpoint::loopback(port),
                                           timeout, query, query ? argv[3] : "", status));
    return ran ? status : 1;
}
