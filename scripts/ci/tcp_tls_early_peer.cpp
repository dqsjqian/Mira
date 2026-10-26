#include "mira/tls/stream.hpp"
#include "mira/transport/tcp.hpp"

#include <array>
#include <charconv>
#include <cstdio>
#include <string>
#include <string_view>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {
std::span<const std::byte> bytes_of(std::string_view text) {
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}
const char* status_name(EarlyDataStatus status) {
    switch (status) {
    case EarlyDataStatus::accepted: return "accepted";
    case EarlyDataStatus::rejected: return "rejected";
    case EarlyDataStatus::pending: return "pending";
    case EarlyDataStatus::not_attempted: return "not_attempted";
    }
    return "invalid";
}

template <typename Stream>
Task<Result<void>> expect_response(Stream& stream, std::string_view expected, OperationOptions options) {
    std::array<std::byte, 64> data{};
    std::size_t received = 0;
    while (received < expected.size()) {
        auto read = co_await stream.read_some(std::span{data}.subspan(received, expected.size() - received), options);
        if (!read) co_return fail(read.error());
        if (*read == 0) co_return fail(Errc::eof);
        received += *read;
    }
    if (std::string_view(reinterpret_cast<const char*>(data.data()), received) != expected)
        co_return fail(Errc::internal);
    co_return Result<void>{};
}

Task<Result<void>> serve(EventLoop& loop, tcp::Listener& listener, const tls::Context& context) {
    for (unsigned index = 0; index < 3; ++index) {
        const OperationOptions options{.deadline = Clock::now() + 10s};
        auto socket = co_await listener.accept(options);
        if (!socket) co_return fail(socket.error());
        auto stream = tls::Stream<tcp::Socket>::create(loop, *socket, context);
        if (!stream) co_return fail(stream.error());
        auto handshake = co_await stream->handshake(options);
        if (!handshake) co_return fail(handshake.error());
        const auto status = stream->early_data_status();
        std::string payload;
        if (index == 0 || status == EarlyDataStatus::accepted) {
            std::array<std::byte, 64> data{};
            auto read = co_await stream->read_some(data, options);
            if (!read) co_return fail(read.error());
            payload.assign(reinterpret_cast<const char*>(data.data()), *read);
        }
        const std::string response = std::string(status_name(status)) + ":" + payload + "\n";
        auto written = co_await write_all(*stream, bytes_of(response), options);
        if (!written) co_return fail(written.error());
        auto shutdown = co_await stream->shutdown(options);
        if (!shutdown) co_return fail(shutdown.error());
        std::printf("RESULT=%s\n", response.c_str());
        std::fflush(stdout);
    }
    co_return Result<void>{};
}

Task<Result<void>> connect_twice(EventLoop& loop, Endpoint endpoint, const tls::Context& context) {
    std::optional<tls::SessionTicket> ticket;
    for (unsigned index = 0; index < 2; ++index) {
        const OperationOptions options{.deadline = Clock::now() + 10s};
        auto socket = co_await tcp::connect(loop, endpoint, {}, options);
        if (!socket) co_return fail(socket.error());
        auto stream = tls::Stream<tcp::Socket>::create(loop, *socket, context, "localhost");
        if (!stream) co_return fail(stream.error());
        if (ticket) {
            auto resumed = stream->resume(std::move(*ticket));
            if (!resumed) co_return fail(resumed.error());
            ticket.reset();
        }
        if (index == 0) {
            auto handshake = co_await stream->handshake(options);
            if (!handshake) co_return fail(handshake.error());
        } else {
            auto handshake = co_await stream->handshake_early_data(bytes_of("safe-tcp\n"),
                EarlyDataPolicy::replay_safe, options);
            if (!handshake) co_return fail(handshake.error());
            if (stream->early_data_status() != EarlyDataStatus::accepted)
                co_return fail(Errc::internal);
        }
        // Ordered after every handshake write: seeing this marker at s_server
        // proves it also read any accidentally repeated 1-RTT application data.
        const std::string marker = std::string("\nMIRA-DRAIN-") + status_name(stream->early_data_status()) + "\n";
        auto drained = co_await write_all(*stream, bytes_of(marker), options);
        if (!drained) co_return fail(drained.error());
        std::printf("READY=%s\n", status_name(stream->early_data_status()));
        std::fflush(stdout);
        const std::string_view expected = index == 0 ? "ticket-ready\n" : "early-ready\n";
        auto response = co_await expect_response(*stream, expected, options);
        if (!response) co_return fail(response.error());
        if (index == 0) {
            auto captured = stream->take_session();
            if (!captured) co_return fail(captured.error());
            if (!captured->has_value()) co_return fail(Errc::internal);
            ticket = std::move(**captured);
        }
        std::printf("RECEIVED=%s\n", status_name(stream->early_data_status()));
        std::fflush(stdout);
        auto drain_ready = co_await expect_response(*stream, "drain-ready\n", options);
        if (!drain_ready) co_return fail(drain_ready.error());
        // The harness closes s_server's interactive connection with its q command.
        // Windows s_server otherwise blocks on redirected stdin before reading
        // close_notify; graceful shutdown is covered by the dedicated TLS tests.
        std::printf("CLIENT=%s\n", status_name(stream->early_data_status()));
        std::fflush(stdout);
        std::array<char, 16> next{};
        if (!std::fgets(next.data(), static_cast<int>(next.size()), stdin) ||
            std::string_view(next.data()) != "next\n") co_return fail(Errc::internal);
    }
    co_return Result<void>{};
}

Task<void> capture(Task<Result<void>> task, Result<void>& result) {
    result = co_await std::move(task);
}
}

int main(int argc, char** argv) {
    if (argc != 4) return 2;
    auto loop = EventLoop::create();
    if (!loop) return 2;
    if (std::string_view(argv[1]) == "server") {
        auto store = MemoryReplayStore::create();
        if (!store) return 2;
        auto context = tls::Context::server(tls::Context::ServerConfig{
            .cert_file = argv[2], .key_file = argv[3], .min_version = "1.3",
            .early_data = EarlyDataPolicy::replay_safe, .replay_store = *store});
        auto listener = tcp::Listener::bind(*loop, Endpoint::loopback(0));
        if (!context || !listener) return 2;
        std::printf("PORT=%u\n", static_cast<unsigned>(listener->local_endpoint().port()));
        std::fflush(stdout);
        Result<void> result;
        auto run = loop->run_until_complete(capture(serve(*loop, *listener, *context), result));
        if (!run || !result) return 1;
        return 0;
    }
    if (std::string_view(argv[1]) == "client") {
        unsigned port = 0;
        const std::string_view value(argv[3]);
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), port);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || !port || port > 65535)
            return 2;
        auto context = tls::Context::client(argv[2]);
        if (!context) return 2;
        Result<void> result;
        auto run = loop->run_until_complete(capture(connect_twice(*loop,
            Endpoint::loopback(static_cast<std::uint16_t>(port)), *context), result));
        if (!run || !result) {
            const auto error = !run ? run.error() : result.error();
            std::fprintf(stderr, "%s\n", error.message().c_str());
            return 1;
        }
        return 0;
    }
    return 2;
}
