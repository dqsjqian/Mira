// Usage: mira_h2_client <port> [127.0.0.1|::1] [timeout_ms=5000]
// Pairs with mira_h2_prior_knowledge_server; submit both streams before pumping.
#include <mira/core/event_loop.hpp>
#include <mira/core/operation.hpp>
#include <mira/core/task.hpp>
#include <mira/http2/connection.hpp>
#include <mira/transport/tcp.hpp>

#include <array>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace {

template <typename Integer>
bool parse_number(std::string_view text, Integer& value) {
    if (text.empty()) return false;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc{} && end == text.data() + text.size();
}

struct Response {
    std::int32_t id = 0;
    std::string body;
    bool complete = false;
};

Mira::Task<Mira::Result<void>> request_pair(Mira::EventLoop& loop,
                                           Mira::transport::Endpoint endpoint,
                                           Mira::OperationOptions options) {
    auto connected = co_await Mira::transport::tcp::connect(loop, endpoint, {}, options);
    if (!connected) co_return Mira::fail(connected.error());
    auto socket = std::move(*connected);
    auto created = Mira::http2::Session::create(Mira::http2::Role::client);
    if (!created) co_return Mira::fail(created.error());
    Mira::http2::Connection connection{socket, std::move(*created)};
    std::array<Response, 2> responses{};

    // Queue both requests on one connection before performing any I/O.
    for (auto& response : responses) {
        Mira::http2::Headers headers{
            {":method", "GET"}, {":scheme", "http"},
            {":authority", endpoint.to_string()}, {":path", "/"}};
        auto submitted = connection.session().request(headers);
        if (!submitted) co_return Mira::fail(submitted.error());
        response.id = *submitted;
    }

    std::size_t completed = 0;
    while (completed < responses.size()) {
        auto pumped = co_await connection.pump(options);
        if (!pumped) co_return Mira::fail(pumped.error());
        for (auto& response : responses) {
            if (response.complete) continue;
            const auto* stream = connection.session().stream(response.id);
            if (stream == nullptr) co_return Mira::fail(std::make_error_code(std::errc::protocol_error));
            if (stream->error) co_return Mira::fail(stream->error);
            if (stream->wire_error != 0) co_return Mira::fail(std::make_error_code(std::errc::protocol_error));

            // Return flow-control credit each round instead of waiting for END_STREAM.
            auto body = connection.session().take_body(response.id);
            if (!body) co_return Mira::fail(body.error());
            const std::string expected = "served by Mira's HTTP/2 server, stream " +
                                         std::to_string(response.id);
            if (body->size() > expected.size() - response.body.size())
                co_return Mira::fail(std::make_error_code(std::errc::protocol_error));
            if (!body->empty()) {
                response.body.append(reinterpret_cast<const char*>(body->data()), body->size());
            }
            if (!stream->closed) continue;

            bool status_ok = false;
            bool content_type_ok = false;
            for (const auto& [name, value] : stream->headers) {
                if (name == ":status") status_ok = value == "200";
                if (name == "content-type") content_type_ok = value == "text/plain";
            }
            if (!stream->headers_received || !stream->remote_end || !status_ok ||
                !content_type_ok || response.body != expected) {
                std::fprintf(stderr, "invalid h2 response on stream %d\n", response.id);
                co_return Mira::fail(std::make_error_code(std::errc::protocol_error));
            }
            auto released = connection.session().release(response.id);
            if (!released) co_return Mira::fail(released.error());
            response.complete = true;
            ++completed;
            std::printf("h2 stream %d status 200 body: %s\n", response.id, response.body.c_str());
        }
    }
    auto closing = connection.session().goaway();
    if (!closing) co_return Mira::fail(closing.error());
    auto flushed = co_await connection.flush(options);
    if (!flushed) co_return Mira::fail(flushed.error());
    std::printf("h2 client completed %zu concurrent requests\n", completed);
    co_return Mira::Result<void>{};
}

Mira::Task<void> run_client(Mira::EventLoop& loop, Mira::transport::Endpoint endpoint,
                            Mira::OperationOptions options, int& exit_code) {
    const auto result = co_await request_pair(loop, endpoint, options);
    if (!result) {
        std::fprintf(stderr, "h2 client: %s\n", result.error().message().c_str());
        co_return;
    }
    exit_code = 0;
}

} // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    std::uint32_t timeout_ms = 5000;
    const std::string_view address = argc > 2 ? argv[2] : "127.0.0.1";
    if (argc < 2 || argc > 4 || !parse_number(argv[1], port) || port == 0 ||
        (address != "127.0.0.1" && address != "::1") ||
        (argc > 3 && (!parse_number(argv[3], timeout_ms) || timeout_ms == 0 ||
                      timeout_ms > 60000))) {
        std::fprintf(stderr, "usage: %s <port: 1..65535> [127.0.0.1|::1] "
                             "[timeout_ms: 1..60000]\n", argv[0]);
        return 2;
    }
#ifdef SIGPIPE
    if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        std::fprintf(stderr, "could not ignore SIGPIPE\n");
        return 1;
    }
#endif
    auto endpoint = Mira::transport::Endpoint::parse(address, port);
    if (!endpoint) {
        std::fprintf(stderr, "endpoint: %s\n", endpoint.error().message().c_str());
        return 1;
    }
    auto created = Mira::EventLoop::create();
    if (!created) {
        std::fprintf(stderr, "event loop: %s\n", created.error().message().c_str());
        return 1;
    }
    auto& loop = *created;
    // One absolute deadline covers connect, every pump, and the final flush.
    Mira::OperationOptions options{
        .deadline = Mira::Clock::now() + std::chrono::milliseconds(timeout_ms)};
    int exit_code = 1;
    const auto ran = loop.run_until_complete(run_client(loop, *endpoint, options, exit_code));
    if (!ran) {
        std::fprintf(stderr, "run: %s\n", ran.error().message().c_str());
        return 1;
    }
    return exit_code;
}
