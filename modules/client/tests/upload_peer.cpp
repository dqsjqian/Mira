#include "mira/client/http.hpp"
#ifdef MIRA_CLIENT_TEST_TLS
#include "mira/client/https.hpp"
#endif

#include <charconv>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

using namespace Mira;
using namespace Mira::client;
using namespace std::chrono_literals;

namespace {
std::span<const std::byte> bytes(std::string_view text) {
    return std::as_bytes(std::span{text.data(), text.size()});
}
bool require(bool value, const char* label) {
    if (!value) std::fprintf(stderr, "failed: %s\n", label);
    return value;
}
template<typename Client>
Task<bool> upload(EventLoop& loop, Client& client, std::uint16_t port,
                  const std::string& marker, std::string& id) {
    for (unsigned round = 0; round != 4; ++round) {
        auto session = co_await client.acquire("localhost", port, {.deadline = Clock::now() + 10s});
        if (!session) std::fprintf(stderr, "acquire: %s / %d / %s\n", session.error().category().name(),
                                    session.error().value(), session.error().message().c_str());
        if (!require(session.has_value(), "acquire")) co_return false;
        http::Request request;
        request.method = http::Method::post;
        request.target = "/upload/" + std::to_string(round);
        const auto framing = round % 2 == 0 ? http::Framing::content_length : http::Framing::chunked;
        const auto started = co_await session->begin(std::move(request), framing,
            framing == http::Framing::content_length ? 32 * 8192 : 0);
        if (!require(started.has_value(), "begin")) co_return false;
        for (unsigned part = 0; part != 32; ++part) {
            const std::string piece(8192, static_cast<char>('a' + part % 26));
            const auto sent = co_await session->send_body(bytes(piece));
            if (!require(sent.has_value(), "send_body")) co_return false;
            if (part == 0) {
                const auto deadline = Clock::now() + 5s;
                const auto path = marker + "." + std::to_string(round);
                while (!std::filesystem::exists(path)) {
                    if (!require(Clock::now() < deadline, "first chunk observed before next production"))
                        co_return false;
                    if (!(co_await loop.sleep_for(1ms))) co_return false;
                }
            }
        }
        const auto finished = co_await session->finish();
        if (!require(finished.has_value(), "finish")) co_return false;
        const auto response = session->response();
        if (!require(response && response->status == 200, "response status")) co_return false;
        const auto current = response->headers.get("X-Connection");
        if (!require(current.has_value(), "connection ID")) co_return false;
        if (id.empty()) id = std::string{*current};
        if (!require(*current == id, "same-origin reuse")) co_return false;
        std::string body;
        for (;;) {
            const auto data = co_await session->read_body();
            if (!require(data.has_value(), "response body")) co_return false;
            if (data->empty()) break;
            body.append(reinterpret_cast<const char*>(data->data()), data->size());
        }
        if (!require(body == "ok", "body payload")) co_return false;
        if (!require(session->recycle().has_value(), "recycle")) co_return false;
    }
    co_return true;
}
Task<bool> root(EventLoop& loop, std::uint16_t port, const std::string& marker,
                const std::string& ca, const std::string& wrong_ca) {
    Options options;
    options.http.limits.max_body_size = 512 * 1024;
    options.max_connections_per_origin = 1;
    options.http.request_timeout = 10s;
    if (ca.empty()) {
        auto client = HttpClient::create(loop, {}, options);
        if (!require(client.has_value(), "HTTP client")) co_return false;
        std::string id;
        co_return co_await upload(loop, *client, port, marker, id);
    }
#ifdef MIRA_CLIENT_TEST_TLS
    auto factory = HttpsFactory::create({.ca_file = ca});
    if (!require(factory.has_value(), "TLS factory")) co_return false;
    auto client = HttpsClient::create(loop, std::move(*factory), options);
    if (!require(client.has_value(), "HTTPS client")) co_return false;
    std::string id;
    if (!(co_await upload(loop, *client, port, marker, id))) co_return false;
    {
        auto broken = co_await client->acquire("localhost", port);
        if (!require(broken.has_value(), "bad-body acquire")) co_return false;
        http::Request request;
        request.target = "/bad";
        if (!require((co_await broken->start(request)).has_value(), "bad-body head")) co_return false;
        bool failed = false;
        for (;;) {
            auto piece = co_await broken->read_body();
            if (!piece) { failed = true; break; }
            if (piece->empty()) break;
        }
        if (!require(failed && !broken->recycle(), "bad TLS body cannot recycle")) co_return false;
    }
    {
        std::stop_source stop;
        auto pending = co_await client->acquire("localhost", port, {.stop = stop.get_token()});
        if (!require(pending.has_value(), "cancel acquire")) co_return false;
        auto full = co_await client->acquire("localhost", port);
        if (!require(!full && full.error() == Errc::would_block, "TLS pool capacity")) co_return false;
        http::Request request;
        request.target = "/stall";
        if (!require((co_await pending->start(request)).has_value(), "cancel head")) co_return false;
        auto cancel = [&]() -> Task<void> {
            static_cast<void>(co_await loop.sleep_for(5ms));
            stop.request_stop();
        };
        TaskScope scope;
        scope.spawn(cancel());
        auto result = co_await pending->read_body();
        co_await scope.join();
        if (!require(!result && result.error() == Errc::cancelled && !pending->recycle(),
                     "TLS pending body cancellation")) co_return false;
    }
    auto other_factory = HttpsFactory::create({.ca_file = ca});
    if (!require(other_factory.has_value(), "second TLS factory")) co_return false;
    auto other = HttpsClient::create(loop, std::move(*other_factory), options);
    if (!require(other.has_value(), "second HTTPS client")) co_return false;
    auto session = co_await other->acquire("localhost", port, {.deadline = Clock::now() + 5s});
    if (!require(session.has_value(), "isolated acquire")) co_return false;
    http::Request request;
    request.target = "/identity";
    if (!require((co_await session->start(request)).has_value(), "isolated request")) co_return false;
    const auto response = session->response();
    if (!require(response && response->headers.get("X-Connection") != id, "TLS context isolation"))
        co_return false;
    for (;;) {
        auto piece = co_await session->read_body();
        if (!require(piece.has_value(), "isolated body")) co_return false;
        if (piece->empty()) break;
    }
    if (!require(session->recycle().has_value(), "isolated recycle")) co_return false;
    auto bad_factory = HttpsFactory::create({.ca_file = wrong_ca});
    if (!require(bad_factory.has_value(), "untrusted factory")) co_return false;
    auto bad = HttpsClient::create(loop, std::move(*bad_factory), options);
    if (!require(bad.has_value(), "untrusted client")) co_return false;
    const auto failed = co_await bad->acquire("localhost", port, {.deadline = Clock::now() + 5s});
    if (!require(!failed, "untrusted context cannot reuse trusted socket")) co_return false;
    co_return true;
#else
    static_cast<void>(wrong_ca);
    std::fprintf(stderr, "TLS support was not built\n");
    co_return false;
#endif
}
Task<void> driver(EventLoop& loop, std::uint16_t port, const std::string& marker,
                  const std::string& ca, const std::string& wrong_ca, bool& result) {
    result = co_await root(loop, port, marker, ca, wrong_ca);
}
}
int main(int argc, char** argv) {
    if (argc != 3 && argc != 5) return 2;
    unsigned port = 0;
    const std::string port_text{argv[1]};
    const auto parsed = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (parsed.ec != std::errc{} || port == 0 || port > 65535) return 2;
    const std::string marker{argv[2]};
    const std::string ca = argc == 5 ? argv[3] : "";
    const std::string wrong_ca = argc == 5 ? argv[4] : "";
    auto loop = EventLoop::create();
    if (!loop) return 1;
    bool success = false;
    const auto run = loop->run_until_complete(driver(*loop, static_cast<std::uint16_t>(port),
                                                     marker, ca, wrong_ca, success));
    return run && success ? 0 : 1;
}
