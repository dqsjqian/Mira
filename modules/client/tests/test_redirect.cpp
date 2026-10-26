// Redirect following: pure resolution/method rules, plus the live loop
// against a loopback server through the pooled client.

#include "check.hpp"
#include "mira/client/http.hpp"
#include "mira/client/redirect.hpp"
#include "mira/core/task_scope.hpp"

#ifdef MIRA_CLIENT_HAS_ZLIB
#include "mira/client/decompress.hpp"
#include <zlib.h>
#endif

#include <array>
#include <charconv>
#include <string>

#define CHECK_VALUE(expr) CHECK(static_cast<bool>(expr))
using namespace Mira;
using namespace Mira::client;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {

std::span<const std::byte> bytes(std::string_view value) {
    return std::as_bytes(std::span{value.data(), value.size()});
}

std::string body_text(const std::vector<std::byte>& body) {
    return {reinterpret_cast<const char*>(body.data()), body.size()};
}

std::vector<std::byte> vec(std::string_view value) {
    const auto view = bytes(value);
    return {view.begin(), view.end()};
}

void resolution_checks() {
    test::section("Location resolution");
    const auto resolve = [](std::string_view location) {
        return resolve_redirect_location("http", "example.com", 80, "/dir/page?x=1", location);
    };
    auto target = resolve("http://other.com/a");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://other.com:80/a");
    target = resolve("https://other.com:8443/a?b=c");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "https://other.com:8443/a?b=c");
    target = resolve("//other.com/a");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://other.com:80/a");
    target = resolve("//other.com");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://other.com:80/");
    target = resolve("/abs");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://example.com:80/abs");
    target = resolve("/abs?y=2");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://example.com:80/abs?y=2");
    target = resolve("?y=2");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://example.com:80/dir/page?y=2");
    target = resolve("sib");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://example.com:80/dir/sib");
    target = resolve("../up");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://example.com:80/up");
    target = resolve("./dot");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://example.com:80/dir/dot");
    target = resolve("/a/./b/../c");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://example.com:80/a/c");
    target = resolve("HTTP://EXAMPLE.com/A");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://example.com:80/A");
    target = resolve("https://other.com/a#frag");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "https://other.com:443/a");
    target = resolve("");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://example.com:80/dir/page?x=1");
    target = resolve("http://host");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://host:80/");
    target = resolve("http://host?x=1");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://host:80/?x=1");
    target = resolve("http://[::1]:8080/a");
    CHECK_VALUE(target);
    if (target) CHECK(target->url() == "http://[::1]:8080/a");
    const auto other_scheme = resolve("ftp://x/y");
    CHECK(!other_scheme && other_scheme.error() == Errc::not_supported);
    const auto bad_port = resolve("http://host:99999/a");
    CHECK(!bad_port && bad_port.error() == Errc::invalid_argument);
    const auto alpha_port = resolve("http://host:abc/a");
    CHECK(!alpha_port && alpha_port.error() == Errc::invalid_argument);
    const auto bare_v6 = resolve("http://::1/a");
    CHECK(!bare_v6 && bare_v6.error() == Errc::invalid_argument);
}

void method_checks() {
    test::section("redirect method policy");
    CHECK(next_redirect_method(301, http::Method::post).method == http::Method::get);
    CHECK(next_redirect_method(301, http::Method::post).drop_body);
    CHECK(next_redirect_method(301, http::Method::get).method == http::Method::get);
    CHECK(!next_redirect_method(301, http::Method::get).drop_body);
    CHECK(next_redirect_method(302, http::Method::post).method == http::Method::get);
    CHECK(next_redirect_method(303, http::Method::post).method == http::Method::get);
    CHECK(next_redirect_method(303, http::Method::post).drop_body);
    CHECK(next_redirect_method(303, http::Method::head).method == http::Method::head);
    CHECK(!next_redirect_method(303, http::Method::head).drop_body);
    CHECK(next_redirect_method(303, http::Method::put).method == http::Method::get);
    CHECK(next_redirect_method(307, http::Method::post).method == http::Method::post);
    CHECK(!next_redirect_method(307, http::Method::post).drop_body);
    CHECK(next_redirect_method(308, http::Method::put).method == http::Method::put);
    CHECK(!next_redirect_method(308, http::Method::put).drop_body);
}

#ifdef MIRA_CLIENT_HAS_ZLIB
std::vector<std::byte> gzip_of(std::string_view input) {
    z_stream stream{};
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return {};
    std::vector<std::byte> output(deflateBound(&stream, static_cast<uLong>(input.size())));
    stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    stream.next_out = reinterpret_cast<Bytef*>(output.data());
    stream.avail_out = static_cast<uInt>(output.size());
    const int result = deflate(&stream, Z_FINISH);
    const auto produced = output.size() - stream.avail_out;
    deflateEnd(&stream);
    if (result != Z_STREAM_END) return {};
    output.resize(produced);
    return output;
}
#endif

struct Record {
    std::string method;
    std::string target;
    bool auth = false;
    bool proxy_auth = false;
    bool cookie = false;
    std::string cookie_value;
    std::string custom;
    std::string body;
};

struct Server {
    EventLoop& loop;
    tcp::Listener listener;
    std::stop_source stop;
    std::vector<Record> records{};
    Task<void> serve(tcp::Socket socket) {
        std::array<std::byte, 4096> buffer{};
        std::string pending;
        const OperationOptions io{.stop = stop.get_token(), .deadline = Clock::now() + 10s};
        for (;;) {
            while (pending.find("\r\n\r\n") == std::string::npos) {
                auto read = co_await socket.read_some(buffer, io);
                if (!read) co_return;
                pending.append(reinterpret_cast<const char*>(buffer.data()), *read);
                if (pending.size() > 65536) co_return;
            }
            const auto end = pending.find("\r\n\r\n") + 4;
            const auto head = pending.substr(0, end);
            pending.erase(0, end);
            Record record;
            const auto first_space = head.find(' ');
            const auto second_space = head.find(' ', first_space + 1);
            record.method = head.substr(0, first_space);
            record.target = head.substr(first_space + 1, second_space - first_space - 1);
            std::size_t content_length = 0;
            std::size_t pos = 0;
            while (pos < head.size()) {
                const auto line_end = head.find("\r\n", pos);
                const auto line = head.substr(pos, line_end == std::string::npos ? std::string::npos
                                                                                 : line_end - pos);
                if (line.starts_with("Content-Length:")) {
                    auto value = line.substr(15);
                    while (!value.empty() && value.front() == ' ') value.erase(0, 1);
                    std::from_chars(value.data(), value.data() + value.size(), content_length);
                }
                if (line.starts_with("Authorization:")) record.auth = true;
                if (line.starts_with("Proxy-Authorization:")) record.proxy_auth = true;
                if (line.starts_with("Cookie:")) {
                    record.cookie = true;
                    record.cookie_value = std::string{Mira::client::detail::trim_redirect_ows(std::string_view{line}.substr(7))};
                }
                if (line.starts_with("X-Custom:")) {
                    auto value = line.substr(9);
                    while (!value.empty() && value.front() == ' ') value.erase(0, 1);
                    record.custom = value;
                }
                if (line_end == std::string::npos) break;
                pos = line_end + 2;
            }
            while (pending.size() < content_length) {
                auto read = co_await socket.read_some(buffer, io);
                if (!read) co_return;
                pending.append(reinterpret_cast<const char*>(buffer.data()), *read);
            }
            record.body = pending.substr(0, content_length);
            pending.erase(0, content_length);
            records.push_back(record);
            const auto target = record.target;
            std::string status_line;
            std::string headers;
            std::string body;
            auto redirect = [&](int status, std::string_view location) {
                status_line = "HTTP/1.1 " + std::to_string(status) + " Redirect\r\n";
                headers = "Location: " + std::string{location} + "\r\nContent-Length: 0\r\n";
            };
            auto ok = [&](std::string_view text) {
                status_line = "HTTP/1.1 200 OK\r\n";
                headers = "Content-Length: " + std::to_string(text.size()) + "\r\n";
                body = text;
            };
            if (target == "/start") redirect(302, "/middle");
            else if (target == "/middle") redirect(301, "/final");
            else if (target == "/final") ok("done");
            else if (target == "/post") redirect(303, "/got");
            else if (target == "/got") ok("got-it");
            else if (target == "/keep") redirect(307, "/kept");
            else if (target == "/kept") ok("kept-it");
            else if (target == "/loop-a") redirect(302, "/loop-b");
            else if (target == "/loop-b") redirect(302, "/loop-a");
            else if (target == "/to-https") redirect(302, "https://other.test/secure");
            else if (target == "/cross") redirect(302, "http://other.test:8080/elsewhere");
            else if (target == "/elsewhere") ok("elsewhere");
            else if (target == "/cookie-start") {
                redirect(302, "/cookie-hop");
                headers += "Set-Cookie: root=one; Path=/\r\nSet-Cookie: scoped=one; Path=/cookie-hop\r\n";
            } else if (target == "/cookie-hop") redirect(302, "/cookie-end");
            else if (target == "/cookie-end") ok(record.cookie_value);
            else if (target == "/set-local") {
                ok("set");
                headers += "Set-Cookie: local=two; Path=/\r\n";
            } else if (target == "/cache" || target == "/private-cache" || target == "/no-store" || target == "/cache-variant") {
                ok(record.custom.empty() ? "cache-body" : record.custom);
                headers += target == "/no-store" ? "Cache-Control: no-store, max-age=60\r\n" : "Cache-Control: max-age=60\r\n";
                if (target == "/private-cache") headers += "Set-Cookie: secret=one; Path=/\r\n";
                if (target == "/cache-variant") headers += "Vary: X-Custom\r\n";
            }
            else if (target == "/max0") redirect(302, "/max1");
            else if (target == "/max1") redirect(302, "/max2");
            else if (target == "/max2") redirect(302, "/max3");
            else if (target == "/max3") ok("max-done");
            else if (target == "/notmod") {
                status_line = "HTTP/1.1 304 Not Modified\r\n";
                headers = "Content-Length: 0\r\n";
            }
#ifdef MIRA_CLIENT_HAS_ZLIB
            else if (target == "/gzip") {
                const auto gzipped = gzip_of("hello-gzip");
                status_line = "HTTP/1.1 200 OK\r\n";
                headers = "Content-Encoding: gzip\r\nContent-Length: " +
                          std::to_string(gzipped.size()) + "\r\n";
                body.assign(reinterpret_cast<const char*>(gzipped.data()), gzipped.size());
            }
#endif
            else ok("unknown");
            const auto wire = status_line + headers + "\r\n" + body;
            static_cast<void>(co_await write_all(socket, bytes(wire), io));
        }
    }
    Task<void> run() {
        TaskScope children;
        for (;;) {
            auto socket = co_await listener.accept({.stop = stop.get_token()});
            if (!socket) break;
            children.spawn(serve(std::move(*socket)));
        }
        co_await children.join();
    }
};

http::Request get(std::string target) {
    http::Request request;
    request.method = http::Method::get;
    request.target = std::move(target);
    return request;
}

std::optional<Record> last_for(Server& server, std::string_view target) {
    for (auto it = server.records.rbegin(); it != server.records.rend(); ++it)
        if (it->target == target) return *it;
    return std::nullopt;
}

Task<void> loop_checks(EventLoop& loop, Server& server) {
    // Every host maps to this server: origins still differ for pooling and
    // header purposes, only the transport destination is faked.
    const auto server_port = server.listener.local_endpoint().port();
    auto backend = [server_port](const ResolveQuery&, std::size_t) -> Result<Resolver::Endpoints> {
        return Resolver::Endpoints{Endpoint::loopback(server_port)};
    };
    Options options;
    options.http.request_timeout = 5s;
    auto client = HttpClient::create(loop, {}, options, {}, backend);
    CHECK_VALUE(client);
    if (!client) co_return;

    test::section("two-hop chain follows to the final body");
    {
        auto result = co_await request_with_redirects(*client, "http", "a.test", server_port, get("/start"));
        CHECK_VALUE(result);
        if (result) {
            CHECK(result->status == 200);
            CHECK(body_text(result->body) == "done");
            CHECK(result->redirects_followed == 2);
            CHECK(result->final_target == "/final");
            CHECK(!result->unfollowed_location);
        }
    }
    test::section("303 converts POST to GET and drops the body");
    {
        http::Request request;
        request.method = http::Method::post;
        request.target = "/post";
        auto result = co_await request_with_redirects(*client, "http", "a.test", server_port,
                                                     std::move(request), vec("data"));
        CHECK_VALUE(result);
        if (result) {
            CHECK(result->status == 200);
            CHECK(body_text(result->body) == "got-it");
            CHECK(result->redirects_followed == 1);
        }
        const auto got = last_for(server, "/got");
        CHECK(got.has_value());
        if (got) {
            CHECK(got->method == "GET");
            CHECK(got->body.empty());
        }
    }
    test::section("307 preserves POST and replays the body");
    {
        http::Request request;
        request.method = http::Method::post;
        request.target = "/keep";
        auto result = co_await request_with_redirects(*client, "http", "a.test", server_port,
                                                     std::move(request), vec("keepme"));
        CHECK_VALUE(result);
        if (result) CHECK(body_text(result->body) == "kept-it");
        const auto kept = last_for(server, "/kept");
        CHECK(kept.has_value());
        if (kept) {
            CHECK(kept->method == "POST");
            CHECK(kept->body == "keepme");
        }
    }
    test::section("a redirect loop fails instead of spinning");
    {
        auto result = co_await request_with_redirects(*client, "http", "a.test", server_port, get("/loop-a"));
        CHECK(!result && result.error() == Errc::limit_exceeded);
    }
    test::section("cross-scheme stops and reports the absolute target");
    {
        auto result = co_await request_with_redirects(*client, "http", "a.test", server_port, get("/to-https"));
        CHECK_VALUE(result);
        if (result) {
            CHECK(result->status == 302);
            CHECK(result->redirects_followed == 0);
            CHECK(result->final_target == "/to-https");
            CHECK(result->unfollowed_location.has_value());
            if (result->unfollowed_location)
                CHECK(*result->unfollowed_location == "https://other.test:443/secure");
        }
    }
    test::section("cross-origin drops Authorization and Cookie but keeps the rest");
    {
        http::Request request = get("/cross");
        request.headers.append("Authorization", "Bearer x");
        request.headers.append("Cookie", "a=b");
        request.headers.append("X-Custom", "keep");
        auto result = co_await request_with_redirects(*client, "http", "a.test", server_port, std::move(request));
        CHECK_VALUE(result);
        if (result) CHECK(body_text(result->body) == "elsewhere");
        const auto elsewhere = last_for(server, "/elsewhere");
        CHECK(elsewhere.has_value());
        if (elsewhere) {
            CHECK(!elsewhere->auth);
            CHECK(!elsewhere->cookie);
            CHECK(elsewhere->custom == "keep");
        }
    }
    test::section("max_redirects caps the chain");
    {
        auto result = co_await request_with_redirects(*client, "http", "a.test", server_port, get("/max0"),
                                                     {}, RedirectOptions{.max_redirects = 2});
        CHECK(!result && result.error() == Errc::limit_exceeded);
    }
    test::section("a 3xx without Location is terminal");
    {
        auto result = co_await request_with_redirects(*client, "http", "a.test", server_port, get("/notmod"));
        CHECK_VALUE(result);
        if (result) {
            CHECK(result->status == 304);
            CHECK(result->body.empty());
        }
    }
    test::section("显式状态逐跳处理 Cookie，路径和跨源 Cookie 不泄露");
    {
        auto state = *RequestState::create({.cookies = CookieOptions{}, .cache = ResponseCacheOptions{}});
        RedirectOptions policy{.state = state};
        auto result = co_await request_with_redirects(*client, "http", "a.test", server_port, get("/cookie-start"), {}, policy);
        CHECK_VALUE(result);
        if (result) CHECK(body_text(result->body) == "root=one");
        const auto hop = last_for(server, "/cookie-hop");
        CHECK(hop && hop->cookie_value == "scoped=one; root=one");
        auto local = co_await request_with_redirects(*client, "http", "other.test", 8080, get("/set-local"), {}, policy);
        CHECK_VALUE(local);
        auto cross = get("/cross");
        cross.headers.append("Authorization", "Bearer first");
        cross.headers.append("Proxy-Authorization", "Basic proxy");
        cross.headers.append("Cookie", "manual=first");
        result = co_await request_with_redirects(*client, "http", "a.test", server_port, std::move(cross), {}, policy);
        CHECK_VALUE(result);
        const auto destination = last_for(server, "/elsewhere");
        CHECK(destination && !destination->auth && !destination->proxy_auth && destination->cookie_value == "local=two");
        result = co_await request_with_redirects(*client, "http", "a.test", server_port, get("/cookie-end"));
        CHECK(result && body_text(result->body).empty());
        auto independent = *RequestState::create({.cookies = CookieOptions{}});
        result = co_await request_with_redirects(*client, "http", "a.test", server_port, get("/cookie-end"), {}, {.state = independent});
        CHECK(result && body_text(result->body).empty());
        const auto before = server.records.size();
        result = co_await request_with_redirects(*client, "https", "a.test", server_port, get("/cookie-end"), {}, policy);
        CHECK(!result && result.error() == Errc::invalid_argument);
        CHECK(server.records.size() == before);
    }
    test::section("缓存集成命中、变体、敏感请求绕过、失效和取消");
    {
        auto state = *RequestState::create({.cache = ResponseCacheOptions{}});
        RedirectOptions policy{.state = state};
        auto first = co_await request_with_redirects(*client, "http", "cache.test", server_port, get("/cache"), {}, policy);
        CHECK_VALUE(first);
        const auto before_hit = server.records.size();
        auto hit = co_await request_with_redirects(*client, "http", "cache.test", server_port, get("/cache"), {}, policy);
        CHECK(hit && body_text(hit->body) == "cache-body" && hit->headers.contains("Age"));
        CHECK(server.records.size() == before_hit);
        std::stop_source cancelled; cancelled.request_stop();
        hit = co_await request_with_redirects(*client, "http", "cache.test", server_port, get("/cache"), {}, policy,
            {.stop = cancelled.get_token()});
        CHECK(!hit && hit.error() == Errc::cancelled);
        hit = co_await request_with_redirects(*client, "http", "cache.test", server_port, get("/cache"), {}, policy,
            {.deadline = Clock::now() - 1s});
        CHECK(!hit && hit.error() == Errc::timed_out);
        CHECK(server.records.size() == before_hit);
        for (const auto header : {"Authorization", "Cookie", "Range", "Cache-Control"}) {
            auto request = get("/cache"); request.headers.append(header, "x");
            const auto before = server.records.size();
            auto result = co_await request_with_redirects(*client, "http", "cache.test", server_port, request, {}, policy);
            CHECK_VALUE(result);
            CHECK(server.records.size() == before + 1);
        }
        for (const auto target : {"/private-cache", "/no-store"}) {
            const auto before = server.records.size();
            for (int i = 0; i < 2; ++i) {
                auto result = co_await request_with_redirects(*client, "http", "cache.test", server_port, get(target), {}, policy);
                CHECK_VALUE(result);
            }
            CHECK(server.records.size() == before + 2);
        }
        for (const auto value : {"en", "fr"}) {
            auto request = get("/cache-variant"); request.headers.append("X-Custom", value);
            auto result = co_await request_with_redirects(*client, "http", "cache.test", server_port, request, {}, policy);
            CHECK(result && body_text(result->body) == value);
            const auto before = server.records.size();
            result = co_await request_with_redirects(*client, "http", "cache.test", server_port, request, {}, policy);
            CHECK(result && body_text(result->body) == value && server.records.size() == before);
        }
        auto update = get("/write"); update.method = http::Method::post;
        auto result = co_await request_with_redirects(*client, "http", "cache.test", server_port, update, {}, policy);
        CHECK_VALUE(result);
        const auto before = server.records.size();
        result = co_await request_with_redirects(*client, "http", "cache.test", server_port, get("/cache"), {}, policy);
        CHECK(result && server.records.size() == before + 1);
        result = co_await request_with_redirects(*client, "http", "another.test", server_port, get("/cache"), {}, policy);
        CHECK(result && server.records.size() == before + 2);
    }
#ifdef MIRA_CLIENT_HAS_ZLIB
    test::section("redirected body composes with Content-Encoding decoding");
    {
        auto result = co_await request_with_redirects(*client, "http", "a.test", server_port, get("/gzip"));
        CHECK_VALUE(result);
        if (result) {
            const auto encoding = result->headers.get("Content-Encoding");
            CHECK(encoding.has_value());
            auto decoded = decompress_body(encoding ? *encoding : "", result->body);
            CHECK(decoded.has_value() && body_text(*decoded) == "hello-gzip");
        }
    }
#endif
}

Task<void> root(EventLoop& loop) {
    resolution_checks();
    method_checks();
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK_VALUE(listener);
    if (!listener) co_return;
    Server server{loop, std::move(*listener), {}};
    TaskScope tasks;
    tasks.spawn(server.run());
    co_await loop_checks(loop, server);
    server.stop.request_stop();
    co_await tasks.join();
}

}  // namespace

int main() {
    auto loop = EventLoop::create();
    CHECK_VALUE(loop);
    if (loop) {
        CHECK_VALUE(loop->run_until_complete(root(*loop)));
        CHECK_VALUE(loop->outstanding() == 0);
    }
    return test::summary();
}
