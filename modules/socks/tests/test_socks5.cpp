#include "check.hpp"
#include "mira/client/socks5.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/socks/socks5.hpp"
#include "mira/transport/tcp.hpp"

#include <cstring>
#include <string>
#include <vector>

#define CHECK_VALUE(expr) CHECK(static_cast<bool>(expr))

using namespace Mira;
using namespace Mira::socks;
using namespace std::chrono_literals;

namespace {

/// Scripted peer returning at most `step` bytes per call.
struct Script {
    std::string input;
    std::string output;
    std::size_t cursor = 0;
    std::size_t step = 1;
    std::vector<OperationOptions> seen;
    Task<Result<std::size_t>> read_some(std::span<std::byte> into, OperationOptions io = {}) {
        seen.push_back(io);
        if (cursor == input.size()) co_return fail(Errc::eof);
        const auto n = std::min({into.size(), input.size() - cursor, step});
        std::memcpy(into.data(), input.data() + cursor, n);
        cursor += n;
        co_return n;
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> from, OperationOptions io = {}) {
        seen.push_back(io);
        const auto n = std::min<std::size_t>(from.size(), 3);
        output.append(reinterpret_cast<const char*>(from.data()), n);
        co_return n;
    }
    std::string_view rest() const { return std::string_view{input}.substr(cursor); }
};

std::string bytes(std::initializer_list<int> values) {
    std::string out;
    for (const int v : values) out.push_back(static_cast<char>(v));
    return out;
}

void addresses() {
    test::section("address parsing and formatting");
    struct Good {
        std::string_view text;
        Address::Kind kind;
        std::string_view host;
    };
    const Good good[] = {
        {"127.0.0.1", Address::Kind::ipv4, "127.0.0.1"},
        {"255.255.255.255", Address::Kind::ipv4, "255.255.255.255"},
        {"::1", Address::Kind::ipv6, "::1"},
        {"[::1]", Address::Kind::ipv6, "::1"},
        {"::", Address::Kind::ipv6, "::"},
        {"2001:DB8:0:0:1:0:0:1", Address::Kind::ipv6, "2001:db8::1:0:0:1"},
        {"2001:db8::", Address::Kind::ipv6, "2001:db8::"},
        {"1:2:3:4:5:6:7::", Address::Kind::ipv6, "1:2:3:4:5:6:7:0"},
        {"::ffff:192.0.2.1", Address::Kind::ipv6, "::ffff:192.0.2.1"},
        {"64:ff9b::192.0.2.33", Address::Kind::ipv6, "64:ff9b::c000:221"},
        {"fe80:0:0:1:0:0:0:1", Address::Kind::ipv6, "fe80:0:0:1::1"},
        {"example.com", Address::Kind::domain, "example.com"},
        {"a-b.test.", Address::Kind::domain, "a-b.test."},
    };
    for (const auto& each : good) {
        const auto parsed = Address::parse(each.text, 1080);
        CHECK_VALUE(parsed);
        if (!parsed) continue;
        CHECK(parsed->kind() == each.kind);
        CHECK(parsed->host() == each.host);
        CHECK(parsed->port() == 1080);
    }
    const std::string_view bad[] = {
        "", "1.2.3", "1.2.3.4.5", "1.2.3.256", "01.2.3.4", "1..2.3", "1.2.3.4.",
        ":::", "1::2::3", ":1::", "1:", "1:2:3:4:5:6:7:8:9", "12345::", "g::1",
        "::1.2.3", "1.2.3.4::", "[::1", "fe80::1%en0", "1:2:3:4:5:6:1.2.3.4:1",
    };
    for (const auto text : bad) CHECK(!Address::parse(text, 1));
    CHECK(Address::parse("[::1]", 443)->to_string() == "[::1]:443");
    CHECK(Address::parse("10.0.0.1", 80)->to_string() == "10.0.0.1:80");
    CHECK(Address::domain(std::string(255, 'a'), 1).has_value());
    CHECK(!Address::domain(std::string(256, 'a'), 1).has_value());
    CHECK(!Address::domain(std::string_view{"a\0b", 3}, 1).has_value());
    CHECK(Address::parse("10.0.0.1", 0x1234)->encode() == bytes({1, 10, 0, 0, 1, 0x12, 0x34}));
    CHECK(Address::domain("ab", 80)->encode() == bytes({3, 2, 'a', 'b', 0, 80}));
    CHECK(reply_error(0x05) == make_error_code(SocksError::connection_refused));
    CHECK(reply_error(0x09) == make_error_code(SocksError::unassigned_reply));
    CHECK(make_error_code(SocksError::auth_failed).message().find("authentication") != std::string::npos);
}

Task<void> client_paths() {
    test::section("client handshake");
    const auto target = *Address::domain("example.com", 443);
    const auto tail = std::string{"TUNNEL"};
    for (std::size_t step : {1u, 2u, 3u, 64u}) {
        Script peer;
        peer.step = step;
        peer.input = bytes({5, 0}) + bytes({5, 0, 0, 4}) + std::string(16, '\x01') + bytes({1, 187}) + tail;
        const auto deadline = Clock::now() + 5s;
        const auto answer = co_await connect(peer, target, {}, {.deadline = deadline});
        CHECK_VALUE(answer);
        if (answer) {
            CHECK(answer->bound.kind() == Address::Kind::ipv6);
            CHECK(answer->bound.port() == 443);
        }
        CHECK(peer.rest() == tail);  // exact reads: tunnelled bytes untouched
        CHECK(peer.output == bytes({5, 1, 0}) + bytes({5, 1, 0}) + target.encode());
        for (const auto& io : peer.seen) CHECK(io.deadline == deadline);
    }
    {
        Script peer;
        peer.input = bytes({5, 2, 1, 0, 5, 0, 0, 1, 1, 2, 3, 4, 0, 80});
        ClientOptions options;
        options.credentials = Credentials{"user", "pass"};
        const auto answer = co_await connect(peer, *Address::parse("10.1.2.3", 80), options);
        CHECK_VALUE(answer);
        CHECK(peer.output == bytes({5, 2, 0, 2}) + bytes({1, 4}) + "user" + bytes({4}) + "pass" +
                                 bytes({5, 1, 0, 1, 10, 1, 2, 3, 0, 80}));
    }
    struct Bad {
        std::string input;
        std::error_code error;
        ClientOptions options{};
    };
    ClientOptions password_only;
    password_only.allow_no_auth = false;
    password_only.credentials = Credentials{"u", "p"};
    const Bad bad[] = {
        {bytes({4, 0}), make_error_code(SocksError::protocol_error), ClientOptions{}},
        {bytes({5, 0xFF}), make_error_code(SocksError::no_acceptable_method), ClientOptions{}},
        {bytes({5, 2}), make_error_code(SocksError::protocol_error), ClientOptions{}},  // not offered
        {bytes({5, 0}), make_error_code(SocksError::protocol_error), password_only},
        {bytes({5, 2, 1, 1}), make_error_code(SocksError::auth_failed), password_only},
        {bytes({5, 2, 2, 0}), make_error_code(SocksError::protocol_error), password_only},
        {bytes({5, 0, 5, 0, 1, 1, 0, 0, 0, 0, 0, 0}), make_error_code(SocksError::protocol_error), ClientOptions{}},  // RSV
        {bytes({5, 0, 5, 0, 0, 9}), make_error_code(SocksError::protocol_error), ClientOptions{}},  // ATYP
        {bytes({5, 0, 5, 0, 0, 3, 0}), make_error_code(SocksError::protocol_error), ClientOptions{}},  // empty domain
        {bytes({5, 0, 5, 0, 0, 1, 1, 2}), make_error_code(SocksError::protocol_error), ClientOptions{}},  // truncated
        {bytes({5, 0, 6, 0, 0, 1, 1, 2, 3, 4, 0, 1}), make_error_code(SocksError::protocol_error), ClientOptions{}},
        {bytes({5, 0, 5, 9, 0, 1, 0, 0, 0, 0, 0, 0}), make_error_code(SocksError::unassigned_reply), ClientOptions{}},
        {"", make_error_code(SocksError::protocol_error), ClientOptions{}},
    };
    for (const auto& each : bad) {
        Script peer;
        peer.input = each.input;
        const auto answer = co_await connect(peer, target, each.options);
        CHECK(!answer && answer.error() == each.error);
    }
    for (int code = 1; code <= 8; ++code) {
        Script peer;
        peer.input = bytes({5, 0, 5, code, 0, 1, 0, 0, 0, 0, 0, 0}) + "after";
        const auto answer = co_await connect(peer, target, {});
        CHECK(!answer && answer.error() == reply_error(static_cast<std::uint8_t>(code)));
        CHECK(peer.rest() == "after");
    }
    {
        Script peer;
        ClientOptions none;
        none.allow_no_auth = false;
        const auto refused = co_await connect(peer, target, none);
        CHECK(!refused && refused.error() == Errc::invalid_argument && peer.output.empty());
        ClientOptions long_user;
        long_user.credentials = Credentials{std::string(256, 'u'), "p"};
        const auto overlong = co_await connect(peer, target, long_user);
        CHECK(!overlong && overlong.error() == Errc::invalid_argument);
        std::stop_source stop;
        stop.request_stop();
        const auto cancelled = co_await connect(peer, target, {}, {.stop = stop.get_token()});
        CHECK(!cancelled && cancelled.error() == Errc::cancelled);
        const auto expired = co_await connect(peer, target, {}, {.deadline = Clock::now() - 1s});
        CHECK(!expired && expired.error() == Errc::timed_out);
    }
}

Task<void> server_paths() {
    test::section("proxy handshake");
    ServerOptions open;
    open.allow_no_auth = true;
    {
        Script peer;
        peer.input = bytes({5, 1, 0, 5, 1, 0, 3, 11}) + "example.com" + bytes({1, 187}) + "DATA";
        const auto request = co_await accept(peer, open);
        CHECK_VALUE(request);
        if (request) {
            CHECK(request->command == Command::connect);
            CHECK(request->target.name() == "example.com" && request->target.port() == 443);
            CHECK(!request->username);
        }
        CHECK(peer.rest() == "DATA");
        CHECK(peer.output == bytes({5, 0}));
        const auto replied = co_await reply(peer, ReplyCode::succeeded, *Address::parse("10.0.0.1", 9));
        CHECK_VALUE(replied);
        CHECK(peer.output.ends_with(bytes({5, 0, 0, 1, 10, 0, 0, 1, 0, 9})));
    }
    ServerOptions secured;
    secured.allow_no_auth = true;
    secured.verify = [](std::string_view user, std::string_view pass) {
        return user == "alice" && pass == "s3cret";
    };
    {
        Script peer;
        peer.input = bytes({5, 2, 0, 2, 1, 5}) + "alice" + bytes({6}) + "s3cret" +
                     bytes({5, 2, 0, 4}) + std::string(16, '\0') + bytes({0, 1});
        const auto request = co_await accept(peer, secured);
        CHECK_VALUE(request);
        if (request) {
            CHECK(request->command == Command::bind);  // parsed; caller refuses
            CHECK(request->username == std::optional<std::string>{"alice"});
            CHECK(request->target.kind() == Address::Kind::ipv6);
        }
        CHECK(peer.output == bytes({5, 2, 1, 0}));
    }
    {
        Script peer;
        peer.input = bytes({5, 1, 2, 1, 5}) + "alice" + bytes({5}) + "wrong";
        const auto request = co_await accept(peer, secured);
        CHECK(!request && request.error() == make_error_code(SocksError::auth_failed));
        CHECK(peer.output == bytes({5, 2, 1, 1}));
    }
    {
        Script peer;
        peer.input = bytes({5, 1, 2});
        const auto request = co_await accept(peer, open);
        CHECK(!request && request.error() == make_error_code(SocksError::no_acceptable_method));
        CHECK(peer.output == bytes({5, 0xFF}));
    }
    {
        Script peer;
        peer.input = bytes({5, 1, 0, 5, 1, 0, 7, 1, 2});
        const auto request = co_await accept(peer, open);
        CHECK(!request && request.error() == make_error_code(SocksError::address_type_not_supported));
        CHECK(peer.output.ends_with(bytes({5, 8, 0, 1, 0, 0, 0, 0, 0, 0})));
    }
    const std::string malformed[] = {
        bytes({4, 1, 0}), bytes({5, 0}), bytes({5, 1, 0, 5, 9, 0, 1}), bytes({5, 1, 0, 5, 1, 1, 1}),
        bytes({5, 1, 0, 5, 1, 0, 3, 0}), bytes({5, 1, 0, 5, 1, 0, 1, 1, 2, 3}), "",
    };
    for (const auto& input : malformed) {
        Script peer;
        peer.input = input;
        const auto request = co_await accept(peer, open);
        CHECK(!request);
    }
    {
        Script peer;
        const auto misconfigured = co_await accept(peer, ServerOptions{});
        CHECK(!misconfigured && misconfigured.error() == Errc::invalid_argument);
    }
}

/// Real sockets: client → Mira proxy → echo target, through dial_via_socks5.
Task<void> loopback(EventLoop& loop) {
    test::section("loopback tunnel through dial_via_socks5");
    auto proxy_listener = transport::tcp::Listener::bind(loop, transport::Endpoint::loopback(0));
    auto target_listener = transport::tcp::Listener::bind(loop, transport::Endpoint::loopback(0));
    auto resolver = transport::Resolver::create();
    CHECK_VALUE(proxy_listener);
    CHECK_VALUE(target_listener);
    CHECK_VALUE(resolver);
    if (!proxy_listener || !target_listener || !resolver) co_return;
    const auto proxy_port = proxy_listener->local_endpoint().port();
    const auto target_port = target_listener->local_endpoint().port();
    std::string proxied_user;
    TaskScope scope;
    auto echo = [&]() -> Task<void> {
        auto peer = co_await target_listener->accept();
        if (!peer) co_return;
        std::array<std::byte, 64> buffer{};
        const auto n = co_await peer->read_some(buffer);
        if (!n) co_return;
        static_cast<void>(co_await write_all(*peer, std::span<const std::byte>{buffer}.first(*n),
                                             OperationOptions{}));
    };
    auto proxy = [&]() -> Task<void> {
        auto client = co_await proxy_listener->accept();
        if (!client) co_return;
        ServerOptions options;
        options.verify = [](std::string_view u, std::string_view p) { return u == "bob" && p == "pw"; };
        auto request = co_await accept(*client, options);
        if (!request) co_return;
        proxied_user = request->username.value_or("");
        auto endpoint = transport::Endpoint::parse(request->target.host(), request->target.port());
        if (!endpoint) {
            static_cast<void>(co_await reply(*client, ReplyCode::address_type_not_supported, {}));
            co_return;
        }
        auto upstream = co_await transport::tcp::connect(loop, *endpoint);
        if (!upstream) {
            static_cast<void>(co_await reply(*client, ReplyCode::connection_refused, {}));
            co_return;
        }
        auto local = upstream->local_endpoint();
        auto bound = Address::parse(local->address(), local->port());
        if (!(co_await reply(*client, ReplyCode::succeeded, *bound))) co_return;
        std::array<std::byte, 64> buffer{};
        const auto n = co_await client->read_some(buffer);
        if (!n) co_return;
        static_cast<void>(co_await write_all(*upstream, std::span<const std::byte>{buffer}.first(*n),
                                             OperationOptions{}));
        const auto back = co_await upstream->read_some(buffer);
        if (!back) co_return;
        static_cast<void>(co_await write_all(*client, std::span<const std::byte>{buffer}.first(*back),
                                             OperationOptions{}));
    };
    scope.spawn(echo());
    scope.spawn(proxy());
    ClientOptions options;
    options.allow_no_auth = false;
    options.credentials = Credentials{"bob", "pw"};
    transport::tcp::DialOptions dial;
    dial.io.deadline = Clock::now() + 10s;
    auto tunnel = co_await client::dial_via_socks5(loop, *resolver, "127.0.0.1", proxy_port,
                                                   *Address::parse("127.0.0.1", target_port),
                                                   options, dial);
    CHECK_VALUE(tunnel);
    if (tunnel) {
        CHECK(tunnel->reply.bound.kind() == Address::Kind::ipv4);
        const std::string_view hello = "hello through socks";
        const auto sent = co_await write_all(tunnel->socket, std::as_bytes(std::span{hello}),
                                             OperationOptions{});
        CHECK_VALUE(sent);
        std::string echoed;
        while (echoed.size() < hello.size()) {
            std::array<std::byte, 64> buffer{};
            const auto n = co_await tunnel->socket.read_some(buffer);
            if (!n) break;
            echoed.append(reinterpret_cast<const char*>(buffer.data()), *n);
        }
        CHECK(echoed == hello);
        tunnel->socket.close();
    }
    co_await scope.join();
    CHECK(proxied_user == "bob");

    test::section("dial_via_socks5 reports proxy refusal and closes");
    auto refusing = transport::tcp::Listener::bind(loop, transport::Endpoint::loopback(0));
    CHECK_VALUE(refusing);
    if (!refusing) co_return;
    TaskScope second;
    auto refuse = [&]() -> Task<void> {
        auto client = co_await refusing->accept();
        if (!client) co_return;
        ServerOptions open;
        open.allow_no_auth = true;
        auto request = co_await accept(*client, open);
        if (!request) co_return;
        static_cast<void>(co_await reply(*client, ReplyCode::host_unreachable, {}));
    };
    second.spawn(refuse());
    auto failed = co_await client::dial_via_socks5(loop, *resolver, "localhost",
                                                   refusing->local_endpoint().port(),
                                                   *Address::domain("unreachable.test", 1), {}, dial);
    CHECK(!failed && failed.error() == make_error_code(SocksError::host_unreachable));
    co_await second.join();
}

Task<void> run(EventLoop& loop) {
    addresses();
    co_await client_paths();
    co_await server_paths();
    co_await loopback(loop);
}

}  // namespace

int main() {
    auto loop = EventLoop::create();
    if (!loop) return 1;
    if (!loop->run_until_complete(run(*loop))) return 1;
    return test::summary();
}
