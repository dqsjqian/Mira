#include "check.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/dns/doh.hpp"
#include "mira/http/connection.hpp"
#include "mira/transport/tcp.hpp"

#include <string>
#include <vector>

#define CHECK_VALUE(expr) CHECK(static_cast<bool>(expr))

using namespace Mira;
using namespace Mira::dns;
using namespace std::chrono_literals;

namespace {

std::vector<std::byte> bytes(std::string_view text) {
    const auto view = std::as_bytes(std::span{text.data(), text.size()});
    return {view.begin(), view.end()};
}

void base64() {
    test::section("base64url (RFC 4648 vectors, strict decoding)");
    const std::pair<std::string_view, std::string_view> vectors[] = {
        {"", ""}, {"f", "Zg"}, {"fo", "Zm8"}, {"foo", "Zm9v"},
        {"foob", "Zm9vYg"}, {"fooba", "Zm9vYmE"}, {"foobar", "Zm9vYmFy"},
    };
    for (const auto& [plain, encoded] : vectors) {
        CHECK(doh::base64url_encode(bytes(plain)) == encoded);
        const auto decoded = doh::base64url_decode(encoded);
        CHECK(decoded && *decoded == bytes(plain));
    }
    const auto url_safe = std::vector<std::byte>{std::byte{0xFB}, std::byte{0xFF}};
    CHECK(doh::base64url_encode(url_safe) == "-_8");
    CHECK(doh::base64url_decode("-_8") == url_safe);
    for (const std::string_view bad : {"Zg==", "Z", "Zh", "Zm9", "Zm9v+", "Zm9v/", "a b", "Zm8=", "Zm9vY"})
        CHECK(!doh::base64url_decode(bad));
}

void mapping() {
    test::section("RFC 8484 request/response mapping");
    // RFC 8484 §4.1.1: www.example.com A, id 0, RD set, no EDNS.
    const auto query = encode_query(*Name::parse("www.example.com"), type::a, {.udp_payload_size = 0});
    CHECK_VALUE(query);
    const auto get = doh::make_get("dnsserver.example.net", "/dns-query", *query);
    CHECK_VALUE(get);
    CHECK(get->target == "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB");
    CHECK(get->headers.get("Accept") == std::optional<std::string_view>{doh::media_type});
    CHECK(doh::make_get("h", "/q?x=1", *query)->target.starts_with("/q?x=1&dns="));
    CHECK(!doh::make_get("h", "dns-query", *query));
    CHECK(!doh::make_get("h", "/a b", *query));
    CHECK(!doh::make_get("", "/q", *query));
    const auto post = doh::make_post("h", "/dns-query");
    CHECK(post && post->method == http::Method::post &&
          post->headers.get("Content-Type") == std::optional<std::string_view>{doh::media_type});

    auto response_wire = *query;
    response_wire[2] = std::byte{0x81};
    response_wire[3] = std::byte{0x83};  // QR, RD, RA, NXDOMAIN
    http::Response response;
    response.status = 200;
    response.headers.append("Content-Type", "Application/DNS-Message; charset=binary");
    const auto parsed = doh::parse_response(response, response_wire);
    CHECK(parsed && parsed->header.rcode == rcode::nxdomain);
    response.status = 404;
    CHECK(doh::parse_response(response, response_wire).error() == make_error_code(DnsError::bad_status));
    response.status = 200;
    response.headers.clear();
    response.headers.append("Content-Type", "text/plain");
    CHECK(doh::parse_response(response, response_wire).error() == make_error_code(DnsError::bad_media_type));
    response.headers.clear();
    CHECK(doh::parse_response(response, response_wire).error() == make_error_code(DnsError::bad_media_type));
    response.headers.append("Content-Type", std::string{doh::media_type});
    Limits tiny;
    tiny.max_message_size = 12;
    CHECK(doh::parse_response(response, response_wire, tiny).error() == make_error_code(DnsError::too_large));

    const auto decoded = doh::decode_request(*get, {});
    CHECK(decoded && *decoded == *query);
    http::Request mixed = *get;
    mixed.target = "/dns-query?ct=x&dns=" + doh::base64url_encode(*query) + "&z";
    CHECK(doh::decode_request(mixed, {}) == *query);
    const std::pair<std::string_view, DnsError> bad_gets[] = {
        {"/dns-query", DnsError::bad_request},
        {"/dns-query?x=1", DnsError::bad_request},
        {"/dns-query?dns=", DnsError::bad_request},
        {"/dns-query?dns=AAAB&dns=AAAB", DnsError::bad_request},
        {"/dns-query?dns=AA%3D", DnsError::bad_request},
        {"/dns-query?dns=AAAB", DnsError::bad_request},  // shorter than a header
    };
    for (const auto& [target, error] : bad_gets) {
        http::Request request;
        request.target = std::string{target};
        const auto result = doh::decode_request(request, {});
        CHECK(!result && result.error() == make_error_code(error));
        CHECK(doh::http_status(result.error()) == 400);
    }
    http::Request posted = *post;
    CHECK(doh::decode_request(posted, *query) == *query);
    posted.headers.clear();
    posted.headers.append("Content-Type", "application/json");
    const auto unsupported = doh::decode_request(posted, *query);
    CHECK(!unsupported && doh::http_status(unsupported.error()) == 415);
    posted.method = http::Method::put;
    const auto wrong_method = doh::decode_request(posted, *query);
    CHECK(!wrong_method && doh::http_status(wrong_method.error()) == 405);
    posted = *post;
    const auto oversize = doh::decode_request(posted, std::vector<std::byte>(70000));
    CHECK(!oversize && doh::http_status(oversize.error()) == 413);
}

/// In-process DoH responder: A records from a tiny zone, NXDOMAIN otherwise.
struct Zone {
    bool wrong_question = false;
    int served = 0;
    template<typename Writer>
    Task<Result<void>> operator()(const http::Request& request, Writer& writer,
                                  std::span<const std::byte> body) {
        ++served;
        http::Response response;
        auto wire = doh::decode_request(request, body);
        if (!wire) {
            response.status = doh::http_status(wire.error());
            co_return co_await writer.send(response);
        }
        auto query = decode(*wire);
        if (!query || query->questions.size() != 1) {
            response.status = 400;
            co_return co_await writer.send(response);
        }
        Message answer = *query;
        answer.header.qr = true;
        answer.header.ra = true;
        if (wrong_question) answer.questions[0].name = *Name::parse("other.test");
        if (query->questions[0].name == *Name::parse("mira.test") && query->questions[0].type == type::a)
            answer.answers.push_back({query->questions[0].name, type::a, class_in, 42, AData{{127, 0, 0, 1}}});
        else
            answer.header.rcode = rcode::nxdomain;
        auto encoded = encode(answer);
        if (!encoded) co_return fail(encoded.error());
        response.status = 200;
        response.headers.append("Content-Type", std::string{doh::media_type});
        response.headers.append("Cache-Control", "max-age=" + std::to_string(min_ttl(answer).value_or(0)));
        co_return co_await writer.send(response, *encoded);
    }
};

Task<void> loopback(EventLoop& loop) {
    test::section("DoH over real TCP: GET, POST, keep-alive, mismatch");
    for (const bool wrong : {false, true}) {
        auto listener = transport::tcp::Listener::bind(loop, transport::Endpoint::loopback(0));
        CHECK_VALUE(listener);
        if (!listener) co_return;
        Zone zone{wrong};
        TaskScope scope;
        auto server = [&]() -> Task<void> {
            auto peer = co_await listener->accept();
            if (!peer) co_return;
            static_cast<void>(co_await http::serve_connection(*peer, [&zone](const http::Request& request,
                                                                             auto& writer,
                                                                             std::span<const std::byte> body) {
                return zone(request, writer, body);
            }));
        };
        scope.spawn(server());
        auto socket = co_await transport::tcp::connect(loop, listener->local_endpoint());
        CHECK_VALUE(socket);
        if (socket) {
            http::ClientConnection client{*socket};
            const OperationOptions io{.deadline = Clock::now() + 10s};
            auto question = make_query(*Name::parse("Mira.Test"), type::a, {.id = 99});
            if (!wrong) {
                auto answered = co_await doh::query(client, "localhost", "/dns-query", *question,
                                                    doh::Method::get, io);
                CHECK_VALUE(answered);
                if (answered) {
                    CHECK(answered->header.id == 0);
                    CHECK(answered->answers.size() == 1);
                    CHECK((std::get<AData>(answered->answers[0].data).address ==
                           std::array<std::uint8_t, 4>{127, 0, 0, 1}));
                }
                CHECK(client.reusable());
                auto missing = make_query(*Name::parse("nope.test"), type::a);
                auto negative = co_await doh::query(client, "localhost", "/dns-query", *missing,
                                                    doh::Method::post, io);
                CHECK(negative && negative->header.rcode == rcode::nxdomain);
                CHECK(client.reusable());
            } else {
                auto mismatched = co_await doh::query(client, "localhost", "/dns-query", *question,
                                                      doh::Method::post, io);
                CHECK(!mismatched && mismatched.error() == make_error_code(DnsError::mismatched_response));
            }
            socket->close();
        }
        co_await scope.join();
        CHECK(zone.served == (wrong ? 1 : 2));
    }
}

}  // namespace

int main() {
    base64();
    mapping();
    auto loop = EventLoop::create();
    if (!loop) return 1;
    if (!loop->run_until_complete(loopback(*loop))) return 1;
    return test::summary();
}
