#include "check.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/dns/doh.hpp"
#include "mira/http/connection.hpp"
#include "mira/transport/tcp.hpp"

#include <string>
#include <limits>
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

    // Raising a local limit cannot enlarge the media type's wire limit, and
    // must not wrap the encoded-size calculation and reject ordinary queries.
    Limits large;
    large.max_message_size = std::numeric_limits<std::size_t>::max() / 4 + 1;
    CHECK(doh::decode_request(*get, {}, large) == *query);
    const std::vector<std::byte> maximum_wire(65535);
    CHECK(doh::decode_request(posted, maximum_wire, large) == maximum_wire);
    const std::vector<std::byte> too_large_wire(65536);
    const auto large_post = doh::decode_request(posted, too_large_wire, large);
    CHECK(!large_post && large_post.error() == make_error_code(DnsError::too_large));
    mixed.target = "/dns-query?dns=" + doh::base64url_encode(too_large_wire);
    large.max_message_size = std::numeric_limits<std::size_t>::max();
    const auto large_get = doh::decode_request(mixed, {}, large);
    CHECK(!large_get && large_get.error() == make_error_code(DnsError::too_large));
}

void response_age() {
    test::section("DoH HTTP cache age reduces DNS TTLs without underflow");
    Message answer;
    answer.header.qr = true;
    answer.answers.push_back({*Name::parse("cached.test"), type::a, class_in, 600, AData{{127, 0, 0, 1}}});
    SoaData soa;
    soa.minimum = 60;
    answer.authorities.push_back({*Name::parse("test"), type::soa, class_in, 60, soa});
    answer.additionals.push_back({*Name::parse("ns.test"), type::a, class_in, 120, AData{{127, 0, 0, 2}}});
    answer.edns = Edns{};
    answer.edns->dnssec_ok = true;
    const auto wire = encode(answer);
    CHECK_VALUE(wire);
    if (!wire) return;
    http::Response response;
    response.headers.append("Content-Type", std::string{doh::media_type});
    response.headers.append("Age", "250");
    auto parsed = doh::parse_response(response, *wire);
    CHECK_VALUE(parsed);
    if (parsed) {
        CHECK(parsed->answers.front().ttl == 350);
        CHECK(parsed->authorities.front().ttl == 0);
        CHECK(parsed->additionals.front().ttl == 0);
        CHECK(std::get<SoaData>(parsed->authorities.front().data).minimum == 60);
        CHECK(parsed->edns == answer.edns);
    }
    for (const auto& [age, ttl] : std::vector<std::pair<std::string, std::uint32_t>>{
             {" 250 , 999", 350}, {"999999999999999999999999", 0},
             {"0", 600}, {"-1", 600}, {"250x", 600}, {"", 600}}) {
        response.headers.clear();
        response.headers.append("Content-Type", std::string{doh::media_type});
        response.headers.append("Age", age);
        response.headers.append("Age", "500");  // First field/list member wins.
        parsed = doh::parse_response(response, *wire);
        CHECK(parsed && parsed->answers.front().ttl == ttl);
    }
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
        response.headers.append("Age", "10");
        co_return co_await writer.send(response, *encoded);
    }
};

struct Multiplexed {
    struct Response { http::Headers headers; std::vector<std::byte> body; };
    bool bad = false;
    Task<Result<Response>> request(http::Headers headers, std::vector<std::byte> body, OperationOptions io) {
        if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
        http::Request mapped;
        mapped.method = http::Method::get;
        for (const auto& field : headers) {
            if (field.name == ":method") mapped.method = field.value == "POST" ? http::Method::post : http::Method::get;
            else if (field.name == ":path") mapped.target = field.value;
            else if (!field.name.starts_with(':')) mapped.headers.append(field.name, field.value);
        }
        auto wire = doh::decode_request(mapped, body);
        if (!wire) co_return fail(wire.error());
        auto question = decode(*wire);
        if (!question) co_return fail(question.error());
        question->header.qr = true;
        if (bad) question->header.id = 7;
        auto encoded = encode(*question);
        if (!encoded) co_return fail(encoded.error());
        co_return Response{{{":status", "200"}, {"content-type", std::string(doh::media_type)}}, std::move(*encoded)};
    }
};
Task<void> multiplexed_mapping() {
    test::section("DoH multiplexed HTTP field mapping and response identity");
    Multiplexed client;
    for (const auto method : {doh::Method::get, doh::Method::post}) {
        auto question = make_query(*Name::parse("mira.test"), type::a);
        CHECK_VALUE(question);
        if (!question) continue;
        auto answer = co_await doh::query_multiplexed(client, "localhost", "/dns-query", *question, method);
        CHECK(answer && answer->header.id == 0 && answer->header.qr);
        client.bad = true;
        auto mismatch = co_await doh::query_multiplexed(client, "localhost", "/dns-query", *question, method);
        CHECK(!mismatch && mismatch.error() == make_error_code(DnsError::mismatched_response));
        client.bad = false;
    }
}

Task<void> loopback(EventLoop& loop) {
    co_await multiplexed_mapping();
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
                    CHECK(answered->answers.front().ttl == 32);
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

struct MultiplexedPeer {
    struct Response { http::Headers headers; std::vector<std::byte> body; };
    bool bad_status = false;
    Task<Result<Response>> request(http::Headers fields, std::vector<std::byte> body, OperationOptions io) {
        CHECK(!io.stop.stop_requested());
        http::Request mapped;
        for (const auto& field : fields) {
            if (field.name == ":method") mapped.method = http::method_from_token(field.value);
            else if (field.name == ":path") mapped.target = field.value;
            else if (field.name == ":scheme") CHECK(field.value == "https");
            else if (field.name == ":authority") mapped.headers.append("host", field.value);
            else mapped.headers.append(field.name, field.value);
        }
        auto wire = doh::decode_request(mapped, body);
        if (!wire) co_return fail(wire.error());
        auto question = decode(*wire);
        if (!question) co_return fail(question.error());
        CHECK(question->header.id == 0);
        question->header.qr = true;
        question->header.rcode = rcode::nxdomain;
        auto encoded = encode(*question);
        if (!encoded) co_return fail(encoded.error());
        co_return Response{{{":status", bad_status ? "20x" : "200"},
                            {"content-type", "application/dns-message"}}, std::move(*encoded)};
    }
};
Task<void> multiplexed_status_validation() {
    test::section("DoH GET/POST over multiplexed request contract");
    MultiplexedPeer peer;
    auto question = make_query(*Name::parse("mira.test"), type::aaaa, {.id = 12});
    for (const auto method : {doh::Method::get, doh::Method::post}) {
        const auto result = co_await doh::query_multiplexed(peer, "localhost", "/dns-query", *question, method);
        CHECK(result && result->header.rcode == rcode::nxdomain);
    }
    peer.bad_status = true;
    const auto invalid = co_await doh::query_multiplexed(peer, "localhost", "/dns-query", *question);
    CHECK(!invalid && invalid.error() == DnsError::bad_status);
}

}  // namespace

int main() {
    base64();
    mapping();
    response_age();
    auto loop = EventLoop::create();
    if (!loop) return 1;
    if (!loop->run_until_complete(loopback(*loop))) return 1;
    if (!loop->run_until_complete(multiplexed_status_validation())) return 1;
    return test::summary();
}
