#include "mira/ws/extended_connect.hpp"
#include "check.hpp"

#include <algorithm>
#include <string>
#include <string_view>

using namespace Mira;
using namespace Mira::ws;
namespace {
http::Headers request(const HandshakeOptions& options = {}) {
    auto result = extended_connect_request("localhost:443", "/chat?room=one", options);
    CHECK(result.has_value());
    return result ? std::move(*result) : http::Headers{};
}
std::string_view value(const http::Headers& fields, std::string_view name) {
    for (const auto& field : fields) if (field.name == name) return field.value;
    return {};
}
void set(http::Headers& fields, std::string_view name, std::string replacement) {
    for (auto& field : fields) if (field.name == name) { field.value = std::move(replacement); return; }
}
std::size_t field_bytes(const http::Headers& fields) {
    std::size_t result = 0;
    for (const auto& field : fields) result += field.name.size() + field.value.size() + 32;
    return result;
}
template<class T> void invalid(const Result<T>& result) {
    CHECK(!result && result.error() == ws::make_error_code(ws::Errc::invalid_handshake));
}
template<class T> void exceeded(const Result<T>& result) {
    CHECK(!result && result.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));
}
void basic_fields() {
    auto fields = request();
    CHECK(fields.size() == 6);
    CHECK(value(fields, ":method") == "CONNECT");
    CHECK(value(fields, ":protocol") == "websocket");
    CHECK(value(fields, ":scheme") == "https");
    CHECK(value(fields, ":authority") == "localhost:443");
    CHECK(value(fields, ":path") == "/chat?room=one");
    CHECK(value(fields, "sec-websocket-version") == "13");
    auto accepted = accept_extended_connect(fields);
    CHECK(accepted.has_value());
    if (!accepted) return;
    CHECK(accepted->fields.size() == 1 && value(accepted->fields, ":status") == "200");
    CHECK(accepted->negotiated.subprotocol.empty() && !accepted->negotiated.compression.enabled);
    CHECK(validate_extended_connect(accepted->fields).has_value());
    auto cookies = accepted->fields;
    cookies.push_back({"set-cookie", "one=1"});
    cookies.push_back({"set-cookie", "two=2"});
    CHECK(validate_extended_connect(cookies).has_value());
    cookies.push_back({":status", "200"});
    invalid(validate_extended_connect(cookies));
    auto offer = extended_connect_offer();
    CHECK(offer && offer->size() == 1);
    if (offer) {
        CHECK(negotiate_extended_server(*offer).has_value());
        invalid(accept_extended_connect(*offer));
    }
    CHECK(negotiate_extended_client(201, {}).has_value());
    invalid(validate_extended_connect({}));
    set(fields, ":scheme", "http");
    CHECK(accept_extended_connect(fields).has_value());
    fields.push_back({"te", "trailers"});
    fields.push_back({"host", "localhost:443"});
    CHECK(accept_extended_connect(fields).has_value());
    set(fields, "host", "other.example");
    invalid(accept_extended_connect(fields));
    CHECK(extended_connect_request("[::1]:443", "/chat").has_value());
    CHECK(extended_connect_request("example.test", "/encoded%20path?q=1").has_value());
}
void invalid_request_fields() {
    const auto base = request();
    for (std::size_t index = 0; index < base.size(); ++index) {
        auto fields = base;
        fields.erase(fields.begin() + static_cast<std::ptrdiff_t>(index));
        invalid(accept_extended_connect(fields));
        invalid(negotiate_extended_server(fields));
        fields = base;
        fields.insert(fields.begin() + static_cast<std::ptrdiff_t>(index), base[index]);
        invalid(accept_extended_connect(fields));
    }
    for (const auto& [name, replacement] : std::initializer_list<std::pair<std::string_view, std::string_view>>{
             {":method", "GET"}, {":method", "connect"}, {":protocol", "WebSocket"}, {":protocol", "other"},
             {":scheme", "wss"}, {":scheme", "HTTPS"}, {":authority", ""}, {":authority", "user@localhost"},
             {":authority", "localhost/path"}, {":authority", "localhost#fragment"}, {":authority", "localhost:abc"},
             {":authority", "localhost:"}, {":authority", "[::1"}, {":authority", "[::1]extra"},
             {":path", ""}, {":path", "*"}, {":path", "https://localhost/chat"}, {":path", "/chat#fragment"},
             {"sec-websocket-version", ""}, {"sec-websocket-version", "12"}, {"sec-websocket-version", "013"},
             {"sec-websocket-version", "13, 13"}, {"sec-websocket-version", "13 "}}) {
        auto fields = base;
        set(fields, name, std::string(replacement));
        invalid(accept_extended_connect(fields));
        invalid(negotiate_extended_server(fields));
    }
    for (std::string_view name : {":unknown", ":status", ":", "Sec-WebSocket-Version", "bad name", "bad:name", ""}) {
        auto fields = base;
        fields.insert(fields.begin(), {std::string(name), "200"});
        invalid(accept_extended_connect(fields));
    }
    auto reordered = base;
    std::swap(reordered.front(), reordered.back());
    invalid(accept_extended_connect(reordered));
    for (std::string_view host : {"", "user@host", "host/path", "host?query", "host#fragment", "host\\x", "host:abc",
                                  "host:", ":443", "::1", "[]", "[::1", "[::1]:abc", "host<bad>", "host%zz", "host\r\nInjected: yes"})
        invalid(extended_connect_request(host));
    for (std::string_view path : {"", "*", "chat", "/chat#fragment", "/a b", "/a\\b", "/a<b", "/bad%", "/bad%2x", "/a\r\nb"})
        invalid(extended_connect_request("localhost", path));
}
void forbidden_and_injected_fields() {
    const auto base = request();
    for (std::string_view name : {"connection", "proxy-connection", "keep-alive", "upgrade", "transfer-encoding",
                                  "content-length", "sec-websocket-key", "sec-websocket-accept"}) {
        auto fields = base;
        fields.push_back({std::string(name), "0"});
        invalid(accept_extended_connect(fields));
        http::Headers response{{":status", "200"}, {std::string(name), "0"}};
        invalid(validate_extended_connect(response));
    }
    for (std::string_view te : {"", "gzip", "trailers, gzip", "Trailers"}) {
        auto fields = base;
        fields.push_back({"te", std::string(te)});
        invalid(accept_extended_connect(fields));
    }
    for (std::string_view name : {"te", "sec-websocket-version"}) {
        http::Headers response{{":status", "200"}, {std::string(name), "13"}};
        invalid(validate_extended_connect(response));
    }
    for (const std::string& injected : {std::string("a\r\nInjected: yes"), std::string("a\nb"),
                                       std::string("a\rb"), std::string("a\0b", 3), std::string("a\x7f"),
                                       std::string("a\x01"), std::string(" leading"), std::string("trailing\t")}) {
        auto fields = base;
        fields.push_back({"x-test", injected});
        invalid(accept_extended_connect(fields));
        http::Headers response{{":status", "200"}, {"x-test", injected}};
        invalid(validate_extended_connect(response));
    }
    auto duplicate = base;
    duplicate.push_back({"x-test", "a"});
    duplicate.push_back({"x-test", "b"});
    invalid(accept_extended_connect(duplicate));
    http::Headers duplicate_response{{":status", "200"}, {"x-test", "a"}, {"x-test", "b"}};
    invalid(validate_extended_connect(duplicate_response));
}
void status_and_subprotocols() {
    for (unsigned status : {200U, 201U, 202U, 205U, 299U}) {
        http::Headers response{{":status", std::to_string(status)}};
        CHECK(validate_extended_connect(response).has_value());
        CHECK(negotiate_extended_client(status, response).has_value());
        invalid(negotiate_extended_client(status == 200 ? 201 : 200, response));
    }
    for (std::string_view status : {"", "099", "101", "199", "300", "403", "599", "600", "2000", "+200", "20x", " 200"}) {
        http::Headers response{{":status", std::string(status)}};
        invalid(validate_extended_connect(response));
    }
    http::Headers no_content{{":status", "204"}};
    auto unsupported = validate_extended_connect(no_content);
    CHECK(!unsupported && unsupported.error() == Mira::Errc::not_supported);
    unsupported = negotiate_extended_client(204, {});
    CHECK(!unsupported && unsupported.error() == Mira::Errc::not_supported);
    for (const http::Headers& response : {http::Headers{{":status", "200"}, {":status", "200"}},
                                           http::Headers{{"x-test", "a"}, {":status", "200"}},
                                           http::Headers{{":status", "200"}, {":method", "CONNECT"}}})
        invalid(validate_extended_connect(response));
    HandshakeOptions client;
    client.subprotocols = {"chat", "chat.v2"};
    client.require_subprotocol = true;
    HandshakeOptions server = client;
    std::reverse(server.subprotocols.begin(), server.subprotocols.end());
    auto accepted = accept_extended_connect(request(client), server);
    CHECK(accepted && accepted->negotiated.subprotocol == "chat.v2");
    if (accepted) {
        auto selected = validate_extended_connect(accepted->fields, client);
        CHECK(selected && selected->subprotocol == "chat.v2");
    }
    for (std::string_view protocol : {"", "chat,", "chat, chat", "chat, chat.v2", "Chat", "unoffered", "chat room"}) {
        http::Headers response{{":status", "200"}, {"sec-websocket-protocol", std::string(protocol)}};
        invalid(validate_extended_connect(response, client));
    }
    http::Headers missing{{":status", "200"}};
    invalid(validate_extended_connect(missing, client));
    auto fields = request();
    fields.push_back({"sec-websocket-protocol", "chat"});
    fields.push_back({"sec-websocket-protocol", "chat.v2"});
    CHECK(accept_extended_connect(fields, server).has_value());
    fields.back().value = "chat";
    invalid(accept_extended_connect(fields, server));
    http::Headers duplicate{{":status", "200"}, {"sec-websocket-protocol", "chat"}, {"sec-websocket-protocol", "chat"}};
    invalid(validate_extended_connect(duplicate, client));
    for (const auto& names : std::vector<std::vector<std::string>>{{"chat", "chat"}, {""}, {"chat\r\nX: x"}}) {
        client.subprotocols = names;
        auto result = extended_connect_request("localhost", "/", client);
        CHECK(!result && result.error() == Mira::Errc::invalid_argument);
    }
}
void compression() {
    HandshakeOptions client;
    client.compression.enabled = true;
    client.compression.server_no_context_takeover = true;
    client.compression.server_max_window_bits = 12;
    client.compression.client_max_window_bits = 13;
    HandshakeOptions server = client;
    server.compression.server_max_window_bits = 11;
    server.compression.client_max_window_bits = 10;
    auto accepted = accept_extended_connect(request(client), server);
    CHECK(accepted && accepted->negotiated.compression.enabled);
    if (accepted) {
        auto selected = validate_extended_connect(accepted->fields, client);
        CHECK(selected && selected->compression.enabled && selected->compression.server_no_context_takeover);
        CHECK(selected && selected->compression.server_max_window_bits == 11 && selected->compression.client_max_window_bits == 10);
        invalid(validate_extended_connect(accepted->fields));
    }
    for (std::string_view extension : {"unknown", "permessage-deflate", "permessage-deflate; server_no_context_takeover",
             "permessage-deflate; server_no_context_takeover; server_max_window_bits=13",
             "permessage-deflate; server_no_context_takeover; server_max_window_bits=12; client_max_window_bits=8",
             "permessage-deflate; server_no_context_takeover; server_max_window_bits=12; unknown",
             "permessage-deflate; server_no_context_takeover; server_max_window_bits=12; server_max_window_bits=12",
             "permessage-deflate, permessage-deflate", "permessage-deflate;"}) {
        http::Headers response{{":status", "200"}, {"sec-websocket-extensions", std::string(extension)}};
        invalid(validate_extended_connect(response, client));
    }
    client = {};
    client.compression.enabled = true;
    client.compression.offer_client_max_window_bits = false;
    http::Headers unoffered{{":status", "200"}, {"sec-websocket-extensions", "permessage-deflate; client_max_window_bits=12"}};
    invalid(validate_extended_connect(unoffered, client));
    auto fields = request();
    fields.push_back({"sec-websocket-extensions", "permessage-deflate; server_max_window_bits=8"});
    fields.push_back({"sec-websocket-extensions", "permessage-deflate; server_max_window_bits=10"});
    accepted = accept_extended_connect(fields, client);
    CHECK(accepted && accepted->negotiated.compression.enabled && accepted->negotiated.compression.server_max_window_bits == 10);
    fields.back().value = "permessage-deflate; server_max_window_bits=10; server_max_window_bits=11";
    accepted = accept_extended_connect(fields, client);
    CHECK(accepted && !accepted->negotiated.compression.enabled);
    fields.back().value = "permessage-deflate;";
    invalid(accept_extended_connect(fields, client));
    http::Headers duplicate{{":status", "200"}, {"sec-websocket-extensions", "permessage-deflate"},
                            {"sec-websocket-extensions", "permessage-deflate"}};
    invalid(validate_extended_connect(duplicate, client));
    client.compression.client_max_window_bits = 8;
    auto unsupported = extended_connect_request("localhost", "/", client);
    CHECK(!unsupported && unsupported.error() == Mira::Errc::not_supported);
}
void limits() {
    HandshakeOptions options;
    options.subprotocols = {"chat"};
    options.compression.enabled = true;
    const auto fields = request(options);
    Limits limit;
    limit.max_handshake = field_bytes(fields);
    CHECK(extended_connect_request("localhost:443", "/chat?room=one", options, limit).has_value());
    CHECK(accept_extended_connect(fields, options, limit).has_value());
    --limit.max_handshake;
    exceeded(extended_connect_request("localhost:443", "/chat?room=one", options, limit));
    exceeded(accept_extended_connect(fields, options, limit));
    exceeded(negotiate_extended_server(fields, options, limit));
    auto accepted = accept_extended_connect(fields, options);
    CHECK(accepted.has_value());
    if (accepted) {
        limit.max_handshake = field_bytes(accepted->fields);
        CHECK(validate_extended_connect(accepted->fields, options, limit).has_value());
        --limit.max_handshake;
        exceeded(validate_extended_connect(accepted->fields, options, limit));
        exceeded(negotiate_extended_client(200, accepted->fields, options, limit));
    }
    auto offer = extended_connect_offer(options);
    CHECK(offer.has_value());
    if (offer) {
        limit.max_handshake = field_bytes(*offer);
        CHECK(extended_connect_offer(options, limit).has_value());
        --limit.max_handshake;
        exceeded(extended_connect_offer(options, limit));
    }
    http::Headers compact{{"sec-websocket-version", "13"}, {"sec-websocket-extensions", "permessage-deflate;client_max_window_bits"}};
    options.compression.server_no_context_takeover = true;
    options.compression.client_no_context_takeover = true;
    options.compression.server_max_window_bits = 10;
    options.compression.client_max_window_bits = 10;
    limit.max_handshake = field_bytes(compact);
    exceeded(negotiate_extended_server(compact, options, limit));
    limit.max_handshake = 0;
    exceeded(extended_connect_offer({}, limit));
    exceeded(extended_connect_request("localhost", "/", {}, limit));
    exceeded(accept_extended_connect(fields, {}, limit));
    http::Headers response{{":status", "200"}};
    exceeded(validate_extended_connect(response, {}, limit));
    limit.max_handshake = 128;
    options.subprotocols = {std::string(129, 'a')};
    exceeded(extended_connect_offer(options, limit));
    exceeded(extended_connect_request(std::string(129, 'a'), "/", {}, limit));
    exceeded(extended_connect_request("localhost", "/" + std::string(128, 'a'), {}, limit));
}
}
int main() {
    basic_fields();
    invalid_request_fields();
    forbidden_and_injected_fields();
    status_and_subprotocols();
    compression();
    limits();
    return Mira::test::summary();
}
