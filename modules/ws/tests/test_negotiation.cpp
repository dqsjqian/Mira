#include "mira/ws/handshake.hpp"
#include "check.hpp"

#include <algorithm>
#include <string>
#include <string_view>

using namespace Mira;
using namespace Mira::ws;
namespace {
constexpr std::string_view key = "dGhlIHNhbXBsZSBub25jZQ==";
std::string request(std::string_view extra = {}) {
    return "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Key: " + std::string(key) + "\r\nSec-WebSocket-Version: 13\r\n" + std::string(extra) + "\r\n";
}
std::string response(std::string_view extra = {}) {
    return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" + std::string(extra) + "\r\n";
}
std::string extension(std::string_view value) {
    return "Sec-WebSocket-Extensions: " + std::string(value) + "\r\n";
}
HandshakeOptions deflate_options() {
    HandshakeOptions result;
    result.compression.enabled = true;
    return result;
}
template<class T>
void invalid_handshake(const Result<T>& result) {
    CHECK(!result && result.error() == ws::make_error_code(ws::Errc::invalid_handshake));
}
template<class T>
void invalid_argument(const Result<T>& result) {
    CHECK(!result && result.error() == Mira::make_error_code(Mira::Errc::invalid_argument));
}
template<class T>
void exceeded(const Result<T>& result) {
    CHECK(!result && result.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));
}
void defaults_and_compatibility() {
    auto accept = accept_key(key);
    CHECK(accept && *accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    auto client = client_handshake("server.example.com", "/chat");
    CHECK(client.has_value());
    if (!client) return;
    CHECK(client->request.find("Sec-WebSocket-Protocol:") == std::string::npos);
    CHECK(client->request.find("Sec-WebSocket-Extensions:") == std::string::npos);
    auto server = server_handshake(client->request);
    CHECK(server.has_value());
    if (!server) return;
    CHECK(validate_server_handshake(*server, client->key).has_value());
    auto negotiated = negotiate_client_handshake(*server, client->key, {});
    CHECK(negotiated && negotiated->subprotocol.empty() && !negotiated->compression.enabled);
    invalid_handshake(validate_server_handshake(response(extension("permessage-deflate")), key));
    invalid_handshake(validate_server_handshake(response("Sec-WebSocket-Protocol: chat\r\n"), key));
    auto ignored = negotiate_server_handshake(request(extension("permessage-deflate")), {});
    CHECK(ignored && !ignored->negotiated.compression.enabled);
    CHECK(ignored && ignored->response == response());
    invalid_handshake(client_handshake("server\r\nInjected: yes", "/", {}));
    invalid_handshake(client_handshake("server", "/x y", {}));
    invalid_handshake(client_handshake("server", "/#fragment", {}));
}
void subprotocols() {
    HandshakeOptions client_options;
    client_options.subprotocols = {"chat", "superchat", "Chat"};
    auto client = client_handshake("server", "/", client_options);
    CHECK(client.has_value());
    if (!client) return;
    CHECK(client->request.find("Sec-WebSocket-Protocol: chat, superchat, Chat\r\n") != std::string::npos);
    HandshakeOptions server_options;
    server_options.subprotocols = {"superchat", "chat"};
    server_options.require_subprotocol = true;
    auto server = negotiate_server_handshake(client->request, server_options);
    CHECK(server && server->negotiated.subprotocol == "superchat");
    if (server) {
        auto selected = negotiate_client_handshake(server->response, client->key, client_options);
        CHECK(selected && selected->subprotocol == "superchat");
    }
    auto multiple = negotiate_server_handshake(request("Sec-WebSocket-Protocol: chat\r\nsec-websocket-protocol: superchat, Chat\r\n"), server_options);
    CHECK(multiple && multiple->negotiated.subprotocol == "superchat");
    auto whitespace = negotiate_server_handshake(request("Sec-WebSocket-Protocol:\tchat ,\t superchat \t\r\n"), server_options);
    CHECK(whitespace && whitespace->negotiated.subprotocol == "superchat");
    server_options.subprotocols = {"CHAT"};
    invalid_handshake(negotiate_server_handshake(client->request, server_options));
    server_options.require_subprotocol = false;
    auto no_match = negotiate_server_handshake(client->request, server_options);
    CHECK(no_match && no_match->negotiated.subprotocol.empty());
    CHECK(no_match && no_match->response.find("Sec-WebSocket-Protocol") == std::string::npos);
    server_options.require_subprotocol = true;
    invalid_handshake(negotiate_server_handshake(request(), server_options));
    client_options.require_subprotocol = true;
    invalid_handshake(negotiate_client_handshake(response(), key, client_options));
    client_options.require_subprotocol = false;
    CHECK(negotiate_client_handshake(response(), key, client_options).has_value());
    for (std::string_view bad : {"", "chat,", ",chat", "chat,,superchat", "chat, chat", "chat room", "\"chat\"", "chat/superchat"}) {
        auto field = "Sec-WebSocket-Protocol: " + std::string(bad) + "\r\n";
        invalid_handshake(negotiate_server_handshake(request(field), {}));
        invalid_handshake(negotiate_client_handshake(response(field), key, client_options));
    }
    invalid_handshake(negotiate_server_handshake(request("Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: chat\r\n"), {}));
    invalid_handshake(negotiate_client_handshake(response("Sec-WebSocket-Protocol: chat, superchat\r\n"), key, client_options));
    invalid_handshake(negotiate_client_handshake(response("Sec-WebSocket-Protocol: chat\r\nsec-websocket-protocol: superchat\r\n"), key, client_options));
    invalid_handshake(negotiate_client_handshake(response("Sec-WebSocket-Protocol: chat\r\nsec-websocket-protocol: chat\r\n"), key, client_options));
    invalid_handshake(negotiate_client_handshake(response("Sec-WebSocket-Protocol: CHAT\r\n"), key, client_options));
    invalid_handshake(negotiate_client_handshake(response("Sec-WebSocket-Protocol: unoffered\r\n"), key, client_options));
    for (const auto& bad : std::vector<std::vector<std::string>>{{"chat", "chat"}, {""}, {" chat"}, {"chat "}, {"chat,other"}, {"chat\r\nInjected: yes"}, {"a/b"}, {"a\tb"}, {"\xc3\xa9"}}) {
        HandshakeOptions options;
        options.subprotocols = bad;
        invalid_argument(client_handshake("server", "/", options));
        invalid_argument(negotiate_server_handshake(request(), options));
        invalid_argument(negotiate_client_handshake(response(), key, options));
    }
    HandshakeOptions required;
    required.require_subprotocol = true;
    invalid_argument(client_handshake("server", "/", required));
    invalid_argument(negotiate_server_handshake(request(), required));
    HandshakeOptions punctuation;
    punctuation.subprotocols = {"!#$%&'*+-.^_`|~", "Case", "case"};
    CHECK(client_handshake("server", "/", punctuation).has_value());
}
void compression_roundtrips() {
    auto options = deflate_options();
    auto client = client_handshake("server", "/", options);
    CHECK(client.has_value());
    if (!client) return;
    CHECK(client->request.find("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n") != std::string::npos);
    auto server = negotiate_server_handshake(client->request, options);
    CHECK(server && server->negotiated.compression.enabled);
    if (server) {
        auto selected = negotiate_client_handshake(server->response, client->key, options);
        CHECK(selected && selected->compression.enabled);
        CHECK(selected && selected->compression.server_max_window_bits == 15);
        CHECK(selected && selected->compression.client_max_window_bits == 15);
    }
    auto declined = negotiate_client_handshake(response(), key, options);
    CHECK(declined && !declined->compression.enabled);
    options.compression.offer_client_max_window_bits = false;
    client = client_handshake("server", "/", options);
    CHECK(client && client->request.find("Sec-WebSocket-Extensions: permessage-deflate\r\n") != std::string::npos);
    auto bare = negotiate_server_handshake(request(extension("permessage-deflate")), options);
    CHECK(bare && bare->response == response(extension("permessage-deflate")));
    invalid_handshake(negotiate_client_handshake(response(extension("permessage-deflate; client_max_window_bits=15")), key, options));
    CHECK(negotiate_client_handshake(response(extension("permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=8")), key, options).has_value());

    auto configured_client = deflate_options();
    configured_client.subprotocols = {"chat"};
    configured_client.compression.server_no_context_takeover = true;
    configured_client.compression.client_no_context_takeover = true;
    configured_client.compression.server_max_window_bits = 12;
    configured_client.compression.client_max_window_bits = 13;
    auto configured_server = deflate_options();
    configured_server.subprotocols = {"chat"};
    configured_server.compression.server_max_window_bits = 11;
    configured_server.compression.client_max_window_bits = 10;
    client = client_handshake("server", "/", configured_client);
    CHECK(client.has_value());
    if (!client) return;
    server = negotiate_server_handshake(client->request, configured_server);
    CHECK(server.has_value());
    if (!server) return;
    auto selected = negotiate_client_handshake(server->response, client->key, configured_client);
    CHECK(selected && selected->subprotocol == "chat");
    CHECK(selected && selected->compression.server_no_context_takeover && selected->compression.client_no_context_takeover);
    CHECK(selected && selected->compression.server_max_window_bits == 11 && selected->compression.client_max_window_bits == 10);
    CHECK(server->negotiated.compression.server_max_window_bits == 11 && server->negotiated.compression.client_max_window_bits == 10);

    auto added = deflate_options();
    added.compression.server_no_context_takeover = true;
    added.compression.client_no_context_takeover = true;
    added.compression.server_max_window_bits = 9;
    auto unsolicited = negotiate_server_handshake(request(extension("permessage-deflate")), added);
    CHECK(unsolicited && unsolicited->negotiated.compression.enabled);
    CHECK(unsolicited && unsolicited->response.find("client_no_context_takeover") != std::string::npos);
    CHECK(unsolicited && unsolicited->response.find("server_max_window_bits=9") != std::string::npos);
    CHECK(unsolicited && negotiate_client_handshake(unsolicited->response, key, options).has_value());

    // RFC7692 7.1.3 single offers and multiple-offer fallback.
    auto vector = negotiate_server_handshake(request(extension("permessage-deflate; client_max_window_bits; server_max_window_bits=10")), deflate_options());
    CHECK(vector && vector->response == response(extension("permessage-deflate; server_max_window_bits=10")));
    auto fallback = negotiate_server_handshake(request(extension("permessage-deflate; client_max_window_bits; server_max_window_bits=8, permessage-deflate; client_max_window_bits; server_max_window_bits=10")), deflate_options());
    CHECK(fallback && fallback->negotiated.compression.enabled && fallback->negotiated.compression.server_max_window_bits == 10);
    auto multiheader = negotiate_server_handshake(request(extension("unknown; value=token") + extension("permessage-deflate; server_max_window_bits=8") + extension("permessage-deflate; server_max_window_bits=11")), deflate_options());
    CHECK(multiheader && multiheader->negotiated.compression.enabled && multiheader->negotiated.compression.server_max_window_bits == 11);
    auto unknown = negotiate_server_handshake(request(extension("unknown; token=\"quoted\"")), deflate_options());
    CHECK(unknown && !unknown->negotiated.compression.enabled);
    auto quoted = negotiate_server_handshake(request(extension("permessage-deflate ; server_max_window_bits = \"1\\0\" ; client_max_window_bits=\"9\"")), deflate_options());
    CHECK(quoted && quoted->negotiated.compression.server_max_window_bits == 10 && quoted->negotiated.compression.client_max_window_bits == 9);
}
void compression_response_rules() {
    auto options = deflate_options();
    options.compression.server_max_window_bits = 10;
    options.compression.server_no_context_takeover = true;
    for (std::string_view bad : {"permessage-deflate", "permessage-deflate; server_no_context_takeover", "permessage-deflate; server_max_window_bits=10", "permessage-deflate; server_no_context_takeover; server_max_window_bits=11"})
        invalid_handshake(negotiate_client_handshake(response(extension(bad)), key, options));
    auto compatible = negotiate_client_handshake(response(extension("permessage-deflate; server_no_context_takeover; server_max_window_bits=9")), key, options);
    CHECK(compatible && compatible->compression.server_max_window_bits == 9);
    options.compression.server_max_window_bits = 15;
    invalid_handshake(negotiate_client_handshake(response(extension("permessage-deflate; server_no_context_takeover")), key, options));

    options = deflate_options();
    options.compression.client_max_window_bits = 9;
    options.compression.client_no_context_takeover = true;
    auto ignored = negotiate_client_handshake(response(extension("permessage-deflate")), key, options);
    CHECK(ignored && ignored->compression.client_max_window_bits == 15 && !ignored->compression.client_no_context_takeover);
    auto larger = negotiate_client_handshake(response(extension("permessage-deflate; client_max_window_bits=15")), key, options);
    CHECK(larger && larger->compression.client_max_window_bits == 15);
    options.compression.offer_client_max_window_bits = false;
    auto numeric = client_handshake("server", "/", options);
    CHECK(numeric && numeric->request.find("client_max_window_bits=9") != std::string::npos);
    CHECK(negotiate_client_handshake(response(extension("permessage-deflate; client_max_window_bits=10")), key, options).has_value());
    auto required_offer = deflate_options();
    required_offer.compression.client_max_window_bits = 10;
    auto no_offer = negotiate_server_handshake(request(extension("permessage-deflate")), required_offer);
    CHECK(no_offer && !no_offer->negotiated.compression.enabled);
    auto offered = negotiate_server_handshake(request(extension("permessage-deflate; client_max_window_bits")), required_offer);
    CHECK(offered && offered->negotiated.compression.enabled && offered->negotiated.compression.client_max_window_bits == 10);
    required_offer.compression.client_max_window_bits = 15;
    no_offer = negotiate_server_handshake(request(extension("permessage-deflate")), required_offer);
    CHECK(no_offer && no_offer->negotiated.compression.enabled && no_offer->response.find("client_max_window_bits") == std::string::npos);

    options = deflate_options();
    for (std::string_view bad : {"unknown", "PerMessage-Deflate", "permessage-deflate, permessage-deflate", "permessage-deflate, unknown",
         "permessage-deflate; unknown", "permessage-deflate; SERVER_MAX_WINDOW_BITS=10",
         "permessage-deflate; server_no_context_takeover=1", "permessage-deflate; client_no_context_takeover=1",
         "permessage-deflate; server_max_window_bits", "permessage-deflate; client_max_window_bits",
         "permessage-deflate; server_max_window_bits=7", "permessage-deflate; server_max_window_bits=16",
         "permessage-deflate; client_max_window_bits=7", "permessage-deflate; client_max_window_bits=16",
         "permessage-deflate; server_max_window_bits=08", "permessage-deflate; client_max_window_bits=+9",
         "permessage-deflate; server_max_window_bits=-9", "permessage-deflate; server_max_window_bits=9.0",
         "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
         "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
         "permessage-deflate; server_max_window_bits=10; server_max_window_bits=10",
         "permessage-deflate; client_max_window_bits=10; client_max_window_bits=11",
         "permessage-deflate; client_max_window_bits=8"})
        invalid_handshake(negotiate_client_handshake(response(extension(bad)), key, options));
    invalid_handshake(negotiate_client_handshake(response(extension("permessage-deflate") + extension("permessage-deflate")), key, options));
    invalid_handshake(negotiate_client_handshake(response(extension("permessage-deflate")), key, {}));
    auto quoted = negotiate_client_handshake(response(extension("permessage-deflate; server_max_window_bits=\"8\"; client_max_window_bits=\"1\\2\"")), key, options);
    CHECK(quoted && quoted->compression.server_max_window_bits == 8 && quoted->compression.client_max_window_bits == 12);
}
void compression_invalid_offers() {
    auto options = deflate_options();
    for (std::string_view bad : {"permessage-deflate; unknown", "permessage-deflate; SERVER_MAX_WINDOW_BITS=10",
         "permessage-deflate; server_no_context_takeover=1", "permessage-deflate; client_no_context_takeover=1",
         "permessage-deflate; server_max_window_bits", "permessage-deflate; server_max_window_bits=7",
         "permessage-deflate; server_max_window_bits=16", "permessage-deflate; server_max_window_bits=08",
         "permessage-deflate; client_max_window_bits=+9", "permessage-deflate; client_max_window_bits=16",
         "permessage-deflate; server_max_window_bits=999999999999999999999999999999999999",
         "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
         "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
         "permessage-deflate; server_max_window_bits=10; server_max_window_bits=10",
         "permessage-deflate; client_max_window_bits; client_max_window_bits=10"}) {
        auto declined = negotiate_server_handshake(request(extension(bad)), options);
        CHECK(declined && !declined->negotiated.compression.enabled);
        CHECK(declined && declined->response.find("Sec-WebSocket-Extensions") == std::string::npos);
        auto fallback = negotiate_server_handshake(request(extension(std::string(bad) + ", permessage-deflate")), options);
        CHECK(fallback && fallback->negotiated.compression.enabled);
    }
    for (std::string_view malformed : {"", " ", ",permessage-deflate", "permessage-deflate,", "permessage-deflate,,unknown",
         "permessage-deflate;", "permessage-deflate; =10", "permessage-deflate; server_max_window_bits=",
         "permessage-deflate; server_max_window_bits=\"\"", "permessage-deflate; server_max_window_bits=\"10",
         "permessage-deflate; server_max_window_bits=\"1 0\"", "permessage-deflate; server_max_window_bits=\"10,\"",
         "permessage-deflate; server_max_window_bits=\"10\"extra", "permessage-deflate; server_max_window_bits=1/0",
         "permessage-deflate; server_max_window_bits=\"1\\\"0\"", "permessage-deflate other", "permessage-deflate; server_max_window_bits==10",
         "permessage-deflate; server_max_window_bits=\"10\\"}) {
        invalid_handshake(negotiate_server_handshake(request(extension(malformed)), options));
        invalid_handshake(negotiate_client_handshake(response(extension(malformed)), key, options));
    }
    auto injected = request(extension("permessage-deflate"));
    injected.insert(injected.size() - 2, "\tserver_max_window_bits=10\r\n");
    invalid_handshake(negotiate_server_handshake(injected, options));
}
void window_boundaries() {
    for (unsigned bits = 8; bits <= 15; ++bits) {
        auto options = deflate_options();
        auto server_offer = "permessage-deflate; server_max_window_bits=" + std::to_string(bits);
        auto server = negotiate_server_handshake(request(extension(server_offer)), options);
        CHECK(server.has_value());
        if (bits == 8) CHECK(server && !server->negotiated.compression.enabled);
        else CHECK(server && server->negotiated.compression.server_max_window_bits == bits);
        auto client = negotiate_client_handshake(response(extension(server_offer)), key, options);
        CHECK(client && client->compression.server_max_window_bits == bits);
        auto client_offer = "permessage-deflate; client_max_window_bits=" + std::to_string(bits);
        server = negotiate_server_handshake(request(extension(client_offer)), options);
        CHECK(server && server->negotiated.compression.client_max_window_bits == bits);
        client = negotiate_client_handshake(response(extension(client_offer)), key, options);
        if (bits == 8) invalid_handshake(client);
        else CHECK(client && client->compression.client_max_window_bits == bits);
    }
    for (unsigned bits : {0U, 7U, 16U, 100U}) {
        auto options = deflate_options();
        options.compression.server_max_window_bits = bits;
        invalid_argument(client_handshake("server", "/", options));
        invalid_argument(negotiate_server_handshake(request(), options));
        invalid_argument(negotiate_client_handshake(response(), key, options));
        options.compression.server_max_window_bits.reset();
        options.compression.client_max_window_bits = bits;
        invalid_argument(client_handshake("server", "/", options));
        invalid_argument(negotiate_server_handshake(request(), options));
        invalid_argument(negotiate_client_handshake(response(), key, options));
    }
    auto unsupported = deflate_options();
    unsupported.compression.client_max_window_bits = 8;
    auto client = client_handshake("server", "/", unsupported);
    CHECK(!client && client.error() == Mira::make_error_code(Mira::Errc::not_supported));
    auto receive8 = negotiate_server_handshake(request(extension("permessage-deflate; client_max_window_bits")), unsupported);
    CHECK(receive8 && receive8->negotiated.compression.client_max_window_bits == 8);
    unsupported.compression.client_max_window_bits.reset();
    unsupported.compression.server_max_window_bits = 8;
    auto server = negotiate_server_handshake(request(), unsupported);
    CHECK(!server && server.error() == Mira::make_error_code(Mira::Errc::not_supported));
    client = client_handshake("server", "/", unsupported);
    CHECK(client && client->request.find("server_max_window_bits=8") != std::string::npos);
    CHECK(negotiate_client_handshake(response(extension("permessage-deflate; server_max_window_bits=8")), key, unsupported).has_value());
    unsupported.compression.enabled = false;
    CHECK(negotiate_server_handshake(request(), unsupported).has_value());
}
void negotiated_parameter_matrix() {
    const std::vector<std::optional<unsigned>> send_bits{std::nullopt, 9, 12, 15};
    const std::vector<std::optional<unsigned>> receive_bits{std::nullopt, 8, 9, 12, 15};
    for (auto client_send : send_bits) for (auto client_receive : receive_bits)
    for (auto server_send : send_bits) for (auto server_receive : receive_bits) {
        auto client_options = deflate_options();
        client_options.compression.client_max_window_bits = client_send;
        client_options.compression.server_max_window_bits = client_receive;
        auto server_options = deflate_options();
        server_options.compression.server_max_window_bits = server_send;
        server_options.compression.client_max_window_bits = server_receive;
        auto client = client_handshake("server", "/", client_options);
        CHECK(client.has_value());
        if (!client) continue;
        auto server = negotiate_server_handshake(client->request, server_options);
        CHECK(server.has_value());
        if (!server) continue;
        auto selected = negotiate_client_handshake(server->response, client->key, client_options);
        if (server->negotiated.compression.enabled && server->negotiated.compression.client_max_window_bits == 8) {
            invalid_handshake(selected);
            continue;
        }
        CHECK(selected.has_value());
        if (!selected) continue;
        const auto& left = selected->compression;
        const auto& right = server->negotiated.compression;
        CHECK(left.enabled == right.enabled);
        CHECK(left.server_max_window_bits == right.server_max_window_bits);
        CHECK(left.client_max_window_bits == right.client_max_window_bits);
    }
    for (unsigned flags = 0; flags < 16; ++flags) {
        auto client_options = deflate_options();
        auto server_options = deflate_options();
        client_options.compression.server_no_context_takeover = (flags & 1) != 0;
        client_options.compression.client_no_context_takeover = (flags & 2) != 0;
        server_options.compression.server_no_context_takeover = (flags & 4) != 0;
        server_options.compression.client_no_context_takeover = (flags & 8) != 0;
        auto client = client_handshake("server", "/", client_options);
        CHECK(client.has_value());
        if (!client) continue;
        auto server = negotiate_server_handshake(client->request, server_options);
        CHECK(server.has_value());
        if (!server) continue;
        auto selected = negotiate_client_handshake(server->response, client->key, client_options);
        CHECK(selected && selected->compression.server_no_context_takeover == ((flags & 5) != 0));
        CHECK(selected && selected->compression.client_no_context_takeover == ((flags & 10) != 0));
    }
}
void limits_and_header_integrity() {
    auto options = deflate_options();
    options.subprotocols = {"chat"};
    auto client = client_handshake("server", "/", options);
    CHECK(client.has_value());
    if (!client) return;
    Limits exact;
    exact.max_handshake = client->request.size();
    CHECK(client_handshake("server", "/", options, exact).has_value());
    CHECK(negotiate_server_handshake(client->request, options, exact).has_value());
    --exact.max_handshake;
    exceeded(client_handshake("server", "/", options, exact));
    exceeded(negotiate_server_handshake(client->request, options, exact));
    auto server = negotiate_server_handshake(client->request, options);
    CHECK(server.has_value());
    if (!server) return;
    exact.max_handshake = server->response.size();
    CHECK(negotiate_client_handshake(server->response, client->key, options, exact).has_value());
    --exact.max_handshake;
    exceeded(negotiate_client_handshake(server->response, client->key, options, exact));
    Limits tiny;
    tiny.max_handshake = 0;
    exceeded(client_handshake("server", "/", {}, tiny));
    exceeded(negotiate_server_handshake(request(), {}, tiny));
    exceeded(negotiate_client_handshake(response(), key, {}, tiny));
    tiny.max_handshake = 256;
    HandshakeOptions oversized;
    oversized.subprotocols = {std::string(257, 'a')};
    exceeded(client_handshake("server", "/", oversized, tiny));
    exceeded(negotiate_server_handshake(request(), oversized, tiny));
    exceeded(client_handshake(std::string(257, 'a'), "/", {}, tiny));
    exceeded(client_handshake("server", "/" + std::string(257, 'a'), {}, tiny));
    // Bound the response even when the request itself is shorter.
    auto compact = request(extension("permessage-deflate;client_max_window_bits"));
    auto expanded_options = deflate_options();
    expanded_options.compression.server_no_context_takeover = true;
    expanded_options.compression.client_no_context_takeover = true;
    expanded_options.compression.server_max_window_bits = 10;
    expanded_options.compression.client_max_window_bits = 10;
    Limits output_limit;
    output_limit.max_handshake = compact.size();
    auto full = negotiate_server_handshake(compact, expanded_options);
    CHECK(full && full->response.size() > compact.size());
    exceeded(negotiate_server_handshake(compact, expanded_options, output_limit));
    for (std::string_view duplicate : {"Host: server.example.com\r\n", "Sec-WebSocket-Version: 13\r\n", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"})
        invalid_handshake(negotiate_server_handshake(request(duplicate), options));
    invalid_handshake(negotiate_client_handshake(response("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"), key, options));
    invalid_handshake(negotiate_server_handshake(request("Transfer-Encoding: chunked\r\n"), options));
    invalid_handshake(negotiate_server_handshake(request("Content-Length: 1\r\n"), options));
    CHECK(negotiate_server_handshake(request("Connection: keep-alive\r\nUpgrade: h2c\r\nContent-Length: 0\r\n"), options).has_value());
    invalid_handshake(negotiate_server_handshake(request("Sec-WebSocket-Extensions : permessage-deflate\r\n"), options));
}
}
void extended_fields() {
    HandshakeOptions options;
    options.subprotocols = {"chat.v2", "chat.v1"};
    options.require_subprotocol = true;
    options.compression.enabled = true;
    auto offer = extended_connect_offer(options);
    CHECK(offer.has_value());
    if (!offer) return;
    auto server = negotiate_extended_server(*offer, options);
    CHECK(server.has_value());
    if (!server) return;
    auto accepted = negotiate_extended_client(200, server->fields, options);
    CHECK(accepted && accepted->subprotocol == "chat.v2" && accepted->compression.enabled);
    for (unsigned status : {101U, 199U, 300U, 403U})
        CHECK(!negotiate_extended_client(status, server->fields, options));
    auto invalid = *offer;
    invalid[0].value = "12";
    CHECK(!negotiate_extended_server(invalid, options));
    for (const auto& name : {"connection", "upgrade", "sec-websocket-key", "sec-websocket-accept"}) {
        invalid = *offer;
        invalid.push_back({name, "invalid"});
        CHECK(!negotiate_extended_server(invalid, options));
    }
    auto reply = server->fields;
    reply.push_back({"sec-websocket-protocol", "chat.v2"});
    CHECK(!negotiate_extended_client(200, reply, options));
    CHECK(!negotiate_extended_client(200, server->fields, {}));
    reply = {{"sec-websocket-protocol", "unoffered"}};
    CHECK(!negotiate_extended_client(200, reply, options));
    invalid = *offer;
    invalid.push_back({"sec-websocket-version", "13"});
    CHECK(!negotiate_extended_server(invalid, options));
    invalid = {{"sec-websocket-version", "13\r\nInjected: value"}};
    CHECK(!negotiate_extended_server(invalid, options));
    Limits tiny;
    tiny.max_handshake = 8;
    CHECK(!extended_connect_offer(options, tiny));
    CHECK(!negotiate_extended_server(*offer, options, tiny));
    CHECK(!negotiate_extended_client(200, server->fields, options, tiny));
}
int main() {
    extended_fields();
    defaults_and_compatibility();
    subprotocols();
    compression_roundtrips();
    compression_response_rules();
    compression_invalid_offers();
    window_boundaries();
    negotiated_parameter_matrix();
    limits_and_header_integrity();
    return Mira::test::summary();
}
