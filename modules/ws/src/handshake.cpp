#include "mira/ws/handshake.hpp"
#include "mira/crypto/crypto.hpp"

#include <algorithm>
#include <map>

namespace Mira::ws {
namespace {
constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string base64(std::span<const std::byte> bytes) {
    std::string out;
    for (std::size_t i = 0; i < bytes.size(); i += 3) {
        auto a = std::to_integer<unsigned>(bytes[i]);
        auto b = i + 1 < bytes.size() ? std::to_integer<unsigned>(bytes[i + 1]) : 0;
        auto c = i + 2 < bytes.size() ? std::to_integer<unsigned>(bytes[i + 2]) : 0;
        out += alphabet[a >> 2]; out += alphabet[((a & 3) << 4) | (b >> 4)];
        out += i + 1 < bytes.size() ? alphabet[((b & 15) << 2) | (c >> 6)] : '=';
        out += i + 2 < bytes.size() ? alphabet[c & 63] : '=';
    }
    return out;
}
bool key_valid(std::string_view key) {
    if (key.size() != 24 || key.substr(22) != "==") return false;
    for (std::size_t i = 0; i < 22; ++i) if (alphabet.find(key[i]) == alphabet.npos) return false;
    return (alphabet.find(key[21]) & 15) == 0;
}
char lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c; }
std::string lowercase(std::string_view text) {
    std::string result(text);
    std::transform(result.begin(), result.end(), result.begin(), lower);
    return result;
}
std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return text;
}
bool token_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) != std::string_view::npos;
}
bool has_token(std::string_view list, std::string_view token) {
    bool found = false;
    while (!list.empty()) {
        auto comma = list.find(',');
        auto part = trim(list.substr(0, comma));
        if (part.empty() || !std::all_of(part.begin(), part.end(), token_char)) return false;
        if (lowercase(part) == token) found = true;
        if (comma == list.npos) return found;
        list.remove_prefix(comma + 1);
        if (list.empty()) return false;
    }
    return found;
}
struct Head { std::string_view line; std::map<std::string, std::string> fields; };
Result<Head> parse(std::string_view wire, Limits limits) {
    if (wire.size() > limits.max_handshake) return fail(Mira::Errc::limit_exceeded);
    if (!wire.ends_with("\r\n\r\n")) return fail(make_error_code(Errc::invalid_handshake));
    auto end = wire.find("\r\n");
    if (end == wire.npos) return fail(make_error_code(Errc::invalid_handshake));
    Head head{wire.substr(0, end), {}};
    wire.remove_prefix(end + 2);
    while (wire != "\r\n") {
        end = wire.find("\r\n");
        if (end == wire.npos || end == 0) return fail(make_error_code(Errc::invalid_handshake));
        auto line = wire.substr(0, end);
        auto colon = line.find(':');
        if (colon == 0 || colon == line.npos) return fail(make_error_code(Errc::invalid_handshake));
        auto name = line.substr(0, colon);
        if (!std::all_of(name.begin(), name.end(), token_char)) return fail(make_error_code(Errc::invalid_handshake));
        auto content = trim(line.substr(colon + 1));
        for (char byte : content) {
            auto c = static_cast<unsigned char>(byte);
            if ((c < 32 && c != '\t') || c == 127) return fail(make_error_code(Errc::invalid_handshake));
        }
        auto key = lowercase(name);
        auto [it, inserted] = head.fields.emplace(key, content);
        if (!inserted) {
            if (key != "connection" && key != "upgrade") return fail(make_error_code(Errc::invalid_handshake));
            it->second += ","; it->second += content;
        }
        wire.remove_prefix(end + 2);
    }
    if (!has_token(head.fields["connection"], "upgrade") || !has_token(head.fields["upgrade"], "websocket") ||
        head.fields.contains("transfer-encoding") ||
        (head.fields.contains("content-length") && head.fields["content-length"] != "0"))
        return fail(make_error_code(Errc::invalid_handshake));
    return head;
}
bool clean(std::string_view text) {
    return std::all_of(text.begin(), text.end(), [](unsigned char c) { return c > 32 && c < 127; });
}
}
Result<std::string> accept_key(std::string_view key) {
    if (!key_valid(key)) return fail(make_error_code(Errc::invalid_handshake));
    std::string input(key);
    input += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    auto digest = crypto::sha1(std::as_bytes(std::span(input.data(), input.size())));
    if (!digest) return fail(digest.error());
    return base64(*digest);
}
Result<ClientHandshake> client_handshake(std::string_view host, std::string_view target) {
    if (host.empty() || target.empty() || target.front() != '/' || !clean(host) || !clean(target) || target.find('#') != target.npos)
        return fail(make_error_code(Errc::invalid_handshake));
    std::array<std::byte, 16> nonce{};
    auto generated = crypto::random_bytes(nonce);
    if (!generated) return fail(generated.error());
    ClientHandshake result;
    result.key = base64(nonce);
    result.request = "GET " + std::string(target) + " HTTP/1.1\r\nHost: " + std::string(host) +
        "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + result.key + "\r\n\r\n";
    return result;
}
Result<std::string> server_handshake(std::string_view request, Limits limits) {
    auto parsed = parse(request, limits);
    if (!parsed) return fail(parsed.error());
    auto& h = *parsed;
    if (!h.line.starts_with("GET /") || !h.line.ends_with(" HTTP/1.1") || h.line.size() < 14 ||
        !clean(h.line.substr(4, h.line.size() - 13)) || h.line.find('#') != h.line.npos ||
        h.fields["host"].empty() || !clean(h.fields["host"]) ||
        h.fields["sec-websocket-version"] != "13") return fail(make_error_code(Errc::invalid_handshake));
    auto accept = accept_key(h.fields["sec-websocket-key"]);
    if (!accept) return fail(accept.error());
    return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + *accept + "\r\n\r\n";
}
Result<void> validate_server_handshake(std::string_view response, std::string_view key, Limits limits) {
    auto parsed = parse(response, limits);
    if (!parsed) return fail(parsed.error());
    auto expected = accept_key(key);
    if (!expected) return fail(expected.error());
    auto& h = *parsed;
    if (!h.line.starts_with("HTTP/1.1 101 ") || h.fields["sec-websocket-accept"] != *expected ||
        h.fields.contains("sec-websocket-extensions") || h.fields.contains("sec-websocket-protocol"))
        return fail(make_error_code(Errc::invalid_handshake));
    for (char byte : h.line) {
        auto c = static_cast<unsigned char>(byte);
        if (c < 32 || c == 127) return fail(make_error_code(Errc::invalid_handshake));
    }
    return {};
}
} // namespace Mira::ws
