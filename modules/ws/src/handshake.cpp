#include "mira/ws/handshake.hpp"
#include "mira/crypto/crypto.hpp"

#include <algorithm>
#include <map>
#include <set>

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
bool token(std::string_view text) {
    return !text.empty() && std::all_of(text.begin(), text.end(), token_char);
}
bool has_token(std::string_view list, std::string_view expected) {
    bool found = false;
    while (!list.empty()) {
        auto comma = list.find(',');
        auto part = trim(list.substr(0, comma));
        if (!token(part)) return false;
        if (lowercase(part) == expected) found = true;
        if (comma == list.npos) return found;
        list.remove_prefix(comma + 1);
        if (list.empty()) return false;
    }
    return found;
}
struct Head { std::string_view line; std::map<std::string, std::string> fields; };
Result<Head> parse(std::string_view wire, Limits limits, bool request) {
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
        if (!token(name)) return fail(make_error_code(Errc::invalid_handshake));
        auto content = trim(line.substr(colon + 1));
        for (char byte : content) {
            auto c = static_cast<unsigned char>(byte);
            if ((c < 32 && c != '\t') || c == 127) return fail(make_error_code(Errc::invalid_handshake));
        }
        auto key = lowercase(name);
        auto [it, inserted] = head.fields.emplace(key, content);
        if (!inserted) {
            if (key != "connection" && key != "upgrade" &&
                !(request && (key == "sec-websocket-protocol" || key == "sec-websocket-extensions")))
                return fail(make_error_code(Errc::invalid_handshake));
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
bool append(std::string& out, std::string_view text, Limits limits) {
    if (text.size() > limits.max_handshake - out.size()) return false;
    out += text;
    return true;
}
Result<void> validate_options(const HandshakeOptions& options, Role role, Limits limits) {
    std::set<std::string_view> names;
    std::size_t size = 0;
    for (const auto& protocol : options.subprotocols) {
        if (protocol.size() > limits.max_handshake - size) return fail(Mira::Errc::limit_exceeded);
        size += protocol.size();
        if (!token(protocol) || !names.insert(protocol).second) return fail(Mira::Errc::invalid_argument);
    }
    if (options.require_subprotocol && options.subprotocols.empty()) return fail(Mira::Errc::invalid_argument);
    const auto& compression = options.compression;
    if (!compression.enabled) return {};
    for (auto bits : {compression.server_max_window_bits, compression.client_max_window_bits})
        if (bits && (*bits < 8 || *bits > 15)) return fail(Mira::Errc::invalid_argument);
    auto local_bits = role == Role::server ? compression.server_max_window_bits : compression.client_max_window_bits;
    if (local_bits == 8) return fail(Mira::Errc::not_supported);
    return {};
}
Result<std::vector<std::string_view>> protocols(const Head& head) {
    std::vector<std::string_view> result;
    auto field = head.fields.find("sec-websocket-protocol");
    if (field == head.fields.end()) return result;
    std::string_view list = field->second;
    std::set<std::string_view> seen;
    for (;;) {
        auto comma = list.find(',');
        auto part = trim(list.substr(0, comma));
        if (!token(part) || !seen.insert(part).second) return fail(make_error_code(Errc::invalid_handshake));
        result.push_back(part);
        if (comma == list.npos) break;
        list.remove_prefix(comma + 1);
    }
    return result;
}
struct Parameter {
    std::string_view name;
    std::optional<std::string> value;
};
struct Extension {
    std::string_view name;
    std::vector<Parameter> parameters;
};
std::string_view take_token(std::string_view& text) {
    std::size_t end = 0;
    while (end < text.size() && token_char(static_cast<unsigned char>(text[end]))) ++end;
    auto result = text.substr(0, end);
    text = trim(text.substr(end));
    return result;
}
Result<std::vector<Extension>> extensions(const Head& head) {
    std::vector<Extension> result;
    auto field = head.fields.find("sec-websocket-extensions");
    if (field == head.fields.end()) return result;
    std::string_view text = field->second;
    for (;;) {
        Extension extension{take_token(text), {}};
        if (extension.name.empty()) return fail(make_error_code(Errc::invalid_handshake));
        while (!text.empty() && text.front() == ';') {
            text = trim(text.substr(1));
            Parameter parameter{take_token(text), {}};
            if (parameter.name.empty()) return fail(make_error_code(Errc::invalid_handshake));
            if (!text.empty() && text.front() == '=') {
                text = trim(text.substr(1));
                if (text.empty()) return fail(make_error_code(Errc::invalid_handshake));
                parameter.value.emplace();
                if (text.front() == '"') {
                    text.remove_prefix(1);
                    bool closed = false;
                    while (!text.empty()) {
                        char c = text.front();
                        text.remove_prefix(1);
                        if (c == '"') { closed = true; break; }
                        if (c == '\\') {
                            if (text.empty()) return fail(make_error_code(Errc::invalid_handshake));
                            c = text.front();
                            text.remove_prefix(1);
                        }
                        *parameter.value += c;
                    }
                    if (!closed || !token(*parameter.value)) return fail(make_error_code(Errc::invalid_handshake));
                    text = trim(text);
                } else {
                    *parameter.value = take_token(text);
                    if (parameter.value->empty()) return fail(make_error_code(Errc::invalid_handshake));
                }
            }
            extension.parameters.push_back(std::move(parameter));
        }
        result.push_back(std::move(extension));
        if (text.empty()) break;
        if (text.front() != ',') return fail(make_error_code(Errc::invalid_handshake));
        text = trim(text.substr(1));
    }
    return result;
}
struct Deflate {
    bool server_no_context_takeover = false;
    bool client_no_context_takeover = false;
    std::optional<unsigned> server_max_window_bits;
    std::optional<unsigned> client_max_window_bits;
    bool client_window_present = false;
};
Result<unsigned> window_bits(const std::optional<std::string>& value) {
    if (value) {
        if (*value == "8") return 8;
        if (*value == "9") return 9;
        if (value->size() == 2 && (*value)[0] == '1' && (*value)[1] >= '0' && (*value)[1] <= '5')
            return 10U + static_cast<unsigned>((*value)[1] - '0');
    }
    return fail(make_error_code(Errc::invalid_handshake));
}
Result<Deflate> deflate_parameters(const Extension& extension, bool response) {
    Deflate result;
    std::set<std::string_view> seen;
    for (const auto& parameter : extension.parameters) {
        if (!seen.insert(parameter.name).second) return fail(make_error_code(Errc::invalid_handshake));
        if (parameter.name == "server_no_context_takeover" || parameter.name == "client_no_context_takeover") {
            if (parameter.value) return fail(make_error_code(Errc::invalid_handshake));
            if (parameter.name == "server_no_context_takeover") result.server_no_context_takeover = true;
            else result.client_no_context_takeover = true;
        } else if (parameter.name == "server_max_window_bits") {
            auto bits = window_bits(parameter.value);
            if (!bits) return fail(bits.error());
            result.server_max_window_bits = *bits;
        } else if (parameter.name == "client_max_window_bits") {
            result.client_window_present = true;
            if (!response && !parameter.value) continue;
            auto bits = window_bits(parameter.value);
            if (!bits) return fail(bits.error());
            result.client_max_window_bits = *bits;
        } else {
            return fail(make_error_code(Errc::invalid_handshake));
        }
    }
    return result;
}
std::string format_deflate(const Deflate& parameters) {
    std::string result = "permessage-deflate";
    if (parameters.server_no_context_takeover) result += "; server_no_context_takeover";
    if (parameters.client_no_context_takeover) result += "; client_no_context_takeover";
    if (parameters.server_max_window_bits)
        result += "; server_max_window_bits=" + std::to_string(*parameters.server_max_window_bits);
    if (parameters.client_window_present) {
        result += "; client_max_window_bits";
        if (parameters.client_max_window_bits) result += "=" + std::to_string(*parameters.client_max_window_bits);
    }
    return result;
}
CompressionParameters agreed(const Deflate& parameters) {
    return {.enabled = true,
            .server_no_context_takeover = parameters.server_no_context_takeover,
            .client_no_context_takeover = parameters.client_no_context_takeover,
            .server_max_window_bits = parameters.server_max_window_bits.value_or(15),
            .client_max_window_bits = parameters.client_max_window_bits.value_or(15)};
}
std::optional<Deflate> select_deflate(const std::vector<Extension>& offers, const CompressionOptions& options) {
    if (!options.enabled) return {};
    for (const auto& offer : offers) {
        if (offer.name != "permessage-deflate") continue;
        auto parameters = deflate_parameters(offer, false);
        if (!parameters) continue;
        unsigned server_bits = std::min(options.server_max_window_bits.value_or(15),
                                        parameters->server_max_window_bits.value_or(15));
        // zlib cannot reliably encode an 8-bit window; decline offers requiring it.
        if (server_bits == 8) continue;
        if (!parameters->client_window_present && options.client_max_window_bits.value_or(15) < 15) continue;
        Deflate result;
        result.server_no_context_takeover = options.server_no_context_takeover || parameters->server_no_context_takeover;
        result.client_no_context_takeover = options.client_no_context_takeover || parameters->client_no_context_takeover;
        if (options.server_max_window_bits || parameters->server_max_window_bits) result.server_max_window_bits = server_bits;
        if (parameters->client_window_present && (options.client_max_window_bits || parameters->client_max_window_bits)) {
            result.client_window_present = true;
            result.client_max_window_bits = std::min(options.client_max_window_bits.value_or(15),
                                                      parameters->client_max_window_bits.value_or(15));
        }
        return result;
    }
    return {};
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
    return client_handshake(host, target, HandshakeOptions{});
}
Result<ClientHandshake> client_handshake(std::string_view host, std::string_view target,
                                        const HandshakeOptions& options, Limits limits) {
    auto valid = validate_options(options, Role::client, limits);
    if (!valid) return fail(valid.error());
    if (host.size() > limits.max_handshake || target.size() > limits.max_handshake) return fail(Mira::Errc::limit_exceeded);
    if (host.empty() || target.empty() || target.front() != '/' || !clean(host) || !clean(target) || target.find('#') != target.npos)
        return fail(make_error_code(Errc::invalid_handshake));
    std::array<std::byte, 16> nonce{};
    auto generated = crypto::random_bytes(nonce);
    if (!generated) return fail(generated.error());
    ClientHandshake result;
    result.key = base64(nonce);
    auto add = [&](std::string_view text) { return append(result.request, text, limits); };
    if (!add("GET ") || !add(target) || !add(" HTTP/1.1\r\nHost: ") || !add(host) ||
        !add("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ") ||
        !add(result.key) || !add("\r\n")) return fail(Mira::Errc::limit_exceeded);
    if (!options.subprotocols.empty()) {
        if (!add("Sec-WebSocket-Protocol: ")) return fail(Mira::Errc::limit_exceeded);
        for (std::size_t i = 0; i < options.subprotocols.size(); ++i)
            if ((i != 0 && !add(", ")) || !add(options.subprotocols[i])) return fail(Mira::Errc::limit_exceeded);
        if (!add("\r\n")) return fail(Mira::Errc::limit_exceeded);
    }
    const auto& compression = options.compression;
    if (compression.enabled) {
        Deflate offer{compression.server_no_context_takeover, compression.client_no_context_takeover,
                      compression.server_max_window_bits, compression.client_max_window_bits,
                      compression.offer_client_max_window_bits || compression.client_max_window_bits.has_value()};
        if (!add("Sec-WebSocket-Extensions: ") || !add(format_deflate(offer)) || !add("\r\n"))
            return fail(Mira::Errc::limit_exceeded);
    }
    if (!add("\r\n")) return fail(Mira::Errc::limit_exceeded);
    return result;
}
Result<ServerHandshake> negotiate_server_handshake(std::string_view request,
                                                  const HandshakeOptions& options, Limits limits) {
    auto valid = validate_options(options, Role::server, limits);
    if (!valid) return fail(valid.error());
    auto parsed = parse(request, limits, true);
    if (!parsed) return fail(parsed.error());
    auto& h = *parsed;
    if (!h.line.starts_with("GET /") || !h.line.ends_with(" HTTP/1.1") || h.line.size() < 14 ||
        !clean(h.line.substr(4, h.line.size() - 13)) || h.line.find('#') != h.line.npos ||
        h.fields["host"].empty() || !clean(h.fields["host"]) ||
        h.fields["sec-websocket-version"] != "13") return fail(make_error_code(Errc::invalid_handshake));
    auto accept = accept_key(h.fields["sec-websocket-key"]);
    if (!accept) return fail(accept.error());
    auto offered_protocols = protocols(h);
    if (!offered_protocols) return fail(offered_protocols.error());
    auto offered_extensions = extensions(h);
    if (!offered_extensions) return fail(offered_extensions.error());
    ServerHandshake result;
    for (const auto& protocol : options.subprotocols) {
        if (std::find(offered_protocols->begin(), offered_protocols->end(), protocol) != offered_protocols->end()) {
            result.negotiated.subprotocol = protocol;
            break;
        }
    }
    if (result.negotiated.subprotocol.empty() && options.require_subprotocol)
        return fail(make_error_code(Errc::invalid_handshake));
    auto compression = select_deflate(*offered_extensions, options.compression);
    if (compression) result.negotiated.compression = agreed(*compression);
    auto add = [&](std::string_view text) { return append(result.response, text, limits); };
    if (!add("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ") ||
        !add(*accept) || !add("\r\n")) return fail(Mira::Errc::limit_exceeded);
    if (!result.negotiated.subprotocol.empty() &&
        (!add("Sec-WebSocket-Protocol: ") || !add(result.negotiated.subprotocol) || !add("\r\n")))
        return fail(Mira::Errc::limit_exceeded);
    if (compression && (!add("Sec-WebSocket-Extensions: ") || !add(format_deflate(*compression)) || !add("\r\n")))
        return fail(Mira::Errc::limit_exceeded);
    if (!add("\r\n")) return fail(Mira::Errc::limit_exceeded);
    return result;
}
Result<Negotiated> negotiate_client_handshake(std::string_view response, std::string_view key,
                                            const HandshakeOptions& options, Limits limits) {
    auto valid = validate_options(options, Role::client, limits);
    if (!valid) return fail(valid.error());
    auto parsed = parse(response, limits, false);
    if (!parsed) return fail(parsed.error());
    auto expected = accept_key(key);
    if (!expected) return fail(expected.error());
    auto& h = *parsed;
    if (!h.line.starts_with("HTTP/1.1 101 ") || h.fields["sec-websocket-accept"] != *expected)
        return fail(make_error_code(Errc::invalid_handshake));
    for (char byte : h.line) {
        auto c = static_cast<unsigned char>(byte);
        if (c < 32 || c == 127) return fail(make_error_code(Errc::invalid_handshake));
    }
    auto selected = protocols(h);
    if (!selected) return fail(selected.error());
    Negotiated result;
    if (selected->size() > 1 || (selected->empty() && options.require_subprotocol))
        return fail(make_error_code(Errc::invalid_handshake));
    if (!selected->empty()) {
        if (std::find(options.subprotocols.begin(), options.subprotocols.end(), selected->front()) == options.subprotocols.end())
            return fail(make_error_code(Errc::invalid_handshake));
        result.subprotocol = selected->front();
    }
    auto selected_extensions = extensions(h);
    if (!selected_extensions) return fail(selected_extensions.error());
    if (selected_extensions->empty()) return result;
    const auto& offered = options.compression;
    if (!offered.enabled || selected_extensions->size() != 1 || selected_extensions->front().name != "permessage-deflate")
        return fail(make_error_code(Errc::invalid_handshake));
    auto parameters = deflate_parameters(selected_extensions->front(), true);
    if (!parameters) return fail(parameters.error());
    if ((offered.server_no_context_takeover && !parameters->server_no_context_takeover) ||
        (offered.server_max_window_bits && (!parameters->server_max_window_bits ||
         *parameters->server_max_window_bits > *offered.server_max_window_bits)) ||
        (parameters->client_window_present && !offered.offer_client_max_window_bits && !offered.client_max_window_bits) ||
        parameters->client_max_window_bits == 8)
        return fail(make_error_code(Errc::invalid_handshake));
    // Client offer hints are not response limits. The connection separately
    // honors stricter local promises when constructing its outbound codec.
    result.compression = agreed(*parameters);
    return result;
}
Result<std::string> server_handshake(std::string_view request, Limits limits) {
    auto result = negotiate_server_handshake(request, HandshakeOptions{}, limits);
    if (!result) return fail(result.error());
    return std::move(result->response);
}
Result<void> validate_server_handshake(std::string_view response, std::string_view key, Limits limits) {
    auto result = negotiate_client_handshake(response, key, HandshakeOptions{}, limits);
    if (!result) return fail(result.error());
    return {};
}
} // namespace Mira::ws
