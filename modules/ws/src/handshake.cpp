#include "mira/ws/extended_connect.hpp"
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
        if (!inserted && !(!request && key == "set-cookie")) {
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
Result<Negotiated> negotiate_selection(const Head& head, const HandshakeOptions& options) {
    auto selected = protocols(head);
    if (!selected) return fail(selected.error());
    Negotiated result;
    if (selected->size() > 1 || (selected->empty() && options.require_subprotocol))
        return fail(make_error_code(Errc::invalid_handshake));
    if (!selected->empty()) {
        if (std::find(options.subprotocols.begin(), options.subprotocols.end(), selected->front()) == options.subprotocols.end())
            return fail(make_error_code(Errc::invalid_handshake));
        result.subprotocol = selected->front();
    }
    auto selected_extensions = extensions(head);
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
    // Client send preferences are not response bounds; the codec honors local commitments.
    result.compression = agreed(*parameters);
    return result;
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
    return negotiate_selection(h, options);
}
namespace {
bool uri_component(std::string_view value, std::string_view extra) {
    constexpr std::string_view hex = "0123456789abcdefABCDEF";
    for (std::size_t i = 0; i < value.size(); ++i) {
        const char c = value[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            std::string_view("-._~!$&'()*+,;=").find(c) != value.npos || extra.find(c) != extra.npos)
            continue;
        if (c != '%' || value.size() - i < 3 || hex.find(value[i + 1]) == hex.npos || hex.find(value[i + 2]) == hex.npos)
            return false;
        i += 2;
    }
    return true;
}
bool connect_target(std::string_view authority, std::string_view path) {
    if (authority.empty() || !clean(authority) || authority.find_first_of("/?#@\\") != authority.npos ||
        path.empty() || path.front() != '/' || !uri_component(path, ":@/?"))
        return false;
    std::string_view host = authority;
    std::string_view port;
    if (authority.front() == '[') {
        const auto end = authority.find(']');
        if (end == authority.npos || end == 1 || authority.substr(1, end - 1).find_first_of("[]") != authority.npos)
            return false;
        host = authority.substr(1, end - 1);
        if (end + 1 != authority.size()) {
            if (authority[end + 1] != ':') return false;
            port = authority.substr(end + 2);
            if (port.empty()) return false;
        }
    } else {
        if (authority.find_first_of("[]") != authority.npos) return false;
        const auto colon = authority.find(':');
        if (colon != authority.npos) {
            host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
            if (port.empty()) return false;
        }
    }
    return !host.empty() && uri_component(host, authority.front() == '[' ? ":" : "") &&
           std::all_of(port.begin(), port.end(), [](char c) { return c >= '0' && c <= '9'; });
}
Result<Head> connect_fields(std::span<const http::Header> fields, Limits limits, bool response) {
    Head head{};
    std::size_t used = 0;
    bool regular = false, pseudo = false;
    for (const auto& field : fields) {
        for (const auto size : {field.name.size(), field.value.size(), std::size_t{32}}) {
            if (size > limits.max_handshake - used) return fail(Mira::Errc::limit_exceeded);
            used += size;
        }
        if (field.name.empty()) return fail(make_error_code(Errc::invalid_handshake));
        const bool is_pseudo = field.name.front() == ':';
        const auto name = is_pseudo ? std::string_view(field.name).substr(1) : std::string_view(field.name);
        if (!token(name) || lowercase(name) != name || trim(field.value) != field.value)
            return fail(make_error_code(Errc::invalid_handshake));
        for (const char byte : field.value) {
            const auto c = static_cast<unsigned char>(byte);
            if ((c < 32 && c != '\t') || c == 127) return fail(make_error_code(Errc::invalid_handshake));
        }
        if (is_pseudo) {
            if (regular || field.value.empty() ||
                (response ? field.name != ":status" :
                 field.name != ":method" && field.name != ":protocol" && field.name != ":scheme" &&
                 field.name != ":authority" && field.name != ":path"))
                return fail(make_error_code(Errc::invalid_handshake));
            pseudo = true;
        } else {
            regular = true;
            if (field.name == "connection" || field.name == "upgrade" || field.name == "keep-alive" ||
                field.name == "proxy-connection" || field.name == "transfer-encoding" ||
                field.name == "content-length" || field.name == "sec-websocket-key" ||
                field.name == "sec-websocket-accept" ||
                (field.name == "te" && (response || field.value != "trailers")) ||
                (response && field.name == "sec-websocket-version"))
                return fail(make_error_code(Errc::invalid_handshake));
        }
        auto [it, inserted] = head.fields.emplace(field.name, field.value);
        if (!inserted && !(response && field.name == "set-cookie")) {
            if (response || (field.name != "sec-websocket-protocol" && field.name != "sec-websocket-extensions"))
                return fail(make_error_code(Errc::invalid_handshake));
            it->second += ',';
            it->second += field.value;
        }
    }
    if (pseudo) {
        if (response) {
            const auto& status = head.fields[":status"];
            if (status.size() != 3 || status.front() < '1' || status.front() > '5' ||
                !std::all_of(status.begin(), status.end(), [](char c) { return c >= '0' && c <= '9'; }))
                return fail(make_error_code(Errc::invalid_handshake));
        } else if (head.fields[":method"] != "CONNECT" || head.fields[":protocol"] != "websocket" ||
                   (head.fields[":scheme"] != "https" && head.fields[":scheme"] != "http") ||
                   !connect_target(head.fields[":authority"], head.fields[":path"]) ||
                   (head.fields.contains("host") && head.fields["host"] != head.fields[":authority"])) {
            return fail(make_error_code(Errc::invalid_handshake));
        }
    }
    return head;
}
}
Result<http::Headers> extended_connect_offer(const HandshakeOptions& options, Limits limits) {
    if (auto valid = validate_options(options, Role::client, limits); !valid) return fail(valid.error());
    http::Headers fields{{"sec-websocket-version", "13"}};
    if (!options.subprotocols.empty()) {
        std::string value;
        for (const auto& protocol : options.subprotocols) {
            if ((!value.empty() && !append(value, ", ", limits)) || !append(value, protocol, limits))
                return fail(Mira::Errc::limit_exceeded);
        }
        fields.push_back({"sec-websocket-protocol", std::move(value)});
    }
    const auto& c = options.compression;
    if (c.enabled) fields.push_back({"sec-websocket-extensions", format_deflate(Deflate{
        c.server_no_context_takeover, c.client_no_context_takeover, c.server_max_window_bits,
        c.client_max_window_bits, c.offer_client_max_window_bits || c.client_max_window_bits.has_value()})});
    if (auto checked = connect_fields(fields, limits, false); !checked) return fail(checked.error());
    return fields;
}
Result<ConnectHandshake> negotiate_extended_server(std::span<const http::Header> fields,
    const HandshakeOptions& options, Limits limits) {
    if (auto valid = validate_options(options, Role::server, limits); !valid) return fail(valid.error());
    auto head = connect_fields(fields, limits, false);
    if (!head) return fail(head.error());
    if (head->fields["sec-websocket-version"] != "13") return fail(make_error_code(Errc::invalid_handshake));
    auto offered = protocols(*head);
    if (!offered) return fail(offered.error());
    auto offered_extensions = extensions(*head);
    if (!offered_extensions) return fail(offered_extensions.error());
    ConnectHandshake result;
    for (const auto& protocol : options.subprotocols) {
        if (std::find(offered->begin(), offered->end(), protocol) == offered->end()) continue;
        result.negotiated.subprotocol = protocol;
        result.fields.push_back({"sec-websocket-protocol", protocol});
        break;
    }
    if (options.require_subprotocol && result.negotiated.subprotocol.empty())
        return fail(make_error_code(Errc::invalid_handshake));
    if (auto parameters = select_deflate(*offered_extensions, options.compression)) {
        result.negotiated.compression = agreed(*parameters);
        result.fields.push_back({"sec-websocket-extensions", format_deflate(*parameters)});
    }
    if (auto checked = connect_fields(result.fields, limits, true); !checked) return fail(checked.error());
    return result;
}
Result<Negotiated> negotiate_extended_client(unsigned status, std::span<const http::Header> fields,
    const HandshakeOptions& offered, Limits limits) {
    if (status < 200 || status >= 300) return fail(make_error_code(Errc::invalid_handshake));
    if (status == 204) return fail(Mira::Errc::not_supported);
    if (auto valid = validate_options(offered, Role::client, limits); !valid) return fail(valid.error());
    auto head = connect_fields(fields, limits, true);
    if (!head) return fail(head.error());
    if (head->fields.contains(":status") && head->fields[":status"] != std::to_string(status))
        return fail(make_error_code(Errc::invalid_handshake));
    return negotiate_selection(*head, offered);
}
Result<http::Headers> extended_connect_request(std::string_view authority, std::string_view path,
    const HandshakeOptions& options, Limits limits) {
    if (authority.size() > limits.max_handshake || path.size() > limits.max_handshake)
        return fail(Mira::Errc::limit_exceeded);
    if (!connect_target(authority, path)) return fail(make_error_code(Errc::invalid_handshake));
    auto offer = extended_connect_offer(options, limits);
    if (!offer) return fail(offer.error());
    http::Headers fields{{":method", "CONNECT"}, {":protocol", "websocket"}, {":scheme", "https"},
                        {":authority", std::string(authority)}, {":path", std::string(path)}};
    for (auto& field : *offer) fields.push_back(std::move(field));
    if (auto checked = connect_fields(fields, limits, false); !checked) return fail(checked.error());
    return fields;
}
Result<ExtendedHandshake> accept_extended_connect(std::span<const http::Header> request,
    const HandshakeOptions& options, Limits limits) {
    auto head = connect_fields(request, limits, false);
    if (!head) return fail(head.error());
    if (!head->fields.contains(":method")) return fail(make_error_code(Errc::invalid_handshake));
    auto selected = negotiate_extended_server(request, options, limits);
    if (!selected) return fail(selected.error());
    ExtendedHandshake result{{{":status", "200"}}, std::move(selected->negotiated)};
    for (auto& field : selected->fields) result.fields.push_back(std::move(field));
    if (auto checked = connect_fields(result.fields, limits, true); !checked) return fail(checked.error());
    return result;
}
Result<Negotiated> validate_extended_connect(std::span<const http::Header> response,
    const HandshakeOptions& offered, Limits limits) {
    auto head = connect_fields(response, limits, true);
    if (!head) return fail(head.error());
    const auto field = head->fields.find(":status");
    if (field == head->fields.end()) return fail(make_error_code(Errc::invalid_handshake));
    const auto& value = field->second;
    const auto status = static_cast<unsigned>((value[0] - '0') * 100 + (value[1] - '0') * 10 + value[2] - '0');
    return negotiate_extended_client(status, response, offered, limits);
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
