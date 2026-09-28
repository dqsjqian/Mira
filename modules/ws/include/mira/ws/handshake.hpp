#pragma once

#include "mira/ws/compression.hpp"
#include "mira/http/fields.hpp"
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Mira::ws {

struct HandshakeOptions {
    std::vector<std::string> subprotocols;
    bool require_subprotocol = false;
    CompressionOptions compression;
};

struct Negotiated {
    std::string subprotocol;
    CompressionParameters compression;
};

struct ServerHandshake {
    std::string response;
    Negotiated negotiated;
};

struct ClientHandshake {
    std::string request;
    std::string key;
};

// Negotiate WebSocket fields; validate completeness/order when pseudo-fields occur.
// Full headers use extended_connect.hpp; the HTTP engine validates SETTINGS/state.
// max_handshake charges name.size() + value.size() + 32 per decoded field.
struct ConnectHandshake {
    http::Headers fields;
    Negotiated negotiated;
};
Result<http::Headers> extended_connect_offer(const HandshakeOptions& options = {}, Limits limits = {});
Result<ConnectHandshake> negotiate_extended_server(std::span<const http::Header> fields,
    const HandshakeOptions& options = {}, Limits limits = {});
Result<Negotiated> negotiate_extended_client(unsigned status, std::span<const http::Header> fields,
    const HandshakeOptions& offered = {}, Limits limits = {});

Result<std::string> accept_key(std::string_view key);
Result<ClientHandshake> client_handshake(std::string_view host, std::string_view target = "/");
Result<ClientHandshake> client_handshake(std::string_view host, std::string_view target,
                                        const HandshakeOptions& options, Limits limits = {});
Result<ServerHandshake> negotiate_server_handshake(std::string_view request,
                                                  const HandshakeOptions& options, Limits limits = {});
Result<Negotiated> negotiate_client_handshake(std::string_view response, std::string_view key,
                                            const HandshakeOptions& options, Limits limits = {});
Result<std::string> server_handshake(std::string_view request, Limits limits = {});
Result<void> validate_server_handshake(std::string_view response, std::string_view key,
                                       Limits limits = {});

} // namespace Mira::ws
