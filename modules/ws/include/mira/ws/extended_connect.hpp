#pragma once

#include "mira/ws/handshake.hpp"

namespace Mira::ws {

struct ExtendedHandshake {
    http::Headers fields;
    Negotiated negotiated;
};

// Full RFC8441/RFC9220 headers without an HTTP/1 handshake or nonce.
// Requests contain five pseudo-fields and version 13; successful responses use 200.
// Validate SETTINGS, stream state and transport security before passing negotiated
// state to Connection::adopt_extended_connect. These helpers perform no network I/O.
// max_handshake charges name, value and 32 bytes of overhead per decoded field.
Result<http::Headers> extended_connect_request(std::string_view authority,
    std::string_view path = "/", const HandshakeOptions& options = {}, Limits limits = {});
Result<ExtendedHandshake> accept_extended_connect(std::span<const http::Header> request,
    const HandshakeOptions& options = {}, Limits limits = {});
// Accept 2xx except 204, which the pinned engines cannot tunnel (not_supported).
Result<Negotiated> validate_extended_connect(std::span<const http::Header> response,
    const HandshakeOptions& offered = {}, Limits limits = {});

} // namespace Mira::ws
