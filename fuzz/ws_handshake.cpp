// Exercise both upgrade directions and strict HTTP/token parsing without I/O.
#include "mira/ws/handshake.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 16384) return 0;
    const std::string_view input(reinterpret_cast<const char*>(data), size);
    constexpr std::string_view key = "dGhlIHNhbXBsZSBub25jZQ==";
    constexpr Mira::ws::Limits limits{4096, 8192, 16384};
    (void)Mira::ws::server_handshake(input, limits);
    (void)Mira::ws::validate_server_handshake(input, key, limits);
    Mira::ws::HandshakeOptions options;
    options.subprotocols = {"chat", "binary"};
    options.compression.enabled = true;
    (void)Mira::ws::negotiate_server_handshake(input, options, limits);
    (void)Mira::ws::negotiate_client_handshake(input, key, options, limits);
    if (size <= 128) (void)Mira::ws::accept_key(input);
    if (size < 4096) {
        // Place mutations into otherwise valid requests/responses so coverage
        // does not stop at the first invalid start-line on every iteration.
        const std::string request = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " +
            std::string(key) + "\r\n" + std::string(input) + "\r\n\r\n";
        auto response = Mira::ws::server_handshake(request, limits);
        if (response && !Mira::ws::validate_server_handshake(*response, key, limits)) std::abort();
        const std::string extension_request = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " +
            std::string(key) + "\r\nSec-WebSocket-Extensions: " + std::string(input) + "\r\n\r\n";
        (void)Mira::ws::negotiate_server_handshake(extension_request, options, limits);
        const std::string protocol_request = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " +
            std::string(key) + "\r\nSec-WebSocket-Protocol: " + std::string(input) + "\r\n\r\n";
        (void)Mira::ws::negotiate_server_handshake(protocol_request, options, limits);
    }
    return 0;
}
