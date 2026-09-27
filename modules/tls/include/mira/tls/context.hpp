#pragma once

#include "mira/core/error.hpp"

#include <memory>
#include <span>
#include <string_view>

namespace Mira::tls {

class Engine;

/// Immutable TLS configuration. Clients always verify the certificate chain and
/// the peer identity, with a minimum of TLS 1.2. When ca_file is empty, OpenSSL's
/// default trust paths are used, which is not equivalent to the native system keychain.
class Context {
public:
    /// Full server configuration: certificate chain + private key, with optional
    /// mTLS and minimum protocol version.
    ///
    /// The string_views only need to survive until Context::server returns; all
    /// inputs are copied or loaded once at construction, and the Context retains
    /// no views.
    struct ServerConfig {
        std::string_view cert_file;
        std::string_view key_file;
        /// When non-empty, this CA is loaded and client certificate verification
        /// is enforced (mTLS); a client that presents no certificate fails the
        /// handshake. Empty = no client certificate required.
        std::string_view client_ca_file{};
        /// Minimum protocol version: "1.2" (default) or "1.3"; other values are rejected.
        std::string_view min_version{"1.2"};
        /// Single-protocol ALPN; empty disables it. Semantics match server(cert, key, protocol).
        std::string_view protocol{};
    };

    /// Full client configuration: optional custom trust anchor and client certificate
    /// chain (mTLS client side).
    struct ClientConfig {
        /// Empty = OpenSSL default trust paths.
        std::string_view ca_file{};
        /// Single-protocol ALPN; empty disables it. Semantics match client(ca_file, protocol).
        std::string_view protocol{};
        /// When non-empty, the client certificate chain is presented during the
        /// handshake; cert/key must appear as a pair.
        std::string_view cert_file{};
        std::string_view key_file{};
    };

    /// An empty protocol disables ALPN; otherwise it is a single binary protocol
    /// name of at most 255 bytes.
    [[nodiscard]] static Result<Context> client(std::string_view ca_file = {},
                                                std::string_view protocol = {});
    /// Once enabled, the handshake fails if the peer offers ALPN without including
    /// protocol; a peer that offers none may proceed without negotiation.
    [[nodiscard]] static Result<Context>
    server(std::string_view cert_file, std::string_view key_file, std::string_view protocol = {});

    /// Full-configuration overloads: add mTLS and minimum protocol version control
    /// on top of the basic forms. min_version only relaxes down to "1.2": no matter
    /// how it is configured, TLS 1.0/1.1 are always rejected.
    [[nodiscard]] static Result<Context> server(ServerConfig config);
    [[nodiscard]] static Result<Context> client(ClientConfig config);

    /// protocols are ordered by preference; each entry is a 1..255-byte binary name
    /// and duplicates are not allowed. The length-prefixed encoding must not exceed
    /// 65535 bytes in total; an empty list disables ALPN, and the input is copied.
    [[nodiscard]] static Result<Context>
    client_alpn(std::string_view ca_file, std::span<const std::string_view> protocols);
    /// Selects the common protocol following the server's list order; the handshake
    /// fails when the client offers ALPN but no protocol is shared. A client that
    /// offers no ALPN may proceed without negotiation. The caller must check
    /// negotiated_protocol() and choose the application protocol explicitly (for
    /// example an HTTP/1 fallback); TLS does not switch between HTTP/1 and HTTP/2
    /// automatically. The protocol list lives as long as the SSL_CTX; streams already
    /// created do not depend on this Context to stay alive.
    [[nodiscard]] static Result<Context> server_alpn(
        std::string_view cert_file,
        std::string_view key_file,
        std::span<const std::string_view> protocols);

    Context(Context&&) noexcept;
    Context& operator=(Context&&) noexcept;
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    ~Context();

private:
    struct Impl;
    explicit Context(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
    friend class Engine;
};

}  // namespace Mira::tls
