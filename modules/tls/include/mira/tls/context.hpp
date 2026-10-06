#pragma once

#include "mira/core/error.hpp"

#include <cstddef>
#include <memory>
#include <span>
#include <string_view>

namespace Mira::tls {

class Engine;

/// TLS configuration snapshots. Clients always verify the chain and peer identity,
/// with a TLS 1.2 minimum. Empty ca_file uses OpenSSL default trust paths, not the
/// native keychain. reload_server atomically replaces the snapshot for new engines;
/// existing engines retain the generation captured at creation.
class Context {
public:
    enum class SniPolicy { use_default, reject };
    enum class CrlMode { leaf, chain };
    /// request permits a missing staple but rejects an invalid one; require also
    /// rejects absence. disabled disables OCSP only, never chain/identity checks.
    enum class OcspPolicy { disabled, request, require };
    static constexpr std::size_t max_ocsp_response_bytes = 64 * 1024;

    /// Local PEM CRLs only; no online fetching. OCSP is configured separately.
    /// Missing, expired, incorrectly signed CRLs or revoked certificates fail.
    /// chain requires an applicable CRL at every checked level. Callers update
    /// files and rebuild configuration. Servers disable session resumption when
    /// enabled, so each new connection rechecks revocation and CRL validity.
    struct RevocationConfig {
        std::string_view crl_file{};
        CrlMode mode{CrlMode::leaf};
    };

    /// ASCII DNS names only (IDNs must first be converted to A-labels).
    /// Case-insensitive exact routing; no wildcard routes, trailing dots, IPs
    /// or empty labels. Certificate SANs must cover the configured name; a
    /// certificate may contain a valid whole-label wildcard.
    struct ServerIdentity {
        std::string_view hostname;
        std::string_view cert_file;
        std::string_view key_file;
        /// This identity's DER OCSPResponse, never inherited from the default.
        /// Empty means no stapling for this identity.
        std::span<const std::byte> ocsp_response{};
    };

    /// Identities share TLS minimum, mTLS CA, revocation and ALPN policy; no
    /// per-domain security downgrade. All string_views/spans, including nested
    /// values, need live only until server/reload_server returns. Inputs are
    /// copied or fully loaded; snapshots retain no caller-owned views.
    struct ServerConfig {
        std::string_view cert_file;
        std::string_view key_file;
        /// Nonempty enforces mTLS; a client without a verifiable certificate fails.
        std::string_view client_ca_file{};
        /// Minimum version: "1.2" (default) or "1.3"; other values are rejected.
        std::string_view min_version{"1.2"};
        /// Single ALPN. Empty together with protocols disables ALPN.
        std::string_view protocol{};
        /// Multiple ALPN protocols, combinable with mTLS/SNI; exclusive of protocol.
        std::span<const std::string_view> protocols{};
        std::span<const ServerIdentity> identities{};
        /// With named identities, an unknown SNI is rejected by default. Without
        /// named identities, any valid DNS SNI retains the single-certificate policy.
        SniPolicy unknown_sni{SniPolicy::reject};
        /// Missing SNI uses the default certificate by default, including IP clients.
        SniPolicy missing_sni{SniPolicy::use_default};
        /// Client-certificate CRLs; requires client_ca_file.
        RevocationConfig revocation{};
        /// Default identity's DER OCSPResponse, copied with the snapshot, <=64 KiB.
        /// The server checks complete DER/successful basic-response structure,
        /// not signatures, certificate binding, status or time. It does not know
        /// the client's trust policy. The caller validates, obtains and refreshes
        /// the staple; the client independently verifies it. No network/auto-refresh.
        /// OpenSSL may filter mismatched responses; that proves neither validation
        /// nor transmission. Use client OcspPolicy::require when status is mandatory.
        std::span<const std::byte> ocsp_response{};
    };

    /// Client trust and optional mTLS identity configuration.
    struct ClientConfig {
        /// Empty = OpenSSL default trust paths.
        std::string_view ca_file{};
        /// Single ALPN; empty together with protocols disables ALPN.
        std::string_view protocol{};
        /// Optional client certificate/key, required as a pair.
        std::string_view cert_file{};
        std::string_view key_file{};
        /// Multiple ALPN protocols, combinable with mTLS; exclusive of protocol.
        std::span<const std::string_view> protocols{};
        RevocationConfig revocation{};
        /// Leaf staple only: authorized signature, issuer/serial, unique good
        /// record and freshness. nextUpdate is mandatory; clock skew is 300s,
        /// maximum thisUpdate/producedAt age is seven days. No automatic
        /// Must-Staple, intermediate/client-certificate OCSP or online fetching.
        /// Enabled policy refuses resumption to revalidate every new connection;
        /// failures report certificate_verify_failed.
        OcspPolicy ocsp{OcspPolicy::disabled};
    };

    /// Empty protocol disables ALPN; otherwise one binary name of <=255 bytes.
    [[nodiscard]] static Result<Context> client(std::string_view ca_file = {},
                                                std::string_view protocol = {});
    /// ALPN mismatch fails; a peer offering none may proceed without negotiation.
    [[nodiscard]] static Result<Context>
    server(std::string_view cert_file, std::string_view key_file, std::string_view protocol = {});

    /// TLS 1.0/1.1 are always rejected, regardless of configuration.
    [[nodiscard]] static Result<Context> server(ServerConfig config);
    [[nodiscard]] static Result<Context> client(ClientConfig config);

    /// Load all certificate/key/CA/CRL inputs before publication, checking key
    /// pairs and SNI SAN coverage. Failure preserves the current snapshot. Chain
    /// trust, validity and CRL signatures/time are checked at handshake, not
    /// pre-certified offline. May run concurrently with Engine::create and other
    /// reloads on this Context; last successful publication wins. Existing engines
    /// keep their snapshot. Every identity/generation has a separate session scope.
    /// Context move/destruction must remain exclusive; client contexts cannot reload.
    [[nodiscard]] Result<void> reload_server(ServerConfig config);

    /// Protocols are ordered by preference, binary names of 1..255 bytes, without
    /// duplicates. Total length-prefixed encoding <=65535 bytes; inputs are copied.
    [[nodiscard]] static Result<Context>
    client_alpn(std::string_view ca_file, std::span<const std::string_view> protocols);
    /// Server preference selects the common protocol. An ALPN offer without a
    /// match fails; no offer may proceed unnegotiated. Check negotiated_protocol
    /// before selecting H1/H2: TLS never switches application protocols itself.
    /// Streams already created remain valid after this Context is destroyed.
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
