#include "mira/tls/context.hpp"

#include "context_impl.hpp"
#include "mira/tls/error.hpp"

#include <openssl/err.h>
#include <string>
#include <unordered_set>

namespace Mira::tls {
namespace {
Result<SSL_CTX*> make_context() {
    ERR_clear_error();
    SSL_CTX* handle = SSL_CTX_new(TLS_method());
    if (!handle) return fail(make_error_code(Errc::configuration_error));
    ERR_clear_error();
    if (SSL_CTX_set_min_proto_version(handle, TLS1_2_VERSION) != 1) {
        SSL_CTX_free(handle);
        return fail(make_error_code(Errc::configuration_error));
    }
    ERR_clear_error();
    SSL_CTX_set_options(handle, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    ERR_clear_error();
    SSL_CTX_set_mode(handle, SSL_MODE_ENABLE_PARTIAL_WRITE);
    return handle;
}

bool valid_path(std::string_view path) {
    return !path.empty() && path.find('\0') == std::string_view::npos;
}

Result<std::string> encode_protocols(std::span<const std::string_view> protocols) {
    std::string wire;
    std::unordered_set<std::string_view> seen;
    for (const auto protocol : protocols) {
        if (protocol.empty() || protocol.size() > 255 ||
            protocol.size() + 1 > 65535 - wire.size() || !seen.insert(protocol).second)
            return fail(Mira::Errc::invalid_argument);
        wire += static_cast<char>(protocol.size());
        wire += protocol;
    }
    return wire;
}

int protocol_index() {
    static const int index = SSL_CTX_get_ex_new_index(
        0, nullptr, nullptr, nullptr, [](void*, void* value, CRYPTO_EX_DATA*, int, long, void*) {
            delete static_cast<std::string*>(value);
        });
    return index;
}

int select_protocol(SSL* ssl,
                    const unsigned char** out,
                    unsigned char* out_length,
                    const unsigned char* offered,
                    unsigned int offered_length,
                    void*) {
    const auto* protocols = static_cast<const std::string*>(
        SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), protocol_index()));
    if (!protocols) return SSL_TLSEXT_ERR_ALERT_FATAL;
    // Validate the whole offer first, then match in the server's preference order;
    // the selection must not change with the client's ordering.
    for (std::size_t offset = 0; offset < offered_length;) {
        const auto length = offered[offset++];
        if (length == 0 || length > offered_length - offset) return SSL_TLSEXT_ERR_ALERT_FATAL;
        offset += length;
    }
    for (std::size_t preferred = 0; preferred < protocols->size();) {
        const auto length = static_cast<unsigned char>((*protocols)[preferred++]);
        const std::string_view protocol(protocols->data() + preferred, length);
        preferred += length;
        for (std::size_t offset = 0; offset < offered_length;) {
            const auto offered_size = offered[offset++];
            const std::string_view candidate(reinterpret_cast<const char*>(offered + offset),
                                             offered_size);
            if (candidate == protocol) {
                *out = offered + offset;
                *out_length = offered_size;
                return SSL_TLSEXT_ERR_OK;
            }
            offset += offered_size;
        }
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/// Loads the certificate chain and the private key and verifies they match.
/// The three OpenSSL steps share one error domain.
Result<void> apply_identity(SSL_CTX* handle,
                            std::string_view cert_file,
                            std::string_view key_file) {
    const std::string cert(cert_file);
    const std::string key(key_file);
    ERR_clear_error();
    if (SSL_CTX_use_certificate_chain_file(handle, cert.c_str()) != 1)
        return fail(make_error_code(Errc::configuration_error));
    ERR_clear_error();
    if (SSL_CTX_use_PrivateKey_file(handle, key.c_str(), SSL_FILETYPE_PEM) != 1)
        return fail(make_error_code(Errc::configuration_error));
    ERR_clear_error();
    if (SSL_CTX_check_private_key(handle) != 1)
        return fail(make_error_code(Errc::configuration_error));
    return Result<void>{};
}

/// The minimum protocol version accepts only "1.2"/"1.3"; TLS 1.0/1.1 have
/// never been an option.
Result<void> apply_min_version(SSL_CTX* handle, std::string_view min_version) {
    const int version = min_version == "1.2"   ? TLS1_2_VERSION
                        : min_version == "1.3" ? TLS1_3_VERSION
                                               : 0;
    if (version == 0) return fail(Mira::Errc::invalid_argument);
    ERR_clear_error();
    if (SSL_CTX_set_min_proto_version(handle, version) != 1)
        return fail(make_error_code(Errc::configuration_error));
    return Result<void>{};
}

/// Server-side single-protocol ALPN: attaches the protocol name to the SSL_CTX's
/// ex_data and installs the selection callback. The SSL keeps a reference to the
/// SSL_CTX; the protocol copy is released with the SSL_CTX and does not depend on
/// the Context's lifetime.
Result<void> install_server_alpn(SSL_CTX* handle, std::span<const std::string_view> protocols) {
    auto wire = encode_protocols(protocols);
    if (!wire) return fail(wire.error());
    if (wire->empty()) return Result<void>{};
    const int index = protocol_index();
    if (index < 0) return fail(make_error_code(Errc::configuration_error));
    auto retained = std::make_unique<std::string>(std::move(*wire));
    ERR_clear_error();
    if (SSL_CTX_set_ex_data(handle, index, retained.get()) != 1)
        return fail(make_error_code(Errc::configuration_error));
    retained.release();
    ERR_clear_error();
    SSL_CTX_set_alpn_select_cb(handle, select_protocol, nullptr);
    return Result<void>{};
}
}  // namespace

Context::Context(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Context::Context(Context&&) noexcept = default;
Context& Context::operator=(Context&&) noexcept = default;
Context::~Context() = default;

Result<Context> Context::client(std::string_view ca_file, std::string_view protocol) {
    return client_alpn(ca_file,
                       protocol.empty() ? std::span<const std::string_view>{}
                                        : std::span<const std::string_view>{&protocol, 1});
}

Result<Context> Context::client_alpn(std::string_view ca_file,
                                     std::span<const std::string_view> protocols) {
    if (!ca_file.empty() && !valid_path(ca_file))
        return fail(Mira::Errc::invalid_argument);
    auto wire = encode_protocols(protocols);
    if (!wire) return fail(wire.error());
    auto impl = std::make_unique<Impl>();
    auto handle = make_context();
    if (!handle) return fail(handle.error());
    impl->handle = *handle;
    impl->client = true;
    if (!wire->empty()) {
        ERR_clear_error();
        if (SSL_CTX_set_alpn_protos(impl->handle,
                                    reinterpret_cast<const unsigned char*>(wire->data()),
                                    static_cast<unsigned int>(wire->size())) != 0)
            return fail(make_error_code(Errc::configuration_error));
    }
    ERR_clear_error();
    SSL_CTX_set_verify(impl->handle, SSL_VERIFY_PEER, nullptr);
    const std::string path(ca_file);
    ERR_clear_error();
    const int loaded = path.empty()
                           ? SSL_CTX_set_default_verify_paths(impl->handle)
                           : SSL_CTX_load_verify_locations(impl->handle, path.c_str(), nullptr);
    if (loaded != 1) return fail(make_error_code(Errc::configuration_error));
    return Context(std::move(impl));
}

Result<Context>
Context::server(std::string_view cert_file, std::string_view key_file, std::string_view protocol) {
    return server_alpn(cert_file, key_file,
                       protocol.empty() ? std::span<const std::string_view>{}
                                        : std::span<const std::string_view>{&protocol, 1});
}

Result<Context> Context::server_alpn(std::string_view cert_file,
                                     std::string_view key_file,
                                     std::span<const std::string_view> protocols) {
    if (!valid_path(cert_file) || !valid_path(key_file))
        return fail(Mira::Errc::invalid_argument);
    auto impl = std::make_unique<Impl>();
    auto handle = make_context();
    if (!handle) return fail(handle.error());
    impl->handle = *handle;
    auto alpn = install_server_alpn(impl->handle, protocols);
    if (!alpn) return fail(alpn.error());
    auto identity = apply_identity(impl->handle, cert_file, key_file);
    if (!identity) return fail(identity.error());
    return Context(std::move(impl));
}

Result<Context> Context::server(ServerConfig config) {
    if (!config.client_ca_file.empty() && !valid_path(config.client_ca_file))
        return fail(Mira::Errc::invalid_argument);
    auto protocols = config.protocol.empty()
                         ? std::span<const std::string_view>{}
                         : std::span<const std::string_view>{&config.protocol, 1};
    auto base = server_alpn(config.cert_file, config.key_file, protocols);
    if (!base) return base;
    auto& impl = base->impl_;
    auto min = apply_min_version(impl->handle, config.min_version);
    if (!min) return fail(min.error());
    if (!config.client_ca_file.empty()) {
        const std::string ca(config.client_ca_file);
        ERR_clear_error();
        if (SSL_CTX_load_verify_locations(impl->handle, ca.c_str(), nullptr) != 1)
            return fail(make_error_code(Errc::configuration_error));
        ERR_clear_error();
        // Mandatory mode: clients that present no verifiable certificate are
        // rejected during the handshake.
        SSL_CTX_set_verify(impl->handle,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }
    return std::move(*base);
}

Result<Context> Context::client(ClientConfig config) {
    const bool has_cert = !config.cert_file.empty();
    const bool has_key = !config.key_file.empty();
    if (has_cert != has_key) return fail(Mira::Errc::invalid_argument);
    auto protocols = config.protocol.empty()
                         ? std::span<const std::string_view>{}
                         : std::span<const std::string_view>{&config.protocol, 1};
    auto base = client_alpn(config.ca_file, protocols);
    if (!base) return base;
    if (has_cert) {
        auto identity = apply_identity(base->impl_->handle, config.cert_file, config.key_file);
        if (!identity) return fail(identity.error());
    }
    return std::move(*base);
}

}  // namespace Mira::tls
