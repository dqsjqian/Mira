#include "mira/tls/context.hpp"

#include "context_impl.hpp"
#include "mira/tls/error.hpp"

#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <string>
#include <unordered_set>

namespace Mira::tls {
namespace {
Result<ContextHandle> make_context() {
    ERR_clear_error();
    ContextHandle handle{SSL_CTX_new(TLS_method())};
    if (!handle) return fail(make_error_code(Errc::configuration_error));
    ERR_clear_error();
    if (SSL_CTX_set_min_proto_version(handle.get(), TLS1_2_VERSION) != 1)
        return fail(make_error_code(Errc::configuration_error));
    ERR_clear_error();
    SSL_CTX_set_options(handle.get(), SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    ERR_clear_error();
    SSL_CTX_set_mode(handle.get(), SSL_MODE_ENABLE_PARTIAL_WRITE);
    return handle;
}

bool valid_path(std::string_view path) noexcept {
    return !path.empty() && path.find('\0') == std::string_view::npos;
}

char ascii_lower(char value) noexcept {
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

bool valid_hostname(std::string_view name) noexcept {
    if (name.empty() || name.size() > 253) return false;
    std::size_t label_size = 0;
    char previous = '.';
    bool has_non_digit = false;
    for (const char raw : name) {
        const char ch = ascii_lower(raw);
        if (ch == '.') {
            if (label_size == 0 || previous == '-') return false;
            label_size = 0;
        } else {
            const bool letter = ch >= 'a' && ch <= 'z';
            const bool digit = ch >= '0' && ch <= '9';
            if ((!letter && !digit && ch != '-') || (label_size == 0 && ch == '-') ||
                ++label_size > 63) return false;
            has_non_digit = has_non_digit || !digit;
        }
        previous = ch;
    }
    return label_size != 0 && previous != '-' && has_non_digit;
}

bool hostname_matches(std::string_view name, std::string_view canonical) noexcept {
    if (name.size() != canonical.size()) return false;
    for (std::size_t i = 0; i < name.size(); ++i)
        if (ascii_lower(name[i]) != canonical[i]) return false;
    return true;
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

Result<std::string> encode_protocols(std::string_view protocol,
                                     std::span<const std::string_view> protocols) {
    if (!protocol.empty() && !protocols.empty()) return fail(Mira::Errc::invalid_argument);
    return encode_protocols(protocol.empty() ? protocols
                                             : std::span<const std::string_view>{&protocol, 1});
}

int protocol_index() noexcept {
    static const int index = SSL_CTX_get_ex_new_index(
        0, nullptr, nullptr, nullptr, [](void*, void* value, CRYPTO_EX_DATA*, int, long, void*) noexcept {
            delete static_cast<std::string*>(value);
        });
    return index;
}

int select_protocol(SSL* ssl,
                    const unsigned char** out,
                    unsigned char* out_length,
                    const unsigned char* offered,
                    unsigned int offered_length,
                    void*) noexcept {
    const auto* protocols = static_cast<const std::string*>(
        SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), protocol_index()));
    if (!protocols) return SSL_TLSEXT_ERR_ALERT_FATAL;
    // Validate the entire offer before preference matching; no C++ allocation here.
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

int select_identity(SSL* ssl, int* alert, void* argument) noexcept {
    const auto& snapshot = *static_cast<const ContextSnapshot*>(argument);
    const unsigned char* extension = nullptr;
    std::size_t size = 0;
    SSL_CTX* selected = snapshot.handle.get();
    const auto* scope = &snapshot.session_scope;
    bool reject = snapshot.missing_sni == Context::SniPolicy::reject;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &extension, &size) == 1) {
        // Parse this ClientHello, not the old SNI potentially returned during TLS 1.2 resumption.
        if (size < 5 || ((static_cast<std::size_t>(extension[0]) << 8) | extension[1]) != size - 2 ||
            extension[2] != TLSEXT_NAMETYPE_host_name ||
            ((static_cast<std::size_t>(extension[3]) << 8) | extension[4]) != size - 5) {
            *alert = SSL_AD_DECODE_ERROR;
            return SSL_CLIENT_HELLO_ERROR;
        }
        const std::string_view name(reinterpret_cast<const char*>(extension + 5), size - 5);
        if (!valid_hostname(name)) {
            *alert = SSL_AD_ILLEGAL_PARAMETER;
            return SSL_CLIENT_HELLO_ERROR;
        }
        reject = !snapshot.identities.empty() && snapshot.unknown_sni == Context::SniPolicy::reject;
        for (const auto& identity : snapshot.identities) {
            if (hostname_matches(name, identity.hostname)) {
                selected = identity.handle.get();
                scope = &identity.session_scope;
                reject = false;
                break;
            }
        }
    }
    if (reject) {
        *alert = SSL_AD_UNRECOGNIZED_NAME;
        return SSL_CLIENT_HELLO_ERROR;
    }
    // Isolate identity/generation before resumption; old tickets cannot cross domains or reloads.
    if (!SSL_set_SSL_CTX(ssl, selected) ||
        SSL_set_session_id_context(ssl, scope->data(), static_cast<unsigned int>(scope->size())) != 1) {
        *alert = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }
    return SSL_CLIENT_HELLO_SUCCESS;
}

int acknowledge_identity(SSL*, int*, void*) noexcept {
    return SSL_TLSEXT_ERR_OK;
}

Result<void> apply_identity(SSL_CTX* handle,
                            std::string_view cert_file,
                            std::string_view key_file) {
    if (!valid_path(cert_file) || !valid_path(key_file)) return fail(Mira::Errc::invalid_argument);
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

Result<void> install_server_alpn(SSL_CTX* handle, const std::string& wire) {
    if (wire.empty()) return Result<void>{};
    const int index = protocol_index();
    if (index < 0) return fail(make_error_code(Errc::configuration_error));
    auto retained = std::make_unique<std::string>(wire);
    ERR_clear_error();
    if (SSL_CTX_set_ex_data(handle, index, retained.get()) != 1)
        return fail(make_error_code(Errc::configuration_error));
    retained.release();
    ERR_clear_error();
    SSL_CTX_set_alpn_select_cb(handle, select_protocol, nullptr);
    return Result<void>{};
}

using OcspResponse = std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)>;
using OcspBasic = std::unique_ptr<OCSP_BASICRESP, decltype(&OCSP_BASICRESP_free)>;

OcspBasic parse_ocsp(const unsigned char* bytes, std::size_t size) noexcept {
    OcspBasic none{nullptr, OCSP_BASICRESP_free};
    if (!bytes || size == 0 || size > Context::max_ocsp_response_bytes) return none;
    const auto* cursor = bytes;
    OcspResponse response{d2i_OCSP_RESPONSE(nullptr, &cursor, static_cast<long>(size)), OCSP_RESPONSE_free};
    if (!response || cursor != bytes + size ||
        OCSP_response_status(response.get()) != OCSP_RESPONSE_STATUS_SUCCESSFUL) return none;
    return OcspBasic{OCSP_response_get1_basic(response.get()), OCSP_BASICRESP_free};
}

int ocsp_wire_index() noexcept {
    static const int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

struct WireCursor {
    std::span<const unsigned char> bytes;
    bool skip(std::size_t size) noexcept {
        if (size > bytes.size()) return false;
        bytes = bytes.subspan(size);
        return true;
    }
    bool length(unsigned width, std::size_t& value) noexcept {
        if (width > bytes.size()) return false;
        value = 0;
        for (unsigned i = 0; i < width; ++i) value = (value << 8) | bytes[i];
        return skip(width);
    }
};

void inspect_ocsp_wire(SSL* ssl, std::span<const unsigned char> bytes) noexcept {
    auto* state = static_cast<OcspWireState*>(SSL_get_ex_data(ssl, ocsp_wire_index()));
    if (!state) return;
    if (state->seen) state->invalid = true;
    state->seen = true;
    WireCursor body{bytes};
    std::size_t type = 0;
    std::size_t size = 0;
    if (!body.length(1, type) || type != TLSEXT_STATUSTYPE_ocsp || !body.length(3, size) ||
        size != body.bytes.size() || !parse_ocsp(body.bytes.data(), size)) state->invalid = true;
}

void inspect_ocsp_message(int writing, int, int content_type, const void* data,
                          std::size_t size, SSL* ssl, void*) noexcept {
    if (writing || content_type != SSL3_RT_HANDSHAKE || size < 4) return;
    const auto* bytes = static_cast<const unsigned char*>(data);
    if (bytes[0] == SSL3_MT_CERTIFICATE_STATUS) {
        inspect_ocsp_wire(ssl, {bytes + 4, size - 4});
        return;
    }
    if (bytes[0] != SSL3_MT_CERTIFICATE || SSL_version(ssl) != TLS1_3_VERSION) return;
    WireCursor message{{bytes + 4, size - 4}};
    std::size_t length = 0;
    if (!message.length(1, length) || !message.skip(length) || !message.length(3, length) ||
        length != message.bytes.size() || !message.length(3, length) || !message.skip(length) ||
        !message.length(2, length) || length > message.bytes.size()) return;
    WireCursor extensions{message.bytes.first(length)};
    while (!extensions.bytes.empty()) {
        std::size_t type = 0;
        if (!extensions.length(2, type) || !extensions.length(2, length) ||
            length > extensions.bytes.size()) return;
        if (type == TLSEXT_TYPE_status_request) inspect_ocsp_wire(ssl, extensions.bytes.first(length));
        if (!extensions.skip(length)) return;
    }
}

int staple_index() noexcept {
    static const int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr,
        [](void*, void* value, CRYPTO_EX_DATA*, int, long, void*) noexcept {
            delete static_cast<std::vector<std::byte>*>(value);
        });
    return index;
}

int staple_ocsp(SSL* ssl, void*) noexcept {
    const auto* bytes = static_cast<const std::vector<std::byte>*>(
        SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), staple_index()));
    if (!bytes || bytes->empty()) return SSL_TLSEXT_ERR_NOACK;
    // SSL owns this OpenSSL-allocated copy; never pass snapshot or cross-connection memory.
    auto* copy = static_cast<unsigned char*>(OPENSSL_memdup(bytes->data(), bytes->size()));
    if (!copy) return SSL_TLSEXT_ERR_ALERT_FATAL;
    if (SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP,
                  static_cast<long>(bytes->size()), copy) != 1) {
        OPENSSL_free(copy);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
}

Result<void> install_server_ocsp(SSL_CTX* handle, std::span<const std::byte> bytes) {
    if (bytes.empty()) return Result<void>{};
    if (bytes.size() > Context::max_ocsp_response_bytes) return fail(Mira::Errc::invalid_argument);
    ERR_clear_error();
    if (!parse_ocsp(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()))
        return fail(make_error_code(Errc::configuration_error));
    const int index = staple_index();
    if (index < 0) return fail(make_error_code(Errc::configuration_error));
    auto retained = std::make_unique<std::vector<std::byte>>(bytes.begin(), bytes.end());
    if (SSL_CTX_set_ex_data(handle, index, retained.get()) != 1)
        return fail(make_error_code(Errc::configuration_error));
    retained.release();
    if (SSL_CTX_callback_ctrl(handle, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB,
                              reinterpret_cast<void (*)()>(staple_ocsp)) != 1)
        return fail(make_error_code(Errc::configuration_error));
    return Result<void>{};
}

bool verify_ocsp_status(SSL* ssl, Context::OcspPolicy policy) noexcept {
    if (policy == Context::OcspPolicy::disabled) return true;
    if (SSL_session_reused(ssl) != 0) return false;
    const auto* wire = static_cast<const OcspWireState*>(SSL_get_ex_data(ssl, ocsp_wire_index()));
    if (!wire || wire->invalid) return false;
    const unsigned char* bytes = nullptr;
    const long size = SSL_ctrl(ssl, SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP, 0, &bytes);
    if (size == -1 && !bytes) return !wire->seen && policy == Context::OcspPolicy::request;
    if (size <= 0 || !bytes || !wire->seen || SSL_get_verify_result(ssl) != X509_V_OK) return false;
    auto basic = parse_ocsp(bytes, static_cast<std::size_t>(size));
    if (!basic) return false;
    auto* chain = SSL_get0_verified_chain(ssl);
    const auto* stack = reinterpret_cast<const OPENSSL_STACK*>(chain);
    const int count = chain ? OPENSSL_sk_num(stack) : 0;
    if (count < 1) return false;
    auto* leaf = static_cast<X509*>(OPENSSL_sk_value(stack, 0));
    auto* issuer = static_cast<X509*>(OPENSSL_sk_value(stack, count > 1 ? 1 : 0));
    if (!leaf || !issuer || X509_cmp(leaf, SSL_get0_peer_certificate(ssl)) != 0 ||
        X509_check_issued(issuer, leaf) != X509_V_OK) return false;
    // Explicit OCSP trust for another CA cannot replace this certificate issuer's authorization.
    if (OCSP_basic_verify(basic.get(), chain, SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl)),
                           OCSP_NOEXPLICIT) != 1) return false;
    constexpr long skew = 300;
    constexpr long max_age = 7 * 24 * 60 * 60;
    const auto* produced = OCSP_resp_get0_produced_at(basic.get());
    if (!produced || OCSP_check_validity(const_cast<ASN1_GENERALIZEDTIME*>(produced),
                                         nullptr, skew, max_age) != 1) return false;
    bool found = false;
    const int responses = OCSP_resp_count(basic.get());
    for (int i = 0; i < responses; ++i) {
        auto* single = OCSP_resp_get0(basic.get(), i);
        if (!single) return false;
        const auto* id = OCSP_SINGLERESP_get0_id(single);
        ASN1_OBJECT* digest_id = nullptr;
        if (!id || OCSP_id_get0_info(nullptr, &digest_id, nullptr, nullptr,
                                      const_cast<OCSP_CERTID*>(id)) != 1) return false;
        // CertID hashes are identifiers, not signatures; accept RFC SHA-1/SHA-2 identifiers.
        const int nid = OBJ_obj2nid(digest_id);
        const EVP_MD* digest = nid == NID_sha1 ? EVP_sha1() :
            nid == NID_sha256 ? EVP_sha256() : nid == NID_sha384 ? EVP_sha384() :
            nid == NID_sha512 ? EVP_sha512() : nullptr;
        if (!digest) return false;
        std::unique_ptr<OCSP_CERTID, decltype(&OCSP_CERTID_free)> expected{
            OCSP_cert_to_id(digest, leaf, issuer), OCSP_CERTID_free};
        if (!expected) return false;
        if (OCSP_id_cmp(id, expected.get()) != 0) continue;
        if (found) return false;
        found = true;
        ASN1_GENERALIZEDTIME* this_update = nullptr;
        ASN1_GENERALIZEDTIME* next_update = nullptr;
        const int status = OCSP_single_get0_status(single, nullptr, nullptr, &this_update, &next_update);
        if (status != V_OCSP_CERTSTATUS_GOOD || !this_update || !next_update ||
            OCSP_check_validity(this_update, next_update, skew, max_age) != 1) return false;
        // Unknown critical extensions must not be silently ignored.
        for (int ext = 0; ext < OCSP_SINGLERESP_get_ext_count(single); ++ext)
            if (X509_EXTENSION_get_critical(OCSP_SINGLERESP_get_ext(single, ext)) != 0) return false;
    }
    for (int ext = 0; ext < OCSP_BASICRESP_get_ext_count(basic.get()); ++ext)
        if (X509_EXTENSION_get_critical(OCSP_BASICRESP_get_ext(basic.get(), ext)) != 0) return false;
    return found;
}

int verify_ocsp_callback(SSL* ssl, void* argument) noexcept {
    const auto* snapshot = static_cast<const ContextSnapshot*>(argument);
    if (snapshot && verify_ocsp_status(ssl, snapshot->ocsp)) return 1;
    SSL_set_verify_result(ssl, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}

Result<void> apply_revocation(SSL_CTX* handle, Context::RevocationConfig config) {
    if (config.mode != Context::CrlMode::leaf && config.mode != Context::CrlMode::chain)
        return fail(Mira::Errc::invalid_argument);
    if (config.crl_file.empty()) return Result<void>{};
    if (!valid_path(config.crl_file)) return fail(Mira::Errc::invalid_argument);
    const std::string file(config.crl_file);
    X509_STORE* store = SSL_CTX_get_cert_store(handle);
    ERR_clear_error();
    X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup || X509_load_crl_file(lookup, file.c_str(), X509_FILETYPE_PEM) <= 0)
        return fail(make_error_code(Errc::configuration_error));
    const unsigned long flags = X509_V_FLAG_CRL_CHECK |
        (config.mode == Context::CrlMode::chain ? X509_V_FLAG_CRL_CHECK_ALL : 0UL);
    ERR_clear_error();
    if (X509_STORE_set_flags(store, flags) != 1)
        return fail(make_error_code(Errc::configuration_error));
    // Resumption skips certificate checks; disable it so stale CRLs cannot reuse old approval.
    SSL_CTX_set_options(handle, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(handle, SSL_SESS_CACHE_OFF);
    if (SSL_CTX_set_num_tickets(handle, 0) != 1)
        return fail(make_error_code(Errc::configuration_error));
    return Result<void>{};
}

Result<ContextHandle> make_server_handle(Context::ServerConfig config,
                                          std::string_view cert,
                                          std::string_view key,
                                          const std::string& wire,
                                          std::span<const std::byte> ocsp) {
    auto handle = make_context();
    if (!handle) return fail(handle.error());
    auto identity = apply_identity(handle->get(), cert, key);
    if (!identity) return fail(identity.error());
    auto min = apply_min_version(handle->get(), config.min_version);
    if (!min) return fail(min.error());
    auto alpn = install_server_alpn(handle->get(), wire);
    if (!alpn) return fail(alpn.error());
    auto staple = install_server_ocsp(handle->get(), ocsp);
    if (!staple) return fail(staple.error());
    if (!config.client_ca_file.empty()) {
        if (!valid_path(config.client_ca_file)) return fail(Mira::Errc::invalid_argument);
        const std::string ca(config.client_ca_file);
        ERR_clear_error();
        if (SSL_CTX_load_verify_locations(handle->get(), ca.c_str(), nullptr) != 1)
            return fail(make_error_code(Errc::configuration_error));
        SSL_CTX_set_verify(handle->get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        // Advertise acceptable CAs to clients selecting among several identities.
        ERR_clear_error();
        auto* names = SSL_load_client_CA_file(ca.c_str());
        if (!names) return fail(make_error_code(Errc::configuration_error));
        SSL_CTX_set_client_CA_list(handle->get(), names);
    } else if (!config.revocation.crl_file.empty()) {
        return fail(Mira::Errc::invalid_argument);
    }
    auto revocation = apply_revocation(handle->get(), config.revocation);
    if (!revocation) return fail(revocation.error());
    return std::move(*handle);
}

Result<std::shared_ptr<const ContextSnapshot>> make_server_snapshot(Context::ServerConfig config) {
    if ((config.unknown_sni != Context::SniPolicy::reject &&
         config.unknown_sni != Context::SniPolicy::use_default) ||
        (config.missing_sni != Context::SniPolicy::reject &&
         config.missing_sni != Context::SniPolicy::use_default))
        return fail(Mira::Errc::invalid_argument);
    auto wire = encode_protocols(config.protocol, config.protocols);
    if (!wire) return fail(wire.error());
    auto handle = make_server_handle(config, config.cert_file, config.key_file, *wire, config.ocsp_response);
    if (!handle) return fail(handle.error());
    auto snapshot = std::make_shared<ContextSnapshot>();
    snapshot->handle = std::move(*handle);
    snapshot->unknown_sni = config.unknown_sni;
    snapshot->missing_sni = config.missing_sni;
    std::unordered_set<std::string> seen;
    for (const auto& identity : config.identities) {
        if (!valid_hostname(identity.hostname)) return fail(Mira::Errc::invalid_argument);
        std::string hostname(identity.hostname);
        for (char& ch : hostname) ch = ascii_lower(ch);
        if (!seen.insert(hostname).second) return fail(Mira::Errc::invalid_argument);
        auto named = make_server_handle(config, identity.cert_file, identity.key_file, *wire, identity.ocsp_response);
        if (!named) return fail(named.error());
        ERR_clear_error();
        if (X509_check_host(SSL_CTX_get0_certificate(named->get()), hostname.c_str(), hostname.size(),
                            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
                            nullptr) != 1)
            return fail(make_error_code(Errc::configuration_error));
        snapshot->identities.push_back({std::move(hostname), std::move(*named)});
    }
    const auto install = [&](SSL_CTX* target, std::array<unsigned char, 32>& scope) -> Result<void> {
        ERR_clear_error();
        if (RAND_bytes(scope.data(), static_cast<int>(scope.size())) != 1 ||
            SSL_CTX_set_session_id_context(target, scope.data(), static_cast<unsigned int>(scope.size())) != 1)
            return fail(make_error_code(Errc::configuration_error));
        SSL_CTX_set_client_hello_cb(target, select_identity, snapshot.get());
        // Avoid OpenSSL 3.0 macros' C-style function-pointer casts under strict GCC warnings.
        if (SSL_CTX_callback_ctrl(target, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,
                                   reinterpret_cast<void (*)()>(acknowledge_identity)) != 1)
            return fail(make_error_code(Errc::configuration_error));
        return Result<void>{};
    };
    auto installed = install(snapshot->handle.get(), snapshot->session_scope);
    if (!installed) return fail(installed.error());
    for (auto& identity : snapshot->identities) {
        installed = install(identity.handle.get(), identity.session_scope);
        if (!installed) return fail(installed.error());
    }
    return std::shared_ptr<const ContextSnapshot>{std::move(snapshot)};
}
}  // namespace

Result<void> track_peer_ocsp(SSL* ssl, OcspWireState& state) noexcept {
    const int index = ocsp_wire_index();
    if (index < 0 || SSL_set_ex_data(ssl, index, &state) != 1)
        return fail(make_error_code(Errc::configuration_error));
    // OpenSSL 3.6 re-encodes OCSP: inspect original DER so trailing bytes cannot be hidden.
    SSL_set_msg_callback(ssl, inspect_ocsp_message);
    return Result<void>{};
}

bool verify_peer_ocsp(SSL* ssl, Context::OcspPolicy policy) noexcept {
    return verify_ocsp_status(ssl, policy);
}

Context::Context(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Context::Context(Context&&) noexcept = default;
Context& Context::operator=(Context&&) noexcept = default;
Context::~Context() = default;

Result<Context> Context::client(std::string_view ca_file, std::string_view protocol) {
    return client(ClientConfig{.ca_file = ca_file, .protocol = protocol});
}

Result<Context> Context::client_alpn(std::string_view ca_file,
                                     std::span<const std::string_view> protocols) {
    return client(ClientConfig{.ca_file = ca_file, .protocols = protocols});
}

Result<Context>
Context::server(std::string_view cert_file, std::string_view key_file, std::string_view protocol) {
    return server(ServerConfig{.cert_file = cert_file, .key_file = key_file, .protocol = protocol});
}

Result<Context> Context::server_alpn(std::string_view cert_file,
                                     std::string_view key_file,
                                     std::span<const std::string_view> protocols) {
    return server(ServerConfig{.cert_file = cert_file, .key_file = key_file, .protocols = protocols});
}

Result<Context> Context::server(ServerConfig config) {
    auto snapshot = make_server_snapshot(config);
    if (!snapshot) return fail(snapshot.error());
    auto impl = std::make_unique<Impl>();
    impl->snapshot = std::move(*snapshot);
    return Context(std::move(impl));
}

Result<void> Context::reload_server(ServerConfig config) {
    if (!impl_ || impl_->client) return fail(make_error_code(Errc::invalid_state));
    auto snapshot = make_server_snapshot(config);
    if (!snapshot) return fail(snapshot.error());
    impl_->publish(std::move(*snapshot));
    return Result<void>{};
}

Result<Context> Context::client(ClientConfig config) {
    if (config.ocsp != OcspPolicy::disabled && config.ocsp != OcspPolicy::request &&
        config.ocsp != OcspPolicy::require) return fail(Mira::Errc::invalid_argument);
    const bool has_cert = !config.cert_file.empty();
    const bool has_key = !config.key_file.empty();
    if (has_cert != has_key || (!config.ca_file.empty() && !valid_path(config.ca_file)))
        return fail(Mira::Errc::invalid_argument);
    auto wire = encode_protocols(config.protocol, config.protocols);
    if (!wire) return fail(wire.error());
    auto handle = make_context();
    if (!handle) return fail(handle.error());
    if (!wire->empty()) {
        ERR_clear_error();
        if (SSL_CTX_set_alpn_protos(handle->get(),
                                    reinterpret_cast<const unsigned char*>(wire->data()),
                                    static_cast<unsigned int>(wire->size())) != 0)
            return fail(make_error_code(Errc::configuration_error));
    }
    ERR_clear_error();
    SSL_CTX_set_verify(handle->get(), SSL_VERIFY_PEER, nullptr);
    const std::string path(config.ca_file);
    ERR_clear_error();
    const int loaded = path.empty()
                           ? SSL_CTX_set_default_verify_paths(handle->get())
                           : SSL_CTX_load_verify_locations(handle->get(), path.c_str(), nullptr);
    if (loaded != 1) return fail(make_error_code(Errc::configuration_error));
    if (has_cert) {
        auto identity = apply_identity(handle->get(), config.cert_file, config.key_file);
        if (!identity) return fail(identity.error());
    }
    auto revocation = apply_revocation(handle->get(), config.revocation);
    if (!revocation) return fail(revocation.error());
    auto snapshot = std::make_shared<ContextSnapshot>();
    snapshot->handle = std::move(*handle);
    snapshot->ocsp = config.ocsp;
    if (config.ocsp != OcspPolicy::disabled) {
        SSL_CTX* target = snapshot->handle.get();
        SSL_CTX_set_options(target, SSL_OP_NO_TICKET);
        SSL_CTX_set_session_cache_mode(target, SSL_SESS_CACHE_OFF);
        if (SSL_CTX_ctrl(target, SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE, TLSEXT_STATUSTYPE_ocsp, nullptr) != 1 ||
            SSL_CTX_callback_ctrl(target, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB,
                                   reinterpret_cast<void (*)()>(verify_ocsp_callback)) != 1 ||
            SSL_CTX_ctrl(target, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG, 0, snapshot.get()) != 1)
            return fail(make_error_code(Errc::configuration_error));
    }
    auto impl = std::make_unique<Impl>();
    impl->client = true;
    impl->snapshot = std::move(snapshot);
    return Context(std::move(impl));
}

}  // namespace Mira::tls
