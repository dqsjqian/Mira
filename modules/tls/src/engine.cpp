#include "mira/tls/engine.hpp"

#include "context_impl.hpp"

#include <algorithm>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <string>

namespace Mira::tls {

struct Engine::Impl {
    SSL* ssl = nullptr;
    BIO* wire = nullptr;
    bool ready = false;
    bool failed = false;
    bool sent_shutdown = false;
    bool peer_closed = false;

    ~Impl() {
        SSL_free(ssl);
        BIO_free(wire);
    }

    Result<Step> classify(int result, std::size_t transferred = 0) {
        if (result == 1) return Step{Status::complete, transferred};
        // Must sit immediately after the SSL call; it cannot cross an await or
        // any call that might modify the thread's error queue.
        const int error = SSL_get_error(ssl, result);
        switch (error) {
        case SSL_ERROR_WANT_READ:
            return Step{Status::want_input};
        case SSL_ERROR_WANT_WRITE:
            return Step{Status::want_output};
        case SSL_ERROR_ZERO_RETURN:
            peer_closed = true;
            return Step{Status::eof};
        default:
            failed = true;
            ERR_clear_error();
            if (SSL_get_verify_result(ssl) != X509_V_OK)
                return fail(make_error_code(Errc::certificate_verify_failed));
            return fail(make_error_code(Errc::protocol_error));
        }
    }
};

Engine::Engine(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Engine::Engine(Engine&&) noexcept = default;
Engine& Engine::operator=(Engine&&) noexcept = default;
Engine::~Engine() = default;

Result<Engine> Engine::create(const Context& context, std::string_view peer_name) {
    if (!context.impl_) return fail(make_error_code(Errc::invalid_state));
    if (context.impl_->client &&
        (peer_name.empty() || peer_name.find('\0') != std::string_view::npos))
        return fail(Mira::Errc::invalid_argument);
    auto impl = std::make_unique<Impl>();
    ERR_clear_error();
    impl->ssl = SSL_new(context.impl_->handle);
    if (!impl->ssl) return fail(make_error_code(Errc::configuration_error));
    BIO* internal = nullptr;
    ERR_clear_error();
    if (BIO_new_bio_pair(&internal, buffer_capacity, &impl->wire, buffer_capacity) != 1)
        return fail(make_error_code(Errc::configuration_error));
    ERR_clear_error();
    SSL_set_bio(impl->ssl, internal, internal);
    if (context.impl_->client) {
        const std::string name(peer_name);
        ERR_clear_error();
        SSL_set_connect_state(impl->ssl);
        ERR_clear_error();
        ASN1_OCTET_STRING* ip = a2i_IPADDRESS(name.c_str());
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
        // OpenSSL 4.0 deprecated SSL_set1_host in favour of the split
        // dnsname/ipaddr entry points; SSL_set_hostflags is available on
        // both major versions and is not deprecated.
        SSL_set_hostflags(impl->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        ERR_clear_error();
        const int expected = ip ? SSL_set1_ipaddr(impl->ssl, name.c_str())
                                : SSL_set1_dnsname(impl->ssl, name.c_str());
        if (ip) ASN1_OCTET_STRING_free(ip);
        if (expected != 1)
            return fail(make_error_code(Errc::configuration_error));
#else
        X509_VERIFY_PARAM* parameters = SSL_get0_param(impl->ssl);
        X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (ip) {
            ASN1_OCTET_STRING_free(ip);
            ERR_clear_error();
            if (X509_VERIFY_PARAM_set1_ip_asc(parameters, name.c_str()) != 1)
                return fail(make_error_code(Errc::configuration_error));
        } else {
            ERR_clear_error();
            if (SSL_set1_host(impl->ssl, name.c_str()) != 1)
                return fail(make_error_code(Errc::configuration_error));
        }
#endif
        {
            ERR_clear_error();
            // The convenience macro expands to a C-style cast on OpenSSL 3.0.
            // Use its underlying control call with an explicit C++ cast so
            // GCC's -Wold-style-cast remains enabled for our own code.
            if (SSL_ctrl(impl->ssl,
                         SSL_CTRL_SET_TLSEXT_HOSTNAME,
                         TLSEXT_NAMETYPE_host_name,
                         const_cast<char*>(name.c_str())) != 1)
                return fail(make_error_code(Errc::configuration_error));
        }
    } else {
        ERR_clear_error();
        SSL_set_accept_state(impl->ssl);
    }
    return Engine(std::move(impl));
}

Result<Engine::Step> Engine::handshake() {
    if (!impl_ || impl_->failed || impl_->sent_shutdown || impl_->peer_closed)
        return fail(make_error_code(Errc::invalid_state));
    if (impl_->ready) return Step{Status::complete};
    ERR_clear_error();
    const int result = SSL_do_handshake(impl_->ssl);
    auto step = impl_->classify(result);
    if (step && step->status == Status::complete) impl_->ready = true;
    if (step && step->status == Status::eof) {
        impl_->failed = true;
        return fail(make_error_code(Errc::protocol_error));
    }
    return step;
}

Result<Engine::Step> Engine::read(std::span<std::byte> destination) {
    if (!impl_ || impl_->failed || !impl_->ready || impl_->sent_shutdown)
        return fail(make_error_code(Errc::invalid_state));
    if (destination.empty()) return Step{Status::complete};
    if (impl_->peer_closed) return Step{Status::eof};
    std::size_t transferred = 0;
    ERR_clear_error();
    const int result =
        SSL_read_ex(impl_->ssl, destination.data(), destination.size(), &transferred);
    return impl_->classify(result, transferred);
}

Result<Engine::Step> Engine::write(std::span<const std::byte> source) {
    if (!impl_ || impl_->failed || !impl_->ready || impl_->sent_shutdown || impl_->peer_closed)
        return fail(make_error_code(Errc::invalid_state));
    if (source.empty()) return Step{Status::complete};
    std::size_t transferred = 0;
    ERR_clear_error();
    const int result = SSL_write_ex(
        impl_->ssl, source.data(), std::min(source.size(), std::size_t{16 * 1024}), &transferred);
    return impl_->classify(result, transferred);
}

Result<Engine::Step> Engine::shutdown() {
    if (!impl_ || impl_->failed || !impl_->ready) return fail(make_error_code(Errc::invalid_state));
    if (impl_->sent_shutdown) return Step{Status::complete};
    ERR_clear_error();
    const int result = SSL_shutdown(impl_->ssl);
    // A return of 0 means our notification has been sent; it does not require
    // the peer's notification to have arrived.
    if (result >= 0) {
        impl_->sent_shutdown = true;
        return Step{Status::complete};
    }
    auto step = impl_->classify(result);
    if (step && step->status == Status::eof) {
        impl_->failed = true;
        return fail(make_error_code(Errc::protocol_error));
    }
    return step;
}

std::string_view Engine::negotiated_protocol() const noexcept {
    if (!impl_ || !impl_->ready) return {};
    const unsigned char* protocol = nullptr;
    unsigned int length = 0;
    SSL_get0_alpn_selected(impl_->ssl, &protocol, &length);
    if (length == 0) return {};
    return {reinterpret_cast<const char*>(protocol), length};
}

std::size_t Engine::input_capacity() const noexcept {
    if (!impl_ || impl_->failed) return 0;
    return BIO_ctrl_get_write_guarantee(impl_->wire);
}

std::size_t Engine::output_pending() const noexcept {
    return impl_ ? static_cast<std::size_t>(BIO_ctrl_pending(impl_->wire)) : 0;
}

Result<std::size_t> Engine::feed(std::span<const std::byte> ciphertext) {
    if (!impl_ || impl_->failed) return fail(make_error_code(Errc::invalid_state));
    if (ciphertext.empty()) return std::size_t{0};
    const auto size = std::min(ciphertext.size(), input_capacity());
    if (size == 0) return fail(Mira::Errc::would_block);
    ERR_clear_error();
    const int count = BIO_write(impl_->wire, ciphertext.data(), static_cast<int>(size));
    if (count <= 0) {
        impl_->failed = true;
        return fail(make_error_code(Errc::protocol_error));
    }
    return static_cast<std::size_t>(count);
}

Result<std::size_t> Engine::drain(std::span<std::byte> ciphertext) {
    if (!impl_) return fail(make_error_code(Errc::invalid_state));
    const auto pending = static_cast<std::size_t>(BIO_ctrl_pending(impl_->wire));
    const auto size = std::min({ciphertext.size(), pending, buffer_capacity});
    if (size == 0) return std::size_t{0};
    ERR_clear_error();
    const int count = BIO_read(impl_->wire, ciphertext.data(), static_cast<int>(size));
    if (count <= 0) {
        impl_->failed = true;
        return fail(make_error_code(Errc::protocol_error));
    }
    return static_cast<std::size_t>(count);
}

void Engine::invalidate() noexcept {
    if (impl_) impl_->failed = true;
}

}  // namespace Mira::tls
