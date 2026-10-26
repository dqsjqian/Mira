#include "mira/tls/engine.hpp"

#include "context_impl.hpp"

#include <algorithm>
#include <ctime>
#include <new>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <string>

namespace Mira::tls {

namespace {
using SessionHandle = std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)>;

std::chrono::seconds remaining_lifetime(const SSL_SESSION* session) noexcept {
#if OPENSSL_VERSION_NUMBER >= 0x30400000L
    const auto issued = SSL_SESSION_get_time_ex(session);
#else
    const auto issued = static_cast<std::time_t>(SSL_SESSION_get_time(session));
#endif
    const auto now = std::time(nullptr);
    const auto local_timeout = SSL_SESSION_get_timeout(session);
    const auto advertised = SSL_SESSION_get_ticket_lifetime_hint(session);
    if (now < issued || local_timeout <= 0 || advertised == 0) return std::chrono::seconds::zero();
    const auto timeout = std::min({static_cast<unsigned long>(local_timeout), advertised, 7UL * 24 * 3600});
    const auto age = static_cast<unsigned long>(now - issued);
    if (age >= timeout) return std::chrono::seconds::zero();
    return std::chrono::seconds(timeout - age);
}
}

struct SessionTicket::Impl {
    SessionHandle session{nullptr, SSL_SESSION_free};
    std::shared_ptr<const ContextSnapshot> snapshot;
    std::string peer_name;
    std::chrono::steady_clock::time_point expires;
};
SessionTicket::SessionTicket(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
SessionTicket::SessionTicket(SessionTicket&&) noexcept = default;
SessionTicket& SessionTicket::operator=(SessionTicket&&) noexcept = default;
SessionTicket::~SessionTicket() = default;

struct Engine::Impl {
    ResourceBudget::Reservation reservation;
    ResourceBudget::Reservation early_reservation;
    std::optional<ResourceBudget> budget;
    std::shared_ptr<const ContextSnapshot> snapshot;
    SSL* ssl = nullptr;
    BIO* wire = nullptr;
    OcspWireState ocsp;
    std::string peer_name;
    SessionHandle offered_session{nullptr, SSL_SESSION_free};
    std::chrono::steady_clock::time_point resumption_expires{};
    std::unique_ptr<std::array<std::byte, max_early_data_bytes>> early_bytes;
    std::size_t early_size = 0;
    std::size_t early_offset = 0;
    EarlyDataStatus early_status = EarlyDataStatus::not_attempted;
    bool client = false;
    bool started = false;
    bool resumed = false;
    bool ticket_taken = false;
    bool early_receiving = false;
    bool early_operation = false;
    bool early_written = false;
    bool early_complete = false;
    bool ready = false;
    bool failed = false;
    bool sent_shutdown = false;
    bool peer_closed = false;

    ~Impl() {
        release_early();
        SSL_free(ssl);
        BIO_free(wire);
    }

    void release_early() noexcept {
        if (early_bytes) OPENSSL_cleanse(early_bytes->data(), early_bytes->size());
        early_bytes.reset();
        early_reservation.reset();
    }

    Result<void> reserve_early() noexcept {
        if (early_bytes) return {};
        ResourceBudget::Reservation charge;
        if (budget) {
            auto acquired = budget->try_acquire(max_early_data_bytes);
            if (!acquired) {
                failed = true;
                return fail(acquired.error());
            }
            charge = std::move(*acquired);
        }
        early_bytes.reset(new (std::nothrow) std::array<std::byte, max_early_data_bytes>);
        if (!early_bytes) {
            failed = true;
            return fail(Mira::Errc::limit_exceeded);
        }
        early_reservation = std::move(charge);
        return {};
    }

    Result<void> prepare_resumption() {
        if (!resumed || started || (std::chrono::steady_clock::now() < resumption_expires &&
            remaining_lifetime(offered_session.get()).count() > 0)) return {};
        ERR_clear_error();
        if (SSL_set_session(ssl, nullptr) != 1) {
            failed = true;
            release_early();
            return fail(make_error_code(Errc::configuration_error));
        }
        resumed = false;
        offered_session.reset();
        return {};
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
            release_early();
            return Step{Status::eof};
        default:
            failed = true;
            release_early();
            ERR_clear_error();
            if (ocsp.invalid || SSL_get_verify_result(ssl) != X509_V_OK)
                return fail(make_error_code(Errc::certificate_verify_failed));
            return fail(make_error_code(Errc::protocol_error));
        }
    }
};

Engine::Engine(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Engine::Engine(Engine&&) noexcept = default;
Engine& Engine::operator=(Engine&&) noexcept = default;
Engine::~Engine() = default;

Result<Engine> Engine::create(const Context& context, std::string_view peer_name,
                              std::optional<ResourceBudget> budget) {
    if (!context.impl_) return fail(make_error_code(Errc::invalid_state));
    if (context.impl_->client &&
        (peer_name.empty() || peer_name.find('\0') != std::string_view::npos))
        return fail(Mira::Errc::invalid_argument);
    ResourceBudget::Reservation reservation;
    if (budget) {
        auto acquired = budget->try_acquire(reserved_buffer_bytes);
        if (!acquired) return fail(acquired.error());
        reservation = std::move(*acquired);
    }
    auto impl = std::make_unique<Impl>();
    impl->reservation = std::move(reservation);
    impl->budget = std::move(budget);
    impl->snapshot = context.impl_->load_snapshot();
    impl->client = context.impl_->client;
    impl->early_receiving = !impl->client && impl->snapshot->early_data == EarlyDataPolicy::replay_safe;
    ERR_clear_error();
    impl->ssl = SSL_new(impl->snapshot->handle.get());
    if (!impl->ssl) return fail(make_error_code(Errc::configuration_error));
    if (impl->snapshot->ocsp != Context::OcspPolicy::disabled) {
        auto tracked = track_peer_ocsp(impl->ssl, impl->ocsp);
        if (!tracked) return fail(tracked.error());
    }
    BIO* internal = nullptr;
    ERR_clear_error();
    if (BIO_new_bio_pair(&internal, buffer_capacity, &impl->wire, buffer_capacity) != 1)
        return fail(make_error_code(Errc::configuration_error));
    ERR_clear_error();
    SSL_set_bio(impl->ssl, internal, internal);
    if (context.impl_->client) {
        // A zone id routes the connection; it is never TLS identity. A
        // scoped literal ("fe80::1%eth0") would otherwise fail
        // a2i_IPADDRESS below and be misclassified as a DNS name, sending
        // a bogus SNI and verifying against the wrong name. Strip the zone
        // only when the part before '%' is itself an IP literal, so every
        // other peer name passes through unchanged.
        std::string name(peer_name);
        if (const auto percent = name.find('%'); percent != std::string::npos) {
            const std::string bare = name.substr(0, percent);
            if (ASN1_OCTET_STRING* probe = a2i_IPADDRESS(bare.c_str()); probe != nullptr) {
                ASN1_OCTET_STRING_free(probe);
                name = bare;
            }
        }
        impl->peer_name = name;
        ERR_clear_error();
        SSL_set_connect_state(impl->ssl);
        ERR_clear_error();
        ASN1_OCTET_STRING* ip = a2i_IPADDRESS(name.c_str());
        const bool is_ip = ip != nullptr;
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
        if (!is_ip) {
            ERR_clear_error();
            // IP literals are verified through SAN but are not legal SNI names.
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
    if (!impl_ || impl_->failed || impl_->sent_shutdown || impl_->peer_closed ||
        (impl_->early_operation && !impl_->early_complete))
        return fail(make_error_code(Errc::invalid_state));
    return drive_handshake();
}

Result<Engine::Step> Engine::drive_handshake() {
    if (impl_->ready) return Step{Status::complete};
    const auto prepared = impl_->prepare_resumption();
    if (!prepared) return fail(prepared.error());
    impl_->started = true;
    while (impl_->early_receiving) {
        const auto reserved = impl_->reserve_early();
        if (!reserved) return fail(reserved.error());
        std::size_t transferred = 0;
        std::byte overflow{};
        const auto remaining = impl_->early_bytes->size() - impl_->early_size;
        void* destination = remaining ? impl_->early_bytes->data() + impl_->early_size : &overflow;
        ERR_clear_error();
        const int result = SSL_read_early_data(impl_->ssl, destination, remaining ? remaining : 1, &transferred);
        if (result == SSL_READ_EARLY_DATA_ERROR) return impl_->classify(0);
        if (transferred > remaining) {
            impl_->failed = true;
            impl_->release_early();
            return fail(make_error_code(Errc::protocol_error));
        }
        impl_->early_size += transferred;
        if (result == SSL_READ_EARLY_DATA_FINISH) {
            impl_->early_receiving = false;
            if (impl_->early_size == 0) impl_->release_early();
        }
    }
    ERR_clear_error();
    const int result = SSL_do_handshake(impl_->ssl);
    auto step = impl_->classify(result);
    if (step && step->status == Status::complete) {
        if (!verify_peer_ocsp(impl_->ssl, impl_->snapshot->ocsp)) {
            impl_->failed = true;
            impl_->release_early();
            return fail(make_error_code(Errc::certificate_verify_failed));
        }
        impl_->ready = true;
        const auto status = SSL_get_early_data_status(impl_->ssl);
        impl_->early_status = status == SSL_EARLY_DATA_ACCEPTED ? EarlyDataStatus::accepted :
            status == SSL_EARLY_DATA_REJECTED ? EarlyDataStatus::rejected : EarlyDataStatus::not_attempted;
    }
    if (step && step->status == Status::eof) {
        impl_->failed = true;
        return fail(make_error_code(Errc::protocol_error));
    }
    return step;
}

Result<Engine::Step> Engine::handshake_early_data(std::span<const std::byte> source, EarlyDataPolicy policy) {
    if (!impl_ || impl_->failed || !impl_->client || impl_->sent_shutdown || impl_->peer_closed ||
        impl_->early_complete || (!impl_->early_operation && impl_->started))
        return fail(make_error_code(Errc::invalid_state));
    if (policy != EarlyDataPolicy::replay_safe || source.empty() || source.size() > max_early_data_bytes ||
        !impl_->snapshot->client_sessions) return fail(Mira::Errc::invalid_argument);
    if (!impl_->early_operation) {
        const auto reserved = impl_->reserve_early();
        if (!reserved) return fail(reserved.error());
        const auto prepared = impl_->prepare_resumption();
        if (!prepared) return fail(prepared.error());
        std::copy(source.begin(), source.end(), impl_->early_bytes->begin());
        impl_->early_size = source.size();
        impl_->early_operation = true;
        impl_->started = true;
        const auto* session = SSL_get_session(impl_->ssl);
        const bool eligible = impl_->resumed && session && remaining_lifetime(session).count() > 0 &&
                              SSL_SESSION_get_max_early_data(session) >= source.size();
        impl_->early_written = !eligible;
        if (eligible) impl_->early_status = EarlyDataStatus::pending;
    } else if (source.size() != impl_->early_size ||
               !std::equal(source.begin(), source.end(), impl_->early_bytes->begin())) {
        return fail(Mira::Errc::invalid_argument);
    }
    if (!impl_->early_written) {
        std::size_t transferred = 0;
        ERR_clear_error();
        const int result = SSL_write_early_data(impl_->ssl, impl_->early_bytes->data() + impl_->early_offset,
                                               impl_->early_size - impl_->early_offset, &transferred);
        const auto step = impl_->classify(result, transferred);
        if (!step || step->status != Status::complete) return step;
        impl_->early_offset += transferred;
        if (impl_->early_offset != impl_->early_size) return Step{Status::want_output};
        impl_->early_written = true;
        impl_->early_offset = 0;
    }
    const auto handshake = drive_handshake();
    if (!handshake || handshake->status != Status::complete) return handshake;
    if (impl_->early_status != EarlyDataStatus::accepted) {
        std::size_t transferred = 0;
        ERR_clear_error();
        const int result = SSL_write_ex(impl_->ssl, impl_->early_bytes->data() + impl_->early_offset,
                                        impl_->early_size - impl_->early_offset, &transferred);
        const auto step = impl_->classify(result, transferred);
        if (!step || step->status != Status::complete) return step;
        impl_->early_offset += transferred;
        if (impl_->early_offset != impl_->early_size) return Step{Status::want_output};
    }
    impl_->early_complete = true;
    impl_->release_early();
    return Step{Status::complete, impl_->early_size};
}

Result<void> Engine::resume(SessionTicket ticket) {
    if (!impl_ || impl_->failed || !impl_->client || impl_->started || impl_->resumed)
        return fail(make_error_code(Errc::invalid_state));
    if (!ticket.impl_ || !impl_->snapshot->client_sessions || ticket.impl_->snapshot != impl_->snapshot ||
        ticket.impl_->peer_name != impl_->peer_name) return fail(Mira::Errc::invalid_argument);
    if (std::chrono::steady_clock::now() >= ticket.impl_->expires ||
        remaining_lifetime(ticket.impl_->session.get()).count() <= 0) return {};
    ERR_clear_error();
    if (SSL_set_session(impl_->ssl, ticket.impl_->session.get()) != 1)
        return fail(make_error_code(Errc::configuration_error));
    impl_->resumed = true;
    impl_->resumption_expires = ticket.impl_->expires;
    impl_->offered_session = std::move(ticket.impl_->session);
    return {};
}

Result<std::optional<SessionTicket>> Engine::take_session() {
    if (!impl_ || impl_->failed || !impl_->client || !impl_->ready ||
        (impl_->early_operation && !impl_->early_complete))
        return fail(make_error_code(Errc::invalid_state));
    if (!impl_->snapshot->client_sessions || impl_->ticket_taken) return std::optional<SessionTicket>{};
    auto* session = SSL_get_session(impl_->ssl);
    if (!session || SSL_SESSION_get_protocol_version(session) != TLS1_3_VERSION ||
        !SSL_SESSION_has_ticket(session) || !SSL_SESSION_is_resumable(session))
        return std::optional<SessionTicket>{};
    if (impl_->offered_session) {
        const unsigned char* offered = nullptr;
        const unsigned char* current = nullptr;
        std::size_t offered_size = 0, current_size = 0;
        SSL_SESSION_get0_ticket(impl_->offered_session.get(), &offered, &offered_size);
        SSL_SESSION_get0_ticket(session, &current, &current_size);
        if (offered && current && offered_size == current_size &&
            std::equal(offered, offered + offered_size, current))
            return std::optional<SessionTicket>{};
    }
    const auto lifetime = remaining_lifetime(session);
    if (lifetime.count() <= 0) return std::optional<SessionTicket>{};
    auto ticket = std::make_unique<SessionTicket::Impl>();
    ticket->session.reset(SSL_SESSION_dup(session));
    if (!ticket->session) return fail(make_error_code(Errc::configuration_error));
    ticket->snapshot = impl_->snapshot;
    ticket->peer_name = impl_->peer_name;
    ticket->expires = std::chrono::steady_clock::now() + lifetime;
    impl_->ticket_taken = true;
    return std::optional<SessionTicket>{SessionTicket(std::move(ticket))};
}

EarlyDataStatus Engine::early_data_status() const noexcept {
    return impl_ ? impl_->early_status : EarlyDataStatus::not_attempted;
}

Result<Engine::Step> Engine::read(std::span<std::byte> destination) {
    if (!impl_ || impl_->failed || !impl_->ready || impl_->sent_shutdown ||
        (impl_->early_operation && !impl_->early_complete))
        return fail(make_error_code(Errc::invalid_state));
    if (destination.empty()) return Step{Status::complete};
    if (!impl_->client && impl_->early_offset < impl_->early_size) {
        const auto count = std::min(destination.size(), impl_->early_size - impl_->early_offset);
        std::copy_n(impl_->early_bytes->data() + impl_->early_offset, count, destination.data());
        OPENSSL_cleanse(impl_->early_bytes->data() + impl_->early_offset, count);
        impl_->early_offset += count;
        if (impl_->early_offset == impl_->early_size) impl_->release_early();
        return Step{Status::complete, count};
    }
    if (impl_->peer_closed) return Step{Status::eof};
    std::size_t transferred = 0;
    ERR_clear_error();
    const int result =
        SSL_read_ex(impl_->ssl, destination.data(), destination.size(), &transferred);
    return impl_->classify(result, transferred);
}

Result<Engine::Step> Engine::write(std::span<const std::byte> source) {
    if (!impl_ || impl_->failed || !impl_->ready || impl_->sent_shutdown || impl_->peer_closed ||
        (impl_->early_operation && !impl_->early_complete))
        return fail(make_error_code(Errc::invalid_state));
    if (source.empty()) return Step{Status::complete};
    std::size_t transferred = 0;
    ERR_clear_error();
    const int result = SSL_write_ex(
        impl_->ssl, source.data(), std::min(source.size(), std::size_t{16 * 1024}), &transferred);
    return impl_->classify(result, transferred);
}

Result<Engine::Step> Engine::shutdown() {
    if (!impl_ || impl_->failed || !impl_->ready || (impl_->early_operation && !impl_->early_complete))
        return fail(make_error_code(Errc::invalid_state));
    if (impl_->sent_shutdown) return Step{Status::complete};
    ERR_clear_error();
    const int result = SSL_shutdown(impl_->ssl);
    // A return of 0 means our notification has been sent; it does not require
    // the peer's notification to have arrived.
    if (result >= 0) {
        impl_->sent_shutdown = true;
        impl_->release_early();
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
    if (impl_) {
        impl_->failed = true;
        impl_->release_early();
    }
}

}  // namespace Mira::tls
