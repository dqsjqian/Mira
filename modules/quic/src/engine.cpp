#include "mira/quic/engine.hpp"

#include <ngtcp2/ngtcp2.h>
#if NGTCP2_VERSION_NUM < 0x011601
    #error "Mira::quic requires ngtcp2 >= 1.22.1"
#endif
#include <algorithm>
#include <array>
#include <deque>
#include <exception>
#include <limits>
#include <map>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace Mira::quic {
namespace {
// Engine-owned error codes, placed far away from native ngtcp2 negative codes.
constexpr int invalid = -100000;
constexpr int budget = -100001;

class QuicCategory final : public std::error_category {
public:
    const char* name() const noexcept override { return "Mira.quic"; }
    std::string message(int code) const override {
        if (code == invalid) return "invalid QUIC argument or state";
        if (code == budget) return "QUIC resource budget exceeded";
        return ngtcp2_strerror(code);
    }
};
}  // namespace

Error quic_error(int code) noexcept {
    // The category must be returned as a storage-duration constant: std::error_code only holds a
    // reference to it, and a temporary would be destroyed after the return, leaving a dangling pointer.
    static const QuicCategory category{};
    return {code, category};
}

bool fill_random(std::uint8_t* destination, std::size_t length) noexcept {
    if (length > static_cast<std::size_t>(std::numeric_limits<int>::max())) return false;
    return RAND_bytes(destination, static_cast<int>(length)) == 1;
}
Result<PacketRoute> packet_route(std::span<const std::byte> packet) {
    if (packet.empty() || packet.size() > detail::kMaxDatagram)
        return std::unexpected(quic_error(invalid));
    ngtcp2_version_cid ids{};
    auto* data = reinterpret_cast<const std::uint8_t*>(packet.data());
    int rv = ngtcp2_pkt_decode_version_cid(&ids, data, packet.size(), 16);
    if (rv || !ids.dcidlen || ids.dcidlen > NGTCP2_MAX_CIDLEN)
        return std::unexpected(quic_error(rv ? rv : invalid));
    bool initial = false;
    if ((data[0] & 0x80) != 0) {
        if (ids.version != NGTCP2_PROTO_VER_V1)
            return std::unexpected(quic_error(invalid));
        ngtcp2_pkt_hd hd{};
        initial = packet.size() >= 1200 && ngtcp2_accept(&hd, data, packet.size()) == 0;
    }
    auto* cid = reinterpret_cast<const std::byte*>(ids.dcid);
    return PacketRoute{Bytes(cid, cid + ids.dcidlen), initial};
}

struct Engine::Impl {
    Options options;
    ngtcp2_conn* conn = nullptr;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    ngtcp2_crypto_ossl_ctx* crypto = nullptr;
    ngtcp2_crypto_conn_ref ref{};
    ngtcp2_path path{};
    bool failed = false;
    bool ended = false;
    int failure_code = 0;
    std::vector<Bytes> retained_ids;
    std::uint64_t clock = 0;
    std::size_t buffered = 0;
    std::size_t queued_chunks = 0;
    std::size_t received = 0;
    std::uint64_t remote_bidi_limit = 0;
    std::vector<Event> events;
    struct Chunk {
        Bytes bytes;
        std::uint64_t start;
        std::size_t sent = 0;
        bool fin;
        bool submitted = false;
    };
    struct Stream {
        std::deque<Chunk> chunks;
        std::uint64_t end = 0;
        std::uint64_t unread = 0;
        bool fin = false;
        bool cancelled = false;
        bool closed = false;
    };
    std::map<std::int64_t, Stream> streams;
    std::int64_t last_application_stream = -1;
    ~Impl() {
        if (ssl) {
            SSL_set_app_data(ssl, nullptr);
            SSL_free(ssl);
        }
        if (conn) ngtcp2_conn_del(conn);
        if (crypto) ngtcp2_crypto_ossl_ctx_del(crypto);
        if (ctx) SSL_CTX_free(ctx);
    }
    bool time(std::uint64_t now) {
        if (now < clock) return false;
        clock = now;
        return true;
    }
    static Impl& self(void* p) { return *static_cast<Impl*>(p); }
    template<class F>
    static int guarded(F&& f) noexcept {
        try {
            return f();
        } catch (...) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }
    bool capacity() const { return streams.size() < options.max_streams * 2 + 8; }
    static int receive_data(ngtcp2_conn*,
                            std::uint32_t flags,
                            std::int64_t id,
                            std::uint64_t,
                            const std::uint8_t* data,
                            std::size_t size,
                            void* p,
                            void*) {
        return guarded([&] {
            auto& s = self(p);
            if (size > s.options.max_buffered_bytes - s.received ||
                (!s.streams.contains(id) && !s.capacity()) || s.events.size() >= 4096)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            auto& stream = s.streams[id];
            stream.unread += size;
            s.received += size;
            // The C API hands us `const uint8_t*`; the library-wide byte
            // type is `std::byte`, and this callback is the boundary.
            Bytes bytes(reinterpret_cast<const std::byte*>(data),
                        reinterpret_cast<const std::byte*>(data) + size);
            s.events.push_back({Event::Kind::data,
                                id,
                                std::move(bytes),
                                0,
                                bool(flags & NGTCP2_STREAM_DATA_FLAG_FIN)});
            return 0;
        });
    }
    static int acknowledged(
        ngtcp2_conn*, std::int64_t id, std::uint64_t offset, std::uint64_t size, void* p, void*) {
        return guarded([&] {
            auto& s = self(p);
            if (auto it = s.streams.find(id); it != s.streams.end()) {
                auto& q = it->second.chunks;
                while (!q.empty() && q.front().submitted &&
                       q.front().start + q.front().bytes.size() <= offset + size) {
                    s.buffered -= q.front().bytes.size();
                    --s.queued_chunks;
                    q.pop_front();
                }
            }
            if (s.events.size() >= 4096) return NGTCP2_ERR_CALLBACK_FAILURE;
            s.events.push_back({Event::Kind::acknowledged, id, {}, size, false});
            return 0;
        });
    }
    static int stream_close(
        ngtcp2_conn* conn, std::uint32_t, std::int64_t id, std::uint64_t code, void* p, void*) {
        return guarded([&] {
            auto& s = self(p);
            bool released = true;
            if (auto it = s.streams.find(id); it != s.streams.end()) {
                for (auto& c : it->second.chunks)
                    s.buffered -= c.bytes.size();
                // Delivered-but-unconsumed data still counts against the total window, letting the application consume it later.
                s.queued_chunks -= it->second.chunks.size();
                it->second.chunks.clear();
                it->second.closed = true;
                if (!it->second.unread) s.streams.erase(it);
                else released = false;
            }
            // After a peer-initiated stream closes, return its credit for opening new streams.
            // When the record is retained because of unconsumed data, the return is deferred and
            // re-issued by consume() once the record is drained, so local record capacity always
            // covers the number of peer streams already admitted.
            if (released && !ngtcp2_conn_is_local_stream(conn, id)) {
                if (ngtcp2_is_bidi_stream(id))
                    ngtcp2_conn_extend_max_streams_bidi(conn, 1);
                else
                    ngtcp2_conn_extend_max_streams_uni(conn, 1);
            }
            if (s.events.size() >= 4096) return NGTCP2_ERR_CALLBACK_FAILURE;
            s.events.push_back({Event::Kind::closed, id, {}, code, false});
            return 0;
        });
    }
    static int
    reset(ngtcp2_conn*, std::int64_t id, std::uint64_t, std::uint64_t code, void* p, void*) {
        return guarded([&] {
            auto& s = self(p);
            if (s.events.size() >= 4096) return NGTCP2_ERR_CALLBACK_FAILURE;
            s.events.push_back({Event::Kind::reset, id, {}, code, false});
            return 0;
        });
    }
    static void random(std::uint8_t* dest, std::size_t len, const ngtcp2_rand_ctx*) {
        // This no-return-value callback is only used for non-security-protocol randomness; security-relevant CIDs below check the RNG return value separately.
        if (RAND_bytes(dest, static_cast<int>(len)) != 1) std::terminate();
    }
    void retain(const ngtcp2_cid& id) {
        auto* first = reinterpret_cast<const std::byte*>(id.data);
        Bytes bytes(first, first + id.datalen);
        if (std::find(retained_ids.begin(), retained_ids.end(), bytes) == retained_ids.end())
            retained_ids.push_back(std::move(bytes));
    }
    static int cid(ngtcp2_conn*,
                   ngtcp2_cid* id,
                   ngtcp2_stateless_reset_token* token,
                   std::size_t length,
                   void* p) {
        return guarded([&] {
            auto& s = self(p);
            // Never evict retired CIDs: terminate rather than issue an unprotectable CID.
            if (s.retained_ids.size() >= s.options.max_connection_ids)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            id->datalen = length;
            if (RAND_bytes(id->data, static_cast<int>(length)) != 1 ||
                RAND_bytes(token->data, sizeof(token->data)) != 1)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            s.retain(*id);
            return 0;
        });
    }
    static int select_alpn(SSL*,
                           const unsigned char** out,
                           unsigned char* outlen,
                           const unsigned char* in,
                           unsigned int inlen,
                           void* p) {
        auto& protocol = self(p).options.alpn;
        for (unsigned int i = 0; i < inlen;) {
            unsigned int len = in[i++];
            if (len > inlen - i) return SSL_TLSEXT_ERR_ALERT_FATAL;
            if (len == protocol.size() && std::equal(in + i, in + i + len, protocol.begin())) {
                *out = in + i;
                *outlen = static_cast<unsigned char>(len);
                return SSL_TLSEXT_ERR_OK;
            }
            i += len;
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
};
Engine::Engine(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Engine::Engine(Engine&&) noexcept = default;
Engine& Engine::operator=(Engine&&) noexcept = default;
Engine::~Engine() = default;
Result<Engine> Engine::client(Options o, std::uint64_t now) {
    o.server = false;
    return create(std::move(o), {}, now);
}
Result<Engine> Engine::accept(Options o, std::span<const std::byte> initial, std::uint64_t now) {
    o.server = true;
    return create(std::move(o), initial, now);
}
Result<Engine>
Engine::create(Options options, std::span<const std::byte> initial, std::uint64_t now) {
    if (options.local.address_bytes().empty() || options.remote.address_bytes().empty() ||
        options.alpn.empty() || options.alpn.size() > 255 ||
        options.alpn.find('\0') != std::string::npos || options.max_streams == 0 ||
        options.max_streams > 4096 || options.max_buffered_bytes < 4096 ||
        options.max_buffered_bytes > 64 * 1024 * 1024 ||
        options.max_connection_ids < 2 || options.max_connection_ids > 64 ||
        (!options.server &&
         (options.peer_name.empty() || options.peer_name.find('\0') != std::string::npos)))
        return std::unexpected(quic_error(invalid));
    auto s = std::make_unique<Impl>();
    s->options = std::move(options);
    s->remote_bidi_limit = s->options.max_streams;
    s->clock = now;
    auto local = s->options.local.address_bytes(), remote = s->options.remote.address_bytes();
    s->path.local = {reinterpret_cast<ngtcp2_sockaddr*>(const_cast<std::byte*>(local.data())),
                     static_cast<ngtcp2_socklen>(local.size())};
    s->path.remote = {reinterpret_cast<ngtcp2_sockaddr*>(const_cast<std::byte*>(remote.data())),
                      static_cast<ngtcp2_socklen>(remote.size())};
    ngtcp2_callbacks cb{};
    cb.client_initial = ngtcp2_crypto_client_initial_cb;
    cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
    cb.update_key = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    cb.rand = Impl::random;
    cb.get_new_connection_id2 = Impl::cid;
    cb.recv_stream_data = Impl::receive_data;
    cb.acked_stream_data_offset = Impl::acknowledged;
    cb.stream_close = Impl::stream_close;
    cb.stream_reset = Impl::reset;
    cb.extend_max_remote_streams_bidi = [](ngtcp2_conn*, std::uint64_t limit, void* p) {
        Impl::self(p).remote_bidi_limit = limit;
        return 0;
    };
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now;
    settings.no_pmtud = 1;
    settings.max_tx_udp_payload_size = 1200;
    settings.handshake_timeout = 10 * NGTCP2_SECONDS;
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_data = s->options.max_buffered_bytes;
    params.initial_max_stream_data_bidi_local = s->options.max_buffered_bytes;
    params.initial_max_stream_data_bidi_remote = s->options.max_buffered_bytes;
    params.initial_max_stream_data_uni = s->options.max_buffered_bytes;
    params.initial_max_streams_bidi = s->options.max_streams;
    params.initial_max_streams_uni = 3;
    params.max_idle_timeout = s->options.idle_timeout_ns;
    params.active_connection_id_limit = 2;
    params.disable_active_migration = 1;
    ngtcp2_cid scid{}, dcid{};
    scid.datalen = 16;
    dcid.datalen = 16;
    if (RAND_bytes(scid.data, 16) != 1 || RAND_bytes(dcid.data, 16) != 1)
        return std::unexpected(quic_error(invalid));
    int rv;
    if (s->options.server) {
        ngtcp2_pkt_hd hd{};
        // ngtcp2's C API only speaks uint8_t; the library-wide byte is std::byte, and the cast is contained here.
        rv = ngtcp2_accept(&hd, reinterpret_cast<const std::uint8_t*>(initial.data()),
                           initial.size());
        if (rv != 0) return std::unexpected(quic_error(rv));
        dcid = hd.scid;
        params.original_dcid = hd.dcid;
        params.original_dcid_present = 1;
        rv = ngtcp2_conn_server_new(&s->conn,
                                    &dcid,
                                    &scid,
                                    &s->path,
                                    hd.version,
                                    &cb,
                                    &settings,
                                    &params,
                                    nullptr,
                                    s.get());
    } else {
        rv = ngtcp2_conn_client_new(&s->conn,
                                    &dcid,
                                    &scid,
                                    &s->path,
                                    NGTCP2_PROTO_VER_V1,
                                    &cb,
                                    &settings,
                                    &params,
                                    nullptr,
                                    s.get());
    }
    if (rv) return std::unexpected(quic_error(rv));
    s->retain(scid);
    s->retain(s->options.server ? params.original_dcid : dcid);
    s->ctx = SSL_CTX_new(TLS_method());
    if (!s->ctx || SSL_CTX_set_min_proto_version(s->ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(s->ctx, TLS1_3_VERSION) != 1)
        return std::unexpected(quic_error(invalid));
    if (s->options.server) {
        if (SSL_CTX_use_certificate_chain_file(s->ctx, s->options.certificate_file.c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(
                s->ctx, s->options.private_key_file.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(s->ctx) != 1)
            return std::unexpected(quic_error(invalid));
        SSL_CTX_set_alpn_select_cb(s->ctx, Impl::select_alpn, s.get());
    } else {
        SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER, nullptr);
        int trust =
            s->options.ca_file.empty()
                ? SSL_CTX_set_default_verify_paths(s->ctx)
                : SSL_CTX_load_verify_locations(s->ctx, s->options.ca_file.c_str(), nullptr);
        if (trust != 1) return std::unexpected(quic_error(invalid));
    }
    s->ssl = SSL_new(s->ctx);
    if (!s->ssl || ngtcp2_crypto_ossl_ctx_new(&s->crypto, s->ssl) != 0)
        return std::unexpected(quic_error(invalid));
    s->ref.get_conn = [](ngtcp2_crypto_conn_ref* ref) {
        return static_cast<Impl*>(ref->user_data)->conn;
    };
    s->ref.user_data = s.get();
    SSL_set_app_data(s->ssl, &s->ref);
    if (s->options.server) {
        rv = ngtcp2_crypto_ossl_configure_server_session(s->ssl);
        SSL_set_accept_state(s->ssl);
    } else {
        rv = ngtcp2_crypto_ossl_configure_client_session(s->ssl);
        SSL_set_connect_state(s->ssl);
        auto name = s->options.peer_name.c_str();
        if (transport::Endpoint::parse(s->options.peer_name, 0)) {
            if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(s->ssl), name) != 1) rv = -1;
        } else if (
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
                   // OpenSSL 4.0 deprecated SSL_set1_host in favour of the
                   // split dnsname/ipaddr entry points.
                   SSL_set1_dnsname(s->ssl, name) != 1 ||
#else
                   SSL_set1_host(s->ssl, name) != 1 ||
#endif
                   // The convenience macro expands to a C-style cast; use its
                   // underlying control call so GCC's -Wold-style-cast stays
                   // enabled, matching the tls module's precedent.
                   SSL_ctrl(s->ssl,
                            SSL_CTRL_SET_TLSEXT_HOSTNAME,
                            TLSEXT_NAMETYPE_host_name,
                            const_cast<char*>(name)) != 1)
            rv = -1;
        // Wire-format ALPN list: one length-prefixed protocol. SSL wants
        // `const uint8_t*`; the cast is the boundary.
        Bytes protocol{static_cast<std::byte>(s->options.alpn.size())};
        protocol.insert(protocol.end(),
                        reinterpret_cast<const std::byte*>(s->options.alpn.data()),
                        reinterpret_cast<const std::byte*>(s->options.alpn.data()) +
                            s->options.alpn.size());
        if (SSL_set_alpn_protos(s->ssl,
                                reinterpret_cast<const unsigned char*>(protocol.data()),
                                static_cast<unsigned int>(protocol.size())) != 0)
            rv = -1;
    }
    if (rv) return std::unexpected(quic_error(invalid));
    ngtcp2_conn_set_tls_native_handle(s->conn, s->crypto);
    Engine engine(std::move(s));
    if (engine.impl_->options.server) {
        if (auto r = engine.receive(initial, now); !r) return std::unexpected(r.error());
    }
    return engine;
}
Result<void> Engine::receive(std::span<const std::byte> packet, std::uint64_t now) {
    auto& s = *impl_;
    if (s.failed || s.ended || !s.time(now))
        return std::unexpected(quic_error(invalid));
    ngtcp2_pkt_info info{};
    int rv = ngtcp2_conn_read_pkt(s.conn, &s.path, &info,
                                  reinterpret_cast<const std::uint8_t*>(packet.data()),
                                  packet.size(), now);
    if (rv == NGTCP2_ERR_DRAINING) {
        s.ended = true;
        return {};
    }
    if (rv) {
        s.failed = true;
        s.failure_code = rv;
        return std::unexpected(quic_error(rv));
    }
    return {};
}
Result<Bytes> Engine::poll(std::uint64_t now) {
    auto& s = *impl_;
    if (s.failed || s.ended || !s.time(now))
        return std::unexpected(quic_error(invalid));
    std::array<std::uint8_t, 1200> out{};
    ngtcp2_pkt_info info{};
    ngtcp2_path_storage path;
    ngtcp2_path_storage_zero(&path);
    // Unidirectional control streams come before bidirectional application streams, so an exhausted application window cannot stall control/QPACK progress.
    for (bool unidirectional : {true, false}) {
    auto it = unidirectional ? s.streams.begin() : s.streams.upper_bound(s.last_application_stream);
    for (std::size_t visited = 0; visited < s.streams.size(); ++visited) {
        if (it == s.streams.end()) it = s.streams.begin();
        auto& [id, stream] = *it++;
        if (stream.cancelled || bool(id & 2) != unidirectional) continue;
        for (auto& chunk : stream.chunks) {
            if (chunk.submitted) continue;
            // `ngtcp2_vec::base` is `uint8_t*` (a C API without const
            // discipline); ngtcp2 only reads it, so the const_cast marks the
            // library boundary rather than granting mutation.
            ngtcp2_vec vec{
                chunk.bytes.empty()
                    ? nullptr
                    : const_cast<std::uint8_t*>(
                          reinterpret_cast<const std::uint8_t*>(chunk.bytes.data())) +
                          chunk.sent,
                chunk.bytes.size() - chunk.sent};
            ngtcp2_ssize used = -1;
            auto n = ngtcp2_conn_writev_stream(s.conn,
                                               &path.path,
                                               &info,
                                               out.data(),
                                               out.size(),
                                               &used,
                                               chunk.fin ? NGTCP2_WRITE_STREAM_FLAG_FIN
                                                         : NGTCP2_WRITE_STREAM_FLAG_NONE,
                                               id,
                                               &vec,
                                               1,
                                               now);
            if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED || n == NGTCP2_ERR_STREAM_SHUT_WR ||
                n == NGTCP2_ERR_STREAM_NOT_FOUND)
                break;
            if (n < 0) {
                s.failed = true;
                s.failure_code = static_cast<int>(n);
                return std::unexpected(quic_error(static_cast<int>(n)));
            }
            if (used >= 0) {
                chunk.sent += static_cast<std::size_t>(used);
                chunk.submitted = chunk.sent == chunk.bytes.size();
            }
            if (n > 0) {
                if (!unidirectional) s.last_application_stream = id;
                ngtcp2_conn_update_pkt_tx_time(s.conn, now);
                // `out` is the C-API scratch; convert at the boundary.
                return Bytes(reinterpret_cast<const std::byte*>(out.data()),
                             reinterpret_cast<const std::byte*>(out.data()) + n);
            }
            break;
        }
    }
    }
    auto n = ngtcp2_conn_write_pkt(s.conn, &path.path, &info, out.data(), out.size(), now);
    if (n < 0) {
        s.failed = true;
        s.failure_code = static_cast<int>(n);
        return std::unexpected(quic_error(static_cast<int>(n)));
    }
    if (n) ngtcp2_conn_update_pkt_tx_time(s.conn, now);
    return Bytes(reinterpret_cast<const std::byte*>(out.data()),
                 reinterpret_cast<const std::byte*>(out.data()) + n);
}
Result<void> Engine::handle_expiry(std::uint64_t now) {
    auto& s = *impl_;
    if (s.failed || s.ended || !s.time(now))
        return std::unexpected(quic_error(invalid));
    int rv = ngtcp2_conn_handle_expiry(s.conn, now);
    if (rv) {
        s.failed = true;
        s.failure_code = rv;
        return std::unexpected(quic_error(rv));
    }
    return {};
}
std::uint64_t Engine::expiry() const noexcept {
    return ngtcp2_conn_get_expiry(impl_->conn);
}
bool Engine::handshake_complete() const noexcept {
    return !impl_->failed && ngtcp2_conn_get_handshake_completed(impl_->conn);
}
bool Engine::is_server() const noexcept {
    return impl_->options.server;
}
std::size_t Engine::write_capacity() const noexcept {
    return impl_->failed || impl_->ended ? 0 : impl_->options.max_buffered_bytes - impl_->buffered;
}
std::uint64_t Engine::remote_bidi_stream_limit() const noexcept {
    return impl_->remote_bidi_limit;
}
bool Engine::closed() const noexcept {
    return impl_->ended || impl_->failed;
}
std::vector<Bytes> Engine::local_connection_ids() const {
    std::vector<ngtcp2_cid> ids(ngtcp2_conn_get_scid(impl_->conn, nullptr));
    ngtcp2_conn_get_scid(impl_->conn, ids.data());
    std::vector<Bytes> result;
    result.reserve(ids.size());
    for (const auto& id : ids) {
        auto* first = reinterpret_cast<const std::byte*>(id.data);
        result.emplace_back(first, first + id.datalen);
    }
    return result;
}
std::vector<Bytes> Engine::retained_connection_ids() const {
    return impl_->retained_ids;
}
std::uint64_t Engine::pto() const noexcept {
    return ngtcp2_conn_get_pto(impl_->conn);
}
bool Engine::draining() const noexcept {
    return ngtcp2_conn_in_draining_period(impl_->conn) != 0;
}
Bytes Engine::initial_destination_cid() const {
    const auto* id = ngtcp2_conn_get_client_initial_dcid(impl_->conn);
    auto* first = reinterpret_cast<const std::byte*>(id->data);
    return Bytes(first, first + id->datalen);
}
std::string Engine::negotiated_protocol() const {
    const unsigned char* data = nullptr;
    unsigned int size = 0;
    SSL_get0_alpn_selected(impl_->ssl, &data, &size);
    return size ? std::string(reinterpret_cast<const char*>(data), size) : std::string{};
}
Result<std::int64_t> Engine::open_stream(bool uni) {
    auto& s = *impl_;
    if (s.failed || s.ended || !handshake_complete())
        return std::unexpected(quic_error(invalid));
    if (!s.capacity()) return std::unexpected(quic_error(budget));
    std::int64_t id;
    int rv = uni ? ngtcp2_conn_open_uni_stream(s.conn, &id, nullptr)
                 : ngtcp2_conn_open_bidi_stream(s.conn, &id, nullptr);
    if (rv) return std::unexpected(quic_error(rv));
    s.streams.try_emplace(id);
    return id;
}
Result<void> Engine::write(std::int64_t id, std::span<const std::byte> bytes, bool fin) {
    auto& s = *impl_;
    auto it = s.streams.find(id);
    if (s.failed || s.ended || it == s.streams.end() || it->second.fin || it->second.cancelled)
        return std::unexpected(quic_error(invalid));
    if (bytes.size() > s.options.max_buffered_bytes - s.buffered ||
        s.queued_chunks >= 4096)
        return std::unexpected(quic_error(budget));
    if (bytes.empty() && !fin) return {};
    auto& stream = it->second;
    stream.chunks.push_back({Bytes(reinterpret_cast<const std::byte*>(bytes.data()),
                                   reinterpret_cast<const std::byte*>(bytes.data()) +
                                       bytes.size()),
                             stream.end,
                             0,
                             fin,
                             false});
    stream.end += bytes.size();
    stream.fin = fin;
    s.buffered += bytes.size();
    ++s.queued_chunks;
    return {};
}
std::vector<Event> Engine::take_events() {
    std::vector<Event> result;
    result.swap(impl_->events);
    return result;
}
Result<void> Engine::consume(std::int64_t id, std::size_t bytes) {
    auto& s = *impl_;
    auto it = s.streams.find(id);
    if (it == s.streams.end() || bytes > it->second.unread)
        return std::unexpected(quic_error(invalid));
    int rv = ngtcp2_conn_extend_max_stream_offset(s.conn, id, bytes);
    if (rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) return std::unexpected(quic_error(rv));
    ngtcp2_conn_extend_max_offset(s.conn, bytes);
    it->second.unread -= bytes;
    s.received -= bytes;
    if (it->second.closed && !it->second.unread) {
        // Peer stream credit whose return was deferred at close due to unconsumed data is re-issued here.
        if (!ngtcp2_conn_is_local_stream(s.conn, id)) {
            if (ngtcp2_is_bidi_stream(id)) ngtcp2_conn_extend_max_streams_bidi(s.conn, 1);
            else ngtcp2_conn_extend_max_streams_uni(s.conn, 1);
        }
        s.streams.erase(it);
    }
    return {};
}
Result<void> Engine::cancel(std::int64_t id, std::uint64_t code) {
    if (id < 0 || code >= (std::uint64_t{1} << 62))
        return std::unexpected(quic_error(invalid));
    auto& s = *impl_;
    if (s.failed || s.ended) return std::unexpected(quic_error(invalid));
    int rv = ngtcp2_conn_shutdown_stream(s.conn, 0, id, code);
    if (rv) return std::unexpected(quic_error(rv));
    if (auto it = s.streams.find(id); it != s.streams.end()) it->second.cancelled = true;
    return {};
}
Result<Bytes> Engine::close(std::uint64_t code, std::uint64_t now) {
    if (code >= (std::uint64_t{1} << 62))
        return std::unexpected(quic_error(invalid));
    auto& s = *impl_;
    if (s.ended || !s.time(now)) return std::unexpected(quic_error(invalid));
    if (s.failure_code == NGTCP2_ERR_IDLE_CLOSE || s.failure_code == NGTCP2_ERR_DROP_CONN ||
        s.failure_code == NGTCP2_ERR_RETRY || draining()) {
        s.ended = true;
        return Bytes{};
    }
    ngtcp2_ccerr err;
    ngtcp2_ccerr_default(&err);
    if (s.failure_code == NGTCP2_ERR_CRYPTO)
        ngtcp2_ccerr_set_tls_alert(&err, ngtcp2_conn_get_tls_alert(s.conn), nullptr, 0);
    else if (s.failure_code)
        ngtcp2_ccerr_set_liberr(&err, s.failure_code, nullptr, 0);
    else
        ngtcp2_ccerr_set_application_error(&err, code, nullptr, 0);
    Bytes packet(1200);
    ngtcp2_pkt_info info{};
    auto n = ngtcp2_conn_write_connection_close(
        s.conn, nullptr, &info, reinterpret_cast<std::uint8_t*>(packet.data()), packet.size(),
        &err, now);
    if (n < 0) return std::unexpected(quic_error(static_cast<int>(n)));
    packet.resize(static_cast<std::size_t>(n));
    s.ended = true;
    return packet;
}
}  // namespace Mira::quic
