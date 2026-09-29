#include "mira/http3/engine.hpp"

#include <nghttp3/nghttp3.h>
#if NGHTTP3_VERSION_NUM < 0x010f00
    #error "Mira::http3 requires nghttp3 >= 1.15.0"
#endif
#include <algorithm>
#include <array>
#include <charconv>
#include <deque>
#include <exception>
#include <map>
#include <optional>
#include <set>

namespace Mira::http3 {
namespace {
// Engine-owned error codes, placed far away from the native nghttp3 negative-code range to avoid clashing with the dependency.
constexpr int invalid = -110000;
constexpr std::size_t qpack_capacity = 4096;
constexpr std::size_t qpack_blocked = 16;

// RFC 9110 safe methods: the only requests this engine sends in, or surfaces from, 0-RTT.
bool early_safe(std::string_view method) {
    return method == "GET" || method == "HEAD" || method == "OPTIONS";
}

std::string_view field(const Headers& fields, std::string_view name) {
    for (const auto& h : fields) if (h.name == name) return h.value;
    return {};
}
bool protocol_token(std::string_view value) {
    if (value.empty()) return false;
    for (const char raw : value) {
        const auto c = static_cast<unsigned char>(raw);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) != std::string_view::npos)
            continue;
        return false;
    }
    return true;
}
bool success_status(const Headers& fields) {
    const auto value = field(fields, ":status");
    return value.size() == 3 && value.front() == '2';
}

class Http3Category final : public std::error_category {
public:
    const char* name() const noexcept override { return "Mira.http3"; }
    std::string message(int code) const override {
        if (code == invalid) return "invalid HTTP/3 argument or state";
        return nghttp3_strerror(code);
    }
};
}  // namespace

Error http3_error(int code) noexcept {
    // Same as quic_error: the category must have static storage duration, not be a temporary.
    static const Http3Category category{};
    return {code, category};
}
std::string early_data_context(const Limits& limits) {
    return "h3-settings-v1;max_field_section_size=" + std::to_string(limits.max_header_bytes) +
           ";qpack_max_dtable_capacity=" + std::to_string(qpack_capacity) +
           ";qpack_blocked_streams=" + std::to_string(qpack_blocked) +
           ";enable_connect_protocol=" + (limits.enable_connect_protocol ? "1" : "0");
}
struct Engine::Impl {
    quic::Engine transport;
    bool server;
    Limits limits;
    nghttp3_conn* conn = nullptr;
    bool failed = false, initialized = false, going = false, remote_going = false;
    bool final_goaway = false, peer_connect = false;
    // Client: control/QPACK streams and requests were opened as 0-RTT streams.
    bool early_mode = false;
    // Server: client bidi streams that carried 0-RTT data, and unsafe ones awaiting 425.
    std::set<std::int64_t> early_ids;
    std::vector<std::int64_t> too_early;
    std::uint64_t clock = 0;
    std::size_t output_bytes = 0, input_bytes = 0, header_bytes = 0;
    std::vector<Event> events;
    std::size_t retained_chunk_count() const {
        std::size_t total = 0;
        for (const auto& [id, stream] : streams) { (void)id; total += stream.output.size(); }
        return total;
    }
    struct Stream {
        std::deque<quic::Bytes> output;
        std::size_t offered = 0, acked = 0, queued = 0, produced = 0;
        std::size_t unread = 0, field_bytes = 0;
        std::optional<std::size_t> content_length;
        Headers fields;
        bool responded = false, closed = false, head = false;
        bool streaming = false, finished = false, body_forbidden = false;
        std::string protocol;
        bool accepted = false, headers_received = false, remote_end = false;
        // early: sent (client) in 0-RTT. too_early: unsafe 0-RTT request answered 425 (server).
        bool early = false, too_early = false;
        // Client 0-RTT request fields, kept until the server accepts or rejects early data.
        Headers replay;
        Error error;
        std::deque<quic::Bytes> input;
        std::size_t input_offset = 0;
    };
    std::map<std::int64_t, Stream> streams;
    Impl(quic::Engine q, bool s, Limits l) : transport(std::move(q)), server(s), limits(l) {}
    ~Impl() { nghttp3_conn_del(conn); }
    template<class F>
    static int guard(F&& f) noexcept {
        try {
            return f();
        } catch (...) {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
    }
    static Impl& self(void* p) { return *static_cast<Impl*>(p); }
    int push(Event e) {
        if (events.size() >= limits.max_events) return NGHTTP3_ERR_CALLBACK_FAILURE;
        events.push_back(std::move(e));
        return 0;
    }
    static int begin(nghttp3_conn*, std::int64_t id, void* p, void*) {
        return guard([&] {
            auto& s = self(p);
            if (!s.streams.contains(id) && s.streams.size() >= s.limits.max_streams)
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            auto& stream = s.streams[id];
            stream.fields.clear();
            stream.field_bytes = 0;
            return 0;
        });
    }
    static int header(nghttp3_conn*,
                      std::int64_t id,
                      std::int32_t,
                      nghttp3_rcbuf* name,
                      nghttp3_rcbuf* value,
                      std::uint8_t,
                      void* p,
                      void*) {
        return guard([&] {
            auto& s = self(p);
            auto& stream = s.streams.at(id);
            auto n = nghttp3_rcbuf_get_buf(name), v = nghttp3_rcbuf_get_buf(value);
            std::size_t size = n.len + v.len + 32;
            if (size > s.limits.max_header_bytes - stream.field_bytes ||
                stream.fields.size() >= s.limits.max_headers ||
                size > s.limits.max_header_bytes * s.limits.max_streams - s.header_bytes)
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            stream.field_bytes += size;
            s.header_bytes += size;
            stream.fields.push_back(Header{std::string(reinterpret_cast<char*>(n.base), n.len),
                                           std::string(reinterpret_cast<char*>(v.base), v.len)});
            if (stream.fields.back().name == ":method") stream.head = stream.fields.back().value == "HEAD";
            return 0;
        });
    }
    void drop_fields(Stream& stream) {
        header_bytes -= stream.field_bytes;
        stream.fields.clear();
        stream.field_bytes = 0;
    }
    static int end_headers(nghttp3_conn*, std::int64_t id, int, void* p, void*) {
        return guard([&] {
            auto& s = self(p);
            auto& stream = s.streams.at(id);
            if (stream.too_early) {
                s.drop_fields(stream);
                return 0;
            }
            const auto status = field(stream.fields, ":status");
            const bool informational = !s.server && status.size() == 3 && status.front() == '1';
            const bool early = s.server ? s.early_ids.contains(id) : stream.early;
            if (!stream.headers_received && !informational) {
                if (s.server && early && !early_safe(field(stream.fields, ":method"))) {
                    // RFC 8470: never surface a replayable unsafe request; answer 425 after this read.
                    s.drop_fields(stream);
                    stream.headers_received = stream.too_early = true;
                    s.too_early.push_back(id);
                    return 0;
                }
                if (s.server && field(stream.fields, ":method") == "CONNECT") {
                    if (!s.limits.enable_connect_protocol ||
                        !s.valid_fields(stream.fields, {}, true, true)) {
                        s.header_bytes -= stream.field_bytes;
                        stream.fields.clear();
                        stream.field_bytes = 0;
                        return reset(s.conn, id, NGHTTP3_H3_MESSAGE_ERROR, p, nullptr);
                    }
                    stream.protocol = field(stream.fields, ":protocol");
                } else if (!s.server && !stream.protocol.empty()) {
                    if (!s.valid_fields(stream.fields, {}, true, false, true)) {
                        s.header_bytes -= stream.field_bytes;
                        stream.fields.clear();
                        stream.field_bytes = 0;
                        return reset(s.conn, id, NGHTTP3_H3_MESSAGE_ERROR, p, nullptr);
                    }
                    if (status == "204") {
                        s.header_bytes -= stream.field_bytes;
                        stream.fields.clear();
                        stream.field_bytes = 0;
                        return reset(s.conn, id, NGHTTP3_H3_REQUEST_CANCELLED, p, nullptr);
                    }
                    stream.accepted = success_status(stream.fields);
                }
                stream.headers_received = true;
            }
            Event event{Event::Kind::headers, id, std::move(stream.fields), {}, 0};
            event.early_data = early;
            return s.push(std::move(event));
        });
    }
    static int data(nghttp3_conn*,
                    std::int64_t id,
                    const std::uint8_t* bytes,
                    std::size_t size,
                    void* p,
                    void*) {
        return guard([&] {
            auto& s = self(p);
            if (size > s.limits.max_buffered_body - s.input_bytes)
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            auto& stream = s.streams.at(id);
            if (stream.error || stream.too_early)
                return s.transport.consume(id, size) ? 0 : NGHTTP3_ERR_CALLBACK_FAILURE;
            stream.unread += size;
            s.input_bytes += size;
            quic::Bytes chunk(reinterpret_cast<const std::byte*>(bytes),
                              reinterpret_cast<const std::byte*>(bytes) + size);
            if (!stream.protocol.empty() && (s.server || stream.accepted)) {
                if (stream.input.size() >= s.limits.max_events) return NGHTTP3_ERR_CALLBACK_FAILURE;
                stream.input.push_back(std::move(chunk));
                return 0;
            }
            return s.push({Event::Kind::body, id, {}, std::move(chunk), 0});
        });
    }
    static int deferred(nghttp3_conn*, std::int64_t id, std::size_t size, void* p, void*) {
        return guard(
            [&] { return self(p).transport.consume(id, size) ? 0 : NGHTTP3_ERR_CALLBACK_FAILURE; });
    }
    static int end(nghttp3_conn*, std::int64_t id, void* p, void*) {
        return guard([&] {
            auto& s = self(p);
            auto& stream = s.streams.at(id);
            stream.remote_end = true;
            if (stream.too_early) return 0;
            return s.push({Event::Kind::end, id, {}, {}, 0});
        });
    }
    bool hidden(std::int64_t id) const {
        const auto it = streams.find(id);
        return it != streams.end() && it->second.too_early;
    }
    static int reset(nghttp3_conn*, std::int64_t id, std::uint64_t code, void* p, void*) {
        return guard([&] {
            auto& s = self(p);
            if (!s.transport.cancel(id, code)) return NGHTTP3_ERR_CALLBACK_FAILURE;
            auto it = s.streams.find(id);
            if (it != s.streams.end()) it->second.error = std::make_error_code(std::errc::connection_reset);
            if (s.hidden(id)) return 0;
            return s.push({Event::Kind::reset, id, {}, {}, code});
        });
    }
    static int shutdown(nghttp3_conn*, std::int64_t id, void* p) {
        return guard([&] {
            auto& s = self(p);
            s.remote_going = true;
            return s.push({Event::Kind::goaway, id, {}, {}, 0});
        });
    }
    static int ack(nghttp3_conn*, std::int64_t id, std::uint64_t bytes, void* p, void*) {
        return guard([&] {
            auto& s = self(p);
            auto it = s.streams.find(id);
            if (it != s.streams.end()) {
                auto& stream = it->second;
                stream.acked += static_cast<std::size_t>(bytes);
                while (!stream.output.empty() && stream.acked >= stream.output.front().size()) {
                    const auto size = stream.output.front().size();
                    if (!stream.offered) return NGHTTP3_ERR_CALLBACK_FAILURE;
                    stream.acked -= size;
                    stream.queued -= size;
                    s.output_bytes -= size;
                    --stream.offered;
                    stream.output.pop_front();
                }
            }
            return 0;
        });
    }
    static int stream_close(nghttp3_conn*, std::int64_t id, std::uint64_t code, void* p, void*) {
        return guard([&] {
            auto& s = self(p);
            s.early_ids.erase(id);
            auto it = s.streams.find(id);
            if (it != s.streams.end()) {
                for (const auto& h : it->second.fields) s.header_bytes -= h.name.size() + h.value.size() + 32;
                it->second.fields.clear();
                s.output_bytes -= it->second.queued;
                it->second.queued = it->second.offered = it->second.acked = 0;
                it->second.output.clear();
                it->second.closed = true;
                if (code != NGHTTP3_H3_NO_ERROR && !it->second.error)
                    it->second.error = std::make_error_code(std::errc::connection_reset);
                if (!it->second.unread && it->second.protocol.empty()) s.streams.erase(it);
            }
            return 0;
        });
    }
    static nghttp3_ssize read_body(nghttp3_conn*,
                                   std::int64_t id,
                                   nghttp3_vec* vec,
                                   std::size_t count,
                                   std::uint32_t* flags,
                                   void* p,
                                   void*) noexcept {
        try {
            auto& stream = self(p).streams.at(id);
            if (count == 0) return NGHTTP3_ERR_CALLBACK_FAILURE;
            if (stream.offered == stream.output.size() && !stream.finished)
                return NGHTTP3_ERR_WOULDBLOCK;
            std::size_t filled = 0;
            while (filled < count && stream.offered < stream.output.size()) {
                auto& chunk = stream.output[stream.offered++];
                vec[filled++] = {reinterpret_cast<std::uint8_t*>(chunk.data()), chunk.size()};
            }
            if (stream.finished && stream.offered == stream.output.size())
                *flags |= NGHTTP3_DATA_FLAG_EOF;
            return static_cast<nghttp3_ssize>(filled);
        } catch (...) {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
    }
    Result<void> check(int rv) {
        if (rv < 0) {
            failed = true;
            return std::unexpected(http3_error(rv));
        }
        return {};
    }
    int new_conn() {
        nghttp3_callbacks cb{};
        cb.begin_headers = begin;
        cb.recv_header = header;
        cb.end_headers = end_headers;
        cb.begin_trailers = begin;
        cb.recv_trailer = header;
        cb.end_trailers = end_headers;
        cb.recv_data = data;
        cb.deferred_consume = deferred;
        cb.end_stream = end;
        cb.stop_sending = reset;
        cb.reset_stream = reset;
        cb.shutdown = shutdown;
        cb.acked_stream_data = ack;
        cb.stream_close = stream_close;
        cb.recv_settings2 = [](nghttp3_conn*, const nghttp3_proto_settings* settings, void* p) {
            self(p).peer_connect = settings->enable_connect_protocol != 0;
            return 0;
        };
        cb.rand = [](std::uint8_t* p, std::size_t n) {
            // The random source comes from the QUIC module; HTTP/3 does not depend on the TLS backend directly.
            if (!quic::fill_random(p, n)) std::terminate();
        };
        nghttp3_settings settings;
        nghttp3_settings_default(&settings);
        // Any change here must be reflected in early_data_context().
        settings.max_field_section_size = limits.max_header_bytes;
        settings.qpack_max_dtable_capacity = qpack_capacity;
        settings.qpack_blocked_streams = qpack_blocked;
        settings.enable_connect_protocol = server && limits.enable_connect_protocol;
        return server ? nghttp3_conn_server_new(&conn, &cb, &settings, nullptr, this)
                      : nghttp3_conn_client_new(&conn, &cb, &settings, nullptr, this);
    }
    Result<void> initialize() {
        if (initialized) return {};
        const bool complete = transport.handshake_complete();
        const auto early = transport.early_data_status();
        // A client with a ticket opens its control/QPACK streams in 0-RTT; a server that accepted
        // 0-RTT opens them for 0.5-RTT. ALPN is only known here once the server has chosen it.
        const bool client_early = !server && !complete && early == quic::EarlyDataStatus::pending;
        const bool server_early = server && !complete && early == quic::EarlyDataStatus::accepted;
        if (!complete && !client_early && !server_early) return {};
        if (!client_early && transport.negotiated_protocol() != "h3") {
            failed = true;
            return std::unexpected(http3_error(invalid));
        }
        const auto open = [&] {
            return client_early ? transport.open_early_stream(true) : transport.open_stream(true);
        };
        auto control = open();
        if (!control) return std::unexpected(control.error());
        auto enc = open();
        if (!enc) return std::unexpected(enc.error());
        auto dec = open();
        if (!dec) return std::unexpected(dec.error());
        if (auto r = check(nghttp3_conn_bind_control_stream(conn, *control)); !r) return r;
        if (auto r = check(nghttp3_conn_bind_qpack_streams(conn, *enc, *dec)); !r) return r;
        initialized = true;
        early_mode = client_early;
        if (server) nghttp3_conn_set_max_client_streams_bidi(conn, transport.remote_bidi_stream_limit());
        return {};
    }
    Result<void> broken(Error error) {
        failed = true;
        return std::unexpected(error);
    }
    // Client, at handshake completion after a 0-RTT attempt.
    Result<void> settle_early() {
        early_mode = false;
        if (transport.negotiated_protocol() != "h3") return broken(http3_error(invalid));
        if (transport.early_data_status() == quic::EarlyDataStatus::accepted) {
            for (auto& [id, stream] : streams) {
                (void)id;
                stream.replay.clear();
            }
            return {};
        }
        // Rejected: ngtcp2 discarded every early stream and stream-ID allocation, and TLS
        // guarantees the server processed none of it. Rebuild HTTP/3 under the server's real
        // SETTINGS and resubmit the safe requests in order, which reproduces their stream IDs.
        struct Replay {
            std::int64_t id;
            Headers fields;
            quic::Bytes body;
        };
        std::vector<Replay> replay;
        for (auto& [id, stream] : streams) {
            if (stream.replay.empty()) continue;
            Replay entry{id, std::move(stream.replay), {}};
            for (auto& chunk : stream.output) entry.body.insert(entry.body.end(), chunk.begin(), chunk.end());
            replay.push_back(std::move(entry));
        }
        streams.clear();
        events.clear();
        early_ids.clear();
        too_early.clear();
        output_bytes = input_bytes = header_bytes = 0;
        peer_connect = remote_going = going = false;
        nghttp3_conn_del(conn);
        conn = nullptr;
        initialized = false;
        if (const int rv = new_conn(); rv) return broken(http3_error(rv));
        if (auto r = initialize(); !r) return broken(r.error());
        for (auto& entry : replay) {
            auto id = transport.open_stream();
            if (!id) return broken(id.error());
            if (*id != entry.id) return broken(http3_error(invalid));
            streams.try_emplace(*id);
            if (auto r = submit(*id, entry.fields, entry.body, false); !r) return broken(r.error());
        }
        return {};
    }
    // Server: 425 for unsafe 0-RTT requests, submitted outside nghttp3 callbacks.
    Result<void> answer_too_early() {
        static const Headers fields{{":status", "425"}, {"content-length", "0"}};
        for (const auto id : std::exchange(too_early, {})) {
            const auto it = streams.find(id);
            if (it == streams.end() || it->second.responded || it->second.closed) continue;
            if (auto r = submit(id, fields, {}, false); !r) return broken(r.error());
        }
        return {};
    }
    Result<void> process(std::uint64_t now) {
        if (failed || now < clock) return std::unexpected(http3_error(invalid));
        clock = now;
        if (early_mode && transport.handshake_complete())
            if (auto r = settle_early(); !r) return r;
        if (auto r = initialize(); !r) return r;
        if (!initialized) return {};
        if (server) nghttp3_conn_set_max_client_streams_bidi(conn, transport.remote_bidi_stream_limit());
        for (auto& event : transport.take_events()) {
            int rv = 0;
            switch (event.kind) {
            case quic::Event::Kind::data: {
                // Client-initiated bidirectional stream data carried in 0-RTT marks its request early.
                if (server && event.early_data && (event.stream_id & 0x3) == 0) {
                    if (!early_ids.contains(event.stream_id) && early_ids.size() >= limits.max_streams)
                        return broken(make_error_code(Errc::limit_exceeded));
                    early_ids.insert(event.stream_id);
                }
                auto n = nghttp3_conn_read_stream2(
                    conn, event.stream_id,
                    reinterpret_cast<const std::uint8_t*>(event.data.data()),
                    event.data.size(), event.fin, now);
                // A negative read_stream2 result is connection-fatal under
                // nghttp3's public contract; no subsequent decoder API is legal.
                if (n < 0) return check(static_cast<int>(n));
                if (n > 0) {
                    auto r = transport.consume(event.stream_id, static_cast<std::size_t>(n));
                    if (!r) {
                        failed = true;
                        return r;
                    }
                }
                break;
            }
            case quic::Event::Kind::acknowledged:
                rv = nghttp3_conn_add_ack_offset(conn, event.stream_id, event.value);
                break;
            case quic::Event::Kind::reset:
                if (auto it = streams.find(event.stream_id); it != streams.end())
                    it->second.error = std::make_error_code(std::errc::connection_reset);
                rv = nghttp3_conn_shutdown_stream_read(conn, event.stream_id);
                if (!hidden(event.stream_id) &&
                    push({Event::Kind::reset, event.stream_id, {}, {}, event.value}))
                    rv = NGHTTP3_ERR_CALLBACK_FAILURE;
                break;
            case quic::Event::Kind::closed:
                rv = nghttp3_conn_close_stream(
                    conn, event.stream_id, event.value ? event.value : NGHTTP3_H3_NO_ERROR);
                if (rv == NGHTTP3_ERR_STREAM_NOT_FOUND) rv = 0;
                break;
            }
            if (auto r = check(rv); !r) return r;
        }
        return answer_too_early();
    }
    Result<void> valid_fields(const Headers& fields, std::span<const std::byte> body, bool streaming,
                              bool request, bool connect_response = false) {
        if (body.size() > limits.max_buffered_body - output_bytes) return fail(Errc::would_block);
        if (fields.size() > limits.max_headers) return fail(Errc::invalid_argument);
        std::size_t size = 0;
        bool regular = false, method = false, scheme = false, path = false, authority = false;
        bool status = false, length = false, forbidden = false, protocol = false, connect = false;
        bool success = false;
        for (auto& [name, value] : fields) {
            if (name.empty() || !nghttp3_check_header_name(reinterpret_cast<const std::uint8_t*>(name.data()),
                                                          name.size()) ||
                !nghttp3_check_header_value(reinterpret_cast<const std::uint8_t*>(value.data()), value.size()))
                return fail(Errc::invalid_argument);
            if (name.size() + value.size() + 32 > limits.max_header_bytes - size)
                return fail(Errc::invalid_argument);
            size += name.size() + value.size() + 32;
            for (char c : name) if (c >= 'A' && c <= 'Z') return fail(Errc::invalid_argument);
            if (name.front() == ':') {
                if (regular || value.empty()) return fail(Errc::invalid_argument);
                bool* seen = nullptr;
                if (request && name == ":method") {
                    seen = &method;
                    connect = value == "CONNECT";
                } else if (request && name == ":protocol") {
                    seen = &protocol;
                    if (!protocol_token(value)) return fail(Errc::invalid_argument);
                } else if (request && name == ":scheme") seen = &scheme;
                else if (request && name == ":path") seen = &path;
                else if (request && name == ":authority") seen = &authority;
                else if (!request && name == ":status") {
                    seen = &status;
                    unsigned code = 0;
                    auto parsed = std::from_chars(value.data(), value.data() + value.size(), code);
                    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
                        value.size() != 3 || code < 200 || code > 599) return fail(Errc::invalid_argument);
                    success = code < 300;
                    forbidden = (code == 204 || code == 304) && !(connect_response && success);
                }
                if (!seen || *seen) return fail(Errc::invalid_argument);
                *seen = true;
            } else {
                regular = true;
                if (name == "connection" || name == "proxy-connection" || name == "keep-alive" ||
                    name == "upgrade" || name == "transfer-encoding" ||
                    (name == "te" && value != "trailers")) return fail(Errc::invalid_argument);
                if (name == "content-length") {
                    std::size_t n = 0;
                    auto parsed = std::from_chars(value.data(), value.data() + value.size(), n);
                    if (length || parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
                        (!streaming && n != body.size())) return fail(Errc::invalid_argument);
                    length = true;
                }
            }
        }
        if ((request ? !(method && scheme && path && authority) : !status) ||
            (request && (connect != protocol || (connect && length))) ||
            (connect_response && success && length) ||
            (forbidden && !body.empty())) return fail(Errc::invalid_argument);
        return {};
    }
    Result<void>
    submit(std::int64_t id, const Headers& fields, std::span<const std::byte> body, bool streaming) {
        auto& stream = streams.at(id);
        stream.streaming = streaming;
        stream.finished = !streaming;
        stream.body_forbidden = server && stream.head;
        for (const auto& [name, value] : fields) {
            if (name == "content-length") {
                std::size_t size = 0;
                std::from_chars(value.data(), value.data() + value.size(), size);
                stream.content_length = size;
            }
            if (name == ":status" && (value == "204" || value == "304") &&
                !(!stream.protocol.empty() && success_status(fields))) stream.body_forbidden = true;
        }
        if (stream.body_forbidden) body = {};
        if (!body.empty() && retained_chunk_count() >= limits.max_events) return fail(Errc::would_block);
        if (!body.empty()) stream.output.emplace_back(body.begin(), body.end());
        stream.queued = stream.produced = body.size();
        output_bytes += body.size();
        std::vector<nghttp3_nv> nv;
        for (auto& [name, value] : fields)
            nv.push_back({reinterpret_cast<std::uint8_t*>(const_cast<char*>(name.data())),
                          reinterpret_cast<std::uint8_t*>(const_cast<char*>(value.data())),
                          name.size(),
                          value.size(),
                          NGHTTP3_NV_FLAG_NONE});
        nghttp3_data_reader reader{read_body};
        int rv =
            server ? nghttp3_conn_submit_response(
                         conn, id, nv.data(), nv.size(), streaming || !body.empty() ? &reader : nullptr)
                   : nghttp3_conn_submit_request(
                         conn, id, nv.data(), nv.size(), streaming || !body.empty() ? &reader : nullptr, nullptr);
        if (rv < 0) {
            output_bytes -= stream.queued;
            stream.queued = 0;
            stream.output.clear();
            if (nghttp3_err_is_fatal(rv)) failed = true;
            return std::unexpected(http3_error(rv));
        }
        if (streaming) {
            // Incremental producers must not serialize later streams behind an unfinished body.
            if (server) {
                nghttp3_pri priority{};
                rv = nghttp3_conn_get_stream_priority(conn, &priority, id);
                if (!rv) {
                    priority.inc = 1;
                    rv = nghttp3_conn_set_server_stream_priority(conn, id, &priority);
                }
            } else {
                const std::uint8_t priority[] = {'i'};
                rv = nghttp3_conn_set_client_stream_priority(conn, id, priority, sizeof(priority));
            }
            if (auto r = check(rv); !r) return r;
        }
        stream.responded = true;
        if (server && !stream.protocol.empty()) stream.accepted = success_status(fields);
        return {};
    }
};
Engine::Engine(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Engine::Engine(Engine&&) noexcept = default;
Engine& Engine::operator=(Engine&&) noexcept = default;
Engine::~Engine() = default;
quic::Engine& Engine::transport() noexcept { return impl_->transport; }
const quic::Engine& Engine::transport() const noexcept { return impl_->transport; }
Result<Engine> Engine::create(quic::Engine transport, bool server, Limits limits) {
    if (transport.is_server() != server || transport.closed())
        return std::unexpected(http3_error(invalid));
    if (!limits.max_streams || limits.max_streams > 4096 || !limits.max_headers ||
        limits.max_headers > 4096 || !limits.max_header_bytes ||
        limits.max_header_bytes > 1024 * 1024 || !limits.max_buffered_body ||
        limits.max_buffered_body > 64 * 1024 * 1024 || !limits.max_events ||
        limits.max_events > 65536)
        return std::unexpected(http3_error(invalid));
    // The ServerContext pins early_data_context for every ticket it issues; a server whose
    // SETTINGS differ from that context could accept 0-RTT sent under incompatible SETTINGS.
    if (server && transport.early_data_policy() != quic::EarlyDataPolicy::disabled &&
        transport.early_data_context() != early_data_context(limits))
        return fail(Errc::invalid_argument);
    auto s = std::make_unique<Impl>(std::move(transport), server, limits);
    if (const int rv = s->new_conn(); rv) return std::unexpected(http3_error(rv));
    if (server) nghttp3_conn_set_max_client_streams_bidi(s->conn, s->transport.remote_bidi_stream_limit());
    // Client with a ticket: 0-RTT control streams. Server that accepted 0-RTT: 0.5-RTT setup.
    if (auto r = s->initialize(); !r) return std::unexpected(r.error());
    return Engine(std::move(s));
}
Result<void> Engine::receive(std::span<const std::byte> packet, std::uint64_t now) {
    if (impl_->failed) return std::unexpected(http3_error(invalid));
    if (auto r = impl_->transport.receive(packet, now); !r) {
        impl_->failed = true;
        return r;
    }
    return impl_->process(now);
}
Result<void> Engine::receive(const quic::Path& path, std::span<const std::byte> packet, std::uint64_t now) {
    if (impl_->failed) return std::unexpected(http3_error(invalid));
    if (auto r = impl_->transport.receive(path, packet, now); !r) {
        impl_->failed = true;
        return r;
    }
    return impl_->process(now);
}
Result<quic::Bytes> Engine::poll(std::uint64_t now) {
    if (impl_->transport.migration_policy() != quic::MigrationPolicy::fixed_peer)
        return fail(Errc::invalid_argument);
    auto result = poll_datagram(now);
    if (!result) return fail(result.error());
    return std::move(result->data);
}
Result<quic::Packet> Engine::poll_datagram(std::uint64_t now) {
    auto& s = *impl_;
    if (auto r = s.process(now); !r) return std::unexpected(r.error());
    if (s.initialized) {
        for (int k = 0; k < 16; ++k) {
            const auto capacity = std::min(std::size_t{16384}, s.transport.write_capacity());
            if (!capacity) break;
            std::array<nghttp3_vec, 16> vec{};
            std::int64_t id = -1;
            int fin = 0;
            auto n = nghttp3_conn_writev_stream(s.conn, &id, &fin, vec.data(), vec.size());
            if (n < 0) {
                s.failed = true;
                return std::unexpected(http3_error(static_cast<int>(n)));
            }
            if (id == -1) break;
            quic::Bytes bytes;
            std::size_t available = 0;
            for (nghttp3_ssize i = 0; i < n; ++i) {
                auto& part = vec[static_cast<std::size_t>(i)];
                available += part.len;
                auto count = std::min(part.len, capacity - bytes.size());
                if (count) bytes.insert(bytes.end(),
                                         reinterpret_cast<const std::byte*>(part.base),
                                         reinterpret_cast<const std::byte*>(part.base) + count);
            }
            const std::span<const std::byte> view{bytes.data(), bytes.size()};
            const bool last = fin != 0 && bytes.size() == available;
            auto r = s.early_mode ? s.transport.write_early(id, view, last)
                                  : s.transport.write(id, view, last);
            if (!r) {
                // -100001 is the QUIC engine's send-budget backpressure: pause output this round and retry on the next poll.
                if (r.error() == Errc::would_block || r.error().value() == -100001) break;
                s.failed = true;
                return std::unexpected(r.error());
            }
            if (auto r2 = s.check(nghttp3_conn_add_write_offset(s.conn, id, bytes.size())); !r2)
                return std::unexpected(r2.error());
        }
    }
    auto packet = s.transport.poll_datagram(now);
    if (!packet) s.failed = true;
    return packet;
}
Result<void> Engine::handle_expiry(std::uint64_t now) {
    if (impl_->failed) return std::unexpected(http3_error(invalid));
    if (auto r = impl_->transport.handle_expiry(now); !r) {
        impl_->failed = true;
        return r;
    }
    return impl_->process(now);
}
std::uint64_t Engine::expiry() const noexcept {
    return impl_->transport.expiry();
}
bool Engine::ready() const noexcept {
    return impl_->initialized && !impl_->failed && !impl_->early_mode;
}
bool Engine::early_ready() const noexcept {
    return impl_->initialized && !impl_->failed && impl_->early_mode;
}
bool Engine::closed() const noexcept {
    return impl_->transport.closed() || impl_->failed;
}
bool Engine::peer_goaway() const noexcept {
    return impl_->remote_going;
}
bool Engine::is_server() const noexcept {
    return impl_->server;
}
Result<std::int64_t> Engine::request(const Headers& fields, std::span<const std::byte> body) {
    return request_impl(fields, body, false);
}
Result<std::int64_t> Engine::request_stream(const Headers& fields) {
    return request_impl(fields, {}, true);
}
Result<std::int64_t> Engine::request_impl(const Headers& fields, std::span<const std::byte> body,
                                         bool streaming) {
    auto& s = *impl_;
    const bool early = early_ready();
    if (!(ready() || early) || s.server || s.going || s.remote_going ||
        s.streams.size() >= s.limits.max_streams)
        return std::unexpected(http3_error(invalid));
    if (auto r = s.valid_fields(fields, body, streaming, true); !r) return std::unexpected(r.error());
    const auto protocol = field(fields, ":protocol");
    if (!protocol.empty() && (!streaming || !s.peer_connect)) return fail(Errc::not_supported);
    if (early && (streaming || !early_safe(field(fields, ":method")))) return fail(Errc::not_supported);
    auto id = early ? s.transport.open_early_stream() : s.transport.open_stream();
    if (!id) return std::unexpected(id.error());
    auto& stream = s.streams.try_emplace(*id).first->second;
    stream.protocol = protocol;
    stream.early = early;
    if (early) stream.replay = fields;
    if (auto r = s.submit(*id, fields, body, streaming); !r) {
        s.streams.erase(*id);
        static_cast<void>(s.transport.cancel(*id, NGHTTP3_H3_REQUEST_CANCELLED));
        return std::unexpected(r.error());
    }
    return *id;
}
Result<void>
Engine::respond(std::int64_t id, const Headers& fields, std::span<const std::byte> body) {
    return respond_impl(id, fields, body, false);
}
Result<void> Engine::respond_stream(std::int64_t id, const Headers& fields) {
    return respond_impl(id, fields, {}, true);
}
Result<void> Engine::respond_impl(std::int64_t id, const Headers& fields,
                                 std::span<const std::byte> body, bool streaming) {
    auto& s = *impl_;
    auto it = s.streams.find(id);
    if (!ready() || !s.server || it == s.streams.end() || it->second.responded || it->second.closed ||
        it->second.error || !it->second.headers_received)
        return std::unexpected(http3_error(invalid));
    const bool connect = !it->second.protocol.empty();
    if (connect && field(fields, ":status") == "204") return fail(Errc::not_supported);
    if (auto r = s.valid_fields(fields, body, streaming, false, connect); !r) return r;
    if (connect && success_status(fields) && !streaming) return fail(Errc::invalid_argument);
    return s.submit(id, fields, body, streaming);
}
Result<void> Engine::write_body(std::int64_t id, std::span<const std::byte> body, bool end) {
    auto& s = *impl_;
    auto it = s.streams.find(id);
    if (!ready() || it == s.streams.end()) return fail(Errc::invalid_argument);
    auto& stream = it->second;
    if (!stream.streaming || !stream.responded || stream.closed || stream.finished || stream.error ||
        (stream.body_forbidden && !body.empty())) return fail(Errc::invalid_argument);
    if (stream.content_length && !stream.body_forbidden &&
        (body.size() > *stream.content_length - stream.produced ||
         (end && stream.produced + body.size() != *stream.content_length))) return fail(Errc::invalid_argument);
    if (body.size() > s.limits.max_buffered_body - s.output_bytes ||
        (!body.empty() && s.retained_chunk_count() >= s.limits.max_events)) return fail(Errc::would_block);
    if (body.empty() && !end) return {};
    if (!body.empty()) stream.output.emplace_back(body.begin(), body.end());
    const int rv = nghttp3_conn_resume_stream(s.conn, id);
    if (rv < 0) {
        if (!body.empty()) stream.output.pop_back();
        if (nghttp3_err_is_fatal(rv)) s.failed = true;
        return std::unexpected(http3_error(rv));
    }
    stream.queued += body.size();
    s.output_bytes += body.size();
    if (stream.protocol.empty()) stream.produced += body.size();
    stream.finished = end;
    return {};
}
Result<void> Engine::finish_body(std::int64_t id) { return write_body(id, {}, true); }
std::size_t Engine::queued_body_bytes() const noexcept { return impl_->output_bytes; }
bool Engine::peer_connect_protocol_enabled() const noexcept { return impl_->peer_connect; }
bool Engine::local_connect_protocol_enabled() const noexcept {
    return impl_->server && impl_->initialized && impl_->limits.enable_connect_protocol;
}
Result<ConnectState> Engine::connect_state(std::int64_t id) const {
    const auto it = impl_->streams.find(id);
    if (it == impl_->streams.end() || it->second.protocol.empty()) return fail(Errc::invalid_argument);
    const auto& stream = it->second;
    return ConnectState{stream.protocol, stream.accepted, stream.finished, stream.remote_end,
                        stream.closed, stream.error};
}
Result<std::size_t> Engine::read_connect(std::int64_t id, std::span<std::byte> destination) {
    auto state = connect_state(id);
    if (!state) return fail(state.error());
    if (closed()) return fail(Errc::eof);
    if (state->error) return fail(state->error);
    if (!state->accepted) return fail(Errc::not_supported);
    if (destination.empty()) return std::size_t{0};
    auto& stream = impl_->streams.at(id);
    if (stream.input.empty()) return fail(state->remote_end ? Errc::eof : Errc::would_block);
    auto& chunk = stream.input.front();
    const auto count = std::min(destination.size(), chunk.size() - stream.input_offset);
    if (auto credit = consume(id, count); !credit) return fail(credit.error());
    std::copy_n(chunk.begin() + static_cast<std::ptrdiff_t>(stream.input_offset), count, destination.begin());
    stream.input_offset += count;
    if (stream.input_offset == chunk.size()) { stream.input.pop_front(); stream.input_offset = 0; }
    return count;
}
Result<std::size_t> Engine::write_connect(std::int64_t id, std::span<const std::byte> source) {
    auto state = connect_state(id);
    if (!state) return fail(state.error());
    if (state->error) return fail(state->error);
    if (!state->accepted || state->closed || state->local_end) return fail(Errc::invalid_argument);
    const auto count = std::min(source.size(), impl_->limits.max_buffered_body);
    if (auto result = write_body(id, source.first(count)); !result) return fail(result.error());
    return count;
}
Result<void> Engine::release_connect(std::int64_t id) {
    auto& s = *impl_;
    const auto it = s.streams.find(id);
    if (it == s.streams.end() || it->second.protocol.empty() || !it->second.closed)
        return fail(Errc::invalid_argument);
    if (it->second.unread) {
        if (auto credit = consume(id, it->second.unread); !credit) return credit;
    }
    s.streams.erase(id);
    return {};
}

std::vector<Event> Engine::take_events() {
    std::vector<Event> result;
    result.swap(impl_->events);
    for (auto& event : result)
        for (auto& [name, value] : event.fields)
            impl_->header_bytes -= name.size() + value.size() + 32;
    return result;
}
Result<void> Engine::consume(std::int64_t id, std::size_t bytes) {
    auto& s = *impl_;
    auto it = s.streams.find(id);
    if (s.failed)
        return std::unexpected(http3_error(invalid));
    // A fin chunk carries no bytes; by the time the application consumes it
    // the stream record may already have been erased (closed and fully
    // consumed). Consuming nothing from a finished stream is not an error.
    if (it == s.streams.end())
        return bytes == 0 ? Result<void>{} : std::unexpected(http3_error(invalid));
    if (bytes > it->second.unread)
        return std::unexpected(http3_error(invalid));
    if (auto r = s.transport.consume(id, bytes); !r) return r;
    it->second.unread -= bytes;
    s.input_bytes -= bytes;
    if (it->second.closed && !it->second.unread && it->second.protocol.empty()) s.streams.erase(it);
    return {};
}
Result<void> Engine::cancel(std::int64_t id) {
    auto& s = *impl_;
    if (!ready()) return std::unexpected(http3_error(invalid));
    if (id < 0 || id >= (std::int64_t{1} << 62) || id % 4 != 0 ||
        !s.streams.contains(id) || s.streams.at(id).closed)
        return std::unexpected(http3_error(invalid));
    s.streams.at(id).error = make_error_code(Errc::cancelled);
    nghttp3_conn_shutdown_stream_write(s.conn, id);
    if (auto r = s.check(nghttp3_conn_shutdown_stream_read(s.conn, id)); !r) return r;
    if (auto r = s.transport.cancel(id, NGHTTP3_H3_REQUEST_CANCELLED); !r) return r;
    const int rv = nghttp3_conn_close_stream(s.conn, id, NGHTTP3_H3_REQUEST_CANCELLED);
    if (rv != NGHTTP3_ERR_STREAM_NOT_FOUND) return s.check(rv);
    return {};
}
Result<void> Engine::shutdown_notice() {
    auto& s = *impl_;
    if (!ready()) return std::unexpected(http3_error(invalid));
    if (s.final_goaway) return std::unexpected(http3_error(invalid));
    if (s.going) return {};
    s.going = true;
    return s.check(nghttp3_conn_submit_shutdown_notice(s.conn));
}
Result<void> Engine::shutdown() {
    auto& s = *impl_;
    if (!ready() || !s.going) return std::unexpected(http3_error(invalid));
    if (s.final_goaway) return {};
    if (auto r = s.check(nghttp3_conn_shutdown(s.conn)); !r) return r;
    s.final_goaway = true;
    return {};
}
Result<quic::Bytes> Engine::close(std::uint64_t code, std::uint64_t now) {
    impl_->failed = true;
    return impl_->transport.close(code, now);
}
Result<quic::Packet> Engine::close_datagram(std::uint64_t code, std::uint64_t now) {
    impl_->failed = true;
    return impl_->transport.close_datagram(code, now);
}
}  // namespace Mira::http3
