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

namespace Mira::http3 {
namespace {
// Engine-owned error codes, placed far away from the native nghttp3 negative-code range to avoid clashing with the dependency.
constexpr int invalid = -110000;

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
struct Engine::Impl {
    quic::Engine transport;
    bool server;
    Limits limits;
    nghttp3_conn* conn = nullptr;
    bool failed = false, initialized = false, going = false, remote_going = false;
    bool final_goaway = false;
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
    static int end_headers(nghttp3_conn*, std::int64_t id, int, void* p, void*) {
        return guard([&] {
            auto& s = self(p);
            return s.push({Event::Kind::headers, id, std::move(s.streams.at(id).fields), {}, 0});
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
            s.streams.at(id).unread += size;
            s.input_bytes += size;
            // nghttp3 hands us `const uint8_t*`; converting at the boundary.
            return s.push({Event::Kind::body, id, {},
                           quic::Bytes(reinterpret_cast<const std::byte*>(bytes),
                                       reinterpret_cast<const std::byte*>(bytes) + size),
                           0});
        });
    }
    static int deferred(nghttp3_conn*, std::int64_t id, std::size_t size, void* p, void*) {
        return guard(
            [&] { return self(p).transport.consume(id, size) ? 0 : NGHTTP3_ERR_CALLBACK_FAILURE; });
    }
    static int end(nghttp3_conn*, std::int64_t id, void* p, void*) {
        return guard([&] { return self(p).push({Event::Kind::end, id, {}, {}, 0}); });
    }
    static int reset(nghttp3_conn*, std::int64_t id, std::uint64_t code, void* p, void*) {
        return guard([&] {
            auto& s = self(p);
            if (!s.transport.cancel(id, code)) return NGHTTP3_ERR_CALLBACK_FAILURE;
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
    static int stream_close(nghttp3_conn*, std::int64_t id, std::uint64_t, void* p, void*) {
        return guard([&] {
            auto& s = self(p);
            auto it = s.streams.find(id);
            if (it != s.streams.end()) {
                s.output_bytes -= it->second.queued;
                it->second.queued = it->second.offered = it->second.acked = 0;
                it->second.output.clear();
                it->second.closed = true;
                if (!it->second.unread) s.streams.erase(it);
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
    Result<void> initialize() {
        if (initialized || !transport.handshake_complete()) return {};
        if (transport.negotiated_protocol() != "h3") {
            failed = true;
            return std::unexpected(http3_error(invalid));
        }
        auto control = transport.open_stream(true);
        if (!control) return std::unexpected(control.error());
        auto enc = transport.open_stream(true);
        if (!enc) return std::unexpected(enc.error());
        auto dec = transport.open_stream(true);
        if (!dec) return std::unexpected(dec.error());
        if (auto r = check(nghttp3_conn_bind_control_stream(conn, *control)); !r) return r;
        if (auto r = check(nghttp3_conn_bind_qpack_streams(conn, *enc, *dec)); !r) return r;
        initialized = true;
        return {};
    }
    Result<void> process(std::uint64_t now) {
        if (failed || now < clock) return std::unexpected(http3_error(invalid));
        clock = now;
        if (auto r = initialize(); !r) return r;
        if (!initialized) return {};
        if (server) nghttp3_conn_set_max_client_streams_bidi(conn, transport.remote_bidi_stream_limit());
        for (auto& event : transport.take_events()) {
            int rv = 0;
            switch (event.kind) {
            case quic::Event::Kind::data: {
                auto n = nghttp3_conn_read_stream2(
                    conn, event.stream_id,
                    reinterpret_cast<const std::uint8_t*>(event.data.data()),
                    event.data.size(), event.fin, now);
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
                rv = nghttp3_conn_shutdown_stream_read(conn, event.stream_id);
                if (push({Event::Kind::reset, event.stream_id, {}, {}, event.value}))
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
        return {};
    }
    Result<void> valid_fields(const Headers& fields, std::span<const std::byte> body, bool streaming) {
        if (body.size() > limits.max_buffered_body - output_bytes) return fail(Errc::would_block);
        if (fields.size() > limits.max_headers) return fail(Errc::invalid_argument);
        std::size_t size = 0;
        bool regular = false, method = false, scheme = false, path = false, authority = false;
        bool status = false, length = false, forbidden = false;
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
                if (!server && name == ":method") {
                    seen = &method;
                    if (value == "CONNECT") return fail(Errc::invalid_argument);
                } else if (!server && name == ":scheme") seen = &scheme;
                else if (!server && name == ":path") seen = &path;
                else if (!server && name == ":authority") seen = &authority;
                else if (server && name == ":status") {
                    seen = &status;
                    unsigned code = 0;
                    auto parsed = std::from_chars(value.data(), value.data() + value.size(), code);
                    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
                        value.size() != 3 || code < 200 || code > 599) return fail(Errc::invalid_argument);
                    forbidden = code == 204 || code == 304;
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
        if ((server ? !status : !(method && scheme && path && authority)) ||
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
            if (name == ":status" && (value == "204" || value == "304")) stream.body_forbidden = true;
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
    auto s = std::make_unique<Impl>(std::move(transport), server, limits);
    nghttp3_callbacks cb{};
    cb.begin_headers = Impl::begin;
    cb.recv_header = Impl::header;
    cb.end_headers = Impl::end_headers;
    cb.begin_trailers = Impl::begin;
    cb.recv_trailer = Impl::header;
    cb.end_trailers = Impl::end_headers;
    cb.recv_data = Impl::data;
    cb.deferred_consume = Impl::deferred;
    cb.end_stream = Impl::end;
    cb.stop_sending = Impl::reset;
    cb.reset_stream = Impl::reset;
    cb.shutdown = Impl::shutdown;
    cb.acked_stream_data = Impl::ack;
    cb.stream_close = Impl::stream_close;
    cb.rand = [](std::uint8_t* p, std::size_t n) {
        // The random source comes from the QUIC module; HTTP/3 does not depend on the TLS backend directly.
        if (!quic::fill_random(p, n)) std::terminate();
    };
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.max_field_section_size = limits.max_header_bytes;
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams = 16;
    int rv = server ? nghttp3_conn_server_new(&s->conn, &cb, &settings, nullptr, s.get())
                    : nghttp3_conn_client_new(&s->conn, &cb, &settings, nullptr, s.get());
    if (rv) return std::unexpected(http3_error(rv));
    if (server) nghttp3_conn_set_max_client_streams_bidi(s->conn, s->transport.remote_bidi_stream_limit());
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
Result<quic::Bytes> Engine::poll(std::uint64_t now) {
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
            auto r = s.transport.write(
                id,
                std::span<const std::byte>{bytes.data(), bytes.size()},
                fin != 0 && bytes.size() == available);
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
    auto packet = s.transport.poll(now);
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
    return impl_->initialized && !impl_->failed;
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
    if (!ready() || s.server || s.going || s.remote_going ||
        s.streams.size() >= s.limits.max_streams)
        return std::unexpected(http3_error(invalid));
    if (auto r = s.valid_fields(fields, body, streaming); !r) return std::unexpected(r.error());
    auto id = s.transport.open_stream();
    if (!id) return std::unexpected(id.error());
    s.streams.try_emplace(*id);
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
    if (!ready() || !s.server || it == s.streams.end() || it->second.responded || it->second.closed)
        return std::unexpected(http3_error(invalid));
    if (auto r = s.valid_fields(fields, body, streaming); !r) return r;
    return s.submit(id, fields, body, streaming);
}
Result<void> Engine::write_body(std::int64_t id, std::span<const std::byte> body, bool end) {
    auto& s = *impl_;
    auto it = s.streams.find(id);
    if (!ready() || it == s.streams.end()) return fail(Errc::invalid_argument);
    auto& stream = it->second;
    if (!stream.streaming || !stream.responded || stream.closed || stream.finished ||
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
    stream.produced += body.size();
    stream.finished = end;
    return {};
}
Result<void> Engine::finish_body(std::int64_t id) { return write_body(id, {}, true); }
std::size_t Engine::queued_body_bytes() const noexcept { return impl_->output_bytes; }

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
    if (it->second.closed && !it->second.unread) s.streams.erase(it);
    return {};
}
Result<void> Engine::cancel(std::int64_t id) {
    auto& s = *impl_;
    if (!ready()) return std::unexpected(http3_error(invalid));
    if (id < 0 || id >= (std::int64_t{1} << 62) || id % 4 != 0 ||
        !s.streams.contains(id) || s.streams.at(id).closed)
        return std::unexpected(http3_error(invalid));
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
}  // namespace Mira::http3
