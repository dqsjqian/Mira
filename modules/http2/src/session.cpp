#include "mira/http2/session.hpp"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <deque>
#include <optional>
#include <limits>
#include <map>
#include <new>
#include <string_view>
#include <utility>

namespace Mira::http2 {
namespace {
class EngineCategory final : public std::error_category {
public:
    const char* name() const noexcept override { return "Mira.http2"; }
    std::string message(int value) const override { return nghttp2_strerror(value); }
};

std::string_view field(const Headers& headers, std::string_view name) {
    for (const auto& h : headers) if (h.name == name) return h.value;
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

bool success_status(const Headers& headers) {
    const auto value = field(headers, ":status");
    return value.size() == 3 && value.front() == '2';
}

bool valid_headers(const Headers& headers, bool request, std::optional<std::size_t> body_size,
                   const Limits& limits, bool connect_response = false) {
    std::size_t bytes = 0;
    bool regular = false;
    bool method = false, scheme = false, path = false, authority = false, status = false;
    bool length = false, protocol = false, connect = false;
    unsigned response_status = 0;
    if (headers.size() > limits.max_headers) return false;
    for (const auto& h : headers) {
        if (h.name.empty() || h.name.size() > limits.max_header_bytes - bytes) return false;
        bytes += h.name.size();
        if (h.value.size() > limits.max_header_bytes - bytes) return false;
        bytes += h.value.size();
        const auto* name = reinterpret_cast<const std::uint8_t*>(h.name.data());
        const auto* value = reinterpret_cast<const std::uint8_t*>(h.value.data());
        if (!nghttp2_check_header_name(name, h.name.size()) ||
            !nghttp2_check_header_value_rfc9113(value, h.value.size())) return false;
        for (const char c : h.name) if (c >= 'A' && c <= 'Z') return false;
        if (h.name.front() == ':') {
            if (regular || h.value.empty()) return false;
            bool* seen = nullptr;
            if (request && h.name == ":method") {
                seen = &method;
                connect = h.value == "CONNECT";
            } else if (request && h.name == ":protocol") {
                seen = &protocol;
                if (!protocol_token(h.value)) return false;
            } else if (request && h.name == ":scheme") seen = &scheme;
            else if (request && h.name == ":path") seen = &path;
            else if (request && h.name == ":authority") seen = &authority;
            else if (!request && h.name == ":status") {
                seen = &status;
                auto result = std::from_chars(h.value.data(), h.value.data() + h.value.size(), response_status);
                if (result.ec != std::errc{} || result.ptr != h.value.data() + h.value.size() ||
                    h.value.size() != 3 || response_status < 200 || response_status > 599) return false;
            }
            if (!seen || *seen) return false;
            *seen = true;
        } else {
            regular = true;
            if (h.name == "connection" || h.name == "proxy-connection" || h.name == "keep-alive" ||
                h.name == "upgrade" || h.name == "transfer-encoding" ||
                (h.name == "te" && h.value != "trailers")) return false;
            if (h.name == "content-length") {
                std::size_t size = 0;
                auto result = std::from_chars(h.value.data(), h.value.data() + h.value.size(), size);
                if (length || result.ec != std::errc{} || result.ptr != h.value.data() + h.value.size() ||
                    (body_size && size != *body_size)) return false;
                length = true;
            }
        }
    }
    if (request && (connect != protocol || (connect && length))) return false;
    if (connect_response && response_status >= 200 && response_status < 300 && length) return false;
    if (!request && !(connect_response && response_status < 300) &&
        (response_status == 204 || response_status == 304) && body_size && *body_size != 0) return false;
    return request ? method && scheme && path && authority : status;
}

std::vector<nghttp2_nv> nv_headers(const Headers& headers) {
    std::vector<nghttp2_nv> result;
    result.reserve(headers.size());
    for (const auto& h : headers) {
        result.push_back({reinterpret_cast<std::uint8_t*>(const_cast<char*>(h.name.data())),
                          reinterpret_cast<std::uint8_t*>(const_cast<char*>(h.value.data())),
                          h.name.size(), h.value.size(), NGHTTP2_NV_FLAG_NONE});
    }
    return result;
}
} // namespace

Error engine_error(int code) noexcept {
    static EngineCategory category;
    return {code, category};
}

struct Session::Impl {
    ResourceBudget::Reservation reservation;
    struct Entry {
        Stream visible;
        Headers block;
        std::size_t header_bytes = 0;
        std::size_t received_bytes = 0;
        std::deque<std::vector<std::byte>> outgoing;
        std::size_t front_offset = 0, queued = 0, produced = 0;
        std::optional<std::size_t> content_length;
        bool streaming = false, finished = false, deferred = false, body_forbidden = false;
        bool responded = false;
        bool head = false;
        std::string protocol;
        bool accepted = false;
    };
    nghttp2_session* session = nullptr;
    Role role;
    Limits limits;
    State state = State::open;
    Error error;
    std::map<std::int32_t, Entry> entries;
    std::size_t queued_bodies = 0;
    std::size_t retained_chunk_count() const {
        std::size_t total = 0;
        for (const auto& [id, entry] : entries) { (void)id; total += entry.outgoing.size(); }
        return total;
    }
    std::vector<std::byte> wire;
    std::int32_t last_peer_stream = 0;
    std::int32_t peer_last = std::numeric_limits<std::int32_t>::max();
    std::uint32_t peer_error = 0;
    bool local_goaway = false;
    bool connect_advertised = false;

    Impl(Role r, Limits l) : role(r), limits(l) {}
    ~Impl() { nghttp2_session_del(session); }
    void fail_connection(Error reason) {
        error = reason;
        state = State::failed;
        for (auto& [id, entry] : entries) {
            static_cast<void>(id);
            discard_output(entry);
            if (!entry.visible.closed) {
                entry.visible.closed = true;
                entry.visible.error = reason;
            }
        }
    }
    void discard_output(Entry& e) {
        queued_bodies -= e.queued;
        e.queued = 0;
        e.front_offset = 0;
        e.outgoing.clear();
    }
    static void body_metadata(Entry& e, const Headers& headers) {
        for (const auto& h : headers) {
            if (h.name == "content-length") {
                std::size_t size = 0;
                std::from_chars(h.value.data(), h.value.data() + h.value.size(), size);
                e.content_length = size;
            }
            if (h.name == ":status" && (h.value == "204" || h.value == "304"))
                e.body_forbidden = true;
        }
    }
    int reset(std::int32_t id, Error reason, std::uint32_t wire_code) {
        if (nghttp2_session_get_outbound_queue_size(session) >= limits.max_queued_frames) {
            error = make_error_code(Errc::limit_exceeded);
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        auto it = entries.find(id);
        if (it != entries.end()) {
            it->second.visible.error = reason;
            it->second.visible.wire_error = wire_code;
        }
        return nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, id, wire_code);
    }
    template<typename F> static int guarded(void* user, F&& fn) noexcept {
        try { return fn(*static_cast<Impl*>(user)); }
        catch (...) {
            static_cast<Impl*>(user)->error = std::make_error_code(std::errc::not_enough_memory);
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    static nghttp2_ssize send(nghttp2_session*, const std::uint8_t* data, std::size_t size,
                             int, void* user) noexcept {
        auto& self = *static_cast<Impl*>(user);
        const auto count = std::min(size, self.limits.max_output_bytes - self.wire.size());
        if (count == 0) return NGHTTP2_ERR_WOULDBLOCK;
        try {
            auto bytes = reinterpret_cast<const std::byte*>(data);
            self.wire.insert(self.wire.end(), bytes, bytes + count);
            return static_cast<nghttp2_ssize>(count);
        } catch (...) { return NGHTTP2_ERR_CALLBACK_FAILURE; }
    }
    static int begin(nghttp2_session*, const nghttp2_frame* frame, void* user) noexcept {
        return guarded(user, [&](Impl& self) -> int {
            const auto id = frame->hd.stream_id;
            if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
                if (self.state != State::open || self.entries.size() >= self.limits.max_streams) {
                    return self.reset(id, make_error_code(Errc::limit_exceeded), NGHTTP2_REFUSED_STREAM);
                }
                self.entries.try_emplace(id).first->second.visible.id = id;
                self.last_peer_stream = id;
            }
            auto it = self.entries.find(id);
            if (it != self.entries.end()) it->second.block.clear();
            return 0;
        });
    }
    static int header(nghttp2_session*, const nghttp2_frame* frame, const std::uint8_t* name,
                      std::size_t namelen, const std::uint8_t* value, std::size_t valuelen,
                      std::uint8_t, void* user) noexcept {
        return guarded(user, [&](Impl& self) -> int {
            auto it = self.entries.find(frame->hd.stream_id);
            if (it == self.entries.end() || it->second.visible.error) return 0;
            auto& e = it->second;
            if (e.block.size() + e.visible.headers.size() + e.visible.trailers.size() >= self.limits.max_headers ||
                namelen > self.limits.max_header_bytes - e.header_bytes ||
                valuelen > self.limits.max_header_bytes - e.header_bytes - namelen) {
                return self.reset(frame->hd.stream_id, make_error_code(Errc::limit_exceeded), NGHTTP2_ENHANCE_YOUR_CALM);
            }
            e.header_bytes += namelen + valuelen;
            e.block.push_back({std::string(reinterpret_cast<const char*>(name), namelen),
                               std::string(reinterpret_cast<const char*>(value), valuelen)});
            return 0;
        });
    }
    static int frame_received(nghttp2_session*, const nghttp2_frame* frame, void* user) noexcept {
        return guarded(user, [&](Impl& self) -> int {
            if (nghttp2_session_get_outbound_queue_size(self.session) > self.limits.max_queued_frames) {
                self.error = make_error_code(Errc::limit_exceeded);
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            if (frame->hd.type == NGHTTP2_GOAWAY) {
                self.state = State::draining;
                self.peer_last = frame->goaway.last_stream_id;
                self.peer_error = frame->goaway.error_code;
            }
            auto it = self.entries.find(frame->hd.stream_id);
            if (it == self.entries.end()) return 0;
            auto& e = it->second;
            if (frame->hd.type == NGHTTP2_HEADERS && !e.visible.error) {
                bool informational = false;
                for (const auto& h : e.block) {
                    if (h.name == ":status" && h.value.size() == 3 && h.value.front() == '1') informational = true;
                    if (h.name == ":method") {
                        e.head = h.value == "HEAD";
                    }
                }
                if (!informational && !e.visible.headers_received) {
                    if (self.role == Role::server && field(e.block, ":method") == "CONNECT") {
                        if (!self.connect_advertised || !valid_headers(e.block, true, std::nullopt, self.limits))
                            return self.reset(e.visible.id, make_error_code(Errc::invalid_argument), NGHTTP2_PROTOCOL_ERROR);
                        e.protocol = field(e.block, ":protocol");
                    } else if (self.role == Role::client && !e.protocol.empty()) {
                        if (!valid_headers(e.block, false, std::nullopt, self.limits, true))
                            return self.reset(e.visible.id, make_error_code(Errc::invalid_argument), NGHTTP2_PROTOCOL_ERROR);
                        if (field(e.block, ":status") == "204")
                            return self.reset(e.visible.id, make_error_code(Errc::not_supported), NGHTTP2_CANCEL);
                        e.accepted = success_status(e.block);
                    }
                }
                if (!informational) {
                    if (e.visible.headers_received) e.visible.trailers = std::move(e.block);
                    else {
                        e.visible.headers = std::move(e.block);
                        e.visible.headers_received = true;
                    }
                }
            }
            if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
                (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) e.visible.remote_end = true;
            return 0;
        });
    }
    static int invalid_frame(nghttp2_session*, const nghttp2_frame* frame, int code, void* user) noexcept {
        return guarded(user, [&](Impl& self) -> int {
            auto it = self.entries.find(frame->hd.stream_id);
            if (it != self.entries.end()) it->second.visible.error = engine_error(code);
            if (frame->hd.stream_id == 0) {
                self.error = engine_error(code);
                self.state = State::draining;
            }
            return 0;
        });
    }
    static int frame_not_sent(nghttp2_session*, const nghttp2_frame* frame, int code, void* user) noexcept {
        auto& self = *static_cast<Impl*>(user);
        auto it = self.entries.find(frame->hd.stream_id);
        if (it != self.entries.end() && !it->second.visible.error)
            it->second.visible.error = engine_error(code);
        return 0;
    }
    static int frame_sent(nghttp2_session*, const nghttp2_frame* frame, void* user) noexcept {
        auto& self = *static_cast<Impl*>(user);
        if (frame->hd.type == NGHTTP2_SETTINGS && !(frame->hd.flags & NGHTTP2_FLAG_ACK)) {
            for (std::size_t i = 0; i < frame->settings.niv; ++i)
                if (frame->settings.iv[i].settings_id == NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL &&
                    frame->settings.iv[i].value == 1) self.connect_advertised = true;
        }
        if (frame->hd.type == NGHTTP2_GOAWAY) {
            self.state = State::draining;
            if (frame->goaway.error_code != NGHTTP2_NO_ERROR && !self.error)
                self.error = engine_error(NGHTTP2_ERR_PROTO);
        }
        return 0;
    }
    static int data(nghttp2_session*, std::uint8_t, std::int32_t id,
                    const std::uint8_t* bytes, std::size_t size, void* user) noexcept {
        return guarded(user, [&](Impl& self) -> int {
            auto it = self.entries.find(id);
            if (it == self.entries.end() || it->second.visible.error) {
                return nghttp2_session_consume_connection(self.session, size);
            }
            auto& e = it->second;
            const auto retained = e.protocol.empty() ? e.received_bytes : e.visible.body.size();
            if (size > self.limits.max_body_bytes - retained) {
                int result = nghttp2_session_consume_connection(self.session, size);
                if (result != 0) return result;
                return self.reset(id, make_error_code(Errc::limit_exceeded), NGHTTP2_ENHANCE_YOUR_CALM);
            }
            if (e.protocol.empty()) e.received_bytes += size;
            const auto* first = reinterpret_cast<const std::byte*>(bytes);
            e.visible.body.insert(e.visible.body.end(), first, first + size);
            return 0;
        });
    }
    static int stream_closed(nghttp2_session*, std::int32_t id, std::uint32_t code, void* user) noexcept {
        return guarded(user, [&](Impl& self) -> int {
            auto it = self.entries.find(id);
            if (it == self.entries.end()) return 0;
            auto& e = it->second;
            e.visible.closed = true;
            e.visible.wire_error = code;
            if (code != NGHTTP2_NO_ERROR && !e.visible.error) {
                e.visible.error = code == NGHTTP2_CANCEL ? make_error_code(Errc::cancelled)
                                                       : engine_error(NGHTTP2_ERR_STREAM_CLOSED);
            }
            self.discard_output(e);
            return 0;
        });
    }
    static nghttp2_ssize read_data(nghttp2_session*, std::int32_t, std::uint8_t* bytes,
                                  std::size_t size, std::uint32_t* flags,
                                  nghttp2_data_source* source, void* user) noexcept {
        auto& self = *static_cast<Impl*>(user);
        auto& e = *static_cast<Entry*>(source->ptr);
        if (e.visible.error) return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        if (e.outgoing.empty() && !e.finished) {
            e.deferred = true;
            return NGHTTP2_ERR_DEFERRED;
        }
        std::size_t count = 0;
        while (count < size && !e.outgoing.empty()) {
            auto& chunk = e.outgoing.front();
            const auto n = std::min(size - count, chunk.size() - e.front_offset);
            std::memcpy(bytes + count, chunk.data() + e.front_offset, n);
            count += n;
            e.front_offset += n;
            if (e.front_offset == chunk.size()) {
                // Keep the allocation charged until the entire chunk can be freed.
                self.queued_bodies -= chunk.size();
                e.queued -= chunk.size();
                e.outgoing.pop_front();
                e.front_offset = 0;
            }
        }
        if (e.outgoing.empty() && e.finished) *flags |= NGHTTP2_DATA_FLAG_EOF;
        return static_cast<nghttp2_ssize>(count);
    }
};

Session::Session(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Session::~Session() = default;
Session::Session(Session&&) noexcept = default;
Session& Session::operator=(Session&&) noexcept = default;

Result<Session> Session::create(Role role, Limits limits, std::optional<ResourceBudget> budget) {
    if (limits.max_streams == 0 || limits.max_streams > 100000 || limits.max_headers == 0 ||
        limits.max_header_bytes == 0 || limits.max_header_bytes > 0xffffffffU ||
        limits.max_output_bytes < 16393 || limits.max_queued_frames == 0) return fail(Errc::invalid_argument);
    ResourceBudget::Reservation reservation;
    if (budget) {
        const auto max = std::numeric_limits<std::size_t>::max();
        if (limits.max_header_bytes > (max - limits.max_body_bytes) / 3)
            return fail(Errc::limit_exceeded);
        const auto per_stream = limits.max_body_bytes + 3 * limits.max_header_bytes;
        if (per_stream > max / limits.max_streams) return fail(Errc::limit_exceeded);
        auto total = per_stream * limits.max_streams;
        for (const auto extra : {limits.max_output_bytes, limits.max_queued_body_bytes}) {
            if (extra > max - total) return fail(Errc::limit_exceeded);
            total += extra;
        }
        auto acquired = budget->try_acquire(total);
        if (!acquired) return fail(acquired.error());
        reservation = std::move(*acquired);
    }
    auto impl = std::make_unique<Impl>(role, limits);
    impl->reservation = std::move(reservation);
    nghttp2_session_callbacks* raw_callbacks = nullptr;
    int rc = nghttp2_session_callbacks_new(&raw_callbacks);
    if (rc) return fail(engine_error(rc));
    std::unique_ptr<nghttp2_session_callbacks, decltype(&nghttp2_session_callbacks_del)>
        callbacks(raw_callbacks, nghttp2_session_callbacks_del);
    nghttp2_session_callbacks_set_send_callback2(callbacks.get(), Impl::send);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks.get(), Impl::begin);
    nghttp2_session_callbacks_set_on_header_callback(callbacks.get(), Impl::header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(), Impl::frame_received);
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(callbacks.get(), Impl::invalid_frame);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks.get(), Impl::frame_sent);
    nghttp2_session_callbacks_set_on_frame_not_send_callback(callbacks.get(), Impl::frame_not_sent);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks.get(), Impl::data);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks.get(), Impl::stream_closed);
    nghttp2_option* raw_options = nullptr;
    rc = nghttp2_option_new(&raw_options);
    if (rc) return fail(engine_error(rc));
    std::unique_ptr<nghttp2_option, decltype(&nghttp2_option_del)> options(raw_options, nghttp2_option_del);
    nghttp2_option_set_no_auto_window_update(options.get(), 1);
    nghttp2_option_set_no_closed_streams(options.get(), 1);
    nghttp2_option_set_max_reserved_remote_streams(options.get(), 0);
    nghttp2_option_set_max_outbound_ack(options.get(), 32);
    nghttp2_option_set_max_continuations(options.get(), 8);
    nghttp2_option_set_max_send_header_block_length(options.get(), limits.max_header_bytes);
    nghttp2_option_set_max_deflate_dynamic_table_size(options.get(), 4096);
    rc = role == Role::client
        ? nghttp2_session_client_new2(&impl->session, callbacks.get(), impl.get(), options.get())
        : nghttp2_session_server_new2(&impl->session, callbacks.get(), impl.get(), options.get());
    if (rc) return fail(engine_error(rc));
    std::vector<nghttp2_settings_entry> settings{
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, static_cast<std::uint32_t>(limits.max_streams)},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, static_cast<std::uint32_t>(limits.max_header_bytes)},
        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 4096}
    };
    if (role == Role::client) settings.push_back({NGHTTP2_SETTINGS_ENABLE_PUSH, 0});
    if (limits.enable_connect_protocol) settings.push_back({NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1});
    rc = nghttp2_submit_settings(impl->session, NGHTTP2_FLAG_NONE, settings.data(), settings.size());
    if (rc) return fail(engine_error(rc));
    return Session(std::move(impl));
}

Result<std::int32_t> Session::request(const Headers& headers, std::span<const std::byte> body) {
    return request_impl(headers, body, false);
}
Result<std::int32_t> Session::request_stream(const Headers& headers) {
    return request_impl(headers, {}, true);
}
Result<std::int32_t> Session::request_impl(const Headers& headers, std::span<const std::byte> body,
                                          bool streaming) {
    auto& s = *impl_;
    if (s.role != Role::client || s.state != State::open) return fail(Errc::invalid_argument);
    if (nghttp2_session_get_outbound_queue_size(s.session) >= s.limits.max_queued_frames ||
        s.entries.size() >= s.limits.max_streams || body.size() > s.limits.max_body_bytes)
        return fail(Errc::limit_exceeded);
    if (body.size() > s.limits.max_queued_body_bytes - s.queued_bodies ||
        (!body.empty() && s.retained_chunk_count() >= s.limits.max_queued_frames))
        return fail(Errc::would_block);
    if (!valid_headers(headers, true, streaming ? std::nullopt : std::optional{body.size()}, s.limits))
        return fail(Errc::invalid_argument);
    const auto protocol = field(headers, ":protocol");
    if (!protocol.empty() && (!streaming || !peer_connect_protocol_enabled()))
        return fail(Errc::not_supported);
    auto nv = nv_headers(headers);
    const auto id = static_cast<std::int32_t>(nghttp2_session_get_next_stream_id(s.session));
    if (id <= 0) return fail(engine_error(NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE));
    auto& e = s.entries.try_emplace(id).first->second;
    e.visible.id = id;
    e.protocol = protocol;
    for (const auto& h : headers) if (h.name == ":method") e.head = h.value == "HEAD";
    if (!body.empty()) e.outgoing.emplace_back(body.begin(), body.end());
    e.queued = e.produced = body.size();
    e.streaming = streaming;
    e.finished = !streaming;
    Impl::body_metadata(e, headers);
    nghttp2_data_provider2 provider{{.ptr = &e}, Impl::read_data};
    const auto actual = nghttp2_submit_request2(s.session, nullptr, nv.data(), nv.size(),
                                              streaming || !body.empty() ? &provider : nullptr, nullptr);
    if (actual < 0) { s.entries.erase(id); return fail(engine_error(actual)); }
    s.queued_bodies += body.size();
    return actual;
}

Result<void> Session::respond(std::int32_t id, const Headers& headers, std::span<const std::byte> body) {
    return respond_impl(id, headers, body, false);
}
Result<void> Session::respond_stream(std::int32_t id, const Headers& headers) {
    return respond_impl(id, headers, {}, true);
}
Result<void> Session::respond_impl(std::int32_t id, const Headers& headers,
                                  std::span<const std::byte> body, bool streaming) {
    auto& s = *impl_;
    auto it = s.entries.find(id);
    if (s.role != Role::server || s.state == State::closed || s.state == State::failed ||
        it == s.entries.end() || it->second.responded || it->second.visible.closed || it->second.visible.error ||
        !it->second.visible.headers_received) return fail(Errc::invalid_argument);
    if (nghttp2_session_get_outbound_queue_size(s.session) >= s.limits.max_queued_frames ||
        body.size() > s.limits.max_body_bytes) return fail(Errc::limit_exceeded);
    if (body.size() > s.limits.max_queued_body_bytes - s.queued_bodies ||
        (!body.empty() && s.retained_chunk_count() >= s.limits.max_queued_frames))
        return fail(Errc::would_block);
    auto& e = it->second;
    const bool accepting = !e.protocol.empty() && success_status(headers);
    if (accepting && field(headers, ":status") == "204") return fail(Errc::not_supported);
    if (!valid_headers(headers, false, streaming ? std::nullopt : std::optional{body.size()}, s.limits,
                       !e.protocol.empty()) || (accepting && !streaming))
        return fail(Errc::invalid_argument);
    auto nv = nv_headers(headers);
    if (!e.head && !body.empty()) e.outgoing.emplace_back(body.begin(), body.end());
    e.queued = e.produced = e.head ? 0 : body.size();
    e.streaming = streaming;
    e.finished = !streaming;
    Impl::body_metadata(e, headers);
    e.body_forbidden = !accepting && (e.body_forbidden || e.head);
    nghttp2_data_provider2 provider{{.ptr = &e}, Impl::read_data};
    const int rc = nghttp2_submit_response2(s.session, id, nv.data(), nv.size(),
                                           streaming || !e.outgoing.empty() ? &provider : nullptr);
    if (rc) { e.outgoing.clear(); e.queued = 0; return fail(engine_error(rc)); }
    s.queued_bodies += e.queued;
    e.responded = true;
    e.accepted = accepting;
    return {};
}

Result<void> Session::write_body(std::int32_t id, std::span<const std::byte> body, bool end) {
    auto& s = *impl_;
    auto it = s.entries.find(id);
    if (s.state == State::closed || s.state == State::failed || it == s.entries.end())
        return fail(Errc::invalid_argument);
    auto& e = it->second;
    if (!e.streaming || e.finished || e.visible.closed || e.visible.error ||
        (e.body_forbidden && !body.empty())) return fail(Errc::invalid_argument);
    if (e.protocol.empty() && body.size() > s.limits.max_body_bytes - e.produced) return fail(Errc::limit_exceeded);
    if (e.content_length && !e.body_forbidden &&
        (body.size() > *e.content_length - e.produced ||
         (end && e.produced + body.size() != *e.content_length))) return fail(Errc::invalid_argument);
    if (body.size() > s.limits.max_queued_body_bytes - s.queued_bodies ||
        (!body.empty() && s.retained_chunk_count() >= s.limits.max_queued_frames))
        return fail(Errc::would_block);
    if (!body.empty()) e.outgoing.emplace_back(body.begin(), body.end());
    if (e.deferred && (!body.empty() || end)) {
        const int rc = nghttp2_session_resume_data(s.session, id);
        if (rc) {
            if (!body.empty()) e.outgoing.pop_back();
            return fail(engine_error(rc));
        }
        e.deferred = false;
    }
    e.queued += body.size();
    s.queued_bodies += body.size();
    if (e.protocol.empty()) e.produced += body.size();
    e.finished = end;
    return {};
}
Result<void> Session::finish_body(std::int32_t id) { return write_body(id, {}, true); }
std::size_t Session::queued_body_bytes() const noexcept { return impl_->queued_bodies; }
bool Session::peer_connect_protocol_enabled() const noexcept {
    return nghttp2_session_get_remote_settings(impl_->session, NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL) == 1;
}
bool Session::local_connect_protocol_enabled() const noexcept { return impl_->connect_advertised; }
bool Session::local_connect_protocol_acknowledged() const noexcept {
    return nghttp2_session_get_local_settings(impl_->session, NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL) == 1;
}
Result<ConnectState> Session::connect_state(std::int32_t id) const {
    const auto it = impl_->entries.find(id);
    if (it == impl_->entries.end() || it->second.protocol.empty()) return fail(Errc::invalid_argument);
    const auto& e = it->second;
    return ConnectState{e.protocol, e.accepted, e.finished, e.visible.remote_end,
                        e.visible.closed, e.visible.error};
}
Result<std::size_t> Session::read_connect(std::int32_t id, std::span<std::byte> destination) {
    auto state = connect_state(id);
    if (!state) return fail(state.error());
    if (state->error) return fail(state->error);
    if (!state->accepted) return fail(Errc::not_supported);
    if (destination.empty()) return std::size_t{0};
    auto& e = impl_->entries.at(id);
    const auto count = std::min(destination.size(), e.visible.body.size());
    if (!count) return fail(state->remote_end ? Errc::eof : Errc::would_block);
    int rc = nghttp2_session_consume_connection(impl_->session, count);
    if (!rc && !e.visible.closed) rc = nghttp2_session_consume_stream(impl_->session, id, count);
    if (rc) return fail(engine_error(rc));
    std::copy_n(e.visible.body.begin(), count, destination.begin());
    e.visible.body.erase(e.visible.body.begin(), e.visible.body.begin() + static_cast<std::ptrdiff_t>(count));
    return count;
}
Result<std::size_t> Session::write_connect(std::int32_t id, std::span<const std::byte> source) {
    auto state = connect_state(id);
    if (!state) return fail(state.error());
    if (state->error) return fail(state->error);
    if (!state->accepted || state->local_end || state->closed) return fail(Errc::invalid_argument);
    const auto count = std::min(source.size(), impl_->limits.max_queued_body_bytes);
    if (!source.empty() && count == 0) return fail(Errc::limit_exceeded);
    auto written = write_body(id, source.first(count));
    if (!written) return fail(written.error());
    return count;
}

Result<void> Session::receive(std::span<const std::byte> bytes) {
    auto& s = *impl_;
    if (s.state == State::closed || s.state == State::failed) return fail(s.error ? s.error : make_error_code(Errc::eof));
    while (!bytes.empty()) {
        const auto count = std::min<std::size_t>(bytes.size(), 16384);
        const auto rc = nghttp2_session_mem_recv2(s.session, reinterpret_cast<const std::uint8_t*>(bytes.data()), count);
        if (rc < 0 || static_cast<std::size_t>(rc) != count) {
            s.fail_connection(s.error ? s.error : engine_error(rc < 0 ? static_cast<int>(rc) : NGHTTP2_ERR_PROTO));
            return fail(s.error);
        }
        if (nghttp2_session_get_outbound_queue_size(s.session) > s.limits.max_queued_frames) {
            s.fail_connection(make_error_code(Errc::limit_exceeded));
            return fail(s.error);
        }
        bytes = bytes.subspan(count);
    }
    return {};
}

Result<std::vector<std::byte>> Session::output() {
    auto& s = *impl_;
    if (s.state == State::closed || s.state == State::failed) return fail(s.error ? s.error : make_error_code(Errc::eof));
    const int rc = nghttp2_session_send(s.session);
    if (rc) { s.fail_connection(s.error ? s.error : engine_error(rc)); return fail(s.error); }
    std::vector<std::byte> out;
    out.swap(s.wire);
    if (!nghttp2_session_want_read(s.session) && !nghttp2_session_want_write(s.session)) s.state = State::closed;
    return out;
}

Result<std::vector<std::byte>> Session::take_body(std::int32_t id) {
    auto& s = *impl_;
    auto it = s.entries.find(id);
    if (it == s.entries.end()) return fail(Errc::invalid_argument);
    auto& e = it->second;
    int rc = nghttp2_session_consume_connection(s.session, e.visible.body.size());
    if (!rc && !e.visible.closed) rc = nghttp2_session_consume_stream(s.session, id, e.visible.body.size());
    if (rc) return fail(engine_error(rc));
    std::vector<std::byte> body;
    body.swap(e.visible.body);
    return body;
}
Result<void> Session::cancel(std::int32_t id) {
    auto& s = *impl_;
    auto it = s.entries.find(id);
    if (s.state == State::closed || s.state == State::failed || it == s.entries.end() || it->second.visible.closed)
        return fail(Errc::invalid_argument);
    const int rc = s.reset(id, make_error_code(Errc::cancelled), NGHTTP2_CANCEL);
    if (rc) return fail(engine_error(rc));
    s.discard_output(it->second);
    return {};
}
Result<void> Session::release(std::int32_t id) {
    auto it = impl_->entries.find(id);
    if (it == impl_->entries.end() || !it->second.visible.closed) return fail(Errc::invalid_argument);
    auto body = take_body(id);
    if (!body) return fail(body.error());
    impl_->entries.erase(it);
    return {};
}
Result<void> Session::goaway(std::uint32_t code) {
    auto& s = *impl_;
    if (s.state == State::closed || s.state == State::failed || s.local_goaway) return fail(Errc::invalid_argument);
    if (nghttp2_session_get_outbound_queue_size(s.session) >= s.limits.max_queued_frames) return fail(Errc::limit_exceeded);
    const int rc = nghttp2_submit_goaway(s.session, NGHTTP2_FLAG_NONE, s.last_peer_stream, code, nullptr, 0);
    if (rc) return fail(engine_error(rc));
    s.state = State::draining;
    s.local_goaway = true;
    return {};
}
void Session::close(Error reason) {
    impl_->fail_connection(reason);
    impl_->state = State::closed;
}
const Stream* Session::stream(std::int32_t id) const noexcept {
    auto it = impl_->entries.find(id);
    return it == impl_->entries.end() ? nullptr : &it->second.visible;
}
std::vector<std::int32_t> Session::streams() const {
    std::vector<std::int32_t> result;
    result.reserve(impl_->entries.size());
    for (const auto& [id, entry] : impl_->entries) { static_cast<void>(entry); result.push_back(id); }
    return result;
}
State Session::state() const noexcept { return impl_->state; }
Error Session::error() const noexcept { return impl_->error; }
std::int32_t Session::peer_last_stream_id() const noexcept { return impl_->peer_last; }
std::uint32_t Session::peer_goaway_error() const noexcept { return impl_->peer_error; }
bool Session::wants_write() const noexcept {
    return impl_->state != State::closed && impl_->state != State::failed && nghttp2_session_want_write(impl_->session);
}
} // namespace Mira::http2
