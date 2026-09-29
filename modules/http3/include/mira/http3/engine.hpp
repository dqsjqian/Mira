#pragma once
#include "mira/core/error.hpp"
#include "mira/http/fields.hpp"
#include "mira/quic/engine.hpp"

#include <utility>

namespace Mira::http3 {
using Mira::Result;
/// HTTP/2 and HTTP/3 share the same header-block semantics (HPACK/QPACK compress the same field
/// sequence model), so they share one header list type: swapping transports requires no rewrite
/// of header-handling code.
using Mira::http::Header;
using Mira::http::Headers;

/// Error category shared by native nghttp3 negative codes and engine-owned boundary codes.
/// The -110000 range holds engine-owned codes; the rest are native nghttp3 codes.
[[nodiscard]] Error http3_error(int code) noexcept;
struct Limits {
    std::size_t max_header_bytes = 64 * 1024;
    std::size_t max_headers = 128;
    // Independent connection-wide budgets for unread input and retained output (including unacked data).
    std::size_t max_buffered_body = 4 * 1024 * 1024;
    std::size_t max_events = 4096;
    std::size_t max_streams = 64;
    bool enable_connect_protocol = false;
};
/// Canonical SETTINGS this engine advertises for `limits`. A server enabling 0-RTT must put this
/// into quic::Options::early_data_context before creating its ServerContext: every ticket the
/// context issues then carries identical SETTINGS, so 0-RTT is only accepted when a client's
/// remembered SETTINGS are still compatible (RFC 9114 section 7.2.4.2).
[[nodiscard]] std::string early_data_context(const Limits& limits);
struct ConnectState {
    std::string protocol;
    bool accepted = false;
    bool local_end = false;
    bool remote_end = false;
    bool closed = false;
    Error error;
};
struct Event {
    enum class Kind { headers, body, end, reset, goaway } kind;
    std::int64_t stream_id;
    Headers fields;
    quic::Bytes data;
    std::uint64_t error_code = 0;
    /// Headers only. Server: the request arrived in 0-RTT and may be a replay (RFC 8470); answer
    /// 425 if processing it twice is unsafe. Client: the request was sent and accepted in 0-RTT.
    bool early_data = false;
};
/// HTTP/3 state machine owning a QUIC engine; h3 ALPN only, no server push.
/// Extended CONNECT is opt-in and waits for the server's actual SETTINGS.
///
/// 0-RTT (quic EarlyDataPolicy::replay_safe on both ends). A client holding a compatible ticket is
/// early_ready() right after create: request() then sends GET/HEAD/OPTIONS whole-body requests in
/// 0-RTT under default SETTINGS (nothing is remembered, which RFC 9114 permits); other methods,
/// streaming and extended CONNECT return not_supported until ready(). If the server rejects 0-RTT,
/// TLS guarantees it processed none of them, and the engine resubmits them after the handshake on
/// the same stream IDs. A server that accepted 0-RTT becomes ready() before handshake completion
/// and answers in 0.5-RTT; early requests with unsafe methods are answered 425 (Too Early)
/// automatically and never surfaced. There is no anti-replay guarantee for surfaced early requests.
/// The pinned dependency treats 204 as bodyless; 204 tunnels are explicitly unsupported.
/// Incoming body is delivered in chunks and the window is restored via consume. Outgoing chunks
/// remain stable until acknowledged; max_buffered_body bounds the connection-wide retained body.
class Engine {
public:
    static Result<Engine> create(quic::Engine transport, bool server, Limits limits = {});
    Engine(Engine&&) noexcept;
    Engine& operator=(Engine&&) noexcept;
    ~Engine();
    Result<void> receive(std::span<const std::byte> datagram, std::uint64_t now);
    Result<void> receive(const quic::Path& path, std::span<const std::byte> datagram, std::uint64_t now);
    Result<quic::Bytes> poll(std::uint64_t now);
    Result<quic::Packet> poll_datagram(std::uint64_t now);
    Result<void> handle_expiry(std::uint64_t now);
    std::uint64_t expiry() const noexcept;
    bool ready() const noexcept;
    /// Client only: 0-RTT is pending and early-eligible requests may be submitted.
    bool early_ready() const noexcept;
    bool peer_goaway() const noexcept;
    bool is_server() const noexcept;
    bool closed() const noexcept;
    quic::Engine& transport() noexcept;
    const quic::Engine& transport() const noexcept;
    Result<std::int64_t> request(const Headers& fields, std::span<const std::byte> body = {});
    Result<void>
    respond(std::int64_t stream, const Headers& fields, std::span<const std::byte> body = {});
    Result<std::int64_t> request_stream(const Headers& fields);
    Result<void> respond_stream(std::int64_t stream, const Headers& fields);
    // would_block accepts no bytes; drive packets/ACKs and retry with chunks no larger than the budget.
    // finish_body is single-use. Streaming submissions use incremental scheduling.
    Result<void> write_body(std::int64_t stream, std::span<const std::byte> body, bool end = false);
    Result<void> finish_body(std::int64_t stream);
    std::size_t queued_body_bytes() const noexcept;
    bool peer_connect_protocol_enabled() const noexcept;
    bool local_connect_protocol_enabled() const noexcept;
    Result<ConnectState> connect_state(std::int64_t stream) const;
    Result<std::size_t> read_connect(std::int64_t stream, std::span<std::byte> destination);
    Result<std::size_t> write_connect(std::int64_t stream, std::span<const std::byte> source);
    // Accepted CONNECT records are retained until release_connect, including after RESET/FIN.
    Result<void> release_connect(std::int64_t stream);
    std::vector<Event> take_events();
    Result<void> consume(std::int64_t stream, std::size_t bytes);
    Result<void> cancel(std::int64_t stream);
    /// Two-phase GOAWAY: after the notice the caller waits a suitable RTT before calling shutdown.
    Result<void> shutdown_notice();
    Result<void> shutdown();
    Result<quic::Bytes> close(std::uint64_t code, std::uint64_t now);
    Result<quic::Packet> close_datagram(std::uint64_t code, std::uint64_t now);

private:
    Result<std::int64_t> request_impl(const Headers&, std::span<const std::byte>, bool streaming);
    Result<void> respond_impl(std::int64_t, const Headers&, std::span<const std::byte>, bool streaming);
    struct Impl;
    explicit Engine(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}  // namespace Mira::http3
