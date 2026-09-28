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
};
struct Event {
    enum class Kind { headers, body, end, reset, goaway } kind;
    std::int64_t stream_id;
    Headers fields;
    quic::Bytes data;
    std::uint64_t error_code = 0;
};
/// HTTP/3 state machine owning a QUIC engine; h3 ALPN only, no 0-RTT/server push/extended CONNECT.
/// Incoming body is delivered in chunks and the window is restored via consume. Outgoing chunks
/// remain stable until acknowledged; max_buffered_body bounds the connection-wide retained body.
class Engine {
public:
    static Result<Engine> create(quic::Engine transport, bool server, Limits limits = {});
    Engine(Engine&&) noexcept;
    Engine& operator=(Engine&&) noexcept;
    ~Engine();
    Result<void> receive(std::span<const std::byte> datagram, std::uint64_t now);
    Result<quic::Bytes> poll(std::uint64_t now);
    Result<void> handle_expiry(std::uint64_t now);
    std::uint64_t expiry() const noexcept;
    bool ready() const noexcept;
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
    std::vector<Event> take_events();
    Result<void> consume(std::int64_t stream, std::size_t bytes);
    Result<void> cancel(std::int64_t stream);
    /// Two-phase GOAWAY: after the notice the caller waits a suitable RTT before calling shutdown.
    Result<void> shutdown_notice();
    Result<void> shutdown();
    Result<quic::Bytes> close(std::uint64_t code, std::uint64_t now);

private:
    Result<std::int64_t> request_impl(const Headers&, std::span<const std::byte>, bool streaming);
    Result<void> respond_impl(std::int64_t, const Headers&, std::span<const std::byte>, bool streaming);
    struct Impl;
    explicit Engine(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}  // namespace Mira::http3
