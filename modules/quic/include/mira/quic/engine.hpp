#pragma once

#include "mira/core/error.hpp"
#include "mira/transport/endpoint.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <chrono>
#include <cstddef>

namespace Mira::quic {

using Mira::Result;
/// Owned wire bytes, in the library-wide byte type: the transport layer
/// speaks `std::byte` end to end, and the C-API boundaries (ngtcp2/nghttp3)
/// are the only places allowed to reinterpret — and they do it inside the
/// engine's own translation units.
using Bytes = std::vector<std::byte>;

namespace detail {

/// Theoretical upper bound for a QUIC v1 datagram (the largest UDP payload reachable within a
/// varint length plus the 20-byte AEAD tag). quic::Connection and http3::Connection both use it
/// as their single-packet buffer size; defining it here in the engine header keeps the two
/// implementations from silently drifting apart.
inline constexpr std::size_t kMaxDatagram = 65536;

/// Engine time source: monotonic nanoseconds from steady_clock. All ngtcp2 now/expiry values use this unit.
inline std::uint64_t now_ns() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          std::chrono::steady_clock::now().time_since_epoch())
                                          .count());
}

}  // namespace detail

/// Error category shared by native ngtcp2 negative codes and engine-owned boundary codes.
/// The -100000 range holds engine-owned codes (see engine.cpp); the rest are native ngtcp2 codes.
[[nodiscard]] Error quic_error(int code) noexcept;

/// Fills the buffer from a cryptographically secure random source. Returns false on failure, never fills partial data.
/// Reused by protocol modules above QUIC (HTTP/3 etc.) so they do not depend on the TLS backend directly.
[[nodiscard]] bool fill_random(std::uint8_t* destination, std::size_t length) noexcept;
struct Options {
    bool server = false;
    transport::Endpoint local;
    transport::Endpoint remote;
    std::string certificate_file;
    std::string private_key_file;
    std::string ca_file;
    std::string peer_name;
    std::string alpn = "h3";
    std::size_t max_buffered_bytes = 4 * 1024 * 1024;
    std::uint64_t max_streams = 64;
    std::uint64_t idle_timeout_ns = 30'000'000'000;
};
struct Event {
    enum class Kind { data, acknowledged, reset, closed } kind;
    std::int64_t stream_id;
    Bytes data;
    std::uint64_t value = 0;
    bool fin = false;
};
/// Single-threaded, socket-free QUIC v1 state machine. Time is monotonic nanoseconds; the caller
/// owns sending packets and waking on expiry. The path is currently fixed: migration, 0-RTT, and
/// Retry policies are not supported. The OpenSSL ossl backend is experimental upstream support.
class Engine {
public:
    static Result<Engine> client(Options options, std::uint64_t now);
    /// The initial is the peer's first datagram; the factory parses the connection ID and consumes that packet.
    /// May return ERR_RETRY when the first visible CRYPTO is not at offset 0; listener address
    /// validation / Retry policies are not provided yet.
    static Result<Engine>
    accept(Options options, std::span<const std::byte> initial, std::uint64_t now);
    Engine(Engine&&) noexcept;
    Engine& operator=(Engine&&) noexcept;
    ~Engine();
    Result<void> receive(std::span<const std::byte> packet, std::uint64_t now);
    /// Returns an owning-buffer datagram; empty means no packet for now. Call in a loop until empty or the scheduling budget is reached.
    Result<Bytes> poll(std::uint64_t now);
    Result<void> handle_expiry(std::uint64_t now);
    std::uint64_t expiry() const noexcept;
    bool handshake_complete() const noexcept;
    bool is_server() const noexcept;
    std::size_t write_capacity() const noexcept;
    std::uint64_t remote_bidi_stream_limit() const noexcept;
    bool closed() const noexcept;
    std::string negotiated_protocol() const;
    Result<std::int64_t> open_stream(bool unidirectional = false);
    /// Copies and holds the data until a real ACK or stream_close; returns a backpressure error once the total send budget is reached.
    Result<void> write(std::int64_t stream, std::span<const std::byte> bytes, bool fin);
    std::vector<Event> take_events();
    /// Restores the receive window after the application actually consumes (take_events does not count as consumption).
    Result<void> consume(std::int64_t stream, std::size_t bytes);
    Result<void> cancel(std::int64_t stream, std::uint64_t application_error);
    Result<Bytes> close(std::uint64_t application_error, std::uint64_t now);

private:
    struct Impl;
    explicit Engine(std::unique_ptr<Impl> impl);
    static Result<Engine> create(Options, std::span<const std::byte>, std::uint64_t);
    std::unique_ptr<Impl> impl_;
};

}  // namespace Mira::quic
