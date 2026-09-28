#pragma once

#include "mira/core/error.hpp"
#include "mira/transport/endpoint.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
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
struct PacketRoute {
    Bytes destination_cid;
    bool initial = false;
};
/// Decode routing metadata without authenticating the packet. Short headers use
/// the engine's fixed 16-byte local CID length; only QUIC v1 Initials admit peers.
[[nodiscard]] Result<PacketRoute> packet_route(std::span<const std::byte> packet);

enum class RetryPolicy { disabled, required };
using RetryKey = std::array<std::uint8_t, 32>;

/// Disabled preserves legacy admission, allocating an engine before address validation.
/// Required validates a short-lived ngtcp2 Retry token before any connection reservation.
/// This is address validation, not replay prevention or a complete denial-of-service defense.
struct RetryOptions {
    RetryPolicy policy = RetryPolicy::disabled;
    // Omitted keys use a fresh cryptographically random per-listener secret.
    // Injected keys must be secret, random, and accompanied by a nonempty service scope.
    std::optional<RetryKey> current_key;
    std::optional<RetryKey> previous_key;
    // Empty auto-key scopes are instance-random and remain isolated after rotation.
    // Shared listeners need identical scope, local endpoint, ALPN and monotonic clock epoch.
    std::string scope;
    // Positive and at most 60 seconds; expiry is exclusive, future tokens fail.
    std::uint64_t token_lifetime_ns = 10'000'000'000;
    // Whole-listener fixed window, not a per-address map; no queued Retry packets.
    // At most twice the configured ceiling may straddle a window boundary.
    std::uint64_t window_ns = 1'000'000'000;
    std::size_t max_replies_per_window = 128;
};

namespace detail { class RetryGate; }

/// Opaque proof issued only by the listener's Retry verifier. Custom factories must
/// preserve it and call Engine::accept with the same Initial, endpoints and timestamp.
class RetryValidation {
    friend class detail::RetryGate;
    friend class Engine;
    RetryValidation() = default;
    transport::Endpoint local_, remote_;
    std::string alpn_;
    Bytes original_dcid_, retry_scid_, token_;
    std::uint32_t version_ = 0;
    std::uint64_t verified_at_ = 0;
};

enum class MigrationPolicy { fixed_peer, validated };
enum class EarlyDataPolicy { disabled, replay_safe };
enum class EarlyDataStatus { not_attempted, pending, accepted, rejected };
class SessionCache;
class ServerContext;
struct Path {
    transport::Endpoint local;
    transport::Endpoint remote;
    friend bool operator==(const Path&, const Path&) = default;
};
struct Packet {
    Path path;
    Bytes data;
};

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
    // Lifetime CID limit including original DCID and Retry SCID; never evict retired IDs.
    std::size_t max_connection_ids = 64;
    std::shared_ptr<const RetryValidation> retry_validation;
    // Fixed peer by default; opt-in requires the path-aware receive/output APIs.
    MigrationPolicy migration = MigrationPolicy::fixed_peer;
    // Resumption/0RTT requires an explicit CA file. Keys include the loaded trust
    // material (including AUX/CRLs), not only its path. Empty ca_file uses system
    // trust with a fresh handshake; no tickets are stored or resumed.
    std::shared_ptr<SessionCache> session_cache;
    std::shared_ptr<ServerContext> server_context;
    std::string service_scope;
    // Caller declares all early operations replay-safe; rejected data is never replayed automatically.
    EarlyDataPolicy early_data = EarlyDataPolicy::disabled;
};

struct SessionCacheLimits {
    std::size_t max_entries = 16;
    std::size_t max_bytes = 256 * 1024;
    std::size_t max_ticket_bytes = 16 * 1024;
    std::uint64_t lifetime_ns = 3'600'000'000'000;
};
// Single-threaded bounded in-memory ticket cache. No concurrent use or disk export;
// removal cleanses serialized secret bytes.
class SessionCache {
public:
    static Result<std::shared_ptr<SessionCache>> create(SessionCacheLimits limits = {});
    ~SessionCache();
    void clear() noexcept;
    std::size_t size() const noexcept;
    std::size_t bytes() const noexcept;
private:
    friend class Engine;
    struct Impl;
    explicit SessionCache(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};
// Explicitly shared server ticket domain with immutable certificate, ALPN, scope and limits.
class ServerContext {
public:
    static Result<std::shared_ptr<ServerContext>> create(Options options,
                                                        std::uint64_t lifetime_seconds = 3600);
    ~ServerContext();
private:
    friend class Engine;
    struct Impl;
    explicit ServerContext(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

namespace detail {
class RetryGate {
public:
    struct Decision {
        bool admitted = false;
        Bytes reply;
        std::shared_ptr<const RetryValidation> validation;
    };
    static Result<RetryGate> create(const Options& options, RetryOptions retry);
    RetryGate(RetryGate&&) noexcept;
    RetryGate& operator=(RetryGate&&) noexcept;
    ~RetryGate();
    Result<Decision> inspect(const transport::Endpoint& peer,
                             std::span<const std::byte> initial, std::uint64_t now);
    Result<void> rotate(const RetryKey& key);
    void discard_previous() noexcept;
private:
    struct Impl;
    explicit RetryGate(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};
}  // namespace detail

struct Event {
    enum class Kind { data, acknowledged, reset, closed } kind;
    std::int64_t stream_id;
    Bytes data;
    std::uint64_t value = 0;
    bool fin = false;
    bool early_data = false;
};
/// Single-threaded, socket-free QUIC v1 state machine. Time is monotonic nanoseconds; the caller
/// owns sending packets and waking on expiry. Migration is opt-in and uses ngtcp2 path validation.
/// Retry address validation is provided by Listener; clients process Retry automatically.
/// The OpenSSL ossl backend is experimental upstream support.
class Engine {
public:
    static Result<Engine> client(Options options, std::uint64_t now);
    /// Consumes the Initial exactly once. A token-bearing Initial requires the listener's opaque
    /// retry_validation; client-provided original CIDs are never trusted. May return ERR_RETRY
    /// when the first visible CRYPTO is not at offset 0; callers must not retry such failures in a loop.
    static Result<Engine>
    accept(Options options, std::span<const std::byte> initial, std::uint64_t now);
    Engine(Engine&&) noexcept;
    Engine& operator=(Engine&&) noexcept;
    ~Engine();
    // Pathless compatibility operations require fixed_peer policy.
    Result<void> receive(std::span<const std::byte> packet, std::uint64_t now);
    Result<void> receive(const Path& path, std::span<const std::byte> packet, std::uint64_t now);
    /// Returns an owning-buffer datagram; empty means no packet for now. Call in a loop until empty or the scheduling budget is reached.
    Result<Bytes> poll(std::uint64_t now);
    Result<Packet> poll_datagram(std::uint64_t now);
    // Validate before client migration; retain both endpoints until path validation completes.
    Result<void> initiate_migration(const Path& path, std::uint64_t now);
    Path active_path() const;
    Path validated_path() const;
    bool path_validation_pending() const noexcept;
    Result<void> handle_expiry(std::uint64_t now);
    std::uint64_t expiry() const noexcept;
    bool handshake_complete() const noexcept;
    bool session_reused() const noexcept;
    MigrationPolicy migration_policy() const noexcept;
    EarlyDataPolicy early_data_policy() const noexcept;
    EarlyDataStatus early_data_status() const noexcept;
    // Requires replay_safe and a compatible ticket; normal open_stream/write never send early data.
    Result<std::int64_t> open_early_stream(bool unidirectional = false);
    Result<void> write_early(std::int64_t stream, std::span<const std::byte> bytes, bool fin);
    bool is_server() const noexcept;
    std::size_t write_capacity() const noexcept;
    std::uint64_t remote_bidi_stream_limit() const noexcept;
    bool closed() const noexcept;
    /// Active locally-issued CIDs, including replacements; retired CIDs are omitted.
    std::vector<Bytes> local_connection_ids() const;
    /// Original DCID and every issued local CID, including retired IDs, bounded by Options.
    std::vector<Bytes> retained_connection_ids() const;
    /// Current ngtcp2 PTO in nanoseconds, for external closing/draining lifetimes.
    std::uint64_t pto() const noexcept;
    bool draining() const noexcept;
    /// The client's original Initial DCID (also available on server engines).
    Bytes initial_destination_cid() const;
    std::string negotiated_protocol() const;
    Result<std::int64_t> open_stream(bool unidirectional = false);
    /// Copies and holds data until ACK or stream_close. Backpressure bounds both
    /// total send bytes and 4096 queued chunks across all streams.
    Result<void> write(std::int64_t stream, std::span<const std::byte> bytes, bool fin);
    std::vector<Event> take_events();
    /// Restores the receive window after the application actually consumes (take_events does not count as consumption).
    Result<void> consume(std::int64_t stream, std::size_t bytes);
    Result<void> cancel(std::int64_t stream, std::uint64_t application_error);
    /// Normal close sends an application error; existing failures retain their transport/TLS code.
    /// Idle/drop/retry emit no packet. Standalone Engine users schedule the closing period.
    Result<Bytes> close(std::uint64_t application_error, std::uint64_t now);
    Result<Packet> close_datagram(std::uint64_t application_error, std::uint64_t now);

private:
    friend class ServerContext;
    struct Impl;
    explicit Engine(std::unique_ptr<Impl> impl);
    static Result<Engine> create(Options, std::span<const std::byte>, std::uint64_t);
    std::unique_ptr<Impl> impl_;
};

}  // namespace Mira::quic
