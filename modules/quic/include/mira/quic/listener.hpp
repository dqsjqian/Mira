#pragma once

#include "mira/quic/engine.hpp"
#include "mira/core/resource_budget.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <type_traits>
#include <utility>

namespace Mira::quic {

namespace detail {
inline constexpr std::size_t kClosePacket = 1200;
// Unrepresentable protection periods never expire automatically; overflow must not reopen admission.
inline std::uint64_t closing_deadline(std::uint64_t now, std::uint64_t pto) noexcept {
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    return pto > (maximum - now) / 3 ? maximum : now + 3 * pto;
}
}  // namespace detail

struct ListenerLimits {
    std::size_t max_connections = 64;
    std::size_t max_payload_bytes = 256 * 1024 * 1024;
    std::size_t max_queue_entries = 64 * 1024 * 1024;
    // Lifetime total including original and retired CIDs; issuance stops at this limit.
    std::size_t max_connection_ids = 16;
    // Admission reserves a closing slot; protected tombstones are never evicted.
    std::size_t max_closing_connections = 128;
};

/// Socket-free, single-threaded CID dispatcher for one local UDP endpoint.
/// Protocol must expose the Engine operations and a const transport() accessor,
/// or be quic::Engine itself. A factory consumes the Initial exactly once.
/// Admission reserves each connection's full send/receive payload and queue
/// limits (QUIC: 4096 events + 4096 outgoing chunks), rather than oversubscribing idle connections.
/// Each live connection also reserves a closing slot and 1200 ciphertext bytes.
/// Local closes retransmit at most twice upon matching peer/CID input, spaced
/// by at least one PTO and never larger than the triggering datagram. Peer
/// draining and idle expiry remain silent. Application budgets are released
/// on termination; tombstones retain all CIDs for at least three ngtcp2 PTOs.
/// Metadata is bounded by max_closing_connections * max_connection_ids, not RSS.
/// Closing slots are separate from application event queues; reserved_payload_bytes()
/// includes the closing ciphertext reservation.
/// The caller must bound its own output queue and stop polling when it is full.
/// Required Retry returns at most one small reply directly from ingest; send it
/// immediately or discard it. Replies never enter poll or reserve a connection.
/// Disabled Retry admits unvalidated peers; select required for public endpoints.
/// Migration is opt-in; ngtcp2 validates candidate paths and owns each output route.
template<class Protocol = Engine>
class Dispatcher {
public:
    using Id = std::uint64_t;
    using Factory = std::function<Result<Protocol>(Options, std::span<const std::byte>, std::uint64_t)>;
    struct Datagram {
        Id connection_id;
        transport::Endpoint peer;
        Bytes data;
        transport::Endpoint local;
    };
    struct Ingest {
        enum class Kind { dropped, admitted, delivered, removed, retry } kind;
        Id connection_id = 0;
        // Retry has no connection: reply.connection_id is zero. No retained output queue.
        std::optional<Datagram> reply = std::nullopt;
    };

    /// Custom factories must preserve the supplied QUIC limits and declare their
    /// additional retained payload/queue ceilings. The HTTP/3 adapter supplies
    /// these from its validated limits.
    static Result<Dispatcher> create(Options options, ListenerLimits limits = {},
                                      Factory factory = {}, std::size_t extra_payload = 0,
                                      std::size_t extra_queue_entries = 0,
                                      std::optional<ResourceBudget> shared_payload = std::nullopt,
                                      RetryOptions retry = {}) {
        if (options.local.address_bytes().empty() || !options.max_streams ||
            options.max_streams > 4096 || options.alpn.empty() || options.alpn.size() > 255 ||
            options.alpn.find('\0') != std::string::npos || !limits.max_connections ||
            limits.max_connections > 65536 || limits.max_connection_ids < 2 ||
            (retry.policy == RetryPolicy::required && limits.max_connection_ids < 3) ||
            options.retry_validation || limits.max_connection_ids > 64 || !limits.max_closing_connections ||
            limits.max_closing_connections > 65536 || options.max_buffered_bytes < 4096 ||
            options.max_buffered_bytes > 64 * 1024 * 1024 ||
            extra_payload > std::numeric_limits<std::size_t>::max() -
                                2 * options.max_buffered_bytes - detail::kClosePacket ||
            extra_queue_entries > std::numeric_limits<std::size_t>::max() - 8192)
            return std::unexpected(quic_error(-100000));
        auto payload = 2 * options.max_buffered_bytes + extra_payload;
        auto events = 8192 + extra_queue_entries;
        if (options.max_datagram_frame_size) {
            if (options.max_datagram_frame_size > 65527 || options.max_datagram_bytes == 0 ||
                options.max_datagram_bytes > 64 * 1024 * 1024 || options.max_queued_datagrams == 0 ||
                options.max_queued_datagrams > 4096 ||
                options.max_datagram_bytes > std::numeric_limits<std::size_t>::max() - payload - detail::kClosePacket ||
                options.max_queued_datagrams > std::numeric_limits<std::size_t>::max() - events)
                return std::unexpected(quic_error(-100000));
            payload += options.max_datagram_bytes;
            events += options.max_queued_datagrams;
        }
        if (payload + detail::kClosePacket > limits.max_payload_bytes || events > limits.max_queue_entries)
            return std::unexpected(quic_error(-100001));
        if (!factory) {
            if constexpr (std::is_same_v<Protocol, Engine>) factory = Engine::accept;
            else return std::unexpected(quic_error(-100000));
        }
        if constexpr (!requires(Protocol& protocol, const Path& path, std::span<const std::byte> data) {
            protocol.receive(path, data, std::uint64_t{});
            protocol.poll_datagram(std::uint64_t{});
            protocol.close_datagram(std::uint64_t{}, std::uint64_t{});
        }) {
            if (options.migration != MigrationPolicy::fixed_peer)
                return std::unexpected(quic_error(-100000));
        }
        options.server = true;
        options.max_connection_ids = limits.max_connection_ids;
        auto gate = detail::RetryGate::create(options, std::move(retry));
        if (!gate) return std::unexpected(gate.error());
        return Dispatcher(std::move(options), limits, std::move(factory), payload, events,
                          shared_payload.value_or(ResourceBudget{limits.max_payload_bytes}),
                          std::move(*gate));
    }

    Result<Ingest> ingest(const transport::Endpoint& peer, std::span<const std::byte> packet,
                          std::uint64_t now) {
        if (!time(now)) return std::unexpected(quic_error(-100000));
        reap();
        auto route = packet_route(packet);
        if (!route || peer.address_bytes().empty()) return Ingest{Ingest::Kind::dropped};
        auto found = routes_.find(route->destination_cid);
        if (found != routes_.end()) {
            auto id = found->second;
            auto& entry = entries_.at(id);
            if (entry.peer != peer && (!entry.engine ||
                options_.migration == MigrationPolicy::fixed_peer))
                return Ingest{Ingest::Kind::dropped};
            if (!entry.engine) {
                auto& closed = entry.closed;
                if (!closed.packet.empty() && closed.transmissions < 3 &&
                    closed.next_send != std::numeric_limits<std::uint64_t>::max() &&
                    now >= closed.next_send && packet.size() >= closed.packet.size())
                    closed.pending = true;
                return Ingest{Ingest::Kind::dropped, id};
            }
            auto result = receive(*entry.engine, Path{options_.local, peer}, packet, now);
            if (!result || entry.engine->closed()) {
                finish(id);
                if (!result) return std::unexpected(result.error());
                return Ingest{Ingest::Kind::removed, id};
            }
            if (!refresh(id)) {
                finish(id);
                return std::unexpected(quic_error(-100001));
            }
            return Ingest{Ingest::Kind::delivered, id};
        }
        if (!route->initial || size() >= limits_.max_connections ||
            entries_.size() >= limits_.max_closing_connections ||
            payload_per_connection_ + detail::kClosePacket > limits_.max_payload_bytes - reserved_payload_bytes() ||
            queue_entries_per_connection_ > limits_.max_queue_entries - reserved_queue_entries() ||
            next_id_ == std::numeric_limits<Id>::max())
            return Ingest{Ingest::Kind::dropped};
        auto decision = retry_.inspect(peer, packet, now);
        if (!decision) return std::unexpected(decision.error());
        if (!decision->reply.empty())
            return Ingest{Ingest::Kind::retry, 0, Datagram{0, peer, std::move(decision->reply), options_.local}};
        if (!decision->admitted) return Ingest{Ingest::Kind::dropped};
        auto reservation = shared_payload_.try_acquire(payload_per_connection_);
        if (!reservation) return Ingest{Ingest::Kind::dropped};
        auto close_reservation = shared_payload_.try_acquire(detail::kClosePacket);
        if (!close_reservation) return Ingest{Ingest::Kind::dropped};
        auto options = options_;
        options.remote = peer;
        options.retry_validation = std::move(decision->validation);
        auto engine = factory_(std::move(options), packet, now);
        if (!engine) return std::unexpected(engine.error());
        auto id = next_id_++;
        entries_.emplace(id, Entry{peer, std::move(*reservation), std::move(*close_reservation),
                                   std::move(*engine), {}});
        ++active_;
        close_reserved_bytes_ += detail::kClosePacket;
        routes_.emplace(route->destination_cid, id);
        if (!refresh(id)) {
            finish(id);
            return std::unexpected(quic_error(-100001));
        }
        return Ingest{Ingest::Kind::admitted, id};
    }

    /// Round-robin, at most one packet. An engine error ends only that connection.
    /// No timer-only close retransmissions; an automatic error queues its initial close once.
    Result<std::optional<Datagram>> poll(std::uint64_t now) {
        if (!time(now)) return std::unexpected(quic_error(-100000));
        reap();
        auto count = entries_.size();
        for (std::size_t n = 0; n < count; ++n) {
            auto it = entries_.upper_bound(last_polled_);
            if (it == entries_.end()) it = entries_.begin();
            auto id = it->first;
            auto& entry = it->second;
            last_polled_ = id;
            if (!entry.engine) {
                auto& closed = entry.closed;
                if (!closed.pending) continue;
                closed.pending = false;
                ++closed.transmissions;
                const auto maximum = std::numeric_limits<std::uint64_t>::max();
                closed.next_send = now > maximum - closed.pto ? maximum : now + closed.pto;
                return std::optional<Datagram>{Datagram{id, entry.peer, closed.packet, options_.local}};
            }
            auto packet = produce(*entry.engine, now);
            if (!packet) {
                auto error = packet.error();
                finish(id);
                return std::unexpected(error);
            }
            if (!refresh(id)) {
                finish(id);
                return std::unexpected(quic_error(-100001));
            }
            if (!packet->data.empty())
                return std::optional<Datagram>{Datagram{id, packet->path.remote,
                    std::move(packet->data), packet->path.local}};
        }
        return std::optional<Datagram>{};
    }

    /// Errors end only the affected connection; other deadlines are serviced.
    Result<void> handle_expiry(std::uint64_t now) {
        if (!time(now)) return std::unexpected(quic_error(-100000));
        reap();
        for (auto& [id, entry] : entries_) {
            if (!entry.engine || entry.engine->expiry() > now) continue;
            auto result = entry.engine->handle_expiry(now);
            if (!result || entry.engine->closed() || !refresh(id)) finish(id);
        }
        return {};
    }
    std::uint64_t expiry() const noexcept {
        auto result = std::numeric_limits<std::uint64_t>::max();
        for (const auto& [id, entry] : entries_) {
            (void)id;
            if (!entry.engine) {
                if (entry.closed.pending) return clock_;
                result = std::min(result, entry.closed.deadline);
            } else {
                if (entry.engine->closed()) return clock_;
                result = std::min(result, entry.engine->expiry());
            }
        }
        return result;
    }
    Result<Datagram> close(Id id, std::uint64_t code, std::uint64_t now) {
        if (code >= (std::uint64_t{1} << 62) || !time(now))
            return std::unexpected(quic_error(-100000));
        reap();
        auto it = entries_.find(id);
        if (it == entries_.end() || !it->second.engine) return std::unexpected(quic_error(-100000));
        auto& entry = it->second;
        const auto pto = transport_engine(*entry.engine).pto();
        auto packet = terminate(*entry.engine, code, now);
        if (!packet) {
            auto error = packet.error();
            finish(id);
            return std::unexpected(error);
        }
        Datagram result{id, packet->path.remote, packet->data, packet->path.local};
        protect(id, pto, std::move(packet->data), false);
        return result;
    }
    /// Explicit purge releases tombstones, budgets and routes, allowing Initial replay.
    /// Automatic close/error paths never use this to forget protected CIDs early.
    bool remove(Id id) {
        auto it = entries_.find(id);
        if (it == entries_.end()) return false;
        if (it->second.engine) --active_;
        close_reserved_bytes_ -= it->second.close_reservation.size();
        entries_.erase(it);
        std::erase_if(routes_, [id](const auto& item) { return item.second == id; });
        return true;
    }
    /// Borrowed until termination. Use only application operations (streams/events),
    /// not close/receive/poll/expiry or moving the engine; the dispatcher owns wire/time.
    Protocol* connection(Id id) noexcept {
        auto it = entries_.find(id);
        return it == entries_.end() || !it->second.engine ? nullptr : &*it->second.engine;
    }
    std::vector<Id> connections() const {
        std::vector<Id> result;
        result.reserve(size());
        for (const auto& [id, entry] : entries_)
            if (entry.engine) result.push_back(id);
        return result;
    }
    std::size_t size() const noexcept { return active_; }
    std::size_t tombstone_count() const noexcept { return entries_.size() - active_; }
    std::size_t reserved_close_bytes() const noexcept { return close_reserved_bytes_; }
    std::size_t reserved_payload_bytes() const noexcept {
        return size() * payload_per_connection_ + reserved_close_bytes();
    }
    std::size_t reserved_queue_entries() const noexcept { return size() * queue_entries_per_connection_; }
    std::size_t route_count() const noexcept { return routes_.size(); }
    /// Keep exactly the formerly-current key as previous. Does not refill the reply limiter.
    /// Rotate on this single-threaded dispatcher; shared-key listeners need coordinated keys,
    /// scope, local endpoint, ALPN and a common monotonic clock epoch.
    Result<void> rotate_retry_key(const RetryKey& key) { return retry_.rotate(key); }
    void discard_previous_retry_key() noexcept { retry_.discard_previous(); }

private:
    struct Closed {
        Bytes packet;
        std::uint64_t deadline = 0, pto = 0, next_send = 0;
        unsigned transmissions = 0;
        bool pending = false;
    };
    struct Entry {
        transport::Endpoint peer;
        ResourceBudget::Reservation reservation, close_reservation;
        std::optional<Protocol> engine;
        Closed closed;
    };
    Dispatcher(Options options, ListenerLimits limits, Factory factory,
               std::size_t payload, std::size_t events, ResourceBudget shared_payload,
               detail::RetryGate retry)
        : options_(std::move(options)), limits_(limits), factory_(std::move(factory)),
          payload_per_connection_(payload), queue_entries_per_connection_(events),
          shared_payload_(std::move(shared_payload)), retry_(std::move(retry)) {}
    static const Engine& transport_engine(const Protocol& engine) {
        if constexpr (std::is_same_v<Protocol, Engine>) return engine;
        else return engine.transport();
    }
    static Result<void> receive(Protocol& protocol, const Path& path,
                                std::span<const std::byte> data, std::uint64_t now) {
        if constexpr (requires { protocol.receive(path, data, now); })
            return protocol.receive(path, data, now);
        else return protocol.receive(data, now);
    }
    static Result<Packet> produce(Protocol& protocol, std::uint64_t now) {
        if constexpr (requires { protocol.poll_datagram(now); }) return protocol.poll_datagram(now);
        else {
            auto bytes = protocol.poll(now);
            if (!bytes) return std::unexpected(bytes.error());
            return Packet{transport_engine(protocol).validated_path(), std::move(*bytes)};
        }
    }
    static Result<Packet> terminate(Protocol& protocol, std::uint64_t code, std::uint64_t now) {
        if constexpr (requires { protocol.close_datagram(code, now); })
            return protocol.close_datagram(code, now);
        else {
            auto bytes = protocol.close(code, now);
            if (!bytes) return std::unexpected(bytes.error());
            return Packet{transport_engine(protocol).validated_path(), std::move(*bytes)};
        }
    }
    bool time(std::uint64_t now) {
        if (now < clock_) return false;
        clock_ = now;
        return true;
    }
    bool refresh(Id id) {
        auto& entry = entries_.at(id);
        const auto& transport = transport_engine(*entry.engine);
        entry.peer = transport.validated_path().remote;
        auto ids = transport.retained_connection_ids();
        if (ids.size() > limits_.max_connection_ids) return false;
        bool valid = true;
        for (auto& cid : ids) {
            if (cid.empty() || cid.size() > 20) { valid = false; continue; }
            auto [it, inserted] = routes_.emplace(std::move(cid), id);
            if (!inserted && it->second != id) valid = false;
        }
        return valid;
    }
    void protect(Id id, std::uint64_t pto, Bytes packet, bool pending) {
        auto& entry = entries_.at(id);
        (void)refresh(id);
        pto = std::max(pto, std::uint64_t{1});
        const auto maximum = std::numeric_limits<std::uint64_t>::max();
        // Custom factories cannot enlarge the close cache; oversize packets become silent tombstones.
        if (packet.empty() || packet.size() > detail::kClosePacket) {
            packet = Bytes{};
            close_reserved_bytes_ -= entry.close_reservation.size();
            entry.close_reservation.reset();
        }
        entry.closed = {std::move(packet), detail::closing_deadline(clock_, pto), pto,
                        clock_ > maximum - pto ? maximum : clock_ + pto,
                        pending ? 0u : 1u, false};
        entry.closed.pending = pending && !entry.closed.packet.empty();
        entry.engine.reset();
        entry.reservation.reset();
        --active_;
    }
    void finish(Id id) {
        auto& entry = entries_.at(id);
        const auto& transport = transport_engine(*entry.engine);
        const auto pto = transport.pto();
        Bytes packet;
        if (!transport.draining()) {
            auto result = terminate(*entry.engine, 1, clock_);
            if (result) packet = std::move(result->data);
        }
        protect(id, pto, std::move(packet), true);
    }
    void reap() {
        for (auto it = entries_.begin(); it != entries_.end();) {
            auto id = it->first;
            auto& entry = it++->second;
            if (entry.engine) {
                if (entry.engine->closed()) finish(id);
            } else if (entry.closed.deadline != std::numeric_limits<std::uint64_t>::max() &&
                       entry.closed.deadline <= clock_) remove(id);
        }
    }
    Options options_;
    ListenerLimits limits_;
    Factory factory_;
    std::size_t payload_per_connection_, queue_entries_per_connection_;
    std::size_t active_ = 0, close_reserved_bytes_ = 0;
    ResourceBudget shared_payload_;
    detail::RetryGate retry_;
    std::uint64_t clock_ = 0;
    Id next_id_ = 1, last_polled_ = 0;
    std::map<Id, Entry> entries_;
    struct CidLess {
        bool operator()(const Bytes& left, const Bytes& right) const noexcept {
            const auto common = (std::min)(left.size(), right.size());
            for (std::size_t i = 0; i < common; ++i) {
                if (left[i] != right[i]) return left[i] < right[i];
            }
            return left.size() < right.size();
        }
    };
    // CIDs are short byte keys; avoid the library's vector<=> memcmp path
    // whose unconstrained size triggers GCC 14 -Wstringop-overread at -O3.
    std::map<Bytes, Id, CidLess> routes_;
};

using Listener = Dispatcher<>;

}  // namespace Mira::quic
