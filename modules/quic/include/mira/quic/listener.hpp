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

struct ListenerLimits {
    std::size_t max_connections = 64;
    std::size_t max_payload_bytes = 256 * 1024 * 1024;
    std::size_t max_queue_entries = 64 * 1024 * 1024;
    std::size_t max_connection_ids = 16;  // Per connection, including the original Initial DCID.
};

/// Socket-free, single-threaded CID dispatcher for one local UDP endpoint.
/// Protocol must expose the Engine operations and a const transport() accessor,
/// or be quic::Engine itself. A factory consumes the Initial exactly once.
/// Admission reserves each connection's full send/receive payload and queue
/// limits (QUIC: 4096 events + 4096 outgoing chunks), rather than oversubscribing idle connections. These are accounted
/// payload/queue limits, NOT process RSS: TLS, protocol-library allocations,
/// container capacity, and payload transferred to the caller are not included.
/// No datagrams are queued: poll/close transfer one packet directly to the caller.
/// The caller must bound its own output queue and stop polling when it is full.
/// Retry, stateless reset, migration, and address validation are not implemented.
template<class Protocol = Engine>
class Dispatcher {
public:
    using Id = std::uint64_t;
    using Factory = std::function<Result<Protocol>(Options, std::span<const std::byte>, std::uint64_t)>;
    struct Datagram {
        Id connection_id;
        transport::Endpoint peer;
        Bytes data;
    };
    struct Ingest {
        enum class Kind { dropped, admitted, delivered, removed } kind;
        Id connection_id = 0;
    };

    /// Custom factories must preserve the supplied QUIC limits and declare their
    /// additional retained payload/queue ceilings. The HTTP/3 adapter supplies
    /// these from its validated limits.
    static Result<Dispatcher> create(Options options, ListenerLimits limits = {},
                                      Factory factory = {}, std::size_t extra_payload = 0,
                                      std::size_t extra_queue_entries = 0,
                                      std::optional<ResourceBudget> shared_payload = std::nullopt) {
        if (options.local.address_bytes().empty() || !options.max_streams ||
            options.max_streams > 4096 || options.alpn.empty() || options.alpn.size() > 255 ||
            options.alpn.find('\0') != std::string::npos || !limits.max_connections ||
            limits.max_connections > 65536 || !limits.max_connection_ids ||
            limits.max_connection_ids > 64 || options.max_buffered_bytes < 4096 ||
            options.max_buffered_bytes > 64 * 1024 * 1024 ||
            extra_payload > std::numeric_limits<std::size_t>::max() - 2 * options.max_buffered_bytes ||
            extra_queue_entries > std::numeric_limits<std::size_t>::max() - 8192)
            return std::unexpected(quic_error(-100000));
        auto payload = 2 * options.max_buffered_bytes + extra_payload;
        auto events = 8192 + extra_queue_entries;
        if (payload > limits.max_payload_bytes || events > limits.max_queue_entries)
            return std::unexpected(quic_error(-100001));
        if (!factory) {
            if constexpr (std::is_same_v<Protocol, Engine>) factory = Engine::accept;
            else return std::unexpected(quic_error(-100000));
        }
        options.server = true;
        return Dispatcher(std::move(options), limits, std::move(factory), payload, events,
                          shared_payload.value_or(ResourceBudget{limits.max_payload_bytes}));
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
            if (entry.peer != peer) return Ingest{Ingest::Kind::dropped};
            auto result = entry.engine.receive(packet, now);
            if (!result || entry.engine.closed()) {
                remove(id);
                if (!result) return std::unexpected(result.error());
                return Ingest{Ingest::Kind::removed, id};
            }
            if (!refresh(id)) {
                remove(id);
                return std::unexpected(quic_error(-100001));
            }
            return Ingest{Ingest::Kind::delivered, id};
        }
        if (!route->initial || entries_.size() >= limits_.max_connections ||
            payload_per_connection_ > limits_.max_payload_bytes - reserved_payload_bytes() ||
            queue_entries_per_connection_ > limits_.max_queue_entries - reserved_queue_entries() ||
            next_id_ == std::numeric_limits<Id>::max())
            return Ingest{Ingest::Kind::dropped};
        auto reservation = shared_payload_.try_acquire(payload_per_connection_);
        if (!reservation) return Ingest{Ingest::Kind::dropped};
        auto options = options_;
        options.remote = peer;
        auto engine = factory_(std::move(options), packet, now);
        if (!engine) return std::unexpected(engine.error());
        auto id = next_id_++;
        entries_.emplace(id, Entry{peer, std::move(*reservation), std::move(*engine)});
        if (!refresh(id)) {
            remove(id);
            return std::unexpected(quic_error(-100001));
        }
        return Ingest{Ingest::Kind::admitted, id};
    }

    /// Round-robin, at most one packet. No packet is generated when the caller
    /// does not poll; this keeps dispatcher-owned wire queues at zero. An engine
    /// error removes only that connection; continue polling the remaining ones.
    Result<std::optional<Datagram>> poll(std::uint64_t now) {
        if (!time(now)) return std::unexpected(quic_error(-100000));
        reap();
        auto count = entries_.size();
        for (std::size_t n = 0; n < count; ++n) {
            auto it = entries_.upper_bound(last_polled_);
            if (it == entries_.end()) it = entries_.begin();
            auto id = it->first;
            last_polled_ = id;
            auto packet = it->second.engine.poll(now);
            if (!packet) {
                auto error = packet.error();
                remove(id);
                return std::unexpected(error);
            }
            if (!refresh(id)) {
                remove(id);
                return std::unexpected(quic_error(-100001));
            }
            if (!packet->empty())
                return std::optional<Datagram>{Datagram{id, it->second.peer, std::move(*packet)}};
        }
        return std::optional<Datagram>{};
    }

    /// Errors remove only the affected connection; other deadlines are serviced.
    Result<void> handle_expiry(std::uint64_t now) {
        if (!time(now)) return std::unexpected(quic_error(-100000));
        reap();
        for (auto it = entries_.begin(); it != entries_.end();) {
            auto id = it->first;
            auto& engine = it++->second.engine;
            if (engine.expiry() > now) continue;
            auto result = engine.handle_expiry(now);
            if (!result || engine.closed() || !refresh(id)) remove(id);
        }
        return {};
    }
    std::uint64_t expiry() const noexcept {
        auto result = std::numeric_limits<std::uint64_t>::max();
        for (const auto& [id, entry] : entries_) {
            (void)id;
            if (entry.engine.closed()) return clock_;
            result = std::min(result, entry.engine.expiry());
        }
        return result;
    }
    Result<Datagram> close(Id id, std::uint64_t code, std::uint64_t now) {
        if (!time(now)) return std::unexpected(quic_error(-100000));
        auto it = entries_.find(id);
        if (it == entries_.end()) return std::unexpected(quic_error(-100000));
        auto packet = it->second.engine.close(code, now);
        if (!packet) return std::unexpected(packet.error());
        Datagram result{id, it->second.peer, std::move(*packet)};
        remove(id);
        return result;
    }
    /// Immediate local removal, without a close packet or draining tombstone.
    /// All payload/queue reservations and CID routes are released together.
    /// Replayed Initials may be admitted again; this is not an anti-replay policy.
    bool remove(Id id) {
        if (!entries_.erase(id)) return false;
        std::erase_if(routes_, [id](const auto& item) { return item.second == id; });
        return true;
    }
    /// Borrowed until removal. Use only application operations (streams/events),
    /// not receive/poll/expiry or moving the engine; the dispatcher owns wire/time.
    Protocol* connection(Id id) noexcept {
        auto it = entries_.find(id);
        return it == entries_.end() ? nullptr : &it->second.engine;
    }
    std::vector<Id> connections() const {
        std::vector<Id> result;
        result.reserve(entries_.size());
        for (const auto& [id, entry] : entries_) {
            (void)entry;
            result.push_back(id);
        }
        return result;
    }
    std::size_t size() const noexcept { return entries_.size(); }
    std::size_t reserved_payload_bytes() const noexcept { return size() * payload_per_connection_; }
    std::size_t reserved_queue_entries() const noexcept { return size() * queue_entries_per_connection_; }
    std::size_t route_count() const noexcept { return routes_.size(); }

private:
    struct Entry {
        transport::Endpoint peer;
        ResourceBudget::Reservation reservation;
        Protocol engine;
    };
    Dispatcher(Options options, ListenerLimits limits, Factory factory,
               std::size_t payload, std::size_t events, ResourceBudget shared_payload)
        : options_(std::move(options)), limits_(limits), factory_(std::move(factory)),
          payload_per_connection_(payload), queue_entries_per_connection_(events),
          shared_payload_(std::move(shared_payload)) {}
    static const Engine& transport_engine(const Protocol& engine) {
        if constexpr (std::is_same_v<Protocol, Engine>) return engine;
        else return engine.transport();
    }
    bool time(std::uint64_t now) {
        if (now < clock_) return false;
        clock_ = now;
        return true;
    }
    bool refresh(Id id) {
        const auto& engine = transport_engine(entries_.at(id).engine);
        auto ids = engine.local_connection_ids();
        // Retain the client's original DCID for retransmitted Initial packets.
        ids.push_back(engine.initial_destination_cid());
        if (ids.size() > limits_.max_connection_ids) return false;
        for (const auto& cid : ids) {
            if (cid.empty()) return false;
            auto it = routes_.find(cid);
            if (it != routes_.end() && it->second != id) return false;
        }
        std::erase_if(routes_, [id](const auto& item) { return item.second == id; });
        for (auto& cid : ids) routes_.emplace(std::move(cid), id);
        return true;
    }
    void reap() {
        for (auto it = entries_.begin(); it != entries_.end();) {
            auto id = it->first;
            if (it++->second.engine.closed()) remove(id);
        }
    }
    Options options_;
    ListenerLimits limits_;
    Factory factory_;
    std::size_t payload_per_connection_, queue_entries_per_connection_;
    ResourceBudget shared_payload_;
    std::uint64_t clock_ = 0;
    Id next_id_ = 1, last_polled_ = 0;
    std::map<Id, Entry> entries_;
    std::map<Bytes, Id> routes_;
};

using Listener = Dispatcher<>;

}  // namespace Mira::quic
