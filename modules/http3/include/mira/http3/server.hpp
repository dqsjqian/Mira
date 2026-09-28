#pragma once

#include "mira/http3/engine.hpp"
#include "mira/quic/listener.hpp"

namespace Mira::http3 {

using Server = quic::Dispatcher<Engine>;

/// A single-port, socket-free HTTP/3 server. The caller pumps one UDP socket,
/// feeds (peer, datagram) to ingest, services application events per connection,
/// sends poll results to their peer, and wakes at expiry(). With required Retry,
/// immediately send ingest().reply (or discard it); Retry never enters poll().
/// Reservations cover QUIC send/receive payload, HTTP/3 send/receive body and
/// retained decoded header accounting, plus both engines' event queue limits.
/// Each nonempty HTTP/3 output chunk costs at least one body byte, so reserving
/// max_buffered_body queue entries covers the worst-case one-byte chunks.
/// Each live connection reserves 1200 closing bytes and one closing slot. Once
/// closed it leaves size()/connection(), but its CIDs remain protected for at least
/// three PTOs. Peer closes drain silently; local closes retransmit only on matching
/// input within a bounded budget. remove() explicitly purges this protection.
/// Protocol-library allocations and application-owned events are not RSS-bounded.
inline Result<Server> make_server(quic::Options options,
                                  quic::ListenerLimits admission = {}, Limits limits = {},
                                  std::optional<ResourceBudget> shared_payload = std::nullopt,
                                  quic::RetryOptions retry = {}) {
    if (options.alpn != "h3" || !limits.max_streams || limits.max_streams > 4096 || !limits.max_headers ||
        limits.max_headers > 4096 || !limits.max_header_bytes ||
        limits.max_header_bytes > 1024 * 1024 || !limits.max_buffered_body ||
        limits.max_buffered_body > 64 * 1024 * 1024 || !limits.max_events ||
        limits.max_events > 65536)
        return std::unexpected(http3_error(-110000));
    auto factory = [limits](quic::Options transport, std::span<const std::byte> initial,
                            std::uint64_t now) -> Result<Engine> {
        auto accepted = quic::Engine::accept(std::move(transport), initial, now);
        if (!accepted) return std::unexpected(accepted.error());
        return Engine::create(std::move(*accepted), true, limits);
    };
    const auto headers = static_cast<std::uint64_t>(limits.max_header_bytes) * limits.max_streams;
    const auto payload = 2 * static_cast<std::uint64_t>(limits.max_buffered_body) + headers;
    if (payload > std::numeric_limits<std::size_t>::max())
        return std::unexpected(http3_error(-110000));
    return Server::create(std::move(options), admission, std::move(factory),
                          static_cast<std::size_t>(payload),
                          2 * limits.max_events, std::move(shared_payload), std::move(retry));
}

}  // namespace Mira::http3
