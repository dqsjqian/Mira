#pragma once

// UDP DNS with automatic TCP fallback (RFC 1035 §4.2.2: a server that sets
// the TC bit is telling the client the answer did not fit in 512 bytes and
// to retry over TCP).
//
// query_udp reports that case as DnsError::truncated and the answer is
// lost; this helper retries the same question over TCP instead. The helper
// never dials: dns must not depend on transport (see
// scripts/ci/check_layering.py), so the caller supplies a connector that
// establishes the stream — typically a one-line tcp::connect call. Only
// truncation triggers the retry: every other UDP failure (timeout, refusal,
// mismatch) is returned as-is, and a TCP-phase failure replaces the
// truncation error rather than masking it. Each phase applies its own
// WireQueryOptions timeout; the caller's absolute deadline caps the whole
// attempt. The TCP exchange re-randomizes the transaction ID, as query_tcp
// always does, so no ID is reused across transports.

#include "mira/dns/query.hpp"

#include <concepts>
#include <utility>

namespace Mira::dns {

// The connector's stream type is not named here on purpose: it is deduced
// from the connector's return type, and query_tcp's own BoundedStream
// constraint validates it at instantiation.
template<class Datagram, std::equality_comparable Peer, class Connect>
    requires requires(Datagram& socket, std::span<const std::byte> out, std::span<std::byte> in,
                      Peer peer, OperationOptions io, Connect& connect) {
    { socket.send_to(out, peer, io) } -> std::same_as<Task<Result<std::size_t>>>;
    socket.receive_from(in, io);
    connect(io);
}
[[nodiscard]] Task<Result<Message>> query_with_tcp_fallback(Datagram& udp_socket, Peer peer,
                                                            Connect&& connect, Message question,
                                                            OperationOptions io = {},
                                                            WireQueryOptions options = {}) {
    auto udp = co_await query_udp(udp_socket, peer, question, io, options);
    if (udp) co_return std::move(*udp);
    if (udp.error() != DnsError::truncated) co_return fail(udp.error());
    auto stream = co_await connect(io);
    if (!stream) co_return fail(stream.error());
    co_return co_await query_tcp(*stream, std::move(question), io, options);
}

}  // namespace Mira::dns
