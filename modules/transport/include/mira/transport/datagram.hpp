#pragma once

// Mira/transport/datagram.hpp — the seam between datagram transports and
// UDP-based protocols.
//
// The stream twin of this file names no socket: protocols such as QUIC are
// written against `DatagramTransport`, not against `udp::Socket`. An
// in-memory deterministic transport can model it just as well, which is how
// the engines get tested without a network.
//
// The contract is whole-datagram and peer-addressed, mirroring sendto(2) and
// recvfrom(2) semantics:
//
//   * `send_to` resolves with the number of bytes handed to the OS — for a
//     datagram that is all or nothing, so any short value is an error path,
//     not a partial transfer.
//   * `receive_from` resolves with a `Datagram`: the received size and the
//     sender's endpoint. Truncation is the destination span's business; a
//     real `udp::Socket` reports `message_size` and drops the tail.
//
// One operation per direction may be in flight; overlapping the same
// direction is the caller's bug and lands in `invalid_argument` territory.
// Implementations document their own overlap and lifetime rules — the
// concept only fixes the shapes that compose.

#include "mira/core/operation.hpp"
#include "mira/core/task.hpp"
#include "mira/transport/endpoint.hpp"
#include "mira/transport/udp.hpp"

#include <concepts>
#include <cstddef>
#include <span>
#include <utility>

namespace Mira::transport {

/// A transport carrying whole datagrams with peer addressing.
/// `udp::Socket` satisfies this; a deterministic in-memory transport can too.
template<typename T>
concept DatagramTransport = requires(
    T transport, std::span<const std::byte> out, std::span<std::byte> in,
    Endpoint peer, OperationOptions options) {
    { transport.send_to(out, peer, options) } -> std::same_as<Task<Result<std::size_t>>>;
    { transport.receive_from(in, options) } -> std::same_as<Task<Result<udp::Datagram>>>;
};

}  // namespace Mira::transport
