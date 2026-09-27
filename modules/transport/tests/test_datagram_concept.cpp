// DatagramTransport — the shapes that compose, pinned at compile time.
//
// A concept nobody asserts is a comment pretending to be a contract. This
// translation unit exists to make both directions of the claim executable:
// `udp::Socket` satisfies `transport::DatagramTransport` (the positive
// proof, as a static_assert so it can never regress silently), and types
// that miss the contract fail to satisfy it — asserted through the
// negation idiom, because the failure itself lives in template
// substitution and cannot be caught as a runtime test.
//
// The negative cases each drop exactly one requirement:
//   * ShortSendTo   — hands back Task<Result<int>> instead of size_t, the
//                     datagram-equivalent of losing the "all or nothing"
//                     count;
//   * MissingPeer   — receives into a bare span without reporting the
//                     sender, so a multiplexer could never route a reply;
//   * BlockingSend  — synchronous signature, coroutine-shaped contract, no
//                     suspension point to yield at.
//
// If a refactor ever loosens the concept enough that one of these models
// it, the static_assert below fires and demands a deliberate decision —
// which is the point of writing concepts down at all.

#include "mira/transport/datagram.hpp"
#include "mira/transport/udp.hpp"

#include <cstddef>
#include <span>

using namespace Mira;
using Mira::transport::DatagramTransport;

// Positive: the concrete datagram transport models the concept.
static_assert(DatagramTransport<transport::udp::Socket>);

// Negative: each shape below misses exactly one clause.
struct ShortSendTo {
    Task<Result<int>> send_to(std::span<const std::byte>, transport::Endpoint,
                              OperationOptions = {}) {
        co_return Result<int>{0};
    }
    Task<Result<transport::udp::Datagram>>
    receive_from(std::span<std::byte>, OperationOptions = {}) {
        co_return Result<transport::udp::Datagram>{};
    }
};
static_assert(!DatagramTransport<ShortSendTo>);

struct MissingPeer {
    Task<Result<std::size_t>> send_to(std::span<const std::byte>, transport::Endpoint,
                                      OperationOptions = {}) {
        co_return Result<std::size_t>{0};
    }
    Task<Result<std::size_t>> receive_from(std::span<std::byte>, OperationOptions = {}) {
        co_return Result<std::size_t>{0};
    }
};
static_assert(!DatagramTransport<MissingPeer>);

struct BlockingSend {
    Result<std::size_t> send_to(std::span<const std::byte>, transport::Endpoint,
                                OperationOptions = {}) {
        return Result<std::size_t>{0};
    }
    Task<Result<transport::udp::Datagram>>
    receive_from(std::span<std::byte>, OperationOptions = {}) {
        co_return Result<transport::udp::Datagram>{};
    }
};
static_assert(!DatagramTransport<BlockingSend>);

int main() {
    // Every assertion above is compile-time; reaching here is the pass.
    return 0;
}
