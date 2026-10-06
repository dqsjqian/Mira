#pragma once

#include "mira/core/stream.hpp"
#include "mira/dns/message.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <concepts>
#include <random>

namespace Mira::dns {

struct WireQueryOptions {
    Limits limits{};
    std::chrono::milliseconds timeout{5000};
    std::size_t max_discarded_packets{16};
};

namespace detail {
inline Result<OperationOptions> query_budget(OperationOptions io, const WireQueryOptions& options) {
    if (io.stop.stop_requested()) return fail(Errc::cancelled);
    const auto now = Clock::now();
    if (io.deadline && *io.deadline <= now) return fail(Errc::timed_out);
    if (options.timeout <= std::chrono::milliseconds::zero() ||
        options.timeout > std::chrono::hours{24} || options.limits.max_message_size < 12 ||
        options.max_discarded_packets > 65536) return fail(Errc::invalid_argument);
    const auto deadline = now + options.timeout;
    if (!io.deadline || deadline < *io.deadline) io.deadline = deadline;
    return io;
}

inline Result<std::vector<std::byte>> wire_question(Message& question) {
    if (question.header.qr || question.header.opcode != 0 || question.questions.size() != 1)
        return fail(Errc::invalid_argument);
    // Fresh transaction ID; callers still need a dedicated socket/connection.
    std::random_device random;
    question.header.id = static_cast<std::uint16_t>(random());
    return encode(question);
}

template<BoundedReadStream Stream>
Task<Result<void>> read_dns_exact(Stream& stream, std::span<std::byte> output, OperationOptions io) {
    while (!output.empty()) {
        const auto count = co_await stream.read_some(output, io);
        if (!count) co_return fail(count.error());
        if (*count == 0) co_return fail(Errc::eof);
        if (*count > output.size()) co_return fail(Errc::invalid_argument);
        output = output.subspan(*count);
    }
    co_return Result<void>{};
}
}  // namespace detail

/// One asynchronous UDP DNS exchange using only send_to/receive_from and peer
/// equality, with no OS or transport dependency. Exclusively borrow the socket
/// until completion. Cancellation/deadlines finish through the underlying I/O;
/// no worker threads or getaddrinfo calls are involved. Mismatched peers, IDs,
/// and questions are discarded up to a bound. TC returns truncated: the caller
/// may explicitly establish TCP and call query_tcp. RCODE, including NXDOMAIN,
/// is preserved. No NSS/search domains, retries, automatic fallback or DNSSEC.
template<class Datagram, std::equality_comparable Peer>
requires requires(Datagram& socket, std::span<const std::byte> out,
                  std::span<std::byte> in, Peer peer, OperationOptions io) {
    { socket.send_to(out, peer, io) } -> std::same_as<Task<Result<std::size_t>>>;
    socket.receive_from(in, io);
}
[[nodiscard]] Task<Result<Message>> query_udp(Datagram& socket, Peer peer, Message question,
                                              OperationOptions io = {}, WireQueryOptions options = {}) {
    const auto budget = detail::query_budget(io, options);
    if (!budget) co_return fail(budget.error());
    io = *budget;
    auto wire = detail::wire_question(question);
    if (!wire) co_return fail(wire.error());
    options.limits.max_message_size = (std::min)(options.limits.max_message_size, std::size_t{65535});
    if (wire->size() > options.limits.max_message_size) co_return fail(DnsError::too_large);
    const auto sent = co_await socket.send_to(*wire, peer, io);
    if (!sent) co_return fail(sent.error());
    if (*sent != wire->size()) co_return fail(std::make_error_code(std::errc::message_size));
    std::vector<std::byte> input(options.limits.max_message_size);
    for (std::size_t discarded = 0;; ++discarded) {
        const auto received = co_await socket.receive_from(input, io);
        if (!received) co_return fail(received.error());
        if (received->size > input.size()) co_return fail(DnsError::too_large);
        if (received->peer == peer) {
            const auto bytes = std::span<const std::byte>{input}.first(received->size);
            if (bytes.size() >= 2 && bytes[0] == (*wire)[0] && bytes[1] == (*wire)[1]) {
                auto response = decode(bytes, options.limits);
                if (!response) co_return fail(response.error());
                if (answers(question, *response)) {
                    if (response->header.tc) co_return fail(DnsError::truncated);
                    co_return std::move(*response);
                }
            }
        }
        if (discarded >= options.max_discarded_packets) co_return fail(DnsError::mismatched_response);
    }
}

/// One DNS-over-TCP exchange with a two-byte network-order length prefix.
/// Exclusively borrow an established connection. Close the stream after any
/// failure: cancellation or a short read may have consumed a partial frame.
/// No background state or destructor join; cancel/close the underlying I/O.
template<BoundedStream Stream>
[[nodiscard]] Task<Result<Message>> query_tcp(Stream& stream, Message question,
                                              OperationOptions io = {}, WireQueryOptions options = {}) {
    const auto budget = detail::query_budget(io, options);
    if (!budget) co_return fail(budget.error());
    io = *budget;
    auto wire = detail::wire_question(question);
    if (!wire) co_return fail(wire.error());
    options.limits.max_message_size = (std::min)(options.limits.max_message_size, std::size_t{65535});
    if (wire->size() > options.limits.max_message_size) co_return fail(DnsError::too_large);
    const std::array prefix{static_cast<std::byte>(wire->size() >> 8), static_cast<std::byte>(wire->size() & 255U)};
    auto written = co_await write_all(stream, prefix, io);
    if (!written) co_return fail(written.error());
    written = co_await write_all(stream, *wire, io);
    if (!written) co_return fail(written.error());
    std::array<std::byte, 2> length{};
    auto read = co_await detail::read_dns_exact(stream, length, io);
    if (!read) co_return fail(read.error());
    const std::size_t size = (std::to_integer<std::size_t>(length[0]) << 8) |
                             std::to_integer<std::size_t>(length[1]);
    if (size < 12) co_return fail(DnsError::truncated);
    if (size > options.limits.max_message_size) co_return fail(DnsError::too_large);
    std::vector<std::byte> input(size);
    read = co_await detail::read_dns_exact(stream, input, io);
    if (!read) co_return fail(read.error());
    auto response = decode(input, options.limits);
    if (!response) co_return fail(response.error());
    if (!answers(question, *response)) co_return fail(DnsError::mismatched_response);
    if (response->header.tc) co_return fail(DnsError::truncated);
    co_return std::move(*response);
}

}  // namespace Mira::dns
