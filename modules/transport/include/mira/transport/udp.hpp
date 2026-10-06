#pragma once

#include "mira/core/event_loop.hpp"
#include "mira/transport/endpoint.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

namespace Mira::transport::udp {

struct BindOptions {
    bool dual_stack{false};
    /// Opt into shared binding, mainly for multicast; exclusive by default.
    bool reuse_address{false};
    /// Options follow the socket family; IPv4-mapped packets on dual-stack
    /// sockets are not guaranteed to carry every requested metadata field.
    bool receive_packet_info{false};
    bool receive_traffic_class{false};
    bool receive_timestamp{false};
};

struct PacketMetadata {
    std::optional<Endpoint> destination;
    std::optional<std::uint32_t> interface_index;
    /// Full IPv4 TOS / IPv6 traffic class; the low two bits carry ECN.
    std::optional<std::uint8_t> traffic_class{};
    /// Kernel receive time in system_clock, not monotonic or hardware time.
    std::optional<std::chrono::system_clock::time_point> timestamp;
    bool truncated{false};
};

struct Datagram {
    std::size_t size{0};
    Endpoint peer;
    PacketMetadata metadata{};
};

struct SendOptions {
    /// Select only the source IP; port must be zero or the socket's local port.
    std::optional<Endpoint> source{};
    /// Follows native pktinfo semantics; an IPv4 interface may override source IP.
    std::uint32_t interface_index{0};
    std::optional<std::uint8_t> traffic_class{};
};

struct MulticastInterface {
    /// Select an IPv4 interface by local address; 0.0.0.0 uses the system default.
    Endpoint ipv4_address{Endpoint::any(0)};
    /// IPv6 interface index; zero uses the default. Link-scope groups usually
    /// require an explicit index.
    std::uint32_t ipv6_index{0};
};

/// Single-threaded, completion-based datagram transport; not an AsyncStream.
/// Only one in-flight operation per direction; send and receive may proceed
/// simultaneously; conflicts return invalid_argument. Zero-length datagrams
/// are valid, and a zero-length receive buffer also consumes one datagram;
/// truncation returns message_size and discards the tail. The caller must keep
/// the Task and borrowed buffers alive until completion; close cancels but
/// does not synchronously drain IOCP. The EventLoop must outlive the Socket.
/// Moving or destroying the wrapper does not affect the state of started
/// operations.
class Socket {
public:
    Socket() = default;
    Socket(Socket&&) noexcept = default;
    Socket& operator=(Socket&& other) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    ~Socket();

    /// Exclusive by default; reuse_address opts into SO_REUSEADDR. Port zero
    /// selects a system-assigned port. Unsupported metadata requests fail with
    /// not_supported rather than being silently ignored.
    [[nodiscard]] static Result<Socket>
    bind(EventLoop& loop, const Endpoint& endpoint, BindOptions options = {});
    [[nodiscard]] Result<Endpoint> local_endpoint() const;
    [[nodiscard]] NativeHandle native_handle() const noexcept;
    [[nodiscard]] bool is_open() const noexcept;
    void close() noexcept;

    /// ASM membership ignores the group's port; closing leaves all groups.
    /// The OS reports duplicate membership or missing interfaces. No SSM support.
    [[nodiscard]] Result<void> join_multicast(Endpoint group, MulticastInterface interface = {});
    [[nodiscard]] Result<void> leave_multicast(Endpoint group, MulticastInterface interface = {});
    [[nodiscard]] Result<void> set_multicast_interface(MulticastInterface interface);
    [[nodiscard]] Result<void> set_multicast_hops(unsigned hops);
    [[nodiscard]] Result<void> set_multicast_loopback(bool enabled);

    /// peer is captured by value, so a lazily started or suspended Task does
    /// not require the caller's Endpoint to stay alive.
    [[nodiscard]] Task<Result<std::size_t>>
    send_to(std::span<const std::byte> source, Endpoint peer, OperationOptions options = {});
    /// POSIX sendmsg selects source/interface/traffic class per packet.
    /// IOCP currently rejects nonempty packet options with not_supported.
    [[nodiscard]] Task<Result<std::size_t>>
    send_message(std::span<const std::byte> source, Endpoint peer,
                 SendOptions packet, OperationOptions options = {});
    [[nodiscard]] Task<Result<Datagram>> receive_from(std::span<std::byte> destination,
                                                      OperationOptions options = {});

private:
    struct State;
    static Task<Result<std::size_t>> send(std::shared_ptr<State> state,
                                          std::span<const std::byte> source,
                                          Endpoint peer,
                                          SendOptions packet,
                                          OperationOptions options);
    Result<void> membership(Endpoint group, MulticastInterface interface, bool join);
    static Task<Result<Datagram>> receive(std::shared_ptr<State> state,
                                          std::span<std::byte> destination,
                                          OperationOptions options);
    std::shared_ptr<State> state_;
};

}  // namespace Mira::transport::udp
