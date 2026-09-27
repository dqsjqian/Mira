#pragma once

#include "mira/core/event_loop.hpp"
#include "mira/transport/endpoint.hpp"

#include <memory>
#include <utility>

namespace Mira::transport::udp {

struct BindOptions {
    bool dual_stack{false};
};

struct Datagram {
    std::size_t size{0};
    Endpoint peer;
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

    /// Exclusive bind; SO_REUSEADDR/SO_REUSEPORT are not enabled. Port 0 is
    /// assigned by the system.
    [[nodiscard]] static Result<Socket>
    bind(EventLoop& loop, const Endpoint& endpoint, BindOptions options = {});
    [[nodiscard]] Result<Endpoint> local_endpoint() const;
    [[nodiscard]] NativeHandle native_handle() const noexcept;
    [[nodiscard]] bool is_open() const noexcept;
    void close() noexcept;

    /// peer is captured by value, so a lazily started or suspended Task does
    /// not require the caller's Endpoint to stay alive.
    [[nodiscard]] Task<Result<std::size_t>>
    send_to(std::span<const std::byte> source, Endpoint peer, OperationOptions options = {});
    [[nodiscard]] Task<Result<Datagram>> receive_from(std::span<std::byte> destination,
                                                      OperationOptions options = {});

private:
    struct State;
    static Task<Result<std::size_t>> send(std::shared_ptr<State> state,
                                          std::span<const std::byte> source,
                                          Endpoint peer,
                                          OperationOptions options);
    static Task<Result<Datagram>> receive(std::shared_ptr<State> state,
                                          std::span<std::byte> destination,
                                          OperationOptions options);
    std::shared_ptr<State> state_;
};

}  // namespace Mira::transport::udp
