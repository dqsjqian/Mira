#pragma once

// Mira/transport/tcp.hpp — TCP listeners and connections.
//
// `Socket` models `Mira::AsyncStream`, so a protocol written against the
// concept accepts one without naming it. `Listener` owns the bind semantics,
// which is where this library began: see `ListenOptions::exclusive`.

#include "mira/core/error.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/operation.hpp"
#include "mira/core/platform.hpp"
#include "mira/core/task.hpp"
#include "mira/transport/endpoint.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace Mira::transport::tcp {

/// How a listening socket treats an address that is already in use.
///
/// This option exists because the platforms disagree, and the disagreement is
/// silent. `SO_REUSEADDR` on POSIX permits rebinding a port left in TIME_WAIT;
/// the same constant on Windows lets a second process **steal** a port another
/// process is actively bound to, so two servers "successfully" listen on one
/// port and split the incoming connections between them.
///
/// Mira therefore does not expose `SO_REUSEADDR` as a portable flag. It
/// exposes the *intent*, and each backend implements it with whatever option
/// actually produces that behaviour — `SO_EXCLUSIVEADDRUSE` on Windows,
/// plain `SO_REUSEADDR`-off on POSIX.
struct ListenOptions {
    /// Refuse to bind a port another socket is actively using.
    ///
    /// On by default, and on *every* platform: a second `bind()` to a live
    /// port fails rather than silently succeeding. Turning this off enables
    /// port sharing (`SO_REUSEPORT`) for deliberate multi-process accept.
    bool exclusive = true;

    /// Allow rebinding a port still in TIME_WAIT from a previous run.
    ///
    /// On by default because the alternative is a server that cannot restart
    /// for a minute after exiting. Independent of `exclusive`: this concerns
    /// dead sockets, that one concerns live ones.
    bool reuse_after_close = true;

    /// Pending-connection queue depth handed to `listen()`.
    int backlog = 128;

    /// Disable Nagle's algorithm on accepted connections.
    ///
    /// On by default: a request/response protocol pays ~40ms of latency per
    /// exchange for a bandwidth optimisation it does not want.
    bool no_delay = true;

    /// Accept IPv4 connections on an IPv6 listener (dual-stack).
    bool dual_stack = true;
};

/// A connected TCP stream. Models `Mira::AsyncStream`.
class Socket {
public:
    Socket() = default;
    Socket(EventLoop& loop, NativeHandle handle) noexcept : loop_(&loop), handle_(handle) {}

    Socket(Socket&& other) noexcept
        : loop_(std::exchange(other.loop_, nullptr)),
          handle_(std::exchange(other.handle_, invalid_handle)) {}

    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            auto previous = std::move(*this);
            loop_ = std::exchange(other.loop_, nullptr);
            handle_ = std::exchange(other.handle_, invalid_handle);
            return *this;  // Form the result before previous.close() resumes user code.
        }
        return *this;
    }

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    ~Socket() { close(); }

    [[nodiscard]] bool valid() const noexcept { return handle_ != invalid_handle; }
    [[nodiscard]] explicit operator bool() const noexcept { return valid(); }
    [[nodiscard]] NativeHandle native_handle() const noexcept { return handle_; }

    /// Read once; short reads are normal. `Errc::eof` on a clean close.
    ///
    /// `options` is forwarded to the event loop unchanged, so the rules in
    /// `operation.hpp` apply here as written — including that a cancelled read
    /// on Windows may discard bytes the kernel had already moved, which makes
    /// the connection unfit for reuse.
    [[nodiscard]] Task<Result<std::size_t>> read_some(std::span<std::byte> destination,
                                                      OperationOptions options = {});

    /// Write once; short writes are normal.
    [[nodiscard]] Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                                       OperationOptions options = {});

    /// Write several buffers in one submission (writev/WSASend); short
    /// writes are normal. The kernel gathers — a response head and body go
    /// out without being concatenated first.
    [[nodiscard]] Task<Result<std::size_t>>
    writev_some(std::span<const std::span<const std::byte>> pieces,
                OperationOptions options = {});

    /// Address of the peer, as reported by the OS.
    [[nodiscard]] Result<Endpoint> peer_endpoint() const;

    /// Local address, as reported by the OS.
    [[nodiscard]] Result<Endpoint> local_endpoint() const;

    /// Send a FIN without discarding buffered incoming data.
    ///
    /// The correct way to end an HTTP response on a connection the peer may
    /// still be reading from: closing outright can discard data in flight.
    Result<void> shutdown_send();

    /// Close the socket and detach it from the loop.
    void close() noexcept;

private:
    EventLoop* loop_{nullptr};
    NativeHandle handle_{invalid_handle};
};

/// A listening TCP socket.
class Listener {
public:
    /// Bind and start listening, or report why not.
    ///
    /// Binding a port that is already actively bound fails with
    /// `std::errc::address_in_use` on every platform when `exclusive` is set —
    /// which is the default. That uniformity is the whole point of the option.
    [[nodiscard]] static Result<Listener>
    bind(EventLoop& loop, const Endpoint& endpoint, ListenOptions options = {});

    Listener(Listener&& other) noexcept
        : loop_(std::exchange(other.loop_, nullptr)),
          handle_(std::exchange(other.handle_, invalid_handle)),
          local_(other.local_),
          options_(other.options_) {}

    Listener& operator=(Listener&& other) noexcept {
        if (this != &other) {
            auto previous = std::move(*this);
            loop_ = std::exchange(other.loop_, nullptr);
            handle_ = std::exchange(other.handle_, invalid_handle);
            local_ = other.local_;
            options_ = other.options_;
            return *this;
        }
        return *this;
    }

    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

    ~Listener() { close(); }

    /// Accept one connection.
    ///
    /// A cancelled or timed-out accept produces no socket: any connection the
    /// kernel had already prepared is closed rather than leaked.
    [[nodiscard]] Task<Result<Socket>> accept(OperationOptions options = {});

    /// The address actually bound — resolves port 0 to the assigned port,
    /// which is how a test binds without guessing a free port.
    [[nodiscard]] const Endpoint& local_endpoint() const noexcept { return local_; }

    [[nodiscard]] NativeHandle native_handle() const noexcept { return handle_; }

    void close() noexcept;

private:
    Listener() = default;

    EventLoop* loop_{nullptr};
    NativeHandle handle_{invalid_handle};
    Endpoint local_{};
    ListenOptions options_{};
};

/// Options for an outgoing connection.
struct ConnectOptions {
    /// Disable Nagle's algorithm. See `ListenOptions::no_delay`.
    bool no_delay = true;
};

/// Connect to `endpoint`.
///
/// `options` configures the socket and may be reused across calls; `io` is
/// per-call and must not be, since it carries a stop token and an absolute
/// deadline. Keeping them apart is deliberate: an `OperationOptions` stored
/// inside a reusable configuration struct is a deadline that silently belongs
/// to whichever call ran first.
///
/// A cancelled connect abandons the *wait*. The kernel's attempt carries on,
/// so the returned failure leaves nothing for the caller to reuse — the socket
/// this function created is closed on the way out.
[[nodiscard]] Task<Result<Socket>> connect(EventLoop& loop,
                                           Endpoint endpoint,
                                           ConnectOptions options = {},
                                           OperationOptions io = {});

}  // namespace Mira::transport::tcp
