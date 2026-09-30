#include "mira/transport/tcp.hpp"

#include "socket_compat.hpp"

#include <array>

namespace Mira::transport::tcp {
namespace {

/// Scratch space for `getsockname`/`getpeername`, sized for `sockaddr_in6`.
using AddressScratch = std::array<std::byte, 128>;

}  // namespace

// ── Socket ───────────────────────────────────────────────────────────────────

Task<Result<std::size_t>> Socket::read_some(std::span<std::byte> destination,
                                            OperationOptions options) {
    if (loop_ == nullptr || handle_ == invalid_handle) {
        co_return fail(Errc::invalid_argument);
    }
    co_return co_await loop_->read(handle_, destination, std::move(options));
}

Task<Result<std::size_t>> Socket::write_some(std::span<const std::byte> source,
                                             OperationOptions options) {
    if (loop_ == nullptr || handle_ == invalid_handle) {
        co_return fail(Errc::invalid_argument);
    }
    co_return co_await loop_->write(handle_, source, std::move(options));
}

Task<Result<std::size_t>> Socket::writev_some(
    std::span<const std::span<const std::byte>> pieces, OperationOptions options) {
    if (loop_ == nullptr || handle_ == invalid_handle) {
        co_return fail(Errc::invalid_argument);
    }
    co_return co_await loop_->writev(handle_, pieces, std::move(options));
}

Result<Endpoint> Socket::peer_endpoint() const {
    if (handle_ == invalid_handle) {
        return fail(Errc::invalid_argument);
    }
    AddressScratch scratch{};
    Result<std::size_t> length =
        detail::peer_address(static_cast<detail::socket_t>(handle_), scratch);
    if (!length) {
        return fail(length.error());
    }
    return Endpoint::from_bytes(std::span<const std::byte>{scratch.data(), *length});
}

Result<Endpoint> Socket::local_endpoint() const {
    if (handle_ == invalid_handle) {
        return fail(Errc::invalid_argument);
    }
    AddressScratch scratch{};
    Result<std::size_t> length =
        detail::local_address(static_cast<detail::socket_t>(handle_), scratch);
    if (!length) {
        return fail(length.error());
    }
    return Endpoint::from_bytes(std::span<const std::byte>{scratch.data(), *length});
}

Result<void> Socket::shutdown_send() {
    if (handle_ == invalid_handle) {
        return fail(Errc::invalid_argument);
    }
    return detail::shutdown_write(static_cast<detail::socket_t>(handle_));
}

void Socket::close() noexcept {
    if (handle_ == invalid_handle) {
        return;
    }
    // Publish the closed state before detach can resume user code. A resumed
    // cancellation handler may close (or destroy) this wrapper reentrantly.
    const NativeHandle handle = std::exchange(handle_, invalid_handle);
    EventLoop* loop = std::exchange(loop_, nullptr);
    if (loop != nullptr) {
        loop->detach(handle);
    }
    // No access to this after resuming user code.
    detail::close_socket(static_cast<detail::socket_t>(handle));
}

// ── Listener ─────────────────────────────────────────────────────────────────

Result<Listener> Listener::bind(EventLoop& loop, const Endpoint& endpoint, ListenOptions options) {
    Result<detail::socket_t> created = detail::create_tcp_socket(endpoint.native_family());
    if (!created) {
        return fail(created.error());
    }
    const detail::socket_t socket = *created;

    // Bind semantics before bind(), obviously — but also before anything else,
    // because this is the option that has to behave identically on every
    // platform and the rest are conveniences.
    Result<void> applied =
        detail::apply_exclusive_bind(socket, options.exclusive, options.reuse_after_close);
    if (!applied) {
        detail::close_socket(socket);
        return fail(applied.error());
    }

    if (endpoint.family() == Family::ipv6) {
        Result<void> dual = detail::apply_dual_stack(socket, options.dual_stack);
        if (!dual) {
            detail::close_socket(socket);
            return fail(dual.error());
        }
    }

    Result<void> bound = detail::bind_socket(socket, endpoint.address_bytes());
    if (!bound) {
        detail::close_socket(socket);
        return fail(bound.error());
    }

    Result<void> listening = detail::listen_socket(socket, options.backlog);
    if (!listening) {
        detail::close_socket(socket);
        return fail(listening.error());
    }

    // Read the bound address back so a port-0 bind reports its real port.
    AddressScratch scratch{};
    Result<std::size_t> length = detail::local_address(socket, scratch);
    if (!length) {
        detail::close_socket(socket);
        return fail(length.error());
    }
    Result<Endpoint> local =
        Endpoint::from_bytes(std::span<const std::byte>{scratch.data(), *length});
    if (!local) {
        detail::close_socket(socket);
        return fail(local.error());
    }

    Result<void> attached = loop.attach(static_cast<NativeHandle>(socket));
    if (!attached) {
        detail::close_socket(socket);
        return fail(attached.error());
    }

    Listener listener;
    listener.loop_ = &loop;
    listener.handle_ = static_cast<NativeHandle>(socket);
    listener.local_ = *local;
    listener.options_ = options;
    return listener;
}

Task<Result<Socket>> Listener::accept(OperationOptions options) {
    if (loop_ == nullptr || handle_ == invalid_handle) {
        co_return fail(Errc::invalid_argument);
    }

    EventLoop* loop = loop_;
    const NativeHandle listening = handle_;
    const bool no_delay = options_.no_delay;
    Result<NativeHandle> accepted =
        co_await loop->accept(listening, local_.native_family(), std::move(options));
    if (!accepted) {
        co_return fail(accepted.error());
    }

    Socket socket{*loop, *accepted};
    // The loop rejects an accept whose listener was detached before delivery.
    // The wrapper itself may already have been destroyed by another callback.

    // Per-connection options are applied here rather than inherited: Windows
    // does not propagate all listener options to accepted sockets, so relying
    // on inheritance would work on POSIX and quietly differ on Windows.
    Result<void> nodelay =
        detail::apply_no_delay(static_cast<detail::socket_t>(*accepted), no_delay);
    if (!nodelay) {
        co_return fail(nodelay.error());
    }

    co_return socket;
}

void Listener::close() noexcept {
    if (handle_ == invalid_handle) {
        return;
    }
    const NativeHandle handle = std::exchange(handle_, invalid_handle);
    EventLoop* loop = std::exchange(loop_, nullptr);
    if (loop != nullptr) {
        loop->detach(handle);
    }
    detail::close_socket(static_cast<detail::socket_t>(handle));
}

// ── connect ──────────────────────────────────────────────────────────────────

Task<Result<Socket>> connect(EventLoop& loop,
                             Endpoint endpoint,
                             ConnectOptions options,
                             OperationOptions io) {
    Result<detail::socket_t> created = detail::create_tcp_socket(endpoint.native_family());
    if (!created) {
        co_return fail(created.error());
    }
    const detail::socket_t socket = *created;

    Result<void> attached = loop.attach(static_cast<NativeHandle>(socket));
    if (!attached) {
        detail::close_socket(socket);
        co_return fail(attached.error());
    }

    // Wrap before awaiting: if the connect fails or the coroutine is dropped,
    // the Socket destructor closes the descriptor rather than leaking it.
    Socket wrapper{loop, static_cast<NativeHandle>(socket)};

    Result<void> connected = co_await loop.connect(
        static_cast<NativeHandle>(socket), endpoint.address_bytes(), std::move(io));
    if (!connected) {
        co_return fail(connected.error());
    }

    Result<void> nodelay = detail::apply_no_delay(socket, options.no_delay);
    if (!nodelay) {
        co_return fail(nodelay.error());
    }

    co_return wrapper;
}

}  // namespace Mira::transport::tcp
