#include "mira/transport/udp.hpp"

#include "socket_compat.hpp"

namespace Mira::transport::udp {

struct Socket::State {
    EventLoop* loop{nullptr};
    NativeHandle handle{invalid_handle};
    Endpoint local;
};

Socket::~Socket() {
    close();
}

Socket& Socket::operator=(Socket&& other) noexcept {
    Socket previous;
    if (this != &other) {
        // The new state is in place first; cancelling the old state may resume
        // user code, after which members are no longer accessed.
        previous.state_ = std::exchange(state_, std::move(other.state_));
    }
    return *this;
}

Result<Socket> Socket::bind(EventLoop& loop, const Endpoint& endpoint, BindOptions options) {
    if (endpoint.address_bytes().empty()) return fail(Errc::invalid_argument);
#if MIRA_PLATFORM_WINDOWS
    const auto handle = ::WSASocketW(
        endpoint.native_family(), SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
#else
    const auto handle = ::socket(endpoint.native_family(), SOCK_DGRAM, IPPROTO_UDP);
#endif
    if (handle == detail::invalid_socket) return fail(detail::last_socket_error());
    struct Guard {
        detail::socket_t handle;
        ~Guard() { detail::close_socket(handle); }
    } guard{handle};
#if MIRA_PLATFORM_WINDOWS
    const auto exclusive = detail::set_flag(handle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, true);
    if (!exclusive) return fail(exclusive.error());
#else
    const int flags = ::fcntl(handle, F_GETFD, 0);
    if (flags < 0 || ::fcntl(handle, F_SETFD, flags | FD_CLOEXEC) < 0)
        return fail(detail::last_socket_error());
#endif
    if (endpoint.family() == Family::ipv6) {
        const auto dual = detail::apply_dual_stack(handle, options.dual_stack);
        if (!dual) return fail(dual.error());
    }
    const auto bound = detail::bind_socket(handle, endpoint.address_bytes());
    if (!bound) return fail(bound.error());
    alignas(std::max_align_t) std::array<std::byte, 128> scratch{};
    const auto length = detail::local_address(handle, scratch);
    if (!length) return fail(length.error());
    const auto local = Endpoint::from_bytes({scratch.data(), *length});
    if (!local) return fail(local.error());
    Socket socket;
    socket.state_ = std::make_shared<State>();
    const auto attached = loop.attach(static_cast<NativeHandle>(handle));
    if (!attached) return fail(attached.error());
    socket.state_->loop = &loop;
    socket.state_->local = *local;
    socket.state_->handle =
        static_cast<NativeHandle>(std::exchange(guard.handle, detail::invalid_socket));
    return socket;
}

Result<Endpoint> Socket::local_endpoint() const {
    if (!is_open()) return fail(Errc::invalid_argument);
    return state_->local;
}

NativeHandle Socket::native_handle() const noexcept {
    return state_ ? state_->handle : invalid_handle;
}

bool Socket::is_open() const noexcept {
    return native_handle() != invalid_handle;
}

void Socket::close() noexcept {
    // detach may synchronously resume coroutines and destroy the wrapper;
    // only local state is used afterwards.
    auto state = std::exchange(state_, {});
    if (!state || state->handle == invalid_handle) return;
    const NativeHandle handle = std::exchange(state->handle, invalid_handle);
    EventLoop* loop = std::exchange(state->loop, nullptr);
    loop->detach(handle);
    detail::close_socket(static_cast<detail::socket_t>(handle));
}

Task<Result<std::size_t>>
Socket::send_to(std::span<const std::byte> source, Endpoint peer, OperationOptions options) {
    return send(state_, source, std::move(peer), std::move(options));
}

Task<Result<Datagram>> Socket::receive_from(std::span<std::byte> destination,
                                            OperationOptions options) {
    return receive(state_, destination, std::move(options));
}

Task<Result<std::size_t>> Socket::send(std::shared_ptr<State> state,
                                       std::span<const std::byte> source,
                                       Endpoint peer,
                                       OperationOptions options) {
    if (!state || state->handle == invalid_handle) co_return fail(Errc::invalid_argument);
    co_return co_await state->loop->send_to(state->handle, source, peer.address_bytes(), options);
}

Task<Result<Datagram>> Socket::receive(std::shared_ptr<State> state,
                                       std::span<std::byte> destination,
                                       OperationOptions options) {
    if (!state || state->handle == invalid_handle) co_return fail(Errc::invalid_argument);
    const auto result = co_await state->loop->receive_from(state->handle, destination, options);
    if (!result) co_return fail(result.error());
    const auto peer = Endpoint::from_bytes({result->address.data(), result->address_size});
    if (!peer) co_return fail(peer.error());
    co_return Datagram{result->size, *peer};
}

}  // namespace Mira::transport::udp
