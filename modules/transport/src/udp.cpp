#include "mira/transport/udp.hpp"

#if MIRA_PLATFORM_APPLE
#define __APPLE_USE_RFC_3542 1
#endif
#include "socket_compat.hpp"

#include <limits>
#if !MIRA_PLATFORM_WINDOWS
#include <sys/time.h>
#endif

namespace Mira::transport::udp {
namespace {

Error option_error() {
    const auto error = detail::last_socket_error();
    if (error == std::errc::no_protocol_option || error == std::errc::operation_not_supported)
        return std::make_error_code(std::errc::not_supported);
    return error;
}

template<class T>
Result<void> set_option(detail::socket_t socket, int level, int option, const T& value) {
    if (::setsockopt(socket, level, option, reinterpret_cast<const char*>(&value),
                     static_cast<detail::socklen_type>(sizeof(value))) != 0)
        return fail(option_error());
    return {};
}

Result<void> configure_metadata(detail::socket_t socket, Family family, BindOptions options) {
#if MIRA_PLATFORM_WINDOWS
    (void)socket;
    (void)family;
    if (options.receive_packet_info || options.receive_traffic_class || options.receive_timestamp)
        return fail(std::make_error_code(std::errc::not_supported));
#else
    if (options.receive_packet_info) {
        Result<void> configured = fail(std::make_error_code(std::errc::not_supported));
        if (family == Family::ipv4) {
#if defined(IP_PKTINFO)
            configured = set_option(socket, IPPROTO_IP, IP_PKTINFO, 1);
#endif
        } else {
#if defined(IPV6_RECVPKTINFO) && defined(IPV6_PKTINFO)
            configured = set_option(socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1);
#endif
        }
        if (!configured) return configured;
    }
    if (options.receive_traffic_class) {
        Result<void> configured = fail(std::make_error_code(std::errc::not_supported));
        if (family == Family::ipv4) {
#if defined(IP_RECVTOS)
            configured = set_option(socket, IPPROTO_IP, IP_RECVTOS, 1);
#endif
        } else {
#if defined(IPV6_RECVTCLASS)
            configured = set_option(socket, IPPROTO_IPV6, IPV6_RECVTCLASS, 1);
#endif
        }
        if (!configured) return configured;
    }
    if (options.receive_timestamp) {
#if defined(SO_TIMESTAMPNS)
        return set_option(socket, SOL_SOCKET, SO_TIMESTAMPNS, 1);
#elif defined(SO_TIMESTAMP)
        return set_option(socket, SOL_SOCKET, SO_TIMESTAMP, 1);
#else
        return fail(std::make_error_code(std::errc::not_supported));
#endif
    }
#endif
    return {};
}

#if !MIRA_PLATFORM_WINDOWS
template<class T>
bool control_value(const cmsghdr& header, T& value) {
    if (header.cmsg_len < CMSG_LEN(sizeof(T))) return false;
    std::memcpy(&value, CMSG_DATA(const_cast<cmsghdr*>(&header)), sizeof(T));
    return true;
}

PacketMetadata packet_metadata(EventLoop::DatagramResult& raw, std::uint16_t port) {
    PacketMetadata metadata;
    metadata.truncated = raw.control_truncated;
    msghdr message{};
    message.msg_control = raw.control.data();
    message.msg_controllen = static_cast<decltype(message.msg_controllen)>(raw.control_size);
    for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
#if defined(IP_PKTINFO)
        if (header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_PKTINFO) {
            in_pktinfo info{};
            if (control_value(*header, info)) {
                sockaddr_in address{};
                address.sin_family = AF_INET;
                address.sin_port = htons(port);
                address.sin_addr = info.ipi_addr;
                const auto endpoint = Endpoint::from_bytes({reinterpret_cast<const std::byte*>(&address), sizeof(address)});
                if (endpoint) metadata.destination = *endpoint;
                metadata.interface_index = static_cast<std::uint32_t>(info.ipi_ifindex);
            }
        }
#endif
#if defined(IPV6_PKTINFO)
        if (header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_PKTINFO) {
            in6_pktinfo info{};
            if (control_value(*header, info)) {
                sockaddr_in6 address{};
                address.sin6_family = AF_INET6;
                address.sin6_port = htons(port);
                address.sin6_addr = info.ipi6_addr;
                if (IN6_IS_ADDR_LINKLOCAL(&address.sin6_addr) || IN6_IS_ADDR_MULTICAST(&address.sin6_addr))
                    address.sin6_scope_id = info.ipi6_ifindex;
                const auto endpoint = Endpoint::from_bytes({reinterpret_cast<const std::byte*>(&address), sizeof(address)});
                if (endpoint) metadata.destination = *endpoint;
                metadata.interface_index = info.ipi6_ifindex;
            }
        }
#endif
        if (header->cmsg_level == IPPROTO_IP &&
            (header->cmsg_type == IP_TOS
#if defined(IP_RECVTOS)
             || header->cmsg_type == IP_RECVTOS
#endif
            )) {
            std::uint8_t value{};
            int wide{};
            if (control_value(*header, wide)) metadata.traffic_class = static_cast<std::uint8_t>(wide);
            else if (control_value(*header, value)) metadata.traffic_class = value;
        }
#if defined(IPV6_TCLASS)
        if (header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_TCLASS) {
            int value{};
            if (control_value(*header, value)) metadata.traffic_class = static_cast<std::uint8_t>(value);
        }
#endif
#if defined(SCM_TIMESTAMPNS)
        if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_TIMESTAMPNS) {
            timespec value{};
            if (control_value(*header, value)) metadata.timestamp = std::chrono::system_clock::time_point{
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    std::chrono::seconds{value.tv_sec} + std::chrono::nanoseconds{value.tv_nsec})};
        }
#endif
#if defined(SCM_TIMESTAMP)
        if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_TIMESTAMP) {
            timeval value{};
            if (control_value(*header, value)) metadata.timestamp = std::chrono::system_clock::time_point{
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    std::chrono::seconds{value.tv_sec} + std::chrono::microseconds{value.tv_usec})};
        }
#endif
    }
    return metadata;
}

struct SendControl {
    alignas(std::max_align_t) std::array<std::byte, 128> bytes{};
    std::size_t size{0};
    template<class T>
    void append(int level, int type, const T& value) {
        auto* header = reinterpret_cast<cmsghdr*>(bytes.data() + size);
        header->cmsg_level = level;
        header->cmsg_type = type;
        header->cmsg_len = static_cast<decltype(header->cmsg_len)>(CMSG_LEN(sizeof(T)));
        std::memcpy(CMSG_DATA(header), &value, sizeof(T));
        size += CMSG_SPACE(sizeof(T));
    }
};
#endif

}  // namespace

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
    if (!options.reuse_address) {
        const auto exclusive = detail::set_flag(handle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, true);
        if (!exclusive) return fail(exclusive.error());
    }
#else
    const int flags = ::fcntl(handle, F_GETFD, 0);
    if (flags < 0 || ::fcntl(handle, F_SETFD, flags | FD_CLOEXEC) < 0)
        return fail(detail::last_socket_error());
#endif
    if (endpoint.family() == Family::ipv6) {
        const auto dual = detail::apply_dual_stack(handle, options.dual_stack);
        if (!dual) return fail(dual.error());
    }
    if (options.reuse_address) {
        const auto reuse = set_option(handle, SOL_SOCKET, SO_REUSEADDR, 1);
        if (!reuse) return fail(reuse.error());
    }
    const auto metadata = configure_metadata(handle, endpoint.family(), options);
    if (!metadata) return fail(metadata.error());
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

Result<void> Socket::membership(Endpoint group, MulticastInterface interface, bool join) {
    if (!is_open() || group.address_bytes().empty() || group.family() != state_->local.family())
        return fail(Errc::invalid_argument);
    const auto handle = static_cast<detail::socket_t>(state_->handle);
    if (group.family() == Family::ipv4) {
        if (interface.ipv4_address.address_bytes().empty() ||
            interface.ipv4_address.family() != Family::ipv4 || interface.ipv6_index != 0)
            return fail(Errc::invalid_argument);
        sockaddr_in address{}, local{};
        std::memcpy(&address, group.address_bytes().data(), sizeof(address));
        std::memcpy(&local, interface.ipv4_address.address_bytes().data(), sizeof(local));
        if ((ntohl(address.sin_addr.s_addr) & 0xf0000000U) != 0xe0000000U)
            return fail(Errc::invalid_argument);
        ip_mreq request{};
        request.imr_multiaddr = address.sin_addr;
        request.imr_interface = local.sin_addr;
        return set_option(handle, IPPROTO_IP, join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, request);
    }
    sockaddr_in6 address{};
    std::memcpy(&address, group.address_bytes().data(), sizeof(address));
    if (!IN6_IS_ADDR_MULTICAST(&address.sin6_addr)) return fail(Errc::invalid_argument);
    if (address.sin6_scope_id != 0 && interface.ipv6_index != 0 &&
        address.sin6_scope_id != interface.ipv6_index) return fail(Errc::invalid_argument);
    ipv6_mreq request{};
    request.ipv6mr_multiaddr = address.sin6_addr;
    request.ipv6mr_interface = interface.ipv6_index != 0 ? interface.ipv6_index : address.sin6_scope_id;
    return set_option(handle, IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, request);
}

Result<void> Socket::join_multicast(Endpoint group, MulticastInterface interface) {
    return membership(std::move(group), std::move(interface), true);
}
Result<void> Socket::leave_multicast(Endpoint group, MulticastInterface interface) {
    return membership(std::move(group), std::move(interface), false);
}
Result<void> Socket::set_multicast_interface(MulticastInterface interface) {
    if (!is_open()) return fail(Errc::invalid_argument);
    const auto handle = static_cast<detail::socket_t>(state_->handle);
    if (state_->local.family() == Family::ipv6)
        return set_option(handle, IPPROTO_IPV6, IPV6_MULTICAST_IF, interface.ipv6_index);
    if (interface.ipv4_address.address_bytes().empty() ||
        interface.ipv4_address.family() != Family::ipv4 || interface.ipv6_index != 0)
        return fail(Errc::invalid_argument);
    sockaddr_in address{};
    std::memcpy(&address, interface.ipv4_address.address_bytes().data(), sizeof(address));
    return set_option(handle, IPPROTO_IP, IP_MULTICAST_IF, address.sin_addr);
}
Result<void> Socket::set_multicast_hops(unsigned hops) {
    if (!is_open() || hops > 255) return fail(Errc::invalid_argument);
    const auto handle = static_cast<detail::socket_t>(state_->handle);
    if (state_->local.family() == Family::ipv6)
        return set_option(handle, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, static_cast<int>(hops));
#if MIRA_PLATFORM_WINDOWS
    return set_option(handle, IPPROTO_IP, IP_MULTICAST_TTL, static_cast<DWORD>(hops));
#else
    return set_option(handle, IPPROTO_IP, IP_MULTICAST_TTL, static_cast<unsigned char>(hops));
#endif
}
Result<void> Socket::set_multicast_loopback(bool enabled) {
    if (!is_open()) return fail(Errc::invalid_argument);
    const auto handle = static_cast<detail::socket_t>(state_->handle);
    if (state_->local.family() == Family::ipv6)
        return set_option(handle, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, static_cast<unsigned>(enabled));
#if MIRA_PLATFORM_WINDOWS
    return set_option(handle, IPPROTO_IP, IP_MULTICAST_LOOP, static_cast<DWORD>(enabled));
#else
    return set_option(handle, IPPROTO_IP, IP_MULTICAST_LOOP, static_cast<unsigned char>(enabled));
#endif
}

Task<Result<std::size_t>>
Socket::send_to(std::span<const std::byte> source, Endpoint peer, OperationOptions options) {
    return send(state_, source, std::move(peer), {}, std::move(options));
}

Task<Result<std::size_t>> Socket::send_message(std::span<const std::byte> source, Endpoint peer,
                                              SendOptions packet, OperationOptions options) {
    return send(state_, source, std::move(peer), std::move(packet), std::move(options));
}

Task<Result<Datagram>> Socket::receive_from(std::span<std::byte> destination,
                                            OperationOptions options) {
    return receive(state_, destination, std::move(options));
}

Task<Result<std::size_t>> Socket::send(std::shared_ptr<State> state,
                                       std::span<const std::byte> source,
                                       Endpoint peer,
                                       SendOptions packet,
                                       OperationOptions options) {
    if (!state || state->handle == invalid_handle) co_return fail(Errc::invalid_argument);
    if (options.stop.stop_requested()) co_return fail(Errc::cancelled);
    if (options.deadline && *options.deadline <= Clock::now()) co_return fail(Errc::timed_out);
    if (!packet.source && packet.interface_index == 0 && !packet.traffic_class)
        co_return co_await state->loop->send_to(state->handle, source, peer.address_bytes(), options);
    if (peer.address_bytes().empty() || peer.family() != state->local.family() ||
        (packet.source && (packet.source->address_bytes().empty() ||
            packet.source->family() != peer.family() ||
            (packet.source->port() != 0 && packet.source->port() != state->local.port()))))
        co_return fail(Errc::invalid_argument);
#if MIRA_PLATFORM_WINDOWS
    co_return fail(std::make_error_code(std::errc::not_supported));
#else
    SendControl control;
    if (packet.source || packet.interface_index != 0) {
        if (peer.family() == Family::ipv4) {
#if defined(IP_PKTINFO)
            if (packet.interface_index > static_cast<std::uint32_t>((std::numeric_limits<int>::max)()))
                co_return fail(Errc::invalid_argument);
            in_pktinfo info{};
            info.ipi_ifindex = static_cast<decltype(info.ipi_ifindex)>(packet.interface_index);
            if (packet.source) {
                sockaddr_in address{};
                std::memcpy(&address, packet.source->address_bytes().data(), sizeof(address));
                info.ipi_spec_dst = address.sin_addr;
            }
            control.append(IPPROTO_IP, IP_PKTINFO, info);
#else
            co_return fail(std::make_error_code(std::errc::not_supported));
#endif
        } else {
#if defined(IPV6_PKTINFO)
            in6_pktinfo info{};
            info.ipi6_ifindex = packet.interface_index;
            if (packet.source) {
                sockaddr_in6 address{};
                std::memcpy(&address, packet.source->address_bytes().data(), sizeof(address));
                info.ipi6_addr = address.sin6_addr;
                if (address.sin6_scope_id != 0) {
                    if (info.ipi6_ifindex != 0 && info.ipi6_ifindex != address.sin6_scope_id)
                        co_return fail(Errc::invalid_argument);
                    info.ipi6_ifindex = address.sin6_scope_id;
                }
            }
            control.append(IPPROTO_IPV6, IPV6_PKTINFO, info);
#else
            co_return fail(std::make_error_code(std::errc::not_supported));
#endif
        }
    }
    if (packet.traffic_class) {
        const int value = *packet.traffic_class;
        if (peer.family() == Family::ipv4) control.append(IPPROTO_IP, IP_TOS, value);
        else {
#if defined(IPV6_TCLASS)
            control.append(IPPROTO_IPV6, IPV6_TCLASS, value);
#else
            co_return fail(std::make_error_code(std::errc::not_supported));
#endif
        }
    }
    auto sent = co_await state->loop->send_message(state->handle, source, peer.address_bytes(),
        std::span<const std::byte>{control.bytes.data(), control.size}, options);
    if (!sent && (sent.error() == std::errc::no_protocol_option ||
                  sent.error() == std::errc::operation_not_supported))
        co_return fail(std::make_error_code(std::errc::not_supported));
    co_return sent;
#endif
}

Task<Result<Datagram>> Socket::receive(std::shared_ptr<State> state,
                                       std::span<std::byte> destination,
                                       OperationOptions options) {
    if (!state || state->handle == invalid_handle) co_return fail(Errc::invalid_argument);
    auto result = co_await state->loop->receive_from(state->handle, destination, options);
    if (!result) co_return fail(result.error());
    const auto peer = Endpoint::from_bytes({result->address.data(), result->address_size});
    if (!peer) co_return fail(peer.error());
#if MIRA_PLATFORM_WINDOWS
    co_return Datagram{result->size, *peer};
#else
    co_return Datagram{result->size, *peer, packet_metadata(*result, state->local.port())};
#endif
}

}  // namespace Mira::transport::udp
