#pragma once

// Internal socket-API compatibility layer — NOT a public header.
//
// The one place in the transport module that includes OS networking headers,
// so the rest of the module reads as ordinary C++. Nothing here does I/O; it
// only creates, configures, and inspects sockets.

#include "mira/core/platform.hpp"

#if MIRA_PLATFORM_WINDOWS
// clang-format off
    #include <winsock2.h>
    #include <ws2tcpip.h>
// clang-format on
#else
    #include <arpa/inet.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <net/if.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

#include "mira/core/error.hpp"

#include <cstddef>
#include <cstring>

namespace Mira::transport::detail {

#if MIRA_PLATFORM_WINDOWS
using socket_t = SOCKET;
using socklen_type = int;
inline constexpr socket_t invalid_socket = INVALID_SOCKET;
#else
using socket_t = int;
using socklen_type = socklen_t;
inline constexpr socket_t invalid_socket = -1;
#endif

/// Last socket error as an `std::error_code` in the system category.
[[nodiscard]] inline Error last_socket_error() noexcept {
#if MIRA_PLATFORM_WINDOWS
    return socket_error(::WSAGetLastError());
#else
    return socket_error(errno);
#endif
}

/// Close a socket with the platform's own call.
inline void close_socket(socket_t socket) noexcept {
    if (socket == invalid_socket) {
        return;
    }
#if MIRA_PLATFORM_WINDOWS
    ::closesocket(socket);
#else
    ::close(socket);
#endif
}

/// Create a TCP socket suitable for overlapped/non-blocking use.
[[nodiscard]] inline Result<socket_t> create_tcp_socket(int family) {
#if MIRA_PLATFORM_WINDOWS
    // WSA_FLAG_OVERLAPPED is required for IOCP; a socket() call without it
    // silently produces a handle the completion port cannot drive.
    const socket_t socket =
        ::WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
#else
    #if defined(SOCK_CLOEXEC)
    socket_t socket = ::socket(family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    #else
    socket_t socket = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
    #endif
    if (socket >= 0) {
        // Non-blocking is not optional: the loop emulates completion on top of
        // readiness, and a blocking descriptor would stall it inside one read.
        const int flags = ::fcntl(socket, F_GETFL, 0);
        if (flags < 0 || ::fcntl(socket, F_SETFL, flags | O_NONBLOCK) < 0) {
            const Error error = last_socket_error();
            close_socket(socket);
            return fail(error);
        }
    #if !defined(SOCK_CLOEXEC)
        const int descriptor_flags = ::fcntl(socket, F_GETFD, 0);
        if (descriptor_flags < 0 || ::fcntl(socket, F_SETFD, descriptor_flags | FD_CLOEXEC) < 0) {
            const Error error = last_socket_error();
            close_socket(socket);
            return fail(error);
        }
    #endif
    }
#endif
    if (socket == invalid_socket) {
        return fail(last_socket_error());
    }
    return socket;
}

/// Set a boolean socket option.
[[nodiscard]] inline Result<void> set_flag(socket_t socket, int level, int option, bool enabled) {
    const int value = enabled ? 1 : 0;
#if MIRA_PLATFORM_WINDOWS
    const int status =
        ::setsockopt(socket, level, option, reinterpret_cast<const char*>(&value), sizeof(value));
#else
    const int status = ::setsockopt(socket, level, option, &value, sizeof(value));
#endif
    if (status != 0) {
        return fail(last_socket_error());
    }
    return Result<void>{};
}

/// Apply "refuse to bind a port another socket is actively using".
///
/// The platforms need opposite options to express one intent, which is exactly
/// why the public API exposes the intent instead of the option:
///
///   * Windows: `SO_EXCLUSIVEADDRUSE`. Without it, `SO_REUSEADDR` semantics
///     let a second process steal a live binding.
///   * POSIX: simply not setting `SO_REUSEADDR` for the live-socket case;
///     TIME_WAIT reuse is a separate concern handled below.
[[nodiscard]] inline Result<void>
apply_exclusive_bind(socket_t socket, bool exclusive, bool reuse_after_close) {
#if MIRA_PLATFORM_WINDOWS
    // SO_EXCLUSIVEADDRUSE already permits rebinding a port this process left
    // in TIME_WAIT, so Windows needs no separate switch for it — the flag is
    // meaningful only on the POSIX branch below.
    static_cast<void>(reuse_after_close);

    if (exclusive) {
        return set_flag(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, true);
    }
    // Non-exclusive on Windows means the classic stealing behaviour; only set
    // it when the caller explicitly asked for shared binding.
    return set_flag(socket, SOL_SOCKET, SO_REUSEADDR, true);
#else
    // On POSIX, SO_REUSEADDR is what permits rebinding a TIME_WAIT port; it
    // does not allow stealing a live binding, so it is safe alongside
    // exclusivity.
    if (reuse_after_close) {
        Result<void> applied = set_flag(socket, SOL_SOCKET, SO_REUSEADDR, true);
        if (!applied) {
            return applied;
        }
    }
    #ifdef SO_REUSEPORT
    if (!exclusive) {
        // Deliberate port sharing across processes.
        return set_flag(socket, SOL_SOCKET, SO_REUSEPORT, true);
    }
    #endif
    return Result<void>{};
#endif
}

/// Disable Nagle's algorithm.
[[nodiscard]] inline Result<void> apply_no_delay(socket_t socket, bool enabled) {
    if (!enabled) {
        return Result<void>{};
    }
    return set_flag(socket, IPPROTO_TCP, TCP_NODELAY, true);
}

/// Allow IPv4 connections on an IPv6 socket.
[[nodiscard]] inline Result<void> apply_dual_stack(socket_t socket, bool dual_stack) {
#ifdef IPV6_V6ONLY
    return set_flag(socket, IPPROTO_IPV6, IPV6_V6ONLY, !dual_stack);
#else
    static_cast<void>(socket);
    static_cast<void>(dual_stack);
    return Result<void>{};
#endif
}

/// `bind()`, translating "already in use" into a portable condition.
[[nodiscard]] inline Result<void> bind_socket(socket_t socket, std::span<const std::byte> address) {
    const auto* target = reinterpret_cast<const sockaddr*>(address.data());
    if (::bind(socket, target, static_cast<socklen_type>(address.size())) != 0) {
        return fail(last_socket_error());
    }
    return Result<void>{};
}

[[nodiscard]] inline Result<void> listen_socket(socket_t socket, int backlog) {
    if (::listen(socket, backlog) != 0) {
        return fail(last_socket_error());
    }
    return Result<void>{};
}

/// Read back the address the OS assigned — resolves a port-0 bind.
[[nodiscard]] inline Result<std::size_t> local_address(socket_t socket, std::span<std::byte> out) {
    auto length = static_cast<socklen_type>(out.size());
    if (::getsockname(socket, reinterpret_cast<sockaddr*>(out.data()), &length) != 0) {
        return fail(last_socket_error());
    }
    return static_cast<std::size_t>(length);
}

[[nodiscard]] inline Result<std::size_t> peer_address(socket_t socket, std::span<std::byte> out) {
    auto length = static_cast<socklen_type>(out.size());
    if (::getpeername(socket, reinterpret_cast<sockaddr*>(out.data()), &length) != 0) {
        return fail(last_socket_error());
    }
    return static_cast<std::size_t>(length);
}

/// Half-close the sending direction.
[[nodiscard]] inline Result<void> shutdown_write(socket_t socket) {
#if MIRA_PLATFORM_WINDOWS
    const int how = SD_SEND;
#else
    const int how = SHUT_WR;
#endif
    if (::shutdown(socket, how) != 0) {
        return fail(last_socket_error());
    }
    return Result<void>{};
}

}  // namespace Mira::transport::detail
