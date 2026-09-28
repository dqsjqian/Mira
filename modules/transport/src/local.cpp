#include "mira/transport/local.hpp"
#include "mira/core/platform.hpp"
#include <cstring>
#include <cerrno>
#if !MIRA_PLATFORM_WINDOWS
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace Mira::transport::local {
#if !MIRA_PLATFORM_WINDOWS
namespace {
Result<sockaddr_un> address(const std::string& path) {
    sockaddr_un result{};
    if (path.empty() || path.find('\0') != std::string::npos || path.size() >= sizeof(result.sun_path))
        return fail(Errc::invalid_argument);
    result.sun_family = AF_UNIX;
    std::memcpy(result.sun_path, path.c_str(), path.size() + 1);
    return result;
}
Error os_error() { return std::error_code(errno, std::generic_category()); }
}
#endif
Result<Listener> Listener::bind(EventLoop& loop, std::string path, int backlog) {
#if !MIRA_PLATFORM_WINDOWS
    auto endpoint = address(path);
    if (!endpoint || backlog <= 0) return fail(Errc::invalid_argument);
    const int handle = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (handle < 0) return fail(os_error());
    if (::bind(handle, reinterpret_cast<const sockaddr*>(&*endpoint), sizeof(*endpoint)) != 0 ||
        ::listen(handle, backlog) != 0) {
        const auto error = os_error();
        ::close(handle);
        return fail(error);
    }
    auto attached = loop.attach(handle);
    if (!attached) { ::close(handle); return fail(attached.error()); }
    return Listener{loop, handle};
#else
    (void)loop; (void)path; (void)backlog;
    return fail(Errc::not_supported);
#endif
}
Task<Result<Socket>> Listener::accept(OperationOptions io) {
#if !MIRA_PLATFORM_WINDOWS
    if (!loop_ || handle_ == invalid_handle) co_return fail(Errc::invalid_argument);
    auto* loop = loop_;
    const auto listening = handle_;
    auto handle = co_await loop->accept(listening, AF_UNIX, io);
    if (!handle) co_return fail(handle.error());
    co_return Socket{*loop, *handle};
#else
    (void)io;
    co_return fail(Errc::not_supported);
#endif
}
void Listener::close() noexcept {
#if !MIRA_PLATFORM_WINDOWS
    auto* loop = std::exchange(loop_, nullptr);
    const auto handle = std::exchange(handle_, invalid_handle);
    if (handle != invalid_handle) {
        if (loop) loop->detach(handle);
        ::close(handle);
    }
#endif
}
Task<Result<Socket>> connect(EventLoop& loop, std::string path, OperationOptions io) {
#if !MIRA_PLATFORM_WINDOWS
    auto endpoint = address(path);
    if (!endpoint) co_return fail(endpoint.error());
    const int handle = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (handle < 0) co_return fail(os_error());
    auto attached = loop.attach(handle);
    if (!attached) { ::close(handle); co_return fail(attached.error()); }
    Socket socket{loop, handle};
    const auto encoded = std::as_bytes(std::span(&*endpoint, 1));
    auto connected = co_await loop.connect(handle, encoded, io);
    if (!connected) co_return fail(connected.error());
    co_return std::move(socket);
#else
    (void)loop; (void)path; (void)io;
    co_return fail(Errc::not_supported);
#endif
}
}  // namespace Mira::transport::local
