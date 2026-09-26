// epoll readiness backend (Linux, Android).
//
// Exercised for real: the author's Linux container runs this backend through
// the full test suite (and the h1/h2 benchmarks) on every pass, and CI's
// Linux jobs do the same. It stays a close sibling of the kqueue backend —
// the two event models differ in register/unregister shape only.

#include "mira/core/platform.hpp"

#if defined(MIRA_IO_BACKEND_EPOLL)

    #include "poller.hpp"

    #include <array>
    #include <cerrno>
    #include <sys/epoll.h>
    #include <unistd.h>

namespace Mira::detail {
namespace {

[[nodiscard]] Error last_os_error() noexcept {
    return std::error_code{errno, std::system_category()};
}

[[nodiscard]] uint32_t to_epoll_events(Interest interest) noexcept {
    // EPOLLONESHOT mirrors kqueue's EV_ONESHOT: one wakeup per arm, which is
    // the lifetime a suspended coroutine wants.
    uint32_t events = EPOLLONESHOT;
    if (contains(interest, Interest::read)) {
        events |= EPOLLIN;
    }
    if (contains(interest, Interest::write)) {
        events |= EPOLLOUT;
    }
    return events;
}

}  // namespace

Result<Poller> Poller::create() noexcept {
    const int handle = ::epoll_create1(EPOLL_CLOEXEC);
    if (handle < 0) {
        return fail(last_os_error());
    }
    return Poller{handle};
}

void Poller::close() noexcept {
    if (handle_ >= 0) {
        ::close(handle_);
        handle_ = -1;
    }
}

Result<void> Poller::arm(int fd, Interest interest) noexcept {
    const uint32_t events = to_epoll_events(interest);
    if ((events & (EPOLLIN | EPOLLOUT)) == 0u) {
        return fail(Errc::invalid_argument);
    }

    epoll_event registration{};
    registration.events = events;
    registration.data.fd = fd;

    // One-shot descriptors stay registered after firing, just disabled, so a
    // second arm() has to MOD rather than ADD.
    if (::epoll_ctl(handle_, EPOLL_CTL_MOD, fd, &registration) == 0) {
        return Result<void>{};
    }
    if (errno != ENOENT) {
        return fail(last_os_error());
    }
    if (::epoll_ctl(handle_, EPOLL_CTL_ADD, fd, &registration) < 0) {
        return fail(last_os_error());
    }
    return Result<void>{};
}

Result<void> Poller::disarm(int fd) noexcept {
    // ENOENT means it already fired or was never armed — an ordinary race for
    // a cancelling waiter, not a failure.
    if (::epoll_ctl(handle_, EPOLL_CTL_DEL, fd, nullptr) < 0 && errno != ENOENT) {
        return fail(last_os_error());
    }
    return Result<void>{};
}

Result<std::size_t> Poller::poll(std::span<ReadyEvent> out, int timeout_ms) noexcept {
    if (out.empty()) {
        return fail(Errc::invalid_argument);
    }

    std::array<epoll_event, 64> events{};
    const std::size_t capacity = out.size() < events.size() ? out.size() : events.size();

    const int count = ::epoll_wait(handle_, events.data(), static_cast<int>(capacity), timeout_ms);
    if (count < 0) {
        if (errno == EINTR) {
            return std::size_t{0};
        }
        return fail(last_os_error());
    }

    for (int i = 0; i < count; ++i) {
        const epoll_event& source = events[static_cast<std::size_t>(i)];
        ReadyEvent& target = out[static_cast<std::size_t>(i)];
        target.fd = source.data.fd;
        target.readable = (source.events & EPOLLIN) != 0u;
        target.writable = (source.events & EPOLLOUT) != 0u;
        target.failed = (source.events & (EPOLLERR | EPOLLHUP)) != 0u;
    }

    return static_cast<std::size_t>(count);
}

}  // namespace Mira::detail

#endif  // __linux__
