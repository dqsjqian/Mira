// kqueue readiness backend (macOS, iOS, FreeBSD).
//
// Platform detection lives in exactly one place — platform.hpp. Every other
// file asks it instead of testing compiler macros directly, and the layering
// check fails the build on any file that forgets.

#include "mira/core/platform.hpp"

#if defined(MIRA_IO_BACKEND_KQUEUE)

    #include "poller.hpp"

    #include <array>
    #include <cerrno>
    #include <ctime>
    #include <sys/event.h>
    #include <sys/types.h>
    #include <unistd.h>

namespace Mira::detail {
namespace {

/// Wrap the current `errno` as an error_code in the system category, so that
/// callers can compare against `std::errc` without a translation table.
[[nodiscard]] Error last_os_error() noexcept {
    return std::error_code{errno, std::system_category()};
}

constexpr std::size_t kMaxChanges = 2;

#if MIRA_PLATFORM_APPLE
// Darwin treats a zero timespec as a timed wait that expires at once, which
// costs 12-20 us even with nothing to report; KEVENT_FLAG_IMMEDIATE is a plain
// scan of about 0.2 us. The loop polls with a zero timeout whenever work is
// already queued, so that is its hot path. The flag exists only on kevent64,
// and Darwin binds a kqueue to the first flavour used on it (mixing fails
// with EINVAL), so every call in this file uses kevent64 there.
using KernelEvent = struct kevent64_s;

int kernel_event(int queue, const KernelEvent* changes, int change_count, KernelEvent* events,
                 int event_count, int timeout_ms) noexcept {
    if (timeout_ms == 0) {
        return ::kevent64(queue, changes, change_count, events, event_count,
                          KEVENT_FLAG_IMMEDIATE, nullptr);
    }
    struct timespec timeout{};
    if (timeout_ms > 0) {
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_nsec = static_cast<long>(timeout_ms % 1000) * 1'000'000L;
    }
    return ::kevent64(queue, changes, change_count, events, event_count, 0,
                      timeout_ms < 0 ? nullptr : &timeout);
}
#else
using KernelEvent = struct kevent;

int kernel_event(int queue, const KernelEvent* changes, int change_count, KernelEvent* events,
                 int event_count, int timeout_ms) noexcept {
    struct timespec timeout{};
    if (timeout_ms > 0) {
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_nsec = static_cast<long>(timeout_ms % 1000) * 1'000'000L;
    }
    return ::kevent(queue, changes, change_count, events, event_count,
                    timeout_ms < 0 ? nullptr : &timeout);
}
#endif

/// One change-list entry; every other field stays zero.
[[nodiscard]] KernelEvent change(int fd, decltype(KernelEvent::filter) filter,
                                 decltype(KernelEvent::flags) flags) noexcept {
    KernelEvent event{};
    event.ident = static_cast<decltype(event.ident)>(fd);
    event.filter = filter;
    event.flags = flags;
    return event;
}

}  // namespace

Result<Poller> Poller::create() noexcept {
    const int handle = ::kqueue();
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
    std::array<KernelEvent, kMaxChanges> changes{};
    std::size_t count = 0;

    // EV_ONESHOT: the filter is removed as soon as it fires, which is exactly
    // the lifetime a suspended coroutine wants.
    if (contains(interest, Interest::read)) {
        changes[count++] = change(fd, EVFILT_READ, EV_ADD | EV_ONESHOT);
    }
    if (contains(interest, Interest::write)) {
        changes[count++] = change(fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT);
    }
    if (count == 0) {
        return fail(Errc::invalid_argument);
    }

    if (kernel_event(handle_, changes.data(), static_cast<int>(count), nullptr, 0, -1) < 0) {
        return fail(last_os_error());
    }
    return Result<void>{};
}

Result<void> Poller::disarm(int fd) noexcept {
    const std::array<KernelEvent, kMaxChanges> changes{change(fd, EVFILT_READ, EV_DELETE),
                                                       change(fd, EVFILT_WRITE, EV_DELETE)};

    // ENOENT means the filter already fired (one-shot) or was never armed —
    // both are ordinary races for a cancelling waiter, not failures.
    if (kernel_event(handle_, changes.data(), static_cast<int>(changes.size()), nullptr, 0, -1) <
            0 &&
        errno != ENOENT) {
        return fail(last_os_error());
    }
    return Result<void>{};
}

Result<std::size_t> Poller::poll(std::span<ReadyEvent> out, int timeout_ms) noexcept {
    if (out.empty()) {
        return fail(Errc::invalid_argument);
    }

    std::array<KernelEvent, 64> events{};
    const std::size_t capacity = out.size() < events.size() ? out.size() : events.size();

    const int count =
        kernel_event(handle_, nullptr, 0, events.data(), static_cast<int>(capacity), timeout_ms);
    if (count < 0) {
        // A signal during the wait is not a failure; report "nothing ready"
        // and let the caller loop.
        if (errno == EINTR) {
            return std::size_t{0};
        }
        return fail(last_os_error());
    }

    for (int i = 0; i < count; ++i) {
        const KernelEvent& source = events[static_cast<std::size_t>(i)];
        ReadyEvent& target = out[static_cast<std::size_t>(i)];
        target.fd = static_cast<int>(source.ident);
        target.readable = source.filter == EVFILT_READ;
        target.writable = source.filter == EVFILT_WRITE;
        target.failed = (source.flags & EV_ERROR) != 0 || (source.flags & EV_EOF) != 0;
    }

    return static_cast<std::size_t>(count);
}

}  // namespace Mira::detail

#endif  // BSD-family
