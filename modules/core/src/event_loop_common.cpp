// Backend-independent parts of EventLoop.
//
// Compiled on every platform, unlike `event_loop_posix.cpp` and
// `event_loop_iocp.cpp`. Anything here must be written against the loop's own
// public API, so that it cannot acquire a second, subtly different behaviour
// per backend — which is the failure mode this library spends most of its
// effort on.

#include "mira/core/event_loop.hpp"

#include <coroutine>
#include <cstdio>
#include <exception>
#include <utility>

namespace Mira {
namespace {

/// Owns a root coroutine and records how it ended.
///
/// Deliberately not a `Task`: a `Task` is resumed by an awaiting coroutine,
/// and the entire point of a root is that there is not one.
///
/// It stays suspended at its final suspend point rather than self-destroying,
/// so that the caller can read the exception out and then destroy a frame that
/// has *finished* — the one state in which destroying it is allowed.
class RootTask {
public:
    struct promise_type {
        bool finished{false};
        std::exception_ptr failure{};

        RootTask get_return_object() noexcept {
            return RootTask{std::coroutine_handle<promise_type>::from_promise(*this)};
        }

        std::suspend_always initial_suspend() noexcept { return {}; }

        std::suspend_always final_suspend() noexcept {
            // Reached on both the normal and the exceptional path, so this is
            // the single place that records "no longer running".
            finished = true;
            return {};
        }

        void return_void() noexcept {}
        void unhandled_exception() noexcept { failure = std::current_exception(); }
    };

    using Handle = std::coroutine_handle<promise_type>;

    explicit RootTask(Handle handle) noexcept : handle_(handle) {}

    RootTask(const RootTask&) = delete;
    RootTask& operator=(const RootTask&) = delete;

    ~RootTask() {
        if (handle_) {
            handle_.destroy();
        }
    }

    void start() { handle_.resume(); }

    [[nodiscard]] bool finished() const noexcept { return handle_.promise().finished; }

    void rethrow_if_failed() const {
        if (handle_.promise().failure) {
            std::rethrow_exception(handle_.promise().failure);
        }
    }

private:
    Handle handle_;
};

RootTask run_root(Task<void> task) {
    co_await std::move(task);
}

/// Describes a posted callback failure held back until the root finished,
/// so a terminating diagnostic does not silently drop it.
void report_deferred_post_failure(const std::exception_ptr& failure) noexcept {
    if (!failure) return;
    try {
        std::rethrow_exception(failure);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "An earlier posted callback had thrown: %s\n", error.what());
    } catch (...) {
        std::fprintf(stderr, "An earlier posted callback had thrown a non-std exception.\n");
    }
}

[[noreturn]] void unresolvable(const char* reason, const std::exception_ptr& post_failure) {
    std::fprintf(stderr,
                 "Mira::EventLoop::run_until_complete: %s.\n"
                 "The root coroutine is started and unfinished, so its frame cannot be\n"
                 "destroyed: the loop may still hold its handle, its result slot, and\n"
                 "buffers it borrowed. Terminating rather than corrupting memory.\n",
                 reason);
    report_deferred_post_failure(post_failure);
    std::fflush(stderr);
    std::terminate();
}

}  // namespace

Result<void> EventLoop::run_until_complete(Task<void> task) {
    RootTask root = run_root(std::move(task));
    root.start();
    std::exception_ptr post_failure;

    while (!root.finished()) {
        // Checked *before* pumping, because pumping blocks until something
        // happens and nothing ever will.
        //
        // This is sound only because of an invariant `run()` already depends
        // on: whatever can resume a coroutine must be registered as
        // outstanding work, even when the resumption originates off-thread.
        // Anything that breaks that invariant already makes `run()` return
        // while its work is still pending, so there is no case where this is
        // wrong and `run()` is right.
        if (outstanding() == 0) {
            unresolvable("nothing is outstanding, so nothing can resume it", post_failure);
        }

        // A failure here may still have delivered the completion that finished
        // the task, so the outcome is checked before the error is acted on.
        Result<void> pumped = pump_once(Duration::min(), &post_failure);
        if (root.finished()) {
            root.rethrow_if_failed();
            if (post_failure) std::rethrow_exception(post_failure);
            return pumped;
        }
        if (!pumped) {
            unresolvable("the loop could not be pumped", post_failure);
        }
    }

    root.rethrow_if_failed();
    return Result<void>{};
}

}  // namespace Mira
