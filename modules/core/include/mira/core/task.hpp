#pragma once

// Mira/core/task.hpp — the coroutine type every Mira speaks.
//
// `Task<T>` is a *lazy* coroutine: the body does not start until the task is
// awaited (or driven by `sync_get()`). Awaiting starts the awaited task on the
// current thread. When it finishes before suspending, the awaiting frame
// continues from `await_suspend` returning false, not from a nested resume, so
// a loop over synchronously completing tasks runs in constant native stack.
// That must not depend on the compiler turning symmetric transfer into a tail
// call: GCC does not at -O0/-O1, which grew the stack by one resume pair per
// await until a long I/O-free loop overflowed. Symmetric transfer remains only
// on the asynchronous path, where depth is bounded by the static await nesting.
//
// Ownership: `Task<T>` is move-only and owns its coroutine frame. Awaiting a
// task consumes it (`operator co_await() &&` moves the handle into the
// awaiter), which is what keeps a temporary `Task` from destroying a frame
// that is still running.
//
// Destroying a *started but unfinished* frame is a contract violation and
// terminates — the same rule as destroying a joinable `std::thread`. See
// `detail::report_abandoned_frame`.
//
// Deliberately absent: `then()`-style continuations and detached launching.
// Per-operation cancellation lives on the event loop (`OperationOptions`),
// not on `Task`: a task does not know which operation it is suspended on.

#include <atomic>
#include <coroutine>
#include <cstdio>
#include <exception>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace Mira {

template<typename T = void>
class Task;

namespace detail {

/// Report that a started, unfinished coroutine frame was about to be destroyed,
/// then terminate.
///
/// Why terminate rather than throw: once a task has started and suspended,
/// something else may hold its handle — the event loop stores it, along with a
/// pointer into the awaiter that lives in that very frame, plus whatever
/// buffers the operation borrowed. Destroying the frame turns all of those into
/// dangling references, and there is no way for the destructor to find out
/// whether that happened. Throwing would be worse than useless: the frame would
/// still be destroyed (or leaked) while the exception unwinds.
///
/// This is the same contract as destroying a joinable `std::thread`.
///
/// `std::terminate` rather than `std::abort`, so that the subprocess contract
/// tests can install a `std::set_terminate` handler and assert an exit code.
[[noreturn]] inline void report_abandoned_frame(const char* site) noexcept {
    std::fprintf(stderr,
                 "Mira::Task: %s must not destroy a started, unfinished coroutine frame.\n"
                 "  The event loop may still hold its handle, its result slot, or buffers it\n"
                 "  borrowed. Await the task to completion, or keep it alive until whatever\n"
                 "  owns the suspension resumes it. To stop an operation early, pass\n"
                 "  OperationOptions{.stop = token} instead of destroying the task.\n"
                 "  This is the same contract as destroying a joinable std::thread.\n",
                 site);
    std::terminate();
}

/// Shared promise state: the continuation to resume once the body finishes.
///
/// `FinalAwaiter::await_suspend` is a template so that a
/// `coroutine_handle<DerivedPromise>` can be accepted and up-cast to this base
/// — a non-template overload taking `coroutine_handle<TaskPromiseBase>` would
/// not be convertible from the derived handle.
struct TaskPromiseBase {
    std::coroutine_handle<> continuation{};

    /// Set at the two — and only two — places that resume a task frame:
    /// `Task::Awaiter::await_suspend` and `Task::sync_get`. Together with
    /// `handle.done()` this separates "never ran, safe to destroy" from
    /// "suspended mid-flight, someone else may hold it".
    bool started{false};

    /// Rendezvous between `Task::Awaiter::await_suspend`, which runs the body
    /// inline, and this frame's final suspension. Whichever arrives second
    /// continues the awaiting frame: the final suspension when the body
    /// completed after suspending elsewhere, or the awaiter when it completed
    /// inline. Atomic because a body may finish on another thread (for
    /// example after `schedule_on`) before `await_suspend` has returned.
    std::atomic<bool> rendezvous{false};

    struct FinalAwaiter {
        [[nodiscard]] bool await_ready() const noexcept { return false; }

        template<typename Promise>
        std::coroutine_handle<> await_suspend(std::coroutine_handle<Promise> self) noexcept {
            TaskPromiseBase& base = self.promise();
            if (!base.rendezvous.exchange(true, std::memory_order_acq_rel)) {
                // First to arrive: the awaiter is still inside its resume()
                // call and continues the awaiting frame once that returns.
                return std::noop_coroutine();
            }
            return base.continuation ? base.continuation : std::noop_coroutine();
        }

        void await_resume() const noexcept {}
    };

    [[nodiscard]] std::suspend_always initial_suspend() noexcept { return {}; }
    [[nodiscard]] FinalAwaiter final_suspend() noexcept { return {}; }
};

/// True when destroying `handle`'s frame would be a contract violation.
///
/// `done()` is well defined for a frame suspended at any suspend point,
/// including the initial and final ones; it is undefined only while a frame is
/// *executing*, and no caller of this reaches it from inside a running body.
template<typename Promise>
[[nodiscard]] bool frame_abandoned(std::coroutine_handle<Promise> handle) noexcept {
    return handle && handle.promise().started && !handle.done();
}

template<typename T>
struct TaskPromise final : TaskPromiseBase {
    std::optional<T> value{};
    std::exception_ptr failure{};

    Task<T> get_return_object() noexcept;

    template<typename U = T>
        requires std::is_constructible_v<T, U&&>
    void return_value(U&& v) {
        value.emplace(std::forward<U>(v));
    }

    void unhandled_exception() noexcept { failure = std::current_exception(); }

    /// Hand the result to the awaiter, rethrowing a body exception if any.
    ///
    /// The returned reference is bound into the promise's `optional`; the
    /// task frame is destroyed as soon as the awaiting expression finishes
    /// (Awaiter/FrameGuard). Consume the value inside that same full
    /// expression — `auto value = co_await task;` moves it out, while
    /// binding `T&` or `auto&&` to the result and reading it later dangles.
    T&& result() && {
        if (failure) {
            std::rethrow_exception(failure);
        }
        return std::move(*value);
    }
};

template<>
struct TaskPromise<void> final : TaskPromiseBase {
    std::exception_ptr failure{};

    Task<void> get_return_object() noexcept;

    void return_void() noexcept {}
    void unhandled_exception() noexcept { failure = std::current_exception(); }

    void result() && {
        if (failure) {
            std::rethrow_exception(failure);
        }
    }
};

}  // namespace detail

/// Lazy, move-only coroutine handle used by every asynchronous Mira.
template<typename T>
class Task {
public:
    using promise_type = detail::TaskPromise<T>;
    using handle_type = std::coroutine_handle<promise_type>;
    using value_type = T;

    Task() noexcept = default;
    explicit Task(handle_type handle) noexcept : handle_(handle) {}

    Task(Task&& other) noexcept : handle_(std::exchange(other.handle_, {})) {}

    Task& operator=(Task&& other) noexcept {
        if (this != &other) {
            destroy();
            handle_ = std::exchange(other.handle_, {});
        }
        return *this;
    }

    Task(const Task&) = delete;
    Task& operator=(const Task&) = delete;

    ~Task() { destroy(); }

    /// True when the task holds no frame, or its body has run to completion.
    [[nodiscard]] bool done() const noexcept { return !handle_ || handle_.done(); }

    /// True when the task owns a coroutine frame.
    [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(handle_); }

    /// Await the task, consuming it.
    ///
    /// The awaiter takes ownership of the frame, so the awaited expression may
    /// be a temporary without the frame being destroyed while it still runs.
    auto operator co_await() && noexcept {
        class Awaiter {
        public:
            explicit Awaiter(handle_type handle) noexcept : handle_(handle) {}

            Awaiter(Awaiter&& other) noexcept : handle_(std::exchange(other.handle_, {})) {}
            Awaiter(const Awaiter&) = delete;
            Awaiter& operator=(const Awaiter&) = delete;
            Awaiter& operator=(Awaiter&&) = delete;

            ~Awaiter() {
                if (!handle_) {
                    return;
                }
                // The awaiter lives in the awaiting frame and outlives the
                // suspension, so destroying that frame mid-await lands here
                // first. Cascading destruction therefore fails fast at the
                // outermost abandoned level, never deeper.
                if (detail::frame_abandoned(handle_)) {
                    detail::report_abandoned_frame("awaiting frame");
                }
                handle_.destroy();
            }

            [[nodiscard]] bool await_ready() const noexcept { return !handle_ || handle_.done(); }

            bool await_suspend(std::coroutine_handle<> awaiting) noexcept {
                auto& promise = handle_.promise();
                promise.continuation = awaiting;
                promise.started = true;  // before the body runs
                handle_.resume();
                // Second to arrive means the body already reached its final
                // suspension: decline to suspend, so the awaiting frame goes
                // on in this stack frame instead of one nested beneath it.
                // Nothing may touch `this` after the exchange: once it lands
                // first, another thread may resume and destroy this frame.
                return !promise.rendezvous.exchange(true, std::memory_order_acq_rel);
            }

            decltype(auto) await_resume() {
                if (!handle_) {
                    throw std::logic_error("Mira::Task: cannot await an empty task");
                }
                return std::move(handle_.promise()).result();
            }

        private:
            handle_type handle_;
        };

        return Awaiter{std::exchange(handle_, {})};
    }

    /// Drive a task that completes without ever suspending, and take its value.
    ///
    /// Intended for tests and for synchronous entry points. A task that
    /// suspends on real I/O will *not* complete here — that needs an event
    /// loop, and a suspension is a contract violation that terminates rather
    /// than either destroying a frame the loop may reference or leaking it.
    decltype(auto) sync_get() && {
        handle_type handle = std::exchange(handle_, {});
        if (!handle) {
            throw std::logic_error("Mira::Task::sync_get: task holds no coroutine frame");
        }

        struct FrameGuard {
            handle_type handle;
            ~FrameGuard() {
                if (handle) {
                    handle.destroy();
                }
            }
        } guard{handle};

        handle.promise().started = true;
        handle.resume();
        if (!handle.done()) {
            // The guard must not run: the frame is suspended, so whatever it
            // suspended on may hold the handle and the awaiter inside it.
            detail::report_abandoned_frame("sync_get");
        }

        if constexpr (std::is_void_v<T>) {
            std::move(handle.promise()).result();
            return;
        } else {
            T value = std::move(handle.promise()).result();
            return value;
        }
    }

private:
    void destroy() noexcept {
        if (!handle_) {
            return;
        }
        // A `Task` normally owns only an unstarted frame — awaiting moves the
        // handle into the awaiter. Holding a started one and dropping it is the
        // same violation, so it gets the same answer.
        if (detail::frame_abandoned(handle_)) {
            detail::report_abandoned_frame("task destructor");
        }
        handle_.destroy();
        handle_ = {};
    }

    handle_type handle_{};
};

namespace detail {

template<typename T>
Task<T> TaskPromise<T>::get_return_object() noexcept {
    return Task<T>{std::coroutine_handle<TaskPromise<T>>::from_promise(*this)};
}

inline Task<void> TaskPromise<void>::get_return_object() noexcept {
    return Task<void>{std::coroutine_handle<TaskPromise<void>>::from_promise(*this)};
}

}  // namespace detail

}  // namespace Mira
