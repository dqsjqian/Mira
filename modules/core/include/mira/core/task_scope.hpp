#pragma once

#include <mira/core/task.hpp>
#include <coroutine>
#include <cstddef>
#include <exception>
#include <stdexcept>
#include <stop_token>
#include <utility>
#include <vector>

namespace Mira {

/// Single-threaded structured task ownership: child tasks start immediately,
/// and join waits for all of their frames to be released.
///
/// The scope, child-task completion, and stop callbacks must all run on the
/// same thread; no cross-thread synchronisation is provided. The stop token
/// is a cooperative signal only — it does not automatically cancel event
/// loop I/O. Resources referenced by a child task must stay alive until join
/// completes. When passing a coroutine lambda, the caller must still keep
/// the closure alive.
///
/// join may be called once, and calling it closes the scope to further
/// spawns; the returned Task must be driven to completion. A scope that
/// never spawned or joined may be destructed directly; every other scope
/// must be destructed after join completes (even if join rethrows a child
/// exception). Destroying one early, or destroying a join that is still
/// waiting, terminates rather than destroying child frames still referenced
/// by I/O.
class TaskScope final {
public:
    TaskScope() = default;
    TaskScope(const TaskScope&) = delete;
    TaskScope& operator=(const TaskScope&) = delete;
    TaskScope(TaskScope&&) = delete;
    TaskScope& operator=(TaskScope&&) = delete;

    ~TaskScope() {
        if (!joined_ && (used_ || joining_)) {
            std::terminate();
        }
        // The retired queue holds only finished runner frames; by this point
        // their execution chains have long returned.
        for (auto runner : retired_) {
            runner.destroy();
        }
    }

    /// Take over a not-yet-started, non-null Task; finished child frames do
    /// not accumulate inside the scope.
    void spawn(Task<void> task) {
        if (joining_) {
            throw std::logic_error("Mira::TaskScope::spawn: scope is closed");
        }
        if (!task) {
            throw std::invalid_argument(
                "Mira::TaskScope::spawn: task holds no coroutine frame");
        }
        auto runner = run_child(this, std::move(task));
        used_ = true;
        ++pending_;
        runner.start(*this);
    }

    /// Closes the scope to further spawns; waits for all child tasks to
    /// clean up, then rethrows the first exception.
    [[nodiscard]] Task<void> join() {
        if (joining_) {
            throw std::logic_error("Mira::TaskScope::join: join already requested");
        }
        auto task = wait_for_children(this);
        joining_ = true;
        return task;
    }

    [[nodiscard]] std::size_t pending() const noexcept { return pending_; }

    [[nodiscard]] std::stop_token get_stop_token() const noexcept {
        return stop_source_.get_token();
    }

    bool request_stop() noexcept {
        // A callback may synchronously complete the last child task, which
        // then resumes the parent and destroys the scope. The local copy
        // keeps the stop state alive independently, so this is not accessed
        // after the callbacks.
        auto source = stop_source_;
        return source.request_stop();
    }

private:
    // Only a start/completion bridge for Task; this is not a second async
    // task API.
    struct Runner {
        struct promise_type {
            TaskScope* scope{};
            bool retired = false;

            Runner get_return_object() noexcept {
                return Runner{std::coroutine_handle<promise_type>::from_promise(*this)};
            }
            std::suspend_always initial_suspend() const noexcept { return {}; }

            struct FinalAwaiter {
                bool await_ready() const noexcept { return false; }

                std::coroutine_handle<>
                await_suspend(std::coroutine_handle<promise_type> self) const noexcept {
                    // The final suspension boundary has been reached. The
                    // runner frame must never be destroyed here: it still
                    // hosts the wakeup machinery and local state from
                    // co_awaiting the child task, and MSVC (including its
                    // coroutine frame merging optimisation) touches them on
                    // the wrap-up path after destruction (ASan
                    // heap-use-after-free). The frame is handed over to the
                    // scope's retired queue, to be destroyed at a safe
                    // point — after spawn's resume returns, or when the
                    // scope is destructed.
                    auto* owner = self.promise().scope;
                    self.promise().retired = true;
                    owner->retire(self);
                    return owner->child_completed();
                }

                void await_resume() const noexcept {}
            };

            FinalAwaiter final_suspend() const noexcept { return {}; }
            void return_void() const noexcept {}
            void unhandled_exception() const noexcept { std::terminate(); }
        };

        using Handle = std::coroutine_handle<promise_type>;
        Handle handle;

        explicit Runner(Handle value) noexcept : handle(value) {}
        Runner(const Runner&) = delete;
        Runner& operator=(const Runner&) = delete;
        ~Runner() {
            if (handle) {
                handle.destroy();
            }
        }

        void start(TaskScope& scope) noexcept {
            handle.promise().scope = &scope;
            auto running = std::exchange(handle, {});
            scope.frame_guard_ = running.address();
            running.resume();
            // When the child completes synchronously (the frame is already
            // in the retired queue), resume has returned, so it is safe to
            // destroy it here on the stack; frames that complete
            // asynchronously are destroyed together by the scope's
            // destructor.
            if (running && running.promise().retired) {
                scope.reclaim(running);
            }
        }
    };

    struct JoinAwaiter {
        TaskScope* scope;
        bool waiting{false};

        ~JoinAwaiter() {
            if (waiting) {
                std::terminate();
            }
        }

        bool await_ready() const noexcept { return scope->pending_ == 0; }

        void await_suspend(std::coroutine_handle<> continuation) noexcept {
            waiting = true;
            scope->waiter_ = continuation;
        }

        void await_resume() noexcept { waiting = false; }
    };

    static Runner run_child(TaskScope* scope, Task<void> task) {
        try {
            // Task's owning awaiter releases the child frame at the end of
            // the full expression.
            co_await std::move(task);
        } catch (...) {
            if (!scope->failure_) {
                scope->failure_ = std::current_exception();
                scope->request_stop();
            }
        }
    }

    static Task<void> wait_for_children(TaskScope* scope) {
        co_await JoinAwaiter{scope};
        scope->joined_ = true;
        if (scope->failure_) {
            std::rethrow_exception(scope->failure_);
        }
    }

    std::coroutine_handle<> child_completed() noexcept {
        --pending_;
        if (pending_ == 0 && waiter_) {
            return std::exchange(waiter_, {});
        }
        return std::noop_coroutine();
    }

    std::stop_source stop_source_;
    std::exception_ptr failure_;
    void* frame_guard_ = nullptr;  // MSVC HALO escape hatch, see Runner::start
    std::vector<std::coroutine_handle<>> retired_;

    /// Register a runner frame as retired: it is not destroyed inside its
    /// own execution chain; safe points reclaim them all.
    void retire(std::coroutine_handle<> runner) {
        retired_.push_back(runner);
    }

    /// Reclaim a synchronously completed runner frame after start's resume
    /// has returned.
    void reclaim(std::coroutine_handle<> runner) {
        for (std::size_t i = retired_.size(); i-- > 0;) {
            if (retired_[i] == runner) {
                retired_.erase(retired_.begin() + static_cast<long>(i));
                runner.destroy();
                return;
            }
        }
        runner.destroy();  // not in the queue (e.g. completed synchronously
                           // without enqueuing), destroy it directly
    }
    std::coroutine_handle<> waiter_{};
    std::size_t pending_{0};
    bool used_{false};
    bool joining_{false};
    bool joined_{false};
};

}  // namespace Mira
