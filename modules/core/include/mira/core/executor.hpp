#pragma once

// Mira/core/executor.hpp — where coroutines get resumed.
//
// Mira does not own a thread policy. The `Executor` concept is the single
// hook a host uses to decide *which thread* runs a resumption, which is what
// lets the library sit under a GUI framework's main loop, a per-core event
// loop, or a plain thread pool without any of them knowing about the others.
//
// The concept is one function — `post(callable)`, "run this soon, not now" —
// because that is the smallest thing every scheduler already has. Timers and
// readiness waits are separate interfaces owned by the event loop, so a host
// that only wants to control thread affinity does not have to implement them.
//
// `InlineExecutor` runs work immediately on the calling thread. It exists for
// tests and for single-threaded embedding; it is not a default, because
// silently running I/O completions inline is exactly the kind of surprise this
// seam is meant to prevent.

#include "mira/core/task.hpp"

#include <concepts>
#include <coroutine>
#include <utility>

namespace Mira {

namespace detail {

/// The exact callable `schedule_on` posts: a coroutine handle wrapped in a
/// copyable, callable shape. Naming the type is what lets the `Executor`
/// concept probe the *real* requirement — accepting this closure — rather
/// than an incidental one like "accepts a function pointer", which a
/// capture-carrying closure can never satisfy.
struct PostedResumption {
    std::coroutine_handle<> awaiting;

    void operator()() const noexcept { awaiting.resume(); }
};

}  // namespace detail

/// An executor accepts any callable Mira needs to post, including the
/// stateful resumption closure above. Probing with `PostedResumption` itself
/// means a type satisfying the concept actually works with `schedule_on`,
/// rather than failing later inside the template body. post() is a reliable
/// control channel: a bounded application queue must expose a separate
/// try_post() API, never silently discard PostedResumption on saturation.
template<typename E>
concept Executor = requires(E& executor, detail::PostedResumption&& work) {
    { executor.post(std::move(work)) } -> std::same_as<void>;
};

/// The precise per-callable form, for hosts that want to check their own
/// executor types against arbitrary work shapes.
template<typename E, typename F>
concept ExecutorFor = requires(E& executor, F&& work) {
    { executor.post(std::forward<F>(work)) } -> std::same_as<void>;
};

/// Executor that runs posted work synchronously on the calling thread.
class InlineExecutor {
public:
    template<typename F>
    void post(F&& work) {
        std::forward<F>(work)();
    }
};

static_assert(Executor<InlineExecutor>);

/// Awaitable that reschedules the current coroutine onto `executor`.
///
/// Everything after the `co_await` runs on whatever thread that executor
/// dispatches on:
///
///     co_await schedule_on(ui_executor);
///     // ... now on the UI thread
template<Executor E>
[[nodiscard]] auto schedule_on(E& executor) noexcept {
    class Awaiter {
    public:
        explicit Awaiter(E& target) noexcept : target_(target) {}

        [[nodiscard]] bool await_ready() const noexcept { return false; }

        void await_suspend(std::coroutine_handle<> awaiting) {
            // The handle is wrapped in the named closure the `Executor`
            // concept probes with, so "compiles against the concept" and
            // "works at runtime" cannot drift apart. Capturing by reference
            // here would dangle as soon as this awaiter dies.
            target_.post(detail::PostedResumption{awaiting});
        }

        void await_resume() const noexcept {}

    private:
        E& target_;
    };

    return Awaiter{executor};
}

}  // namespace Mira
