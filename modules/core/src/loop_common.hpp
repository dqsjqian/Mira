#pragma once

// Internal pieces shared by every event-loop backend — NOT a public header.
//
// Timers, the posted-work queue, operation identity, and the suspension
// awaiter behave identically whether completions arrive from kqueue, epoll, or
// IOCP. Keeping them here means the POSIX and Windows backends differ only
// where the platforms genuinely differ, instead of drifting apart in code that
// should be the same.

#include "mira/core/error.hpp"
#include "mira/core/operation.hpp"
#include "mira/core/resource_budget.hpp"

#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include "mira/core/functional.hpp"  // mira::move_only_function
#include <map>
#include <optional>
#include <stop_token>
#include <utility>
#include <vector>

namespace Mira::detail {

using Clock = std::chrono::steady_clock;

/// Stable identity for one in-flight operation.
///
/// Monotonic and never reused. That single property is what makes every
/// indirect reference safe: a timer, a cancellation request, or a readiness
/// event naming an operation that has already resolved finds *nothing* rather
/// than finding a different operation that happens to occupy the same slot.
/// It is the generation counter other designs bolt on separately, except that
/// it cannot be forgotten at a comparison site — there is no slot to compare.
using OperationId = std::uint64_t;

/// Reserved: "no operation". Never handed out, so a zeroed field is
/// unambiguously empty rather than pointing at the first operation ever made.
inline constexpr OperationId kNoOperation = 0;

/// Which operation a timer belongs to, and what its firing means.
struct TimerTarget {
    OperationId operation{kNoOperation};

    /// `false`: the operation *succeeds* when this fires — a sleep reaching
    /// the time it asked for. `true`: the operation is cut short with
    /// `Errc::timed_out`. One queue holds both, because they are the same
    /// mechanism answering to different words.
    bool is_deadline{false};
};

/// Reference to a registered timer, or `{}` for "none".
struct TimerHandle {
    Clock::time_point deadline{};
    std::uint64_t serial{0};

    [[nodiscard]] bool valid() const noexcept { return serial != 0; }
};

/// Deadline-ordered timer queue with cancellable entries.
///
/// Not thread-safe on its own; the owning backend holds its lock.
///
/// Entries carry an `OperationId` rather than a coroutine handle. A timer that
/// outlives the operation it was registered for therefore cannot resume a
/// stale frame — it names something that is no longer in the table, and the
/// lookup fails harmlessly.
///
/// Keyed by `(deadline, serial)` so that cancellation is a single `erase` of a
/// key the caller already holds: no second index to keep in step, and
/// cancelling twice is naturally a no-op.
class TimerQueue {
public:
    [[nodiscard]] TimerHandle add(Clock::time_point deadline, TimerTarget target) {
        const std::uint64_t serial = ++serial_;  // from 1: 0 means "no timer"
        timers_.emplace(Key{deadline, serial}, target);
        return TimerHandle{deadline, serial};
    }

    /// Idempotent. Cancelling a timer that already fired, or was never
    /// registered, is the ordinary path for an operation that completed some
    /// other way.
    void cancel(TimerHandle handle) noexcept {
        if (handle.valid()) {
            timers_.erase(Key{handle.deadline, handle.serial});
        }
    }

    [[nodiscard]] bool empty() const noexcept { return timers_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return timers_.size(); }

    /// Nearest deadline, or `time_point::max()` when idle.
    [[nodiscard]] Clock::time_point earliest() const noexcept {
        return timers_.empty() ? Clock::time_point::max() : timers_.begin()->first.deadline;
    }

    /// Append every timer due at `now` to `out`, in the order they came due.
    ///
    /// The key ordering *is* the tie-break rule, and it is the right one. When
    /// a sleep and an operation deadline are both due in the same batch, the
    /// one with the earlier time is delivered first — so a deadline that
    /// expired before the sleep's target really does cut the sleep short. When
    /// the two land on the same instant, the serial decides, and since the
    /// wake-up is always registered first it sorts first, which makes reaching
    /// the requested time a success.
    ///
    /// An earlier revision of this partitioned non-deadline entries to the
    /// front "on purpose". That was wrong: it also reordered a deadline that
    /// had genuinely expired first, turning a timed-out sleep into a
    /// successful one.
    void extract_expired(Clock::time_point now, std::vector<TimerTarget>& out) {
        while (!timers_.empty() && timers_.begin()->first.deadline <= now) {
            out.push_back(timers_.begin()->second);
            timers_.erase(timers_.begin());
        }
    }

private:
    struct Key {
        Clock::time_point deadline;
        std::uint64_t serial;

        friend auto operator<=>(const Key&, const Key&) = default;
    };

    std::map<Key, TimerTarget> timers_{};
    std::uint64_t serial_{0};
};

/// Convert a caller timeout, the nearest deadline, and queued work into the
/// milliseconds a backend should block for.
///
/// Returns a negative value to mean "block indefinitely" — the convention both
/// `epoll_wait` and `GetQueuedCompletionStatus` already use.
///
/// Invariant for callers: the wake-up byte a backend writes may be collapsed
/// or drained spuriously, so it is never the thing that guarantees progress.
/// **Every queue whose arrival triggers a wake must be reported through
/// `work_already_queued`**, or the loop can block with work sitting in it.
[[nodiscard]] inline int resolve_timeout_ms(Clock::duration caller_timeout,
                                            Clock::time_point earliest_deadline,
                                            bool work_already_queued) {
    using std::chrono::ceil;
    using std::chrono::milliseconds;

    if (work_already_queued) {
        return 0;
    }

    int limit = -1;
    if (caller_timeout != Clock::duration::min()) {
        const auto rounded = ceil<milliseconds>(caller_timeout).count();
        limit = rounded <= 0 ? 0 : static_cast<int>(rounded);
    }

    if (earliest_deadline != Clock::time_point::max()) {
        const Clock::duration remaining = earliest_deadline - Clock::now();
        const int until_deadline = remaining <= Clock::duration::zero()
                                       ? 0
                                       : static_cast<int>(ceil<milliseconds>(remaining).count());
        limit = limit < 0 ? until_deadline : (until_deadline < limit ? until_deadline : limit);
    }

    return limit;
}

/// Decide whether an operation must be refused before it is submitted.
///
/// Cancellation outranks an elapsed deadline. Both are "do not do this", but a
/// stop request is something the caller asked for, while a deadline is a
/// budget that ran out; when both apply, the explicit one is the more useful
/// thing to report.
///
/// Evaluated before the first syscall of an operation, and again every time it
/// is about to park. A retry after `EAGAIN` registers a *new* operation with a
/// new id, so a cancellation aimed at the previous one is already spent — the
/// check before parking is what catches a stop that arrived while the syscall
/// was answering "not yet".
///
/// Deliberately *not* evaluated between a readiness wake-up and the retry it
/// enables. A readiness-emulated read that becomes ready in the same batch as
/// its deadline has genuinely completed, and must be reported that way — which
/// is also what IOCP does, since the completion packet is dequeued before the
/// timer is examined. Checking in between would make the same program answer
/// differently on the two backends.
[[nodiscard]] inline std::optional<Error>
rejected_before_submit(const OperationOptions& options) noexcept {
    if (options.stop.stop_requested()) {
        return make_error_code(Errc::cancelled);
    }
    if (options.deadline && *options.deadline <= Clock::now()) {
        return make_error_code(Errc::timed_out);
    }
    return std::nullopt;
}

/// Report that the loop was destroyed, replaced, or re-entered from inside a
/// callback it was dispatching, then terminate.
[[noreturn]] inline void report_dispatch_violation(const char* what) noexcept {
    std::fprintf(stderr,
                 "Mira::EventLoop: %s.\n"
                 "  The loop is midway through dispatching a batch: operations already taken\n"
                 "  out of its queues are waiting to be delivered, and on Windows a partially\n"
                 "  drained completion batch still refers to loop state. Destroying, replacing\n"
                 "  or re-entering the loop here cannot be made safe by the loop alone.\n"
                 "  Stop the loop and let run()/run_once() return first.\n",
                 what);
    std::terminate();
}

/// Marks the loop as dispatching, so that the check above can fire.
///
/// The depth it guards is a plain integer, not an atomic: it is only ever
/// touched on the loop thread, which is the same restriction that already
/// applies to `run_once` and to destroying the loop.
class DispatchScope {
public:
    // `atomic<int>`: shutdown may run on a foreign thread while a dispatch is
    // in flight, and its violation check reads the depth from there. A plain
    // int would be a data race the diagnostics path itself commits.
    explicit DispatchScope(std::atomic<int>& depth) noexcept : depth_(depth) {
        depth_.fetch_add(1, std::memory_order_relaxed);
    }

    ~DispatchScope() { depth_.fetch_sub(1, std::memory_order_relaxed); }

    DispatchScope(const DispatchScope&) = delete;
    DispatchScope& operator=(const DispatchScope&) = delete;
    DispatchScope(DispatchScope&&) = delete;
    DispatchScope& operator=(DispatchScope&&) = delete;

private:
    std::atomic<int>& depth_;
};

/// Awaiter that parks the caller until a backend resolves its operation.
///
/// `await_suspend` returns `bool` so that a submission failure can decline to
/// suspend: the coroutine continues immediately and observes the error, rather
/// than parking on an operation that was never started.
///
/// `Submit` yields the operation's `OperationId` on success. The id is what a
/// later cancellation names; deliberately not a pointer to this awaiter, which
/// lives in a coroutine frame and must not be reachable from anything that
/// could outlive the suspension.
///
/// The stop callback is registered *after* a successful submission, and only
/// ever asks the loop to cancel. It cannot resume: a `std::stop_callback`
/// built on an already-stopped token runs synchronously, which here would mean
/// resuming a coroutine from inside its own `await_suspend`. Deferring to the
/// loop is what closes that window, and it is the same mechanism that makes a
/// stop request from another thread safe. If the registration itself fails to
/// allocate, the awaiter degrades to operating without a cancel callback
/// rather than propagating an exception through an irreversible submission.
template<typename T, typename Submit, typename RequestCancel>
class OperationAwaiter {
public:
    OperationAwaiter(Submit submit, RequestCancel request_cancel, std::stop_token stop) noexcept
        : submit_(std::move(submit)),
          request_cancel_(std::move(request_cancel)),
          stop_(std::move(stop)) {}

    // The stop callback holds `this`, and the awaiter must stay put once it is
    // registered.
    OperationAwaiter(const OperationAwaiter&) = delete;
    OperationAwaiter& operator=(const OperationAwaiter&) = delete;
    OperationAwaiter(OperationAwaiter&&) = delete;
    OperationAwaiter& operator=(OperationAwaiter&&) = delete;

    [[nodiscard]] bool await_ready() const noexcept { return false; }

    bool await_suspend(std::coroutine_handle<> handle) {
        const Result<OperationId> submitted = submit_(handle, &result_);
        if (!submitted) {
            result_ = fail(submitted.error());
            return false;
        }
        id_ = *submitted;
        if (stop_.stop_possible()) {
            // Registering the callback can allocate, and allocation can throw.
            // By this point the submission is irreversible: the loop holds the
            // handle and the result slot, so letting an exception propagate
            // here would destroy the awaiter (and the frame's result slot)
            // while the operation is still in flight — the loop would then
            // finalize a dead object and resume a frame that never suspended,
            // both undefined behavior. Degrade instead: without the callback,
            // cancellation is not delivered early, but the operation itself
            // still completes (or times out) and resumes normally. Losing one
            // cancellation under OOM is the honest failure mode.
            try {
                callback_.emplace(stop_, Notify{this});
            } catch (...) {
                // Deliberately swallowed: see the comment above. Every path
                // out of here must leave the awaiter suspended-and-tracked.
            }
        }
        return true;
    }

    [[nodiscard]] T await_resume() const noexcept { return result_; }

private:
    struct Notify {
        OperationAwaiter* owner;

        void operator()() const noexcept { owner->request_cancel_(owner->id_); }
    };

    Submit submit_;
    RequestCancel request_cancel_;
    std::stop_token stop_;
    OperationId id_{kNoOperation};
    /// Destroyed when the coroutine resumes past the `co_await`, which happens
    /// outside the loop's lock — so the destructor's wait for a concurrently
    /// running callback cannot deadlock against it.
    std::optional<std::stop_callback<Notify>> callback_{};
    T result_{};
};

/// Build the awaiter for one operation, inferring its template arguments.
template<typename T, typename Submit, typename RequestCancel>
[[nodiscard]] auto
await_operation(Submit submit, RequestCancel request_cancel, std::stop_token stop) noexcept {
    return OperationAwaiter<T, Submit, RequestCancel>{
        std::move(submit), std::move(request_cancel), std::move(stop)};
}

/// The cancellation hook every cancellable operation shares: name the id, let
/// the loop deliver it.
///
/// A template so that it need not name `EventLoop::Impl`, which is private to
/// each backend.
template<typename Impl>
[[nodiscard]] auto cancel_through(Impl* impl) noexcept {
    return [impl](OperationId id) noexcept { impl->request_cancel(id); };
}

/// For a suspension with nothing to cancel, such as `yield`.
[[nodiscard]] inline auto cancel_never() noexcept {
    return [](OperationId) noexcept {};
}

/// Keep admission charged even after a queue is swapped into a dispatch
/// batch. Move the callable out so captures are released as soon as invocation
/// returns, not on the next loop turn. Both release and invocation are outside
/// the backend lock; a destructor may itself post work.
[[nodiscard]] inline move_only_function<void()> budgeted_post(
    move_only_function<void()> work, ResourceBudget::Reservation reservation) {
    return [work = std::move(work), reservation = std::move(reservation)]() mutable {
        auto running = std::move(work);
        reservation.reset();
        running();
    };
}

/// One throwing application callback must not strand later reliable control
/// callbacks already removed from the queue. Finish the batch, then propagate
/// the first exception to the host's pump boundary.
inline void dispatch_posts(std::vector<move_only_function<void()>>& batch) {
    std::exception_ptr failure;
    for (auto& work : batch) {
        auto running = std::move(work);
        try {
            running();
        } catch (...) {
            if (!failure) failure = std::current_exception();
        }
    }
    batch.clear();
    if (failure) std::rethrow_exception(failure);
}

/// Work queued by `post()`, drained on the loop thread.
class PostQueue {
public:
    void push(move_only_function<void()>&& work) { queued_.push_back(std::move(work)); }

    [[nodiscard]] bool empty() const noexcept { return queued_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return queued_.size(); }

    void drain_into(std::vector<move_only_function<void()>>& out) noexcept {
        out.swap(queued_);
    }

    void clear() noexcept { queued_.clear(); }

private:
    std::vector<move_only_function<void()>> queued_{};
};

}  // namespace Mira::detail
