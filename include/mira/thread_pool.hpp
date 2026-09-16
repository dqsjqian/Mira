// Mira - a modern C++23 thread pool.
//
// Copyright (c) 2026 dqsjqian
// SPDX-License-Identifier: MIT

#ifndef MIRA_THREAD_POOL_HPP
#define MIRA_THREAD_POOL_HPP

// std::stacktrace is the one C++23 library feature Mira uses that is not
// universally available. libc++ has no <stacktrace> header at all, Apple's
// included, and GCC 13 and 14 keep the symbols out of the main runtime
// library, so a toolchain can have the header and still fail to link it. The
// CMake build probes for both cases and defines MIRA_NO_STACKTRACE; a
// header-only user can define it too, and __has_include catches the missing
// header on its own.
#if !defined(MIRA_NO_STACKTRACE) && defined(__has_include)
#if !__has_include(<stacktrace>)
#define MIRA_NO_STACKTRACE 1
#endif
#endif

// [[assume]] where the compiler implements it, and nothing where it does not.
// MSVC only learned the attribute in 19.50, so VS2022 warns about it and a
// /WX build treats that warning as an error.
#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(assume) >= 202207L
#define MIRA_ASSUME(condition) [[assume(condition)]]
#endif
#endif
#if !defined(MIRA_ASSUME)
#define MIRA_ASSUME(condition) static_cast<void>(0)
#endif

#include <chrono>
#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <format>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <ranges>
#if !defined(MIRA_NO_STACKTRACE)
#include <stacktrace>
#endif
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace mira {

inline constexpr int version_major = 2;
inline constexpr int version_minor = 0;
inline constexpr int version_patch = 0;

/// The C++ standard level this translation unit was compiled with.
///
/// MSVC keeps __cplusplus at 199711L unless /Zc:__cplusplus is passed, so
/// _MSVC_LANG is the only reliable source there.
#if defined(_MSVC_LANG)
inline constexpr long cpp_standard = _MSVC_LANG;
#else
inline constexpr long cpp_standard = __cplusplus;
#endif

// 202100L is the smallest value any conforming C++23 implementation reports:
// GCC 13 and Clang 17 still say 202100/202101 and only later releases say
// 202302. C++20 reports 202002 on every compiler, so this threshold accepts
// every C++23 mode and rejects C++20 and below.
static_assert(cpp_standard >= 202100L,
              "Mira requires C++23 or later: use -std=c++23 (GCC/Clang) or "
              "/std:c++23preview or /std:c++latest (MSVC)");

using size_type = std::size_t;

// ---------------------------------------------------------------------------
// Standard library compatibility
//
// libc++ has not implemented std::move_only_function at all, not even in the
// version Apple ships with Xcode 26, so the task queue cannot name it
// directly. MoveOnlyFunction is the real thing where it exists and a small
// stand-in where it does not. Either way the queue holds a move-only,
// type-erased callable: no shared ownership and no reference counting.
// ---------------------------------------------------------------------------

#if defined(__cpp_lib_move_only_function)
template<class Signature> using MoveOnlyFunction = std::move_only_function<Signature>;
#else
/// A move-only type-erased callable, standing in for std::move_only_function.
template<class Signature> class MoveOnlyFunction;

template<class Result, class... Args> class MoveOnlyFunction<Result(Args...)> {
public:
    MoveOnlyFunction() noexcept = default;

    template<class Callable>
        requires(!std::same_as<std::remove_cvref_t<Callable>, MoveOnlyFunction> &&
                 std::invocable<std::remove_cvref_t<Callable>&, Args...>)
    MoveOnlyFunction(Callable&& callable)
        : holder_(std::make_unique<Holder<std::remove_cvref_t<Callable>>>(
              std::forward<Callable>(callable))) {}

    MoveOnlyFunction(MoveOnlyFunction&&) noexcept = default;
    MoveOnlyFunction& operator=(MoveOnlyFunction&&) noexcept = default;
    MoveOnlyFunction(const MoveOnlyFunction&) = delete;
    MoveOnlyFunction& operator=(const MoveOnlyFunction&) = delete;
    ~MoveOnlyFunction() = default;

    [[nodiscard]] explicit operator bool() const noexcept { return holder_ != nullptr; }

    Result operator()(Args... args) { return holder_->invoke(std::forward<Args>(args)...); }

private:
    struct Base {
        Base() = default;
        Base(const Base&) = delete;
        Base& operator=(const Base&) = delete;
        virtual ~Base() = default;
        virtual Result invoke(Args&&... args) = 0;
    };

    template<class Callable> class Holder final : public Base {
    public:
        explicit Holder(Callable callable) : callable_(std::move(callable)) {}

        Result invoke(Args&&... args) override {
            return std::invoke(callable_, std::forward<Args>(args)...);
        }

    private:
        Callable callable_;
    };

    std::unique_ptr<Base> holder_;
};
#endif

/// Lifecycle of a pool.
enum class State : std::uint8_t {
    /// Accepting submissions and executing tasks.
    running,
    /// Accepting submissions but not executing anything until resume().
    paused,
    /// No longer accepting submissions; workers finish the queue and exit.
    draining,
};

/// Why a submission or a control operation was refused.
enum class PoolError : std::uint8_t {
    /// The pool is draining or already shut down.
    stopped,
    /// Options::max_pending has been reached.
    queue_full,
};

[[nodiscard]] constexpr std::string_view to_string(State state) noexcept {
    switch (state) {
    case State::running:
        return "running";
    case State::paused:
        return "paused";
    case State::draining:
        return "draining";
    }
    std::unreachable();
}

[[nodiscard]] constexpr std::string_view to_string(PoolError error) noexcept {
    switch (error) {
    case PoolError::stopped:
        return "stopped";
    case PoolError::queue_full:
        return "queue_full";
    }
    std::unreachable();
}

/// A point-in-time copy of a pool's counters.
struct PoolStats {
    size_type threads = 0;
    size_type idle = 0;
    size_type active = 0;
    size_type pending = 0;
    size_type completed = 0;
    size_type max_pending = 0;
    State state = State::running;
};

#if defined(MIRA_NO_STACKTRACE)
/// One frame of a task's provenance trace.
///
/// This stands in for std::stacktrace_entry on toolchains that have no usable
/// std::stacktrace, so that TaskRecord keeps the same shape everywhere. It
/// always reports nothing.
class StackFrame {
public:
    [[nodiscard]] std::string description() const { return {}; }
    [[nodiscard]] std::string source_file() const { return {}; }
    [[nodiscard]] std::uint_least32_t source_line() const noexcept { return 0; }
};

/// The call stack captured when a task was submitted.
class StackTrace {
public:
    [[nodiscard]] bool empty() const noexcept { return true; }
    [[nodiscard]] std::size_t size() const noexcept { return 0; }
    [[nodiscard]] StackFrame operator[](std::size_t) const noexcept { return StackFrame{}; }
    [[nodiscard]] static StackTrace current(std::size_t skip = 0,
                                            std::size_t max_depth = 0) noexcept {
        static_cast<void>(skip);
        static_cast<void>(max_depth);
        return {};
    }
};
#else
/// One frame of a task's provenance trace.
using StackFrame = std::stacktrace_entry;
/// The call stack captured when a task was submitted.
using StackTrace = std::stacktrace;
#endif

/// Whether task provenance can be recorded in this translation unit.
#if defined(MIRA_NO_STACKTRACE)
inline constexpr bool has_stacktrace = false;
#else
inline constexpr bool has_stacktrace = true;
#endif

/// Where a task came from. Only recorded when Options::trace_depth is non-zero.
struct TaskRecord {
    /// Monotonic submission number, starting at 1.
    std::uint64_t sequence = 0;
    /// Stack of the submit()/try_submit() call site, empty when has_stacktrace
    /// is false. Symbol names need debug information in the binary; without it
    /// the frames carry module offsets.
    StackTrace origin;
};

/// Identity of one worker thread.
struct WorkerInfo {
    /// Position of the worker in the pool, 0 based.
    size_type index = 0;
    std::thread::id id;
};

[[nodiscard]] inline std::string to_string(const PoolStats& stats) {
    return std::format("threads={} idle={} active={} pending={} completed={} max_pending={} "
                       "state={}({})",
                       stats.threads, stats.idle, stats.active, stats.pending, stats.completed,
                       stats.max_pending, mira::to_string(stats.state),
                       std::to_underlying(stats.state));
}

/// A pool of worker threads that execute submitted tasks.
///
/// The pool owns its workers and keeps them alive until shutdown. Work is
/// submitted with submit(), which returns a std::future so callers can observe
/// the result or the exception of a task.
///
/// Design notes:
///   * Workers are std::jthread, so they are joined automatically and can be
///     retired cooperatively through std::stop_token.
///   * Every wait goes through a condition variable. There is no polling and no
///     busy-waiting anywhere in the implementation.
///   * Tasks are type-erased into a move-only callable (std::move_only_function
///     where the standard library has it), so a task never needs to be
///     copyable. A std::packaged_task is moved straight into the queue: no
///     shared_ptr, no atomic refcount and no extra allocation per submission.
///
/// Thread safety:
///   * submit() and try_submit() may be called concurrently from any number of
///     threads.
///   * resize(), pause(), resume(), wait(), wait_for() and shutdown() are
///     control-plane operations and are not meant to race with each other.
///   * A task must not call wait(), wait_for(), shutdown() or parallel_for() on
///     its own pool: the pool would wait for work that can only finish on the
///     thread doing the waiting. Submitting from inside a task is fine.
///
/// The pool is not movable or copyable, and the submitting entry points are
/// constrained to lvalue pools. `mira::ThreadPool(4).submit(f)` therefore does
/// not compile instead of handing back a future tied to a dead pool.
class ThreadPool {
public:
    using size_type = mira::size_type;
    using Task = MoveOnlyFunction<void()>;
    using State = mira::State;
    using PoolError = mira::PoolError;
    using Stats = PoolStats;

    /// Upper bound applied to resize() and the constructor, so a bad argument
    /// cannot try to spawn millions of threads.
    static constexpr size_type kMaxThreadCount = 4096;

    /// The worker count the pool actually uses for `requested`: 0 becomes 1,
    /// anything above kMaxThreadCount is capped, every other value is returned
    /// unchanged. This is the rule behind the documented "[1, kMaxThreadCount]"
    /// range, exposed so a caller can validate a configuration without paying
    /// to construct a pool.
    [[nodiscard]] static constexpr size_type clamp_thread_count(size_type requested) noexcept {
        const size_type clamped =
            requested == 0 ? 1 : (requested > kMaxThreadCount ? kMaxThreadCount : requested);
        // A pool with zero workers could never make progress, so every caller
        // may rely on at least one worker being requested.
        MIRA_ASSUME(clamped >= 1);
        return clamped;
    }

    /// Construction parameters.
    struct Options {
        /// Number of workers. 0 selects std::thread::hardware_concurrency().
        /// The ThreadPool(size_type) constructor treats 0 as 1 instead, because
        /// that overload promises a clamped explicit count.
        size_type thread_count = 0;
        /// Maximum number of queued tasks; 0 means unbounded. Once the limit is
        /// reached submit() throws and try_submit() reports
        /// PoolError::queue_full.
        size_type max_pending = 0;
        /// Number of most recent submissions to remember together with the call
        /// site that produced them; 0 disables tracing.
        size_type trace_depth = 0;
    };

    /// Creates a pool with default_thread_count() workers.
    ThreadPool() : ThreadPool(Options{}) {}

    /// Creates a pool with `thread_count` workers, clamped to
    /// [1, kMaxThreadCount]. Use Options to ask for the hardware concurrency
    /// instead: in Options a thread_count of 0 means "auto", here it means 1.
    explicit ThreadPool(size_type thread_count)
        : ThreadPool(Options{.thread_count = clamp_thread_count(thread_count)}) {}

    /// Creates a pool from an explicit configuration.
    explicit ThreadPool(Options options)
        : max_pending_(options.max_pending), trace_depth_(options.trace_depth) {
        const size_type requested =
            options.thread_count == 0 ? default_thread_count() : options.thread_count;
        spawn_workers(clamp_thread_count(requested));
    }

    /// Stops the pool and waits for queued and running tasks to finish.
    ~ThreadPool() { shutdown(); }

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    // ---------------------------------------------------------------- submit

    /// Enqueues a callable and returns a future for its result.
    ///
    /// The callable is invoked as std::invoke(fn, args...), so free functions,
    /// lambdas, functors, member function pointers and move-only callables all
    /// work. If the task throws, the exception is captured in the returned
    /// future.
    ///
    /// Throws std::runtime_error if the pool is draining or the queue is full.
    /// The return value is [[nodiscard]]: for fire-and-forget behaviour make
    /// that explicit with a static_cast<void>(...).
    ///
    /// The `this Self&&` parameter is C++23 explicit object parameter syntax.
    /// It exists to require an lvalue pool, so a future can never outlive the
    /// pool that produced it.
    template<class Self, class F, class... Args>
        requires std::is_lvalue_reference_v<Self> &&
                 std::same_as<std::remove_cvref_t<Self>, ThreadPool> &&
                 std::invocable<std::decay_t<F>, std::decay_t<Args>...>
    [[nodiscard]] auto submit(this Self&& self, F&& fn, Args&&... args)
        -> std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>> {
        using result_type = std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>;

        std::packaged_task<result_type()> task(
            [callable = std::forward<F>(fn),
             ... bound = std::forward<Args>(args)]() mutable -> result_type {
                return std::invoke(std::move(callable), std::move(bound)...);
            });

        std::future<result_type> future = task.get_future();
        self.accept_or_throw(Task(std::move(task)));
        return future;
    }

    /// Non-throwing submit(): reports why the task was refused instead of
    /// throwing.
    ///
    /// `pool.try_submit(fn, args...)` returns the future, or a PoolError. This
    /// is the entry point to use when backpressure (Options::max_pending) or a
    /// concurrent shutdown is expected rather than exceptional.
    template<class Self, class F, class... Args>
        requires std::is_lvalue_reference_v<Self> &&
                 std::same_as<std::remove_cvref_t<Self>, ThreadPool> &&
                 std::invocable<std::decay_t<F>, std::decay_t<Args>...>
    [[nodiscard]] auto try_submit(this Self&& self, F&& fn, Args&&... args)
        -> std::expected<std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>,
                         PoolError> {
        using result_type = std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>;

        std::packaged_task<result_type()> task(
            [callable = std::forward<F>(fn),
             ... bound = std::forward<Args>(args)]() mutable -> result_type {
                return std::invoke(std::move(callable), std::move(bound)...);
            });

        std::future<result_type> future = task.get_future();
        if (const std::expected<void, PoolError> accepted = self.try_accept(Task(std::move(task)));
            !accepted) {
            return std::unexpected(accepted.error());
        }
        return future;
    }

    // ---------------------------------------------------------------- bulk work

    /// Runs `fn` for every index in [first, last) on the pool's workers.
    ///
    /// The range is split into at most thread_count() contiguous chunks, one
    /// task per chunk. This call blocks until every chunk has finished. If a
    /// chunk throws, the remaining chunks are still awaited and the first
    /// exception is rethrown to the caller.
    ///
    /// Must not be called from inside a task.
    template<class Self, class Index, class F>
        requires std::is_lvalue_reference_v<Self> &&
                 std::same_as<std::remove_cvref_t<Self>, ThreadPool> && std::integral<Index> &&
                 std::invocable<F&, Index>
    void parallel_for(this Self&& self, Index first, Index last, F fn) {
        if (first >= last) {
            return;
        }

        const size_type total = static_cast<size_type>(last - first);
        size_type chunks = self.thread_count();
        if (chunks > total) {
            chunks = total;
        }
        if (chunks == 0) {
            chunks = 1;
        }
        const size_type chunk = (total + chunks - 1) / chunks;
        // Every index is covered because chunks <= total, so the rounded-up
        // chunk size is at least one.
        MIRA_ASSUME(chunk >= 1);

        std::vector<std::future<void>> futures;
        futures.reserve(chunks);
        for (size_type index = 0; index < chunks; ++index) {
            const size_type offset = index * chunk;
            if (offset >= total) {
                break;
            }
            const size_type remaining = total - offset;
            const size_type length = remaining < chunk ? remaining : chunk;
            futures.push_back(self.submit([&fn, first, offset, length] {
                for (size_type step = 0; step < length; ++step) {
                    std::invoke(fn, static_cast<Index>(first + static_cast<Index>(offset + step)));
                }
            }));
        }

        std::exception_ptr failure;
        for (std::future<void>& future : futures) {
            try {
                future.get();
            } catch (...) {
                if (!failure) {
                    failure = std::current_exception();
                }
            }
        }
        if (failure) {
            std::rethrow_exception(failure);
        }
    }

    /// Runs `fn` for every element of `range` on the pool's workers.
    ///
    /// A random-access range is split the same way parallel_for() splits an
    /// index range. `fn` receives an lvalue reference to the element. Must not
    /// be called from inside a task.
    template<class Self, class Range, class F>
        requires std::is_lvalue_reference_v<Self> &&
                 std::same_as<std::remove_cvref_t<Self>, ThreadPool> &&
                 std::ranges::random_access_range<Range> && std::ranges::sized_range<Range> &&
                 std::invocable<F&, std::ranges::range_reference_t<Range>>
    void parallel_for_each(this Self&& self, Range&& range, F fn) {
        const size_type total = static_cast<size_type>(std::ranges::size(range));
        if (total == 0) {
            return;
        }
        self.parallel_for(size_type{0}, total,
                          [&range, &fn](size_type index) { std::invoke(fn, range[index]); });
    }

    // ----------------------------------------------------------- pool control

    /// Grows or shrinks the pool at run time.
    ///
    /// Growing spawns new workers immediately. Shrinking retires workers
    /// without interrupting them: a retiring worker finishes the task it is
    /// running and then exits. `thread_count` is clamped to [1, kMaxThreadCount].
    /// Returns PoolError::stopped when the pool is draining.
    [[nodiscard]] std::expected<void, PoolError> try_resize(size_type thread_count) {
        thread_count = clamp_thread_count(thread_count);

        std::vector<std::jthread> retired;
        {
            std::lock_guard lock(mutex_);
            if (state_ == State::draining) {
                return std::unexpected(PoolError::stopped);
            }
            // workers_ is only ever moved from inside shutdown(), which flips
            // state_ to draining under the same lock. Passing the check above
            // therefore proves workers_ was never moved from here.
            // NOLINTNEXTLINE(clang-analyzer-cplusplus.Move)
            const size_type current = workers_.size();
            if (thread_count > current) {
                spawn_workers(thread_count - current);
            } else if (thread_count < current) {
                retired.reserve(current - thread_count);
                for (size_type index = 0; index < current - thread_count; ++index) {
                    retired.push_back(std::move(workers_.back()));
                    workers_.pop_back();
                }
            }
        }

        if (!retired.empty()) {
            // Destroying a std::jthread requests its stop and then joins it.
            // Do this outside the lock: a retiring worker needs the lock to
            // finish its loop before it can exit.
            work_cv_.notify_all();
            retired.clear();
        }
        return {};
    }

    /// Grows or shrinks the pool at run time. Throws std::runtime_error when
    /// the pool is draining.
    void resize(size_type thread_count) {
        const std::expected<void, PoolError> result = try_resize(thread_count);
        if (!result) {
            throw std::runtime_error("mira::ThreadPool: resize() on a stopped pool");
        }
    }

    /// Suspends task execution. Queued tasks stay queued until resume().
    /// No-op unless the pool is running.
    void pause() {
        std::lock_guard lock(mutex_);
        if (state_ == State::running) {
            state_ = State::paused;
        }
    }

    /// Resumes task execution after pause(). No-op unless the pool is paused.
    void resume() {
        {
            std::lock_guard lock(mutex_);
            if (state_ != State::paused) {
                return;
            }
            state_ = State::running;
        }
        work_cv_.notify_all();
    }

    /// Blocks until every submitted task has finished. Tasks submitted by other
    /// threads after this call are not waited for. Must not be called from
    /// inside a task, and will not return while the pool is paused with pending
    /// work.
    void wait() {
        std::unique_lock lock(mutex_);
        idle_cv_.wait(lock, [this] { return outstanding_ == 0; });
    }

    /// Blocks until every submitted task has finished, or until `timeout`
    /// elapses. Returns true when the pool became idle. Same restrictions as
    /// wait().
    template<class Rep, class Period>
    bool wait_for(const std::chrono::duration<Rep, Period>& timeout) {
        std::unique_lock lock(mutex_);
        return idle_cv_.wait_for(lock, timeout, [this] { return outstanding_ == 0; });
    }

    /// Stops accepting new tasks, drains the queue, then joins every worker.
    ///
    /// Safe to call more than once and from the destructor. Concurrent callers
    /// all block until the pool has fully stopped.
    void shutdown() {
        std::call_once(shutdown_once_, [this] {
            std::vector<std::jthread> workers;
            {
                std::lock_guard lock(mutex_);
                state_ = State::draining;
                workers = std::move(workers_);
            }
            work_cv_.notify_all();
            // Each worker drains the remaining queue before it exits, so this
            // returns only once every submitted task has completed.
            workers.clear();
        });
    }

    // ----------------------------------------------------------- observation

    /// Number of worker threads currently owned by the pool.
    [[nodiscard]] size_type thread_count() const {
        std::lock_guard lock(mutex_);
        return workers_.size();
    }

    /// Number of workers that are not currently executing a task.
    [[nodiscard]] size_type idle_count() const {
        std::lock_guard lock(mutex_);
        const size_type workers = workers_.size();
        return workers > active_ ? workers - active_ : 0;
    }

    /// Number of tasks currently executing.
    [[nodiscard]] size_type active_count() const {
        std::lock_guard lock(mutex_);
        return active_;
    }

    /// Number of tasks waiting in the queue.
    [[nodiscard]] size_type pending_count() const {
        std::lock_guard lock(mutex_);
        return tasks_.size();
    }

    /// Number of tasks that have finished since the pool was created.
    [[nodiscard]] size_type completed_count() const {
        std::lock_guard lock(mutex_);
        return completed_;
    }

    /// Configured queue limit, or 0 when the queue is unbounded.
    [[nodiscard]] size_type max_pending() const {
        std::lock_guard lock(mutex_);
        return max_pending_;
    }

    /// True while the pool is paused.
    [[nodiscard]] bool paused() const {
        std::lock_guard lock(mutex_);
        return state_ == State::paused;
    }

    /// True once shutdown() has started.
    [[nodiscard]] bool stopped() const {
        std::lock_guard lock(mutex_);
        return state_ == State::draining;
    }

    /// Current lifecycle state.
    [[nodiscard]] State state() const {
        std::lock_guard lock(mutex_);
        return state_;
    }

    /// Every counter in one consistent snapshot, taken under a single lock.
    [[nodiscard]] Stats stats() const {
        std::lock_guard lock(mutex_);
        const size_type workers = workers_.size();
        return Stats{
            .threads = workers,
            .idle = workers > active_ ? workers - active_ : 0,
            .active = active_,
            .pending = tasks_.size(),
            .completed = completed_,
            .max_pending = max_pending_,
            .state = state_,
        };
    }

    /// Index and thread id of every worker.
    ///
    /// Written as a loop rather than with std::views::enumerate and
    /// std::ranges::to: libc++ has no enumerate at all, and Clang 20 against
    /// libstdc++ 14 rejects the piped form of ranges::to.
    [[nodiscard]] std::vector<WorkerInfo> workers() const {
        std::lock_guard lock(mutex_);
        std::vector<WorkerInfo> result;
        result.reserve(workers_.size());
        for (size_type index = 0; index < workers_.size(); ++index) {
            result.push_back(WorkerInfo{.index = index, .id = workers_[index].get_id()});
        }
        return result;
    }

    /// The most recent submissions, newest last, at most
    /// Options::trace_depth entries. Empty when tracing is disabled.
    [[nodiscard]] std::vector<TaskRecord> task_history() const {
        std::lock_guard lock(mutex_);
        return {history_.begin(), history_.end()};
    }

    /// Hardware concurrency, or 1 when the platform cannot report it.
    [[nodiscard]] static size_type default_thread_count() noexcept {
        const unsigned int hardware = std::thread::hardware_concurrency();
        return hardware == 0 ? 1 : static_cast<size_type>(hardware);
    }

private:
    /// Queues `task`, or reports why it could not be queued.
    [[nodiscard]] std::expected<void, PoolError> try_accept(Task task) {
        {
            std::lock_guard lock(mutex_);
            if (state_ == State::draining) {
                return std::unexpected(PoolError::stopped);
            }
            if (max_pending_ != 0 && tasks_.size() >= max_pending_) {
                return std::unexpected(PoolError::queue_full);
            }
            if (trace_depth_ != 0) {
                // Frame 0 is current() itself; the next frames are Mira's own
                // submit path, then the caller.
                history_.push_back(
                    TaskRecord{.sequence = ++sequence_, .origin = StackTrace::current(1)});
                while (history_.size() > trace_depth_) {
                    history_.pop_front();
                }
            }
            tasks_.push_back(std::move(task));
            ++outstanding_;
        }
        work_cv_.notify_one();
        return {};
    }

    /// Queues `task` or throws, for the throwing submit() overload.
    void accept_or_throw(Task task) {
        const std::expected<void, PoolError> accepted = try_accept(std::move(task));
        if (!accepted) {
            throw std::runtime_error(std::string("mira::ThreadPool: submit() refused: ") +
                                     std::string(to_string(accepted.error())));
        }
    }

    /// Spawns `count` workers. The caller must either hold mutex_ or be the
    /// constructor, where no other thread can observe the pool yet.
    void spawn_workers(size_type count) {
        workers_.reserve(workers_.size() + count);
        for (size_type index = 0; index < count; ++index) {
            // std::jthread hands the token to the callable, which is invocable
            // whether it takes the token by value or by const reference.
            workers_.emplace_back(
                [this](const std::stop_token& stop_token) { worker_loop(stop_token); });
        }
    }

    void worker_loop(const std::stop_token& stop_token) {
        std::unique_lock lock(mutex_);
        for (;;) {
            // Wake up when there is work, when the pool starts draining, or when
            // this particular worker is asked to stop.
            work_cv_.wait(lock, stop_token, [this] {
                return state_ == State::draining || (state_ == State::running && !tasks_.empty());
            });

            if (stop_token.stop_requested() && state_ != State::draining) {
                // Retired by resize(): leave the remaining work to the others.
                break;
            }
            if (tasks_.empty()) {
                // Only reachable while draining. The queue is empty, so this
                // worker is done.
                break;
            }

            Task task = std::move(tasks_.front());
            tasks_.pop_front();
            ++active_;
            lock.unlock();

            try {
                task();
            } catch (...) { // NOLINT(bugprone-empty-catch) - deliberate, see below
                // A std::packaged_task stores the exception in its future, so a
                // task that throws normally never reaches this handler. Landing
                // here means a task wrapper threw outside its own storage.
                // Letting it escape would kill the worker and take the process
                // with it, and there is no caller left to report it to, so
                // swallowing it is the only safe option.
            }

            lock.lock();
            --active_;
            --outstanding_;
            ++completed_;
            if (outstanding_ == 0) {
                idle_cv_.notify_all();
            }
        }
    }

    mutable std::mutex mutex_;
    std::condition_variable_any work_cv_;
    std::condition_variable idle_cv_;
    std::deque<Task> tasks_;
    std::deque<TaskRecord> history_;
    std::vector<std::jthread> workers_;
    std::once_flag shutdown_once_;
    size_type active_ = 0;
    size_type outstanding_ = 0;
    size_type completed_ = 0;
    size_type max_pending_ = 0;
    size_type trace_depth_ = 0;
    std::uint64_t sequence_ = 0;
    State state_ = State::running;
};

} // namespace mira

template<> struct std::formatter<mira::State, char> {
    constexpr auto parse(std::format_parse_context& ctx) { return ctx.begin(); }

    auto format(mira::State state, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "{}", mira::to_string(state));
    }
};

template<> struct std::formatter<mira::PoolError, char> {
    constexpr auto parse(std::format_parse_context& ctx) { return ctx.begin(); }

    auto format(mira::PoolError error, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "{}", mira::to_string(error));
    }
};

template<> struct std::formatter<mira::PoolStats, char> {
    constexpr auto parse(std::format_parse_context& ctx) { return ctx.begin(); }

    auto format(const mira::PoolStats& stats, std::format_context& ctx) const {
        return std::format_to(ctx.out(),
                              "threads={} idle={} active={} pending={} completed={} "
                              "max_pending={} state={}",
                              stats.threads, stats.idle, stats.active, stats.pending,
                              stats.completed, stats.max_pending, mira::to_string(stats.state));
    }
};

#endif // MIRA_THREAD_POOL_HPP
