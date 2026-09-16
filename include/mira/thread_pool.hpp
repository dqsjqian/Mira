// Mira - a modern C++20 thread pool.
//
// Copyright (c) 2026 dqsjqian
// SPDX-License-Identifier: MIT

#ifndef MIRA_THREAD_POOL_HPP
#define MIRA_THREAD_POOL_HPP

#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace mira {

inline constexpr int version_major = 1;
inline constexpr int version_minor = 0;
inline constexpr int version_patch = 0;

/// A fixed-size pool of worker threads that execute submitted tasks.
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
///   * Tasks are type-erased into std::function<void()>. The concrete callable
///     is stored inside a std::packaged_task, which gives each task a future
///     and keeps the queue copyable even for move-only callables.
///
/// Thread safety:
///   * submit() may be called concurrently from any number of threads.
///   * resize(), pause(), resume(), wait() and shutdown() are control-plane
///     operations and are not meant to race with each other.
///   * A task must not call wait() or shutdown() on its own pool: the pool
///     would wait for work that can only finish on the thread doing the
///     waiting. Submitting from inside a task is fine.
class ThreadPool {
public:
    using Task = std::function<void()>;
    using size_type = std::size_t;

    /// Upper bound applied to resize() and the constructor, so a bad argument
    /// cannot try to spawn millions of threads.
    static constexpr size_type kMaxThreadCount = 4096;

    /// Creates a pool with default_thread_count() workers.
    ThreadPool() : ThreadPool(default_thread_count()) {}

    /// Creates a pool with `thread_count` workers. The value is clamped to
    /// [1, kMaxThreadCount].
    explicit ThreadPool(size_type thread_count) { spawn_workers(clamp_thread_count(thread_count)); }

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
    /// Throws std::runtime_error if the pool has been shut down. The return
    /// value is [[nodiscard]]: if you really want fire-and-forget behaviour,
    /// make that explicit with a static_cast<void>(...).
    template<class F, class... Args>
        requires std::invocable<std::decay_t<F>, std::decay_t<Args>...>
    [[nodiscard]] auto submit(F&& fn, Args&&... args)
        -> std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>> {
        using result_type = std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>;

        auto task = std::make_shared<std::packaged_task<result_type()>>(
            [callable = std::forward<F>(fn),
             ... bound = std::forward<Args>(args)]() mutable -> result_type {
                return std::invoke(std::move(callable), std::move(bound)...);
            });

        std::future<result_type> future = task->get_future();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                throw std::runtime_error("mira::ThreadPool: submit() on a stopped pool");
            }
            tasks_.emplace([task] { (*task)(); });
            ++outstanding_;
        }
        work_cv_.notify_one();
        return future;
    }

    // ----------------------------------------------------------- pool control

    /// Grows or shrinks the pool at run time.
    ///
    /// Growing spawns new workers immediately. Shrinking retires workers
    /// without interrupting them: a retiring worker finishes the task it is
    /// running and then exits. `thread_count` is clamped to [1, kMaxThreadCount].
    /// Calling resize() on a stopped pool does nothing.
    void resize(size_type thread_count) {
        thread_count = clamp_thread_count(thread_count);

        std::vector<std::jthread> retired;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return;
            }
            const size_type current = workers_.size();
            if (thread_count > current) {
                spawn_workers(thread_count - current);
            } else if (thread_count < current) {
                retired.reserve(current - thread_count);
                for (size_type i = 0; i < current - thread_count; ++i) {
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
    }

    /// Suspends task execution. Queued tasks stay queued until resume().
    void pause() {
        std::lock_guard<std::mutex> lock(mutex_);
        paused_ = true;
    }

    /// Resumes task execution after pause().
    void resume() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            paused_ = false;
        }
        work_cv_.notify_all();
    }

    /// Blocks until every submitted task has finished. Tasks submitted by other
    /// threads after this call are not waited for. Must not be called from
    /// inside a task, and will not return while the pool is paused with pending
    /// work.
    void wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        idle_cv_.wait(lock, [this] { return outstanding_ == 0; });
    }

    /// Stops accepting new tasks, drains the queue, then joins every worker.
    ///
    /// Safe to call more than once and from the destructor. Concurrent callers
    /// all block until the pool has fully stopped.
    void shutdown() {
        std::call_once(shutdown_once_, [this] { do_shutdown(); });
    }

    // ----------------------------------------------------------- observation

    /// Number of worker threads currently owned by the pool.
    [[nodiscard]] size_type thread_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return workers_.size();
    }

    /// Number of workers that are not currently executing a task.
    [[nodiscard]] size_type idle_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        const size_type workers = workers_.size();
        return workers > active_ ? workers - active_ : 0;
    }

    /// Number of tasks currently executing.
    [[nodiscard]] size_type active_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return active_;
    }

    /// Number of tasks waiting in the queue.
    [[nodiscard]] size_type pending_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tasks_.size();
    }

    /// True while the pool is paused.
    [[nodiscard]] bool paused() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return paused_;
    }

    /// True once shutdown() has started.
    [[nodiscard]] bool stopped() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stopping_;
    }

    /// Hardware concurrency, or 1 when the platform cannot report it.
    [[nodiscard]] static size_type default_thread_count() noexcept {
        const unsigned int hardware = std::thread::hardware_concurrency();
        return hardware == 0 ? 1 : static_cast<size_type>(hardware);
    }

private:
    static size_type clamp_thread_count(size_type count) noexcept {
        if (count == 0) {
            return 1;
        }
        return count > kMaxThreadCount ? kMaxThreadCount : count;
    }

    /// Spawns `count` workers. The caller must either hold mutex_ or be the
    /// constructor, where no other thread can observe the pool yet.
    void spawn_workers(size_type count) {
        workers_.reserve(workers_.size() + count);
        for (size_type i = 0; i < count; ++i) {
            workers_.emplace_back([this](std::stop_token stop_token) { worker_loop(stop_token); });
        }
    }

    void worker_loop(std::stop_token stop_token) {
        std::unique_lock<std::mutex> lock(mutex_);
        for (;;) {
            // Wake up when there is work, when the pool starts draining, or
            // when this particular worker is asked to stop.
            work_cv_.wait(lock, stop_token, [this] {
                if (draining_) {
                    return true;
                }
                return !paused_ && !tasks_.empty();
            });

            if (stop_token.stop_requested() && !draining_) {
                // Retired by resize(): leave the remaining work to the others.
                break;
            }
            if (tasks_.empty()) {
                // Only reachable while draining. The queue is empty, so this
                // worker is done.
                break;
            }

            Task task = std::move(tasks_.front());
            tasks_.pop();
            ++active_;
            lock.unlock();

            try {
                task();
            } catch (...) {
                // A std::packaged_task stores the exception in its future.
                // Anything that still escapes here must not kill the worker.
            }

            lock.lock();
            --active_;
            --outstanding_;
            if (outstanding_ == 0) {
                idle_cv_.notify_all();
            }
        }
    }

    void do_shutdown() {
        std::vector<std::jthread> workers;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
            draining_ = true;
            paused_ = false;
            workers = std::move(workers_);
        }
        work_cv_.notify_all();
        // Each worker drains the remaining queue before it exits, so this
        // returns only once every submitted task has completed.
        workers.clear();
    }

    mutable std::mutex mutex_;
    std::condition_variable_any work_cv_;
    std::condition_variable idle_cv_;
    std::queue<Task> tasks_;
    std::vector<std::jthread> workers_;
    std::once_flag shutdown_once_;
    size_type active_ = 0;
    size_type outstanding_ = 0;
    bool paused_ = false;
    bool stopping_ = false;
    bool draining_ = false;
};

} // namespace mira

#endif // MIRA_THREAD_POOL_HPP
