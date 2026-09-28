#pragma once

#include "mira/core/event_loop.hpp"
#include "mira/core/resource_budget.hpp"

#include <atomic>
#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <exception>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <new>
#include <stop_token>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace Mira {

/// Independent, thread-affine loops, not several threads pumping one loop.
/// Every worker creates, drives, and destroys its own EventLoop. Sockets must
/// be created and used on that worker; an already attached socket may not be
/// handed to another worker (in particular, IOCP association is not movable).
///
/// Submission owns a task factory until its Task AND coroutine frame finish.
/// This makes temporary, capture-owning coroutine lambdas safe. References
/// captured by a factory remain the caller's responsibility. Tasks must remain
/// on their worker and cooperate with the supplied stop token. Do not destroy
/// the group, pump/stop its EventLoop directly, or detach unowned tasks inside
/// a worker. request_stop() is safe on a worker; join() rejects self-join.
///
/// Destruction requests stop and joins, so uncooperative tasks may block it.
/// Destroying the group on its own worker terminates instead of self-joining
/// or leaving a thread with a dangling owner. No thread is ever detached.
class LoopGroup final {
public:
    struct Options {
        std::size_t workers = 1;
        std::size_t max_tasks_per_worker = 1024;
    };

    /// Called on each worker before publication. Each worker owns a copy of
    /// this function; any shared captured state needs its own synchronization.
    /// The factory must create the loop on the calling thread. A failed or
    /// throwing factory rolls back all workers before create() returns.
    using LoopFactory = std::function<Result<EventLoop>(std::size_t)>;

    [[nodiscard]] static Result<std::unique_ptr<LoopGroup>> create(
        Options options, LoopFactory factory = {}) {
        if (options.workers == 0) return fail(Errc::invalid_argument);
        std::unique_ptr<LoopGroup> group;
        try {
            group.reset(new LoopGroup(options));
            for (std::size_t i = 0; i < group->workers_.size(); ++i) {
                auto* worker = group->workers_[i].get();
                worker->thread = std::thread(
                    [owner = group.get(), worker, i, make = factory]() mutable {
                        owner->run_worker(*worker, i, make);
                    });
            }
            {
                std::unique_lock lock{group->mutex_};
                group->started_.wait(lock, [&] {
                    return group->ready_ == group->workers_.size();
                });
                if (group->failure_) return fail(group->failure_);
            }
            return group;
        } catch (const std::bad_alloc&) {
            return fail(std::make_error_code(std::errc::not_enough_memory));
        } catch (const std::system_error& error) {
            return fail(error.code());
        } catch (...) {
            return fail(Errc::internal);
        }
        // On every failure the local owner requests stop and joins all threads
        // already started, including failures part-way through thread creation.
    }

    LoopGroup(const LoopGroup&) = delete;
    LoopGroup& operator=(const LoopGroup&) = delete;
    LoopGroup(LoopGroup&&) = delete;
    LoopGroup& operator=(LoopGroup&&) = delete;

    ~LoopGroup() {
        if (current_ == this) std::terminate();
        request_stop();
        (void)join();
    }

    [[nodiscard]] std::size_t size() const noexcept { return workers_.size(); }

    /// The quota covers queued AND unfinished root tasks; completions and
    /// cancellation never consume it. Saturation returns would_block, a stop
    /// request returns cancelled. Allocation failures may throw before
    /// acceptance, with the reservation and unstarted task rolled back.
    template<typename Factory>
        requires std::same_as<std::invoke_result_t<std::decay_t<Factory>&,
                                                   EventLoop&, std::stop_token>, Task<void>>
    [[nodiscard]] Result<void> try_spawn(std::size_t index, Factory&& factory) {
        if (index >= workers_.size()) return fail(Errc::invalid_argument);
        if (stopping()) return fail(Errc::cancelled);
        auto* worker = workers_[index].get();
        auto slot = worker->tasks.try_acquire(1);
        if (!slot) return fail(slot.error());
        auto pending = std::make_shared<std::list<Root>>();
        pending->push_back(own_task(std::decay_t<Factory>(std::forward<Factory>(factory)),
                                    worker, std::move(*slot)));
        move_only_function<void()> submit = [worker, pending]() mutable {
            // Allocate the ownership node before admission. Starting accepted
            // work must not fail while installing its frame in the worker.
            worker->roots.splice(worker->roots.end(), *pending);
            worker->roots.back().start();
        };
        // Keep a second owner until the lock is released: if post allocation
        // throws, a user factory destructor must not reenter under mutex_.
        const std::lock_guard lock{mutex_};
        if (stopping() || worker->loop == nullptr) return fail(Errc::cancelled);
        worker->loop->post(std::move(submit));
        return {};
    }

    /// Round-robin admission. A full selected worker is reported to the caller,
    /// not silently rerouted: worker affinity is never changed under load.
    template<typename Factory>
        requires std::same_as<std::invoke_result_t<std::decay_t<Factory>&,
                                                   EventLoop&, std::stop_token>, Task<void>>
    [[nodiscard]] Result<void> try_spawn(Factory&& factory) {
        const auto index = next_.fetch_add(1, std::memory_order_relaxed) % size();
        return try_spawn(index, std::forward<Factory>(factory));
    }

    /// Close admission and wake all loops through their reliable control
    /// channel. Stop callbacks run on each worker, outside group locks.
    void request_stop() noexcept {
        if (stopping_.exchange(true, std::memory_order_acq_rel)) return;
        const std::lock_guard lock{mutex_};
        for (const auto& worker : workers_) {
            if (!worker->loop) continue;
            try {
                worker->loop->post([] {});
            } catch (...) {
                // The stop flag is still observed even if allocating the wake
                // callback failed. stop() does not allocate, but subsequent
                // graceful draining may poll rather than block on this path.
                worker->loop->stop();
            }
        }
    }

    [[nodiscard]] bool stopping() const noexcept {
        return stopping_.load(std::memory_order_acquire);
    }

    /// Wait for cooperative shutdown and return the first worker failure.
    /// Call request_stop() first (or arrange another thread to do so). Safe to
    /// repeat, and concurrent external join calls are serialized. A worker's
    /// join returns resource_deadlock_would_occur without blocking or stopping.
    [[nodiscard]] Result<void> join() {
        if (current_ == this)
            return fail(std::make_error_code(std::errc::resource_deadlock_would_occur));
        const std::lock_guard joining{join_mutex_};
        for (const auto& worker : workers_) {
            if (worker->thread.joinable()) worker->thread.join();
        }
        const std::lock_guard lock{mutex_};
        if (failure_) return fail(failure_);
        return {};
    }

    [[nodiscard]] Result<ResourceBudget::Stats> task_stats(std::size_t index) const {
        if (index >= workers_.size()) return fail(Errc::invalid_argument);
        return workers_[index]->tasks.stats();
    }

    /// When join reports internal, retain the original task/factory exception.
    [[nodiscard]] std::exception_ptr exception() const {
        const std::lock_guard lock{mutex_};
        return exception_;
    }

private:
    struct Root {
        struct promise_type {
            std::exception_ptr failure;
            Root get_return_object() noexcept {
                return Root{std::coroutine_handle<promise_type>::from_promise(*this)};
            }
            std::suspend_always initial_suspend() const noexcept { return {}; }
            std::suspend_always final_suspend() const noexcept { return {}; }
            void return_void() const noexcept {}
            void unhandled_exception() noexcept { failure = std::current_exception(); }
        };
        using Handle = std::coroutine_handle<promise_type>;
        explicit Root(Handle handle) noexcept : handle_(handle) {}
        Root(Root&& other) noexcept
            : handle_(std::exchange(other.handle_, {})), started_(other.started_) {}
        Root(const Root&) = delete;
        Root& operator=(const Root&) = delete;
        ~Root() {
            if (!handle_) return;
            if (started_ && !handle_.done()) std::terminate();
            handle_.destroy();
        }
        void start() {
            started_ = true;
            handle_.resume();
        }
        [[nodiscard]] bool done() const noexcept { return handle_.done(); }
        [[nodiscard]] std::exception_ptr failure() const noexcept {
            return handle_.promise().failure;
        }
        Handle handle_;
        bool started_ = false;
    };

    struct Worker {
        explicit Worker(std::size_t capacity) : tasks(capacity) {}
        ResourceBudget tasks;
        std::thread thread;
        EventLoop* loop = nullptr;  // published/cleared under mutex_
        std::stop_source stop;
        std::list<Root> roots;      // worker thread only
    };

    explicit LoopGroup(Options options) {
        workers_.reserve(options.workers);
        for (std::size_t i = 0; i < options.workers; ++i)
            workers_.push_back(std::make_unique<Worker>(options.max_tasks_per_worker));
    }

    template<typename Factory>
    static Root own_task(Factory factory, Worker* worker,
                          ResourceBudget::Reservation reservation) {
        // Parameters remain in this stable frame through final suspension,
        // including the factory closure captured by a coroutine lambda.
        (void)reservation;
        auto task = std::invoke(factory, *worker->loop, worker->stop.get_token());
        if (!task) throw std::invalid_argument("Mira::LoopGroup: empty task");
        co_await std::move(task);
    }

    void failed(Error error, std::exception_ptr exception = {}) noexcept {
        {
            const std::lock_guard lock{mutex_};
            if (!failure_) {
                failure_ = error;
                exception_ = exception;
            }
        }
        request_stop();
    }

    void reap(Worker& worker) {
        for (auto it = worker.roots.begin(); it != worker.roots.end();) {
            if (!it->done()) {
                ++it;
                continue;
            }
            auto error = it->failure();
            it = worker.roots.erase(it);
            if (error) failed(make_error_code(Errc::internal), error);
        }
    }

    void run_worker(Worker& worker, std::size_t index, LoopFactory& factory) noexcept {
        current_ = this;
        bool announced = false;
        try {
            auto created = factory ? factory(index) : EventLoop::create();
            if (!created) {
                failed(created.error());
            } else {
                {
                    const std::lock_guard lock{mutex_};
                    worker.loop = &*created;
                    ++ready_;
                    announced = true;
                }
                started_.notify_all();
                for (;;) {
                    if (stopping()) worker.stop.request_stop();
                    reap(worker);
                    if (stopping() && worker.roots.empty()) {
                        // Serialize the final emptiness check with admission:
                        // a producer may have passed its stop check just before
                        // request_stop closed the gate and still be posting.
                        const std::lock_guard lock{mutex_};
                        if (created->outstanding() == 0) {
                            worker.loop = nullptr;
                            break;
                        }
                    }
                    try {
                        auto pumped = created->run_once();
                        if (!pumped) {
                            failed(pumped.error());
                            // A failed kernel pump cannot safely abandon a
                            // started frame or promise future completions.
                            if (!worker.roots.empty()) std::terminate();
                            break;
                        }
                    } catch (...) {
                        failed(make_error_code(Errc::internal), std::current_exception());
                    }
                }
                {
                    const std::lock_guard lock{mutex_};
                    worker.loop = nullptr;
                }
                // created (and its backend handles) dies on this worker.
            }
        } catch (...) {
            failed(make_error_code(Errc::internal), std::current_exception());
        }
        if (!announced) {
            const std::lock_guard lock{mutex_};
            ++ready_;
        }
        started_.notify_all();
        // Keep the marker until thread exit: destroying the thread's captured
        // loop factory is still worker code and must not self-join either.
    }

    inline static thread_local LoopGroup* current_ = nullptr;
    std::vector<std::unique_ptr<Worker>> workers_;
    mutable std::mutex mutex_;
    std::mutex join_mutex_;
    std::condition_variable started_;
    std::size_t ready_ = 0;
    Error failure_;
    std::exception_ptr exception_;
    std::atomic<bool> stopping_{false};
    std::atomic<std::size_t> next_{0};
};

}  // namespace Mira
