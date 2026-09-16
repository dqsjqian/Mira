// Mira - self-contained test suite.
//
// Copyright (c) 2026 dqsjqian
// SPDX-License-Identifier: MIT

#include <mira/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <expected>
#include <format>
#include <functional>
#include <memory>
#include <numeric>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

int g_checks = 0;
int g_failures = 0;

void check(bool ok, const char* expr, const char* file, int line) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::printf("[FAIL] %s  (%s:%d)\n", expr, file, line);
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

/// Spins until `flag` becomes true or the timeout expires.
bool wait_for(const std::atomic<int>& flag, int target, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (flag.load(std::memory_order_acquire) < target) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

// ---------------------------------------------------------------------------
// Compile-time contract: the pool must not be usable as a temporary.
// ---------------------------------------------------------------------------

template<class T>
concept SubmittableAsLvalue = requires(T& pool) { pool.submit([] { return 1; }); };

template<class T>
concept SubmittableAsRvalue =
    requires(T&& pool) { std::forward<T>(pool).submit([] { return 1; }); };

template<class T>
concept ParallelForableAsRvalue =
    requires(T&& pool) { std::forward<T>(pool).parallel_for(0, 1, [](int) {}); };

static_assert(SubmittableAsLvalue<mira::ThreadPool>);
static_assert(!SubmittableAsRvalue<mira::ThreadPool>);
static_assert(!ParallelForableAsRvalue<mira::ThreadPool>);

static_assert(mira::version_major == 2);
static_assert(mira::cpp_standard >= 202100L);

// ---------------------------------------------------------------------------
// Construction and observation
// ---------------------------------------------------------------------------

void test_default_construction() {
    CHECK(mira::ThreadPool::default_thread_count() >= 1);
    mira::ThreadPool pool;
    CHECK(pool.thread_count() == mira::ThreadPool::default_thread_count());
    CHECK(pool.idle_count() == pool.thread_count());
    CHECK(pool.active_count() == 0);
    CHECK(pool.pending_count() == 0);
    CHECK(pool.completed_count() == 0);
    CHECK(pool.max_pending() == 0);
    CHECK(pool.state() == mira::State::running);
    CHECK(!pool.paused());
    CHECK(!pool.stopped());
}

void test_options_construction() {
    mira::ThreadPool pool(mira::ThreadPool::Options{.thread_count = 3, .max_pending = 5});
    CHECK(pool.thread_count() == 3);
    CHECK(pool.max_pending() == 5);
    CHECK(pool.task_history().empty());
}

void test_thread_count_is_clamped() {
    // ThreadPool(0) promises a clamped explicit count, so it means "1 worker"
    // rather than "auto". This also exercises the clamp through the real
    // constructor.
    mira::ThreadPool small(0);
    CHECK(small.thread_count() == 1);

    // The upper bound is checked through the pure helper, not by constructing a
    // pool: verifying it for real means spawning kMaxThreadCount threads, which
    // is exactly what the clamp exists to prevent, and CI runners refuse to
    // create that many.
    CHECK(mira::ThreadPool::clamp_thread_count(0) == 1);
    CHECK(mira::ThreadPool::clamp_thread_count(1) == 1);
    CHECK(mira::ThreadPool::clamp_thread_count(4) == 4);
    CHECK(mira::ThreadPool::clamp_thread_count(mira::ThreadPool::kMaxThreadCount) ==
          mira::ThreadPool::kMaxThreadCount);
    CHECK(mira::ThreadPool::clamp_thread_count(mira::ThreadPool::kMaxThreadCount + 1000) ==
          mira::ThreadPool::kMaxThreadCount);
}

void test_stats_snapshot() {
    mira::ThreadPool pool(2);
    const mira::PoolStats stats = pool.stats();
    CHECK(stats.threads == 2);
    CHECK(stats.idle == 2);
    CHECK(stats.active == 0);
    CHECK(stats.pending == 0);
    CHECK(stats.completed == 0);
    CHECK(stats.state == mira::State::running);

    static_cast<void>(pool.submit([] { return 1; }).get());
    const mira::PoolStats after = pool.stats();
    CHECK(after.completed == 1);
    CHECK(after.threads == 2);
}

void test_worker_identity() {
    mira::ThreadPool pool(3);
    const std::vector<mira::WorkerInfo> workers = pool.workers();
    CHECK(workers.size() == 3);
    CHECK(workers[0].index == 0);
    CHECK(workers[2].index == 2);
    CHECK(workers[0].id != workers[1].id);
    CHECK(workers[1].id != workers[2].id);

    // The reported ids are the threads that actually run the work.
    const std::thread::id reported = workers[0].id;
    const std::thread::id observed = pool.submit([] { return std::this_thread::get_id(); }).get();
    bool matched = false;
    for (const mira::WorkerInfo& worker : pool.workers()) {
        matched = matched || worker.id == observed;
    }
    CHECK(matched);
    CHECK(reported != std::thread::id{});
}

// ---------------------------------------------------------------------------
// submit()
// ---------------------------------------------------------------------------

void test_submit_returns_value() {
    mira::ThreadPool pool(2);
    auto future = pool.submit([] { return 42; });
    CHECK(future.get() == 42);
}

void test_submit_with_arguments() {
    mira::ThreadPool pool(2);
    auto future = pool.submit([](int a, int b) { return a * b; }, 6, 7);
    CHECK(future.get() == 42);
}

void test_submit_void_task() {
    mira::ThreadPool pool(2);
    std::atomic<int> ran{0};
    auto future = pool.submit([&ran](int by) { ran.fetch_add(by); }, 5);
    future.get();
    CHECK(ran.load() == 5);
}

void test_submit_member_function() {
    struct Counter {
        int value = 0;
        int add(int by) { return value += by; }
    };

    mira::ThreadPool pool(2);
    Counter counter;

    auto by_pointer = pool.submit(&Counter::add, &counter, 3);
    CHECK(by_pointer.get() == 3);

    auto by_reference = pool.submit(&Counter::add, std::ref(counter), 4);
    CHECK(by_reference.get() == 7);
}

void test_submit_move_only_callable() {
    mira::ThreadPool pool(2);
    auto owned = std::make_unique<int>(21);
    auto future = pool.submit([value = std::move(owned)] { return *value * 2; });
    CHECK(future.get() == 42);
}

void test_submit_move_only_callable_object() {
    // std::move_only_function lets the queue hold a task that is not copyable
    // in any way, which std::function could not.
    struct MoveOnly {
        std::unique_ptr<int> value;
        explicit MoveOnly(int seed) : value(std::make_unique<int>(seed)) {}
        MoveOnly(MoveOnly&&) = default;
        MoveOnly& operator=(MoveOnly&&) = default;
        MoveOnly(const MoveOnly&) = delete;
        MoveOnly& operator=(const MoveOnly&) = delete;
        int operator()() const { return *value; }
    };

    mira::ThreadPool pool(2);
    auto future = pool.submit(MoveOnly{11});
    CHECK(future.get() == 11);
}

void test_exception_propagates_through_future() {
    mira::ThreadPool pool(2);
    auto future = pool.submit([]() -> int { throw std::runtime_error("boom"); });

    bool caught = false;
    try {
        (void)future.get();
    } catch (const std::runtime_error& error) {
        caught = std::string(error.what()) == "boom";
    }
    CHECK(caught);

    // The worker must survive a throwing task.
    auto next = pool.submit([] { return 1; });
    CHECK(next.get() == 1);
}

void test_worker_survives_unknown_exception() {
    mira::ThreadPool pool(2);
    auto throwing = pool.submit([] { throw 7; });
    bool caught = false;
    try {
        throwing.get();
    } catch (int value) {
        caught = (value == 7);
    }
    CHECK(caught);
    CHECK(pool.submit([] { return true; }).get());
}

void test_many_tasks() {
    mira::ThreadPool pool(4);
    std::vector<std::future<long long>> futures;
    futures.reserve(1000);
    for (long long i = 1; i <= 1000; ++i) {
        futures.push_back(pool.submit([i] { return i; }));
    }

    long long total = 0;
    for (auto& future : futures) {
        total += future.get();
    }
    CHECK(total == 1000LL * 1001LL / 2LL);
    // A future is fulfilled before the pool finishes bookkeeping for its task,
    // so the last get() can return while completed_ is still catching up.
    // wait() joins that bookkeeping; only then is completed_count() exact.
    pool.wait();
    CHECK(pool.completed_count() == 1000);
}

void test_tasks_run_concurrently() {
    const unsigned int workers =
        mira::ThreadPool::default_thread_count() < 2
            ? 2u
            : static_cast<unsigned int>(mira::ThreadPool::default_thread_count());
    mira::ThreadPool pool(workers);

    std::atomic<int> arrived{0};
    std::atomic<bool> release{false};
    std::vector<std::future<void>> futures;
    futures.reserve(workers);

    for (unsigned int i = 0; i < workers; ++i) {
        futures.push_back(pool.submit([&arrived, &release] {
            arrived.fetch_add(1, std::memory_order_acq_rel);
            while (!release.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
        }));
    }

    // Every worker must be able to run at the same time, otherwise the barrier
    // below never completes and the pool is not actually concurrent.
    CHECK(wait_for(arrived, static_cast<int>(workers), std::chrono::seconds(5)));
    release.store(true, std::memory_order_release);
    for (auto& future : futures) {
        future.get();
    }
}

// ---------------------------------------------------------------------------
// try_submit() and std::expected
// ---------------------------------------------------------------------------

void test_try_submit_succeeds() {
    mira::ThreadPool pool(2);
    std::expected<std::future<int>, mira::PoolError> result = pool.try_submit([] { return 5; });
    CHECK(result.has_value());
    CHECK(result.value().get() == 5);
}

void test_try_submit_reports_stopped() {
    mira::ThreadPool pool(2);
    pool.shutdown();

    std::expected<std::future<int>, mira::PoolError> result = pool.try_submit([] { return 5; });
    CHECK(!result.has_value());
    CHECK(result.error() == mira::PoolError::stopped);
    CHECK(mira::to_string(result.error()) == "stopped");
}

void test_try_submit_reports_queue_full() {
    // One paused worker plus a queue limit of two: the worker cannot drain the
    // queue, so the third submission has to be refused.
    mira::ThreadPool pool(mira::ThreadPool::Options{.thread_count = 1, .max_pending = 2});
    pool.pause();

    CHECK(pool.try_submit([] {}).has_value());
    CHECK(pool.try_submit([] {}).has_value());
    CHECK(pool.pending_count() == 2);

    std::expected<std::future<void>, mira::PoolError> refused = pool.try_submit([] {});
    CHECK(!refused.has_value());
    CHECK(refused.error() == mira::PoolError::queue_full);
    CHECK(mira::to_string(refused.error()) == "queue_full");

    // The throwing overload reports the same condition as an exception.
    bool threw = false;
    try {
        static_cast<void>(pool.submit([] {}));
    } catch (const std::runtime_error& error) {
        threw = std::string(error.what()).find("queue_full") != std::string::npos;
    }
    CHECK(threw);

    // Draining the queue frees the budget again.
    pool.resume();
    pool.wait();
    CHECK(pool.try_submit([] {}).has_value());
    pool.wait();
}

// ---------------------------------------------------------------------------
// Bulk work
// ---------------------------------------------------------------------------

void test_parallel_for_covers_every_index() {
    mira::ThreadPool pool(4);
    std::vector<int> seen(200, 0);
    pool.parallel_for(0, 200, [&seen](int index) { seen[static_cast<std::size_t>(index)] = 1; });

    const int visited = std::accumulate(seen.begin(), seen.end(), 0);
    CHECK(visited == 200);
    CHECK(pool.pending_count() == 0);
}

void test_parallel_for_empty_and_single() {
    mira::ThreadPool pool(2);
    std::atomic<int> calls{0};
    std::atomic<int> observed{-1};

    pool.parallel_for(5, 5, [&calls](int) { calls.fetch_add(1); });
    CHECK(calls.load() == 0);

    pool.parallel_for(5, 4, [&calls](int) { calls.fetch_add(1); });
    CHECK(calls.load() == 0);

    pool.parallel_for(0, 1, [&observed, &calls](int index) {
        observed.store(index);
        calls.fetch_add(1);
    });
    CHECK(calls.load() == 1);
    CHECK(observed.load() == 0);
}

void test_parallel_for_rethrows_first_exception() {
    mira::ThreadPool pool(2);
    std::vector<int> visited(40, 0);

    bool caught = false;
    try {
        pool.parallel_for(0, 40, [&visited](int index) {
            visited[static_cast<std::size_t>(index)] = 1;
            if (index == 7) {
                throw std::runtime_error("chunk failed");
            }
        });
    } catch (const std::runtime_error& error) {
        caught = std::string(error.what()) == "chunk failed";
    }
    CHECK(caught);

    // Every chunk was awaited, so nothing is left pending or running.
    CHECK(pool.pending_count() == 0);
    CHECK(pool.active_count() == 0);

    // The documented split for two workers over 40 indices is two contiguous
    // chunks of 20. The throwing chunk stops at index 7, the other one finishes.
    const int total = std::accumulate(visited.begin(), visited.end(), 0);
    CHECK(visited[7] == 1);
    CHECK(visited[8] == 0);
    CHECK(total == 28);

    // The pool is still usable afterwards.
    CHECK(pool.submit([] { return 1; }).get() == 1);
}

void test_parallel_for_unsigned_range() {
    mira::ThreadPool pool(3);
    std::vector<unsigned int> seen(10, 0u);
    pool.parallel_for(0u, 10u, [&seen](unsigned int index) { seen[index] += 1u; });
    CHECK(std::accumulate(seen.begin(), seen.end(), 0u) == 10u);
}

void test_parallel_for_each() {
    mira::ThreadPool pool(4);
    std::vector<int> data(1000, 3);
    pool.parallel_for_each(data, [](int& value) { value *= 2; });
    CHECK(std::accumulate(data.begin(), data.end(), 0) == 6000);

    // A range that is already empty must not submit anything.
    std::vector<int> empty;
    pool.parallel_for_each(empty, [](int&) {});
    CHECK(pool.pending_count() == 0);
}

// ---------------------------------------------------------------------------
// wait() / wait_for()
// ---------------------------------------------------------------------------

void test_wait_blocks_until_done() {
    mira::ThreadPool pool(3);
    std::atomic<int> finished{0};
    for (int i = 0; i < 200; ++i) {
        static_cast<void>(pool.submit([&finished] {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            finished.fetch_add(1);
        }));
    }

    pool.wait();
    CHECK(finished.load() == 200);
    CHECK(pool.pending_count() == 0);
    CHECK(pool.active_count() == 0);
}

void test_wait_for_times_out_then_succeeds() {
    mira::ThreadPool pool(1);
    CHECK(pool.wait_for(std::chrono::milliseconds(10)));

    static_cast<void>(
        pool.submit([] { std::this_thread::sleep_for(std::chrono::milliseconds(150)); }));
    CHECK(!pool.wait_for(std::chrono::milliseconds(5)));
    CHECK(pool.wait_for(std::chrono::seconds(10)));
}

// ---------------------------------------------------------------------------
// pause() / resume() / resize()
// ---------------------------------------------------------------------------

void test_pause_and_resume() {
    mira::ThreadPool pool(2);
    std::atomic<int> ran{0};

    pool.pause();
    CHECK(pool.paused());
    CHECK(pool.state() == mira::State::paused);
    for (int i = 0; i < 20; ++i) {
        static_cast<void>(pool.submit([&ran] { ran.fetch_add(1); }));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(ran.load() == 0);

    pool.resume();
    CHECK(!pool.paused());
    pool.wait();
    CHECK(ran.load() == 20);
}

void test_pause_is_noop_when_draining() {
    mira::ThreadPool pool(2);
    pool.shutdown();
    pool.pause();
    CHECK(pool.state() == mira::State::draining);
    pool.resume();
    CHECK(pool.state() == mira::State::draining);
}

void test_resize() {
    mira::ThreadPool pool(2);
    CHECK(pool.thread_count() == 2);

    pool.resize(6);
    CHECK(pool.thread_count() == 6);

    pool.resize(3);
    CHECK(pool.thread_count() == 3);

    pool.resize(0);
    CHECK(pool.thread_count() == 1);

    // The pool keeps working after being resized.
    CHECK(pool.submit([] { return 7; }).get() == 7);
    pool.wait();
}

void test_resize_stress() {
    mira::ThreadPool pool(4);
    std::atomic<long long> total{0};
    for (int round = 0; round < 20; ++round) {
        pool.resize(static_cast<mira::ThreadPool::size_type>(2 + (round % 8)));
        for (int i = 0; i < 50; ++i) {
            static_cast<void>(pool.submit([&total] { total.fetch_add(1); }));
        }
        pool.wait();
    }
    CHECK(total.load() == 1000);
}

void test_try_resize_reports_stopped() {
    mira::ThreadPool pool(2);
    CHECK(pool.try_resize(4).has_value());
    CHECK(pool.thread_count() == 4);

    pool.shutdown();
    std::expected<void, mira::PoolError> result = pool.try_resize(2);
    CHECK(!result.has_value());
    CHECK(result.error() == mira::PoolError::stopped);

    bool threw = false;
    try {
        pool.resize(2);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

void test_nested_submit() {
    mira::ThreadPool pool(2);
    auto outer = pool.submit([&pool] {
        auto inner = pool.submit([] { return 21; });
        return inner.get() * 2;
    });
    CHECK(outer.get() == 42);
}

void test_shutdown_rejects_new_tasks() {
    mira::ThreadPool pool(2);
    pool.shutdown();
    CHECK(pool.stopped());
    CHECK(pool.state() == mira::State::draining);

    bool threw = false;
    try {
        static_cast<void>(pool.submit([] {}));
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

void test_shutdown_is_idempotent() {
    mira::ThreadPool pool(2);
    static_cast<void>(pool.submit([] {}));
    pool.shutdown();
    pool.shutdown();
    CHECK(pool.stopped());
}

void test_destructor_drains_queue() {
    std::atomic<int> counter{0};
    {
        mira::ThreadPool pool(4);
        for (int i = 0; i < 100; ++i) {
            static_cast<void>(pool.submit([&counter] { counter.fetch_add(1); }));
        }
        // No explicit wait: the destructor must drain the queue.
    }
    CHECK(counter.load() == 100);
}

// ---------------------------------------------------------------------------
// Tracing, formatting and enum helpers
// ---------------------------------------------------------------------------

void test_task_history_is_bounded_ring() {
    mira::ThreadPool pool(mira::ThreadPool::Options{.thread_count = 2, .trace_depth = 3});
    for (int i = 0; i < 5; ++i) {
        static_cast<void>(pool.submit([] {}));
    }
    pool.wait();

    const std::vector<mira::TaskRecord> history = pool.task_history();
    CHECK(history.size() == 3);
    // The oldest entries were dropped, so the window holds submissions 3 to 5.
    CHECK(history.front().sequence == 3);
    CHECK(history.back().sequence == 5);
    // Frames are only there where std::stacktrace is usable. On toolchains
    // without it the trace is deliberately empty rather than absent.
    if constexpr (mira::has_stacktrace) {
        CHECK(!history.back().origin.empty());
    } else {
        CHECK(history.back().origin.empty());
    }
}

void test_task_history_is_empty_without_tracing() {
    mira::ThreadPool pool(2);
    static_cast<void>(pool.submit([] {}));
    pool.wait();
    CHECK(pool.task_history().empty());
}

void test_formatting() {
    CHECK(std::format("{}", mira::State::running) == "running");
    CHECK(std::format("{}", mira::State::paused) == "paused");
    CHECK(std::format("{}", mira::State::draining) == "draining");
    CHECK(std::format("{}", mira::PoolError::queue_full) == "queue_full");
    CHECK(std::format("{}", mira::PoolError::stopped) == "stopped");

    mira::ThreadPool pool(2);
    const std::string rendered = std::format("{}", pool.stats());
    CHECK(rendered.find("threads=2") != std::string::npos);
    CHECK(rendered.find("state=running") != std::string::npos);

    const std::string via_to_string = mira::to_string(pool.stats());
    CHECK(via_to_string.find("max_pending=0") != std::string::npos);
    CHECK(via_to_string.find("state=running(0)") != std::string::npos);
}

} // namespace

int main() {
    test_default_construction();
    test_options_construction();
    test_thread_count_is_clamped();
    test_stats_snapshot();
    test_worker_identity();

    test_submit_returns_value();
    test_submit_with_arguments();
    test_submit_void_task();
    test_submit_member_function();
    test_submit_move_only_callable();
    test_submit_move_only_callable_object();
    test_exception_propagates_through_future();
    test_worker_survives_unknown_exception();
    test_many_tasks();
    test_tasks_run_concurrently();

    test_try_submit_succeeds();
    test_try_submit_reports_stopped();
    test_try_submit_reports_queue_full();

    test_parallel_for_covers_every_index();
    test_parallel_for_empty_and_single();
    test_parallel_for_rethrows_first_exception();
    test_parallel_for_unsigned_range();
    test_parallel_for_each();

    test_wait_blocks_until_done();
    test_wait_for_times_out_then_succeeds();

    test_pause_and_resume();
    test_pause_is_noop_when_draining();
    test_resize();
    test_resize_stress();
    test_try_resize_reports_stopped();

    test_nested_submit();
    test_shutdown_rejects_new_tasks();
    test_shutdown_is_idempotent();
    test_destructor_drains_queue();

    test_task_history_is_bounded_ring();
    test_task_history_is_empty_without_tracing();
    test_formatting();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
