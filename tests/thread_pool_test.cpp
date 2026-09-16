// Mira - self-contained test suite.
//
// Copyright (c) 2026 dqsjqian
// SPDX-License-Identifier: MIT

#include <mira/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <memory>
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

void test_default_construction() {
    CHECK(mira::ThreadPool::default_thread_count() >= 1);
    mira::ThreadPool pool;
    CHECK(pool.thread_count() == mira::ThreadPool::default_thread_count());
    CHECK(pool.idle_count() == pool.thread_count());
    CHECK(pool.active_count() == 0);
    CHECK(pool.pending_count() == 0);
    CHECK(!pool.paused());
    CHECK(!pool.stopped());
}

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

void test_pause_and_resume() {
    mira::ThreadPool pool(2);
    std::atomic<int> ran{0};

    pool.pause();
    CHECK(pool.paused());
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

} // namespace

int main() {
    test_default_construction();
    test_submit_returns_value();
    test_submit_with_arguments();
    test_submit_void_task();
    test_submit_member_function();
    test_submit_move_only_callable();
    test_exception_propagates_through_future();
    test_worker_survives_unknown_exception();
    test_many_tasks();
    test_tasks_run_concurrently();
    test_wait_blocks_until_done();
    test_pause_and_resume();
    test_resize();
    test_resize_stress();
    test_nested_submit();
    test_shutdown_rejects_new_tasks();
    test_shutdown_is_idempotent();
    test_destructor_drains_queue();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
