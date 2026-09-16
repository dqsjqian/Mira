// Mira - basic usage example.
//
// Copyright (c) 2026 dqsjqian
// SPDX-License-Identifier: MIT

#include <mira/thread_pool.hpp>

#include <cstdio>
#include <memory>
#include <stdexcept>
#include <utility>

namespace {

struct Counter {
    int value = 0;

    int add(int by) { return value += by; }
};

} // namespace

int main() {
    // A pool with four workers. Use mira::ThreadPool pool; to size the pool
    // from std::thread::hardware_concurrency().
    mira::ThreadPool pool(4);

    // A task that returns a value.
    auto answer = pool.submit([] { return 42; });
    std::printf("answer            = %d\n", answer.get());

    // A task with arguments.
    auto product = pool.submit([](int a, int b) { return a * b; }, 6, 7);
    std::printf("product           = %d\n", product.get());

    // A member function: the callable is invoked as std::invoke(fn, args...).
    Counter counter;
    auto sum = pool.submit(&Counter::add, &counter, 5);
    std::printf("counter.add(5)    = %d\n", sum.get());

    // A move-only callable.
    auto owned = std::make_unique<int>(21);
    auto doubled = pool.submit([value = std::move(owned)] { return *value * 2; });
    std::printf("move-only task    = %d\n", doubled.get());

    // Exceptions travel through the future.
    auto failing = pool.submit([]() -> int { throw std::runtime_error("nope"); });
    try {
        (void)failing.get();
    } catch (const std::runtime_error& error) {
        std::printf("caught            = %s\n", error.what());
    }

    // Fire and forget, made explicit.
    static_cast<void>(pool.submit([] { std::printf("detached task ran\n"); }));

    // Block until every submitted task has finished.
    pool.wait();
    std::printf("all tasks done, %zu workers still idle\n", pool.idle_count());

    return 0;
}
