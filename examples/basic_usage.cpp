// Mira - basic usage example.
//
// Copyright (c) 2026 dqsjqian
// SPDX-License-Identifier: MIT

#include <mira/thread_pool.hpp>

#include <atomic>
#include <cstddef>
#include <expected>
#include <future>
#include <memory>
#include <print>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

struct Counter {
    int value = 0;

    int add(int by) { return value += by; }
};

} // namespace

int main() {
    // std::print/std::println are C++23 and replace the printf calls a C++20
    // example would have needed.
    std::println("Mira {} built for C++ standard {}", mira::version_major, mira::cpp_standard);

    // A pool with four workers. Use mira::ThreadPool pool; to size the pool from
    // std::thread::hardware_concurrency().
    mira::ThreadPool pool(4);

    // A task that returns a value.
    auto answer = pool.submit([] { return 42; });
    std::println("answer           = {}", answer.get());

    // A task with arguments.
    auto product = pool.submit([](int a, int b) { return a * b; }, 6, 7);
    std::println("product          = {}", product.get());

    // A member function: the callable is invoked as std::invoke(fn, args...).
    Counter counter;
    auto sum = pool.submit(&Counter::add, &counter, 5);
    std::println("counter.add(5)   = {}", sum.get());

    // A move-only callable. The queue holds std::move_only_function, so nothing
    // has to be copyable.
    auto owned = std::make_unique<int>(21);
    auto doubled = pool.submit([value = std::move(owned)] { return *value * 2; });
    std::println("move-only task   = {}", doubled.get());

    // Exceptions travel through the future.
    auto failing = pool.submit([]() -> int { throw std::runtime_error("nope"); });
    try {
        (void)failing.get();
    } catch (const std::runtime_error& error) {
        std::println("caught           = {}", error.what());
    }

    // std::expected: report a refusal instead of throwing.
    std::expected<std::future<int>, mira::PoolError> accepted = pool.try_submit([] { return 3; });
    if (accepted) {
        std::println("try_submit       = {}", accepted->get());
    } else {
        std::println("try_submit       = refused: {}", accepted.error());
    }

    // Bulk work: the range is split into one chunk per worker and awaited.
    std::vector<int> data(1'000'000, 1);
    pool.parallel_for_each(data, [](int& value) { value = 2; });
    std::println("parallel_for_each wrote {} elements", data.size());

    // The counter is shared by every chunk, so it has to be atomic.
    std::atomic<std::size_t> twos{0};
    pool.parallel_for(std::size_t{0}, data.size(), [&data, &twos](std::size_t index) {
        if (data[index] == 2) {
            twos.fetch_add(1, std::memory_order_relaxed);
        }
    });
    std::println("parallel_for saw {} twos", twos.load());

    // Fire and forget, made explicit.
    static_cast<void>(pool.submit([] { std::println("detached task ran"); }));

    // Block until every submitted task has finished.
    pool.wait();
    // PoolStats has a std::formatter, so it drops straight into std::format.
    std::println("stats            = {}", pool.stats());
    std::println("workers          = {}", pool.workers().size());
    std::println("all tasks done, {} workers idle", pool.idle_count());

    // Backpressure: a bounded queue refuses work instead of growing forever.
    mira::ThreadPool bounded(mira::ThreadPool::Options{.thread_count = 1, .max_pending = 1});
    bounded.pause();
    const std::expected<std::future<void>, mira::PoolError> queued = bounded.try_submit([] {});
    const std::expected<std::future<void>, mira::PoolError> refused = bounded.try_submit([] {});
    std::println("bounded queue    = accepted={} second={}", queued.has_value(), refused.error());
    bounded.resume();

    // Tracing: remember where the last submissions came from.
    mira::ThreadPool traced(mira::ThreadPool::Options{.thread_count = 2, .trace_depth = 2});
    static_cast<void>(traced.submit([] {}));
    static_cast<void>(traced.submit([] {}));
    traced.wait();
    for (const mira::TaskRecord& record : traced.task_history()) {
        const std::string frame =
            record.origin.empty() ? std::string("<no frames>") : record.origin[0].description();
        std::println("task #{} submitted from {}", record.sequence, frame);
    }

    return 0;
}
