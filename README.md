# Mira

A modern C++23 thread pool.

Mira gives you a fixed pool of worker threads and a clean, exception-safe API for
running work on them. It is the successor to an older C++11 thread pool and is
built on the modern C++ threading vocabulary: `std::jthread`, `std::stop_token`,
`std::move_only_function` and `std::expected`.

```cpp
#include <mira/thread_pool.hpp>

mira::ThreadPool pool;                                  // one worker per CPU core
auto answer = pool.submit([] { return 42; });           // runs on a worker
std::println("answer = {}", answer.get());              // 42
```

## Highlights

- **Header only.** One file, no dependencies beyond the C++23 standard library.
- **C++23 first.** The task queue is a `std::move_only_function`, refusals are
  reported with `std::expected`, and pool statistics drop straight into
  `std::format`.
- **No busy waiting.** Every wait goes through a condition variable, including
  `wait()`, which used to spin on an atomic counter.
- **No per-task indirection.** A `std::packaged_task` is moved straight into the
  queue: no `shared_ptr`, no atomic refcount, no extra allocation per submission.
- **Real futures.** `submit()` returns a `std::future`, and an exception thrown by
  a task is delivered through it instead of killing the worker.
- **Accepts everything callable.** Free functions, lambdas, functors, member
  function pointers and move-only callables all work.
- **Backpressure.** `Options::max_pending` bounds the queue; `try_submit()` reports
  `PoolError::queue_full` instead of growing without limit.
- **Bulk work.** `parallel_for()` and `parallel_for_each()` split a range into one
  chunk per worker and await every chunk.
- **Runtime control.** `resize()`, `pause()` / `resume()`, `wait()`, `wait_for()`
  and a graceful `shutdown()` that drains the queue.
- **Thread-safe submission.** `submit()` can be called concurrently from any
  number of threads.
- **No dangling futures.** The submitting entry points are constrained to lvalue
  pools, so `mira::ThreadPool(4).submit(f)` is a compile error rather than a
  future tied to a destroyed pool.

## Requirements

- A C++23 compiler and standard library:
  - MSVC 19.35+ (Visual Studio 2022 17.5+), with `/std:c++23preview` or
    `/std:c++latest`. Verified on MSVC 19.51.36247 (Visual Studio 2026).
  - GCC 14+ with libstdc++ 14+, with `-std=c++23`.
  - Clang 19+ with libc++ 19+, with `-std=c++23`.
- CMake 3.20+ if you want to use the CMake build.

Only MSVC was available on the machine where this version was written, so the GCC
and Clang versions above are minimums derived from when each library feature
landed, not verified numbers.

## Getting started

Drop `include/mira/thread_pool.hpp` into your project, or build it with CMake:

```cmake
add_subdirectory(Mira)
target_link_libraries(your_target PRIVATE mira::mira)
```

Build and run the tests and examples:

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Usage

### Submitting work

`submit()` forwards its arguments into `std::invoke`, so anything callable is
accepted. The returned future carries both the result and any exception.

```cpp
mira::ThreadPool pool(4);

// A value-returning task.
std::future<int> answer = pool.submit([] { return 42; });

// A task with arguments.
auto product = pool.submit([](int a, int b) { return a * b; }, 6, 7);

// A member function, with the object passed explicitly.
struct Counter { int value = 0; int add(int by) { return value += by; } };
Counter counter;
auto sum = pool.submit(&Counter::add, &counter, 5);

// A move-only callable: nothing in the path has to be copyable.
auto owned = std::make_unique<int>(21);
auto doubled = pool.submit([value = std::move(owned)] { return *value * 2; });
```

`submit()` is `[[nodiscard]]` on purpose: a discarded future silently swallows
the task's exception. If you really want fire-and-forget, say so:

```cpp
static_cast<void>(pool.submit([] { /* ... */ }));
```

### Refusing work without exceptions

`try_submit()` returns `std::expected<std::future<R>, mira::PoolError>`:

```cpp
mira::ThreadPool pool(mira::ThreadPool::Options{.thread_count = 4, .max_pending = 1024});

if (auto accepted = pool.try_submit([] { return 7; })) {
    std::println("result = {}", accepted->get());
} else {
    std::println("refused: {}", accepted.error());   // "stopped" or "queue_full"
}
```

### Bulk work

```cpp
std::vector<int> data(1'000'000, 1);

// One chunk per worker, every chunk awaited before returning.
pool.parallel_for_each(data, [](int& value) { value = 2; });

// The same for an index range. The counter is shared, so it has to be atomic.
std::atomic<std::size_t> twos{0};
pool.parallel_for(std::size_t{0}, data.size(), [&data, &twos](std::size_t index) {
    if (data[index] == 2) {
        twos.fetch_add(1, std::memory_order_relaxed);
    }
});
```

If a chunk throws, the remaining chunks are still awaited and the first exception
is rethrown to the caller.

### Exceptions

```cpp
auto failing = pool.submit([]() -> int { throw std::runtime_error("nope"); });
try {
    (void)failing.get();
} catch (const std::runtime_error& error) {
    std::println("caught: {}", error.what());
}
```

### Waiting for results

```cpp
pool.wait();                                        // until every task has finished
if (!pool.wait_for(std::chrono::seconds(1))) {      // or until a deadline
    // still busy
}
```

Do not call `wait()`, `wait_for()`, `shutdown()` or `parallel_for()` from inside
a task: the pool would be waiting for work that can only finish on the thread
doing the waiting. Submitting from inside a task is fine.

### Controlling the pool

```cpp
pool.resize(8);      // grow or shrink at run time
pool.pause();        // suspend execution; queued tasks stay queued
pool.resume();       // continue
pool.shutdown();     // stop accepting work, drain the queue, join every worker
```

Shrinking a pool never interrupts a running task: a retiring worker finishes what
it is doing and then exits.

### Observing and formatting

`PoolStats` has a `std::formatter`, and the pool can report where its most recent
submissions came from.

```cpp
std::println("{}", pool.stats());
// threads=4 idle=4 active=0 pending=0 completed=15 max_pending=0 state=running

// WorkerInfo carries a std::thread::id, which compares but has no
// std::formatter, so print it through a stream if you need it.
std::println("{} workers", pool.workers().size());

for (const mira::TaskRecord& record : pool.task_history()) {
    const std::string frame =
        record.origin.empty() ? std::string("<none>") : record.origin[0].description();
    std::println("task #{} from {}", record.sequence, frame);
}
```

`task_history()` is empty unless `Options::trace_depth` is non-zero, because
capturing a `std::stacktrace` on every submission is not free. Symbol names in
the frames need debug information in the binary; without it the frames carry
module offsets.

## API

| Member | Description |
| --- | --- |
| `ThreadPool()` | Creates a pool sized from `std::thread::hardware_concurrency()`. |
| `ThreadPool(n)` | Creates a pool with `n` workers, clamped to `[1, 4096]`. |
| `ThreadPool(Options)` | Thread count, queue limit and tracing depth. |
| `submit(f, args...)` | Enqueues a task and returns `std::future<R>`. Throws when refused. |
| `try_submit(f, args...)` | Same, but returns `std::expected<std::future<R>, PoolError>`. |
| `parallel_for(first, last, f)` | Runs `f` over an index range across the workers. |
| `parallel_for_each(range, f)` | Runs `f` over a random-access range. |
| `resize(n)` / `try_resize(n)` | Grows or shrinks the pool. |
| `pause()` / `resume()` | Suspends or resumes task execution. |
| `wait()` / `wait_for(d)` | Blocks until all submitted tasks have finished. |
| `shutdown()` | Stops the pool and drains the queue. Idempotent. |
| `thread_count()` | Number of workers owned by the pool. |
| `idle_count()` | Workers not currently executing a task. |
| `active_count()` | Tasks currently executing. |
| `pending_count()` | Tasks waiting in the queue. |
| `completed_count()` | Tasks finished since the pool was created. |
| `max_pending()` | Configured queue limit, or 0 when unbounded. |
| `state()` | `State::running`, `State::paused` or `State::draining`. |
| `paused()` / `stopped()` | Convenience state queries. |
| `stats()` | Every counter in one consistent snapshot. |
| `workers()` | Index and `std::thread::id` of every worker. |
| `task_history()` | Most recent submissions with their call sites. |
| `default_thread_count()` | Hardware concurrency, or 1 if unavailable. |

## C++23 features used

| Feature | Where |
| --- | --- |
| `std::move_only_function` | the task queue, so a task never has to be copyable |
| `std::expected` | `try_submit()`, `try_resize()` |
| Explicit object parameter (`this Self&&`) | `submit()`, `try_submit()`, `parallel_for()`, `parallel_for_each()` require an lvalue pool |
| `std::views::enumerate` + `std::ranges::to` | `workers()` |
| `std::format` + `std::formatter` | `to_string(PoolStats)` and the `PoolStats` formatter |
| `std::print` / `std::println` | the example |
| `[[assume]]` | `clamp_thread_count()` and `parallel_for()` |
| `std::unreachable` | the exhaustive switches in `to_string()` |
| `std::to_underlying` | the numeric state code in `to_string(PoolStats)` |
| `std::stacktrace` | optional task provenance in `task_history()` |
| `std::jthread` + `std::stop_token` (C++20) | worker lifetime and cooperative retirement |

C++26 was probed and deliberately not used: the toolchain this was developed on
does not implement the parts that would help a thread pool. `= delete("reason")`,
`#embed`, pack indexing, contracts, `std::hive`, `std::inplace_vector`,
`std::simd`, `std::execution` senders and `std::optional<T&>` are all absent, and
the C++26 library additions that do exist are unrelated to scheduling. Building
with `/std:c++latest` works and reports `__cplusplus == 202400`, but nothing in
Mira needs it.

## Design notes

The first version of this library was written against C++11 and showed its age.
Mira keeps the useful parts of that API and rebuilds the rest:

| Concern | Before | Now |
| --- | --- | --- |
| Waiting for completion | `while (work_thread_num) {}` busy-wait | `std::condition_variable` |
| Worker lifetime | `std::thread` plus manual `join` / `detach` | `std::jthread`, joined automatically |
| Cancellation | a `std::vector<bool>` of stop flags | `std::stop_token` |
| Exceptions | a throwing task could take down a worker | captured in the task's future |
| Task storage | `std::function` plus a `shared_ptr<packaged_task>` | `std::move_only_function` holding the `packaged_task` directly |
| Refusals | only exceptions | `std::expected`, and an optional queue bound |
| `resize()` | could drop or duplicate workers | spawns or retires the exact delta |
| Header hygiene | `using namespace std;` at global scope | fully qualified, self-contained header |
| Detach semantics | a `freedom_pool` flag that leaked threads | removed; the destructor drains and joins |

A few implementation details worth knowing:

- Tasks are type-erased into `std::move_only_function<void()>`. The concrete
  callable lives inside a `std::packaged_task`, which is what gives every task a
  future and lets the queue hold move-only callables without an indirection.
- The lifecycle is a single `State` value (`running`, `paused`, `draining`)
  instead of three independent booleans, so the transitions are exhaustive and
  the state is always consistent with the worker list.
- `shutdown()` switches to `draining` instead of stopping workers immediately, so
  queued work is finished rather than dropped.
- Control-plane calls (`resize`, `pause`, `resume`, `wait`, `shutdown`) are not
  meant to race with each other. `submit()` and `try_submit()` are fully
  concurrent.
- The header carries two targeted suppressions, both documented in place: an
  empty `catch` that keeps a worker alive, and a `clang-analyzer` false positive
  about `workers_` being moved from. See `.clang-tidy` for the static-analysis
  policy.

## License

MIT. See [LICENSE](LICENSE).
