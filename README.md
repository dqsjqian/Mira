# Mira

A small, modern C++20 thread pool.

Mira gives you a fixed pool of worker threads and a clean, exception-safe API for
running work on them. It is the successor to an older C++11 thread pool and is
built on the C++20 threading vocabulary: `std::jthread`, `std::stop_token` and
`std::condition_variable_any`.

```cpp
#include <mira/thread_pool.hpp>

mira::ThreadPool pool;                                  // one worker per CPU core
auto answer = pool.submit([] { return 42; });           // runs on a worker
std::printf("answer = %d\n", answer.get());             // 42
```

## Highlights

- **Header only.** One file, no dependencies beyond the C++20 standard library.
- **C++20 first.** Workers are `std::jthread`, so they join themselves and can be
  retired cooperatively through `std::stop_token`.
- **No busy waiting.** Every wait goes through a condition variable, including
  `wait()`, which used to spin on an atomic counter.
- **Real futures.** `submit()` returns a `std::future`, and an exception thrown by
  a task is delivered through it instead of killing the worker.
- **Accepts everything callable.** Free functions, lambdas, functors, member
  function pointers and move-only callables all work.
- **Runtime control.** `resize()`, `pause()` / `resume()`, `wait()` and a graceful
  `shutdown()` that drains the queue.
- **Thread-safe submission.** `submit()` can be called concurrently from any
  number of threads.

## Requirements

- A C++20 compiler: GCC 11+, Clang 14+, or MSVC 19.30+ (Visual Studio 2022 17.0+).
- CMake 3.16+ if you want to use the CMake build.

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

// A move-only callable.
auto owned = std::make_unique<int>(21);
auto doubled = pool.submit([value = std::move(owned)] { return *value * 2; });
```

`submit()` is `[[nodiscard]]` on purpose: a discarded future silently swallows
the task's exception. If you really want fire-and-forget, say so:

```cpp
static_cast<void>(pool.submit([] { /* ... */ }));
```

### Exceptions

```cpp
auto failing = pool.submit([]() -> int { throw std::runtime_error("nope"); });
try {
    (void)failing.get();
} catch (const std::runtime_error& error) {
    std::printf("caught: %s\n", error.what());
}
```

### Waiting for results

```cpp
pool.wait();  // blocks until every submitted task has finished
```

Do not call `wait()` from inside a task: the pool would be waiting for work that
can only finish on the thread doing the waiting. Submitting from inside a task is
fine.

### Controlling the pool

```cpp
pool.resize(8);      // grow or shrink at run time
pool.pause();        // suspend execution; queued tasks stay queued
pool.resume();       // continue
pool.shutdown();     // stop accepting work, drain the queue, join every worker
```

Shrinking a pool never interrupts a running task: a retiring worker finishes what
it is doing and then exits.

## API

| Member | Description |
| --- | --- |
| `ThreadPool()` | Creates a pool sized from `std::thread::hardware_concurrency()`. |
| `ThreadPool(n)` | Creates a pool with `n` workers, clamped to `[1, 4096]`. |
| `submit(f, args...)` | Enqueues a task and returns `std::future<R>`. |
| `resize(n)` | Grows or shrinks the pool. No-op after shutdown. |
| `pause()` / `resume()` | Suspends or resumes task execution. |
| `wait()` | Blocks until all submitted tasks have finished. |
| `shutdown()` | Stops the pool and drains the queue. Idempotent. |
| `thread_count()` | Number of workers owned by the pool. |
| `idle_count()` | Workers not currently executing a task. |
| `active_count()` | Tasks currently executing. |
| `pending_count()` | Tasks waiting in the queue. |
| `paused()` / `stopped()` | Pool state queries. |
| `default_thread_count()` | Hardware concurrency, or 1 if unavailable. |

## Design notes

The previous version of this library was written against C++11 and showed its
age. Mira keeps the useful parts of that API and rebuilds the rest:

| Concern | Before | Now |
| --- | --- | --- |
| Waiting for completion | `while (work_thread_num) {}` busy-wait | `std::condition_variable` |
| Worker lifetime | `std::thread` plus manual `join` / `detach` | `std::jthread`, joined automatically |
| Cancellation | a `std::vector<bool>` of stop flags | `std::stop_token` |
| Exceptions | a throwing task could take down a worker | captured in the task's future |
| `resize()` | could drop or duplicate workers | spawns or retires the exact delta |
| Header hygiene | `using namespace std;` at global scope | fully qualified, self-contained header |
| Detach semantics | a `freedom_pool` flag that leaked threads | removed; the destructor drains and joins |

A few implementation details worth knowing:

- Tasks are type-erased into `std::function<void()>`, but the concrete callable
  lives inside a `std::packaged_task`. That is what gives every task a future and
  keeps the queue copyable even when the callable is move-only.
- `shutdown()` sets a draining flag instead of stopping workers immediately, so
  queued work is finished rather than dropped.
- Control-plane calls (`resize`, `pause`, `resume`, `wait`, `shutdown`) are not
  meant to race with each other. `submit()` is fully concurrent.

## License

MIT. See [LICENSE](LICENSE).
