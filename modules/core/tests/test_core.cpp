// Core smoke tests: error model, Task, Buffer, and the stream seam.
//
// The stream test is the load-bearing one. `MemoryStream` is not a socket, yet
// `write_all` — written against the concept — drives it unchanged. That is the
// architectural claim of the whole project, asserted in code rather than in a
// design document.

#include "check.hpp"
#include "mira/core/buffer.hpp"
#include "mira/core/error.hpp"
#include "mira/core/executor.hpp"
#include "mira/core/stream.hpp"
#include "mira/core/resource_budget.hpp"
#include "mira/core/connection_pool.hpp"
#include <thread>
#include "mira/core/task.hpp"
#include "../src/loop_common.hpp"

#include <algorithm>
#include <array>
#include <condition_variable>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <functional>
#include <future>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace Mira;

namespace {

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

std::string to_string(std::span<const std::byte> bytes) {
    return std::string{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

// ── error model ──────────────────────────────────────────────────────────────

void test_error_model() {
    test::section("error model");
    static_assert(std::is_same_v<Result<int>, std::expected<int, Error>>);
    static_assert(std::is_same_v<Result<void>, std::expected<void, Error>>);

    const Error eof = make_error_code(Errc::eof);
    CHECK(eof.category() == mira_category());
    CHECK(eof.value() == static_cast<int>(Errc::eof));
    CHECK(eof.message() == "stream closed by peer");

    // Implicit conversion through is_error_code_enum.
    const Error timeout = Errc::timed_out;
    CHECK(timeout == Errc::timed_out);

    // Mira conditions compare equal to their portable std::errc peers.
    CHECK(timeout == std::errc::timed_out);
    CHECK(make_error_code(Errc::would_block) == std::errc::operation_would_block);

    Result<int> ok{7};
    CHECK(ok.has_value());
    CHECK(static_cast<bool>(ok));
    CHECK(ok.value() == 7);

    Result<int> bad = fail(Errc::limit_exceeded);
    CHECK(!bad.has_value());
    CHECK(!static_cast<bool>(bad));
    CHECK(bad.error() == Errc::limit_exceeded);
    CHECK(bad.value_or(-1) == -1);

    Result<void> void_ok{};
    CHECK(void_ok.has_value());

    Result<void> void_bad = fail(Errc::cancelled);
    CHECK(!void_bad.has_value());
    CHECK(void_bad.error() == Errc::cancelled);
}

// ── Task ─────────────────────────────────────────────────────────────────────

Task<int> answer() {
    co_return 42;
}

Task<int> doubled(int input) {
    const int value = co_await answer();
    co_return value* input;
}

Task<void> no_value() {
    co_return;
}

Task<int> throws_inside() {
    throw std::runtime_error("boom");
    co_return 0;  // unreachable, keeps this a coroutine
}

Task<int> propagates_failure() {
    const int value = co_await throws_inside();
    co_return value;
}

Task<void> suspends_forever() {
    co_await std::suspend_always{};
    co_return;
}

void test_task() {
    test::section("Task");

    CHECK(answer().sync_get() == 42);
    CHECK(doubled(2).sync_get() == 84);

    // Lazy: constructing a task must not run its body.
    bool ran = false;
    auto record = [](bool& flag) -> Task<void> {
        flag = true;
        co_return;
    };
    Task<void> pending = record(ran);
    CHECK(!ran);
    std::move(pending).sync_get();
    CHECK(ran);

    no_value().sync_get();

    // A body exception surfaces at the awaiting frame, not at suspension.
    CHECK_THROWS(throws_inside().sync_get(), std::runtime_error);
    CHECK_THROWS(propagates_failure().sync_get(), std::runtime_error);

    // An empty task is a caller error, not a lifetime violation: there is no
    // frame to abandon, so it still reports by exception.
    CHECK_THROWS(Task<int>{}.sync_get(), std::logic_error);

    // sync_get on a task that suspends is a contract violation and terminates.
    // Asserted out-of-process, in `task_contract_sync-get-suspended`, because a
    // terminating process cannot also report the rest of this file's checks.

    // Move-only ownership: the moved-from task must be empty.
    Task<int> source = answer();
    CHECK(static_cast<bool>(source));
    Task<int> sink = std::move(source);
    CHECK(!static_cast<bool>(source));
    CHECK(std::move(sink).sync_get() == 42);
}

// ── Task: native stack under long await chains ───────────────────────────────
//
// A loop whose awaits all complete without suspending must run in constant
// native stack. Relying on symmetric transfer alone does not give that: GCC
// emits it as a plain call at -O0/-O1, so each such await nested one more
// resume pair, and an I/O-free QUIC pump loop overflowed under Debug ASan.

std::uintptr_t stack_lowest = std::numeric_limits<std::uintptr_t>::max();
std::uintptr_t stack_highest = 0;

void reset_stack_samples() noexcept {
    stack_lowest = std::numeric_limits<std::uintptr_t>::max();
    stack_highest = 0;
}

#if defined(_MSC_VER) && !defined(__clang__)
__declspec(noinline)
#else
[[gnu::noinline]]
#endif
void sample_stack() noexcept {
    // ASan's fake stack can move locals off the native stack; a frame address
    // cannot move.
#if defined(__GNUC__) || defined(__clang__)
    const auto here = reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0));
#else
    volatile unsigned char local = 0;
    const auto here = reinterpret_cast<std::uintptr_t>(&local);
#endif
    stack_lowest = (std::min)(stack_lowest, here);
    stack_highest = (std::max)(stack_highest, here);
}

[[nodiscard]] std::uintptr_t stack_span() noexcept {
    return stack_highest >= stack_lowest ? stack_highest - stack_lowest : 0;
}

// Far below what one leaked frame per await would reach at these counts.
constexpr std::uintptr_t kMaxStackSpan = 64 * 1024;

Task<int> sampled_leaf() {
    sample_stack();
    co_return 1;
}

Task<int> sampled_inner() {
    co_return co_await sampled_leaf();
}

Task<void> sampled_void() {
    sample_stack();
    co_return;
}

Task<int> sampled_throw(int round) {
    sample_stack();
    if (round % 3 == 0) throw std::runtime_error("inline failure");
    co_return 1;
}

Task<long> long_inline_chain(int rounds) {
    long total = 0;
    for (int i = 0; i < rounds; ++i) {
        total += co_await sampled_inner();
        co_await sampled_void();
    }
    co_return total;
}

Task<int> inline_failures(int rounds) {
    int caught = 0;
    for (int i = 0; i < rounds; ++i) {
        try {
            (void)co_await sampled_throw(i);
        } catch (const std::runtime_error&) {
            ++caught;
        }
    }
    co_return caught;
}

/// Parks the awaiting frame until the test resumes it from outside.
struct ExternalGate {
    std::coroutine_handle<> waiter{};

    [[nodiscard]] bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept { waiter = handle; }
    void await_resume() const noexcept {}
};

Task<int> gated_leaf(ExternalGate& gate) {
    co_await gate;
    sample_stack();
    co_return 1;
}

Task<long> mixed_chain(ExternalGate& gate, int rounds, int& progress) {
    long total = 0;
    for (int i = 0; i < rounds; ++i) {
        total += co_await sampled_inner();   // completes inline
        total += co_await gated_leaf(gate);  // completes after an outside resume
        total += co_await sampled_inner();   // inline again, after the async resume
        ++progress;
    }
    co_return total;
}

/// One worker thread running posted closures in order.
class ThreadExecutor {
public:
    ThreadExecutor() : worker_([this] { run(); }) {}
    ThreadExecutor(const ThreadExecutor&) = delete;
    ThreadExecutor& operator=(const ThreadExecutor&) = delete;

    ~ThreadExecutor() {
        {
            const std::lock_guard lock{mutex_};
            stopping_ = true;
        }
        ready_.notify_one();
        worker_.join();
    }

    void post(std::function<void()> work) {
        {
            const std::lock_guard lock{mutex_};
            queue_.push_back(std::move(work));
        }
        ready_.notify_one();
    }

private:
    void run() {
        for (;;) {
            std::function<void()> work;
            {
                std::unique_lock lock{mutex_};
                ready_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                if (queue_.empty()) return;
                work = std::move(queue_.front());
                queue_.pop_front();
            }
            work();
        }
    }

    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<std::function<void()>> queue_;
    bool stopping_ = false;
    std::thread worker_;
};

static_assert(Executor<ThreadExecutor>);

Task<int> hop_to(ThreadExecutor& target) {
    co_await schedule_on(target);
    co_return 1;
}

Task<int> cross_thread_chain(ThreadExecutor& left, ThreadExecutor& right, int rounds,
                             std::promise<void>& finished) {
    int total = 0;
    for (int i = 0; i < rounds; ++i) {
        // Alternating targets keeps the child finishing on a thread other than
        // the one still inside await_suspend, racing the rendezvous both ways.
        total += co_await hop_to(i % 2 == 0 ? left : right);
        total += co_await answer() / 42;  // inline, on whichever thread won
    }
    finished.set_value();
    co_return total;
}

void test_task_stack_depth() {
    test::section("Task stack depth");

    // Deep enough that one leaked native frame per await overflows any
    // default thread stack, even without the span check below.
    constexpr int kRounds = 100000;

    reset_stack_samples();
    CHECK(long_inline_chain(kRounds).sync_get() == kRounds);
    CHECK(stack_span() < kMaxStackSpan);

    // Exceptions thrown by inline-completing children surface at each await
    // and leave the loop's stack where it was.
    reset_stack_samples();
    CHECK(inline_failures(kRounds).sync_get() == (kRounds + 2) / 3);
    CHECK(stack_span() < kMaxStackSpan);

    // Suspension outside the chain: resuming from here goes back through the
    // final-suspend transfer, then continues inline again.
    {
        constexpr int kGatedRounds = 10000;
        ExternalGate gate;
        int progress = 0;
        auto awaiter = mixed_chain(gate, kGatedRounds, progress).operator co_await();
        reset_stack_samples();
        CHECK(awaiter.await_suspend(std::noop_coroutine()));
        CHECK(progress == 0);
        int resumed = 0;
        bool parked = true;
        while (!awaiter.await_ready() && resumed <= kGatedRounds) {
            parked = parked && gate.waiter && !gate.waiter.done();
            if (!parked) break;
            std::exchange(gate.waiter, {}).resume();
            ++resumed;
        }
        CHECK(parked);
        CHECK(resumed == kGatedRounds);
        CHECK(progress == kGatedRounds);
        CHECK(awaiter.await_resume() == 3L * kGatedRounds);
        CHECK(stack_span() < kMaxStackSpan);
    }

    // Completion on another thread, racing the awaiter's rendezvous.
    {
        constexpr int kHops = 5000;
        std::promise<void> finished;
        auto done = finished.get_future();
        std::optional<ThreadExecutor> left;
        std::optional<ThreadExecutor> right;
        left.emplace();
        right.emplace();
        auto awaiter = cross_thread_chain(*left, *right, kHops, finished).operator co_await();
        (void)awaiter.await_suspend(std::noop_coroutine());
        done.wait();
        // Joining the workers waits out the closure that is still running the
        // frame towards its final suspension.
        left.reset();
        right.reset();
        CHECK(awaiter.await_ready());
        CHECK(awaiter.await_resume() == 2 * kHops);
    }
}

// ── Buffer ───────────────────────────────────────────────────────────────────

void test_buffer() {
    test::section("Buffer");

    Buffer buffer;
    CHECK(buffer.empty());

    buffer.append(bytes_of("GET / HTTP/1.1\r\n"));
    CHECK(buffer.size() == 16);
    CHECK(to_string(buffer.readable()) == "GET / HTTP/1.1\r\n");

    buffer.consume(6);
    CHECK(to_string(buffer.readable()) == "HTTP/1.1\r\n");

    // prepare/commit with a short read: only committed bytes become readable.
    std::span<std::byte> writable = buffer.prepare(64);
    CHECK(writable.size() == 64);
    std::memcpy(writable.data(), "Host: x\r\n", 9);
    buffer.commit(9);
    CHECK(to_string(buffer.readable()) == "HTTP/1.1\r\nHost: x\r\n");

    // Draining everything resets the cursors and keeps the allocation.
    const std::size_t capacity_before = buffer.capacity();
    buffer.consume(buffer.size());
    CHECK(buffer.empty());
    CHECK(buffer.capacity() == capacity_before);

    // consume() past the end clamps instead of underflowing.
    buffer.append(bytes_of("abc"));
    buffer.consume(99);
    CHECK(buffer.empty());

    // Reuse across many rounds must not grow without bound: the consumed
    // prefix is reclaimed rather than leaked.
    Buffer reused{128};
    const std::size_t steady_capacity = reused.capacity();
    for (int round = 0; round < 1000; ++round) {
        std::span<std::byte> chunk = reused.prepare(64);
        std::memset(chunk.data(), 'x', 64);
        reused.commit(64);
        reused.consume(64);
    }
    CHECK(reused.empty());
    CHECK(reused.capacity() <= steady_capacity * 4);

    Buffer limits;
    limits.append(bytes_of("abcd"));
    limits.consume(2);
    CHECK_THROWS(limits.prepare((std::numeric_limits<std::size_t>::max)()), std::length_error);
    CHECK(to_string(limits.readable()) == "cd");
    Buffer moved{std::move(limits)};
    CHECK(limits.empty());
    CHECK(limits.readable().empty());
    limits.append(bytes_of("reused"));
    CHECK(to_string(limits.readable()) == "reused");
    CHECK(to_string(moved.readable()) == "cd");
    auto pending = moved.prepare(4);
    std::memcpy(pending.data(), "tail", 4);
    limits = std::move(moved);
    limits.commit(2);
    CHECK(to_string(limits.readable()) == "cdta");
    CHECK(moved.empty());
    moved.prepare(1).front() = std::byte{'x'};
    moved.commit(1);
    CHECK(to_string(moved.readable()) == "x");
}

void test_backend_numeric_limits() {
    test::section("backend timeout saturation and ordered scatter prefix");
    using namespace std::chrono_literals;
    const auto never = detail::Clock::time_point::max();
    const auto maximum = (std::numeric_limits<int>::max)();
    CHECK(detail::resolve_timeout_ms(24h * 30, never, false) == maximum);
    CHECK(detail::resolve_timeout_ms(detail::Clock::duration::max(), never, false) == maximum);
    CHECK(detail::resolve_timeout_ms(detail::Clock::duration::min(), never, false) == -1);
    CHECK(detail::resolve_timeout_ms(1ns, never, false) == 1);
    CHECK(detail::resolve_timeout_ms(-1ns, never, false) == 0);
    CHECK(detail::resolve_timeout_ms(24h * 30, never, true) == 0);
    CHECK(detail::resolve_timeout_ms(detail::Clock::duration::min(),
          detail::Clock::now() + 24h * 30, false) == maximum);
    const std::array pieces{bytes_of("ab"), bytes_of(""), bytes_of("cdef"), bytes_of("gh")};
    std::string prefix;
    const auto count = detail::visit_scatter_prefix(pieces, 5, 16,
        [&prefix](std::size_t, auto piece) { prefix += to_string(piece); });
    CHECK(count == 2);
    CHECK(prefix == "abcde");
    prefix.clear();
    CHECK(detail::visit_scatter_prefix(pieces, 100, 1,
        [&prefix](std::size_t, auto piece) { prefix += to_string(piece); }) == 1);
    CHECK(prefix == "ab");
    CHECK(detail::visit_scatter_prefix(pieces, 0, 16,
        [](std::size_t, auto) { CHECK(false); }) == 0);
}

// ── stream seam ──────────────────────────────────────────────────────────────

/// In-memory stream that accepts at most `chunk_limit` bytes per write, so the
/// short-write path in `write_all` is actually exercised.
class MemoryStream {
public:
    explicit MemoryStream(std::size_t chunk_limit) : chunk_limit_(chunk_limit) {}

    /// `options` is accepted and ignored, which is honest for this stream
    /// rather than a shortcut: it moves bytes already in memory, so it never
    /// waits, and a stop token or deadline has nothing to interrupt. Accepting
    /// them is what makes it a `BoundedStream`, so that code under test can be
    /// the same code that runs over a socket.
    Task<Result<std::size_t>> read_some(std::span<std::byte> destination,
                                       OperationOptions = {}) {
        if (read_pos_ >= written_.size()) {
            co_return fail(Errc::eof);
        }
        const std::size_t available = written_.size() - read_pos_;
        const std::size_t n = std::min({available, destination.size(), chunk_limit_});
        std::memcpy(destination.data(), written_.data() + read_pos_, n);
        read_pos_ += n;
        co_return n;
    }

    Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                        OperationOptions = {}) {
        const std::size_t n = std::min(source.size(), chunk_limit_);
        written_.insert(
            written_.end(), source.begin(), source.begin() + static_cast<std::ptrdiff_t>(n));
        ++write_calls_;
        co_return n;
    }

    [[nodiscard]] std::string contents() const {
        return to_string(std::span<const std::byte>{written_.data(), written_.size()});
    }

    [[nodiscard]] int write_calls() const noexcept { return write_calls_; }

private:
    std::size_t chunk_limit_;
    std::vector<std::byte> written_{};
    std::size_t read_pos_{0};
    int write_calls_{0};
};

static_assert(AsyncReadStream<MemoryStream>);
static_assert(AsyncWriteStream<MemoryStream>);
static_assert(AsyncStream<MemoryStream>);

Task<Result<void>> round_trip(MemoryStream& stream, std::string_view payload) {
    Result<void> written = co_await write_all(stream, bytes_of(payload));
    if (!written) {
        co_return fail(written.error());
    }
    co_return Result<void>{};
}

void test_stream_seam() {
    test::section("stream seam");

    // write_all was written against the concept; it drives a non-socket
    // stream unchanged, looping over short writes.
    MemoryStream stream{4};
    Result<void> result = round_trip(stream, "hello Mira").sync_get();
    CHECK(result.has_value());
    CHECK(stream.contents() == "hello Mira");
    CHECK(stream.write_calls() == 3);  // 10 bytes / 4-byte chunks

    // Reading drains the same bytes, then reports a clean close.
    auto drain = [](MemoryStream& source) -> Task<Result<std::string>> {
        std::string out;
        std::byte scratch[8];
        for (;;) {
            Result<std::size_t> chunk = co_await source.read_some(std::span<std::byte>{scratch, 8});
            if (!chunk) {
                if (chunk.error() == Errc::eof) {
                    break;
                }
                co_return fail(chunk.error());
            }
            out.append(reinterpret_cast<const char*>(scratch), *chunk);
        }
        co_return out;
    };

    Result<std::string> drained = drain(stream).sync_get();
    CHECK(drained.has_value());
    CHECK(drained.value() == "hello Mira");
}

class VectorMemoryStream {
public:
    explicit VectorMemoryStream(std::size_t limit) : limit_(limit) {}
    Task<Result<std::size_t>> write_some(std::span<const std::byte> source) {
        const std::size_t n = std::min(source.size(), limit_);
        output.append(reinterpret_cast<const char*>(source.data()), n);
        co_return n;
    }
    Task<Result<std::size_t>> writev_some(
        std::span<const std::span<const std::byte>> pieces,
        OperationOptions = {}) {
        ++calls;
        std::size_t total = 0;
        for (const auto piece : pieces) {
            const std::size_t n = std::min(piece.size(), limit_ - total);
            if (n != 0) {
                output.append(reinterpret_cast<const char*>(piece.data()), n);
            }
            total += n;
            if (total == limit_) break;
        }
        co_return total;
    }
    std::string output;
    int calls{0};
private:
    std::size_t limit_;
};

struct TestConnection {
    int id;
    int* destroyed;
    ~TestConnection() { ++*destroyed; }
};
Task<Result<std::unique_ptr<TestConnection>>> connect_test(int& created, int& destroyed,
                                                          OperationOptions) {
    auto connection = std::make_unique<TestConnection>();
    connection->id = ++created;
    connection->destroyed = &destroyed;
    co_return connection;
}
void test_connection_pool() {
    test::section("bounded connection pool leases");
    int created = 0, destroyed = 0;
    auto factory = [&created, &destroyed](OperationOptions io) {
        return connect_test(created, destroyed, io);
    };
    ConnectionPool<TestConnection> pool{1};
    {
        auto lease = pool.acquire(factory).sync_get();
        CHECK(lease && lease->get().id == 1);
        CHECK(pool.active_and_idle() == 1);
        auto full = pool.acquire(factory).sync_get();
        CHECK(!full && full.error() == Errc::would_block);
        std::move(*lease).recycle();
        CHECK(pool.idle() == 1);
    }
    CHECK(destroyed == 0);
    {
        auto reused = pool.acquire(factory).sync_get();
        CHECK(reused && reused->get().id == 1 && created == 1);
    }
    CHECK(destroyed == 1 && pool.active_and_idle() == 0);
    {
        auto lease = pool.acquire(factory).sync_get();
        CHECK(lease && lease->get().id == 2);
        pool.close();
        CHECK(pool.active_and_idle() == 1);
        std::move(*lease).recycle();
    }
    CHECK(destroyed == 2 && pool.active_and_idle() == 0);
    auto stopped = pool.acquire(factory).sync_get();
    CHECK(!stopped && stopped.error() == Errc::cancelled);
    ConnectionPool<TestConnection> no_idle{1, Clock::duration::zero()};
    auto lease = no_idle.acquire(factory).sync_get();
    CHECK(lease.has_value());
    std::move(*lease).recycle();
    CHECK(no_idle.idle() == 0 && no_idle.active_and_idle() == 0);
    auto fail_factory = [](OperationOptions) -> Task<Result<std::unique_ptr<TestConnection>>> {
        co_return fail(Errc::not_supported);
    };
    auto failed = no_idle.acquire(fail_factory).sync_get();
    CHECK(!failed && failed.error() == Errc::not_supported && no_idle.active_and_idle() == 0);
    auto timeout = no_idle.acquire(factory, {.deadline = Clock::now()}).sync_get();
    CHECK(!timeout && timeout.error() == Errc::timed_out);
    Task<Result<ConnectionPool<TestConnection>::Lease>> pending;
    {
        ConnectionPool<TestConnection> temporary{1};
        pending = temporary.acquire(factory);
    }
    auto gone = std::move(pending).sync_get();
    CHECK(!gone && gone.error() == Errc::cancelled);
}

void test_resource_budget() {
    test::section("shared resource reservations");
    ResourceBudget budget{8};
    auto shared = budget;
    auto first = budget.try_acquire(6);
    CHECK(first && first->size() == 6 && shared.used() == 6);
    auto rejected = shared.try_acquire(3);
    CHECK(!rejected && rejected.error() == Errc::would_block);
    CHECK(budget.used() == 6);
    auto second = shared.try_acquire(2);
    CHECK(second && budget.used() == 8);
    auto moved = std::move(*first);
    CHECK(first->size() == 0 && budget.used() == 8);
    moved.reset();
    CHECK(budget.used() == 2);
    second->reset();
    CHECK(budget.used() == 0);
    CHECK(budget.try_acquire(0).has_value());
    CHECK(!budget.try_acquire(static_cast<std::size_t>(-1)));
    ResourceBudget::Reservation survivor;
    {
        ResourceBudget temporary{1};
        survivor = std::move(*temporary.try_acquire(1));
    }
    CHECK(survivor.size() == 1);
    survivor.reset();
    std::atomic<bool> exceeded{false};
    std::vector<std::thread> workers;
    for (int i = 0; i < 4; ++i) {
        workers.emplace_back([shared, &exceeded] {
            for (int j = 0; j < 2000; ++j) {
                auto reservation = shared.try_acquire(3);
                if (shared.used() > shared.limit()) exceeded.store(true);
            }
        });
    }
    for (auto& worker : workers) worker.join();
    CHECK(!exceeded.load());
    CHECK(budget.used() == 0);
}

void test_vector_writes() {
    test::section("scattered writes with empty fragments");
    const std::vector<std::vector<std::span<const std::byte>>> cases{
        {}, {{}, {}, {}}, {bytes_of("abc"), {}},
        {{}, bytes_of("abc"), {}, bytes_of("def"), {}, {}},
        {bytes_of("abc"), {}, bytes_of("def")},
    };
    for (const auto& pieces : cases) {
        std::string expected;
        for (const auto piece : pieces) {
            if (!piece.empty()) expected += to_string(piece);
        }
        for (const std::size_t limit : {1U, 3U, 100U}) {
            VectorMemoryStream plain{limit};
            VectorMemoryStream bounded{limit};
            CHECK(writev_all(plain, pieces).sync_get().has_value());
            CHECK(writev_all(bounded, pieces, {}).sync_get().has_value());
            CHECK(plain.output == expected);
            CHECK(bounded.output == expected);
            if (expected.empty()) {
                CHECK(plain.calls == 0);
                CHECK(bounded.calls == 0);
            }
        }
    }
    VectorMemoryStream stalled{0};
    const std::span<const std::byte> nonempty[]{bytes_of("x")};
    auto result = writev_all(stalled, nonempty).sync_get();
    CHECK(!result && result.error() == Errc::eof);
    result = writev_all(stalled, nonempty, {}).sync_get();
    CHECK(!result && result.error() == Errc::eof);
}

// ── executor seam ────────────────────────────────────────────────────────────

/// Executor that defers work until the host pumps it.
///
/// Only the queueing contract is asserted here. Driving a *coroutine* across a
/// deferred executor needs an owner that outlives the suspension — that is the
/// event loop's job, and it arrives with the event loop rather than being
/// faked here with a task whose frame `sync_get()` would tear down while a
/// queued resumption still points at it.
class QueuedExecutor {
public:
    void post(std::function<void()> work) { queue_.push_back(std::move(work)); }

    void pump() {
        // Swap before running: resumed work is free to post more, and mutating
        // the queue while iterating it would invalidate the iterators.
        std::vector<std::function<void()>> batch;
        batch.swap(queue_);
        for (auto& work : batch) {
            work();
        }
    }

    [[nodiscard]] std::size_t pending() const noexcept { return queue_.size(); }

private:
    std::vector<std::function<void()>> queue_{};
};

static_assert(Executor<QueuedExecutor>);

void test_executor_seam() {
    test::section("executor seam");

    // Inline: the host has chosen "run it now, on this thread".
    InlineExecutor inline_executor;
    bool ran = false;
    inline_executor.post([&ran] { ran = true; });
    CHECK(ran);

    // A coroutine hopping onto an inline executor completes synchronously,
    // and everything after the co_await observes the new stage.
    int stage = 0;
    auto hop = [](InlineExecutor& target, int& progress) -> Task<void> {
        progress = 1;
        co_await schedule_on(target);
        progress = 2;
        co_return;
    };
    hop(inline_executor, stage).sync_get();
    CHECK(stage == 2);

    // Queued: nothing runs until the host says so.
    QueuedExecutor queued;
    int calls = 0;
    queued.post([&calls] { ++calls; });
    CHECK(calls == 0);
    CHECK(queued.pending() == 1);
    queued.pump();
    CHECK(calls == 1);
    CHECK(queued.pending() == 0);
}

// ── contract violations, asserted out-of-process ─────────────────────────────

/// Destroying a started, unfinished frame must terminate. Each mode does
/// exactly one violation and must not return; `check_terminates.cmake` asserts
/// the terminate handler's exit code.
int run_contract_violation(std::string_view mode) {
    // A portable terminate handler, not platform-specific signals.
    std::set_terminate([] { std::_Exit(77); });

    if (mode == "sync-get-suspended") {
        // The frame parks on a suspend point sync_get cannot drive.
        suspends_forever().sync_get();
    } else if (mode == "abandoned-awaiter") {
        Task<void> task = suspends_forever();
        auto awaiter = std::move(task).operator co_await();
        // Start the body by hand so that it is genuinely suspended when the
        // awaiter — which lives in the awaiting frame — goes out of scope.
        if (!awaiter.await_suspend(std::noop_coroutine())) {
            return 3;  // the body cannot have completed inline
        }
    } else {
        return 2;
    }
    return 0;  // reaching here means the violation was not caught
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2) {
        return run_contract_violation(argv[1]);
    }
    test_error_model();
    test_task();
    test_task_stack_depth();
    test_buffer();
    test_backend_numeric_limits();
    test_stream_seam();
    test_vector_writes();
    test_resource_budget();
    test_connection_pool();
    test_executor_seam();
    return test::summary();
}
