#include "check.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"

#include <array>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdlib>
#include <new>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#if MIRA_HAS_READINESS_API
    #include <fcntl.h>
    #include <sys/socket.h>
    #include <unistd.h>
#else
    #include <windows.h>
#endif

namespace allocation_probe {

struct State {
    bool enabled{false};
    std::size_t fail_at{0};
    std::size_t calls{0};
    std::size_t peak{0};
    std::array<void*, 64> live{};
};

thread_local State state;

void begin(std::size_t fail_at) {
    for (const void* pointer : state.live) {
        if (pointer != nullptr) std::abort();
    }
    state.fail_at = fail_at;
    state.calls = 0;
    state.peak = 0;
    state.enabled = true;
}

std::size_t end() noexcept {
    state.enabled = false;
    return state.calls;
}

std::size_t live() noexcept {
    std::size_t count = 0;
    for (const void* pointer : state.live) {
        if (pointer != nullptr) ++count;
    }
    return count;
}

void* allocate(std::size_t size) {
    if (state.enabled) {
        ++state.calls;
        if (state.calls == state.fail_at) {
            state.enabled = false;
            throw std::bad_alloc{};
        }
    }
    void* pointer = std::malloc(size == 0 ? 1 : size);
    if (pointer == nullptr) throw std::bad_alloc{};
    if (state.enabled) {
        bool tracked = false;
        for (auto& slot : state.live) {
            if (slot == nullptr) {
                slot = pointer;
                tracked = true;
                break;
            }
        }
        if (!tracked) std::abort();
        state.peak = (std::max)(state.peak, live());
    }
    return pointer;
}

void release(void* pointer) noexcept {
    if (pointer == nullptr) return;
    for (void*& tracked : state.live) {
        if (tracked == pointer) tracked = nullptr;
    }
    std::free(pointer);
}

}  // namespace allocation_probe

void* operator new(std::size_t size) { return allocation_probe::allocate(size); }
void* operator new[](std::size_t size) { return allocation_probe::allocate(size); }
void operator delete(void* pointer) noexcept { allocation_probe::release(pointer); }
void operator delete[](void* pointer) noexcept { allocation_probe::release(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { allocation_probe::release(pointer); }
void operator delete[](void* pointer, std::size_t) noexcept { allocation_probe::release(pointer); }

namespace {

using namespace Mira;
using namespace std::chrono_literals;

struct Completion {
    int calls{0};
    bool bad_alloc{false};
    bool succeeded{false};
    Error error{};
};

class Observer {
public:
    struct promise_type {
        Observer get_return_object() noexcept {
            return Observer{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_always initial_suspend() const noexcept { return {}; }
        std::suspend_always final_suspend() const noexcept { return {}; }
        void return_void() const noexcept {}
        void unhandled_exception() const noexcept { std::terminate(); }
    };

    explicit Observer(std::coroutine_handle<promise_type> handle) noexcept : handle_(handle) {}
    Observer(const Observer&) = delete;
    Observer& operator=(const Observer&) = delete;
    ~Observer() {
        if (started_ && !handle_.done()) std::terminate();
        handle_.destroy();
    }
    void start() {
        started_ = true;
        handle_.resume();
    }

private:
    std::coroutine_handle<promise_type> handle_;
    bool started_{false};
};

Observer observe(Task<Result<void>> task, Completion& completion) {
    try {
        const auto result = co_await std::move(task);
        completion.succeeded = result.has_value();
        if (!result) completion.error = result.error();
    } catch (const std::bad_alloc&) {
        completion.bad_alloc = true;
    }
    ++completion.calls;
}

std::size_t native_handle_count() {
#if MIRA_HAS_READINESS_API
    std::size_t count = 0;
    const long limit = ::sysconf(_SC_OPEN_MAX);
    CHECK(limit > 0);
    for (int fd = 0; fd < limit; ++fd) {
        if (::fcntl(fd, F_GETFD) >= 0) ++count;
    }
    return count;
#else
    DWORD count = 0;
    CHECK(::GetProcessHandleCount(::GetCurrentProcess(), &count) != 0);
    return count;
#endif
}

void test_loop_creation_allocation_rollback() {
    test::section("loop allocation failure releases already-created native handles");
    // Initialise process-wide backend state (notably Winsock) before measuring.
    { CHECK(EventLoop::create().has_value()); }
    const auto before = native_handle_count();
    allocation_probe::begin(1);
    bool threw = false;
    try {
        auto loop = EventLoop::create();
        CHECK(loop.has_value());
    } catch (const std::bad_alloc&) {
        threw = true;
    }
    const auto calls = allocation_probe::end();
    CHECK(threw);
    CHECK(calls == 1);
    CHECK(allocation_probe::live() == 0);
    CHECK(native_handle_count() == before);
}

void complete_timer(EventLoop& loop) {
    Completion completion;
    auto observer = observe(loop.sleep_until(EventLoop::Clock::now()), completion);
    observer.start();
    CHECK(loop.run_once(0ms).has_value());
    CHECK(completion.calls == 1);
    CHECK(completion.succeeded);
    CHECK(loop.outstanding() == 0);
}

std::size_t timer_trial(bool with_deadline, bool warm, std::size_t fail_at) {
    Completion completion;
    std::size_t calls = 0;
    {
        auto created = EventLoop::create();
        CHECK(created.has_value());
        std::optional<EventLoop> loop{std::move(*created)};
        if (warm) complete_timer(*loop);
        OperationOptions options;
        if (with_deadline) options.deadline = EventLoop::Clock::now() + 1h;
        {
            auto observer = observe(loop->sleep_until(EventLoop::Clock::now(), options), completion);
            allocation_probe::begin(fail_at);
            observer.start();
            calls = allocation_probe::end();
            if (fail_at != 0) {
                CHECK(calls == fail_at);
                CHECK(completion.calls == 1);
                CHECK(completion.bad_alloc);
                CHECK(loop->outstanding() == 0);
                if (warm) CHECK(allocation_probe::live() == 0);
            } else {
                CHECK(completion.calls == 0);
                CHECK(loop->outstanding() == 1);
                CHECK(loop->run_once(0ms).has_value());
                CHECK(completion.calls == 1);
                CHECK(completion.succeeded);
                CHECK(loop->outstanding() == 0);
                if (warm) CHECK(allocation_probe::live() == 0);
            }
        }
        loop.reset();
        CHECK(completion.calls == 1);
    }
    CHECK(allocation_probe::live() == 0);
    return calls;
}

void test_timer_allocations() {
    test::section("timer registration allocation rollback");
    for (const bool warm : {false, true}) {
        for (const bool deadline : {false, true}) {
            const auto calls = timer_trial(deadline, warm, 0);
            CHECK(calls >= (deadline ? 3U : 2U));
            for (std::size_t fail_at = 1; fail_at <= calls; ++fail_at) {
                (void)timer_trial(deadline, warm, fail_at);
            }
            std::printf("timer warm=%d deadline=%d: %zu allocation failures checked\n",
                        warm, deadline, calls);
        }
    }
}

void test_timer_dispatch_without_allocation() {
    test::section("multi-batch timer completion performs no allocation after dequeue");
    auto created = EventLoop::create();
    CHECK(created.has_value());
    if (!created) return;
    std::array<Completion, 160> results{};
    std::vector<std::unique_ptr<Observer>> observers;
    for (auto& result : results) {
        observers.emplace_back(new Observer(observe(created->sleep_until(EventLoop::Clock::now()), result)));
        observers.back()->start();
    }
    allocation_probe::begin(1);
    bool threw = false;
    try {
        while (created->outstanding() != 0) CHECK(created->run_once(0ms).has_value());
    } catch (const std::bad_alloc&) {
        threw = true;
    }
    const auto calls = allocation_probe::end();
    CHECK(!threw);
    CHECK(calls == 0);
    // Still drain if a regression throws, so the observer contract does not
    // hide the allocation failure behind an unrelated termination.
    while (created->outstanding() != 0) CHECK(created->run_once(0ms).has_value());
    for (const auto& result : results) CHECK(result.calls == 1 && result.succeeded);
}

void test_cancellation_without_allocation() {
    test::section("stop callbacks and multi-batch cancellation do not allocate");
    auto created = EventLoop::create();
    CHECK(created.has_value());
    if (!created) return;
    std::array<Completion, 160> results{};
    std::vector<std::unique_ptr<Observer>> observers;
    std::stop_source stop;
    for (auto& result : results) {
        observers.emplace_back(new Observer(observe(
            created->sleep_for(1h, {.stop = stop.get_token()}), result)));
        observers.back()->start();
    }
    allocation_probe::begin(1);
    stop.request_stop();
    while (created->outstanding() != 0) CHECK(created->run_once(0ms).has_value());
    const auto calls = allocation_probe::end();
    CHECK(calls == 0);
    for (const auto& result : results)
        CHECK(result.calls == 1 && !result.succeeded && result.error == Errc::cancelled);
}

void test_shutdown_without_allocation() {
    test::section("loop destruction cancels outstanding operations without allocating");
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (!loop) return;
    std::optional<EventLoop> owned{std::move(*loop)};
    std::array<Completion, 8> results{};
    std::vector<std::unique_ptr<Observer>> observers;
    for (auto& result : results) {
        observers.emplace_back(new Observer(observe(owned->sleep_for(1h), result)));
        observers.back()->start();
    }
    allocation_probe::begin(1);
    owned.reset();
    const auto calls = allocation_probe::end();
    CHECK(calls == 0);
    for (const auto& result : results)
        CHECK(result.calls == 1 && !result.succeeded && result.error == Errc::cancelled);
}

struct Gate {
    std::coroutine_handle<> waiter;
    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept { waiter = handle; }
    void await_resume() const noexcept {}
};
Task<void> gated_child(Gate& gate) { co_await gate; }

void test_scope_steady_allocation() {
    test::section("persistent scope reclaims asynchronous runners during connection churn");
    {
        TaskScope scope;
        Gate gate{};
        allocation_probe::begin(0);
        for (int i = 0; i < 20000; ++i) {
            scope.spawn(gated_child(gate));
            std::exchange(gate.waiter, {}).resume();
        }
        const auto calls = allocation_probe::end();
        CHECK(calls >= 20000);
        CHECK(scope.pending() == 0);
        CHECK(allocation_probe::live() <= 1);
        CHECK(allocation_probe::state.peak <= 3);
        scope.join().sync_get();
        CHECK(allocation_probe::live() == 0);
    }
    CHECK(allocation_probe::live() == 0);
}

void test_scope_join_without_allocation() {
    test::section("scope join remains available after memory exhaustion");
    TaskScope scope;
    Gate gate{};
    scope.spawn(gated_child(gate));
    std::exchange(gate.waiter, {}).resume();
    allocation_probe::begin(1);
    bool threw = false;
    try {
        scope.join().sync_get();
    } catch (const std::bad_alloc&) {
        threw = true;
    }
    const auto calls = allocation_probe::end();
    if (threw) scope.join().sync_get();
    CHECK(!threw);
    CHECK(calls == 0);
}

#if MIRA_HAS_READINESS_API

class HandlePair {
public:
    HandlePair() { CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, handles_.data()) == 0); }
    HandlePair(const HandlePair&) = delete;
    HandlePair& operator=(const HandlePair&) = delete;
    ~HandlePair() {
        for (const int handle : handles_) {
            if (handle >= 0) ::close(handle);
        }
    }
    int first() const noexcept { return handles_[0]; }
    void send() const {
        const char byte = 'x';
        CHECK(::write(handles_[1], &byte, 1) == 1);
    }

private:
    std::array<int, 2> handles_{-1, -1};
};

void complete_writable(EventLoop& loop, int fd) {
    Completion completion;
    auto observer = observe(loop.wait_writable(fd), completion);
    observer.start();
    CHECK(loop.run_once(0ms).has_value());
    CHECK(completion.calls == 1);
    CHECK(completion.succeeded);
    CHECK(loop.outstanding() == 0);
}

std::size_t waiter_trial(bool warm, bool sibling, std::size_t fail_at) {
    std::size_t calls = 0;
    HandlePair handles;
    Completion completion;
    Completion existing;
    {
        auto created = EventLoop::create();
        CHECK(created.has_value());
        std::optional<EventLoop> loop{std::move(*created)};
        CHECK(loop->attach(handles.first()).has_value());
        if (warm) complete_writable(*loop, handles.first());
        {
            auto other = observe(loop->wait_readable(handles.first()), existing);
            if (sibling) other.start();
            const OperationOptions options{.deadline = EventLoop::Clock::now() + 1h};
            {
                auto observer = observe(loop->wait_writable(handles.first(), options), completion);
                allocation_probe::begin(fail_at);
                observer.start();
                calls = allocation_probe::end();
                if (fail_at != 0) {
                    CHECK(calls == fail_at);
                    CHECK(completion.calls == 1);
                    CHECK(completion.bad_alloc);
                    CHECK(loop->outstanding() == (sibling ? 1U : 0U));
                    if (warm) CHECK(allocation_probe::live() == 0);
                } else {
                    CHECK(completion.calls == 0);
                    CHECK(loop->outstanding() == (sibling ? 2U : 1U));
                    CHECK(loop->run_once(0ms).has_value());
                    CHECK(completion.calls == 1);
                    CHECK(completion.succeeded);
                }
            }
            if (fail_at != 0) {
                Completion retry;
                auto observer = observe(loop->wait_writable(handles.first(), options), retry);
                observer.start();
                CHECK(loop->run_once(0ms).has_value());
                CHECK(retry.calls == 1);
                CHECK(retry.succeeded);
            }
            if (sibling) {
                CHECK(existing.calls == 0);
                handles.send();
                CHECK(loop->run_once(0ms).has_value());
                CHECK(existing.calls == 1);
                CHECK(existing.succeeded);
            }
            CHECK(loop->outstanding() == 0);
            if (warm) CHECK(allocation_probe::live() == 0);
        }
        loop.reset();
        CHECK(completion.calls == 1);
        CHECK(existing.calls == (sibling ? 1 : 0));
    }
    CHECK(allocation_probe::live() == 0);
    return calls;
}

void test_waiter_allocations() {
    test::section("readiness deadline allocation rollback");
    for (const bool warm : {false, true}) {
        for (const bool sibling : {false, true}) {
            const auto calls = waiter_trial(warm, sibling, 0);
            CHECK(calls >= 2);
            for (std::size_t fail_at = 1; fail_at <= calls; ++fail_at) {
                (void)waiter_trial(warm, sibling, fail_at);
            }
            std::printf("waiter warm=%d sibling=%d: %zu allocation failures checked\n",
                        warm, sibling, calls);
        }
    }
}

#endif

}  // namespace

int main() {
    test_loop_creation_allocation_rollback();
    test_timer_allocations();
    test_timer_dispatch_without_allocation();
    test_cancellation_without_allocation();
    test_shutdown_without_allocation();
    test_scope_steady_allocation();
    test_scope_join_without_allocation();
#if MIRA_HAS_READINESS_API
    test_waiter_allocations();
#endif
    return test::summary();
}
