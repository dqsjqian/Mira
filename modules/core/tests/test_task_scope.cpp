#include "check.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"

#include <chrono>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>

using namespace Mira;
using namespace std::chrono_literals;

namespace {
struct Detached {
    struct promise_type {
        Detached get_return_object() noexcept { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::terminate(); }
    };
};

struct Gate {
    std::coroutine_handle<> waiter{};
    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> value) noexcept { waiter = value; }
    void await_resume() const noexcept {}
    void open() {
        auto next = std::exchange(waiter, {});
        if (next) next.resume();
    }
};

Task<void> increment(int& count) {
    ++count;
    co_return;
}
Task<void> failure() {
    throw std::runtime_error("child failure");
    co_return;
}
Task<void> empty_await() {
    co_await Task<void>{};
}
Task<void> gated(Gate& gate, int& count, int& destroyed) {
    struct Guard {
        int& destroyed;
        ~Guard() { ++destroyed; }
    } guard{destroyed};
    co_await gate;
    ++count;
}
Detached join_scope(TaskScope& scope, bool& finished, std::string& error) {
    try {
        co_await scope.join();
    } catch (const std::exception& ex) {
        error = ex.what();
    }
    finished = true;
}

void basic_contract() {
    test::section("scope empty / synchronous / sealed");
    CHECK_THROWS(empty_await().sync_get(), std::logic_error);
    {
        TaskScope empty;
    }
    TaskScope empty;
    empty.join().sync_get();
    CHECK_THROWS(empty.join(), std::logic_error);
    TaskScope scope;
    int count = 0;
    for (int i = 0; i < 10000; ++i)
        scope.spawn(increment(count));
    CHECK(count == 10000);
    CHECK(scope.pending() == 0);
    auto joining = scope.join();
    CHECK_THROWS(scope.join(), std::logic_error);
    CHECK_THROWS(scope.spawn(increment(count)), std::logic_error);
    std::move(joining).sync_get();
    TaskScope invalid;
    CHECK_THROWS(invalid.spawn(Task<void>{}), std::invalid_argument);
}

void synchronous_frames_are_reclaimed() {
    test::section("completed child frames are reclaimed before spawning more");
    auto child = [](std::shared_ptr<int> value) -> Task<void> {
        static_cast<void>(value);
        co_return;
    };
    TaskScope scope;
    bool reclaimed = true;
    for (int i = 0; i < 1000; ++i) {
        auto value = std::make_shared<int>(i);
        std::weak_ptr<int> weak = value;
        scope.spawn(child(std::move(value)));
        reclaimed = reclaimed && weak.expired();
    }
    CHECK(reclaimed);
    scope.join().sync_get();
}

void asynchronous_join() {
    test::section("scope waits for all child destructors");
    TaskScope scope;
    Gate one, two;
    int count = 0, destroyed = 0;
    scope.spawn(gated(one, count, destroyed));
    scope.spawn(gated(two, count, destroyed));
    bool finished = false;
    std::string error;
    join_scope(scope, finished, error);
    CHECK(!finished);
    CHECK(scope.pending() == 2);
    two.open();
    CHECK(!finished);
    CHECK(count == 1);
    CHECK(destroyed == 1);
    one.open();
    CHECK(finished);
    CHECK(error.empty());
    CHECK(destroyed == 2);
    CHECK(scope.pending() == 0);
}

void lazy_join_gap() {
    test::section("children may complete before lazy join is driven");
    TaskScope scope;
    Gate gate;
    int count = 0, destroyed = 0;
    scope.spawn(gated(gate, count, destroyed));
    auto joining = scope.join();
    gate.open();
    CHECK(destroyed == 1);
    std::move(joining).sync_get();
    CHECK(scope.pending() == 0);
}

void exception_and_stop() {
    test::section("scope exception waits for sibling and requests cooperative stop");
    TaskScope scope;
    const auto token = scope.get_stop_token();
    Gate gate;
    int count = 0, destroyed = 0;
    scope.spawn(gated(gate, count, destroyed));
    scope.spawn(failure());
    CHECK(token.stop_requested());
    CHECK(scope.pending() == 1);
    bool finished = false;
    std::string error;
    join_scope(scope, finished, error);
    CHECK(!finished);
    gate.open();
    CHECK(finished);
    CHECK(error == "child failure");
    CHECK(destroyed == 1);
}

Detached destroy_after_join(std::unique_ptr<TaskScope>& scope, bool& done) {
    co_await scope->join();
    scope.reset();
    done = true;
}
Task<void> join_from_synchronous_child(std::unique_ptr<TaskScope>& scope, bool& done) {
    destroy_after_join(scope, done);
    co_return;
}
void synchronous_child_can_release_scope() {
    test::section("synchronous completion may join and destroy the scope during spawn");
    auto scope = std::make_unique<TaskScope>();
    bool done = false;
    scope->spawn(join_from_synchronous_child(scope, done));
    CHECK(done);
    CHECK(!scope);
}
void last_child_can_release_scope() {
    test::section("last completion may destroy the scope");
    auto scope = std::make_unique<TaskScope>();
    Gate gate;
    int count = 0, destroyed = 0;
    bool done = false;
    scope->spawn(gated(gate, count, destroyed));
    destroy_after_join(scope, done);
    gate.open();
    CHECK(done);
    CHECK(!scope);
    CHECK(destroyed == 1);
}

Task<void> until_stopped(std::stop_token token, Gate& gate, bool& observed) {
    std::stop_callback callback(token, [&gate] { gate.open(); });
    co_await gate;
    observed = token.stop_requested();
}
void stop_can_destroy_scope() {
    test::section("stop callback may synchronously join and destroy scope");
    auto scope = std::make_unique<TaskScope>();
    Gate gate;
    bool observed = false, done = false;
    scope->spawn(until_stopped(scope->get_stop_token(), gate, observed));
    destroy_after_join(scope, done);
    scope->request_stop();
    CHECK(observed);
    CHECK(done);
    CHECK(!scope);
}

Task<void> gated_failure(Gate& gate) {
    co_await gate;
    throw std::runtime_error("first failure");
}
Detached join_failed_and_destroy(std::unique_ptr<TaskScope>& scope, bool& done, bool& caught) {
    try {
        co_await scope->join();
    } catch (const std::runtime_error&) {
        caught = true;
    }
    scope.reset();
    done = true;
}
void failure_cancels_sibling_and_releases_scope() {
    test::section("failure triggers synchronous sibling stop before parent releases scope");
    auto scope = std::make_unique<TaskScope>();
    Gate fail_gate, stop_gate;
    bool observed = false, done = false, caught = false;
    scope->spawn(until_stopped(scope->get_stop_token(), stop_gate, observed));
    scope->spawn(gated_failure(fail_gate));
    join_failed_and_destroy(scope, done, caught);
    fail_gate.open();
    CHECK(observed);
    CHECK(done);
    CHECK(caught);
    CHECK(!scope);
}

Task<void> retain_parameter(std::shared_ptr<int> keep, Gate& gate) {
    static_cast<void>(keep);
    co_await gate;
}
void parameters_released_before_join() {
    test::section("child coroutine parameters released before join completes");
    TaskScope scope;
    Gate gate;
    auto value = std::make_shared<int>(7);
    std::weak_ptr<int> weak = value;
    scope.spawn(retain_parameter(value, gate));
    value.reset();
    CHECK(!weak.expired());
    bool done = false;
    std::string error;
    join_scope(scope, done, error);
    gate.open();
    CHECK(done);
    CHECK(weak.expired());
}

Task<void> delayed(EventLoop& loop, std::stop_token token, int& count) {
    const auto slept = co_await loop.sleep_for(1ms);
    CHECK(slept.has_value());
    if (!token.stop_requested()) ++count;
}
Task<void> yield_once(EventLoop& loop, int& count) {
    co_await loop.yield();
    ++count;
}
void yield_shutdown() {
    test::section("loop shutdown resumes tracked yield so join can finish");
    TaskScope scope;
    int count = 0;
    bool done = false;
    std::string error;
    {
        auto loop = EventLoop::create();
        CHECK(loop.has_value());
        if (!loop) {
            scope.join().sync_get();
            return;
        }
        scope.spawn(yield_once(*loop, count));
        CHECK(count == 0);
        CHECK(loop->outstanding() == 1);
        join_scope(scope, done, error);
        CHECK(!done);
    }
    CHECK(done);
    CHECK(count == 1);
    CHECK(error.empty());
}

void real_loop() {
    test::section("scope integrates with actual event-loop timers");
    auto created = EventLoop::create();
    CHECK(created.has_value());
    if (!created) return;
    auto& loop = *created;
    TaskScope scope;
    int count = 0;
    for (int i = 0; i < 32; ++i)
        scope.spawn(delayed(loop, scope.get_stop_token(), count));
    scope.request_stop();
    bool done = false;
    std::string error;
    join_scope(scope, done, error);
    const auto deadline = EventLoop::Clock::now() + 5s;
    while (!done && EventLoop::Clock::now() < deadline) {
        CHECK(loop.run_once(10ms).has_value());
    }
    if (!done) std::terminate();
    CHECK(error.empty());
    CHECK(count == 0);
    CHECK(loop.outstanding() == 0);
}
}  // namespace

int main(int argc, char** argv) {
    if (argc == 2) {
        // Use a portable terminate handler, not platform-specific fork/signals.
        std::set_terminate([] { std::_Exit(77); });
        const std::string_view mode{argv[1]};
        if (mode == "pending-destruction") {
            Gate gate;
            int count = 0, destroyed = 0;
            {
                TaskScope scope;
                scope.spawn(gated(gate, count, destroyed));
            }
        } else if (mode == "unobserved-failure") {
            {
                TaskScope scope;
                scope.spawn(failure());
            }
        } else if (mode == "abandoned-join") {
            Gate gate;
            int count = 0, destroyed = 0;
            TaskScope scope;
            scope.spawn(gated(gate, count, destroyed));
            {
                auto waiter = scope.join().operator co_await();
                if (!waiter.await_suspend(std::noop_coroutine())) {
                    return 3;  // the join cannot finish while a child is gated
                }
            }
        } else if (mode == "unstarted-join") {
            Task<void> joining;
            {
                TaskScope scope;
                joining = scope.join();
            }
        } else {
            return 2;
        }
        // The intended contract violation above must terminate, not return.
        return 0;
    }
    basic_contract();
    synchronous_frames_are_reclaimed();
    asynchronous_join();
    lazy_join_gap();
    exception_and_stop();
    last_child_can_release_scope();
    synchronous_child_can_release_scope();
    stop_can_destroy_scope();
    failure_cancels_sibling_and_releases_scope();
    parameters_released_before_join();
    real_loop();
    yield_shutdown();
    return test::summary();
}
