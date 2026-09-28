#include "check.hpp"
#include "mira/core/bounded_executor.hpp"
#include "mira/core/executor.hpp"
#include "mira/core/loop_group.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <limits>
#include <latch>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

using namespace Mira;
using namespace std::chrono_literals;

static_assert(Executor<EventLoop>);
static_assert(!Executor<BoundedExecutor>);
static_assert(!Executor<LoopGroup>);

namespace {

template<typename T>
T wait(std::future<T>& future) {
    if (future.wait_for(10s) != std::future_status::ready) std::terminate();
    return future.get();
}

void test_budget() {
    test::section("shared budget resize, overflow and cross-thread release");
    ResourceBudget budget{10};
    auto held = budget.try_acquire(6);
    CHECK(held.has_value());
    CHECK(held->try_resize(10).has_value());
    CHECK(!held->try_resize(11));
    CHECK(held->size() == 10);
    CHECK(budget.used() == 10);
    CHECK(!budget.try_acquire((std::numeric_limits<std::size_t>::max)()));
    CHECK(budget.stats().rejected == 2);
    CHECK(held->try_resize(0).has_value());
    CHECK(held->try_resize(4).has_value());
    std::thread release{[reservation = std::move(*held)]() mutable { reservation.reset(); }};
    release.join();
    CHECK(budget.used() == 0);
    CHECK(budget.stats().peak == 10);
    CHECK(!held->try_resize(1));
    ResourceBudget::Reservation orphan;
    {
        ResourceBudget ephemeral{3};
        orphan = std::move(*ephemeral.try_acquire(3));
    }
    CHECK(orphan.try_resize(1).has_value());
    orphan.reset();

    std::atomic<bool> valid{true};
    std::vector<std::jthread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([shared = budget, &valid] {
            for (int j = 0; j < 2000; ++j) {
                auto reservation = shared.try_acquire(3);
                if (!reservation && reservation.error() != Errc::would_block) valid = false;
                if (shared.used() > shared.limit()) valid = false;
                if (reservation) (void)reservation->try_resize(5);
            }
        });
    }
    threads.clear();
    CHECK(valid.load());
    CHECK(budget.used() == 0);
    CHECK(budget.stats().peak <= budget.limit());
}

void test_bounded_post() {
    test::section("bounded admission includes dispatch batch and allows reentry");
    auto made = EventLoop::create();
    CHECK(made.has_value());
    auto& loop = *made;
    BoundedExecutor gate{loop, 2};
    ResourceBudget bytes{8};
    int calls = 0;
    CHECK(gate.try_post([&] {
        CHECK(gate.stats().used == 1);
        CHECK(bytes.used() == 4);
        ++calls;
        CHECK(gate.try_post([&] { ++calls; }).has_value());
        CHECK(!gate.try_post([] {}));
    }, bytes, 4).has_value());
    CHECK(gate.try_post([&] { ++calls; }, bytes, 4).has_value());
    CHECK(!gate.try_post([] {}, bytes, 1));
    CHECK(gate.stats().used == 2);
    CHECK(bytes.used() == 8);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(calls == 2);
    CHECK(gate.stats().used == 1);
    CHECK(bytes.used() == 0);
    CHECK(loop.run_once(0ms).has_value());
    CHECK(calls == 3);
    CHECK(gate.stats().used == 0);
    CHECK(gate.stats().peak == 2);

    test::section("rejected and abandoned work release ownership and charges");
    auto payload = std::make_shared<int>(7);
    std::weak_ptr<int> weak = payload;
    ResourceBudget none{0};
    auto rejected = loop.try_post([state = std::move(payload)] { (void)state; }, none);
    CHECK(!rejected && rejected.error() == Errc::would_block);
    CHECK(weak.expired());
    {
        auto unused = EventLoop::create();
        CHECK(unused->try_post([] {}, bytes, 8).has_value());
        CHECK(bytes.used() == 8);
    }
    CHECK(bytes.used() == 0);
    auto moved = std::move(*made);
    CHECK(!made->try_post([] {}, bytes));
}

Task<void> control_task(EventLoop& loop, BoundedExecutor& gate) {
    std::stop_source source;
    // This control callback runs before the already-dequeued, budget-charged
    // application callback. Request cancellation from a separate thread while
    // the application queue is genuinely full.
    loop.post([&source, &gate] {
        CHECK(gate.stats().used == 1);
        std::thread requester{[&source] { source.request_stop(); }};
        requester.join();
    });
    CHECK(gate.try_post([] {}).has_value());
    CHECK(!gate.try_post([] {}));
    auto slept = co_await loop.sleep_for(1h, {.stop = source.get_token()});
    CHECK(!slept && slept.error() == Errc::cancelled);
    CHECK(gate.try_post([] {}).has_value());
    CHECK(!gate.try_post([] {}));
    co_await schedule_on(loop);
    co_await loop.yield();
}

void test_control_reliability() {
    test::section("full application gate does not reject cancellation or resumptions");
    auto loop = EventLoop::create();
    BoundedExecutor gate{*loop, 1};
    CHECK(loop->run_until_complete(control_task(*loop, gate)).has_value());
    CHECK(loop->outstanding() == 0);
    CHECK(gate.stats().used == 0);

    test::section("throwing application callback preserves later control callbacks");
    CHECK(gate.try_post([] { throw std::runtime_error("application failure"); }).has_value());
    bool reliable = false;
    loop->post([&] { reliable = true; });
    CHECK_THROWS(loop->run_once(0ms), std::runtime_error);
    CHECK(reliable);
    CHECK(loop->outstanding() == 0);
    CHECK(gate.stats().used == 0);
}

void test_group_affinity_and_stop() {
    test::section("independent loop threads, owned temporary coroutine factories and stop");
    auto made = LoopGroup::create({.workers = 3, .max_tasks_per_worker = 2});
    CHECK(made.has_value());
    auto& group = **made;
    std::array<std::promise<std::thread::id>, 3> started;
    std::array<std::promise<bool>, 3> done;
    std::array<std::future<std::thread::id>, 3> ids;
    std::array<std::future<bool>, 3> finished;
    std::array<std::weak_ptr<int>, 3> weak;
    for (std::size_t i = 0; i < group.size(); ++i) {
        ids[i] = started[i].get_future();
        finished[i] = done[i].get_future();
        auto payload = std::make_shared<int>(static_cast<int>(i));
        weak[i] = payload;
        CHECK(group.try_spawn(i, [payload, &started, &done, i](
            EventLoop& loop, std::stop_token stop) -> Task<void> {
            const auto owner = std::this_thread::get_id();
            bool callback_on_owner = false;
            std::stop_callback on_stop{stop, [&] {
                callback_on_owner = std::this_thread::get_id() == owner;
            }};
            started[i].set_value(owner);
            auto result = co_await loop.sleep_for(1h, {.stop = stop});
            done[i].set_value(!result && result.error() == Errc::cancelled &&
                              owner == std::this_thread::get_id() && callback_on_owner &&
                              *payload == static_cast<int>(i));
        }).has_value());
    }
    std::array<std::thread::id, 3> owners;
    for (std::size_t i = 0; i < owners.size(); ++i) owners[i] = wait(ids[i]);
    CHECK(owners[0] != owners[1] && owners[1] != owners[2] && owners[0] != owners[2]);
    CHECK(owners[0] != std::this_thread::get_id());
    group.request_stop();
    CHECK(group.join().has_value());
    CHECK(group.join().has_value());
    for (std::size_t i = 0; i < finished.size(); ++i) {
        CHECK(wait(finished[i]));
        CHECK(weak[i].expired());
        CHECK(group.task_stats(i)->used == 0);
    }
    CHECK(!group.try_spawn([](EventLoop&, std::stop_token) -> Task<void> { co_return; }));
}

void test_group_capacity_and_reentry() {
    test::section("active roots stay charged, queue saturation and worker self-join");
    auto made = LoopGroup::create({.workers = 1, .max_tasks_per_worker = 1});
    auto& group = **made;
    std::promise<bool> observed;
    auto result = observed.get_future();
    CHECK(group.try_spawn([&group, &observed](EventLoop& loop, std::stop_token stop) -> Task<void> {
        auto joined = group.join();
        auto nested = group.try_spawn([](EventLoop&, std::stop_token) -> Task<void> { co_return; });
        observed.set_value(!joined && joined.error() == std::errc::resource_deadlock_would_occur &&
                           !nested && nested.error() == Errc::would_block);
        (void)co_await loop.sleep_for(1h, {.stop = stop});
    }).has_value());
    CHECK(wait(result));
    CHECK(group.task_stats(0)->used == 1);
    CHECK(!group.try_spawn([](EventLoop&, std::stop_token) -> Task<void> { co_return; }));
    group.request_stop();
    CHECK(group.join().has_value());
    CHECK(group.task_stats(0)->used == 0);

    test::section("round robin dispatch and reentrant request_stop");
    auto other = LoopGroup::create({.workers = 2});
    std::array<std::promise<std::thread::id>, 2> signals;
    auto first = signals[0].get_future();
    auto second = signals[1].get_future();
    for (auto& signal : signals) {
        CHECK((*other)->try_spawn([&signal](EventLoop&, std::stop_token) -> Task<void> {
            signal.set_value(std::this_thread::get_id());
            co_return;
        }).has_value());
    }
    CHECK(wait(first) != wait(second));
    CHECK((*other)->try_spawn([owner = other->get()](EventLoop&, std::stop_token) -> Task<void> {
        owner->request_stop();
        co_return;
    }).has_value());
    CHECK((*other)->join().has_value());

    test::section("rejected factory destruction can reenter stop without holding admission lock");
    auto closed = LoopGroup::create({});
    (*closed)->request_stop();
    struct Reenter {
        LoopGroup* owner;
        ~Reenter() { owner->request_stop(); }
    };
    auto captured = std::make_unique<Reenter>();
    captured->owner = closed->get();
    auto refused = (*closed)->try_spawn([captured = std::move(captured)](
        EventLoop&, std::stop_token) -> Task<void> {
        (void)captured;
        co_return;
    });
    CHECK(!refused && refused.error() == Errc::cancelled);
    CHECK((*closed)->join().has_value());
}

void test_group_failure() {
    test::section("startup failure joins all already created workers");
    std::atomic<std::size_t> factories{0};
    auto failed = LoopGroup::create({.workers = 4}, [&factories](std::size_t index) {
        ++factories;
        if (index == 1) return Result<EventLoop>{fail(Errc::not_supported)};
        return EventLoop::create();
    });
    CHECK(!failed && failed.error() == Errc::not_supported);
    CHECK(factories == 4);
    auto thrown = LoopGroup::create({.workers = 3}, [](std::size_t index) -> Result<EventLoop> {
        if (index == 2) throw std::runtime_error("factory failure");
        return EventLoop::create();
    });
    CHECK(!thrown && thrown.error() == Errc::internal);
    CHECK(!LoopGroup::create({.workers = 0}));

    test::section("partial thread-launch construction failure rolls back started workers");
    struct ThrowingCopy {
        std::shared_ptr<std::atomic<int>> copies;
        std::shared_ptr<std::atomic<int>> calls;
        ThrowingCopy(std::shared_ptr<std::atomic<int>> copied,
                     std::shared_ptr<std::atomic<int>> called)
            : copies(std::move(copied)), calls(std::move(called)) {}
        ThrowingCopy(ThrowingCopy&&) noexcept = default;
        ThrowingCopy(const ThrowingCopy& other) : copies(other.copies), calls(other.calls) {
            if (++*copies == 2) throw std::runtime_error("worker capture construction failure");
        }
        Result<EventLoop> operator()(std::size_t) const {
            ++*calls;
            return EventLoop::create();
        }
    };
    auto copies = std::make_shared<std::atomic<int>>(0);
    auto calls = std::make_shared<std::atomic<int>>(0);
    LoopGroup::LoopFactory factory{ThrowingCopy{copies, calls}};
    auto partial = LoopGroup::create({.workers = 4}, std::move(factory));
    CHECK(!partial && partial.error() == Errc::internal);
    CHECK(copies->load() == 2);
    CHECK(calls->load() == 1);

    test::section("task and empty-task failures are reported, siblings drain cancellation");
    auto group = LoopGroup::create({.workers = 2});
    std::promise<void> begun;
    auto ready = begun.get_future();
    std::promise<bool> cancelled;
    auto done = cancelled.get_future();
    CHECK((*group)->try_spawn(0, [&begun, &cancelled](EventLoop& loop,
                                                   std::stop_token stop) -> Task<void> {
        begun.set_value();
        auto result = co_await loop.sleep_for(1h, {.stop = stop});
        cancelled.set_value(!result && result.error() == Errc::cancelled);
    }).has_value());
    wait(ready);
    CHECK((*group)->try_spawn(1, [](EventLoop&, std::stop_token) -> Task<void> {
        throw std::runtime_error("root failure");
        co_return;
    }).has_value());
    auto joined = (*group)->join();
    CHECK(!joined && joined.error() == Errc::internal);
    CHECK(wait(done));
    CHECK(static_cast<bool>((*group)->exception()));
    auto empty = LoopGroup::create({});
    CHECK((*empty)->try_spawn([](EventLoop&, std::stop_token) { return Task<void>{}; }).has_value());
    CHECK(!(*empty)->join());
}

void test_group_reclaims_finished_factories() {
    test::section("completed factories release on owner before loop destruction");
    auto group = LoopGroup::create({.workers = 1, .max_tasks_per_worker = 2});
    std::promise<std::thread::id> invoked;
    auto owner = invoked.get_future();
    std::promise<std::thread::id> released;
    auto release = released.get_future();
    struct OwnerProbe {
        std::promise<std::thread::id>* signal;
        ~OwnerProbe() { signal->set_value(std::this_thread::get_id()); }
    };
    auto probe = std::make_unique<OwnerProbe>();
    probe->signal = &released;
    CHECK((*group)->try_spawn([probe = std::move(probe), &invoked](
        EventLoop& loop, std::stop_token) -> Task<void> {
        (void)probe;
        co_await loop.yield();
        invoked.set_value(std::this_thread::get_id());
    }).has_value());
    CHECK(wait(owner) == wait(release));
    (*group)->request_stop();
    CHECK((*group)->join().has_value());
}

void test_concurrent_admission() {
    test::section("concurrent producers race graceful shutdown without losing accepted roots");
    auto group = LoopGroup::create({.workers = 3, .max_tasks_per_worker = 64});
    std::atomic<std::size_t> accepted{0};
    std::atomic<std::size_t> completed{0};
    std::atomic<bool> valid{true};
    std::latch admitted{6};
    std::vector<std::jthread> producers;
    for (int i = 0; i < 6; ++i) {
        producers.emplace_back([&] {
            for (int j = 0; j < 500; ++j) {
                auto submitted = (*group)->try_spawn([&completed](EventLoop& loop,
                                                                  std::stop_token) -> Task<void> {
                    co_await loop.yield();
                    ++completed;
                });
                if (submitted) ++accepted;
                else if (submitted.error() != Errc::would_block &&
                         submitted.error() != Errc::cancelled) valid = false;
                if (j == 0) admitted.count_down();
            }
        });
    }
    admitted.wait();
    (*group)->request_stop();
    producers.clear();
    CHECK((*group)->join().has_value());
    CHECK(valid.load());
    CHECK(accepted.load() != 0);
    CHECK(accepted == completed);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view{argv[1]} == "self-destruction") {
        std::set_terminate([] { std::_Exit(77); });
        auto group = LoopGroup::create({});
        std::atomic<LoopGroup*> owner{group->release()};
        auto submitted = owner.load()->try_spawn([&owner](EventLoop&, std::stop_token) -> Task<void> {
            // MSVC keeps terminate handlers per thread; install it on the worker too.
            std::set_terminate([] { std::_Exit(77); });
            delete owner.exchange(nullptr);
            co_return;
        });
        if (!submitted) return 2;
        std::promise<void> never;
        never.get_future().wait();
        return 2;
    }
    test_budget();
    test_bounded_post();
    test_control_reliability();
    test_group_affinity_and_stop();
    test_group_capacity_and_reentry();
    test_group_failure();
    test_group_reclaims_finished_factories();
    test_concurrent_admission();
    return test::summary();
}
