#include "check.hpp"
#include "mira/transport/resolver.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <coroutine>
#include <exception>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {
using Answer = Result<Resolver::Endpoints>;

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
    std::mutex mutex;
    std::condition_variable changed;
    bool entered{false};
    bool released{false};
    std::atomic<int> calls{0};

    Answer resolve(const ResolveQuery&, std::size_t) {
        calls.fetch_add(1);
        std::unique_lock lock{mutex};
        entered = true;
        changed.notify_all();
        changed.wait(lock, [&] { return released; });
        return Resolver::Endpoints{Endpoint::loopback(443)};
    }
    void wait_entered() {
        std::unique_lock lock{mutex};
        CHECK(changed.wait_for(lock, 5s, [&] { return entered; }));
    }
    void release() {
        const std::lock_guard lock{mutex};
        released = true;
        changed.notify_all();
    }
    Resolver::Backend backend() {
        return [this](const ResolveQuery& query, std::size_t limit) { return resolve(query, limit); };
    }
};

Task<void> collect(Task<Answer> task, Answer& answer, bool& done) {
    answer = co_await std::move(task);
    done = true;
}

Detached start(Task<Answer> task, Answer& answer, bool& done) {
    co_await collect(std::move(task), answer, done);
}

bool pump(EventLoop& loop, bool& done) {
    const auto end = Clock::now() + 5s;
    while (!done && Clock::now() < end) {
        if (!loop.run_once(10ms)) return false;
    }
    return done;
}

void test_system_and_validation() {
    test::section("DNS system resolution and input ownership");
    auto loop = EventLoop::create().value();
    auto resolver = Resolver::create().value();
    Answer answer;
    bool done = false;
    CHECK(loop.run_until_complete(collect(resolver.resolve(loop, {"127.0.0.1", "443"}), answer, done)).has_value());
    CHECK(done && answer.has_value());
    CHECK(answer->size() == 1);
    CHECK(answer->front().to_string() == "127.0.0.1:443");
    CHECK(loop.outstanding() == 0);
    CHECK(loop.run_until_complete(collect(resolver.resolve(loop, {"localhost", "80", Family::ipv4}), answer, done)).has_value());
    CHECK(answer.has_value() && !answer->empty());
    CHECK(answer->front().port() == 80);
    CHECK(loop.run_until_complete(collect(resolver.resolve(loop, {"::1", "53", Family::ipv6, ResolveTransport::udp}), answer, done)).has_value());
    CHECK(answer.has_value() && answer->front().family() == Family::ipv6);
    CHECK(loop.run_until_complete(collect(resolver.resolve(loop, {"127.0.0.1", "not a valid service"}), answer, done)).has_value());
    CHECK(!answer && &answer.error().category() == &resolver_category());
    CHECK(!answer && !answer.error().message().empty());

    for (const auto& query : {ResolveQuery{"", "80"}, ResolveQuery{"localhost", ""},
                             ResolveQuery{std::string{"a\0b", 3}, "80"},
                             ResolveQuery{"localhost", std::string{"80\0x", 4}},
                             ResolveQuery{std::string(4097, 'x'), "80"}}) {
        CHECK(loop.run_until_complete(collect(resolver.resolve(loop, query), answer, done)).has_value());
        CHECK(!answer && answer.error() == Errc::invalid_argument);
    }
    std::stop_source stop;
    stop.request_stop();
    CHECK(loop.run_until_complete(collect(resolver.resolve(loop, {"", ""},
        {.stop = stop.get_token(), .deadline = Clock::now() - 1s}), answer, done)).has_value());
    CHECK(!answer && answer.error() == Errc::cancelled);
    CHECK(loop.run_until_complete(collect(resolver.resolve(loop, {"", ""},
        {.deadline = Clock::now() - 1s}), answer, done)).has_value());
    CHECK(!answer && answer.error() == Errc::timed_out);
    CHECK(!Resolver::create({.workers = 0}));
    CHECK(!Resolver::create({.queue_capacity = 0}));
    CHECK(!Resolver::create({.max_results = 0}));
}

void test_root_tracking_and_ownership() {
    test::section("DNS root outstanding and background-thread delivery");
    auto loop = EventLoop::create().value();
    Gate gate;
    const auto loop_thread = std::this_thread::get_id();
    std::atomic<bool> off_thread{false};
    std::atomic<bool> owned_query{false};
    auto resolver = Resolver::create({.workers = 1}, [&](const ResolveQuery& query, std::size_t limit) {
        off_thread = std::this_thread::get_id() != loop_thread;
        owned_query = query.hostname == "owned-host" && query.service == "443";
        return gate.resolve(query, limit);
    }).value();
    ResolveQuery query{"owned-host", "443"};
    auto task = resolver.resolve(loop, query);
    query.hostname = "modified";
    query.service = "0";
    Answer answer;
    bool done = false;
    std::jthread release([&] { gate.wait_entered(); gate.release(); });
    CHECK(loop.run_until_complete(collect(std::move(task), answer, done)).has_value());
    CHECK(done && answer.has_value());
    CHECK(off_thread && owned_query);
    CHECK(loop.outstanding() == 0);
}

void test_cancel_timeout_late_and_loop_shutdown() {
    for (int mode = 0; mode < 3; ++mode) {
        test::section(mode == 0 ? "DNS late completion after cancellation" :
                      mode == 1 ? "DNS late completion after timeout" : "DNS late completion after loop destruction");
        Gate gate;
        auto resolver = Resolver::create({.workers = 1}, gate.backend()).value();
        auto loop = std::make_unique<EventLoop>(EventLoop::create().value());
        std::stop_source stop;
        Answer answer;
        bool done = false;
        OperationOptions options{.stop = stop.get_token()};
        if (mode == 1) options.deadline = Clock::now() + 30ms;
        start(resolver.resolve(*loop, {"blocked", "443"}, options), answer, done);
        gate.wait_entered();
        CHECK(loop->outstanding() == 1);
        CHECK(!done);
        if (mode == 0) {
            std::jthread cancel([&] { stop.request_stop(); });
            CHECK(pump(*loop, done));
        } else if (mode == 1) {
            CHECK(pump(*loop, done));
        } else {
            loop.reset();
        }
        CHECK(done);
        CHECK(!answer && answer.error() == (mode == 1 ? Errc::timed_out : Errc::cancelled));
        if (loop) CHECK(loop->outstanding() == 0);
        loop.reset();
        // The worker is still executing, but the coroutine/loop has ended;
        // the result after release must be cleaned up by the Job alone.
        gate.release();
    }
}

void test_queue_bound_and_cancelled_queue() {
    test::section("DNS bounded queue, overload, and cancelled queued jobs");
    Gate gate;
    auto resolver = Resolver::create({.workers = 1, .queue_capacity = 1}, gate.backend()).value();
    auto loop = EventLoop::create().value();
    Answer first, queued, excess, replacement;
    bool first_done = false, queued_done = false, excess_done = false, replacement_done = false;
    std::stop_source queued_stop;
    start(resolver.resolve(loop, {"first", "443"}), first, first_done);
    gate.wait_entered();
    start(resolver.resolve(loop, {"queued", "443"}, {.stop = queued_stop.get_token()}), queued, queued_done);
    start(resolver.resolve(loop, {"excess", "443"}), excess, excess_done);
    CHECK(excess_done && !excess && excess.error() == Errc::limit_exceeded);
    queued_stop.request_stop();
    CHECK(pump(loop, queued_done));
    CHECK(!queued && queued.error() == Errc::cancelled);
    start(resolver.resolve(loop, {"replacement", "443"}), replacement, replacement_done);
    CHECK(!replacement_done);
    gate.release();
    CHECK(pump(loop, first_done));
    CHECK(pump(loop, replacement_done));
    CHECK(first.has_value() && replacement.has_value());
    CHECK(gate.calls == 2);
}

void test_dedup_limit_and_exceptions() {
    test::section("DNS deduplication, result limit, and worker exception recovery");
    auto loop = EventLoop::create().value();
    auto resolver = Resolver::create({.workers = 1, .max_results = 2},
        [](const ResolveQuery& query, std::size_t) -> Answer {
            if (query.hostname == "throw") throw std::runtime_error("injected");
            if (query.hostname == "badalloc") throw std::bad_alloc{};
            if (query.hostname == "invalid") return Resolver::Endpoints{Endpoint{}};
            if (query.hostname == "empty") return Resolver::Endpoints{};
            Resolver::Endpoints endpoints{Endpoint::loopback(1), Endpoint::loopback(1), Endpoint::loopback(2)};
            if (query.hostname == "limit") endpoints.push_back(Endpoint::loopback(3));
            return endpoints;
        }).value();
    Answer answer;
    bool done = false;
    for (const std::string host : {"throw", "badalloc", "invalid", "empty", "limit", "valid"}) {
        CHECK(loop.run_until_complete(collect(resolver.resolve(loop, {host, "80"}), answer, done)).has_value());
        if (host == "throw") CHECK(!answer && answer.error() == std::errc::io_error);
        if (host == "badalloc") CHECK(!answer && answer.error() == std::errc::not_enough_memory);
        if (host == "invalid") CHECK(!answer && answer.error() == Errc::invalid_argument);
        if (host == "empty") CHECK(!answer && &answer.error().category() == &resolver_category());
        if (host == "limit") CHECK(!answer && answer.error() == Errc::limit_exceeded);
        if (host == "valid") {
            CHECK(answer.has_value());
            if (answer) {
                CHECK(answer->size() == 2);
                CHECK(!answer->empty() && answer->front().port() == 1 && answer->back().port() == 2);
            }
        }
    }
}

void test_result_priority() {
    test::section("DNS result published in the same batch wins over cancellation");
    Gate second_gate;
    auto resolver = Resolver::create({.workers = 1}, [&](const ResolveQuery& query, std::size_t limit) -> Answer {
        if (query.hostname == "first") return Resolver::Endpoints{Endpoint::loopback(80)};
        return second_gate.resolve(query, limit);
    }).value();
    auto loop = EventLoop::create().value();
    std::stop_source stop;
    Answer first, second;
    bool first_done = false, second_done = false;
    start(resolver.resolve(loop, {"first", "80"}, {.stop = stop.get_token()}), first, first_done);
    start(resolver.resolve(loop, {"second", "80"}), second, second_done);
    second_gate.wait_entered();
    stop.request_stop();
    CHECK(pump(loop, first_done));
    CHECK(first.has_value());
    second_gate.release();
    CHECK(pump(loop, second_done));
}

void test_resolver_lifetime() {
    test::section("DNS lazily started Task does not borrow the Resolver");
    auto loop = EventLoop::create().value();
    auto resolver = std::make_unique<Resolver>(Resolver::create().value());
    auto task = resolver->resolve(loop, {"localhost", "80"});
    resolver.reset();
    Answer answer;
    bool done = false;
    CHECK(loop.run_until_complete(collect(std::move(task), answer, done)).has_value());
    CHECK(done && !answer && answer.error() == Errc::cancelled);

    test::section("DNS resolver destructor cancels waits and joins workers");
    Gate gate;
    auto owner = std::make_shared<int>(42);
    std::weak_ptr<int> lifetime = owner;
    resolver = std::make_unique<Resolver>(Resolver::create({.workers = 1},
        [owned = std::move(owner), &gate](const ResolveQuery& query, std::size_t limit) {
            (void)owned;
            return gate.resolve(query, limit);
        }).value());
    done = false;
    start(resolver->resolve(loop, {"blocked", "443"}), answer, done);
    gate.wait_entered();
    Answer queued;
    bool queued_done = false;
    start(resolver->resolve(loop, {"queued", "443"}), queued, queued_done);
    std::atomic<bool> destructor_done{false};
    std::jthread destroy([owned = std::move(resolver), &destructor_done]() mutable {
        owned.reset();
        destructor_done = true;
    });
    CHECK(pump(loop, done));
    CHECK(!answer && answer.error() == Errc::cancelled);
    CHECK(pump(loop, queued_done));
    CHECK(!queued && queued.error() == Errc::cancelled);
    CHECK(gate.calls == 1);
    CHECK(!destructor_done);
    gate.release();
    destroy.join();
    CHECK(destructor_done);
    CHECK(lifetime.expired());
    CHECK(loop.outstanding() == 0);
}

void test_cache_policy() {
    test::section("DNS bounded policy cache, negative results, expiry and key isolation");
    auto loop = EventLoop::create().value();
    std::atomic<int> calls{0};
    auto resolver = Resolver::create({.workers = 1,
        .cache = {.capacity = 2, .positive_lifetime = 1h, .negative_lifetime = 1h}},
        [&](const ResolveQuery& query, std::size_t) -> Answer {
            ++calls;
            if (query.hostname == "missing") return Resolver::Endpoints{};
            if (query.hostname == "temporary") return fail(std::make_error_code(std::errc::io_error));
            return Resolver::Endpoints{Endpoint::loopback(443)};
        }).value();
    Answer answer;
    bool done = false;
    const auto resolve = [&](ResolveQuery query) {
        CHECK(loop.run_until_complete(collect(resolver.resolve(loop, std::move(query)), answer, done)).has_value());
    };
    resolve({"a", "443"});
    resolve({"b", "443"});
    resolve({"a", "443"});
    CHECK(calls == 2);
    resolve({"c", "443"});
    resolve({"b", "443"});
    CHECK(calls == 4);
    resolve({"missing", "443"});
    CHECK(!answer && &answer.error().category() == &resolver_category());
    resolve({"missing", "443"});
    CHECK(calls == 5);
    resolve({"temporary", "443"});
    resolve({"temporary", "443"});
    CHECK(calls == 7);
    resolve({"b", "443", Family::ipv4});
    resolve({"b", "443", Family::ipv4, ResolveTransport::udp});
    resolve({"b", "80", Family::ipv4, ResolveTransport::udp});
    CHECK(calls == 10);
    auto expiring = Resolver::create({.workers = 1,
        .cache = {.capacity = 1, .positive_lifetime = 1ms, .negative_lifetime = 1ms}},
        [&](const ResolveQuery& query, std::size_t) -> Answer {
            ++calls;
            if (query.hostname == "missing") return Resolver::Endpoints{};
            return Resolver::Endpoints{Endpoint::loopback(443)};
        }).value();
    // Test hits with long lifetimes and expiry separately, without scheduling races.
    const auto expire = [](EventLoop& target) -> Task<void> {
        CHECK((co_await target.sleep_for(3ms)).has_value());
    };
    for (const std::string host : {"positive", "missing"}) {
        CHECK(loop.run_until_complete(collect(expiring.resolve(loop, {host, "80"}), answer, done)).has_value());
        CHECK(loop.run_until_complete(expire(loop)).has_value());
        CHECK(loop.run_until_complete(collect(expiring.resolve(loop, {host, "80"}), answer, done)).has_value());
    }
    CHECK(calls == 14);
    auto disabled = Resolver::create({.workers = 1}, [&](const ResolveQuery&, std::size_t) -> Answer {
        ++calls;
        return Resolver::Endpoints{Endpoint::loopback(443)};
    }).value();
    for (int repeat = 0; repeat < 2; ++repeat)
        CHECK(loop.run_until_complete(collect(disabled.resolve(loop, {"same", "80"}), answer, done)).has_value());
    CHECK(calls == 16);
    resolver.clear_cache();
    resolve({"b", "80", Family::ipv4, ResolveTransport::udp});
    CHECK(calls == 17);
    CHECK(!Resolver::create({.cache = {.positive_lifetime = -1ms}}));
    CHECK(!Resolver::create({.max_waiters_per_query = 0}));
}

void test_shared_query_cancellation() {
    test::section("DNS in-flight deduplication, independent cancellation and bounded waiters");
    Gate gate;
    auto resolver = Resolver::create({.workers = 1, .queue_capacity = 1,
        .max_waiters_per_query = 2}, gate.backend()).value();
    auto loop = EventLoop::create().value();
    std::stop_source stop;
    Answer first, second, excess, replacement;
    bool first_done = false, second_done = false, excess_done = false, replacement_done = false;
    start(resolver.resolve(loop, {"same", "443"}, {.stop = stop.get_token()}), first, first_done);
    gate.wait_entered();
    start(resolver.resolve(loop, {"same", "443"}), second, second_done);
    start(resolver.resolve(loop, {"same", "443"}), excess, excess_done);
    CHECK(excess_done && !excess && excess.error() == Errc::limit_exceeded);
    stop.request_stop();
    CHECK(pump(loop, first_done));
    CHECK(!first && first.error() == Errc::cancelled);
    CHECK(!second_done);
    start(resolver.resolve(loop, {"same", "443"}), replacement, replacement_done);
    gate.release();
    CHECK(pump(loop, second_done));
    CHECK(pump(loop, replacement_done));
    CHECK(second.has_value() && replacement.has_value());
    CHECK(gate.calls == 1);
    CHECK(loop.outstanding() == 0);

    Gate timeout_gate;
    auto timeout_resolver = Resolver::create({.workers = 1}, timeout_gate.backend()).value();
    first_done = false;
    second_done = false;
    start(timeout_resolver.resolve(loop, {"same", "443"}, {.deadline = Clock::now() + 3ms}), first, first_done);
    timeout_gate.wait_entered();
    start(timeout_resolver.resolve(loop, {"same", "443"}), second, second_done);
    CHECK(pump(loop, first_done));
    CHECK(!first && first.error() == Errc::timed_out);
    CHECK(!second_done);
    timeout_gate.release();
    CHECK(pump(loop, second_done));
    CHECK(second.has_value() && timeout_gate.calls == 1);

    Gate separate_gate;
    auto separate = Resolver::create({.workers = 1, .deduplicate_in_flight = false}, separate_gate.backend()).value();
    first_done = false;
    second_done = false;
    start(separate.resolve(loop, {"same", "443"}), first, first_done);
    separate_gate.wait_entered();
    start(separate.resolve(loop, {"same", "443"}), second, second_done);
    separate_gate.release();
    CHECK(pump(loop, first_done));
    CHECK(pump(loop, second_done));
    CHECK(first.has_value() && second.has_value() && separate_gate.calls == 2);

    Gate invalidation_gate;
    auto cached = Resolver::create({.workers = 1,
        .cache = {.capacity = 1, .positive_lifetime = 1h}}, invalidation_gate.backend()).value();
    first_done = false;
    second_done = false;
    start(cached.resolve(loop, {"same", "443"}), first, first_done);
    invalidation_gate.wait_entered();
    cached.clear_cache();
    invalidation_gate.release();
    CHECK(pump(loop, first_done));
    CHECK(loop.run_until_complete(collect(cached.resolve(loop, {"same", "443"}), second, second_done)).has_value());
    CHECK(first.has_value() && second.has_value() && invalidation_gate.calls == 2);
}

}  // namespace

int main() {
    test_system_and_validation();
    test_root_tracking_and_ownership();
    test_cancel_timeout_late_and_loop_shutdown();
    test_queue_bound_and_cancelled_queue();
    test_dedup_limit_and_exceptions();
    test_result_priority();
    test_resolver_lifetime();
    test_cache_policy();
    test_shared_query_cancellation();
    return test::summary();
}
