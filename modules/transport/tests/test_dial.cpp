#include "check.hpp"
#include "mira/transport/dial.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <thread>
#include <utility>
#include <vector>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {

using Answer = Result<tcp::Socket>;

Task<void> collect(Task<Answer> task, Answer& answer) {
    answer = co_await std::move(task);
}

Answer run(EventLoop& loop, Task<Answer> task) {
    Answer answer;
    CHECK(loop.run_until_complete(collect(std::move(task), answer)).has_value());
    CHECK(loop.outstanding() == 0);
    return answer;
}

std::vector<Endpoint> mixed_endpoints() {
    return {Endpoint::loopback(1, Family::ipv6), Endpoint::loopback(2, Family::ipv6),
            Endpoint::loopback(3, Family::ipv4), Endpoint::loopback(4, Family::ipv4),
            Endpoint::loopback(5, Family::ipv6)};
}

struct Pair {
    tcp::Socket client;
    tcp::Socket server;
};

Task<void> make_pair(EventLoop& loop, Pair& pair) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0)).value();
    pair.client = (co_await tcp::connect(loop, listener.local_endpoint(), {},
        {.deadline = Clock::now() + 5s})).value();
    pair.server = (co_await listener.accept({.deadline = Clock::now() + 5s})).value();
}

Pair connected_pair(EventLoop& loop) {
    Pair pair;
    CHECK(loop.run_until_complete(make_pair(loop, pair)).has_value());
    return pair;
}

enum class Behavior { failure, pending, success, late_success, thrown, invalid, yielded_failure };

struct Script {
    std::vector<Behavior> actions;
    std::vector<std::uint16_t> starts;
    std::vector<OperationOptions> observed_io;
    std::vector<tcp::Socket> successes;
    std::size_t active{0};
    std::size_t peak{0};
    std::size_t finished{0};
    std::size_t cancelled{0};
    bool no_delay{true};
    std::optional<Clock::time_point> last_failure;
    std::optional<Clock::time_point> next_after_failure;
    std::stop_source* stop_on_success{nullptr};

    Task<Answer> connect(EventLoop& loop, Endpoint endpoint, tcp::ConnectOptions options,
                         OperationOptions io) {
        const auto index = starts.size();
        starts.push_back(endpoint.port());
        observed_io.push_back(io);
        if (last_failure && !next_after_failure) next_after_failure = Clock::now();
        no_delay = no_delay && options.no_delay;
        ++active;
        peak = std::max(peak, active);
        struct Finish {
            Script& script;
            ~Finish() { --script.active; ++script.finished; }
        } finish{*this};
        switch (actions.at(index)) {
        case Behavior::pending:
        case Behavior::late_success: {
            auto waited = co_await loop.sleep_until(Clock::time_point::max(), io);
            if (!waited && waited.error() == Errc::cancelled) ++cancelled;
            if (actions[index] == Behavior::late_success) break;
            co_return waited ? fail(Errc::internal) : fail(waited.error());
        }
        case Behavior::thrown:
            throw std::runtime_error("injected connector failure");
        case Behavior::yielded_failure:
            co_await loop.yield();
            last_failure = Clock::now();
            co_return fail(std::make_error_code(std::errc::connection_refused));
        case Behavior::failure:
            co_return fail(std::make_error_code(std::errc::connection_refused));
        case Behavior::invalid:
            co_return tcp::Socket{};
        case Behavior::success:
            break;
        }
        if (stop_on_success) stop_on_success->request_stop();
        CHECK(!successes.empty());
        auto result = std::move(successes.back());
        successes.pop_back();
        co_return result;
    }

    tcp::DialConnector connector() {
        return [this](EventLoop& loop, Endpoint endpoint, tcp::ConnectOptions options,
                      OperationOptions io) { return connect(loop, endpoint, options, io); };
    }
};

void test_order_failure_and_limits() {
    test::section("dial alternates families, deduplicates, and preserves failure");
    auto loop = EventLoop::create().value();
    auto endpoints = mixed_endpoints();
    endpoints.push_back(endpoints.front());
    Script script;
    script.actions.assign(5, Behavior::failure);
    auto answer = run(loop, tcp::dial(loop, endpoints, {}, script.connector()));
    CHECK(!answer && answer.error() == std::errc::connection_refused);
    CHECK((script.starts == std::vector<std::uint16_t>{1, 3, 2, 4, 5}));
    CHECK(script.peak == 1 && script.active == 0 && script.finished == 5);

    test::section("dial keeps the resolver's IPv4-first preference");
    script = {};
    script.actions.assign(5, Behavior::failure);
    std::rotate(endpoints.begin(), endpoints.begin() + 2, endpoints.end());
    answer = run(loop, tcp::dial(loop, endpoints, {}, script.connector()));
    CHECK((script.starts == std::vector<std::uint16_t>{3, 5, 4, 1, 2}));

    test::section("dial reports attempt budget exhaustion rather than dropping candidates silently");
    script = {};
    script.actions.assign(2, Behavior::failure);
    answer = run(loop, tcp::dial(loop, mixed_endpoints(), {.max_attempts = 2}, script.connector()));
    CHECK(!answer && answer.error() == Errc::limit_exceeded);
    CHECK((script.starts == std::vector<std::uint16_t>{1, 3}));
}

void test_validation_precedence() {
    test::section("dial validates candidates and limits before connecting");
    auto loop = EventLoop::create().value();
    Script script;
    for (const auto& options : {tcp::DialOptions{.max_attempts = 0},
                               tcp::DialOptions{.max_parallel = 0},
                               tcp::DialOptions{.fallback_delay = -1ms}}) {
        auto answer = run(loop, tcp::dial(loop, mixed_endpoints(), options, script.connector()));
        CHECK(!answer && answer.error() == Errc::invalid_argument);
    }
    for (const auto& endpoints : {std::vector<Endpoint>{}, std::vector<Endpoint>{Endpoint{}}}) {
        auto answer = run(loop, tcp::dial(loop, endpoints, {}, script.connector()));
        CHECK(!answer && answer.error() == Errc::invalid_argument);
    }
    std::stop_source stop;
    stop.request_stop();
    auto answer = run(loop, tcp::dial(loop, {},
        {.io = {.stop = stop.get_token(), .deadline = Clock::now() - 1s}, .max_parallel = 0},
        script.connector()));
    CHECK(!answer && answer.error() == Errc::cancelled);
    answer = run(loop, tcp::dial(loop, {}, {.io = {.deadline = Clock::now() - 1s}}, script.connector()));
    CHECK(!answer && answer.error() == Errc::timed_out);
    CHECK(script.starts.empty());

    script.actions = {Behavior::invalid};
    answer = run(loop, tcp::dial(loop, {Endpoint::loopback(1)}, {}, script.connector()));
    CHECK(!answer && answer.error() == Errc::invalid_argument);
}

void test_racing_draining_and_exceptions() {
    test::section("dial starts fallback while first is pending and drains its cancellation");
    auto loop = EventLoop::create().value();
    auto pair = connected_pair(loop);
    Script script;
    script.actions = {Behavior::pending, Behavior::success};
    script.successes.push_back(std::move(pair.client));
    auto answer = run(loop, tcp::dial(loop, mixed_endpoints(),
        {.fallback_delay = 0ms}, script.connector()));
    CHECK(answer && answer->valid());
    CHECK((script.starts == std::vector<std::uint16_t>{1, 3}));
    CHECK(script.peak == 2 && script.cancelled == 1 && script.finished == 2 && script.active == 0);

    test::section("dial's timer starts a fallback without waiting for the pending attempt");
    pair = connected_pair(loop);
    script = {};
    script.actions = {Behavior::pending, Behavior::success};
    script.successes.push_back(std::move(pair.client));
    answer = run(loop, tcp::dial(loop, mixed_endpoints(),
        {.io = {.deadline = Clock::now() + 5s}, .fallback_delay = 5ms}, script.connector()));
    CHECK(answer && script.starts.size() == 2 && script.cancelled == 1 && script.finished == 2);

    test::section("dial closes a loser which reports success after the winner");
    auto first = connected_pair(loop);
    auto second = connected_pair(loop);
    const auto expected = second.client.native_handle();
    script = {};
    script.actions = {Behavior::late_success, Behavior::success};
    script.successes.push_back(std::move(first.client));
    script.successes.push_back(std::move(second.client));
    answer = run(loop, tcp::dial(loop, mixed_endpoints(), {.fallback_delay = 0ms}, script.connector()));
    CHECK(answer && answer->native_handle() == expected);
    CHECK(script.finished == 2 && script.cancelled == 1 && script.successes.empty());
    std::array<std::byte, 1> byte{};
    Result<std::size_t> read;
    auto verify_closed = [&]() -> Task<void> {
        read = co_await first.server.read_some(byte, {.deadline = Clock::now() + 1s});
    };
    CHECK(loop.run_until_complete(verify_closed()).has_value());
    CHECK(!read && read.error() == Errc::eof);

    test::section("dial joins pending siblings before converting connector exceptions");
    script = {};
    script.actions = {Behavior::pending, Behavior::thrown};
    answer = run(loop, tcp::dial(loop, mixed_endpoints(), {.fallback_delay = 0ms}, script.connector()));
    CHECK(!answer && answer.error() == Errc::internal);
    CHECK(script.active == 0 && script.cancelled == 1 && script.finished == 2);
}

void test_fast_failure_and_parallel_bound() {
    test::section("dial fast asynchronous failure bypasses the fallback delay");
    auto loop = EventLoop::create().value();
    auto pair = connected_pair(loop);
    Script script;
    script.actions = {Behavior::yielded_failure, Behavior::success};
    script.successes.push_back(std::move(pair.client));
    auto answer = run(loop, tcp::dial(loop, mixed_endpoints(),
        {.io = {.deadline = Clock::now() + 2s}, .fallback_delay = 1h}, script.connector()));
    CHECK(answer.has_value());
    CHECK(script.next_after_failure && script.last_failure);
    CHECK(*script.next_after_failure - *script.last_failure < 1s);

    test::section("dial respects the active connection cap and cancellation drains all frames");
    script = {};
    script.actions.assign(5, Behavior::pending);
    std::stop_source stop;
    Answer cancelled;
    auto cancel_when_full = [&]() -> Task<void> {
        TaskScope scope;
        scope.spawn(collect(tcp::dial(loop, mixed_endpoints(),
            {.io = {.stop = stop.get_token(), .deadline = Clock::now() + 5s},
             .fallback_delay = 0ms, .max_parallel = 2}, script.connector()), cancelled));
        co_await loop.yield();
        CHECK(script.starts.size() == 2 && script.peak == 2);
        std::jthread cancel([&] { stop.request_stop(); });
        co_await scope.join();
    };
    CHECK(loop.run_until_complete(cancel_when_full()).has_value());
    CHECK(!cancelled && cancelled.error() == Errc::cancelled);
    CHECK(script.starts.size() == 2 && script.cancelled == 2 && script.active == 0);
    CHECK(loop.outstanding() == 0);

    test::section("dial accepts a published winner when cancellation lands in the same completion");
    pair = connected_pair(loop);
    script = {};
    std::stop_source same_batch;
    script.stop_on_success = &same_batch;
    script.actions = {Behavior::success};
    script.successes.push_back(std::move(pair.client));
    answer = run(loop, tcp::dial(loop, mixed_endpoints(),
        {.io = {.stop = same_batch.get_token()}}, script.connector()));
    CHECK(answer && answer->valid());
}

void test_loop_shutdown() {
    test::section("dial drains pending attempts when the event loop shuts down");
    auto loop = std::make_unique<EventLoop>(EventLoop::create().value());
    Script script;
    script.actions.assign(5, Behavior::pending);
    Answer answer;
    TaskScope scope;
    scope.spawn(collect(tcp::dial(*loop, mixed_endpoints(),
        {.fallback_delay = 0ms}, script.connector()), answer));
    CHECK(script.starts.size() == 2);
    loop.reset();
    CHECK(scope.pending() == 0);
    std::move(scope.join()).sync_get();
    CHECK(!answer && answer.error() == Errc::cancelled);
    CHECK(script.active == 0 && script.finished == 2);
}

void test_deadline_and_callable_ownership() {
    test::section("dial uses one absolute deadline for all started attempts");
    auto loop = EventLoop::create().value();
    Script script;
    script.actions.assign(5, Behavior::pending);
    const auto deadline = Clock::now() + 20ms;
    auto answer = run(loop, tcp::dial(loop, mixed_endpoints(),
        {.io = {.deadline = deadline}, .connect = {.no_delay = false},
         .fallback_delay = 0ms}, script.connector()));
    CHECK(!answer && answer.error() == Errc::timed_out);
    CHECK(script.starts.size() == 2 && script.finished == 2 && !script.no_delay);
    for (const auto& io : script.observed_io) CHECK(io.deadline == deadline);

    test::section("dial owns a temporary coroutine connector until its frame is drained");
    auto owner = std::make_shared<int>(42);
    std::weak_ptr<int> lifetime = owner;
    auto task = tcp::dial(loop, {Endpoint::loopback(1)}, {},
        [owned = owner](EventLoop& event_loop, Endpoint, tcp::ConnectOptions,
                        OperationOptions) -> Task<Answer> {
            co_await event_loop.yield();
            CHECK(*owned == 42);
            co_return fail(std::make_error_code(std::errc::connection_refused));
        });
    owner.reset();
    CHECK(!lifetime.expired());
    answer = run(loop, std::move(task));
    CHECK(!answer && lifetime.expired());
}

struct ResolveGate {
    std::mutex mutex;
    std::condition_variable changed;
    bool entered{false};
    bool released{false};

    Result<Resolver::Endpoints> resolve(const ResolveQuery&, std::size_t) {
        std::unique_lock lock{mutex};
        entered = true;
        changed.notify_all();
        changed.wait(lock, [&] { return released; });
        return mixed_endpoints();
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
};

void test_resolution_budget_queue_and_lifetime() {
    test::section("dial passes the resolution budget unchanged to connection attempts");
    auto loop = EventLoop::create().value();
    std::atomic<bool> query_owned{false};
    auto resolver = Resolver::create({}, [&](const ResolveQuery& query, std::size_t) {
        query_owned = query.hostname == "example.test" && query.service == "443" &&
                      query.transport == ResolveTransport::tcp && !query.family;
        return mixed_endpoints();
    }).value();
    Script script;
    script.actions.assign(5, Behavior::failure);
    const auto deadline = Clock::now() + 5s;
    auto answer = run(loop, tcp::dial(loop, resolver, "example.test", std::uint16_t{443},
        {.io = {.deadline = deadline}, .fallback_delay = 0ms}, script.connector()));
    CHECK(query_owned && !answer && answer.error() == std::errc::connection_refused);
    CHECK(script.observed_io.size() == 5);
    for (const auto& io : script.observed_io) CHECK(io.deadline == deadline);

    test::section("dial timeout while resolver worker is blocked starts no connection");
    ResolveGate gate;
    auto gated = Resolver::create({.workers = 1, .queue_capacity = 1},
        [&](const ResolveQuery& query, std::size_t limit) { return gate.resolve(query, limit); }).value();
    script = {};
    answer = run(loop, tcp::dial(loop, gated, "blocked.test", "80",
        {.io = {.deadline = Clock::now() + 30ms}}, script.connector()));
    CHECK(!answer && answer.error() == Errc::timed_out && script.starts.empty());
    gate.release();

    test::section("dial inherits resolver queue bounds without an extra admission queue");
    ResolveGate queue_gate;
    auto queued = Resolver::create({.workers = 1, .queue_capacity = 1},
        [&](const ResolveQuery& query, std::size_t limit) { return queue_gate.resolve(query, limit); }).value();
    Answer first, second, excess;
    std::stop_source stop;
    auto queue_test = [&]() -> Task<void> {
        TaskScope scope;
        scope.spawn(collect(tcp::dial(loop, queued, "first.test", "80",
            {.io = {.stop = stop.get_token()}}, script.connector()), first));
        queue_gate.wait_entered();
        scope.spawn(collect(tcp::dial(loop, queued, "second.test", "80",
            {.io = {.stop = stop.get_token()}}, script.connector()), second));
        excess = co_await tcp::dial(loop, queued, "third.test", "80", {}, script.connector());
        stop.request_stop();
        co_await scope.join();
    };
    CHECK(loop.run_until_complete(queue_test()).has_value());
    CHECK(!excess && excess.error() == Errc::limit_exceeded);
    CHECK(!first && first.error() == Errc::cancelled);
    CHECK(!second && second.error() == Errc::cancelled);
    CHECK(script.starts.empty() && loop.outstanding() == 0);
    queue_gate.release();

    test::section("dial captures resolver state before a lazy task begins");
    auto owned = std::make_unique<Resolver>(Resolver::create().value());
    auto task = tcp::dial(loop, *owned, "localhost", "80");
    owned.reset();
    answer = run(loop, std::move(task));
    CHECK(!answer && answer.error() == Errc::cancelled);
}

void test_loopback() {
    test::section("dial connects through a real resolver and exchanges loopback data");
    auto loop = EventLoop::create().value();
    auto resolver = Resolver::create().value();
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0)).value();
    auto answer = run(loop, tcp::dial(loop, resolver, "localhost", listener.local_endpoint().port(),
        {.io = {.deadline = Clock::now() + 5s}, .fallback_delay = 0ms}));
    CHECK(answer && answer->valid());
    auto exchange = [&]() -> Task<void> {
        auto accepted = co_await listener.accept({.deadline = Clock::now() + 5s});
        CHECK(accepted.has_value());
        std::array<std::byte, 1> sent{std::byte{42}}, received{};
        auto written = co_await answer->write_some(sent, {.deadline = Clock::now() + 5s});
        auto read = co_await accepted->read_some(received, {.deadline = Clock::now() + 5s});
        CHECK(written && *written == 1 && read && *read == 1 && received == sent);
    };
    CHECK(loop.run_until_complete(exchange()).has_value());
    CHECK(loop.outstanding() == 0);

    test::section("dial falls back from a refused endpoint to a real listener");
    auto refused = tcp::Listener::bind(loop, Endpoint::loopback(0)).value();
    const auto closed_endpoint = refused.local_endpoint();
    refused.close();
    answer = run(loop, tcp::dial(loop, {closed_endpoint, listener.local_endpoint()},
        {.io = {.deadline = Clock::now() + 5s}, .fallback_delay = 1h, .max_parallel = 1}));
    CHECK(answer && answer->valid());
}

}  // namespace

int main() {
    test_order_failure_and_limits();
    test_validation_precedence();
    test_racing_draining_and_exceptions();
    test_fast_failure_and_parallel_bound();
    test_loop_shutdown();
    test_deadline_and_callable_ownership();
    test_resolution_budget_queue_and_lifetime();
    test_loopback();
    return test::summary();
}
