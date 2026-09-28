#include "check.hpp"
#include "mira/core/stream.hpp"
#include "mira/transport/server.hpp"

#include <array>
#include <chrono>
#include <coroutine>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {
struct Outcome {
    Result<tcp::ServeStats> result = fail(Errc::internal);
    std::exception_ptr exception;
    bool done = false;
};

template<class Handler>
Task<void> collect(EventLoop& loop, tcp::Listener& listener, Handler handler,
                   tcp::ServeOptions options, Outcome& outcome, bool compatibility = false) {
    try {
        if (compatibility) outcome.result = co_await tcp::serve(listener, std::move(handler), options);
        else outcome.result = co_await tcp::serve(loop, listener, std::move(handler), options);
    } catch (...) {
        outcome.exception = std::current_exception();
    }
    outcome.done = true;
}

struct HandlerState {
    std::size_t started = 0;
    std::size_t finished = 0;
    std::size_t destroyed = 0;
    OperationOptions io;
    Clock::time_point ended{};
};
struct Lifetime {
    HandlerState& state;
    ~Lifetime() { ++state.destroyed; }
};

Task<Result<void>> read_one(tcp::Socket& socket, OperationOptions io, HandlerState& state) {
    Lifetime alive{state};
    ++state.started;
    state.io = io;
    std::array<std::byte, 1> byte{};
    auto result = co_await socket.read_some(byte, io);
    ++state.finished;
    state.ended = Clock::now();
    if (!result) co_return fail(result.error());
    co_return Result<void>{};
}

Task<void> wait_started(EventLoop& loop, HandlerState& state, std::size_t count = 1) {
    while (state.started < count) co_await loop.yield();
}
Task<void> wait_closed(EventLoop& loop, tcp::Listener& listener) {
    while (listener.native_handle() != invalid_handle) co_await loop.yield();
}

Task<void> drain_before_deadline(EventLoop& loop) {
    test::section("admission stop drains without cancelling handlers; timer is joined early");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    std::stop_source stop;
    HandlerState state;
    Outcome outcome;
    auto handler = [&state](tcp::Socket& socket, OperationOptions io) {
        return read_one(socket, io, state);
    };
    TaskScope tasks;
    tasks.spawn(collect(loop, *listener, handler,
                         {.max_connections = 1, .io = {.stop = stop.get_token()}, .grace_period = 1h},
                         outcome));
    auto client = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(client.has_value());
    co_await wait_started(loop, state);
    CHECK(!state.io.deadline.has_value());
    stop.request_stop();
    co_await wait_closed(loop, *listener);
    CHECK(!state.io.stop.stop_requested());
    CHECK(!outcome.done);
    const std::array<std::byte, 1> byte{};
    CHECK((co_await write_all(*client, byte)).has_value());
    co_await tasks.join();
    CHECK(outcome.done && !outcome.exception && outcome.result.has_value());
    CHECK(outcome.result->accepted == 1 && outcome.result->completed == 1);
    CHECK(outcome.result->cancelled == 0 && outcome.result->failed == 0);
    CHECK(state.destroyed == 1);
}

Task<void> cancel_at_deadline(EventLoop& loop, bool cross_thread) {
    test::section(cross_thread ? "cross-thread stop and drain deadline" : "loop-thread stop and drain deadline");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    std::stop_source stop;
    HandlerState state;
    Outcome outcome;
    auto handler = [&state](tcp::Socket& socket, OperationOptions io) {
        return read_one(socket, io, state);
    };
    TaskScope tasks;
    tasks.spawn(collect(loop, *listener, handler,
                         {.io = {.stop = stop.get_token()}, .grace_period = 30ms}, outcome));
    auto client = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(client.has_value());
    co_await wait_started(loop, state);
    const auto stopped_at = Clock::now();
    if (cross_thread) {
        std::thread thread{[stop]() mutable { stop.request_stop(); }};
        thread.join();
    } else stop.request_stop();
    co_await tasks.join();
    CHECK(outcome.result.has_value() && !outcome.exception);
    CHECK(state.ended >= stopped_at + 30ms);
    CHECK(state.io.stop.stop_requested());
    CHECK(outcome.result->completed == 1 && outcome.result->cancelled == 1);
    CHECK(outcome.result->failed == 0 && state.destroyed == 1);
}

struct Gate {
    std::coroutine_handle<> waiter{};
    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> value) noexcept { waiter = value; }
    void await_resume() const noexcept {}
    void open() { std::exchange(waiter, {}).resume(); }
};
Task<Result<void>> ignore_stop(tcp::Socket&, OperationOptions io, HandlerState& state, Gate& gate) {
    Lifetime alive{state};
    ++state.started;
    state.io = io;
    co_await gate;
    ++state.finished;
    co_return Result<void>{};
}
Task<void> noncooperative_is_joined(EventLoop& loop) {
    test::section("grace expiry requests cancellation but never destroys an uncooperative handler");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    std::stop_source stop;
    HandlerState state;
    Gate gate;
    Outcome outcome;
    auto handler = [&state, &gate](tcp::Socket& socket, OperationOptions io) {
        return ignore_stop(socket, io, state, gate);
    };
    TaskScope tasks;
    tasks.spawn(collect(loop, *listener, handler,
                         {.io = {.stop = stop.get_token()}, .grace_period = 1ms}, outcome));
    auto client = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(client.has_value());
    co_await wait_started(loop, state);
    stop.request_stop();
    while (!state.io.stop.stop_requested()) co_await loop.yield();
    CHECK(!outcome.done && state.destroyed == 0 && state.finished == 0);
    gate.open();
    co_await tasks.join();
    CHECK(outcome.done && outcome.result.has_value());
    CHECK(outcome.result->completed == 1 && outcome.result->cancelled == 0);
    CHECK(state.destroyed == 1);
}

Task<Result<void>> throw_first(tcp::Socket& socket, OperationOptions io, HandlerState& state) {
    Lifetime alive{state};
    const auto ordinal = ++state.started;
    if (ordinal == 2) throw std::runtime_error("first handler failure");
    std::array<std::byte, 1> byte{};
    auto result = co_await socket.read_some(byte, io);
    CHECK(!result && result.error() == Errc::cancelled);
    ++state.finished;
    throw std::runtime_error("cleanup failure must not replace first");
    co_return Result<void>{};  // MSVC requires an explicit non-void coroutine return.
}
Task<void> exception_skips_grace(EventLoop& loop) {
    test::section("synchronous child exception cancels siblings, joins and preserves first cause");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    HandlerState state;
    Outcome outcome;
    auto handler = [&state](tcp::Socket& socket, OperationOptions io) {
        return throw_first(socket, io, state);
    };
    TaskScope tasks;
    tasks.spawn(collect(loop, *listener, handler, {.grace_period = 1h}, outcome));
    auto first = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(first.has_value());
    co_await wait_started(loop, state);
    auto second = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(second.has_value());
    co_await tasks.join();
    CHECK(outcome.exception != nullptr && outcome.done);
    try {
        if (outcome.exception) std::rethrow_exception(outcome.exception);
    } catch (const std::runtime_error& error) {
        CHECK(std::string(error.what()) == "first handler failure");
    }
    CHECK(state.started == 2 && state.finished == 1 && state.destroyed == 2);
    CHECK(listener->native_handle() == invalid_handle);
}

Task<void> deadline_is_admission_only(EventLoop& loop) {
    test::section("service deadline stops admission, not draining I/O");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    HandlerState state;
    Outcome outcome;
    auto handler = [&state](tcp::Socket& socket, OperationOptions io) {
        return read_one(socket, io, state);
    };
    TaskScope tasks;
    tasks.spawn(collect(loop, *listener, handler,
                         {.io = {.deadline = Clock::now() + 1s}, .grace_period = 1h}, outcome));
    auto client = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(client.has_value());
    co_await wait_started(loop, state);
    co_await wait_closed(loop, *listener);
    CHECK(!state.io.deadline && !state.io.stop.stop_requested() && !outcome.done);
    const std::array<std::byte, 1> byte{};
    CHECK((co_await write_all(*client, byte)).has_value());
    co_await tasks.join();
    CHECK(outcome.result.has_value() && outcome.result->cancelled == 0);
}

Task<void> rejection_and_compatibility(EventLoop& loop) {
    test::section("bounded admission, rejection, legacy zero-grace cancellation and reclamation");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    HandlerState state;
    Outcome outcome;
    std::stop_source stop;
    auto handler = [&state](tcp::Socket& socket, OperationOptions io) {
        return read_one(socket, io, state);
    };
    TaskScope tasks;
    tasks.spawn(collect(loop, *listener, handler,
                         {.max_connections = 1, .io = {.stop = stop.get_token()}}, outcome, true));
    auto first = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(first.has_value());
    co_await wait_started(loop, state);
    auto rejected = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(rejected.has_value());
    std::array<std::byte, 1> byte{};
    auto eof = co_await rejected->read_some(byte, {.deadline = Clock::now() + 1s});
    CHECK(!eof && eof.error() == Errc::eof);
    CHECK(state.started == 1);
    stop.request_stop();
    co_await tasks.join();
    CHECK(outcome.result.has_value());
    CHECK(outcome.result->accepted == 2 && outcome.result->rejected == 1);
    CHECK(outcome.result->completed == 1 && outcome.result->cancelled == 1);
    CHECK(outcome.result->peak_active == 1 && state.destroyed == 1);
}

Task<Result<void>> finish_then_throw(tcp::Socket&, OperationOptions io, HandlerState& state,
                                      Gate& gate) {
    Lifetime alive{state};
    ++state.started;
    state.io = io;
    co_await gate;
    throw std::runtime_error("failure during grace");
    co_return Result<void>{};  // MSVC requires an explicit non-void coroutine return.
}
Task<void> exception_during_drain(EventLoop& loop) {
    test::section("an exception during grace cancels the long watchdog and still joins");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    HandlerState state;
    Gate gate;
    Outcome outcome;
    std::stop_source stop;
    auto handler = [&state, &gate](tcp::Socket& socket, OperationOptions io) {
        return finish_then_throw(socket, io, state, gate);
    };
    TaskScope tasks;
    tasks.spawn(collect(loop, *listener, handler,
                         {.io = {.stop = stop.get_token()}, .grace_period = 1h}, outcome));
    auto client = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(client.has_value());
    co_await wait_started(loop, state);
    stop.request_stop();
    co_await wait_closed(loop, *listener);
    CHECK(!state.io.stop.stop_requested() && !outcome.done);
    gate.open();
    co_await tasks.join();
    CHECK(outcome.exception != nullptr && outcome.done && state.destroyed == 1);
    try {
        if (outcome.exception) std::rethrow_exception(outcome.exception);
    } catch (const std::runtime_error& error) {
        CHECK(std::string(error.what()) == "failure during grace");
    }
}

Task<void> listener_close_drains(EventLoop& loop) {
    test::section("closing the listener stops admission without cancelling drain");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    HandlerState state;
    Outcome outcome;
    auto handler = [&state](tcp::Socket& socket, OperationOptions io) {
        return read_one(socket, io, state);
    };
    TaskScope tasks;
    tasks.spawn(collect(loop, *listener, handler, {.grace_period = 1h}, outcome));
    auto client = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(client.has_value());
    co_await wait_started(loop, state);
    listener->close();
    co_await loop.yield();
    CHECK(!state.io.stop.stop_requested() && !outcome.done);
    const std::array<std::byte, 1> byte{};
    CHECK((co_await write_all(*client, byte)).has_value());
    co_await tasks.join();
    CHECK(outcome.result.has_value() && outcome.result->completed == 1);
    CHECK(state.destroyed == 1);
}

Task<Result<void>> result_failure(tcp::Socket& socket, OperationOptions io, HandlerState& state) {
    Lifetime alive{state};
    const auto ordinal = ++state.started;
    if (ordinal == 1) co_return fail(std::make_error_code(std::errc::protocol_error));
    std::array<std::byte, 1> byte{};
    auto result = co_await socket.read_some(byte, io);
    if (!result) co_return fail(result.error());
    co_return Result<void>{};
}
Task<void> ordinary_error_does_not_stop_service(EventLoop& loop) {
    test::section("ordinary Result failure is counted; its slot is reclaimed for the next client");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    HandlerState state;
    Outcome outcome;
    std::stop_source stop;
    auto handler = [&state](tcp::Socket& socket, OperationOptions io) {
        return result_failure(socket, io, state);
    };
    TaskScope tasks;
    tasks.spawn(collect(loop, *listener, handler,
                         {.max_connections = 1, .io = {.stop = stop.get_token()}, .grace_period = 1h},
                         outcome));
    auto first = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(first.has_value());
    std::array<std::byte, 1> byte{};
    auto eof = co_await first->read_some(byte);
    CHECK(!eof && eof.error() == Errc::eof);
    auto second = co_await tcp::connect(loop, listener->local_endpoint());
    CHECK(second.has_value());
    co_await wait_started(loop, state, 2);
    second->close();
    stop.request_stop();
    co_await tasks.join();
    CHECK(outcome.result.has_value());
    CHECK(outcome.result->failed == 1 && outcome.result->completed == 2);
    CHECK(outcome.result->cancelled == 0 && outcome.result->rejected == 0);
    CHECK(outcome.result->peak_active == 1 && state.destroyed == 2);
}

Task<void> validation_and_precancel(EventLoop& loop) {
    test::section("invalid grace, pre-cancel, empty join and saturating counters");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    HandlerState state;
    auto handler = [&state](tcp::Socket& socket, OperationOptions io) {
        return read_one(socket, io, state);
    };
    auto invalid = co_await tcp::serve(loop, *listener, handler, {.grace_period = -1ms});
    CHECK(!invalid && invalid.error() == Errc::invalid_argument);
    invalid = co_await tcp::serve(*listener, handler, {.grace_period = 1ms});
    CHECK(!invalid && invalid.error() == Errc::invalid_argument);
    invalid = co_await tcp::serve(loop, *listener, handler, {.max_connections = 0});
    CHECK(!invalid && invalid.error() == Errc::invalid_argument);
    CHECK(listener->native_handle() != invalid_handle);
    auto closed = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(closed.has_value());
    closed->close();
    auto accept_error = co_await tcp::serve(loop, *closed, handler, {.grace_period = 1h});
    CHECK(!accept_error && accept_error.error() == Errc::invalid_argument);
    std::stop_source stop;
    stop.request_stop();
    auto result = co_await tcp::serve(loop, *listener, handler,
                                       {.io = {.stop = stop.get_token()}, .grace_period = 1h});
    CHECK(result.has_value() && result->accepted == 0 && state.started == 0);
    CHECK(listener->native_handle() == invalid_handle);
    auto count = std::numeric_limits<std::size_t>::max() - 1;
    tcp::detail::serve_increment(count);
    tcp::detail::serve_increment(count);
    CHECK(count == std::numeric_limits<std::size_t>::max());
}

Task<void> shared_admission_and_handler_deadline(EventLoop& loop) {
    test::section("shared admission budget and independent handler deadline");
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0)).value();
    ResourceBudget budget{1};
    auto held = budget.try_acquire(1).value();
    HandlerState state;
    Outcome outcome;
    std::stop_source stop;
    auto handler = [&state](tcp::Socket& socket, OperationOptions io) {
        return read_one(socket, io, state);
    };
    tcp::ServeOptions options;
    options.io.stop = stop.get_token();
    options.admission_budget = budget;
    options.handler_deadline = Clock::now() + 100ms;
    options.grace_period = 1s;
    TaskScope tasks;
    tasks.spawn(collect(loop, listener, handler, options, outcome));
    auto rejected = co_await tcp::connect(loop, listener.local_endpoint());
    CHECK(rejected.has_value());
    std::array<std::byte, 1> byte{};
    auto closed = co_await rejected->read_some(byte, {.deadline = Clock::now() + 1s});
    CHECK(!closed || *closed == 0);
    CHECK(state.started == 0 && budget.used() == 1);
    held.reset();
    auto accepted = co_await tcp::connect(loop, listener.local_endpoint());
    CHECK(accepted.has_value());
    co_await wait_started(loop, state);
    CHECK(budget.used() == 1 && state.io.deadline == options.handler_deadline);
    while (!state.finished) co_await loop.yield();
    stop.request_stop();
    co_await tasks.join();
    CHECK(outcome.result.has_value());
    CHECK(outcome.result && outcome.result->accepted == 2 && outcome.result->rejected == 1 &&
          outcome.result->completed == 1 && outcome.result->failed == 1);
    CHECK(budget.used() == 0);
}

Task<void> suite(EventLoop& loop) {
    co_await shared_admission_and_handler_deadline(loop);
    co_await drain_before_deadline(loop);
    co_await cancel_at_deadline(loop, false);
    co_await cancel_at_deadline(loop, true);
    co_await noncooperative_is_joined(loop);
    co_await exception_skips_grace(loop);
    co_await exception_during_drain(loop);
    co_await deadline_is_admission_only(loop);
    co_await rejection_and_compatibility(loop);
    co_await listener_close_drains(loop);
    co_await ordinary_error_does_not_stop_service(loop);
    co_await validation_and_precancel(loop);
}
}  // namespace

int main() {
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (!loop) return test::summary();
    CHECK(loop->run_until_complete(suite(*loop)).has_value());
    CHECK(loop->outstanding() == 0);
    return test::summary();
}
