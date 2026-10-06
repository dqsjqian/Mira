#pragma once

#include "mira/core/stream.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/http/session_driver.hpp"
#include "mira/http/fields.hpp"

#include <array>
#include <chrono>
#include <exception>
#include <stdexcept>
#include <source_location>
#include <string>
#include <thread>
#include <vector>

namespace runtime_test {
using namespace Mira;
using namespace std::chrono_literals;
inline void check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
template<class T> T require(Result<T> value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error(value.error().message() + " at " + where.file_name() + ":" + std::to_string(where.line()));
    return std::move(*value);
}
inline void require(Result<void> value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error(value.error().message() + " at " + where.file_name() + ":" + std::to_string(where.line()));
}
inline http::Headers tunnel_headers() {
    return {{":method", "CONNECT"}, {":scheme", "https"}, {":authority", "localhost"},
            {":path", "/duplex"}, {":protocol", "test"}};
}
inline http::Headers post_headers() {
    return {{":method", "POST"}, {":scheme", "https"}, {":authority", "localhost"}, {":path", "/echo"}};
}
template<class Stream>
Task<void> read_result(Stream& stream, std::span<std::byte> bytes, Result<std::size_t>& output,
                       OperationOptions options) {
    output = co_await stream.read_some(bytes, options);
}
template<class Stream>
Task<void> write_result(Stream& stream, std::span<const std::byte> bytes, Result<std::size_t>& output,
                        OperationOptions options) {
    output = co_await stream.write_some(bytes, options);
}
template<class Stream>
Task<void> send_all(Stream& stream, const std::vector<std::byte>& bytes, OperationOptions options) {
    require(co_await write_all(stream, bytes, options));
}
template<class Stream>
Task<void> receive_all(Stream& stream, std::vector<std::byte>& bytes, OperationOptions options) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        auto count = require(co_await stream.read_some(std::span(bytes).subspan(offset), options));
        check(count != 0, "unexpected EOF on large read");
        offset += count;
    }
}

template<class Client>
Task<void> lost_request(Client& client, Error& error, OperationOptions options) {
    auto result = co_await client.request(post_headers(), {}, options);
    check(!result, "request succeeded on a broken connection");
    error = result.error();
}

template<class Client, class Socket>
Task<void> fail_connection(EventLoop& loop, Client& client, Socket& socket, OperationOptions options) {
    Error a, b;
    TaskScope tasks;
    tasks.spawn(lost_request(client, a, options));
    tasks.spawn(lost_request(client, b, options));
    require(co_await loop.sleep_for(2ms));
    socket.close();
    co_await tasks.join();
    check(a && a == b && client.error() == a, "connection error not broadcast consistently to requests");
    auto rejected = co_await client.request(post_headers());
    check(!rejected && rejected.error() == a, "failed connection accepted a subsequent request");
}

template<class Client>
Task<void> bounded_request(Client& client, OperationOptions options) {
    auto headers = post_headers();
    headers.back().value = "/limit";
    auto result = co_await client.request(headers, {}, options);
    check(!result && result.error() == Errc::limit_exceeded, "response budget did not isolate the oversized response");
}

template<class Client>
Task<void> cancel_request(Client& client, Error& error, OperationOptions options) {
    auto headers = post_headers();
    headers.back().value = "/cancel";
    auto result = co_await client.request(headers, {}, options);
    check(!result && result.error() == Errc::cancelled, "cancelled request did not report cancelled");
    error = result.error();
}

// MakeStream is the protocol-level ConnectStream factory; the low-level
// engine interface is identical.
template<class Engine, class Driver, class MakeStream>
Task<void> duplex(EventLoop& loop, Engine& client, Engine& server, Driver& cd, Driver& sd,
                   MakeStream make_stream) {
    const OperationOptions options{.deadline = Clock::now() + 15s};
    cd.notify(); sd.notify();
    while (!client.peer_connect_protocol_enabled()) require(co_await cd.progress(options));
    const auto id = require(client.request_stream(tunnel_headers()));
    const auto cancel_id = require(client.request_stream(tunnel_headers()));
    require(co_await cd.flush(options));
    while (!server.connect_state(cancel_id)) require(co_await sd.progress(options));
    require(server.respond_stream(id, {{":status", "200"}}));
    require(server.respond_stream(cancel_id, {{":status", "200"}}));
    require(co_await sd.flush(options));
    while (!require(client.connect_state(cancel_id)).accepted) require(co_await cd.progress(options));
    auto c = make_stream(client, id, cd);
    auto s = make_stream(server, id, sd);
    auto cancelled = make_stream(client, cancel_id, cd);

    std::array<std::byte, 4> read{}, probe{};
    const std::array<std::byte, 4> ping{std::byte{'p'}, std::byte{'i'}, std::byte{'n'}, std::byte{'g'}};
    Result<std::size_t> pending = fail(Errc::would_block), written = fail(Errc::would_block);
    TaskScope first;
    std::exception_ptr exception;
    try {
        first.spawn(read_result(c, read, pending, options));
        require(co_await loop.sleep_for(2ms));
        check(!pending && pending.error() == Errc::would_block, "read must actually suspend");
        auto overlap = co_await c.read_some(probe, options);
        check(!overlap && overlap.error() == Errc::invalid_argument, "overlapping read not rejected");
        first.spawn(write_result(c, std::span<const std::byte>(ping), written, options));
        overlap = co_await c.write_some(ping, options);
        check(!overlap && overlap.error() == Errc::invalid_argument, "overlapping write not rejected");
        check(require(co_await s.read_some(probe, options)) == ping.size() && probe == ping,
              "write reached the peer while a read was suspended");
        check(!pending && pending.error() == Errc::would_block, "suspended read completed without peer writes");
        check(require(co_await s.write_some(ping, options)) == ping.size(), "write-back failed");
    } catch (...) { exception = std::current_exception(); }
    try { co_await first.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
    if (exception) std::rethrow_exception(exception);
    check(pending && written && read == ping, "duplex results failed");

    const std::vector<std::byte> forward(512 * 1024, std::byte{0x31}), reverse(512 * 1024, std::byte{0x72});
    std::vector<std::byte> received_forward(forward.size()), received_reverse(reverse.size());
    Result<std::size_t> stopped = fail(Errc::would_block);
    std::stop_source stop;
    TaskScope large;
    large.spawn(read_result(cancelled, probe, stopped, {.stop = stop.get_token(), .deadline = options.deadline}));
    large.spawn(send_all(c, forward, options));
    large.spawn(send_all(s, reverse, options));
    large.spawn(receive_all(c, received_reverse, options));
    large.spawn(receive_all(s, received_forward, options));
    std::thread cancelling([&] { stop.request_stop(); });
    cancelling.join();
    co_await large.join();
    check(!stopped && stopped.error() == Errc::cancelled, "cross-thread single-stream cancellation did not return");
    check(received_forward == forward && received_reverse == reverse, "bidirectional over-window payload incomplete");
    check(!cd.error() && !sd.error(), "single-stream cancellation contaminated the connection");

    const auto deadline_id = require(client.request_stream(tunnel_headers()));
    require(co_await cd.flush(options));
    while (!server.connect_state(deadline_id)) require(co_await sd.progress(options));
    require(server.respond_stream(deadline_id, {{":status", "200"}}));
    require(co_await sd.flush(options));
    while (!require(client.connect_state(deadline_id)).accepted) require(co_await cd.progress(options));
    auto deadline_stream = make_stream(client, deadline_id, cd);
    auto expired = co_await deadline_stream.read_some(probe, {.deadline = Clock::now() + 2ms});
    check(!expired && expired.error() == Errc::timed_out, "suspended stream deadline did not fire");
    check(!cd.error(), "stream deadline cancelled the connection read");
    require(co_await c.finish(options));
    auto ended = co_await s.read_some(probe, options);
    check(!ended && ended.error() == Errc::eof, "half-close did not return EOF");
    require(co_await s.write_some(ping, options));
    check(require(co_await c.read_some(read, options)) == ping.size() && read == ping, "half-close lost the reverse write");

    Result<std::size_t> closed_read = fail(Errc::would_block);
    TaskScope closing;
    closing.spawn(read_result(c, read, closed_read, options));
    c.close();
    co_await closing.join();
    check(!closed_read && closed_read.error() == Errc::cancelled, "close did not wake the suspended read");
    check(!cd.error() && !sd.error(), "close cancelled the whole connection");
}

struct FaultWire {
    EventLoop& loop;
    bool throw_read = false;
    bool throw_write = false;
    int& readers;
    int& writers;
    Task<Result<void>> read(OperationOptions options) {
        ++readers;
        struct Guard { int& n; ~Guard() { --n; } } guard{readers};
        auto result = co_await loop.sleep_for(throw_read ? 2ms : 1h, options);
        if (throw_read && result) throw std::runtime_error("read failure");
        co_return result;
    }
    Task<Result<void>> flush(OperationOptions) {
        ++writers;
        struct Guard { int& n; ~Guard() { --n; } } guard{writers};
        co_await loop.yield();
        if (throw_write) throw std::runtime_error("write failure");
        co_return Result<void>{};
    }
};
Task<void> failure_wait(http::SessionDriver<FaultWire>& driver, Error& error) {
    for (;;) {
        auto result = co_await driver.progress();
        if (!result) { error = result.error(); co_return; }
    }
}
struct TimedWire {
    EventLoop& loop;
    int& expiries;
    int& cancelled_reads;
    Clock::time_point next = Clock::now() + 2ms;
    Task<Result<void>> read(OperationOptions options) {
        auto result = co_await loop.sleep_for(1h, options);
        if (!result && result.error() == Errc::cancelled) ++cancelled_reads;
        co_return result;
    }
    Task<Result<void>> flush(OperationOptions) { co_return Result<void>{}; }
    Clock::time_point expiry() const { return next; }
    Result<void> handle_expiry() {
        ++expiries;
        next = Clock::time_point::max();
        return {};
    }
};
inline Task<void> failures(EventLoop& loop) {
    int readers = 0, writers = 0;
    {
        int expiries = 0, cancelled_reads = 0;
        http::SessionDriver timer{loop, TimedWire{loop, expiries, cancelled_reads}};
        while (!expiries) require(co_await timer.progress({.deadline = Clock::now() + 1s}));
        check(cancelled_reads == 0, "expiry timer must not cancel pending receives");
        co_await timer.join();
        check(cancelled_reads == 1, "join must cancel and drain receives");
    }
    { http::SessionDriver empty{loop, FaultWire{loop, false, false, readers, writers}}; }
    for (const bool reading : {false, true}) {
        http::SessionDriver driver{loop, FaultWire{loop, reading, !reading, readers, writers}};
        Error a, b;
        TaskScope tasks;
        tasks.spawn(failure_wait(driver, a));
        tasks.spawn(failure_wait(driver, b));
        co_await tasks.join();
        check(a == Errc::internal && b == a, "connection exception not broadcast to all waiters");
        bool threw = false;
        try { co_await driver.join(); } catch (const std::runtime_error&) { threw = true; }
        check(threw && readers == 0 && writers == 0, "exceptional join did not drain and rethrow");
    }
    http::SessionDriver driver{loop, FaultWire{loop, false, false, readers, writers}, 1};
    Error a;
    TaskScope tasks;
    tasks.spawn(failure_wait(driver, a));
    auto full = co_await driver.progress();
    check(!full && full.error() == Errc::limit_exceeded, "waiter budget not enforced");
    driver.stop(std::make_error_code(std::errc::connection_reset));
    co_await driver.join();
    co_await tasks.join();
    check(a == std::errc::connection_reset && readers == 0 && writers == 0, "stop/join did not drain tasks");
}
} // namespace runtime_test
