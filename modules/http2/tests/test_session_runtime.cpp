#include "session_runtime_cases.hpp"
#include "mira/http2/client_session.hpp"
#include "mira/http2/connect_stream.hpp"
#include "mira/transport/tcp.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>

using namespace Mira;
using namespace runtime_test;
using namespace std::chrono_literals;

struct Fragmented {
    EventLoop& loop;
    transport::tcp::Socket& socket;
    bool reading = false, writing = false;
    Task<Result<std::size_t>> read_some(std::span<std::byte> bytes, OperationOptions options = {}) {
        check(!reading, "concurrent read reentry below the driver");
        reading = true;
        struct Guard { bool& value; ~Guard() { value = false; } } guard{reading};
        co_return co_await socket.read_some(bytes.first(std::min<std::size_t>(137, bytes.size())), options);
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes, OperationOptions options = {}) {
        check(!writing, "concurrent write reentry below the driver");
        writing = true;
        struct Guard { bool& value; ~Guard() { value = false; } } guard{writing};
        co_await loop.yield();
        co_return co_await socket.write_some(bytes.first(std::min<std::size_t>(251, bytes.size())), options);
    }
};

Task<void> server_requests(http2::Session& engine, http2::SessionDriver<Fragmented>& driver,
                            OperationOptions options) {
    std::map<std::int32_t, std::vector<std::byte>> bodies;
    std::map<std::int32_t, bool> replied;
    unsigned completed = 0;
    while (completed < 6) {
        for (const auto id : engine.streams()) {
            const auto* stream = engine.stream(id);
            if (stream->error || replied[id]) continue;
            bool cancelled = false, limited = false;
            for (const auto& field : stream->headers) {
                if (field.name == ":path" && field.value == "/cancel") cancelled = true;
                if (field.name == ":path" && field.value == "/limit") limited = true;
            }
            if (cancelled) continue;
            auto chunk = require(engine.take_body(id));
            auto& body = bodies[id];
            body.insert(body.end(), chunk.begin(), chunk.end());
            if (!chunk.empty()) driver.notify();
            if (stream->remote_end) {
                if (limited) {
                    require(engine.respond(id, {{":status", "200"}}, std::vector<std::byte>(4096)));
                } else {
                    check(body.size() == 128 * 1024, "concurrent request body incomplete");
                    require(engine.respond(id, {{":status", "200"}}, std::span(body).first(1024)));
                }
                replied[id] = true;
                ++completed;
                driver.notify();
            }
        }
        if (completed < 6) require(co_await driver.progress(options));
    }
    require(co_await driver.flush(options));
}
Task<void> request_one(http2::ClientSession<Fragmented>& client, std::byte value,
                        unsigned& completed, OperationOptions options) {
    auto response = require(co_await client.request(post_headers(), std::vector<std::byte>(128 * 1024, value), options));
    check(response.body == std::vector<std::byte>(1024, value), "multi-stream responses cross-contaminated");
    ++completed;
}
Task<void> runtime(EventLoop& loop, bool client_mode) {
    auto listener = require(transport::tcp::Listener::bind(loop, transport::Endpoint::loopback(0)));
    auto cs = require(co_await transport::tcp::connect(loop, listener.local_endpoint(), {}, {.deadline = Clock::now() + 5s}));
    auto ss = require(co_await listener.accept({.deadline = Clock::now() + 5s}));
    Fragmented ct{loop, cs}, st{loop, ss};
    http2::Limits limits;
    limits.enable_connect_protocol = true;
    limits.max_body_bytes = 1024 * 1024;
    limits.max_queued_body_bytes = 8192;
    auto c = require(http2::Session::create(http2::Role::client, limits));
    auto s = require(http2::Session::create(http2::Role::server, limits));
    http2::SessionDriver sd{loop, st, s};
    std::exception_ptr exception;
    if (!client_mode) {
        http2::SessionDriver cd{loop, ct, c};
        try {
            co_await duplex(loop, c, s, cd, sd, [](auto& engine, auto id, auto& driver) {
                return http2::ConnectStream{engine, id, driver};
            });
        } catch (...) { exception = std::current_exception(); }
        cd.stop(); sd.stop();
        try { co_await cd.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
    } else {
        http2::ClientSession client{loop, ct, c, 2048};
        TaskScope tasks, service;
        const OperationOptions options{.deadline = Clock::now() + 15s};
        unsigned completed = 0;
        service.spawn(server_requests(s, sd, options));
        std::stop_source cancel;
        Error cancelled;
        tasks.spawn(cancel_request(client, cancelled, {.stop = cancel.get_token(), .deadline = options.deadline}));
        tasks.spawn(bounded_request(client, options));
        for (unsigned i = 0; i < 4; ++i) tasks.spawn(request_one(client, std::byte(i), completed, options));
        require(co_await loop.sleep_for(2ms));
        cancel.request_stop();
        try { co_await tasks.join(); } catch (...) { exception = std::current_exception(); }
        // Completed streams must be recyclable; reuse the same ClientSession
        // and submit again.
        if (!exception) {
            try { co_await request_one(client, std::byte{5}, completed, options); }
            catch (...) { exception = std::current_exception(); }
        }
        if (exception) sd.stop();
        try { co_await service.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
        if (!exception) {
            try { co_await fail_connection(loop, client, cs, options); }
            catch (...) { exception = std::current_exception(); }
        }
        client.stop(); sd.stop();
        try { co_await client.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
        if (!exception) check(completed == 5, "reused request did not complete");
    }
    try { co_await sd.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
    check(!ct.reading && !ct.writing && !st.reading && !st.writing, "transport I/O still outstanding after join");
    if (exception) std::rethrow_exception(exception);
}
Task<void> death(EventLoop& loop) {
    int readers = 0, writers = 0;
    http::SessionDriver driver{loop, FaultWire{loop, false, false, readers, writers}};
    driver.notify();
    co_return;
}
Task<void> all(EventLoop& loop) {
    co_await failures(loop);
    co_await runtime(loop, false);
    co_await runtime(loop, true);
}
int main(int argc, char** argv) {
    try {
        auto loop = require(EventLoop::create());
        if (argc == 2 && std::string_view(argv[1]) == "--death") {
            std::set_terminate([] { std::_Exit(73); });
            require(loop.run_until_complete(death(loop)));
            return 0;
        }
        require(loop.run_until_complete(all(loop)));
        check(loop.outstanding() == 0, "driver lifecycle leaked async work");
        std::cout << "HTTP/2 session runtime passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
