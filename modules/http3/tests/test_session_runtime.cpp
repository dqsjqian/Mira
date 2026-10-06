#include "../../http2/tests/session_runtime_cases.hpp"
#include "mira/http3/client_session.hpp"
#include "mira/http3/connect_stream.hpp"
#include "mira/transport/udp.hpp"

#include <iostream>

using namespace Mira;
using namespace runtime_test;
using namespace std::chrono_literals;

struct Datagram {
    EventLoop& loop;
    transport::udp::Socket& socket;
    bool reading = false, writing = false;
    Task<Result<transport::udp::Datagram>> receive_from(std::span<std::byte> bytes, OperationOptions options = {}) {
        check(!reading, "overlapping UDP receives below the driver");
        reading = true;
        struct Guard { bool& value; ~Guard() { value = false; } } guard{reading};
        co_return co_await socket.receive_from(bytes, options);
    }
    Task<Result<std::size_t>> send_to(std::span<const std::byte> bytes, transport::Endpoint peer,
                                     OperationOptions options = {}) {
        check(!writing, "overlapping UDP sends below the driver");
        writing = true;
        struct Guard { bool& value; ~Guard() { value = false; } } guard{writing};
        co_await loop.yield();
        co_return co_await socket.send_to(bytes, peer, options);
    }
};
Task<void> server_requests(http3::Engine& engine, http3::SessionDriver<Datagram>& driver,
                            OperationOptions options) {
    std::map<std::int64_t, std::vector<std::byte>> bodies;
    unsigned completed = 0;
    std::int64_t cancelled = -1, limited = -1;
    while (completed < 6) {
        for (auto& event : engine.take_events()) {
            if (event.kind == http3::Event::Kind::headers)
                for (const auto& field : event.fields) {
                    if (field.name == ":path" && field.value == "/cancel") cancelled = event.stream_id;
                    if (field.name == ":path" && field.value == "/limit") limited = event.stream_id;
                }
            if (event.stream_id == cancelled) continue;
            if (event.kind == http3::Event::Kind::body) {
                auto& body = bodies[event.stream_id];
                body.insert(body.end(), event.data.begin(), event.data.end());
                require(engine.consume(event.stream_id, event.data.size()));
                driver.notify();
            }
            if (event.kind == http3::Event::Kind::end) {
                const auto& body = bodies[event.stream_id];
                if (event.stream_id == limited) {
                    require(engine.respond(event.stream_id, {{":status", "200"}}, std::vector<std::byte>(4096)));
                } else {
                    check(body.size() == 128 * 1024, "H3 concurrent request body incomplete");
                    require(engine.respond(event.stream_id, {{":status", "200"}}, std::span(body).first(1024)));
                }
                ++completed;
                driver.notify();
            }
        }
        if (completed < 6) require(co_await driver.progress(options));
    }
    require(co_await driver.flush(options));
}
Task<void> request_one(http3::ClientSession<Datagram>& client, std::byte value,
                        unsigned& completed, OperationOptions options) {
    auto response = require(co_await client.request(post_headers(), std::vector<std::byte>(128 * 1024, value), options));
    check(response.body == std::vector<std::byte>(1024, value), "H3 multi-stream responses cross-contaminated");
    ++completed;
}
Task<void> runtime(EventLoop& loop, const char* cert, const char* key, bool client_mode) {
    auto cs = require(transport::udp::Socket::bind(loop, transport::Endpoint::loopback(0)));
    auto ss = require(transport::udp::Socket::bind(loop, transport::Endpoint::loopback(0)));
    const auto ca = require(cs.local_endpoint()), sa = require(ss.local_endpoint());
    quic::Options co, so;
    co.local = ca; co.remote = sa; co.ca_file = cert; co.peer_name = "localhost";
    so.local = sa; so.remote = ca; so.certificate_file = cert; so.private_key_file = key;
    co.max_buffered_bytes = so.max_buffered_bytes = 32768;
    auto cq = require(quic::Engine::client(co, quic::detail::now_ns()));
    auto initial = require(cq.poll(quic::detail::now_ns()));
    auto sq = require(quic::Engine::accept(so, initial, quic::detail::now_ns()));
    http3::Limits limits;
    limits.enable_connect_protocol = true;
    limits.max_buffered_body = 16384;
    auto c = require(http3::Engine::create(std::move(cq), false, limits));
    auto s = require(http3::Engine::create(std::move(sq), true, limits));
    Datagram ct{loop, cs}, st{loop, ss};
    http3::SessionDriver sd{loop, st, s, ca};
    std::exception_ptr exception;
    if (!client_mode) {
        http3::SessionDriver cd{loop, ct, c, sa};
        try {
            co_await duplex(loop, c, s, cd, sd, [](auto& engine, auto id, auto& driver) {
                return http3::ConnectStream{engine, id, driver};
            });
        } catch (...) { exception = std::current_exception(); }
        cd.stop(); sd.stop();
        try { co_await cd.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
    } else {
        http3::ClientSession client{loop, ct, c, sa, 2048};
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
        if (!exception) check(completed == 5, "H3 reused request did not complete");
    }
    try { co_await sd.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
    check(!ct.reading && !ct.writing && !st.reading && !st.writing, "H3 transport I/O still outstanding after join");
    if (exception) std::rethrow_exception(exception);
}
Task<void> all(EventLoop& loop, const char* cert, const char* key) {
    co_await runtime(loop, cert, key, false);
    co_await runtime(loop, cert, key, true);
}
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    try {
        auto loop = require(EventLoop::create());
        require(loop.run_until_complete(all(loop, argv[1], argv[2])));
        check(loop.outstanding() == 0, "H3 driver lifecycle leaked async work");
        std::cout << "HTTP/3 session runtime passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
