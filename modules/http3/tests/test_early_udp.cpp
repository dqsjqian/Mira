// HTTP/3 0-RTT through http3::Connection over real UDP loopback: the first
// connection stores a ticket; the second returns from connect() before any
// datagram is sent, carries a GET in 0-RTT, and a POST issued meanwhile waits
// for the handshake instead of being refused.

#include "mira/core/task_scope.hpp"
#include "mira/http3/connection.hpp"
#include "mira/transport/udp.hpp"

#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>

using namespace Mira;
using namespace std::chrono_literals;
using transport::Endpoint;
using H3Connection = http3::Connection<transport::udp::Socket>;

namespace {

template<class T>
T require(Result<T> value, const char* what) {
    if (!value)
        throw std::runtime_error(std::string(what) + ": " + value.error().message() + " (" +
                                 std::to_string(value.error().value()) + ")");
    return std::move(*value);
}
void require(Result<void> value, const char* what) {
    if (!value) throw std::runtime_error(std::string(what) + ": " + value.error().message());
}
void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

struct Seen {
    std::map<std::string, bool> early;  // path -> early flag of its request head
};

Task<void> serve_one(transport::udp::Socket socket, quic::Options options, http3::Limits limits,
                     std::size_t requests, Seen& seen) {
    std::array<std::byte, 65536> buffer{};
    auto datagram = co_await socket.receive_from(buffer, {.deadline = Clock::now() + 5s});
    check(datagram.has_value(), "server did not receive the Initial");
    options.local = require(socket.local_endpoint(), "local endpoint");
    options.remote = datagram->peer;
    auto server = require(co_await H3Connection::serve(std::move(socket), options, limits,
                                                       std::span{buffer.data(), datagram->size},
                                                       {.deadline = Clock::now() + 10s}),
                          "serve");
    std::map<std::int64_t, std::string> paths;
    std::size_t answered = 0;
    while (answered < requests) {
        auto events = require(co_await server.receive_events({.deadline = Clock::now() + 10s}), "events");
        for (const auto& event : events) {
            if (event.kind == http3::Event::Kind::headers) {
                for (const auto& [name, value] : event.fields)
                    if (name == ":path") {
                        paths[event.stream_id] = value;
                        seen.early[value] = event.early_data;
                    }
            } else if (event.kind == http3::Event::Kind::body) {
                require(server.consume(event.stream_id, event.data.size()), "consume");
            } else if (event.kind == http3::Event::Kind::end) {
                const std::string body = "ok " + paths[event.stream_id];
                require(co_await server.respond(event.stream_id,
                            {{":status", "200"}, {"content-length", std::to_string(body.size())}},
                            std::as_bytes(std::span{body.data(), body.size()}),
                            {.deadline = Clock::now() + 10s}),
                        "respond");
                ++answered;
            }
        }
    }
    // Keep serving until the client closes so its final reads complete.
    while (!server.closed()) {
        auto pumped = co_await server.pump({.deadline = Clock::now() + 10s});
        if (!pumped) break;
    }
}

Task<std::string> fetch(H3Connection& client, std::int64_t stream) {
    auto head = require(co_await client.await_head(stream, {.deadline = Clock::now() + 10s}), "head");
    std::string status;
    for (const auto& [name, value] : head.fields)
        if (name == ":status") status = value;
    check(status == "200", "response status is not 200");
    std::string body;
    for (;;) {
        auto chunk = require(co_await client.read_body(stream, {.deadline = Clock::now() + 10s}), "body");
        require(client.consume(stream, chunk.data.size()), "consume");
        body.append(reinterpret_cast<const char*>(chunk.data.data()), chunk.data.size());
        if (chunk.fin) co_return body;
    }
}

http3::Headers fields(std::string method, std::string path) {
    return {{":method", std::move(method)}, {":scheme", "https"}, {":authority", "localhost"},
            {":path", std::move(path)}};
}

Task<void> client_one(EventLoop& loop, quic::Options options, bool expect_early) {
    auto client = require(co_await H3Connection::connect(loop, options, {},
                                                         {.deadline = Clock::now() + 10s}),
                          "connect");
    check(client.early_ready() == expect_early, "0-RTT readiness does not match the ticket state");
    const auto get = require(co_await client.request(fields("GET", "/get")), "GET");
    // Not early-eligible: waits for the handshake (bounded) and goes out in 1-RTT.
    const auto post = require(co_await client.request(fields("POST", "/post"),
                                  std::as_bytes(std::span{"abc", 3}),
                                  {.deadline = Clock::now() + 10s}),
                              "POST");
    check(client.ready(), "POST returned before the handshake completed");
    const auto get_body = co_await fetch(client, get);
    check(get_body == "ok /get", "GET body mismatch");
    const auto post_body = co_await fetch(client, post);
    check(post_body == "ok /post", "POST body mismatch");
    require(co_await client.close(0, {.deadline = Clock::now() + 10s}), "close");
}

// Tickets are keyed by the server endpoint, so both rounds reuse one port.
Task<void> round(EventLoop& loop, quic::Options client_options, quic::Options server_options,
                 http3::Limits limits, bool expect_early, Seen& seen, Endpoint& address) {
    auto socket = require(transport::udp::Socket::bind(loop, address), "bind");
    address = require(socket.local_endpoint(), "server endpoint");
    client_options.local = Endpoint::loopback(0);
    client_options.remote = address;
    TaskScope scope;
    scope.spawn(serve_one(std::move(socket), std::move(server_options), limits, 2, seen));
    scope.spawn(client_one(loop, std::move(client_options), expect_early));
    co_await scope.join();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) return 2;
    auto loop = EventLoop::create();
    if (!loop) return 2;
    try {
        http3::Limits limits;
        quic::Options client, server;
        client.ca_file = argv[1];
        client.peer_name = "localhost";
        client.service_scope = "h3-early-udp";
        client.early_data = quic::EarlyDataPolicy::replay_safe;
        client.session_cache = require(quic::SessionCache::create(), "cache");
        server.certificate_file = argv[1];
        server.private_key_file = argv[2];
        server.service_scope = client.service_scope;
        server.early_data = quic::EarlyDataPolicy::replay_safe;
        server.early_data_context = http3::early_data_context(limits);
        // The context only pins certificate, ALPN, scope and limits; endpoints come per connection.
        server.local = Endpoint::loopback(1);
        server.remote = Endpoint::loopback(2);
        server.server_context = require(quic::ServerContext::create(server), "server context");

        Endpoint address = Endpoint::loopback(0);
        Seen first;
        require(loop->run_until_complete(round(*loop, client, server, limits, false, first, address)),
                "round 1");
        check(!first.early["/get"] && !first.early["/post"], "ticketless requests flagged early");
        check(client.session_cache->size() == 1, "first connection stored no ticket");

        Seen second;
        require(loop->run_until_complete(round(*loop, client, server, limits, true, second, address)),
                "round 2");
        check(second.early["/get"], "GET was not carried in 0-RTT");
        check(!second.early["/post"], "POST was sent in 0-RTT");
        std::cout << "HTTP/3 0-RTT over UDP: connect before the handshake, early GET, "
                     "handshake-gated POST passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
