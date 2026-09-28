// HTTP/3 over a real UDP loopback: the in-memory engine tests prove the
// protocol state machines; this one proves the whole stack — nghttp3 over
// ngtcp2 over the kernel's UDP, driven through the event loop.

#include "mira/core/task_scope.hpp"
#include "mira/http3/connection.hpp"
#include "mira/transport/udp.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>

using namespace Mira;
using namespace std::chrono_literals;
using quic::Bytes;
using transport::Endpoint;
using H3Connection = http3::Connection<transport::udp::Socket>;

namespace {

/// Payloads are library-typed (`std::byte`) end to end; `wire` is a plain
/// span view kept for uniform call sites.
std::span<const std::byte> wire(const Bytes& bytes) {
    return {bytes.data(), bytes.size()};
}

template<class T>
T require(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message() + " (" +
                                 std::to_string(value.error().value()) + ")");
    return std::move(*value);
}

void require(Result<void> value) {
    if (!value) throw std::runtime_error(value.error().message());
}

void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

Task<void> server_side(transport::udp::Socket& server_socket,
                       std::array<std::byte, 65536>& initial_buffer,
                       std::vector<std::byte>& initial,
                       quic::Options& server_options,
                       const Endpoint& server_address,
                       std::unique_ptr<H3Connection>& server,
                       bool overflow) {
    auto datagram =
        co_await server_socket.receive_from(initial_buffer, {.deadline = Clock::now() + 5s});
    check(datagram.has_value(), "server did not receive the Initial");
    initial.assign(initial_buffer.data(), initial_buffer.data() + datagram->size);
    // Engine::accept requires both endpoints: the local one we bound,
    // the remote learned from the Initial datagram's source address.
    server_options.local = server_address;
    server_options.remote = datagram->peer;
    http3::Limits limits;
    if (overflow) limits.max_events = 3;
    auto accepted = co_await H3Connection::serve(std::move(server_socket),
                                                 server_options,
                                                 limits,
                                                 initial,
                                                 {.deadline = Clock::now() + 10s});
    check(accepted.has_value(), "server handshake failed");
    if (!accepted) co_return;
    server = std::make_unique<H3Connection>(std::move(*accepted));
    if (overflow) {
        // Each engine batch fits, but unread events across pumps must obey the Connection budget.
        for (;;) {
            auto round = co_await server->pump({.deadline = Clock::now() + 10s});
            if (!round) {
                check(round.error() == Errc::limit_exceeded,
                      "unconsumed event queue did not hit its bound");
                break;
            }
        }
        auto events = co_await server->receive_events({.deadline = Clock::now() + 10s});
        check(!events && events.error() == Errc::limit_exceeded,
              "queue overflow must remain terminal");
        require(co_await server->close(0, {.deadline = Clock::now() + 10s}));
        co_return;
    }

    std::map<std::int64_t, Bytes> bodies;
    std::size_t answered = 0;
    std::int64_t cancelled_stream = -1;
    while (answered < 3) {
        auto events = require(co_await server->receive_events({.deadline = Clock::now() + 10s}));
        check(!events.empty(), "receive_events must not return an empty batch");
        for (const auto& event : events) {
            if (event.stream_id == cancelled_stream) continue;
            if (event.kind == http3::Event::Kind::headers) {
                check(!bodies.contains(event.stream_id), "duplicate request head");
                bodies.emplace(event.stream_id, Bytes{});
                for (const auto& [name, value] : event.fields) {
                    if (name == ":path" && value == "/reset") {
                        cancelled_stream = event.stream_id;
                        require(server->cancel(event.stream_id));
                        bodies.erase(event.stream_id);
                        ++answered;
                    }
                }
            } else if (event.kind == http3::Event::Kind::body) {
                check(bodies.contains(event.stream_id), "body before request head");
                auto& body = bodies.at(event.stream_id);
                body.insert(body.end(), event.data.begin(), event.data.end());
                require(server->consume(event.stream_id, event.data.size()));
            } else if (event.kind == http3::Event::Kind::end) {
                auto& body = bodies.at(event.stream_id);
                const http3::Headers response_fields{
                    {":status", "200"}, {"content-length", std::to_string(body.size())}};
                require(co_await server->respond(event.stream_id, response_fields, wire(body),
                                                 {.deadline = Clock::now() + 10s}));
                bodies.erase(event.stream_id);
                ++answered;
            } else if (event.kind == http3::Event::Kind::reset) {
                throw std::runtime_error("unexpected reset");
            }
        }
    }
    while (!server->closed()) {
        auto round = co_await server->pump({.deadline = Clock::now() + 10s});
        if (!round) {
            check(server->closed(), "server pump failed before peer close");
            break;
        }
    }
}

Task<void> client_side(EventLoop& loop,
                       quic::Options& client_options,
                       std::unique_ptr<H3Connection>& client,
                       bool overflow) {
    auto connected = co_await H3Connection::connect(
        loop, client_options, http3::Limits{}, {.deadline = Clock::now() + 10s});
    check(connected.has_value(), "client handshake failed");
    if (!connected) co_return;
    client = std::make_unique<H3Connection>(std::move(*connected));
    if (overflow) {
        for (int i = 0; i < 3; ++i) {
            const http3::Headers queued_fields{{":method", "GET"}, {":scheme", "https"},
                                                {":authority", "localhost"}, {":path", "/queued"}};
            require(co_await client->request(queued_fields));
            auto round = co_await client->pump({.deadline = Clock::now() + 10s});
            if (!round) {
                check(client->closed(), "queue-test client failed before peer close");
                co_return;
            }
        }
        while (!client->closed()) {
            auto round = co_await client->pump({.deadline = Clock::now() + 10s});
            if (!round) {
                check(client->closed(), "queue-test client did not observe close");
                break;
            }
        }
        co_return;
    }

    Bytes payload(20000, std::byte{0x48});
    payload[11] = std::byte{0};  // Binary safety.
    const http3::Headers first_fields{{":method", "POST"}, {":scheme", "https"},
                                      {":authority", "localhost"}, {":path", "/echo"}};
    const http3::Headers second_fields{{":method", "POST"}, {":scheme", "https"},
                                       {":authority", "localhost"}, {":path", "/another"}};
    const std::int64_t first = require(co_await client->request(first_fields, wire(payload)));
    const std::int64_t second = require(co_await client->request(second_fields, wire(payload)));
    check(first != second, "requests must have distinct stream IDs");
    // Submit both requests before reading; the second response may arrive while reading the first.
    for (const auto stream : {first, second}) {
        auto head = co_await client->await_head(stream, {.deadline = Clock::now() + 10s});
        check(head.has_value(), "client did not receive the response head");
        if (!head) co_return;
        bool status_ok = false;
        for (const auto& [name, value] : head->fields)
            if (name == ":status" && value == "200") status_ok = true;
        check(status_ok, "response status is not 200");

        std::uint64_t total = 0;
        bool fin = false;
        while (!fin) {
            auto chunk = co_await client->read_body(stream, {.deadline = Clock::now() + 10s});
            if (!chunk)
                throw std::runtime_error(std::string("client body read failed: ") +
                                         chunk.error().message() + " (" +
                                         std::to_string(chunk.error().value()) + ")");
            if (!chunk) co_return;
            require(client->consume(stream, chunk->data.size()));
            check(
                std::all_of(chunk->data.begin(),
                            chunk->data.end(),
                            [](std::byte b) { return b == std::byte{0x48} || b == std::byte{0}; }),
                "echoed data corrupted");
            total += chunk->data.size();
            fin = chunk->fin;
        }
        check(total == payload.size(), "echoed byte count mismatch");
        auto ended = require(co_await client->read_body(stream, {.deadline = Clock::now() + 1s}));
        check(ended.fin && ended.data.empty(), "consumed EOF must remain terminal");
    }
    const http3::Headers reset_fields{{":method", "GET"}, {":scheme", "https"},
                                      {":authority", "localhost"}, {":path", "/reset"}};
    const auto reset_stream = require(co_await client->request(reset_fields));
    auto reset_head = co_await client->await_head(reset_stream, {.deadline = Clock::now() + 10s});
    check(!reset_head && reset_head.error() == std::errc::connection_reset,
          "reset must fail await_head rather than produce an empty successful head");
    auto reset_body = co_await client->read_body(reset_stream, {.deadline = Clock::now() + 10ms});
    check(!reset_body && reset_body.error() == std::errc::connection_reset,
          "consumed reset must remain terminal without waiting for the deadline");
    auto remaining = co_await client->receive_events({.deadline = Clock::now() + 20ms});
    check(!remaining && remaining.error() == Errc::timed_out,
          "reset event must be consumed and an idle receive must respect its deadline");
    require(co_await client->close(0, {.deadline = Clock::now() + 10s}));
}

Task<void> run(EventLoop& loop, const char* certificate, const char* key, bool overflow = false) {
    auto server_socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    const Endpoint server_address = require(server_socket.local_endpoint());

    quic::Options client_options;
    client_options.local = Endpoint::loopback(0);
    client_options.remote = server_address;
    client_options.ca_file = certificate;
    client_options.peer_name = "localhost";
    client_options.alpn = "h3";

    quic::Options server_options;
    server_options.certificate_file = certificate;
    server_options.private_key_file = key;
    server_options.alpn = "h3";

    std::array<std::byte, 65536> initial_buffer{};
    std::vector<std::byte> initial;

    TaskScope scope;
    std::unique_ptr<H3Connection> client;
    std::unique_ptr<H3Connection> server;

    scope.spawn(server_side(
        server_socket, initial_buffer, initial, server_options, server_address, server, overflow));
    scope.spawn(client_side(loop, client_options, client, overflow));
    co_await scope.join();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) return 2;
    auto loop = EventLoop::create();
    if (!loop) return 2;
    try {
        require(loop->run_until_complete(run(*loop, argv[1], argv[2])));
        require(loop->run_until_complete(run(*loop, argv[1], argv[2], true)));
        std::cout << "HTTP/3 over UDP loopback: handshake, two discovered streams, POST/echo 20KB, "
                     "flow control, and close passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
