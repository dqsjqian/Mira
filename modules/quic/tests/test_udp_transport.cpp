// QUIC over a real UDP loopback: the engine's in-memory datagram tests are
// replaced by an actual socket pair for this round. Same certificates, same
// payload discipline — but the packets now traverse the kernel's UDP stack
// and the event loop's datagram operations.

#include "mira/core/task_scope.hpp"
#include "mira/quic/connection.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <stop_token>

using namespace Mira;
using namespace std::chrono_literals;
using transport::Endpoint;
using quic::Connection;
using UdpConnection = Connection<transport::udp::Socket>;

namespace {

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
                       std::vector<std::byte>& initial, quic::Options& server_options,
                       const Endpoint& server_address, std::unique_ptr<UdpConnection>& server) {
        // Receive the Initial datagram, then hand the socket to the
        // connection — a QUIC listener routes by connection ID; this test
        // serves exactly one client per socket.
        auto datagram =
            co_await server_socket.receive_from(initial_buffer, {.deadline = Clock::now() + 5s});
        check(datagram.has_value(), "server did not receive the Initial");
        initial.assign(initial_buffer.data(), initial_buffer.data() + datagram->size);
        // Engine::accept requires both endpoints: the local one we bound,
        // the remote learned from the Initial datagram's source address.
        server_options.local = server_address;
        server_options.remote = datagram->peer;
        auto accepted =
            co_await UdpConnection::serve(std::move(server_socket), server_options, initial,
                                           {.deadline = Clock::now() + 10s});
        if (!accepted) throw std::runtime_error(std::string("server handshake failed: ") + accepted.error().message() + " (" + std::to_string(accepted.error().value()) + ")");
        if (!accepted) co_return;
        server = std::make_unique<UdpConnection>(std::move(*accepted));
        check(server->negotiated_protocol() == "h3", "server ALPN mismatch");

        // Echo the stream, then say goodbye on the same one.
        std::uint64_t total = 0;
        bool fin = false;
        quic::Bytes reply;
        while (!fin) {
            auto chunk = co_await server->read(0, {.deadline = Clock::now() + 10s});
            check(chunk.has_value(), "server read failed");
            if (!chunk) co_return;
            require(server->consume(0, chunk->data.size()));
            total += chunk->data.size();
            fin = chunk->fin;
            reply.insert(reply.end(), chunk->data.begin(), chunk->data.end());
        }
        check(total == 200000, "server received a wrong number of bytes");
        require(co_await server->write(0, reply, true, {.deadline = Clock::now() + 10s}));

        // Keep pumping until the client closes the connection: destroying
        // the connection here would drop unacknowledged echo datagrams.
        while (!server->closed()) {
            auto round = co_await server->pump({.deadline = Clock::now() + 10s});
            if (!round) break;
        }
}

Task<void> client_side(EventLoop& loop, quic::Options& client_options,
                       std::unique_ptr<UdpConnection>& client) {
        auto connected =
            co_await UdpConnection::connect(loop, client_options, {.deadline = Clock::now() + 10s});
        if (!connected) throw std::runtime_error(std::string("client handshake failed: ") + connected.error().message() + " (" + std::to_string(connected.error().value()) + ")");
        if (!connected) co_return;
        client = std::make_unique<UdpConnection>(std::move(*connected));
        check(client->negotiated_protocol() == "h3", "client ALPN mismatch");

        const std::int64_t stream = require(client->open_stream());
        quic::Bytes payload(200000, std::byte{0x5a});
        payload[7] = std::byte{0};  // Binary safety: a zero in the middle.
        // FIN rides with the payload: the server echoes what it received
        // only after seeing the end of stream, so splitting them deadlocks.
        require(co_await client->write(stream, payload, true,
                                        {.deadline = Clock::now() + 10s}));

        std::uint64_t total = 0;
        bool fin = false;
        while (!fin) {
            auto chunk = co_await client->read(stream, {.deadline = Clock::now() + 10s});
            if (!chunk) throw std::runtime_error(std::string("client read failed: ") + chunk.error().message() + " (" + std::to_string(chunk.error().value()) + ")");
            if (!chunk) co_return;
            require(client->consume(stream, chunk->data.size()));
            check(std::all_of(chunk->data.begin(), chunk->data.end(),
                              [](std::byte b) { return b == std::byte{0x5a} || b == std::byte{0}; }),
                  "echoed data corrupted");
            total += chunk->data.size();
            fin = chunk->fin;
        }
        check(total == payload.size(), "client echoed byte count mismatch");
        require(co_await client->close(0, {.deadline = Clock::now() + 10s}));
}

Task<void> run(EventLoop& loop, const char* certificate, const char* key) {
    // Server: bind first so the client has somewhere to connect.
    auto server_socket =
        require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
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
    std::unique_ptr<UdpConnection> client;
    std::unique_ptr<UdpConnection> server;


    scope.spawn(server_side(server_socket, initial_buffer, initial,
                          server_options, server_address, server));
    scope.spawn(client_side(loop, client_options, client));
    co_await scope.join();
}

// Review-report Critical regression: silent peer + the caller's budget already expired.
//
// Behavior before the fix: do_pump treated every timed_out as "engine timer handled
// successfully", so read's for(;;) got no chunk and started another round, while the loop's
// submission of an already-expired deadline is rejected synchronously (without suspending) —
// the loop spun synchronously inside a single dispatch, starving posted work, timers, and
// other connections on the loop thread, with no diagnosis at all.
//
// Contract after the fix: caller budget expiry → the operation fails immediately with
// timed_out; only the engine's own timer expiry goes through handle_expiry to keep pumping.
Task<void> silent_peer_budget(EventLoop& loop, const char* certificate) {
    // A socket that receives our Initial and never answers: the black-hole peer.
    auto black_hole = transport::udp::Socket::bind(loop, Endpoint::loopback(0));
    if (!black_hole) throw std::runtime_error("black-hole socket bind failed");

    quic::Options options;
    options.local = Endpoint::loopback(0);
    options.remote = require(black_hole->local_endpoint());
    options.ca_file = certificate;  // the engine needs a loadable CA to build
    options.peer_name = "localhost";
    options.alpn = "h3";

    // A handshake against a silent peer must fail on its own budget — and it
    // must be the deadline path, not a spin.
    const auto handshake_began = Clock::now();
    auto connected =
        co_await UdpConnection::connect(loop, options, {.deadline = Clock::now() + 300ms});
    const auto handshake_elapsed = Clock::now() - handshake_began;
    check(!connected.has_value(), "silent peer unexpectedly completed the handshake");
    if (!connected.has_value()) {
        check(connected.error() == Errc::timed_out, "handshake failure code must be timed_out");
    }
    check(handshake_elapsed < 5s, "handshake timeout must return on time, not spin and hang");

    // Leave the loop healthy: the caller (main, outside any coroutine) checks
    // afterwards that posted work still runs, i.e. the failed pump released
    // the thread instead of spinning inside one dispatch.
    loop.post([] {});
}

struct DelayedDatagram {
    struct State {
        EventLoop* loop = nullptr;
        Clock::duration delay{};
        std::size_t sends = 0;
        std::size_t receives = 0;
    };
    static inline std::shared_ptr<State> next;
    std::shared_ptr<State> state;

    static Result<DelayedDatagram> bind(EventLoop& loop, const Endpoint&) {
        next->loop = &loop;
        return DelayedDatagram{next};
    }

    Task<Result<std::size_t>> send_to(std::span<const std::byte> bytes,
                                      const Endpoint&, OperationOptions io) {
        if (++state->sends == 1) require(co_await state->loop->sleep_for(state->delay, io));
        co_return bytes.size();
    }

    Task<Result<transport::udp::Datagram>> receive_from(std::span<std::byte>,
                                                       OperationOptions) {
        ++state->receives;
        co_return fail(Errc::cancelled);
    }
};

Task<void> expired_engine_timer(EventLoop& loop, const char* certificate) {
    quic::Options options;
    options.local = Endpoint::loopback(41000);
    options.remote = Endpoint::loopback(41001);
    options.ca_file = certificate;
    options.peer_name = "localhost";

    DelayedDatagram::next = std::make_shared<DelayedDatagram::State>();
    auto retransmit = DelayedDatagram::next;
    retransmit->delay = 1200ms;
    auto connected = co_await Connection<DelayedDatagram>::connect(loop, options);
    check(!connected && connected.error() == Errc::cancelled,
          "PTO regression must terminate at the fake receive");
    check(retransmit->sends >= 2 && retransmit->receives == 1,
          "expired PTO must retransmit before waiting for input");

    DelayedDatagram::next = std::make_shared<DelayedDatagram::State>();
    auto terminal = DelayedDatagram::next;
    terminal->delay = 3200ms;
    options.idle_timeout_ns = 1'000'000;
    connected = co_await Connection<DelayedDatagram>::connect(loop, options);
    check(!connected && connected.error().category() == quic::quic_error(0).category(),
          "expired idle timer must propagate the terminal engine error");
    check(terminal->receives == 0, "terminal expiry must not enter a datagram wait");
    DelayedDatagram::next.reset();
}

Task<void> accept_only(transport::udp::Socket socket, quic::Options options,
                       std::unique_ptr<UdpConnection>& connection, bool& client_ready) {
    std::array<std::byte, 65536> initial{};
    auto datagram = require(co_await socket.receive_from(initial, {.deadline = Clock::now() + 5s}));
    options.local = require(socket.local_endpoint());
    options.remote = datagram.peer;
    auto accepted = require(co_await UdpConnection::serve(
        std::move(socket), std::move(options),
        std::span<const std::byte>{initial.data(), datagram.size},
        {.deadline = Clock::now() + 5s}));
    connection = std::make_unique<UdpConnection>(std::move(accepted));
    // Server handshake completion can precede the peer receiving the final
    // handshake flight. Keep its retransmission timer alive until both finish.
    const auto deadline = Clock::now() + 5s;
    while (!client_ready) {
        auto round = co_await connection->pump({.deadline = std::min(deadline, Clock::now() + 10ms)});
        if (!round && round.error() != Errc::timed_out) require(std::move(round));
        check(Clock::now() < deadline, "client did not confirm handshake completion");
    }
}

Task<void> connect_only(EventLoop& loop, quic::Options options,
                        std::unique_ptr<UdpConnection>& connection, bool& client_ready) {
    auto connected = require(co_await UdpConnection::connect(
        loop, std::move(options), {.deadline = Clock::now() + 5s}));
    connection = std::make_unique<UdpConnection>(std::move(connected));
    client_ready = true;
}

Task<void> drain_input(UdpConnection& connection) {
    const auto deadline = Clock::now() + 30ms;
    for (;;) {
        auto round = co_await connection.pump({.deadline = deadline});
        if (!round) {
            check(round.error() == Errc::timed_out, "datagram drain failed");
            co_return;
        }
    }
}

Task<void> fixed_peer(EventLoop& loop, const char* certificate, const char* key,
                      bool target_server) {
    auto server_socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    const auto server_address = require(server_socket.local_endpoint());
    auto stranger = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    quic::Options client_options;
    client_options.local = Endpoint::loopback(0);
    client_options.remote = server_address;
    client_options.ca_file = certificate;
    client_options.peer_name = "localhost";
    quic::Options server_options;
    server_options.certificate_file = certificate;
    server_options.private_key_file = key;
    std::unique_ptr<UdpConnection> client;
    std::unique_ptr<UdpConnection> server;
    TaskScope scope;
    bool client_ready = false;
    scope.spawn(accept_only(std::move(server_socket), server_options, server, client_ready));
    scope.spawn(connect_only(loop, client_options, client, client_ready));
    co_await scope.join();
    TaskScope drain;
    drain.spawn(drain_input(*client));
    drain.spawn(drain_input(*server));
    co_await drain.join();

    auto& target = target_server ? *server : *client;
    auto& peer = target_server ? *client : *server;
    const auto target_address = require(target.transport()->local_endpoint());
    const std::array junk{std::byte{0xff}, std::byte{0x01}, std::byte{0x02}};
    require(co_await stranger.send_to(junk, target_address, {.deadline = Clock::now() + 1s}));
    co_await drain_input(target);
    check(!target.closed(), "stranger datagram must not poison the QUIC engine");
    require(co_await target.close(0, {.deadline = Clock::now() + 1s}));
    const auto close_deadline = Clock::now() + 1s;
    while (!peer.closed()) {
        auto round = co_await peer.pump({.deadline = close_deadline});
        if (!round) check(peer.closed(), "the original peer must receive CONNECTION_CLOSE");
    }
    std::array<std::byte, 2048> packet{};
    auto leaked = co_await stranger.receive_from(packet, {.deadline = Clock::now() + 30ms});
    check(!leaked && leaked.error() == Errc::timed_out,
          "stranger must not receive QUIC output after a forged source datagram");
}

}  // namespace

// Checkpoint: see test/timeout-expectations.md (review report C1 regression)
int main(int argc, char** argv) {
    if (argc < 3) return 2;
    auto loop = EventLoop::create();
    if (!loop) return 2;
    try {
        static_cast<void>(loop->run_until_complete(run(*loop, argv[1], argv[2])));
        static_cast<void>(loop->run_until_complete(silent_peer_budget(*loop, argv[1])));
        static_cast<void>(loop->run_until_complete(expired_engine_timer(*loop, argv[1])));
        static_cast<void>(loop->run_until_complete(fixed_peer(*loop, argv[1], argv[2], true)));
        static_cast<void>(loop->run_until_complete(fixed_peer(*loop, argv[1], argv[2], false)));

        // Outside any coroutine it is legal to drive the loop again; if the
        // failed pump had spun, we would never get here (run_until_complete
        // would still be inside it) and this posted work would never run.
        bool posted_ran = false;
        loop->post([&posted_ran] { posted_ran = true; });
        check(loop->run_once(100ms).has_value(), "loop is still runnable");
        check(posted_ran, "posted work was starved");

        std::cout << "QUIC over UDP loopback: handshake, 200KB streams, flow control, close, caller budget, expired timers, and fixed peers passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
