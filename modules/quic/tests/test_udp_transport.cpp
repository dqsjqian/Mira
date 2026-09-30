// QUIC over a real UDP loopback: the engine's in-memory datagram tests are
// replaced by an actual socket pair for this round. Same certificates, same
// payload discipline — but the packets now traverse the kernel's UDP stack
// and the event loop's datagram operations.

#include "mira/core/task_scope.hpp"
#include "mira/quic/connection.hpp"
#include "mira/quic/listener.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <source_location>
#include <stop_token>
#include <utility>

using namespace Mira;
using namespace std::chrono_literals;
using transport::Endpoint;
using quic::Connection;
using UdpConnection = Connection<transport::udp::Socket>;

namespace {

template<class T>
T require(Result<T> value, std::source_location location = std::source_location::current()) {
    if (!value)
        throw std::runtime_error(value.error().message() + " (" +
                                 std::to_string(value.error().value()) + ") at line " +
                                 std::to_string(location.line()));
    return std::move(*value);
}

void require(Result<void> value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error(value.error().message() + " at line " +
                                         std::to_string(location.line()));
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
                       std::unique_ptr<UdpConnection>& connection, bool& client_ready,
                       bool& server_ready) {
    std::array<std::byte, 65536> initial{};
    auto datagram = require(co_await socket.receive_from(initial, {.deadline = Clock::now() + 5s}));
    options.local = require(socket.local_endpoint());
    options.remote = datagram.peer;
    auto accepted = require(co_await UdpConnection::serve(
        std::move(socket), std::move(options),
        std::span<const std::byte>{initial.data(), datagram.size},
        {.deadline = Clock::now() + 5s}));
    connection = std::make_unique<UdpConnection>(std::move(accepted));
    server_ready = true;
    // Server handshake completion can precede the peer receiving the final
    // handshake flight. Keep its retransmission timer alive until both finish.
    const auto deadline = Clock::now() + 5s;
    while (!client_ready) {
        auto round = co_await connection->pump({.deadline = std::min(deadline, Clock::now() + 10ms)});
        if (!round && round.error() != Errc::timed_out) require(std::move(round));
        check(Clock::now() < deadline, "client did not confirm handshake completion");
    }
}

template<class Datagram>
Task<void> connect_only(EventLoop& loop, quic::Options options,
                        std::unique_ptr<Connection<Datagram>>& connection, bool& client_ready,
                        bool& server_ready) {
    auto connected = require(co_await Connection<Datagram>::connect(
        loop, std::move(options), {.deadline = Clock::now() + 5s}));
    connection = std::make_unique<Connection<Datagram>>(std::move(connected));
    client_ready = true;
    // Local cryptographic completion does not mean the peer received our
    // Finished flight. Keep handling its retransmissions and our PTO/pacing
    // until the server completes too; otherwise joining the pair can deadlock.
    const auto deadline = Clock::now() + 5s;
    while (!server_ready) {
        auto round = co_await connection->pump({.deadline = std::min(deadline, Clock::now() + 10ms)});
        if (!round && round.error() != Errc::timed_out) require(std::move(round));
        check(Clock::now() < deadline, "server did not confirm handshake completion");
    }
}

template<class Datagram>
Task<void> drain_input(Connection<Datagram>& connection) {
    const auto deadline = Clock::now() + 30ms;
    for (;;) {
        auto round = co_await connection.pump({.deadline = deadline});
        if (!round) {
            check(round.error() == Errc::timed_out, "datagram drain failed");
            co_return;
        }
    }
}

// Fail after the engine has committed its packet, before it reaches the OS.
// Continuing to pump must recover through QUIC retransmission without asking
// the application to submit its payload a second time.
struct FaultDatagram {
    enum class Fault { none, cancelled, timed_out, short_send };
    struct State {
        EventLoop* loop = nullptr;
        Fault fault = Fault::none;
        std::size_t failures = 0;
        const bool* release_handshake = nullptr;
        std::size_t handshake_drops = 0;
    };
    static inline std::shared_ptr<State> next;
    transport::udp::Socket socket;
    std::shared_ptr<State> state;

    static Result<FaultDatagram> bind(EventLoop& loop, const Endpoint& endpoint) {
        auto socket = transport::udp::Socket::bind(loop, endpoint);
        if (!socket) return fail(socket.error());
        next->loop = &loop;
        return FaultDatagram{std::move(*socket), next};
    }
    Result<Endpoint> local_endpoint() const { return socket.local_endpoint(); }
    static bool contains_handshake(std::span<const std::byte> bytes) {
        // QUIC can coalesce Initial and Handshake packets into one datagram.
        // Walk the public long-header lengths, without inspecting ciphertext.
        std::size_t offset = 0;
        const auto skip = [&](std::uint64_t count) {
            if (count > bytes.size() - offset) return false;
            offset += static_cast<std::size_t>(count);
            return true;
        };
        const auto varint = [&]() -> std::optional<std::uint64_t> {
            if (offset == bytes.size()) return std::nullopt;
            const auto first = std::to_integer<unsigned>(bytes[offset]);
            const auto size = std::size_t{1} << (first >> 6);
            if (size > bytes.size() - offset) return std::nullopt;
            std::uint64_t value = first & 0x3fu;
            for (std::size_t i = 1; i < size; ++i)
                value = (value << 8) | std::to_integer<unsigned>(bytes[offset + i]);
            offset += size;
            return value;
        };
        while (bytes.size() - offset >= 5) {
            const auto tag = std::to_integer<unsigned>(bytes[offset]);
            if ((tag & 0x80u) == 0 || bytes[offset + 1] != std::byte{0} ||
                bytes[offset + 2] != std::byte{0} || bytes[offset + 3] != std::byte{0} ||
                bytes[offset + 4] != std::byte{1}) return false;
            const auto type = (tag >> 4) & 3u;
            if (type == 2) return true;
            if (type == 3 || !skip(5)) return false;  // Retry has no length field.
            for (int cid = 0; cid < 2; ++cid) {
                if (offset == bytes.size()) return false;
                const auto size = std::to_integer<unsigned>(bytes[offset++]);
                if (!skip(size)) return false;
            }
            if (type == 0) {
                const auto token = varint();
                if (!token || !skip(*token)) return false;
            }
            const auto length = varint();
            if (!length || !skip(*length)) return false;
        }
        return false;
    }
    Task<Result<std::size_t>> send_to(std::span<const std::byte> bytes,
                                     const Endpoint& peer, OperationOptions io) {
        // QUIC v1 long-header type 0b10 is Handshake. Drop the whole flight
        // before connect() returns, including any ACK-only datagrams before
        // Finished. The client's ready flag then releases retransmissions.
        if (state->release_handshake && !*state->release_handshake && contains_handshake(bytes)) {
            ++state->handshake_drops;
            co_return bytes.size();
        }
        const auto fault = std::exchange(state->fault, Fault::none);
        if (fault != Fault::none) {
            ++state->failures;
            // Force time to advance between packet construction and failure.
            auto paused = co_await state->loop->sleep_for(40ms, io);
            if (!paused) co_return fail(paused.error());
            if (fault == Fault::cancelled) co_return fail(Errc::cancelled);
            if (fault == Fault::timed_out) co_return fail(Errc::timed_out);
            co_return bytes.size() - 1;
        }
        co_return co_await socket.send_to(bytes, peer, io);
    }
    Task<Result<transport::udp::Datagram>> receive_from(std::span<std::byte> bytes,
                                                       OperationOptions io) {
        co_return co_await socket.receive_from(bytes, io);
    }
};

Task<void> fault_echo(UdpConnection& server, std::int64_t id, const quic::Bytes& expected,
                       bool& client_done) {
    const auto deadline = Clock::now() + 2s;
    quic::Bytes received;
    bool fin = false;
    while (!fin) {
        auto chunk = require(co_await server.read(id, {.deadline = deadline}));
        received.insert(received.end(), chunk.data.begin(), chunk.data.end());
        require(server.consume(id, chunk.data.size()));
        fin = chunk.fin;
    }
    check(received == expected, "failed datagram send lost or duplicated stream bytes");
    require(co_await server.write(id, received, true, {.deadline = deadline}));
    while (!client_done) {
        auto round = co_await server.pump({.deadline = std::min(deadline, Clock::now() + 10ms)});
        if (!round && round.error() != Errc::timed_out) require(std::move(round));
        check(Clock::now() < deadline, "client did not complete after failed send recovery");
    }
}

Task<void> fault_reply(Connection<FaultDatagram>& client, std::int64_t id,
                       const quic::Bytes& expected, bool& done) {
    const auto deadline = Clock::now() + 2s;
    quic::Bytes reply;
    bool fin = false;
    while (!fin) {
        auto chunk = require(co_await client.read(id, {.deadline = deadline}));
        reply.insert(reply.end(), chunk.data.begin(), chunk.data.end());
        require(client.consume(id, chunk.data.size()));
        fin = chunk.fin;
    }
    check(reply == expected, "failed send recovery changed the echoed stream");
    done = true;
}

Task<void> failed_send_recovery(EventLoop& loop, const char* certificate, const char* key) {
    auto socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    quic::Options co, so;
    co.local = Endpoint::loopback(0); co.remote = require(socket.local_endpoint());
    co.ca_file = certificate; co.peer_name = "localhost";
    so.certificate_file = certificate; so.private_key_file = key;
    FaultDatagram::next = std::make_shared<FaultDatagram::State>();
    auto faults = FaultDatagram::next;
    std::unique_ptr<Connection<FaultDatagram>> client;
    std::unique_ptr<UdpConnection> server;
    bool ready = false, server_ready = false;
    TaskScope handshake;
    handshake.spawn(accept_only(std::move(socket), so, server, ready, server_ready));
    handshake.spawn(connect_only(loop, co, client, ready, server_ready));
    co_await handshake.join();
    for (const auto fault : {FaultDatagram::Fault::cancelled, FaultDatagram::Fault::timed_out,
                             FaultDatagram::Fault::short_send}) {
        TaskScope settle;
        settle.spawn(drain_input(*client)); settle.spawn(drain_input(*server));
        co_await settle.join();
        const auto id = require(client->open_stream());
        const quic::Bytes payload(512, std::byte{0x6b});
        faults->fault = fault;
        auto written = co_await client->write(id, payload, true, {.deadline = Clock::now() + 2s});
        const auto expected = fault == FaultDatagram::Fault::cancelled ? make_error_code(Errc::cancelled) :
            fault == FaultDatagram::Fault::timed_out ? make_error_code(Errc::timed_out) :
            std::make_error_code(std::errc::io_error);
        check(!written && written.error() == expected, "datagram send failure was hidden");
        check(!client->closed(), "recoverable datagram send failure closed the connection");
        bool done = false;
        TaskScope exchange;
        exchange.spawn(fault_echo(*server, id, payload, done));
        exchange.spawn(fault_reply(*client, id, payload, done));
        co_await exchange.join();
    }
    check(faults->failures == 3, "datagram send fault injection did not run");
    FaultDatagram::next.reset();
}

Task<void> lost_client_handshake(EventLoop& loop, const char* certificate, const char* key) {
    const std::array initial{std::byte{0xc0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0}};
    quic::Bytes coalesced(initial.begin(), initial.end());
    coalesced.insert(coalesced.end(), {std::byte{0xe0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}});
    check(!FaultDatagram::contains_handshake(initial) && FaultDatagram::contains_handshake(coalesced),
          "handshake fault matcher missed a coalesced packet");
    auto socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    quic::Options co, so;
    co.local = Endpoint::loopback(0); co.remote = require(socket.local_endpoint());
    co.ca_file = certificate; co.peer_name = "localhost";
    so.certificate_file = certificate; so.private_key_file = key;
    FaultDatagram::next = std::make_shared<FaultDatagram::State>();
    auto faults = FaultDatagram::next;
    std::unique_ptr<Connection<FaultDatagram>> client;
    std::unique_ptr<UdpConnection> server;
    bool client_ready = false, server_ready = false;
    faults->release_handshake = &client_ready;
    TaskScope handshake;
    handshake.spawn(accept_only(std::move(socket), so, server, client_ready, server_ready));
    handshake.spawn(connect_only(loop, co, client, client_ready, server_ready));
    co_await handshake.join();
    check(faults->handshake_drops != 0, "client handshake flight loss was not injected");
    check(client_ready && server_ready && client->handshake_complete() && server->handshake_complete(),
          "lost client handshake flight prevented the peer completing");
    const auto id = require(client->open_stream());
    const quic::Bytes payload(512, std::byte{0x71});
    require(co_await client->write(id, payload, true));
    bool done = false;
    TaskScope exchange;
    exchange.spawn(fault_echo(*server, id, payload, done));
    exchange.spawn(fault_reply(*client, id, payload, done));
    co_await exchange.join();
    FaultDatagram::next.reset();
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
    bool client_ready = false, server_ready = false;
    scope.spawn(accept_only(std::move(server_socket), server_options, server, client_ready, server_ready));
    scope.spawn(connect_only(loop, client_options, client, client_ready, server_ready));
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

Task<void> buffered_reads_and_queue_limit(EventLoop& loop, const char* certificate, const char* key) {
    auto socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    quic::Options co, so;
    co.local = Endpoint::loopback(0); co.remote = require(socket.local_endpoint());
    co.ca_file = certificate; co.peer_name = "localhost";
    so.certificate_file = certificate; so.private_key_file = key;
    std::unique_ptr<UdpConnection> client, server;
    bool ready = false, server_ready = false;
    TaskScope scope;
    scope.spawn(accept_only(std::move(socket), so, server, ready, server_ready));
    scope.spawn(connect_only(loop, co, client, ready, server_ready));
    co_await scope.join();
    const auto id = require(client->open_stream());
    const quic::Bytes request(1, std::byte{'q'}), reply(3, std::byte{'r'});
    require(co_await client->write(id, request, true));
    const auto request_chunk = require(co_await server->read(id, {.deadline = Clock::now() + 2s}));
    require(server->consume(id, request_chunk.data.size()));
    require(co_await server->write(id, reply, true));
    TaskScope settle;
    settle.spawn(drain_input(*client)); settle.spawn(drain_input(*server));
    co_await settle.join();
    std::stop_source stopped; stopped.request_stop();
    auto cancelled = co_await client->read(id, {.stop = stopped.get_token()});
    check(!cancelled && cancelled.error() == Errc::cancelled, "buffered read ignored cancellation");
    auto expired = co_await client->read(id, {.deadline = Clock::now() - 1ms});
    check(!expired && expired.error() == Errc::timed_out, "buffered read ignored expired deadline");
    const auto chunk = require(co_await client->read(id, {.deadline = Clock::now() + 10ms}));
    check(chunk.data == reply && chunk.fin, "ACK or failed flush lost already-buffered data");
    require(client->consume(id, chunk.data.size()));

    // Empty FIN streams consume no byte budget; their unread terminal records
    // still have to hit the adapter's connection-wide event budget.
    bool overflow = false;
    int opened = 0;
    for (int n = 0; n < 10000 && !overflow && opened < 4097; ++n) {
        auto stream = client->open_stream(true);
        if (stream) {
            ++opened;
            require(co_await client->write(*stream, {}, true));
        }
        auto received = co_await server->pump({.deadline = Clock::now() + 2ms});
        if (!received) {
            if (received.error() == Errc::limit_exceeded) { overflow = true; break; }
            check(received.error() == Errc::timed_out, "empty-stream churn receive failed");
        }
        auto acknowledged = co_await client->pump({.deadline = Clock::now() + 2ms});
        if (!acknowledged) check(acknowledged.error() == Errc::timed_out, "empty-stream churn ACK failed");
    }
    if (!overflow || !server->closed())
        throw std::runtime_error("empty FIN churn bypassed raw Connection event budget, streams=" + std::to_string(opened));
    const auto terminal = co_await server->read(2);
    check(!terminal && terminal.error() == Errc::limit_exceeded, "raw queue overflow did not stay terminal");
    const auto new_stream = server->open_stream();
    check(!new_stream && new_stream.error() == Errc::limit_exceeded,
          "terminal raw queue overflow admitted another stream");
    const auto new_write = co_await server->write(1, reply, true);
    check(!new_write && new_write.error() == Errc::limit_exceeded,
          "terminal raw queue overflow did not reject writes before engine mutation");
}

Task<void> migration_udp(EventLoop& loop, const char* certificate, const char* key, bool active) {
    auto server_socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    auto old_socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    auto new_socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    auto attacker = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)));
    const auto server_address = require(server_socket.local_endpoint());
    const auto old_address = require(old_socket.local_endpoint());
    const auto new_address = require(new_socket.local_endpoint());
    const auto attacker_address = require(attacker.local_endpoint());
    quic::Options co;
    co.local = old_address;
    co.remote = server_address;
    co.ca_file = certificate;
    co.peer_name = "localhost";
    co.migration = quic::MigrationPolicy::validated;
    auto so = co;
    so.local = server_address;
    so.certificate_file = certificate;
    so.private_key_file = key;
    auto listener = require(quic::Listener::create(so));
    auto client = require(quic::Engine::client(co, quic::detail::now_ns()));
    std::array<std::byte, 65536> buffer{};
    bool rebound = false;
    quic::Listener::Id id = 0;
    const auto deadline = Clock::now() + 10s;
    auto round = [&]() -> Task<void> {
        auto now = quic::detail::now_ns();
        if (client.expiry() <= now) require(client.handle_expiry(now));
        require(listener.handle_expiry(now));
        for (int n = 0; n < 32; ++n) {
            auto packet = require(client.poll_datagram(quic::detail::now_ns()));
            if (packet.data.empty()) break;
            auto& socket = (rebound || packet.path.local == new_address) ? new_socket : old_socket;
            require(co_await socket.send_to(packet.data, packet.path.remote, {.deadline = deadline}));
            const auto incoming = require(co_await server_socket.receive_from(buffer, {.deadline = deadline}));
            auto ingested = require(listener.ingest(incoming.peer,
                {buffer.data(), incoming.size}, quic::detail::now_ns()));
            if (!id) id = ingested.connection_id;
        }
        for (int n = 0; n < 32; ++n) {
            auto packet = require(listener.poll(quic::detail::now_ns()));
            if (!packet) break;
            check(packet->connection_id == id && packet->local == server_address,
                  "migration output changed CID/local route");
            check(packet->peer == old_address || packet->peer == new_address,
                  "migration output reflected to wrong source");
            require(co_await server_socket.send_to(packet->data, packet->peer, {.deadline = deadline}));
            auto& socket = packet->peer == new_address ? new_socket : old_socket;
            const auto incoming = require(co_await socket.receive_from(buffer, {.deadline = deadline}));
            const auto local = active ? packet->peer : old_address;
            require(client.receive({local, incoming.peer}, {buffer.data(), incoming.size},
                                   quic::detail::now_ns()));
        }
        require(co_await loop.sleep_for(1ms, {.deadline = deadline}));
    };
    for (int n = 0; n < 100; ++n) co_await round();
    check(client.handshake_complete() && listener.connection(id)->handshake_complete(),
          "migration handshake did not complete");
    check(!client.poll(quic::detail::now_ns()), "migration accepted pathless output");
    if (active) require(client.initiate_migration({new_address, server_address}, quic::detail::now_ns()));
    else rebound = true;
    const auto stream = require(client.open_stream());
    quic::Bytes payload(12000, std::byte{0x73});
    require(client.write(stream, payload, true));
    std::size_t total = 0;
    bool fin = false;
    for (int n = 0; n < 5000; ++n) {
        co_await round();
        auto* server = listener.connection(id);
        check(server, "migration lost CID association");
        for (auto& event : server->take_events()) {
            if (event.kind != quic::Event::Kind::data) continue;
            total += event.data.size();
            fin |= event.fin;
            require(server->consume(event.stream_id, event.data.size()));
        }
        if (fin && server->validated_path().remote == new_address &&
            (!active || client.validated_path().local == new_address)) break;
    }
    auto* server = listener.connection(id);
    check(total == payload.size() && fin && server->validated_path().remote == new_address,
          "real UDP path validation/NAT rebinding failed");
    require(server->write(stream, payload, true));
    total = 0;
    fin = false;
    for (int n = 0; n < 5000 && !fin; ++n) {
        co_await round();
        for (auto& event : client.take_events()) {
            if (event.kind != quic::Event::Kind::data) continue;
            total += event.data.size();
            fin |= event.fin;
            require(client.consume(event.stream_id, event.data.size()));
        }
    }
    check(total == payload.size() && fin, "migrated response did not reach validated endpoint");
    auto ids = server->local_connection_ids();
    quic::Bytes forged(1200, std::byte{0x42});
    std::copy(ids.front().begin(), ids.front().end(), forged.begin() + 1);
    require(co_await attacker.send_to(forged, server_address, {.deadline = deadline}));
    auto bad = require(co_await server_socket.receive_from(buffer, {.deadline = deadline}));
    require(listener.ingest(bad.peer, {buffer.data(), bad.size}, quic::detail::now_ns()));
    check(server->validated_path().remote == new_address && !server->closed(),
          "forged CID source poisoned validated connection");
    // A -> B -> A can reuse ngtcp2's validated-path history without another
    // success callback. Both the engine view and listener close route must
    // still follow the active authenticated path.
    if (active) require(client.initiate_migration({old_address, server_address}, quic::detail::now_ns()));
    else rebound = false;
    const auto returned = require(client.open_stream());
    require(client.write(returned, payload, true));
    total = 0;
    fin = false;
    for (int n = 0; n < 5000; ++n) {
        co_await round();
        for (auto& event : server->take_events()) {
            if (event.kind != quic::Event::Kind::data || event.stream_id != returned) continue;
            total += event.data.size();
            fin |= event.fin;
            require(server->consume(event.stream_id, event.data.size()));
        }
        if (fin && server->validated_path().remote == old_address &&
            (!active || client.validated_path().local == old_address)) break;
    }
    if (total != payload.size() || !fin || server->validated_path().remote != old_address)
        throw std::runtime_error("historical path failed: active=" + std::to_string(active) +
            " bytes=" + std::to_string(total) + " fin=" + std::to_string(fin) +
            " server validated=" + std::to_string(server->validated_path().remote.port()) +
            " server active=" + std::to_string(server->active_path().remote.port()) +
            " server pending=" + std::to_string(server->path_validation_pending()) +
            " client active=" + std::to_string(client.active_path().local.port()) +
            " client validated=" + std::to_string(client.validated_path().local.port()) +
            " old=" + std::to_string(old_address.port()) + " new=" + std::to_string(new_address.port()));
    check(!active || client.validated_path().local == old_address,
          "return to historical path left stale validated client endpoint");
    auto close = require(listener.close(id, 0, quic::detail::now_ns()));
    check(close.peer == old_address && !close.data.empty() && listener.tombstone_count() == 1,
          "migrated closing lost validated peer or tombstone");
    auto discarded = require(listener.ingest(attacker_address, forged, quic::detail::now_ns()));
    check(discarded.kind == quic::Listener::Ingest::Kind::dropped,
          "closing accepted spoofed source");
    std::array<std::byte, 2048> junk{};
    auto leaked = co_await attacker.receive_from(junk, {.deadline = Clock::now() + 20ms});
    check(!leaked && leaked.error() == Errc::timed_out, "attacker received migrated payload");
}

}  // namespace

// Checkpoint: see test/timeout-expectations.md (review report C1 regression)
int main(int argc, char** argv) {
    if (argc < 3) return 2;
    auto loop = EventLoop::create();
    if (!loop) return 2;
    const char* phase = "active migration and return";
    try {
        static_cast<void>(loop->run_until_complete(migration_udp(*loop, argv[1], argv[2], true)));
        phase = "NAT rebinding and return";
        static_cast<void>(loop->run_until_complete(migration_udp(*loop, argv[1], argv[2], false)));
        phase = "200KB bidirectional transfer";
        static_cast<void>(loop->run_until_complete(run(*loop, argv[1], argv[2])));
        phase = "buffered reads and empty-stream event budget";
        static_cast<void>(loop->run_until_complete(buffered_reads_and_queue_limit(*loop, argv[1], argv[2])));
        phase = "failed sends and delayed scheduling";
        static_cast<void>(loop->run_until_complete(failed_send_recovery(*loop, argv[1], argv[2])));
        phase = "lost final client handshake flight";
        static_cast<void>(loop->run_until_complete(lost_client_handshake(*loop, argv[1], argv[2])));
        phase = "silent peer deadline";
        static_cast<void>(loop->run_until_complete(silent_peer_budget(*loop, argv[1])));
        phase = "expired engine timers";
        static_cast<void>(loop->run_until_complete(expired_engine_timer(*loop, argv[1])));
        phase = "fixed server peer";
        static_cast<void>(loop->run_until_complete(fixed_peer(*loop, argv[1], argv[2], true)));
        phase = "fixed client peer";
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
        std::cerr << phase << ": " << error.what() << '\n';
        return 1;
    }
}
