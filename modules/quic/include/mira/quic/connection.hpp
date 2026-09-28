#pragma once

// Mira/quic/connection.hpp — QUIC over a real datagram transport.
//
// The Engine (engine.hpp) is deliberately I/O-free: bytes in, bytes out, a
// monotonic clock. This header is the glue that binds it to a datagram
// transport such as udp::Socket and the EventLoop's timers, following the
// same explicit-pump model as http2::Connection: nothing runs in the
// background, the caller drives progress. One pump at a time; concurrent
// streams multiplex through the shared session state.

#include "mira/core/error.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task.hpp"
#include "mira/quic/engine.hpp"
#include "mira/transport/datagram.hpp"
#include "mira/transport/endpoint.hpp"
#include "mira/transport/udp.hpp"

#include <array>
#include <chrono>
#include <limits>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <span>
#include <utility>

namespace Mira::quic {

/// One chunk of received stream data, with the remote's FIN when it arrives.
struct StreamChunk {
    Bytes data;
    bool fin = false;
    /// Set when the stream ended via RESET_STREAM instead of a clean FIN;
    /// `error_code` then carries the application error the peer sent.
    bool reset = false;
    std::uint64_t error_code = 0;
};

/// A single QUIC connection over a datagram transport.
///
/// Owns the transport and the engine; one connection per socket. The server
/// side takes over the socket that received the Initial packet (a QUIC
/// listener routes by connection ID — one socket serves many clients; this
/// class is one connection, not a multiplexer).
///
/// Operations are driven explicitly: `pump` performs one bounded round —
/// flush pending output, then wait for the next inbound datagram or timer
/// expiry, whichever comes first. `read` pumps until the stream produces.
/// Operations must not overlap; nothing here runs in the background.
template<transport::DatagramTransport Transport>
class Connection {
public:
    Connection(Connection&&) noexcept = default;
    Connection& operator=(Connection&&) noexcept = default;
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    /// Client: bind the transport locally and drive the handshake to
    /// completion (or the first failure). `options.remote` is the server.
    [[nodiscard]] static Task<Result<Connection>>
    connect(EventLoop& loop, Options options, OperationOptions io = {}) {
        const transport::Endpoint remote = options.remote;
        auto bound = Transport::bind(loop, options.local);
        if (!bound) co_return fail(bound.error());
        auto engine = Engine::client(std::move(options), detail::now_ns());
        if (!engine) co_return fail(engine.error());
        Connection connection{std::move(*bound), std::move(*engine)};
        connection.remote_ = remote;
        auto handshake = co_await connection.pump_until(
            [&](const Connection& self) { return self.engine_->handshake_complete(); }, io);
        if (!handshake) co_return fail(handshake.error());
        co_return std::move(connection);
    }

    /// Server: take over the transport that received the Initial datagram.
    /// The datagram is consumed by Engine::accept exactly as in the tests.
    [[nodiscard]] static Task<Result<Connection>> serve(Transport transport,
                                                        Options options,
                                                        std::span<const std::byte> initial,
                                                        OperationOptions io = {}) {
        // The remote is part of the options: whoever sent the Initial.
        const transport::Endpoint remote = options.remote;
        auto engine = Engine::accept(std::move(options), initial, detail::now_ns());
        if (!engine) co_return fail(engine.error());
        Connection connection{std::move(transport), std::move(*engine)};
        connection.remote_ = remote;
        auto handshake = co_await connection.pump_until(
            [&](const Connection& self) { return self.engine_->handshake_complete(); }, io);
        if (!handshake) co_return fail(handshake.error());
        co_return std::move(connection);
    }

    /// Flush pending output, then process one inbound datagram or one timer
    /// expiry, whichever arrives first. Returns when that round is done.
    [[nodiscard]] Task<Result<void>> pump(OperationOptions io = {}) {
        if (!engine_ || !transport_) co_return fail(Errc::invalid_argument);
        if (pumping_) co_return fail(Errc::invalid_argument);
        pumping_ = true;
        const PumpGuard guard{pumping_};
        auto round = co_await do_pump(io);
        if (!round) co_return fail(round.error());
        co_return Result<void>{};
    }

    /// Write up to the engine's buffered-send budget, then flush what it
    /// produced. Blocks only for the outgoing datagrams of this round.
    [[nodiscard]] Task<Result<void>>
    write(std::int64_t stream, std::span<const std::byte> bytes, bool fin,
          OperationOptions io = {}) {
        if (!engine_) co_return fail(Errc::invalid_argument);
        auto written = engine_->write(stream, bytes, fin);
        if (!written) co_return fail(written.error());
        auto flushed = co_await flush(io);
        if (!flushed) co_return fail(flushed.error());
        co_return Result<void>{};
    }

    /// Open a stream (client: bidi or uni).
    [[nodiscard]] Result<std::int64_t> open_stream(bool unidirectional = false) {
        if (!engine_) return fail(Errc::invalid_argument);
        return engine_->open_stream(unidirectional);
    }

    /// Drive until the stream yields its next chunk. An empty `data` with
    /// `fin` is the clean end; `reset` carries the peer's application error.
    [[nodiscard]] Task<Result<StreamChunk>> read(std::int64_t stream, OperationOptions io = {}) {
        if (!engine_) co_return fail(Errc::invalid_argument);
        if (pumping_) co_return fail(Errc::invalid_argument);
        pumping_ = true;
        const PumpGuard guard{pumping_};
        for (;;) {
            if (auto chunk = take_chunk(stream); chunk) {
                // Flush before returning: ngtcp2 may hold a pending ACK or a
                // flow-control update from the caller's consume(). Holding it
                // until the next pump stalls the peer for a full deadline.
                auto flushed = co_await flush(io);
                if (!flushed) co_return fail(flushed.error());
                co_return std::move(*chunk);
            }
            auto round = co_await do_pump(io);
            if (!round) co_return fail(round.error());
        }
    }

    /// Stop the stream, notifying the peer with an application error code.
    [[nodiscard]] Result<void> cancel(std::int64_t stream, std::uint64_t application_error) {
        if (!engine_) return fail(Errc::invalid_argument);
        return engine_->cancel(stream, application_error);
    }

    /// Give the engine flow-control credit after consuming received bytes.
    [[nodiscard]] Result<void> consume(std::int64_t stream, std::size_t bytes) {
        if (!engine_) return fail(Errc::invalid_argument);
        return engine_->consume(stream, bytes);
    }

    /// Send the connection close and drain what the engine still wants to
    /// emit. The transport closes with the connection.
    [[nodiscard]] Task<Result<void>>
    close(std::uint64_t application_error, OperationOptions io = {}) {
        if (!engine_ || !transport_) co_return fail(Errc::invalid_argument);
        auto last = engine_->close(application_error, detail::now_ns());
        if (!last) co_return fail(last.error());
        if (!last->empty()) {
            auto sent = co_await transport_->send_to(std::span<const std::byte>{last->data(),
                                                                                 last->size()},
                                                     remote_, io);
            if (!sent) co_return fail(sent.error());
            if (*sent != last->size()) {
                co_return fail(std::make_error_code(std::errc::io_error));
            }
        }
        co_return Result<void>{};
    }

    [[nodiscard]] bool handshake_complete() const noexcept {
        return engine_ && engine_->handshake_complete();
    }
    [[nodiscard]] std::string negotiated_protocol() const {
        return engine_ ? engine_->negotiated_protocol() : std::string{};
    }
    [[nodiscard]] bool closed() const noexcept { return !engine_ || engine_->closed(); }
    [[nodiscard]] const Transport* transport() const noexcept { return transport_.get(); }

private:
    struct PumpGuard {
        bool& pumping;
        ~PumpGuard() { pumping = false; }
    };

    Connection(Transport transport, Engine engine)
        : transport_(std::make_unique<Transport>(std::move(transport))),
          engine_(std::make_unique<Engine>(std::move(engine))) {}

    /// Take the next buffered chunk for a stream, or nullopt when more
    /// pumping is needed.
    std::optional<StreamChunk> take_chunk(std::int64_t stream) {
        auto it = buffers_.find(stream);
        if (it == buffers_.end() || it->second.empty()) return std::nullopt;
        StreamChunk chunk;
        const Event& front = it->second.front();
        if (front.kind == Event::Kind::data) {
            chunk.data = std::move(front.data);
            chunk.fin = front.fin;
            it->second.pop_front();
            if (it->second.empty()) buffers_.erase(it);
        } else if (front.kind == Event::Kind::reset) {
            chunk.reset = true;
            chunk.error_code = front.value;
            it->second.pop_front();
            if (it->second.empty()) buffers_.erase(it);
        } else if (front.kind == Event::Kind::closed) {
            chunk.fin = true;
            it->second.pop_front();
            if (it->second.empty()) buffers_.erase(it);
        } else {
            it->second.pop_front();  // acknowledged: not interesting to readers
            if (it->second.empty()) buffers_.erase(it);
            return std::nullopt;
        }
        return chunk;
    }

    /// Send everything the engine currently wants to send.
    Task<Result<void>> flush(OperationOptions io) {
        for (std::size_t round = 0; round < 64; ++round) {
            auto packet = engine_->poll(detail::now_ns());
            if (!packet) co_return fail(packet.error());
            if (packet->empty()) break;
            auto sent = co_await transport_->send_to(
                std::span<const std::byte>{packet->data(), packet->size()}, remote_, io);
            if (!sent) co_return fail(sent.error());
            if (*sent != packet->size()) {
                co_return fail(std::make_error_code(std::errc::io_error));
            }
        }
        co_return Result<void>{};
    }

    /// One round: flush output, then wait for the next datagram or the
    /// engine's next timer deadline, and feed whichever arrives.
    Task<Result<void>> do_pump(OperationOptions io) {
        if (engine_->closed()) co_return fail(Errc::eof);
        auto flushed = co_await flush(io);
        if (!flushed) co_return fail(flushed.error());

        collect_events();
        if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (io.deadline && *io.deadline <= EventLoop::Clock::now()) {
            co_return fail(Errc::timed_out);
        }

        const std::uint64_t now = detail::now_ns();
        OperationOptions wait = io;
        // NGTCP2_INFINITY means "no timer armed"; a time_point built from it
        // would overflow the loop's millisecond conversion and turn the
        // receive into an immediate-timeout spin. Only clamp to real timers.
        bool engine_timer_armed = false;
        if (const std::uint64_t expiry = engine_->expiry();
            expiry != std::numeric_limits<std::uint64_t>::max()) {
            if (expiry <= now) {
                auto handled = engine_->handle_expiry(now);
                if (!handled) co_return fail(handled.error());
                if (engine_->closed()) co_return fail(Errc::eof);
                collect_events();
                co_return co_await flush(io);
            }
            const auto deadline =
                EventLoop::Clock::time_point{std::chrono::nanoseconds{expiry}};
            if (!wait.deadline || deadline < *wait.deadline) {
                wait.deadline = deadline;
                engine_timer_armed = true;
            }
        }

        std::array<std::byte, detail::kMaxDatagram> buffer{};
        auto received = co_await transport_->receive_from(buffer, wait);
        if (!received) {
            if (received.error() == Errc::timed_out) {
                if (!engine_timer_armed ||
                    (io.deadline && *io.deadline <= EventLoop::Clock::now())) {
                    co_return fail(Errc::timed_out);
                }
                if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
                if (auto handled = engine_->handle_expiry(detail::now_ns()); !handled) {
                    co_return fail(handled.error());
                }
                if (engine_->closed()) co_return fail(Errc::eof);
                collect_events();
                auto after = co_await flush(io);
                if (!after) co_return fail(after.error());
                co_return Result<void>{};
            }
            co_return fail(received.error());
        }

        if (!(received->peer == remote_)) {
            co_return Result<void>{};
        }
        if (auto fed = engine_->receive(
                std::span<const std::byte>{buffer.data(), received->size},
                detail::now_ns());
            !fed) {
            co_return fail(fed.error());
        }
        collect_events();
        auto out = co_await flush(io);
        if (!out) co_return fail(out.error());
        co_return Result<void>{};
    }

    /// Drain the engine's event queue into per-stream buffers.
    void collect_events() {
        for (auto& event : engine_->take_events()) {
            const std::int64_t id = event.stream_id;
            buffers_[id].push_back(std::move(event));
        }
    }

    /// pump rounds until `done` holds or the wait fails.
    Task<Result<void>> pump_until(auto&& done, OperationOptions io) {
        for (;;) {
            if (done(*this)) co_return Result<void>{};
            auto round = co_await do_pump(io);
            if (!round) co_return fail(round.error());
        }
    }

    std::unique_ptr<Transport> transport_;
    std::unique_ptr<Engine> engine_;
    transport::Endpoint remote_{};
    std::map<std::int64_t, std::deque<Event>> buffers_;
    bool pumping_ = false;
};

}  // namespace Mira::quic
