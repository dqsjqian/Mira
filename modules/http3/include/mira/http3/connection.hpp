#pragma once

// Mira/http3/connection.hpp — HTTP/3 over a real datagram transport.
//
// Same explicit-pump model as http2::Connection and quic::Connection: the
// caller drives progress, nothing runs in the background. The transport is
// a template parameter (udp::Socket satisfies it) so this protocol module
// never includes transport headers directly — applications instantiate.

#include "mira/core/error.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task.hpp"
#include "mira/http3/engine.hpp"
#include "mira/quic/connection.hpp"  // the datagram-constrained QUIC layer
#include "mira/quic/engine.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <utility>
#include <vector>

namespace Mira::http3 {

namespace detail {
// kMaxDatagram and now_ns come from quic/engine.hpp's detail namespace — the
// two protocol layers share one clock and one datagram bound instead of
// drifting duplicates.
using quic::detail::kMaxDatagram;
using quic::detail::now_ns;
}  // namespace detail

/// A received response or request head.
struct MessageHead {
    Headers fields;
};

/// A chunk of received body data; `fin` marks the end of the stream.
struct BodyChunk {
    quic::Bytes data;
    bool fin = false;
};

/// HTTP/3 over one datagram transport. One connection per socket, mirroring
/// quic::Connection; use http3::Server for CID-routed multi-client service.
/// This convenience wrapper uses a fixed peer. Operations must not overlap; `read_body` pumps until
/// the stream produces.
///
/// Constrained by the same `DatagramTransport` concept as `quic::Connection`,
/// so an unsuitable transport fails at the declaration rather than deep
/// inside a pump.
template<transport::DatagramTransport Transport>
class Connection {
public:
    Connection(Connection&&) noexcept = default;
    Connection& operator=(Connection&&) noexcept = default;
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    /// Client: bind the transport and drive the QUIC handshake plus the h3
    /// control-stream setup to completion. With a compatible 0-RTT ticket
    /// (EarlyDataPolicy::replay_safe) it returns at once, before any datagram
    /// is sent, so the first safe request travels in 0-RTT.
    [[nodiscard]] static Task<Result<Connection>>
    connect(EventLoop& loop, quic::Options options, Limits limits = {}, OperationOptions io = {}) {
        if (options.migration != quic::MigrationPolicy::fixed_peer) co_return fail(Errc::not_supported);
        const transport::Endpoint remote = options.remote;
        auto bound = Transport::bind(loop, options.local);
        if (!bound) co_return fail(bound.error());
        if constexpr (requires { bound->local_endpoint(); }) {
            auto local = bound->local_endpoint();
            if (!local) co_return fail(local.error());
            options.local = *local;
        }
        auto transport_engine = quic::Engine::client(std::move(options), detail::now_ns());
        if (!transport_engine) co_return fail(transport_engine.error());
        auto engine = Engine::create(std::move(*transport_engine),
                                     /*server=*/false,
                                     limits);
        if (!engine) co_return fail(engine.error());
        Connection connection{std::move(*bound), std::move(*engine), limits};
        connection.remote_ = remote;
        auto ready = co_await connection.pump_until(
            [&](const Connection& self) {
                return self.engine_->ready() || self.engine_->early_ready();
            },
            io);
        if (!ready) co_return fail(ready.error());
        co_return std::move(connection);
    }

    /// Server: take over the transport that received the QUIC Initial.
    /// A server that accepted 0-RTT is ready before handshake completion.
    [[nodiscard]] static Task<Result<Connection>> serve(Transport transport,
                                                        quic::Options options,
                                                        Limits limits,
                                                        std::span<const std::byte> initial,
                                                        OperationOptions io = {}) {
        if (options.migration != quic::MigrationPolicy::fixed_peer) co_return fail(Errc::not_supported);
        // The remote is part of the options: whoever sent the Initial.
        const transport::Endpoint remote = options.remote;
        auto transport_engine = quic::Engine::accept(std::move(options), initial, detail::now_ns());
        if (!transport_engine) co_return fail(transport_engine.error());
        auto engine = Engine::create(std::move(*transport_engine),
                                     /*server=*/true,
                                     limits);
        if (!engine) co_return fail(engine.error());
        Connection connection{std::move(transport), std::move(*engine), limits};
        connection.remote_ = remote;
        auto ready = co_await connection.pump_until(
            [&](const Connection& self) { return self.engine_->ready(); }, io);
        if (!ready) co_return fail(ready.error());
        co_return std::move(connection);
    }

    /// Client: submit a request; the body is copied into the engine's budget.
    /// While 0-RTT is pending, safe requests go out early; any other request
    /// first drives the handshake (bounded by `io`) and is then sent in 1-RTT.
    [[nodiscard]] Task<Result<std::int64_t>> request(const Headers& fields,
                                                     std::span<const std::byte> body = {},
                                                     OperationOptions io = {}) {
        if (!engine_) co_return fail(Errc::invalid_argument);
        if (buffer_error_) co_return fail(buffer_error_);
        if (engine_->early_ready()) {
            auto early = engine_->request(fields, body);
            if (early || early.error() != Errc::not_supported) co_return early;
            if (pumping_) co_return fail(Errc::invalid_argument);
            pumping_ = true;
            const PumpGuard guard{pumping_};
            auto ready = co_await pump_until(
                [](const Connection& self) { return self.engine_->ready(); }, io);
            if (!ready) co_return fail(ready.error());
        }
        co_return engine_->request(fields, body);
    }
    [[nodiscard]] bool early_ready() const noexcept {
        return engine_ && !buffer_error_ && engine_->early_ready();
    }

    /// Start an incremental request. Empty output pauses until write_body/finish_body.
    [[nodiscard]] Result<std::int64_t> request_stream(const Headers& fields) {
        if (!engine_ || pumping_) return fail(Errc::invalid_argument);
        if (buffer_error_) return fail(buffer_error_);
        return engine_->request_stream(fields);
    }
    [[nodiscard]] Result<void> respond_stream(std::int64_t stream, const Headers& fields) {
        if (!engine_ || pumping_) return fail(Errc::invalid_argument);
        if (buffer_error_) return fail(buffer_error_);
        return engine_->respond_stream(stream, fields);
    }
    /// Enqueue a bounded chunk. would_block accepts no bytes; pump ACKs then retry.
    [[nodiscard]] Result<void> write_body(std::int64_t stream,
        std::span<const std::byte> body, bool end = false) {
        if (!engine_ || pumping_) return fail(Errc::invalid_argument);
        if (buffer_error_) return fail(buffer_error_);
        return engine_->write_body(stream, body, end);
    }
    [[nodiscard]] Result<void> finish_body(std::int64_t stream) {
        if (!engine_ || pumping_) return fail(Errc::invalid_argument);
        if (buffer_error_) return fail(buffer_error_);
        return engine_->finish_body(stream);
    }
    [[nodiscard]] std::size_t queued_body_bytes() const noexcept {
        return engine_ ? engine_->queued_body_bytes() : 0;
    }

    /// Server: answer a request stream.
    [[nodiscard]] Task<Result<void>> respond(std::int64_t stream,
                                             const Headers& fields,
                                             std::span<const std::byte> body = {},
                                             OperationOptions io = {}) {
        if (!engine_) co_return fail(Errc::invalid_argument);
        if (buffer_error_) co_return fail(buffer_error_);
        auto sent = engine_->respond(stream, fields, body);
        if (!sent) co_return fail(sent.error());
        auto flushed = co_await flush(io);
        if (!flushed) co_return fail(flushed.error());
        co_return Result<void>{};
    }

    /// Drain all buffered events in arrival order, pumping when empty.
    /// Shares a queue with await_head/read_body: do not mix the two reading
    /// styles for one stream. Body events still require consume(). Reset
    /// events preserve the peer's application error code.
    [[nodiscard]] Task<Result<std::vector<Event>>> receive_events(OperationOptions io = {}) {
        if (!engine_ || pumping_) co_return fail(Errc::invalid_argument);
        pumping_ = true;
        const PumpGuard guard{pumping_};
        for (;;) {
            if (auto collected = collect_events(); !collected) co_return fail(collected.error());
            if (!buffers_.empty()) {
                auto flushed = co_await flush(io);
                if (!flushed) co_return fail(flushed.error());
                std::vector<Event> events;
                events.reserve(buffers_.size());
                for (auto& event : buffers_)
                    events.push_back(std::move(event));
                buffers_.clear();
                buffered_body_ = buffered_headers_ = 0;
                co_return events;
            }
            if (closed()) co_return fail(Errc::eof);
            auto round = co_await do_pump(io);
            if (!round) co_return fail(round.error());
        }
    }

    /// Drive until the stream produces its head (client: response headers;
    /// server: request headers arrive through `receive_events` instead).
    [[nodiscard]] Task<Result<MessageHead>> await_head(std::int64_t stream,
                                                       OperationOptions io = {}) {
        if (!engine_) co_return fail(Errc::invalid_argument);
        if (pumping_) co_return fail(Errc::invalid_argument);
        pumping_ = true;
        const PumpGuard guard{pumping_};
        for (;;) {
            if (auto collected = collect_events(); !collected) co_return fail(collected.error());
            auto head = take_head(stream);
            if (!head) co_return fail(head.error());
            if (*head) {
                auto flushed = co_await flush(io);
                if (!flushed) co_return fail(flushed.error());
                co_return std::move(**head);
            }
            if (closed()) co_return fail(Errc::eof);
            auto round = co_await do_pump(io);
            if (!round) co_return fail(round.error());
        }
    }

    /// Drive until the stream yields its next body chunk.
    [[nodiscard]] Task<Result<BodyChunk>> read_body(std::int64_t stream, OperationOptions io = {}) {
        if (!engine_) co_return fail(Errc::invalid_argument);
        if (pumping_) co_return fail(Errc::invalid_argument);
        pumping_ = true;
        const PumpGuard guard{pumping_};
        for (;;) {
            if (auto collected = collect_events(); !collected) co_return fail(collected.error());
            auto chunk = take_body(stream);
            if (!chunk) co_return fail(chunk.error());
            if (*chunk) {
                // Flush before returning: pending ACKs and flow-control
                // updates must not wait for the next pump (see quic).
                auto flushed = co_await flush(io);
                if (!flushed) co_return fail(flushed.error());
                co_return std::move(**chunk);
            }
            if (closed()) co_return fail(Errc::eof);
            auto round = co_await do_pump(io);
            if (!round) co_return fail(round.error());
        }
    }

    /// Give the engine flow-control credit for consumed body bytes.
    [[nodiscard]] Result<void> consume(std::int64_t stream, std::size_t bytes) {
        if (!engine_) return fail(Errc::invalid_argument);
        return engine_->consume(stream, bytes);
    }

    /// Cancel a request/response stream.
    [[nodiscard]] Result<void> cancel(std::int64_t stream) {
        if (!engine_) return fail(Errc::invalid_argument);
        return engine_->cancel(stream);
    }

    /// Ask new requests to stop (GOAWAY notice), then finish in-flight ones.
    [[nodiscard]] Result<void> shutdown_notice() {
        if (!engine_) return fail(Errc::invalid_argument);
        return engine_->shutdown_notice();
    }
    [[nodiscard]] Result<void> shutdown() {
        if (!engine_) return fail(Errc::invalid_argument);
        return engine_->shutdown();
    }

    /// Close the underlying QUIC connection and drain its last datagram.
    [[nodiscard]] Task<Result<void>> close(std::uint64_t application_error,
                                           OperationOptions io = {}) {
        if (!engine_ || !transport_) co_return fail(Errc::invalid_argument);
        auto last = engine_->close(application_error, detail::now_ns());
        if (!last) co_return fail(last.error());
        if (!last->empty()) {
            auto sent = co_await transport_->send_to(
                std::span<const std::byte>{last->data(), last->size()}, remote_, io);
            if (!sent) co_return fail(sent.error());
            if (*sent != last->size()) {
                co_return fail(std::make_error_code(std::errc::io_error));
            }
        }
        co_return Result<void>{};
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

    [[nodiscard]] bool ready() const noexcept {
        return engine_ && !buffer_error_ && engine_->ready();
    }
    [[nodiscard]] bool closed() const noexcept {
        return !engine_ || buffer_error_ || engine_->closed();
    }

private:
    struct PumpGuard {
        bool& pumping;
        ~PumpGuard() { pumping = false; }
    };

    explicit Connection(Transport transport, Engine engine, Limits limits)
        : transport_(std::make_unique<Transport>(std::move(transport))),
          engine_(std::make_unique<Engine>(std::move(engine))),
          limits_(limits) {}

    static std::size_t header_bytes(const Event& event) {
        std::size_t bytes = 0;
        for (const auto& [name, value] : event.fields)
            bytes += name.size() + value.size() + 32;
        return bytes;
    }

    Event take(std::deque<Event>::iterator it) {
        buffered_body_ -= it->data.size();
        buffered_headers_ -= header_bytes(*it);
        Event event = std::move(*it);
        buffers_.erase(it);
        return event;
    }

    // Remember the most recent max_streams terminal states without growing
    // indefinitely. Re-reading those streams never waits for more packets.
    void remember_terminal(std::int64_t stream, Error error) {
        for (const auto& terminal : terminals_)
            if (terminal.first == stream) return;
        if (terminals_.size() == limits_.max_streams) terminals_.pop_front();
        terminals_.emplace_back(stream, error);
    }

    Result<std::optional<MessageHead>> take_head(std::int64_t stream) {
        for (const auto& [id, error] : terminals_)
            if (id == stream) return fail(error);
        for (auto it = buffers_.begin(); it != buffers_.end(); ++it) {
            if (it->stream_id != stream) continue;
            if (it->kind == Event::Kind::reset) {
                static_cast<void>(take(it));
                const auto error = std::make_error_code(std::errc::connection_reset);
                remember_terminal(stream, error);
                return fail(error);
            }
            if (it->kind == Event::Kind::headers) {
                auto event = take(it);
                return MessageHead{std::move(event.fields)};
            }
            if (it->kind == Event::Kind::end) {
                static_cast<void>(take(it));
                remember_terminal(stream, make_error_code(Errc::eof));
                return fail(Errc::eof);
            }
        }
        return std::optional<MessageHead>{};
    }

    Result<std::optional<BodyChunk>> take_body(std::int64_t stream) {
        for (const auto& [id, error] : terminals_) {
            if (id != stream) continue;
            if (error == Errc::eof) return BodyChunk{{}, true};
            return fail(error);
        }
        for (auto it = buffers_.begin(); it != buffers_.end();) {
            if (it->stream_id != stream || it->kind == Event::Kind::goaway) {
                ++it;
                continue;
            }
            auto event = take(it);
            if (event.kind == Event::Kind::body) return BodyChunk{std::move(event.data), false};
            if (event.kind == Event::Kind::end) {
                remember_terminal(stream, make_error_code(Errc::eof));
                return BodyChunk{{}, true};
            }
            if (event.kind == Event::Kind::reset) {
                const auto error = std::make_error_code(std::errc::connection_reset);
                remember_terminal(stream, error);
                return fail(error);
            }
            // Skip unread heads/trailers but keep looking for buffered body/end;
            // an already queued terminal event must never require another packet.
            it = buffers_.begin();
        }
        return std::optional<BodyChunk>{};
    }

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

    Task<Result<void>> do_pump(OperationOptions io) {
        if (buffer_error_) co_return fail(buffer_error_);
        if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (io.deadline && *io.deadline <= EventLoop::Clock::now()) co_return fail(Errc::timed_out);
        if (closed()) co_return fail(Errc::eof);
        const auto buffered_before = buffers_.size();
        auto flushed = co_await flush(io);
        if (!flushed) co_return fail(flushed.error());

        if (auto collected = collect_events(); !collected) co_return fail(collected.error());
        if (buffers_.size() > buffered_before) co_return Result<void>{};

        const std::uint64_t now = detail::now_ns();
        OperationOptions wait = io;
        // See quic: NGTCP2_INFINITY must not become a deadline (overflow spin).
        bool engine_timer_armed = false;
        if (const std::uint64_t expiry = engine_->expiry();
            expiry != std::numeric_limits<std::uint64_t>::max()) {
            if (expiry <= now) {
                auto handled = engine_->handle_expiry(now);
                if (!handled) co_return fail(handled.error());
                if (closed()) co_return fail(Errc::eof);
                if (auto collected = collect_events(); !collected)
                    co_return fail(collected.error());
                co_return co_await flush(io);
            }
            const auto deadline = EventLoop::Clock::time_point{std::chrono::nanoseconds{expiry}};
            if (!wait.deadline || deadline < *wait.deadline) {
                wait.deadline = deadline;
                engine_timer_armed = true;
            }
        }

        // See quic: the caller's expired budget must fail the operation, not
        // be mistaken for the engine's timer and "handled" into a spin.
        if (io.deadline && *io.deadline <= EventLoop::Clock::now()) {
            co_return fail(Errc::timed_out);
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
                if (closed()) co_return fail(Errc::eof);
                if (auto collected = collect_events(); !collected)
                    co_return fail(collected.error());
                auto after = co_await flush(io);
                if (!after) co_return fail(after.error());
                co_return Result<void>{};
            }
            co_return fail(received.error());
        }

        if (!(received->peer == remote_)) {
            co_return Result<void>{};  // Fixed peer: unrelated datagrams cannot redirect output.
        }
        if (auto fed = engine_->receive(std::span<const std::byte>{buffer.data(), received->size},
                                        detail::now_ns());
            !fed) {
            co_return fail(fed.error());
        }
        if (auto collected = collect_events(); !collected) co_return fail(collected.error());
        if (closed()) co_return fail(Errc::eof);
        auto out = co_await flush(io);
        if (!out) co_return fail(out.error());
        co_return Result<void>{};
    }

    Result<void> collect_events() {
        if (buffer_error_) return fail(buffer_error_);
        for (auto& event : engine_->take_events()) {
            const auto headers = header_bytes(event);
            // Draining the engine releases its event budget. Enforce a separate
            // budget here so repeated pump() calls cannot grow without bound.
            if (buffers_.size() >= limits_.max_events ||
                event.data.size() > limits_.max_buffered_body - buffered_body_ ||
                headers > limits_.max_header_bytes * limits_.max_streams - buffered_headers_) {
                buffer_error_ = make_error_code(Errc::limit_exceeded);
                return fail(buffer_error_);
            }
            buffered_body_ += event.data.size();
            buffered_headers_ += headers;
            buffers_.push_back(std::move(event));
        }
        return {};
    }

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
    std::deque<Event> buffers_;
    std::deque<std::pair<std::int64_t, Error>> terminals_;
    Limits limits_;
    std::size_t buffered_body_ = 0;
    std::size_t buffered_headers_ = 0;
    Error buffer_error_;
    bool pumping_ = false;
};

}  // namespace Mira::http3
