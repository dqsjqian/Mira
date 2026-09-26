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
#include "mira/quic/connection.hpp"  // DatagramTransport concept
#include "mira/quic/engine.hpp"

#include <array>
#include <chrono>
#include <limits>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <utility>

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
/// quic::Connection; a listener that routes many clients by connection ID is
/// not provided yet. Operations must not overlap; `read_body` pumps until
/// the stream produces.
///
/// Constrained by the same `DatagramTransport` concept as `quic::Connection`,
/// so an unsuitable transport fails at the declaration rather than deep
/// inside a pump.
template<quic::DatagramTransport Transport>
class Connection {
public:
    Connection(Connection&&) noexcept = default;
    Connection& operator=(Connection&&) noexcept = default;
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    /// Client: bind the transport and drive the QUIC handshake plus the h3
    /// control-stream setup to completion.
    [[nodiscard]] static Task<Result<Connection>>
    connect(EventLoop& loop, quic::Options options, Limits limits = {}, OperationOptions io = {}) {
        const transport::Endpoint remote = options.remote;
        auto bound = Transport::bind(loop, options.local);
        if (!bound) co_return fail(bound.error());
        auto transport_engine = quic::Engine::client(std::move(options), detail::now_ns());
        if (!transport_engine) co_return fail(transport_engine.error());
        auto engine = Engine::create(std::move(*transport_engine),
                                     /*server=*/false, limits);
        if (!engine) co_return fail(engine.error());
        Connection connection{std::move(*bound), std::move(*engine)};
        connection.remote_ = remote;
        auto ready = co_await connection.pump_until(
            [&](const Connection& self) { return self.engine_->ready(); }, io);
        if (!ready) co_return fail(ready.error());
        co_return std::move(connection);
    }

    /// Server: take over the transport that received the QUIC Initial.
    [[nodiscard]] static Task<Result<Connection>>
    serve(Transport transport, quic::Options options, Limits limits,
          std::span<const std::byte> initial, OperationOptions io = {}) {
        // The remote is part of the options: whoever sent the Initial.
        const transport::Endpoint remote = options.remote;
        auto transport_engine = quic::Engine::accept(std::move(options), initial,
                                                      detail::now_ns());
        if (!transport_engine) co_return fail(transport_engine.error());
        auto engine = Engine::create(std::move(*transport_engine),
                                     /*server=*/true, limits);
        if (!engine) co_return fail(engine.error());
        Connection connection{std::move(transport), std::move(*engine)};
        connection.remote_ = remote;
        auto ready = co_await connection.pump_until(
            [&](const Connection& self) { return self.engine_->ready(); }, io);
        if (!ready) co_return fail(ready.error());
        co_return std::move(connection);
    }

    /// Client: submit a request; the body is copied into the engine's budget.
    [[nodiscard]] Task<Result<std::int64_t>>
    request(const Headers& fields, std::span<const std::byte> body = {}) {
        if (!engine_) co_return fail(Errc::invalid_argument);
        co_return engine_->request(fields, body);
    }

    /// Server: answer a request stream.
    [[nodiscard]] Task<Result<void>>
    respond(std::int64_t stream, const Headers& fields, std::span<const std::byte> body = {},
            OperationOptions io = {}) {
        if (!engine_) co_return fail(Errc::invalid_argument);
        auto sent = engine_->respond(stream, fields, body);
        if (!sent) co_return fail(sent.error());
        auto flushed = co_await flush(io);
        if (!flushed) co_return fail(flushed.error());
        co_return Result<void>{};
    }

    /// Drive until the stream produces its head (client: response headers;
    /// server: request headers arrive through `receive_events` instead).
    [[nodiscard]] Task<Result<MessageHead>>
    await_head(std::int64_t stream, OperationOptions io = {}) {
        if (!engine_) co_return fail(Errc::invalid_argument);
        if (pumping_) co_return fail(Errc::invalid_argument);
        pumping_ = true;
        const PumpGuard guard{pumping_};
        for (;;) {
            if (auto head = take_head(stream)) {
                auto flushed = co_await flush(io);
                if (!flushed) co_return fail(flushed.error());
                co_return std::move(*head);
            }
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
            if (auto chunk = take_body(stream)) {
                // Flush before returning: pending ACKs and flow-control
                // updates must not wait for the next pump (see quic).
                auto flushed = co_await flush(io);
                if (!flushed) co_return fail(flushed.error());
                co_return std::move(*chunk);
            }
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
    [[nodiscard]] Task<Result<void>>
    close(std::uint64_t application_error, OperationOptions io = {}) {
        if (!engine_ || !transport_) co_return fail(Errc::invalid_argument);
        auto last = engine_->close(application_error, detail::now_ns());
        if (!last) co_return fail(last.error());
        if (!last->empty()) {
            auto sent = co_await transport_->send_to(std::span<const std::byte>{last->data(), last->size()}, remote_, io);
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

    [[nodiscard]] bool ready() const noexcept { return engine_ && engine_->ready(); }
    [[nodiscard]] bool closed() const noexcept {
        return !engine_ || engine_->closed();
    }

private:
    struct PumpGuard {
        bool& pumping;
        ~PumpGuard() { pumping = false; }
    };

    explicit Connection(Transport transport, Engine engine)
        : transport_(std::make_unique<Transport>(std::move(transport))),
          engine_(std::make_unique<Engine>(std::move(engine))) {}

    std::optional<MessageHead> take_head(std::int64_t stream) {
        auto it = buffers_.find(stream);
        if (it == buffers_.end() || it->second.empty()) return std::nullopt;
        auto& queue = it->second;
        for (auto iter = queue.begin(); iter != queue.end();) {
            if (iter->kind == Event::Kind::headers) {
                MessageHead head{std::move(iter->fields)};
                iter = queue.erase(iter);
                if (queue.empty()) buffers_.erase(it);
                return head;
            }
            if (iter->kind == Event::Kind::reset) {
                return MessageHead{};  // reset streams surface as an empty head
            }
            ++iter;
        }
        return std::nullopt;
    }

    std::optional<BodyChunk> take_body(std::int64_t stream) {
        auto it = buffers_.find(stream);
        if (it == buffers_.end() || it->second.empty()) return std::nullopt;
        auto& queue = it->second;
        if (queue.front().kind == Event::Kind::body) {
            BodyChunk chunk{std::move(queue.front().data), false};
            queue.pop_front();
            if (queue.empty()) buffers_.erase(it);
            return chunk;
        }
        if (queue.front().kind == Event::Kind::end) {
            BodyChunk chunk{{}, true};
            queue.pop_front();
            if (queue.empty()) buffers_.erase(it);
            return chunk;
        }
        if (queue.front().kind == Event::Kind::reset) {
            BodyChunk chunk{{}, true};
            queue.pop_front();
            if (queue.empty()) buffers_.erase(it);
            return chunk;
        }
        queue.pop_front();  // headers were left for await_head
        if (queue.empty()) buffers_.erase(it);
        return std::nullopt;
    }

    Task<Result<void>> flush(OperationOptions io) {
        for (std::size_t round = 0; round < 64; ++round) {
            auto packet = engine_->poll(detail::now_ns());
            if (!packet) co_return fail(packet.error());
            if (packet->empty()) break;
            auto sent = co_await transport_->send_to(std::span<const std::byte>{packet->data(), packet->size()}, remote_, io);
            if (!sent) co_return fail(sent.error());
            if (*sent != packet->size()) {
                co_return fail(std::make_error_code(std::errc::io_error));
            }
        }
        co_return Result<void>{};
    }

    Task<Result<void>> do_pump(OperationOptions io) {
        auto flushed = co_await flush(io);
        if (!flushed) co_return fail(flushed.error());

        collect_events();

        const std::uint64_t now = detail::now_ns();
        OperationOptions wait = io;
        // See quic: NGTCP2_INFINITY must not become a deadline (overflow spin).
        bool engine_timer_armed = false;
        if (const std::uint64_t expiry = engine_->expiry();
            expiry > now && expiry != std::numeric_limits<std::uint64_t>::max()) {
            const auto deadline = EventLoop::Clock::time_point{std::chrono::nanoseconds{expiry}};
            if (!wait.deadline || deadline < *wait.deadline) wait.deadline = deadline;
            engine_timer_armed = true;
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
                if (engine_timer_armed && wait.deadline == io.deadline) {
                    // The caller's own deadline won the race mid-wait.
                    co_return fail(Errc::timed_out);
                }
                if (auto handled = engine_->handle_expiry(detail::now_ns()); !handled) {
                    co_return fail(handled.error());
                }
                auto after = co_await flush(io);
                if (!after) co_return fail(after.error());
                co_return Result<void>{};
            }
            co_return fail(received.error());
        }

        if (engine_->is_server()) {
            remote_ = received->peer;
        } else if (!(received->peer == remote_)) {
            co_return Result<void>{};  // not ours; drop
        }
        if (auto fed = engine_->receive(std::span<const std::byte>{buffer.data(), received->size},
                                        detail::now_ns());
            !fed) {
            co_return fail(fed.error());
        }
        collect_events();
        auto out = co_await flush(io);
        if (!out) co_return fail(out.error());
        co_return Result<void>{};
    }

    void collect_events() {
        for (auto& event : engine_->take_events()) {
            buffers_[event.stream_id].push_back(std::move(event));
        }
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
    std::map<std::int64_t, std::deque<Event>> buffers_;
    bool pumping_ = false;
};

}  // namespace Mira::http3
