#pragma once

#include "mira/http/session_driver.hpp"
#include "mira/http3/engine.hpp"
#include "mira/quic/connection.hpp"

#include <array>
#include <chrono>
#include <limits>

namespace Mira::http3 {

// QUIC packet receive, send and expiry timers are driven separately; timers and
// new output never wake by cancelling the receive. The current composition
// supports only a fixed peer with one connection per socket. The application
// drains plain HTTP events, CONNECT input is consumed separately via
// Engine::read_connect, and each engine's budget stays strictly enforced.
template<transport::DatagramTransport Transport>
struct SessionWire {
    Transport& transport;
    Engine& engine;
    transport::Endpoint peer;

    static std::uint64_t now() noexcept { return quic::detail::now_ns(); }

    Task<Result<void>> read(OperationOptions options) {
        if (engine.transport().migration_policy() != quic::MigrationPolicy::fixed_peer)
            co_return fail(Errc::not_supported);
        if (engine.closed()) co_return fail(Errc::eof);
        std::array<std::byte, quic::detail::kMaxDatagram> bytes{};
        auto received = co_await transport.receive_from(bytes, options);
        if (!received) co_return fail(received.error());
        if (received->size > bytes.size()) co_return fail(std::make_error_code(std::errc::protocol_error));
        if (!(received->peer == peer)) co_return Result<void>{};
        auto result = engine.receive(std::span<const std::byte>(bytes).first(received->size), now());
        if (!result) co_return result;
        if (engine.closed()) co_return fail(Errc::eof);
        co_return Result<void>{};
    }
    Task<Result<void>> flush(OperationOptions options) {
        for (;;) {
            auto packet = engine.poll(now());
            if (!packet) co_return fail(packet.error());
            if (packet->empty()) break;
            auto sent = co_await transport.send_to(*packet, peer, options);
            if (!sent) co_return fail(sent.error());
            if (*sent != packet->size()) co_return fail(std::make_error_code(std::errc::protocol_error));
        }
        co_return Result<void>{};
    }
    Clock::time_point expiry() const noexcept {
        const auto value = engine.expiry();
        if (value == std::numeric_limits<std::uint64_t>::max()) return Clock::time_point::max();
        return Clock::time_point{std::chrono::nanoseconds{static_cast<std::int64_t>(value)}};
    }
    Result<void> handle_expiry() {
        auto result = engine.handle_expiry(now());
        if (!result) return result;
        if (engine.closed()) return fail(Errc::eof);
        return {};
    }
};

template<transport::DatagramTransport Transport>
class SessionDriver : public http::SessionDriver<SessionWire<Transport>> {
public:
    SessionDriver(EventLoop& loop, Transport& transport, Engine& engine,
                  transport::Endpoint peer, std::size_t max_waiters = 256)
        : http::SessionDriver<SessionWire<Transport>>(loop, {transport, engine, peer}, max_waiters) {}
};

} // namespace Mira::http3
