#pragma once

// Mira/client/socks5.hpp — dial a TCP tunnel through a SOCKS5 proxy.
//
// Composition only: resolves and dials the proxy with `tcp::dial`, then runs
// `socks::connect` on the socket. The target is sent to the proxy as given —
// a domain target is resolved by the proxy, never locally, so no DNS lookup
// for it leaks outside the tunnel. One absolute deadline covers both steps.

#include "mira/socks/socks5.hpp"
#include "mira/transport/dial.hpp"
#include "mira/transport/resolver.hpp"
#include "mira/transport/tcp.hpp"
#include "mira/transport/udp.hpp"

#include <string>
#include <utility>

namespace Mira::client {

struct Socks5Dial {
    transport::tcp::Socket socket;
    socks::Reply reply;
};

/// Connect to the proxy at `proxy_host:proxy_port`, then CONNECT to `target`.
/// `dial.io` bounds the whole operation. On failure the proxy socket is closed.
[[nodiscard]] inline Task<Result<Socks5Dial>>
dial_via_socks5(EventLoop& loop, transport::Resolver& resolver, std::string proxy_host,
                std::uint16_t proxy_port, socks::Address target, socks::ClientOptions options = {},
                transport::tcp::DialOptions dial = {}) {
    const OperationOptions io = dial.io;
    auto socket = co_await transport::tcp::dial(loop, resolver, std::move(proxy_host), proxy_port,
                                                std::move(dial));
    if (!socket) co_return fail(socket.error());
    auto reply = co_await socks::connect(*socket, target, options, io);
    if (!reply) {
        socket->close();
        co_return fail(reply.error());
    }
    co_return Socks5Dial{std::move(*socket), std::move(*reply)};
}

/// Owning SOCKS5 UDP association. create borrows the loop and takes an already
/// connected TCP control socket; proxy must be that socket's numeric peer.
/// Run monitor() in a joined TaskScope for the association lifetime: TCP EOF
/// closes UDP and wakes pending operations. Call close(), join monitor and all
/// I/O tasks, then destroy. No target-host DNS resolution is performed locally.
class Socks5UdpSession {
public:
    struct Received { std::size_t size; socks::Address peer; };
    static Task<Result<std::unique_ptr<Socks5UdpSession>>> create(EventLoop& loop,
        transport::tcp::Socket control, transport::Endpoint proxy,
        socks::ClientOptions options = {}, OperationOptions io = {}) {
        if (proxy.address_bytes().empty()) co_return fail(Errc::invalid_argument);
        auto socket = transport::udp::Socket::bind(loop, transport::Endpoint::any(0, proxy.family()));
        if (!socket) co_return fail(socket.error());
        auto endpoint = socket->local_endpoint();
        if (!endpoint) co_return fail(endpoint.error());
        auto local = socks::Address::parse(endpoint->address(), endpoint->port());
        if (!local) co_return fail(local.error());
        auto reply = co_await socks::udp_associate(control, *local, options, io);
        if (!reply) co_return fail(reply.error());
        if (!reply->bound.port()) co_return fail(Errc::invalid_argument);
        // Relay DNS names require an explicit resolution policy; never silently
        // send target names or credentials through a system resolver.
        if (reply->bound.kind() == socks::Address::Kind::domain) co_return fail(Errc::not_supported);
        const auto address = reply->bound.host();
        auto relay = transport::Endpoint::parse(
            address == "0.0.0.0" || address == "::" ? proxy.address() : address, reply->bound.port());
        if (!relay) co_return fail(relay.error());
        if (relay->family() != proxy.family()) co_return fail(Errc::not_supported);
        co_return std::unique_ptr<Socks5UdpSession>(new Socks5UdpSession(
            std::move(control), std::move(*socket), std::move(*relay)));
    }
    Socks5UdpSession(const Socks5UdpSession&) = delete;
    Socks5UdpSession& operator=(const Socks5UdpSession&) = delete;
    ~Socks5UdpSession() { if (monitoring_ || reading_ || writing_) std::terminate(); }
    Task<Result<void>> monitor(OperationOptions io = {}) {
        if (monitoring_ || monitored_) co_return fail(Errc::invalid_argument);
        monitored_ = true;
        monitoring_ = true;
        Guard guard{monitoring_};
        std::array<std::byte, 1> byte{};
        try {
            auto result = co_await control_.read_some(byte, io);
            close();
            if (!result && (result.error() == Errc::eof || result.error() == Errc::cancelled))
                co_return Result<void>{};
            co_return result ? fail(Errc::invalid_argument) : fail(result.error());
        } catch (...) { close(); throw; }
    }
    Task<Result<std::size_t>> send_to(std::span<const std::byte> payload, socks::Address target,
                                      OperationOptions io = {}) {
        if (writing_ || !monitoring_ || closed_) co_return fail(Errc::invalid_argument);
        Guard guard{writing_};
        auto wire = socks::encode_udp(target, payload);
        if (!wire) co_return fail(wire.error());
        auto written = co_await udp_.send_to(*wire, relay_, io);
        if (!written) co_return fail(written.error());
        if (*written != wire->size()) co_return fail(Errc::internal);
        co_return payload.size();
    }
    Task<Result<Received>> receive_from(std::span<std::byte> into, OperationOptions io = {}) {
        if (reading_ || !monitoring_ || closed_) co_return fail(Errc::invalid_argument);
        Guard guard{reading_};
        std::array<std::byte, 65536> wire{};
        for (;;) {
            auto packet = co_await udp_.receive_from(wire, io);
            if (!packet) co_return fail(packet.error());
            if (packet->peer != relay_) continue;
            auto decoded = socks::decode_udp(std::span<const std::byte>{wire}.first(packet->size));
            if (!decoded) continue; // RFC 1928: discard unsupported fragments.
            if (decoded->payload.size() > into.size()) co_return fail(std::make_error_code(std::errc::message_size));
            std::copy(decoded->payload.begin(), decoded->payload.end(), into.begin());
            co_return Received{decoded->payload.size(), std::move(decoded->target)};
        }
    }
    void close() noexcept {
        if (closed_) return;
        closed_ = true;
        udp_.close();
        control_.close();
    }
    [[nodiscard]] const transport::Endpoint& relay_endpoint() const noexcept { return relay_; }
private:
    struct Guard {
        bool& active;
        explicit Guard(bool& value) : active(value) { active = true; }
        ~Guard() { active = false; }
    };
    Socks5UdpSession(transport::tcp::Socket control, transport::udp::Socket udp, transport::Endpoint relay)
        : control_(std::move(control)), udp_(std::move(udp)), relay_(std::move(relay)) {}
    transport::tcp::Socket control_;
    transport::udp::Socket udp_;
    transport::Endpoint relay_;
    bool monitoring_ = false, monitored_ = false, reading_ = false, writing_ = false, closed_ = false;
};

}  // namespace Mira::client
