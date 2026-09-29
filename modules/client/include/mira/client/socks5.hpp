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

}  // namespace Mira::client
