#pragma once

#include "mira/client/multiplex_pool.hpp"
#include "mira/http2/client_session.hpp"
#include "mira/tls/stream.hpp"
#include "mira/transport/dial.hpp"

namespace Mira::client {

class Http2Connection {
public:
    using Stream = tls::Stream<transport::tcp::Socket>;
    Http2Connection(transport::tcp::Socket socket, std::shared_ptr<const tls::Context> context,
                    http2::Session engine)
        : socket_(std::move(socket)), context_(std::move(context)), engine_(std::move(engine)) {}
    Http2Connection(const Http2Connection&) = delete;
    Http2Connection& operator=(const Http2Connection&) = delete;
    Task<Result<http2::Response>> request(http::Headers headers, std::vector<std::byte> body, OperationOptions io) {
        co_return co_await session_->request(std::move(headers), std::move(body), io);
    }
    void stop() noexcept { if (session_) session_->stop(); }
    Task<void> join() { if (session_) co_await session_->join(); }
private:
    friend class Http2Factory;
    transport::tcp::Socket socket_;
    std::shared_ptr<const tls::Context> context_;
    http2::Session engine_;
    std::optional<Stream> tls_;
    std::optional<http2::ClientSession<Stream>> session_;
};

// Fixed trust configuration, strict h2 negotiation; no cleartext prior-knowledge and no HTTP/1 downgrade.
class Http2Factory {
public:
    using Connection = Http2Connection;
    using Response = http2::Response;
    [[nodiscard]] static Result<Http2Factory> create(tls::Context::ClientConfig config = {},
                                                    http2::Limits limits = {}) {
        if ((!config.protocol.empty() && config.protocol != "h2") || !config.protocols.empty())
            return fail(Errc::invalid_argument);
        config.protocol = "h2";
        auto context = tls::Context::client(config);
        if (!context) return fail(context.error());
        return Http2Factory{std::make_shared<const tls::Context>(std::move(*context)), limits};
    }
    [[nodiscard]] Task<Result<std::unique_ptr<Connection>>> connect(EventLoop& loop,
        transport::Resolver& resolver, const std::string& host, std::uint16_t port,
        std::size_t max_response, OperationOptions io) const {
        transport::tcp::DialOptions dial;
        dial.io = io;
        auto socket = co_await transport::tcp::dial(loop, resolver, host, port, dial);
        if (!socket) co_return fail(socket.error());
        auto engine = http2::Session::create(http2::Role::client, limits_);
        if (!engine) co_return fail(engine.error());
        auto connection = std::make_unique<Connection>(std::move(*socket), context_, std::move(*engine));
        auto stream = Connection::Stream::create(loop, connection->socket_, *connection->context_, host);
        if (!stream) co_return fail(stream.error());
        connection->tls_.emplace(std::move(*stream));
        auto ready = co_await connection->tls_->handshake(io);
        if (!ready) co_return fail(ready.error());
        if (connection->tls_->negotiated_protocol() != "h2") co_return fail(Errc::not_supported);
        connection->session_.emplace(loop, *connection->tls_, connection->engine_, max_response);
        co_return connection;
    }
private:
    Http2Factory(std::shared_ptr<const tls::Context> context, http2::Limits limits)
        : context_(std::move(context)), limits_(limits) {}
    std::shared_ptr<const tls::Context> context_;
    http2::Limits limits_;
};

using Http2Client = MultiplexClient<Http2Factory>;

} // namespace Mira::client
