#pragma once

#include "mira/client/multiplex_pool.hpp"
#include "mira/http3/client_session.hpp"
#include "mira/transport/udp.hpp"

namespace Mira::client {

class Http3Connection {
public:
    Http3Connection(EventLoop& loop, transport::udp::Socket socket, http3::Engine engine,
                    transport::Endpoint peer, std::size_t max_response)
        : socket_(std::move(socket)), engine_(std::move(engine)),
          session_(loop, socket_, engine_, peer, max_response) {}
    Http3Connection(const Http3Connection&) = delete;
    Http3Connection& operator=(const Http3Connection&) = delete;
    Task<Result<http3::Response>> request(http::Headers headers, std::vector<std::byte> body, OperationOptions io) {
        co_return co_await session_.request(std::move(headers), std::move(body), io);
    }
    void stop() noexcept { session_.stop(); }
    Task<void> join() { co_await session_.join(); }
    Task<Result<void>> handshake(OperationOptions io) {
        while (!engine_.ready()) {
            auto result = co_await session_.progress(io);
            if (!result) co_return result;
        }
        co_return Result<void>{};
    }
private:
    transport::udp::Socket socket_;
    http3::Engine engine_;
    http3::ClientSession<transport::udp::Socket> session_;
};

struct Http3Options {
    std::string ca_file;
    http3::Limits limits{};
    std::size_t max_buffered_bytes = 4 * 1024 * 1024;
};

// Strict certificate/hostname verification, fixed h3 ALPN, one UDP socket per origin; no migration or 0-RTT.
class Http3Factory {
public:
    using Connection = Http3Connection;
    using Response = http3::Response;
    explicit Http3Factory(Http3Options options = {}) : options_(std::move(options)) {}
    [[nodiscard]] Task<Result<std::unique_ptr<Connection>>> connect(EventLoop& loop,
        transport::Resolver& resolver, const std::string& host, std::uint16_t port,
        std::size_t max_response, OperationOptions io) const {
        auto endpoints = co_await resolver.resolve(loop,
            {.hostname = host, .service = std::to_string(port), .transport = transport::ResolveTransport::udp}, io);
        if (!endpoints) co_return fail(endpoints.error());
        if (endpoints->empty()) co_return fail(Errc::invalid_argument);
        const auto peer = endpoints->front();
        auto socket = transport::udp::Socket::bind(loop, transport::Endpoint::any(0, peer.family()));
        if (!socket) co_return fail(socket.error());
        auto local = socket->local_endpoint();
        if (!local) co_return fail(local.error());
        quic::Options options;
        options.local = *local;
        options.remote = peer;
        options.ca_file = options_.ca_file;
        options.peer_name = host;
        options.max_buffered_bytes = options_.max_buffered_bytes;
        auto transport = quic::Engine::client(std::move(options), quic::detail::now_ns());
        if (!transport) co_return fail(transport.error());
        auto engine = http3::Engine::create(std::move(*transport), false, options_.limits);
        if (!engine) co_return fail(engine.error());
        auto connection = std::make_unique<Connection>(loop, std::move(*socket), std::move(*engine), peer, max_response);
        Error failure;
        std::exception_ptr exception;
        try {
            auto ready = co_await connection->handshake(io);
            if (!ready) failure = ready.error();
        } catch (...) { exception = std::current_exception(); }
        if (failure || exception) {
            try { co_await connection->join(); } catch (...) { if (!exception) exception = std::current_exception(); }
            if (exception) std::rethrow_exception(exception);
            co_return fail(failure);
        }
        co_return connection;
    }
private:
    Http3Options options_;
};

using Http3Client = MultiplexClient<Http3Factory>;

} // namespace Mira::client
