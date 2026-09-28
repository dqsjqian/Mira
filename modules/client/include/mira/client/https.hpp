#pragma once

#include "mira/client/pool.hpp"
#include "mira/tls/stream.hpp"

namespace Mira::client {

class HttpsConnection {
public:
    using Stream = tls::Stream<transport::tcp::Socket>;
    explicit HttpsConnection(transport::tcp::Socket socket) : socket_(std::move(socket)) {}
    HttpsConnection(const HttpsConnection&) = delete;
    HttpsConnection& operator=(const HttpsConnection&) = delete;
    ~HttpsConnection() { if (http_) static_cast<void>(http_->abandon()); }
    [[nodiscard]] http::ClientConnection<Stream>& http() noexcept { return *http_; }
    void retain_admission(ResourceBudget::Reservation charge) noexcept { admission_ = std::move(charge); }
private:
    friend class HttpsFactory;
    ResourceBudget::Reservation admission_;
    transport::tcp::Socket socket_;
    std::optional<Stream> tls_;
    std::optional<http::ClientConnection<Stream>> http_;
};

/// Immutable TLS configuration; each client owns separate pools even when sharing a factory.
/// Negotiates HTTP/1.1 only. Trust, client certificates and identity policy remain fixed.
class HttpsFactory {
public:
    using Connection = HttpsConnection;
    [[nodiscard]] static Result<HttpsFactory> create(tls::Context::ClientConfig config = {},
                                                               std::optional<ResourceBudget> buffer_budget = {}) {
        if (!config.protocol.empty() && config.protocol != "http/1.1")
            return fail(Errc::not_supported);
        config.protocol = "http/1.1";
        auto context = tls::Context::client(config);
        if (!context) return fail(context.error());
        return HttpsFactory{std::make_shared<const tls::Context>(std::move(*context)), std::move(buffer_budget)};
    }
    [[nodiscard]] Task<Result<std::unique_ptr<Connection>>> operator()(
        EventLoop& loop, transport::tcp::Socket socket, const std::string& host,
        http::ClientOptions options, OperationOptions io) const {
        auto connection = std::make_unique<Connection>(std::move(socket));
        auto stream = Connection::Stream::create(loop, connection->socket_, *context_, host, buffer_budget_);
        if (!stream) co_return fail(stream.error());
        connection->tls_.emplace(std::move(*stream));
        const auto ready = co_await connection->tls_->handshake(std::move(io));
        if (!ready) co_return fail(ready.error());
        const auto protocol = connection->tls_->negotiated_protocol();
        if (!protocol.empty() && protocol != "http/1.1") co_return fail(Errc::not_supported);
        connection->http_.emplace(*connection->tls_, options);
        co_return connection;
    }
private:
    explicit HttpsFactory(std::shared_ptr<const tls::Context> context, std::optional<ResourceBudget> budget)
        : context_(std::move(context)), buffer_budget_(std::move(budget)) {}
    std::shared_ptr<const tls::Context> context_;
    std::optional<ResourceBudget> buffer_budget_;
};

using HttpsClient = BasicClient<HttpsFactory>;

}  // namespace Mira::client
