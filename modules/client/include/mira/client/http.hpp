#pragma once

#include "mira/client/pool.hpp"

namespace Mira::client {

class HttpConnection {
public:
    HttpConnection(transport::tcp::Socket socket, http::ClientOptions options)
        : socket_(std::move(socket)), http_(socket_, options) {}
    HttpConnection(const HttpConnection&) = delete;
    HttpConnection& operator=(const HttpConnection&) = delete;
    ~HttpConnection() { static_cast<void>(http_.abandon()); }
    [[nodiscard]] http::ClientConnection<transport::tcp::Socket>& http() noexcept { return http_; }
    void retain_admission(ResourceBudget::Reservation charge) noexcept { admission_ = std::move(charge); }
private:
    ResourceBudget::Reservation admission_;
    transport::tcp::Socket socket_;
    http::ClientConnection<transport::tcp::Socket> http_;
};

struct HttpFactory {
    using Connection = HttpConnection;
    [[nodiscard]] Task<Result<std::unique_ptr<Connection>>> operator()(
        EventLoop&, transport::tcp::Socket socket, const std::string&,
        http::ClientOptions options, OperationOptions) const {
        co_return std::make_unique<Connection>(std::move(socket), options);
    }
};

using HttpClient = BasicClient<HttpFactory>;

}  // namespace Mira::client
