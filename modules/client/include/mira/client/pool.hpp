#pragma once

#include "mira/client/session.hpp"
#include "mira/transport/dial.hpp"

#include <map>
#include <memory>
#include <string>
#include <utility>

namespace Mira::client {

struct Options {
    http::ClientOptions http{};
    std::size_t max_connections_per_origin = 4;
    std::size_t max_origins = 64;
    Clock::duration idle_timeout = std::chrono::seconds(30);
    /// acquire replaces io per call; never retain an absolute deadline as configuration.
    transport::tcp::DialOptions dial{};
    /// Shared connection slots covering connecting, active and idle sessions.
    std::optional<ResourceBudget> admission_budget{};
};

/// Owning client composition; factories hold fixed TLS configuration and pools
/// are never shared between client instances. Origins use normalized host/port
/// keys and matching Host headers. Full origins return would_block; an idle-only
/// origin pool can be evicted. Idle expiry is lazy on acquire, with no background
/// reads or automatic application retries. The loop outlives all clients, leases
/// and tasks; all operations belong to that loop's thread.
template<typename Factory>
class BasicClient {
public:
    using Connection = typename Factory::Connection;
    using SessionType = Session<Connection>;
private:
    using Pool = ConnectionPool<Connection>;
    using Key = std::pair<std::string, std::uint16_t>;
    struct State {
        State(EventLoop& executor, transport::Resolver value, Factory connector, Options settings)
            : loop(&executor), resolver(std::move(value)), factory(std::move(connector)),
              options(std::move(settings)) {}
        EventLoop* loop;
        transport::Resolver resolver;
        Factory factory;
        Options options;
        std::map<Key, std::unique_ptr<Pool>> pools;
        bool closed = false;
    };
public:
    [[nodiscard]] static Result<BasicClient> create(EventLoop& loop, Factory factory,
                                                    Options options = {},
                                                    transport::ResolverOptions dns = {},
                                                    transport::Resolver::Backend backend = {}) {
        if (options.max_connections_per_origin == 0 || options.max_origins == 0 ||
            options.idle_timeout < Clock::duration::zero() || options.http.read_chunk == 0 ||
            options.http.max_buffer_size == 0 ||
            options.http.request_timeout < Clock::duration::zero() ||
            options.dial.fallback_delay < Clock::duration::zero() ||
            options.dial.max_attempts == 0 || options.dial.max_parallel == 0)
            return fail(Errc::invalid_argument);
        auto resolver = transport::Resolver::create(dns, std::move(backend));
        if (!resolver) return fail(resolver.error());
        return BasicClient{std::make_shared<State>(loop, std::move(*resolver), std::move(factory),
                                                   std::move(options))};
    }
    BasicClient(BasicClient&&) noexcept = default;
    BasicClient& operator=(BasicClient&& other) noexcept {
        if (this != &other) {
            close();
            state_ = std::move(other.state_);
        }
        return *this;
    }
    BasicClient(const BasicClient&) = delete;
    BasicClient& operator=(const BasicClient&) = delete;
    ~BasicClient() { close(); }

    /// host is a bare name or IP without brackets, URL, userinfo, scope or proxy syntax.
    /// One deadline covers DNS, TCP, TLS, upload and response without phase resets.
    [[nodiscard]] Task<Result<SessionType>> acquire(std::string host, std::uint16_t port,
                                                    OperationOptions io = {}) {
        return acquire_impl(state_, std::move(host), port, std::move(io));
    }
    void close() noexcept {
        if (!state_) return;
        state_->closed = true;
        for (auto& [key, pool] : state_->pools) {
            static_cast<void>(key);
            pool->close();
        }
    }
    [[nodiscard]] std::size_t active_and_idle() const noexcept {
        if (!state_) return 0;
        std::size_t count = 0;
        for (const auto& [key, pool] : state_->pools) {
            static_cast<void>(key);
            count += pool->active_and_idle();
        }
        return count;
    }
    [[nodiscard]] std::size_t idle() const noexcept {
        if (!state_) return 0;
        std::size_t count = 0;
        for (const auto& [key, pool] : state_->pools) {
            static_cast<void>(key);
            count += pool->idle();
        }
        return count;
    }
private:
    explicit BasicClient(std::shared_ptr<State> state) : state_(std::move(state)) {}
    static Result<std::string> normalize_host(std::string host) {
        if (host.empty() || host.size() > 253) return fail(Errc::invalid_argument);
        if (host.find(':') != std::string::npos) {
            if (host.find('%') != std::string::npos) return fail(Errc::not_supported);
            const auto endpoint = transport::Endpoint::parse(host, 1);
            if (!endpoint) return fail(Errc::invalid_argument);
            return endpoint->address();
        }
        for (char& c : host) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'))
                return fail(Errc::invalid_argument);
        }
        return host;
    }
    static Task<Result<SessionType>> acquire_impl(std::shared_ptr<State> state, std::string host,
                                                    std::uint16_t port, OperationOptions io) {
        if (!state || state->closed || io.stop.stop_requested()) co_return fail(Errc::cancelled);
        const auto now = Clock::now();
        if (io.deadline && now >= *io.deadline) co_return fail(Errc::timed_out);
        if (port == 0) co_return fail(Errc::invalid_argument);
        const auto timeout = state->options.http.request_timeout;
        if (timeout > Clock::duration::zero()) {
            const auto deadline = timeout > Clock::time_point::max() - now
                                      ? Clock::time_point::max() : now + timeout;
            if (!io.deadline || deadline < *io.deadline) io.deadline = deadline;
        }
        auto canonical = normalize_host(std::move(host));
        if (!canonical) co_return fail(canonical.error());
        Key key{*canonical, port};
        auto found = state->pools.find(key);
        if (found == state->pools.end()) {
            for (auto it = state->pools.begin(); it != state->pools.end();) {
                if (it->second->active_and_idle() == 0) it = state->pools.erase(it);
                else ++it;
            }
            if (state->pools.size() >= state->options.max_origins) {
                auto evict = std::find_if(state->pools.begin(), state->pools.end(), [](const auto& entry) {
                    return entry.second->active_and_idle() == entry.second->idle();
                });
                if (evict == state->pools.end()) co_return fail(Errc::would_block);
                state->pools.erase(evict);
            }
            found = state->pools.emplace(key, std::make_unique<Pool>(
                state->options.max_connections_per_origin, state->options.idle_timeout)).first;
        }
        const auto authority = canonical->find(':') == std::string::npos
                                   ? *canonical + ":" + std::to_string(port)
                                   : "[" + *canonical + "]:" + std::to_string(port);
        auto factory = [state, host_name = *canonical, port](OperationOptions operation)
            -> Task<Result<std::unique_ptr<Connection>>> {
            ResourceBudget::Reservation admission;
            if (state->options.admission_budget) {
                auto acquired = state->options.admission_budget->try_acquire(1);
                if (!acquired) co_return fail(acquired.error());
                admission = std::move(*acquired);
            }
            auto dial = state->options.dial;
            dial.io = operation;
            auto socket = co_await transport::tcp::dial(*state->loop, state->resolver,
                                                         host_name, port, std::move(dial));
            if (!socket) co_return fail(socket.error());
            auto connected = co_await state->factory(*state->loop, std::move(*socket), host_name,
                                                      state->options.http, operation);
            if (!connected) co_return fail(connected.error());
            if constexpr (requires(Connection& value, ResourceBudget::Reservation charge) {
                value.retain_admission(std::move(charge));
            }) {
                (*connected)->retain_admission(std::move(admission));
            } else if (state->options.admission_budget) co_return fail(Errc::not_supported);
            co_return std::move(*connected);
        };
        auto lease = co_await found->second->acquire(std::move(factory), io);
        if (!lease) co_return fail(lease.error());
        co_return SessionType{std::move(*lease), authority, std::move(io)};
    }
    std::shared_ptr<State> state_;
};

}  // namespace Mira::client
