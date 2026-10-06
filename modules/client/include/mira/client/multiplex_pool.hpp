#pragma once

#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/http/fields.hpp"
#include "mira/transport/resolver.hpp"

#include <algorithm>
#include <map>
#include <vector>
#include <memory>
#include <string>
#include <thread>
#include <utility>

namespace Mira::client {

struct MultiplexOptions {
    std::size_t max_origins = 16;
    std::size_t max_active = 64;
    std::size_t max_response_bytes = 4 * 1024 * 1024;
    Clock::duration connect_timeout = std::chrono::seconds(10);
};

// One owned multiplexed connection per origin. No queueing, no automatic
// retries, no cross-origin connection sharing. Quotas also cover origins that
// are currently dialing; cancelling one request never cancels a dial or session
// shared with other callers. After the first request the pool must be shut down
// with stop()+co_await join() or co_await close(), including exceptional exits.
// join stops and awaits dials, application requests and session drivers before
// destroying the owned sockets/SSL/protocol engines. Object methods are for the
// constructing thread only; OperationOptions.stop may be requested from any thread.
template<class Factory>
class MultiplexClient {
    using Connection = typename Factory::Connection;
    using Key = std::pair<std::string, std::uint16_t>;
    struct Entry {
        std::unique_ptr<Connection> connection;
        Error error;
        std::exception_ptr exception;
        std::stop_source ready;
        bool done = false;
    };
    struct State {
        State(EventLoop& executor, transport::Resolver dns, Factory connector, MultiplexOptions settings)
            : loop(executor), resolver(std::move(dns)), factory(std::move(connector)), options(settings),
              joining_task(finish(this)) {}
        EventLoop& loop;
        transport::Resolver resolver;
        Factory factory;
        MultiplexOptions options;
        const std::thread::id thread = std::this_thread::get_id();
        TaskScope dialing;
        Task<void> joining_task;
        std::stop_source stop;
        std::stop_source drained;
        std::map<Key, std::shared_ptr<Entry>> entries;
        std::size_t active = 0;
        bool used = false, closing = false, joining = false, joined = false;
    };
    struct Forward {
        std::stop_source source;
        void operator()() const noexcept { auto copy = source; copy.request_stop(); }
    };
    struct Active {
        State& state;
        explicit Active(State& value) : state(value) { ++state.active; state.used = true; }
        ~Active() { if (--state.active == 0) state.drained.request_stop(); }
    };
public:
    using Response = typename Factory::Response;
    [[nodiscard]] static Result<MultiplexClient> create(EventLoop& loop, Factory factory,
        MultiplexOptions options = {}, transport::ResolverOptions dns = {},
        transport::Resolver::Backend backend = {}) {
        if (!options.max_origins || !options.max_active || options.max_active > 64 ||
            options.connect_timeout <= Clock::duration::zero()) return fail(Errc::invalid_argument);
        auto resolver = transport::Resolver::create(dns, std::move(backend));
        if (!resolver) return fail(resolver.error());
        return MultiplexClient{std::make_shared<State>(loop, std::move(*resolver), std::move(factory), options)};
    }
    MultiplexClient(const MultiplexClient&) = delete;
    MultiplexClient& operator=(const MultiplexClient&) = delete;
    MultiplexClient(MultiplexClient&& other) noexcept : state_(std::move(other.state_)) {}
    MultiplexClient& operator=(MultiplexClient&& other) noexcept {
        if (this != &other) {
            require_closed();
            if (state_) state_->closing = true;
            state_ = std::move(other.state_);
        }
        return *this;
    }
    ~MultiplexClient() {
        require_closed();
        if (state_) state_->closing = true;
    }

    [[nodiscard]] Task<Result<Response>> request(std::string host, std::uint16_t port,
        http::Headers headers, std::vector<std::byte> body = {}, OperationOptions io = {}) {
        return request_impl(state_, std::move(host), port, std::move(headers), std::move(body), io);
    }
    void stop() noexcept { if (state_) stop_state(*state_); }
    [[nodiscard]] Task<void> join() {
        if (!state_) throw std::logic_error("Mira::client::MultiplexClient is moved from");
        require_thread(*state_);
        if (state_->joining) throw std::logic_error("Mira::client::MultiplexClient join already requested");
        state_->joining = true;
        stop_state(*state_);
        return std::move(state_->joining_task);
    }
    [[nodiscard]] Task<void> close() { return join(); }
    [[nodiscard]] std::size_t origins() const noexcept { return state_ ? state_->entries.size() : 0; }
    [[nodiscard]] std::size_t active() const noexcept { return state_ ? state_->active : 0; }

private:
    explicit MultiplexClient(std::shared_ptr<State> state) : state_(std::move(state)) {}
    void require_closed() const noexcept {
        if (state_ && ((state_->used || state_->joining) && !state_->joined)) std::terminate();
    }
    static void require_thread(const State& state) noexcept {
        if (state.thread != std::this_thread::get_id()) std::terminate();
    }
    static Result<std::string> normalize(std::string host) {
        if (host.empty() || host.size() > 253) return fail(Errc::invalid_argument);
        if (host.find(':') != std::string::npos) {
            if (host.find('%') != std::string::npos) return fail(Errc::not_supported);
            auto endpoint = transport::Endpoint::parse(host, 1);
            if (!endpoint) return fail(Errc::invalid_argument);
            return endpoint->address();
        }
        bool start = true;
        for (char& c : host) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            if (c == '.') { if (start) return fail(Errc::invalid_argument); start = true; continue; }
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                return fail(Errc::invalid_argument);
            start = false;
        }
        if (start) return fail(Errc::invalid_argument);
        return host;
    }
    static Result<void> bind_authority(http::Headers& headers, const Key& key) {
        const auto host = key.first.find(':') == std::string::npos ? key.first : "[" + key.first + "]";
        const auto authority = host + ":" + std::to_string(key.second);
        bool present = false;
        for (auto& field : headers) {
            if (field.name == ":scheme" && field.value != "https") return fail(Errc::invalid_argument);
            if (field.name == ":authority" || field.name == "host") {
                if (field.value != authority && !(key.second == 443 && field.value == host))
                    return fail(Errc::invalid_argument);
                if (field.name == ":authority") {
                    if (present) return fail(Errc::invalid_argument);
                    present = true;
                }
            }
        }
        if (!present) {
            auto regular = std::find_if(headers.begin(), headers.end(), [](const auto& field) {
                return field.name.empty() || field.name.front() != ':';
            });
            headers.insert(regular, {":authority", authority});
        }
        return {};
    }
    static void stop_state(State& state) noexcept {
        require_thread(state);
        state.closing = true;
        for (auto& [key, entry] : state.entries) {
            static_cast<void>(key);
            if (entry->connection) entry->connection->stop();
        }
        auto stop = state.stop;
        stop.request_stop();
    }
    static Task<void> connect_one(State* state, Key key, std::shared_ptr<Entry> entry) {
        const auto now = Clock::now();
        const auto timeout = state->options.connect_timeout;
        const auto deadline = timeout > Clock::time_point::max() - now ? Clock::time_point::max() : now + timeout;
        try {
            auto result = co_await state->factory.connect(state->loop, state->resolver, key.first, key.second,
                state->options.max_response_bytes, {.stop = state->stop.get_token(), .deadline = deadline});
            if (result) entry->connection = std::move(*result);
            else entry->error = result.error();
        } catch (...) {
            entry->exception = std::current_exception();
            entry->error = make_error_code(Errc::internal);
        }
        entry->done = true;
        if (!entry->connection) state->entries.erase(key);
        else if (state->closing) entry->connection->stop();
        entry->ready.request_stop();
    }
    static Task<Result<Response>> request_impl(std::shared_ptr<State> state, std::string host,
        std::uint16_t port, http::Headers headers, std::vector<std::byte> body, OperationOptions io) {
        if (!state) co_return fail(Errc::cancelled);
        require_thread(*state);
        if (state->closing || io.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (io.deadline && *io.deadline <= Clock::now()) co_return fail(Errc::timed_out);
        if (!port) co_return fail(Errc::invalid_argument);
        auto canonical = normalize(std::move(host));
        if (!canonical) co_return fail(canonical.error());
        Key key{std::move(*canonical), port};
        if (auto valid = bind_authority(headers, key); !valid) co_return fail(valid.error());
        if (state->active >= state->options.max_active) co_return fail(Errc::would_block);
        auto found = state->entries.find(key);
        if (found == state->entries.end() && state->entries.size() >= state->options.max_origins)
            co_return fail(Errc::would_block);
        Active active{*state};
        std::stop_source request_stop;
        std::stop_callback caller(io.stop, Forward{request_stop});
        std::stop_callback pool(state->stop.get_token(), Forward{request_stop});
        io.stop = request_stop.get_token();
        std::shared_ptr<Entry> entry;
        if (found != state->entries.end()) entry = found->second;
        else {
            entry = std::make_shared<Entry>();
            state->entries.emplace(key, entry);
            try { state->dialing.spawn(connect_one(state.get(), key, entry)); }
            catch (...) { state->entries.erase(key); throw; }
        }
        if (!entry->done) {
            std::stop_source wake;
            std::stop_callback complete(entry->ready.get_token(), Forward{wake});
            std::stop_callback cancelled(io.stop, Forward{wake});
            static_cast<void>(co_await state->loop.sleep_until(io.deadline.value_or(Clock::time_point::max()),
                                                               {.stop = wake.get_token()}));
        }
        if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (io.deadline && *io.deadline <= Clock::now()) co_return fail(Errc::timed_out);
        if (entry->exception) std::rethrow_exception(entry->exception);
        if (entry->error) co_return fail(entry->error);
        if (!entry->connection) co_return fail(Errc::internal);
        try {
            co_return co_await entry->connection->request(std::move(headers), std::move(body), io);
        } catch (...) {
            // A session is not assumed reusable after an application-level exception;
            // close/join still releases the owned resources.
            entry->connection->stop();
            throw;
        }
    }
    static Task<void> finish(State* state) {
        co_await state->dialing.join();
        if (state->active) {
            state->drained = std::stop_source{};
            static_cast<void>(co_await state->loop.sleep_until(Clock::time_point::max(),
                                                               {.stop = state->drained.get_token()}));
        }
        std::exception_ptr exception;
        for (auto& [key, entry] : state->entries) {
            static_cast<void>(key);
            try { co_await entry->connection->join(); }
            catch (...) { if (!exception) exception = std::current_exception(); }
        }
        state->entries.clear();
        state->joined = true;
        if (exception) std::rethrow_exception(exception);
    }
    std::shared_ptr<State> state_;
};

} // namespace Mira::client
