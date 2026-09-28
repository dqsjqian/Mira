#pragma once

#include "mira/core/connection_pool.hpp"
#include "mira/http/client.hpp"

#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace Mira::client {

/// Move-only session with a heap-pinned connection; lazy tasks retain ownership.
/// Body spans are borrowed. Await started tasks and use only on the owning loop.
/// Destruction discards by default; recycle requires drain and no retained tasks.
template<typename Connection>
class Session {
    using Lease = typename ConnectionPool<Connection>::Lease;
    struct State {
        State(Lease value, std::string host, OperationOptions settings)
            : lease(std::move(value)), authority(std::move(host)), io(std::move(settings)) {}
        Lease lease;
        std::string authority;
        OperationOptions io;
        bool attached = true;
    };
public:
    Session(Lease lease, std::string authority, OperationOptions io)
        : state_(std::make_shared<State>(std::move(lease), std::move(authority), std::move(io))) {}
    Session(Session&&) noexcept = default;
    Session& operator=(Session&& other) noexcept {
        if (this != &other) {
            discard();
            state_ = std::move(other.state_);
        }
        return *this;
    }
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    ~Session() { discard(); }

    [[nodiscard]] Task<Result<void>> begin(http::Request request, http::Framing framing,
                                           std::uint64_t length = 0) {
        return begin_impl(state_, std::move(request), framing, length);
    }
    [[nodiscard]] Task<Result<void>> start(http::Request request,
                                           std::span<const std::byte> body = {}) {
        return start_impl(state_, std::move(request), body);
    }
    [[nodiscard]] Task<Result<void>> send_body(std::span<const std::byte> body) {
        return send_impl(state_, body);
    }
    [[nodiscard]] Task<Result<void>> finish() { return finish_impl(state_); }
    /// Borrows the session buffer until the next protocol operation, recycle or discard.
    [[nodiscard]] Task<Result<std::span<const std::byte>>> read_body() { return read_impl(state_); }

    /// Return a copy rather than a reference invalidated by recycling or moving.
    [[nodiscard]] Result<http::Response> response() const {
        if (!state_) return fail(Errc::invalid_argument);
        return state_->lease->http().response();
    }
    [[nodiscard]] Result<http::HeaderMap> trailers() const {
        if (!state_) return fail(Errc::invalid_argument);
        return state_->lease->http().trailers();
    }
    [[nodiscard]] bool reusable() const noexcept {
        return state_ && state_.use_count() == 1 && state_->lease->http().reusable();
    }
    /// Failure retains the lease; finish draining or destroy the session to discard it.
    [[nodiscard]] Result<void> recycle() {
        if (!reusable()) return fail(Errc::invalid_argument);
        std::move(state_->lease).recycle();
        state_.reset();
        return {};
    }
    /// Release this handle; existing tasks retain ownership but never recycle implicitly.
    void discard() noexcept {
        if (state_) state_->attached = false;
        state_.reset();
    }

private:
    static Result<void> prepare_request(const State& state, http::Request& request) {
        if (!request.headers.contains("Host")) {
            request.headers.append("Host", state.authority);
        } else if (request.headers.count("Host") != 1 ||
                   !http::HeaderMap::names_equal(*request.headers.get("Host"), state.authority)) {
            return fail(Errc::invalid_argument);
        }
        return {};
    }
    static Task<Result<void>> begin_impl(std::shared_ptr<State> state, http::Request request,
                                          http::Framing framing, std::uint64_t length) {
        if (!state) co_return fail(Errc::invalid_argument);
        const auto prepared = prepare_request(*state, request);
        if (!prepared) co_return prepared;
        co_return co_await state->lease->http().begin(request, framing, length, state->io);
    }
    static Task<Result<void>> start_impl(std::shared_ptr<State> state, http::Request request,
                                          std::span<const std::byte> body) {
        if (!state) co_return fail(Errc::invalid_argument);
        const auto prepared = prepare_request(*state, request);
        if (!prepared) co_return prepared;
        co_return co_await state->lease->http().start(request, body, state->io);
    }
    static Task<Result<void>> send_impl(std::shared_ptr<State> state,
                                         std::span<const std::byte> body) {
        if (!state) co_return fail(Errc::invalid_argument);
        co_return co_await state->lease->http().send_body(body);
    }
    static Task<Result<void>> finish_impl(std::shared_ptr<State> state) {
        if (!state) co_return fail(Errc::invalid_argument);
        co_return co_await state->lease->http().finish();
    }
    static Task<Result<std::span<const std::byte>>> read_impl(std::shared_ptr<State> state) {
        if (!state) co_return fail(Errc::invalid_argument);
        // A returned span needs a live session handle, not just this task's owner.
        if (!state->attached) co_return fail(Errc::invalid_argument);
        auto result = co_await state->lease->http().read_body();
        if (!state->attached) co_return fail(Errc::invalid_argument);
        co_return result;
    }
    std::shared_ptr<State> state_;
};

}  // namespace Mira::client
