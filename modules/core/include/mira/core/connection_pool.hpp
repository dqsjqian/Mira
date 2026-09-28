#pragma once

#include "mira/core/operation.hpp"
#include "mira/core/resource_budget.hpp"
#include "mira/core/task.hpp"

#include <memory>
#include <vector>

namespace Mira {

/// Single-event-loop, per-origin pool. The factory owns transport/TLS setup.
/// No hidden retries: never replay a request whose remote effect is unknown.
/// Exhaustion returns would_block rather than creating an unbounded wait queue.
/// Leases discard by default; return only completely drained, reusable connections.
template<typename Connection>
class ConnectionPool {
    struct Entry {
        std::unique_ptr<Connection> connection;
        ResourceBudget::Reservation slot;
        Clock::time_point returned;
    };
    struct State {
        State(std::size_t capacity, Clock::duration ttl)
            : slots(capacity), idle_timeout(ttl) {}
        ResourceBudget slots;
        Clock::duration idle_timeout;
        std::vector<Entry> idle;
        bool closed = false;
    };
public:
    class Lease {
    public:
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&&) noexcept = default;
        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                connection_.reset();
                slot_.reset();
                state_ = std::move(other.state_);
                slot_ = std::move(other.slot_);
                connection_ = std::move(other.connection_);
            }
            return *this;
        }
        [[nodiscard]] Connection& get() const noexcept { return *connection_; }
        [[nodiscard]] Connection* operator->() const noexcept { return connection_.get(); }
        /// Returning an unhealthy connection is a caller contract violation.
        /// Call only after all operations and response bodies have completed.
        void recycle() && {
            if (connection_ && !state_->closed && state_->idle_timeout > Clock::duration::zero()) {
                state_->idle.push_back({std::move(connection_), std::move(slot_), Clock::now()});
            } else {
                connection_.reset();
                slot_.reset();
            }
        }
    private:
        friend class ConnectionPool;
        Lease(std::shared_ptr<State> state, std::unique_ptr<Connection> connection,
              ResourceBudget::Reservation slot)
            : state_(std::move(state)), slot_(std::move(slot)), connection_(std::move(connection)) {}
        std::shared_ptr<State> state_;
        ResourceBudget::Reservation slot_;
        std::unique_ptr<Connection> connection_;
    };

    explicit ConnectionPool(std::size_t max_connections,
                            Clock::duration idle_timeout = std::chrono::seconds(30))
        : state_(std::make_shared<State>(max_connections, idle_timeout)) {}
    ConnectionPool(const ConnectionPool&) = delete;
    ConnectionPool& operator=(const ConnectionPool&) = delete;
    ~ConnectionPool() { close(); }

    /// Factory(OperationOptions) -> Task<Result<unique_ptr<Connection>>>.
    /// The returned task owns the shared state and factory before suspension.
    template<typename Factory>
    [[nodiscard]] Task<Result<Lease>> acquire(Factory factory, OperationOptions io = {}) {
        return acquire_impl(state_, std::move(factory), std::move(io));
    }
    /// Stop admission and drop idle connections; active leases remain owned by
    /// their callers and are discarded when returned. No in-flight I/O is destroyed.
    void close() noexcept { state_->closed = true; state_->idle.clear(); }
    [[nodiscard]] std::size_t active_and_idle() const noexcept { return state_->slots.used(); }
    [[nodiscard]] std::size_t idle() const noexcept { return state_->idle.size(); }
private:
    template<typename Factory>
    static Task<Result<Lease>> acquire_impl(std::shared_ptr<State> state, Factory factory,
                                            OperationOptions io) {
        if (io.stop.stop_requested() || state->closed) co_return fail(Errc::cancelled);
        if (io.deadline && Clock::now() >= *io.deadline) co_return fail(Errc::timed_out);
        if (state->idle_timeout < Clock::duration::zero()) co_return fail(Errc::invalid_argument);
        while (!state->idle.empty()) {
            Entry entry = std::move(state->idle.back());
            state->idle.pop_back();
            if (Clock::now() - entry.returned < state->idle_timeout)
                co_return Lease{state, std::move(entry.connection), std::move(entry.slot)};
        }
        auto reservation = state->slots.try_acquire(1);
        if (!reservation) co_return fail(reservation.error());
        auto connected = co_await factory(io);
        if (!connected) co_return fail(connected.error());
        if (!*connected) co_return fail(Errc::invalid_argument);
        if (io.stop.stop_requested() || state->closed) co_return fail(Errc::cancelled);
        if (io.deadline && Clock::now() >= *io.deadline) co_return fail(Errc::timed_out);
        co_return Lease{state, std::move(*connected), std::move(*reservation)};
    }
    std::shared_ptr<State> state_;
};

}  // namespace Mira
