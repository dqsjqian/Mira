#pragma once

#include "mira/core/error.hpp"

#include <atomic>
#include <cstddef>
#include <memory>
#include <utility>

namespace Mira {

/// A shareable accounting budget, not a bound on allocator overhead or RSS.
/// Copies share a counter. Reservations may outlive the budget object and may
/// be released from another thread. Exhaustion never changes the counter.
class ResourceBudget {
    struct State {
        explicit State(std::size_t value) : limit(value) {}
        const std::size_t limit;
        std::atomic<std::size_t> used{0};
    };
public:
    class Reservation {
    public:
        Reservation() = default;
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;
        Reservation(Reservation&& other) noexcept
            : state_(std::move(other.state_)), size_(std::exchange(other.size_, 0)) {}
        Reservation& operator=(Reservation&& other) noexcept {
            if (this != &other) {
                reset();
                state_ = std::move(other.state_);
                size_ = std::exchange(other.size_, 0);
            }
            return *this;
        }
        ~Reservation() { reset(); }
        void reset() noexcept {
            if (state_) {
                state_->used.fetch_sub(size_, std::memory_order_relaxed);
                state_.reset();
                size_ = 0;
            }
        }
        [[nodiscard]] std::size_t size() const noexcept { return size_; }
    private:
        friend class ResourceBudget;
        Reservation(std::shared_ptr<State> state, std::size_t size)
            : state_(std::move(state)), size_(size) {}
        std::shared_ptr<State> state_;
        std::size_t size_ = 0;
    };

    explicit ResourceBudget(std::size_t limit) : state_(std::make_shared<State>(limit)) {}
    [[nodiscard]] Result<Reservation> try_acquire(std::size_t size) const {
        auto used = state_->used.load(std::memory_order_relaxed);
        for (;;) {
            if (size > state_->limit - used) return fail(Errc::would_block);
            if (state_->used.compare_exchange_weak(used, used + size,
                                                  std::memory_order_relaxed)) {
                return Reservation{state_, size};
            }
        }
    }
    [[nodiscard]] std::size_t used() const noexcept {
        return state_->used.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::size_t limit() const noexcept { return state_->limit; }
private:
    std::shared_ptr<State> state_;
};

}  // namespace Mira
