#pragma once

#include "mira/core/error.hpp"

#include <atomic>
#include <cstddef>
#include <memory>
#include <utility>

namespace Mira {

/// A shareable, thread-safe accounting budget, not an allocator or RSS cap.
/// Copies share all counters. Acquire and release may run on different loops;
/// reservations may outlive the budget. The caller chooses the accounted unit
/// (bytes, tasks, etc.) and must reserve before committing that resource.
class ResourceBudget {
    struct State {
        explicit State(std::size_t value) : limit(value) {}

        bool acquire(std::size_t size) noexcept {
            auto current = used.load(std::memory_order_relaxed);
            for (;;) {
                if (size > limit - current) {
                    rejected.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
                if (used.compare_exchange_weak(current, current + size,
                                               std::memory_order_relaxed)) {
                    auto high = peak.load(std::memory_order_relaxed);
                    while (high < current + size &&
                           !peak.compare_exchange_weak(high, current + size,
                                                       std::memory_order_relaxed)) {}
                    return true;
                }
            }
        }

        const std::size_t limit;
        std::atomic<std::size_t> used{0};
        std::atomic<std::size_t> peak{0};
        std::atomic<std::size_t> rejected{0};
    };
public:
    struct Stats {
        std::size_t limit = 0;
        std::size_t used = 0;
        std::size_t peak = 0;
        std::size_t rejected = 0;
    };

    /// Move-only ownership of a charge. Different reservations are independent;
    /// mutating the same Reservation concurrently requires external locking.
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

        /// Grow transactionally, or release a suffix. Failure leaves the
        /// existing charge intact. Resizing to zero retains the budget so a
        /// later growth is possible; reset() relinquishes it altogether.
        [[nodiscard]] Result<void> try_resize(std::size_t size) noexcept {
            if (!state_) return fail(Errc::invalid_argument);
            if (size > size_) {
                if (!state_->acquire(size - size_)) return fail(Errc::would_block);
            } else {
                state_->used.fetch_sub(size_ - size, std::memory_order_relaxed);
            }
            size_ = size;
            return {};
        }
    private:
        friend class ResourceBudget;
        Reservation(std::shared_ptr<State> state, std::size_t size) noexcept
            : state_(std::move(state)), size_(size) {}
        std::shared_ptr<State> state_;
        std::size_t size_ = 0;
    };

    explicit ResourceBudget(std::size_t limit) : state_(std::make_shared<State>(limit)) {}
    [[nodiscard]] Result<Reservation> try_acquire(std::size_t size) const noexcept {
        if (!state_->acquire(size)) return fail(Errc::would_block);
        return Reservation{state_, size};
    }
    [[nodiscard]] std::size_t used() const noexcept {
        return state_->used.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::size_t limit() const noexcept { return state_->limit; }

    /// Individually atomic observations, not a transactional snapshot. Counters
    /// settle after producers quiesce; they do not publish application memory.
    [[nodiscard]] Stats stats() const noexcept {
        return {state_->limit, used(), state_->peak.load(std::memory_order_relaxed),
                state_->rejected.load(std::memory_order_relaxed)};
    }
private:
    std::shared_ptr<State> state_;
};

}  // namespace Mira
