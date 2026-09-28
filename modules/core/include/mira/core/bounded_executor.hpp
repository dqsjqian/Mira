#pragma once

#include "mira/core/event_loop.hpp"
#include "mira/core/resource_budget.hpp"

#include <cstddef>
#include <utility>

namespace Mira {

/// An application admission gate, deliberately NOT an Executor: it has no
/// post() that could silently drop schedule_on's coroutine continuation.
/// The borrowed loop must outlive this gate and all accepted work. Copies
/// share capacity; independently constructed gates have independent quotas.
class BoundedExecutor {
public:
    BoundedExecutor(EventLoop& loop, std::size_t capacity)
        : loop_(loop), slots_(capacity) {}

    [[nodiscard]] Result<void> try_post(move_only_function<void()> work) const {
        return loop_.try_post(std::move(work), slots_);
    }

    /// Enforce both the local slot quota and a shared application cost budget.
    /// Costs are caller-declared; reservations end before invocation. Neither
    /// quota bounds asynchronous work started by the callback.
    [[nodiscard]] Result<void> try_post(move_only_function<void()> work,
                                        const ResourceBudget& budget,
                                        std::size_t cost) const {
        auto reserved = budget.try_acquire(cost);
        if (!reserved) return fail(reserved.error());
        return loop_.try_post(
            [work = std::move(work), reservation = std::move(*reserved)]() mutable {
                auto running = std::move(work);
                reservation.reset();
                running();
            }, slots_);
    }

    [[nodiscard]] ResourceBudget::Stats stats() const noexcept { return slots_.stats(); }

private:
    EventLoop& loop_;
    ResourceBudget slots_;
};

}  // namespace Mira
