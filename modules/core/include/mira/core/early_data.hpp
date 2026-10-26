#pragma once

#include "mira/core/error.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace Mira {

enum class EarlyDataPolicy { disabled, replay_safe };
enum class EarlyDataStatus { not_attempted, pending, accepted, rejected };

/// Atomic anti-replay admission after a protocol authenticates its resumption
/// token. Keys must be domain-separated by protocol and service. now/expires
/// use a common monotonic nanosecond clock for every caller sharing a store.
/// Retain a successful claim until expires; fail closed on storage failure.
/// Callbacks are synchronous and must not block or reenter their caller.
class ReplayStore {
public:
    virtual ~ReplayStore() = default;
    virtual bool claim(const std::array<std::byte, 32>& key, std::uint64_t now,
                       std::uint64_t expires) noexcept = 0;
};

/// In-process thread-safe bounded store. Full/clock rollback/allocation failure
/// reject admission; live entries are never evicted. All engines in one ticket
/// domain must share this store. Restart loses memory, so restoring old ticket
/// keys with a fresh store is forbidden. This is not a distributed replay store.
class MemoryReplayStore final : public ReplayStore {
public:
    static Result<std::shared_ptr<MemoryReplayStore>> create(std::size_t max_entries = 4096);
    ~MemoryReplayStore();
    bool claim(const std::array<std::byte, 32>& key, std::uint64_t now,
               std::uint64_t expires) noexcept override;
    [[nodiscard]] std::size_t size() const noexcept;
private:
    struct Impl;
    explicit MemoryReplayStore(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

}  // namespace Mira
