#include "mira/core/early_data.hpp"

#include <map>
#include <mutex>
#include <utility>

namespace Mira {
struct MemoryReplayStore::Impl {
    explicit Impl(std::size_t capacity) : maximum(capacity) {}
    const std::size_t maximum;
    mutable std::mutex mutex;
    std::map<std::array<std::byte, 32>, std::uint64_t> entries;
    std::uint64_t clock = 0;
};
MemoryReplayStore::MemoryReplayStore(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
MemoryReplayStore::~MemoryReplayStore() = default;
Result<std::shared_ptr<MemoryReplayStore>> MemoryReplayStore::create(std::size_t max_entries) {
    if (!max_entries || max_entries > 1'000'000) return fail(Errc::invalid_argument);
    return std::shared_ptr<MemoryReplayStore>(new MemoryReplayStore(std::make_unique<Impl>(max_entries)));
}
bool MemoryReplayStore::claim(const std::array<std::byte, 32>& key, std::uint64_t now,
                              std::uint64_t expires) noexcept {
    try {
        const std::lock_guard lock{impl_->mutex};
        if (now < impl_->clock || expires <= now) return false;
        impl_->clock = now;
        std::erase_if(impl_->entries, [now](const auto& entry) { return entry.second <= now; });
        if (impl_->entries.size() >= impl_->maximum) return false;
        return impl_->entries.emplace(key, expires).second;
    } catch (...) { return false; }
}
std::size_t MemoryReplayStore::size() const noexcept {
    const std::lock_guard lock{impl_->mutex};
    return impl_->entries.size();
}
}  // namespace Mira
