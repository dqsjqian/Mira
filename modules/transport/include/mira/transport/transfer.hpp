#pragma once

#include "mira/core/error.hpp"
#include "mira/core/platform.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <utility>

namespace Mira::transport {

/// An exclusively owned, read-only regular file. Open and fallback reads may
/// block on storage; prepare resident files off the event-loop thread for
/// latency-sensitive use. Never close, move or modify the source while a
/// transfer is in flight. With native page-based sends it must stay unmodified
/// until the receiver has consumed the data, not merely until send completes.
class FileSource {
public:
    [[nodiscard]] static Result<FileSource> open(const std::filesystem::path& path);
    FileSource(FileSource&& other) noexcept
        : handle_(std::exchange(other.handle_, invalid_handle)), size_(other.size_) {}
    FileSource& operator=(FileSource&& other) noexcept;
    FileSource(const FileSource&) = delete;
    FileSource& operator=(const FileSource&) = delete;
    ~FileSource();
    [[nodiscard]] NativeHandle native_handle() const noexcept { return handle_; }
    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }
    /// Explicit-offset copy read. EOF is a successful zero-byte result.
    [[nodiscard]] Result<std::size_t> read_at(std::uint64_t offset, std::span<std::byte> output) const;
private:
    FileSource(NativeHandle handle, std::uint64_t size) : handle_(handle), size_(size) {}
    NativeHandle handle_{invalid_handle};
    std::uint64_t size_{};
};

enum class TransferMode { prefer_native, copy, require_native };
struct TransferOptions {
    TransferMode mode{TransferMode::prefer_native};
    /// Bounds fallback allocation and per-turn work, in [1, 1 MiB].
    std::size_t chunk_size{64 * 1024};
};
struct TransferResult {
    std::size_t bytes{};
    /// Native API usage, not a promise that the kernel avoided every copy.
    std::size_t native_bytes{};
    std::size_t copied_bytes{};
};

}  // namespace Mira::transport
