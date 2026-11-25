#pragma once

// Mira/core/buffer.hpp — a contiguous buffer for incremental protocol I/O.
// prepare(n) exposes writable space, commit(k) publishes the bytes actually
// written, and consume(k) advances the read cursor without moving data.

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <functional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace Mira {

class Buffer {
public:
    Buffer() = default;
    explicit Buffer(std::size_t capacity) { storage_.reserve(capacity); }

    // Copy only live data and the outstanding reservation, not unused scratch.
    Buffer(const Buffer& other)
        : storage_(other.storage_.begin() + static_cast<std::ptrdiff_t>(other.read_pos_),
                   other.storage_.begin() + static_cast<std::ptrdiff_t>(other.write_pos_ + other.pending_)),
          write_pos_(other.size()), pending_(other.pending_) {}
    Buffer& operator=(const Buffer& other) {
        if (this != &other) *this = Buffer(other);
        return *this;
    }
    Buffer(Buffer&& other) noexcept
        : storage_(std::move(other.storage_)), read_pos_(std::exchange(other.read_pos_, 0)),
          write_pos_(std::exchange(other.write_pos_, 0)), pending_(std::exchange(other.pending_, 0)) {}
    Buffer& operator=(Buffer&& other) noexcept {
        if (this != &other) {
            storage_ = std::move(other.storage_);
            read_pos_ = std::exchange(other.read_pos_, 0);
            write_pos_ = std::exchange(other.write_pos_, 0);
            pending_ = std::exchange(other.pending_, 0);
        }
        return *this;
    }

    [[nodiscard]] std::size_t size() const noexcept { return write_pos_ - read_pos_; }
    [[nodiscard]] bool empty() const noexcept { return read_pos_ == write_pos_; }
    [[nodiscard]] std::size_t capacity() const noexcept { return storage_.capacity(); }
    [[nodiscard]] std::span<const std::byte> readable() const noexcept {
        return std::span{storage_}.subspan(read_pos_, size());
    }

    /// Replace any uncommitted reservation. Its contents are unspecified;
    /// publish only bytes actually written. Readers cannot see it until commit.
    /// Consuming already published bytes does not invalidate the writable span.
    [[nodiscard]] std::span<std::byte> prepare(std::size_t n) {
        const auto unread = size();
        if (n > storage_.max_size() - unread)
            throw std::length_error("Mira::Buffer::prepare: size exceeds max_size");
        if (read_pos_ != 0 && n > storage_.capacity() - write_pos_) {
            // Keep a failed growth from moving either cursor. Grow before
            // compaction only when the reclaimed prefix still would not fit.
            if (n > storage_.capacity() - unread) storage_.resize(unread + n);
            if (unread != 0) std::memmove(storage_.data(), storage_.data() + read_pos_, unread);
            read_pos_ = 0;
            write_pos_ = unread;
        }
        if (const auto end = write_pos_ + n; end > storage_.size()) storage_.resize(end);
        pending_ = n;
        return std::span{storage_}.subspan(write_pos_, n);
    }

    /// Publish up to n reserved bytes and discard the rest. With no outstanding
    /// reservation this is a no-op. Reusing storage does not re-zero each read.
    void commit(std::size_t n) noexcept {
        write_pos_ += (std::min)(n, pending_);
        pending_ = 0;
        if (empty()) read_pos_ = write_pos_ = 0;
    }

    void consume(std::size_t n) noexcept {
        read_pos_ += (std::min)(n, size());
        if (empty() && pending_ == 0) read_pos_ = write_pos_ = 0;
    }

    /// Append an external span or a slice of readable(); replaces any pending
    /// reservation. To publish a prepared span use commit, not append. A
    /// readable slice may move when prepare compacts or reallocates.
    void append(std::span<const std::byte> bytes) {
        if (bytes.empty()) { commit(0); return; }
        const auto source = readable();
        const auto less = std::less<const std::byte*>{};
        const bool internal = !source.empty() && !less(bytes.data(), source.data()) &&
                              less(bytes.data(), source.data() + source.size());
        const auto offset = internal ? static_cast<std::size_t>(bytes.data() - source.data()) : 0;
        const auto count = bytes.size();
        const auto destination = prepare(count);
        if (internal) bytes = readable().subspan(offset, count);
        std::memcpy(destination.data(), bytes.data(), count);
        commit(count);
    }

    /// Reset both cursors while retaining the allocation and reusable storage.
    void clear() noexcept { read_pos_ = write_pos_ = pending_ = 0; }
    void reserve(std::size_t n) { storage_.reserve(n); }

private:
    std::vector<std::byte> storage_;
    std::size_t read_pos_ = 0, write_pos_ = 0, pending_ = 0;
};

}  // namespace Mira
