#pragma once

// Mira/core/buffer.hpp — the byte buffer protocol parsers read from.
//
// `Buffer` is a single contiguous region with a read cursor and a write
// cursor, which is the shape a streaming parser wants:
//
//     buf.prepare(4096)            → span to read OS bytes into
//     buf.commit(n)                → n bytes are now readable
//     buf.readable()               → span the parser inspects
//     buf.consume(k)               → k bytes are fully parsed, drop them
//
// Contiguity lets HTTP/1.1 header parsing run `memchr` over an unbroken region.
// Protocols needing segmented storage can implement it separately without
// complicating the contiguous parser interface.
//
// `consume()` does not memmove. Read bytes accumulate in front of the cursor
// and are reclaimed lazily by `prepare()` — so the common "parse a request,
// keep the connection alive" loop reuses one allocation instead of shifting
// bytes on every call.

#include <algorithm>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace Mira {

/// Growable byte buffer with separate read and write cursors.
class Buffer {
public:
    Buffer() = default;

    /// Construct with `capacity` bytes reserved up front.
    explicit Buffer(std::size_t capacity) { storage_.reserve(capacity); }

    Buffer(const Buffer&) = default;
    Buffer& operator=(const Buffer&) = default;
    Buffer(Buffer&& other) noexcept
        : storage_(std::move(other.storage_)),
          read_pos_(std::exchange(other.read_pos_, 0)),
          pending_(std::exchange(other.pending_, 0)) {
        other.storage_.clear();
    }
    Buffer& operator=(Buffer&& other) noexcept {
        if (this != &other) {
            storage_ = std::move(other.storage_);
            read_pos_ = std::exchange(other.read_pos_, 0);
            pending_ = std::exchange(other.pending_, 0);
            other.storage_.clear();
        }
        return *this;
    }

    /// Bytes available to the reader.
    [[nodiscard]] std::size_t size() const noexcept { return storage_.size() - read_pos_; }

    /// True when no bytes are available to the reader.
    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    /// Total bytes allocated, including the already-consumed prefix.
    [[nodiscard]] std::size_t capacity() const noexcept { return storage_.capacity(); }

    /// The readable region: parsed by the protocol layer, never written to.
    [[nodiscard]] std::span<const std::byte> readable() const noexcept {
        return std::span<const std::byte>{storage_.data() + read_pos_, size()};
    }

    /// Make room for at least `n` writable bytes and return that region.
    ///
    /// Reclaims the consumed prefix first, so a steady read/consume loop
    /// settles into reusing the same allocation.
    [[nodiscard]] std::span<std::byte> prepare(std::size_t n) {
        if (n > storage_.max_size() - size()) {
            throw std::length_error("Mira::Buffer::prepare: size exceeds max_size");
        }
        reclaim_if_worthwhile(n);
        const std::size_t write_pos = storage_.size();
        storage_.resize(write_pos + n);
        pending_ = n;
        return std::span<std::byte>{storage_.data() + write_pos, n};
    }

    /// Publish `n` bytes written into the span returned by `prepare()`.
    ///
    /// `n` may be smaller than what was prepared (a short read); the unused
    /// tail is released.
    void commit(std::size_t n) noexcept {
        const std::size_t unused = pending_ > n ? pending_ - n : 0;
        storage_.resize(storage_.size() - unused);
        pending_ = 0;
    }

    /// Drop `n` fully parsed bytes from the front of the readable region.
    void consume(std::size_t n) noexcept {
        read_pos_ += n < size() ? n : size();
        if (read_pos_ == storage_.size()) {
            storage_.clear();
            read_pos_ = 0;
        }
    }

    /// Append bytes directly, bypassing the prepare/commit pair.
    void append(std::span<const std::byte> bytes) {
        storage_.insert(storage_.end(), bytes.begin(), bytes.end());
    }

    /// Drop every byte and reset both cursors, keeping the allocation.
    void clear() noexcept {
        storage_.clear();
        read_pos_ = 0;
        pending_ = 0;
    }

    /// Pre-allocate room for `n` future bytes without growing `size()`.
    ///
    /// For a buffer whose final length is known up front (e.g. a request body
    /// whose Content-Length has been parsed), this turns the vector's doubling
    /// growth — which copies every byte ≈2× on the way — into one allocation
    /// plus the linear appends. No-op-safe: never shrinks.
    void reserve(std::size_t n) {
        storage_.reserve(n);
    }

private:
    /// Move unread bytes to the front when the consumed prefix is worth
    /// reclaiming — i.e. when it would save a reallocation.
    void reclaim_if_worthwhile(std::size_t incoming) {
        if (read_pos_ == 0) {
            return;
        }
        const bool would_grow = incoming > storage_.capacity() - storage_.size();
        if (!would_grow) {
            return;
        }
        const std::size_t unread = size();
        if (unread > 0) {
            std::copy(storage_.begin() + static_cast<std::ptrdiff_t>(read_pos_),
                      storage_.end(),
                      storage_.begin());
        }
        storage_.resize(unread);
        read_pos_ = 0;
    }

    std::vector<std::byte> storage_{};
    std::size_t read_pos_{0};
    std::size_t pending_{0};
};

}  // namespace Mira
