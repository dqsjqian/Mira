#pragma once

#include "mira/tls/context.hpp"
#include "mira/tls/error.hpp"

#include <cstddef>
#include <memory>
#include <span>
#include <string_view>

namespace Mira::tls {

/// Synchronous memory-BIO state machine; it holds no socket and performs no
/// asynchronous I/O. Calls on a single instance must be serialized; after each
/// step, drain the ciphertext first, then supply whatever input is needed.
class Engine {
public:
    enum class Status { complete, want_input, want_output, eof };
    struct Step {
        Status status;
        std::size_t transferred = 0;
    };
    static constexpr std::size_t buffer_capacity = 64 * 1024;

    [[nodiscard]] static Result<Engine> create(const Context& context,
                                               std::string_view peer_name = {});
    Engine(Engine&&) noexcept;
    Engine& operator=(Engine&&) noexcept;
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    ~Engine();

    [[nodiscard]] Result<Step> handshake();
    [[nodiscard]] Result<Step> read(std::span<std::byte> destination);
    [[nodiscard]] Result<Step> write(std::span<const std::byte> source);
    /// complete only means our close_notify has been generated; the caller must
    /// still drain the ciphertext.
    [[nodiscard]] Result<Step> shutdown();
    /// Empty before the handshake completes or when no ALPN was negotiated; the
    /// view is owned by this Engine and is invalidated on destruction.
    [[nodiscard]] std::string_view negotiated_protocol() const noexcept;

    [[nodiscard]] std::size_t input_capacity() const noexcept;
    [[nodiscard]] std::size_t output_pending() const noexcept;
    [[nodiscard]] Result<std::size_t> feed(std::span<const std::byte> ciphertext);
    /// After a failure the already-generated ciphertext (such as a fatal alert)
    /// can still be collected; the SSL I/O is never driven again.
    [[nodiscard]] Result<std::size_t> drain(std::span<std::byte> ciphertext);
    /// After an underlying failure or a cancelled drive the state machine must be
    /// invalidated; application data must not be retried.
    void invalidate() noexcept;

private:
    struct Impl;
    explicit Engine(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

}  // namespace Mira::tls
