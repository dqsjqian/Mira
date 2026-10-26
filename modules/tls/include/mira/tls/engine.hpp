#pragma once

#include "mira/tls/context.hpp"
#include "mira/tls/error.hpp"
#include "mira/core/resource_budget.hpp"

#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

namespace Mira::tls {

/// 不透明、单次移动的 TLS 1.3 票据；绑定原客户端 Context 快照及对端名称。
/// 不支持导出、复制或跨进程恢复；保存票据不会执行后台 I/O。
class SessionTicket {
public:
    SessionTicket(SessionTicket&&) noexcept;
    SessionTicket& operator=(SessionTicket&&) noexcept;
    SessionTicket(const SessionTicket&) = delete;
    SessionTicket& operator=(const SessionTicket&) = delete;
    ~SessionTicket();
private:
    struct Impl;
    explicit SessionTicket(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
    friend class Engine;
};

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

    static constexpr std::size_t max_early_data_bytes = 16 * 1024;
    // 默认只预留两个 BIO；早期载荷按需额外预留至多 16 KiB，完成或失效时释放。
    // 不包含 OpenSSL 内部分配或 RSS。
    static constexpr std::size_t reserved_buffer_bytes = 2 * buffer_capacity;
    [[nodiscard]] static Result<Engine> create(const Context& context,
                                               std::string_view peer_name = {},
                                               std::optional<ResourceBudget> budget = {});
    Engine(Engine&&) noexcept;
    Engine& operator=(Engine&&) noexcept;
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    ~Engine();

    [[nodiscard]] Result<Step> handshake();
    /// 完成握手并发送至多 16 KiB 安全载荷；首次调用复制载荷以保持重试字节不变。
    /// 显式 replay_safe 必填。仅明确拒绝或没有兼容票据时在同连接 1-RTT 发送一次。
    /// 取消、超时、传输及认证失败不得重试；complete 后再次调用返回 invalid_state。
    /// WANT 重试期间须传入同样的载荷和策略，不能交替调用 handshake/read/write。
    [[nodiscard]] Result<Step> handshake_early_data(std::span<const std::byte> source,
                                                   EarlyDataPolicy policy);
    /// 握手前消费票据。过期票据被消费但忽略，回到完整握手；身份/配置不匹配拒绝。
    [[nodiscard]] Result<void> resume(SessionTicket ticket);
    /// 完成读操作处理 NewSessionTicket 后可取一次；尚无票据时返回空 optional。
    /// 显式 CA 且没有 mTLS/CRL/OCSP 的客户端才允许恢复；不导出 TLS 1.2 会话。
    [[nodiscard]] Result<std::optional<SessionTicket>> take_session();
    [[nodiscard]] EarlyDataStatus early_data_status() const noexcept;
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
    [[nodiscard]] Result<Step> drive_handshake();
    std::unique_ptr<Impl> impl_;
};

}  // namespace Mira::tls
