#pragma once

#include "mira/core/error.hpp"
#include "mira/transport/endpoint.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <chrono>
#include <cstddef>

namespace Mira::quic {

using Mira::Result;
/// Owned wire bytes, in the library-wide byte type: the transport layer
/// speaks `std::byte` end to end, and the C-API boundaries (ngtcp2/nghttp3)
/// are the only places allowed to reinterpret — and they do it inside the
/// engine's own translation units.
using Bytes = std::vector<std::byte>;

namespace detail {

/// QUIC v1 数据报的理论上限（varint length + 20 字节 AEAD tag 之内可达的最大 UDP 载荷）。
/// quic::Connection 与 http3::Connection 都以此为单包缓冲尺寸，定义在引擎头里收口，
/// 避免两份实现各自为政后悄然漂移。
inline constexpr std::size_t kMaxDatagram = 65536;

/// 引擎时间源：steady_clock 的单调纳秒。ngtcp2 的全部 now/expiry 均为此单位。
inline std::uint64_t now_ns() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          std::chrono::steady_clock::now().time_since_epoch())
                                          .count());
}

}  // namespace detail

/// ngtcp2 原生负码与引擎自有边界码共用的错误分类。
/// -100000 段为引擎自有码（见 engine.cpp），其余为 ngtcp2 原生码。
[[nodiscard]] Error quic_error(int code) noexcept;

/// 用加密安全随机源填充缓冲。失败返回 false，不填充部分数据。
/// 供 QUIC 之上的协议模块（HTTP/3 等）复用，避免它们直接依赖 TLS 后端。
[[nodiscard]] bool fill_random(std::uint8_t* destination, std::size_t length) noexcept;
struct Options {
    bool server = false;
    transport::Endpoint local;
    transport::Endpoint remote;
    std::string certificate_file;
    std::string private_key_file;
    std::string ca_file;
    std::string peer_name;
    std::string alpn = "h3";
    std::size_t max_buffered_bytes = 4 * 1024 * 1024;
    std::uint64_t max_streams = 64;
    std::uint64_t idle_timeout_ns = 30'000'000'000;
};
struct Event {
    enum class Kind { data, acknowledged, reset, closed } kind;
    std::int64_t stream_id;
    Bytes data;
    std::uint64_t value = 0;
    bool fin = false;
};
/// 单线程、无 socket 的 QUIC v1 状态机。时间为单调纳秒；调用方负责发包和到期唤醒。
/// 当前固定路径，不支持迁移、0-RTT 或 Retry 策略。OpenSSL ossl 后端属上游实验性支持。
class Engine {
public:
    static Result<Engine> client(Options options, std::uint64_t now);
    /// initial 是对端首个数据报；工厂解析连接 ID 并消费该包。
    /// 首个可见 CRYPTO 不是 offset 0 时可能返回 ERR_RETRY；监听器地址验证/Retry 策略尚未提供。
    static Result<Engine>
    accept(Options options, std::span<const std::byte> initial, std::uint64_t now);
    Engine(Engine&&) noexcept;
    Engine& operator=(Engine&&) noexcept;
    ~Engine();
    Result<void> receive(std::span<const std::byte> packet, std::uint64_t now);
    /// 返回一个拥有缓冲区的数据报；空表示暂时无包。应循环调用直到空或达到调度预算。
    Result<Bytes> poll(std::uint64_t now);
    Result<void> handle_expiry(std::uint64_t now);
    std::uint64_t expiry() const noexcept;
    bool handshake_complete() const noexcept;
    bool is_server() const noexcept;
    std::size_t write_capacity() const noexcept;
    std::uint64_t remote_bidi_stream_limit() const noexcept;
    bool closed() const noexcept;
    std::string negotiated_protocol() const;
    Result<std::int64_t> open_stream(bool unidirectional = false);
    /// 复制并持有数据直到真实 ACK 或 stream_close；达到总发送预算返回背压错误。
    Result<void> write(std::int64_t stream, std::span<const std::byte> bytes, bool fin);
    std::vector<Event> take_events();
    /// 应用实际消费后恢复接收窗口（不自动把 take_events 当作消费）。
    Result<void> consume(std::int64_t stream, std::size_t bytes);
    Result<void> cancel(std::int64_t stream, std::uint64_t application_error);
    Result<Bytes> close(std::uint64_t application_error, std::uint64_t now);

private:
    struct Impl;
    explicit Engine(std::unique_ptr<Impl> impl);
    static Result<Engine> create(Options, std::span<const std::byte>, std::uint64_t);
    std::unique_ptr<Impl> impl_;
};

}  // namespace Mira::quic
