#pragma once
#include "mira/core/error.hpp"
#include "mira/http2/headers.hpp"
#include "mira/quic/engine.hpp"

#include <utility>

namespace Mira::http3 {
using Mira::Result;
/// HTTP/2 与 HTTP/3 的头部区块语义相同（HPACK/QPACK 压缩同一份字段序列模型），
/// 所以共用同一个头部列表类型：换传输层不需要重写头部处理代码。
using Mira::http2::Header;
using Mira::http2::Headers;

/// nghttp3 原生负码与引擎自有边界码共用的错误分类。
/// -100000 段为引擎自有码，其余为 nghttp3 原生码。
[[nodiscard]] Error http3_error(int code) noexcept;
struct Limits {
    std::size_t max_header_bytes = 64 * 1024;
    std::size_t max_headers = 128;
    std::size_t max_buffered_body = 4 * 1024 * 1024;
    std::size_t max_events = 4096;
    std::size_t max_streams = 64;
};
struct Event {
    enum class Kind { headers, body, end, reset, goaway } kind;
    std::int64_t stream_id;
    Headers fields;
    quic::Bytes data;
    std::uint64_t error_code = 0;
};
/// 拥有 QUIC 引擎的 HTTP/3 状态机；仅 h3 ALPN、无 0-RTT/server push/扩展 CONNECT。
/// 输入 body 分片交付并通过 consume 恢复窗口；当前输出 body 复制有界整块，非异步 body source。
class Engine {
public:
    static Result<Engine> create(quic::Engine transport, bool server, Limits limits = {});
    Engine(Engine&&) noexcept;
    Engine& operator=(Engine&&) noexcept;
    ~Engine();
    Result<void> receive(std::span<const std::byte> datagram, std::uint64_t now);
    Result<quic::Bytes> poll(std::uint64_t now);
    Result<void> handle_expiry(std::uint64_t now);
    std::uint64_t expiry() const noexcept;
    bool ready() const noexcept;
    bool peer_goaway() const noexcept;
    bool is_server() const noexcept;
    bool closed() const noexcept;
    Result<std::int64_t> request(const Headers& fields, std::span<const std::byte> body = {});
    Result<void>
    respond(std::int64_t stream, const Headers& fields, std::span<const std::byte> body = {});
    std::vector<Event> take_events();
    Result<void> consume(std::int64_t stream, std::size_t bytes);
    Result<void> cancel(std::int64_t stream);
    /// 两阶段 GOAWAY：notice 后由调用方等待合适的 RTT 再调用 shutdown。
    Result<void> shutdown_notice();
    Result<void> shutdown();
    Result<quic::Bytes> close(std::uint64_t code, std::uint64_t now);

private:
    struct Impl;
    explicit Engine(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}  // namespace Mira::http3
