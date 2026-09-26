#pragma once

#include "mira/core/stream.hpp"
#include "mira/http2/session.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace Mira::http2 {

// 适配器不拥有底层流；底层流和 Connection 必须存活且保持地址直到任务结束。
// 同一实例只允许一个未完成操作，包括挂起期间；此时不得访问 session()，
// 不得从其他任务重叠调用 read/flush/pump，也不可移动或析构 Connection。
// pump 一次执行输出、一次输入和协议应答输出。调用方轮询各 stream
// 并 take_body，驱动所有并发请求；不在单个请求上串行阻塞。
// output() 的 vector 由 flush 协程帧独立持有，跨 write_all 挂起不借用引擎内存。
// I/O 取消/deadline 终止连接；单流取消请用 Session::cancel。
template<BoundedStream Transport>
class Connection {
public:
    Connection(Transport& transport, Session session)
        : transport_(&transport), session_(std::move(session)) {}

    // 契约与 tls::Stream、http::ClientConnection 同款：带未完成 I/O 析构
    // 意味着挂起的协程帧还持有 transport_ 与引擎借用，继续运行就是
    // use-after-free。与其无声 UB，不如当场诊断终止。
    ~Connection() {
        if (in_flight_) {
            std::fputs("Mira::http2::Connection destroyed with an operation still in flight\n",
                       stderr);
            std::abort();
        }
    }

    Session& session() noexcept { return session_; }
    const Session& session() const noexcept { return session_; }

    Task<Result<void>> flush(OperationOptions options = {}) {
        if (in_flight_) co_return fail(Errc::invalid_argument);
        Guard guard{in_flight_};
        co_return co_await flush_locked(options);
    }

    Task<Result<void>> read(OperationOptions options = {}) {
        if (in_flight_) co_return fail(Errc::invalid_argument);
        Guard guard{in_flight_};
        co_return co_await read_locked(options);
    }

    Task<Result<void>> pump(OperationOptions options = {}) {
        if (in_flight_) co_return fail(Errc::invalid_argument);
        Guard guard{in_flight_};
        auto result = co_await flush_locked(options);
        if (!result) co_return result;
        result = co_await read_locked(options);
        if (!result) co_return result;
        co_return co_await flush_locked(options);
    }

private:
    // 以下三个 *_locked 假定调用方已持有 in-flight 防护（公共入口或 pump）。
    Task<Result<void>> flush_locked(OperationOptions options) {
        while (session_.wants_write()) {
            auto bytes = session_.output();
            if (!bytes) co_return fail(bytes.error());
            if (bytes->empty()) break;
            auto result = co_await write_all(*transport_, *bytes, options);
            if (!result) {
                session_.close(result.error());
                co_return fail(result.error());
            }
        }
        co_return Result<void>{};
    }

    Task<Result<void>> read_locked(OperationOptions options) {
        std::array<std::byte, 16384> bytes{};
        auto result = co_await transport_->read_some(bytes, options);
        if (!result || *result == 0) {
            auto error = result ? make_error_code(Errc::eof) : result.error();
            session_.close(error);
            co_return fail(error);
        }
        co_return session_.receive(std::span<const std::byte>(bytes.data(), *result));
    }

    // co_await 之间没有栈展开兜底，提前 co_return 会跳过顺序复位代码，
    // 所以用 RAII 守卫保证任何退出路径都清掉 in-flight 标记。
    struct Guard {
        bool& flag;
        explicit Guard(bool& f) noexcept : flag(f) { flag = true; }
        ~Guard() { flag = false; }
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
    };

    Transport* transport_;
    Session session_;
    bool in_flight_ = false;  // 一个未完成的 flush/read/pump 挂起期间为 true
};

} // namespace Mira::http2
