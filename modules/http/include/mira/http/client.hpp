#pragma once

#include "mira/core/stream.hpp"
#include "mira/http/response_parser.hpp"
#include "mira/http/serializer.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace Mira::http {

struct ClientOptions {
    Limits limits{};
    std::size_t read_chunk = 8 * 1024;
    /// 输入缓冲硬上限，与累计 body 限制独立；不足容纳一行时明确失败。
    std::size_t max_buffer_size = 64 * 1024;
    std::size_t max_informational_responses = 16;
    /// 一次交换（发送、1xx、最终响应及 body）的总时限，不逐 read 刷新。
    Clock::duration request_timeout = Clock::duration::zero();
};

/// 顺序 HTTP/1 客户端，不拥有 stream。stream 和本对象必须活到全部任务完成。
/// 仅在同一 event loop 使用；并发调用返回 invalid_argument。
/// 必须 read_body 到空 span 才可发下一请求。取消/错误后永不复用；调用者负责 close。
/// 不做 DNS、连接池、重试、重定向、解压、代理、CONNECT、Upgrade 或 Expect 握手。
/// 请求 body 为借用的已知长度 span；响应 body 为真正按需读取、零收集的 span。
template<BoundedStream Stream>
class ClientConnection {
public:
    explicit ClientConnection(Stream& stream, ClientOptions options = {})
        : stream_(&stream), options_(options), parser_(Method::get, options.limits) {}
    ClientConnection(const ClientConnection&) = delete;
    ClientConnection& operator=(const ClientConnection&) = delete;
    ~ClientConnection() {
        // The class documents "stream 和本对象必须活到全部任务完成" as a
        // borrow contract; dying mid-exchange means the in-flight coroutine
        // owns a parser and a stream pointer that are about to evaporate.
        // Terminate with a diagnosis, matching the library-wide contract
        // style (Task, tls::Stream) instead of dangling silently.
        if (busy_ || active_) {
            std::fputs("Mira: http::ClientConnection destroyed mid-exchange\n", stderr);
            std::abort();
        }
    }

    /// request 和 body 必须活到此任务完成；返回时最终响应头可用，但 body 尚未读取完。
    [[nodiscard]] Task<Result<void>>
    start(const Request& request, std::span<const std::byte> body = {}, OperationOptions io = {}) {
        if (busy_ || active_ || !reusable_) co_return fail(Errc::invalid_argument);
        if (options_.read_chunk == 0 || options_.max_buffer_size == 0 ||
            options_.request_timeout < Clock::duration::zero())
            co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        io_ = std::move(io);
        if (options_.request_timeout != Clock::duration::zero()) {
            const auto now = Clock::now();
            const auto deadline = options_.request_timeout > Clock::time_point::max() - now
                                      ? Clock::time_point::max()
                                      : now + options_.request_timeout;
            if (!io_.deadline || deadline < *io_.deadline) io_.deadline = deadline;
        }
        if (const auto error = budget_error()) co_return invalidate(error);
        Buffer head;
        const auto serialized = write_request_head(head, request, body.size(), options_.limits);
        if (!serialized) co_return fail(serialized.error());
        // 不预读、不过量分配；固定 reserve 避免 Buffer 几何扩容超过输入预算。
        if (input_.capacity() == 0) input_ = Buffer{options_.max_buffer_size};
        active_ = true;
        reusable_ = should_keep_alive(request);
        parser_.reset(request.method);
        eof_ = false;
        const auto sent = co_await write_all(*stream_, head.readable(), io_);
        if (!sent) co_return invalidate(sent.error());
        const auto sent_body = co_await write_all(*stream_, body, io_);
        if (!sent_body) co_return invalidate(sent_body.error());
        std::size_t informational = 0;
        for (;;) {
            auto step = co_await next();
            if (!step) co_return invalidate(step.error());
            if (*step != ParseStep::head)
                co_return invalidate(make_error_code(Errc::invalid_argument));
            if (parser_.response().status >= 200) break;
            if (++informational > options_.max_informational_responses) {
                co_return invalidate(make_error_code(Errc::limit_exceeded));
            }
            auto complete = parser_.parse(input_, eof_);
            if (!complete) co_return invalidate(complete.error());
            parser_.reset(request.method);
        }
        const auto& response = parser_.response();
        if (response.body_kind == BodyKind::close_delimited ||
            mentions(response.headers, "close") ||
            (response.version == Version::http_1_0 && !mentions(response.headers, "keep-alive"))) {
            reusable_ = false;
        }
        co_return Result<void>{};
    }

    /// 返回一个 body 片段；空片段表示完成。span 有效期至下次 start/read_body 或对象析构。
    /// 只读 body 完成后 trailers() 才完整；忽略 body 时应循环 drain 或关闭底层 stream。
    [[nodiscard]] Task<Result<std::span<const std::byte>>> read_body() {
        if (busy_ || !active_) co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        const auto step = co_await next();
        if (!step) co_return invalidate(step.error());
        if (*step == ParseStep::body) co_return parser_.body();
        if (*step != ParseStep::complete)
            co_return invalidate(make_error_code(Errc::invalid_argument));
        active_ = false;
        // 未发送下一请求却收到多余字节：不可将其误作下一次响应。
        if (!input_.empty()) reusable_ = false;
        co_return std::span<const std::byte>{};
    }

    [[nodiscard]] const Response& response() const noexcept { return parser_.response(); }
    [[nodiscard]] const HeaderMap& trailers() const noexcept { return parser_.trailers(); }
    [[nodiscard]] bool reusable() const noexcept { return reusable_ && !active_ && !busy_; }

private:
    struct Guard {
        bool& busy;
        explicit Guard(bool& value) : busy(value) { busy = true; }
        ~Guard() { busy = false; }
    };
    static bool mentions(const HeaderMap& headers, std::string_view wanted) {
        for (const auto& [name, text] : headers) {
            if (!HeaderMap::names_equal(name, "Connection")) continue;
            std::string_view rest{text};
            for (;;) {
                const auto comma = rest.find(',');
                auto token = rest.substr(0, comma);
                while (!token.empty() && (token.front() == ' ' || token.front() == '\t'))
                    token.remove_prefix(1);
                while (!token.empty() && (token.back() == ' ' || token.back() == '\t'))
                    token.remove_suffix(1);
                if (HeaderMap::names_equal(token, wanted)) return true;
                if (comma == std::string_view::npos) break;
                rest.remove_prefix(comma + 1);
            }
        }
        return false;
    }
    Error budget_error() const {
        if (io_.stop.stop_requested()) return make_error_code(Errc::cancelled);
        if (io_.deadline && Clock::now() >= *io_.deadline) return make_error_code(Errc::timed_out);
        return {};
    }
    std::unexpected<Error> invalidate(Error error) {
        reusable_ = false;
        active_ = false;
        return fail(error);
    }
    Task<Result<ParseStep>> next() {
        for (;;) {
            if (const auto error = budget_error()) co_return fail(error);
            const auto step = parser_.parse(input_, eof_);
            if (!step || *step != ParseStep::need_more) co_return step;
            if (input_.size() >= options_.max_buffer_size) co_return fail(Errc::limit_exceeded);
            const auto count =
                std::min(options_.read_chunk, options_.max_buffer_size - input_.size());
            const auto read = co_await stream_->read_some(input_.prepare(count), io_);
            if (!read) {
                input_.commit(0);
                if (read.error() != Errc::eof) co_return fail(read.error());
                eof_ = true;
            } else {
                input_.commit(*read);
                if (*read == 0) eof_ = true;
            }
        }
    }
    Stream* stream_;
    ClientOptions options_;
    ResponseParser parser_;
    Buffer input_;
    OperationOptions io_{};
    bool busy_{false};
    bool active_{false};
    bool reusable_{true};
    bool eof_{false};
};

}  // namespace Mira::http
