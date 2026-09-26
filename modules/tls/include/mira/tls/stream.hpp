#pragma once

#include "mira/core/stream.hpp"
#include "mira/tls/engine.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <utility>

namespace Mira::tls {

/// 泛型异步 TLS 包装器，不拥有底层流，也不关闭底层连接。
/// Context 可在 create 后销毁；底层流、Stream 和传入 span 的存储必须存活到
/// 返回的惰性 Task 完成或被安全销毁。Task 未结束时不可移动/析构 Stream。
/// 同一实例同时只允许一个操作（包括读写），重叠操作返回 operation_in_progress。
/// 已开始的操作被取消/抛异常或发生致命错误后不可复用；析构不会发送 close_notify。
/// 不能绕过本包装器直接操作底层流。跨线程驱动还须遵守底层流的线程约束。
///
/// 底层流必须是 `BoundedStream`。一次 TLS 操作会对底层做任意多次读写，而只有
/// 真正在等待的那一层能停止等待；底层若无法承载 `OperationOptions`，本包装器
/// 就兑现不了取消与截止时间，handshake 会变成一个随时可能挂死的等待。
///
/// `options` 原样转发给**每一次**底层读写。这正是绝对截止时间的含义：没有任何
/// 一层需要扣减已耗时间，一个 `{.deadline = T}` 自然表示「整个 handshake / 读 /
/// 写必须在 T 之前结束」。换成时长的话每层都得自己做减法，而且都会算错。
template<BoundedStream Underlying>
class Stream {
public:
    [[nodiscard]] static Result<Stream>
    create(Underlying& underlying, const Context& context, std::string_view peer_name = {}) {
        auto engine = Engine::create(context, peer_name);
        if (!engine) return fail(engine.error());
        return Stream(std::make_unique<State>(underlying, std::move(*engine)));
    }

    Stream(Stream&&) noexcept = default;
    Stream& operator=(Stream&&) noexcept = default;
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    /// 断言即契约：析构时仍有未完成操作意味着协程帧里还挂着对 State 的
    /// 借用，继续运行就是 use-after-free。与其无声 UB，不如当场诊断终止
    /// ——与 Task 析构契约同款（std::thread 的 join 契约亦是如此）。
    ~Stream() {
        if (state_ && state_->active.test(std::memory_order_acquire)) {
            std::fprintf(stderr,
                         "Mira::tls::Stream destroyed with an operation still in flight; "
                         "await (or destroy) the pending Task before destroying the Stream.\n");
            std::terminate();
        }
    }

    [[nodiscard]] Task<Result<void>> handshake(OperationOptions options = {}) {
        return run_void(state_.get(), Operation::handshake, std::move(options));
    }

    [[nodiscard]] Task<Result<std::size_t>> read_some(std::span<std::byte> destination,
                                                      OperationOptions options = {}) {
        return run(state_.get(), Operation::read, destination, {}, std::move(options));
    }

    [[nodiscard]] Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                                       OperationOptions options = {}) {
        return run(state_.get(), Operation::write, {}, source, std::move(options));
    }

    /// 发送并 flush 本方 close_notify；不等待对方通知，不代表双向关闭完成。
    /// 成功后只能再次 shutdown，不能继续应用读写；底层流由调用方关闭。
    [[nodiscard]] Task<Result<void>> shutdown(OperationOptions options = {}) {
        return run_void(state_.get(), Operation::shutdown, std::move(options));
    }

    /// 仅在没有未完成操作时调用；返回视图在本 Stream 析构后失效。
    [[nodiscard]] std::string_view negotiated_protocol() const noexcept {
        return state_ ? state_->engine.negotiated_protocol() : std::string_view{};
    }

private:
    enum class Operation { handshake, read, write, shutdown };
    struct State {
        Underlying* underlying;
        Engine engine;
        std::atomic_flag active = ATOMIC_FLAG_INIT;
        std::array<std::byte, 16 * 1024> buffer{};
        State(Underlying& stream, Engine value) : underlying(&stream), engine(std::move(value)) {}
    };

    struct OperationGuard {
        State& state;
        bool acquired;
        bool completed = false;
        explicit OperationGuard(State& value)
            : state(value), acquired(!state.active.test_and_set(std::memory_order_acquire)) {}
        ~OperationGuard() {
            if (acquired) {
                // 取消可能发生在密文仅部分写出之后，不能再驱动该 SSL 对象。
                if (!completed) state.engine.invalidate();
                state.active.clear(std::memory_order_release);
            }
        }
    };

    explicit Stream(std::unique_ptr<State> state) : state_(std::move(state)) {}

    static Task<Result<void>> flush(State& state, const OperationOptions& options) {
        for (;;) {
            auto drained = state.engine.drain(state.buffer);
            if (!drained) co_return fail(drained.error());
            if (*drained == 0) co_return Result<void>{};
            std::size_t offset = 0;
            while (offset < *drained) {
                auto written = co_await state.underlying->write_some(
                    std::span<const std::byte>(state.buffer).subspan(offset, *drained - offset),
                    options);
                if (!written || *written == 0 || *written > *drained - offset) {
                    state.engine.invalidate();
                    if (!written) co_return fail(written.error());
                    co_return fail(make_error_code(Errc::protocol_error));
                }
                offset += *written;
            }
        }
    }

    static Task<Result<void>> receive(State& state, const OperationOptions& options) {
        const auto capacity = std::min(state.buffer.size(), state.engine.input_capacity());
        if (capacity == 0) {
            state.engine.invalidate();
            co_return fail(make_error_code(Errc::protocol_error));
        }
        auto received = co_await state.underlying->read_some(
            std::span<std::byte>(state.buffer).first(capacity), options);
        if (!received || *received == 0 || *received > capacity) {
            state.engine.invalidate();
            if ((!received && received.error() == Mira::Errc::eof) ||
                (received && *received == 0))
                co_return fail(make_error_code(Errc::truncated));
            if (!received) co_return fail(received.error());
            co_return fail(make_error_code(Errc::protocol_error));
        }
        auto fed = state.engine.feed(std::span<const std::byte>(state.buffer).first(*received));
        if (!fed || *fed != *received) {
            state.engine.invalidate();
            if (!fed) co_return fail(fed.error());
            co_return fail(make_error_code(Errc::protocol_error));
        }
        co_return Result<void>{};
    }

    static Task<Result<std::size_t>> drive(State& state,
                                           Operation operation,
                                           std::span<std::byte> destination,
                                           std::span<const std::byte> source,
                                           const OperationOptions& options) {
        for (;;) {
            Result<Engine::Step> step = fail(make_error_code(Errc::invalid_state));
            switch (operation) {
            case Operation::handshake:
                step = state.engine.handshake();
                break;
            case Operation::read:
                step = state.engine.read(destination);
                break;
            case Operation::write:
                step = state.engine.write(source);
                break;
            case Operation::shutdown:
                step = state.engine.shutdown();
                break;
            }
            if (!step) {
                const auto error = step.error();
                if (error != make_error_code(Errc::invalid_state)) {
                    // 致命错误后仅发送已生成的 alert，不能再调用 SSL I/O。
                    // 告警是收尾动作，仍受同一截止时间约束，不另给预算。
                    try {
                        (void)co_await flush(state, options);
                    } catch (...) {
                        // 告警发送失败不能覆盖最初的 TLS 错误。
                    }
                }
                co_return fail(error);
            }
            auto flushed = co_await flush(state, options);
            if (!flushed) co_return fail(flushed.error());
            switch (step->status) {
            case Engine::Status::complete:
                co_return step->transferred;
            case Engine::Status::eof:
                co_return fail(Mira::Errc::eof);
            case Engine::Status::want_output:
                break;
            case Engine::Status::want_input:
                auto received = co_await receive(state, options);
                if (!received) co_return fail(received.error());
                break;
            }
        }
    }

    static Task<Result<std::size_t>> run(State* state,
                                         Operation operation,
                                         std::span<std::byte> destination,
                                         std::span<const std::byte> source,
                                         OperationOptions options) {
        if (!state) co_return fail(make_error_code(Errc::invalid_state));
        OperationGuard guard(*state);
        if (!guard.acquired) co_return fail(make_error_code(Errc::operation_in_progress));
        auto result = co_await drive(*state, operation, destination, source, options);
        guard.completed = true;
        co_return result;
    }

    static Task<Result<void>>
    run_void(State* state, Operation operation, OperationOptions options) {
        auto result = co_await run(state, operation, {}, {}, std::move(options));
        if (!result) co_return fail(result.error());
        co_return Result<void>{};
    }

    std::unique_ptr<State> state_;
};

}  // namespace Mira::tls
