#pragma once

#include "mira/ws/connection.hpp"

namespace Mira::ws {

/// Borrowed binary WebSocket-to-byte-stream adapter, including MQTT over WS.
/// Complete the handshake first and require the application's subprotocol
/// ("mqtt" for MQTT). Each write is one bounded binary message; reads may cross
/// message boundaries. At most one input frame is retained. Underlying frame
/// and message limits still apply. One reader and one writer may overlap.
/// Does not own the connection/transport; they must outlive all tasks. close()
/// or protocol/exception failure aborts a closable borrowed transport to wake
/// companion I/O; destruction alone does not close it.
template<BoundedStream Transport>
class ByteStream {
public:
    explicit ByteStream(Connection<Transport>& connection, std::size_t write_chunk = 16384)
        : connection_(connection), write_chunk_(write_chunk) {}
    ByteStream(const ByteStream&) = delete;
    ByteStream& operator=(const ByteStream&) = delete;
    ~ByteStream() {
        if (reading_ || writing_) std::terminate();
    }
    Task<Result<std::size_t>> read_some(std::span<std::byte> output, OperationOptions io = {}) {
        if (reading_) co_return fail(Mira::Errc::invalid_argument);
        Guard guard{*this, reading_};
        if (auto error = preflight(io)) co_return fail(error);
        if (output.empty()) co_return std::size_t{0};
        while (offset_ == pending_.size()) {
            pending_.clear();
            offset_ = 0;
            auto frame = co_await connection_.read_frame(io);
            if (!frame) { error_ = frame.error(); co_return fail(error_); }
            if (frame->opcode == Opcode::ping || frame->opcode == Opcode::pong) continue;
            if (frame->opcode == Opcode::close) { error_ = Mira::make_error_code(Mira::Errc::eof); co_return fail(error_); }
            if ((frame->opcode == Opcode::continuation && !fragmented_) ||
                (frame->opcode != Opcode::continuation && frame->opcode != Opcode::binary)) {
                error_ = make_error_code(Errc::protocol);
                connection_.abort(error_);
                co_return fail(error_);
            }
            fragmented_ = !frame->final;
            pending_ = std::move(frame->payload);
        }
        if (auto error = preflight(io)) co_return fail(error);
        const auto count = (std::min)(output.size(), pending_.size() - offset_);
        std::copy_n(pending_.data() + offset_, count, output.data());
        offset_ += count;
        co_return count;
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> input, OperationOptions io = {}) {
        if (writing_ || write_chunk_ == 0) co_return fail(Mira::Errc::invalid_argument);
        Guard guard{*this, writing_};
        if (auto error = preflight(io)) co_return fail(error);
        if (input.empty()) co_return std::size_t{0};
        const auto count = (std::min)(input.size(), write_chunk_);
        Frame frame{Opcode::binary, true, {input.begin(), input.begin() + static_cast<std::ptrdiff_t>(count)}};
        auto result = co_await connection_.send(std::move(frame), io);
        if (!result) { error_ = result.error(); co_return fail(error_); }
        if (error_) co_return fail(error_);
        co_return count;
    }
    void close() {
        error_ = Mira::make_error_code(Mira::Errc::cancelled);
        connection_.abort(error_);
    }
private:
    struct Guard {
        ByteStream& owner;
        bool& active;
        int exceptions = std::uncaught_exceptions();
        Guard(ByteStream& value, bool& direction) : owner(value), active(direction) { active = true; }
        ~Guard() {
            active = false;
            if (std::uncaught_exceptions() > exceptions) {
                owner.error_ = Mira::make_error_code(Mira::Errc::internal);
                try { owner.connection_.abort(owner.error_); } catch (...) {}
            }
        }
    };
    Error preflight(const OperationOptions& io) const noexcept {
        if (error_) return error_;
        if (io.stop.stop_requested()) return Mira::make_error_code(Mira::Errc::cancelled);
        if (io.deadline && Clock::now() >= *io.deadline) return Mira::make_error_code(Mira::Errc::timed_out);
        return {};
    }
    Connection<Transport>& connection_;
    std::size_t write_chunk_;
    std::vector<std::byte> pending_;
    std::size_t offset_ = 0;
    bool fragmented_ = false, reading_ = false, writing_ = false;
    Error error_;
};

} // namespace Mira::ws
