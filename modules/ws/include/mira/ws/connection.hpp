#pragma once

#include "mira/core/stream.hpp"
#include "mira/crypto/crypto.hpp"
#include "mira/ws/handshake.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <exception>

namespace Mira::ws {

// Borrows the transport; one reader and one writer may overlap after handshake.
// The transport must support a simultaneous read/write (plain TCP does); a TLS
// adapter may impose a stricter contract. Handshake and close are exclusive.
// Automatic pong/close replies are serialized behind an active writer, with
// at most one pending pong and one pending close. No unbounded output queue.
// Messages are bounded; compression, subprotocols and H2/H3 CONNECT are absent.
// Complete TLS handshake first. Do not mix read_frame/read_message mid-fragment.
// Keep this object and its transport alive until every operation completes.
template<AsyncStream Transport>
class Connection {
public:
    Connection(Transport& transport, Role role, Limits limits = {})
        : transport_(&transport), role_(role), limits_(limits), incoming_(role, limits),
          outgoing_(role == Role::client ? Role::server : Role::client, limits) {}
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    ~Connection() {
        if (busy_ || reading_ || writing_) {
            std::fputs("Mira::ws::Connection destroyed with pending operation\n", stderr);
            std::abort();
        }
    }
    bool closed() const noexcept { return failed_ || (close_sent_ && close_received_); }

    Task<Result<void>> handshake(std::string host = {}, std::string target = "/",
                                  OperationOptions options = {}) {
        if (busy_ || ready_ || failed_) co_return fail(Mira::Errc::invalid_argument);
        Guard guard{*this};
        auto checked = check_options(options);
        if (!checked) co_return checked;
        std::string key;
        if (role_ == Role::client) {
            if (host.size() > limits_.max_handshake || target.size() > limits_.max_handshake)
                co_return terminate(make_error_code(Mira::Errc::limit_exceeded));
            auto request = client_handshake(host, target);
            if (!request) co_return terminate(request.error());
            if (request->request.size() > limits_.max_handshake)
                co_return terminate(make_error_code(Mira::Errc::limit_exceeded));
            key = std::move(request->key);
            auto sent = co_await write_bytes(std::as_bytes(std::span(request->request.data(), request->request.size())), options);
            if (!sent) co_return sent;
        }
        std::string head;
        while (!head.ends_with("\r\n\r\n")) {
            if (head.size() == limits_.max_handshake) co_return terminate(make_error_code(Mira::Errc::limit_exceeded));
            std::array<std::byte, 1> byte{};
            auto n = co_await read_bytes(byte, options);
            if (!n) co_return fail(n.error());
            head.push_back(static_cast<char>(std::to_integer<unsigned char>(byte[0])));
        }
        if (role_ == Role::server) {
            auto response = server_handshake(head, limits_);
            if (!response) co_return terminate(response.error());
            auto sent = co_await write_bytes(std::as_bytes(std::span(response->data(), response->size())), options);
            if (!sent) co_return sent;
        } else {
            auto validated = validate_server_handshake(head, key, limits_);
            if (!validated) co_return terminate(validated.error());
        }
        ready_ = true;
        co_return Result<void>{};
    }

    Task<Result<void>> send(Frame frame, OperationOptions options = {}) {
        if (busy_ || writing_) co_return fail(Mira::Errc::invalid_argument);
        DirectionGuard guard{*this, writing_};
        auto sent = co_await send_locked(frame, options);
        if (!sent) co_return sent;
        co_return co_await flush_control(options);
    }

    Task<Result<Frame>> read_frame(OperationOptions options = {}) {
        if (busy_ || reading_) co_return fail(Mira::Errc::invalid_argument);
        DirectionGuard guard{*this, reading_};
        co_return co_await read_locked(options);
    }

    Task<Result<Frame>> read_message(OperationOptions options = {}) {
        if (busy_ || reading_) co_return fail(Mira::Errc::invalid_argument);
        DirectionGuard guard{*this, reading_};
        Frame message;
        bool started = false;
        for (;;) {
            auto frame = co_await read_locked(options);
            if (!frame) co_return fail(frame.error());
            if (frame->opcode == Opcode::close) co_return std::move(*frame);
            if (frame->opcode == Opcode::ping || frame->opcode == Opcode::pong) continue;
            if (!started) { message.opcode = frame->opcode; started = true; }
            if (frame->payload.size() > limits_.max_message - message.payload.size()) {
                terminate(make_error_code(Mira::Errc::limit_exceeded));
                co_return fail(Mira::Errc::limit_exceeded);
            }
            message.payload.insert(message.payload.end(), frame->payload.begin(), frame->payload.end());
            if (frame->final) co_return message;
        }
    }

    // Send close and await the peer close; callers should supply a deadline.
    Task<Result<void>> close(std::uint16_t code = 1000, OperationOptions options = {}) {
        if (busy_ || reading_ || writing_) co_return fail(Mira::Errc::invalid_argument);
        Guard guard{*this};
        if (failed_) co_return fail(make_error_code(Errc::closed));
        if (!close_sent_) {
            auto payload = close_payload(code);
            if (!payload) co_return fail(payload.error());
            Frame frame{Opcode::close, true, std::move(*payload)};
            auto sent = co_await send_locked(frame, options);
            if (!sent) co_return sent;
        }
        while (!close_received_) {
            auto frame = co_await read_locked(options);
            if (!frame) co_return fail(frame.error());
        }
        co_return Result<void>{};
    }

private:
    struct Guard {
        Connection& owner;
        int exceptions = std::uncaught_exceptions();
        explicit Guard(Connection& value) : owner(value) { owner.busy_ = true; }
        ~Guard() {
            owner.busy_ = false;
            if (std::uncaught_exceptions() > exceptions) {
                owner.failed_ = true;
                owner.incoming_.reset(); owner.outgoing_.reset();
            }
        }
    };
    struct DirectionGuard {
        Connection& owner;
        bool& flag;
        int exceptions = std::uncaught_exceptions();
        DirectionGuard(Connection& value, bool& direction) : owner(value), flag(direction) { flag = true; }
        ~DirectionGuard() {
            flag = false;
            if (std::uncaught_exceptions() > exceptions) owner.failed_ = true;
        }
    };
    Task<Result<void>> flush_control(OperationOptions options) {
        if (pending_pong_) {
            auto frame = std::move(*pending_pong_);
            pending_pong_.reset();
            auto sent = co_await send_locked(frame, options, true);
            if (!sent) co_return sent;
        }
        if (pending_close_) {
            auto frame = std::move(*pending_close_);
            pending_close_.reset();
            if (!close_sent_) co_return co_await send_locked(frame, options, true);
        }
        co_return Result<void>{};
    }
    Task<Result<void>> control_reply(Frame frame, OperationOptions options) {
        if (writing_) {
            if (frame.opcode == Opcode::pong) pending_pong_ = std::move(frame);
            else pending_close_ = std::move(frame);
            co_return Result<void>{};
        }
        DirectionGuard guard{*this, writing_};
        co_return co_await send_locked(frame, options, true);
    }
    Result<void> check_options(OperationOptions options) const {
        if constexpr (!BoundedStream<Transport>) {
            if (options.stop.stop_possible() || options.deadline) return fail(Mira::Errc::not_supported);
        }
        if (options.stop.stop_requested()) return fail(Mira::Errc::cancelled);
        if (options.deadline && *options.deadline <= Clock::now()) return fail(Mira::Errc::timed_out);
        return {};
    }
    Result<void> terminate(Error error) {
        failed_ = true;
        incoming_.reset(); outgoing_.reset(); begin_ = end_ = 0;
        if constexpr (ClosableStream<Transport>) transport_->close();
        return fail(error);
    }
    Task<Result<std::size_t>> read_bytes(std::span<std::byte> bytes, OperationOptions options) {
        Result<std::size_t> result;
        if constexpr (BoundedStream<Transport>) result = co_await transport_->read_some(bytes, options);
        else result = co_await transport_->read_some(bytes);
        if (!result || *result == 0 || *result > bytes.size()) {
            auto error = !result ? result.error() : make_error_code(Errc::abnormal_close);
            if (error == make_error_code(Mira::Errc::eof)) error = make_error_code(Errc::abnormal_close);
            terminate(error);
            co_return fail(error);
        }
        co_return result;
    }
    Task<Result<void>> write_bytes(std::span<const std::byte> bytes, OperationOptions options) {
        while (!bytes.empty()) {
            Result<std::size_t> n;
            if constexpr (BoundedStream<Transport>) n = co_await transport_->write_some(bytes, options);
            else n = co_await transport_->write_some(bytes);
            if (!n || *n == 0 || *n > bytes.size()) {
                auto error = !n ? n.error() : make_error_code(Errc::abnormal_close);
                co_return terminate(error);
            }
            bytes = bytes.subspan(*n);
        }
        co_return Result<void>{};
    }
    Task<Result<void>> send_locked(const Frame& frame, OperationOptions options, bool reply = false) {
        const bool closing_pong = close_sent_ && !close_received_ && reply && frame.opcode == Opcode::pong;
        if (!ready_ || failed_ || (close_sent_ && !closing_pong) || (close_received_ && !reply))
            co_return fail(make_error_code(Errc::closed));
        auto checked = check_options(options);
        if (!checked) co_return checked;
        std::optional<std::array<std::byte, 4>> mask;
        if (role_ == Role::client) {
            mask.emplace();
            auto random = crypto::random_bytes(*mask);
            if (!random) co_return terminate(random.error());
        }
        auto wire = serialize(frame, role_, mask, limits_);
        if (!wire) co_return fail(wire.error());
        if (!closing_pong) {
            auto valid = outgoing_.feed(*wire);
            if (!valid) co_return terminate(valid.error());
        }
        auto sent = co_await write_bytes(*wire, options);
        if (!sent) co_return sent;
        if (failed_) co_return fail(make_error_code(Errc::closed));
        if (frame.opcode == Opcode::close) close_sent_ = true;
        co_return Result<void>{};
    }
    Task<Result<Frame>> read_locked(OperationOptions options) {
        if (!ready_ || failed_ || close_received_) co_return fail(make_error_code(Errc::closed));
        auto checked = check_options(options);
        if (!checked) co_return fail(checked.error());
        for (;;) {
            if (begin_ == end_) {
                auto n = co_await read_bytes(buffer_, options);
                if (!n) co_return fail(n.error());
                begin_ = 0; end_ = *n;
            }
            auto parsed = incoming_.feed(std::span<const std::byte>(buffer_).subspan(begin_, end_ - begin_));
            if (!parsed) {
                auto error = parsed.error();
                if (!close_sent_) {
                    std::uint16_t code = error == make_error_code(Errc::invalid_utf8) ? 1007 :
                        error == make_error_code(Mira::Errc::limit_exceeded) ? 1009 : 1002;
                    auto payload = close_payload(code);
                    Frame close_frame{Opcode::close, true, std::move(*payload)};
                    if (!writing_) {
                        DirectionGuard writer{*this, writing_};
                        auto sent = co_await send_locked(close_frame, options);
                        (void)sent;
                    }
                }
                terminate(error);
                co_return fail(error);
            }
            begin_ += parsed->consumed;
            if (!parsed->frame) continue;
            auto frame = std::move(*parsed->frame);
            if (frame.opcode == Opcode::ping) {
                Frame pong{Opcode::pong, true, frame.payload};
                auto sent = co_await control_reply(std::move(pong), options);
                if (!sent) co_return fail(sent.error());
            } else if (frame.opcode == Opcode::close) {
                close_received_ = true;
                if (!close_sent_) {
                    auto reply = frame;
                    if (role_ == Role::server && reply.payload.size() >= 2 &&
                        reply.payload[0] == std::byte{3} && reply.payload[1] == std::byte{242})
                        reply.payload = *close_payload(1000);
                    auto sent = co_await control_reply(std::move(reply), options);
                    if (!sent) co_return fail(sent.error());
                }
            }
            co_return frame;
        }
    }
    Transport* transport_;
    Role role_;
    Limits limits_;
    FrameParser incoming_;
    FrameParser outgoing_;
    std::array<std::byte, 4096> buffer_{};
    std::size_t begin_ = 0, end_ = 0;
    std::optional<Frame> pending_pong_, pending_close_;
    bool reading_ = false, writing_ = false;
    bool busy_ = false, ready_ = false, failed_ = false;
    bool close_sent_ = false, close_received_ = false;
};
} // namespace Mira::ws
