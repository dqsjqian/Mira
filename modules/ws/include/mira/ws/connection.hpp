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
// Messages are bounded; negotiated compression and subprotocols are opt-in.
// HTTP/2 and HTTP/3 Extended CONNECT are separate protocols, not handled here.
// Complete TLS handshake first. Do not mix read_frame/read_message mid-fragment.
// Keep this object and its transport alive until every operation completes.
template<AsyncStream Transport>
class Connection {
public:
    Connection(Transport& transport, Role role, Limits limits = {}, HandshakeOptions handshake_options = {})
        : transport_(&transport), role_(role), limits_(limits),
          handshake_options_(std::move(handshake_options)), incoming_(role, limits),
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
    std::string_view subprotocol() const noexcept { return negotiated_.subprotocol; }
    const CompressionParameters& compression_parameters() const noexcept { return negotiated_.compression; }

    // Trusted handoff from an HTTP/2 or HTTP/3 Extended CONNECT driver. That
    // driver must already have validated SETTINGS, :protocol, version and
    // extension response parameters for this exact stream. This performs no
    // HTTP I/O and is not a generic bypass for the HTTP/1 upgrade handshake.
    Result<void> adopt_extended_connect(std::string_view protocol, unsigned status,
                                       Negotiated negotiated = {}) {
        if (busy_ || ready_ || failed_ || reading_ || writing_ ||
            protocol != "websocket" || status < 200 || status >= 300)
            return fail(Mira::Errc::invalid_argument);
        const auto& selected = negotiated.subprotocol;
        if ((selected.empty() && handshake_options_.require_subprotocol) ||
            (!selected.empty() && std::find(handshake_options_.subprotocols.begin(),
                handshake_options_.subprotocols.end(), selected) == handshake_options_.subprotocols.end()) ||
            (negotiated.compression.enabled && !handshake_options_.compression.enabled))
            return fail(make_error_code(Errc::invalid_handshake));
        Guard guard{*this};
        auto configured = configure_extensions(negotiated);
        if (!configured) return terminate(configured.error());
        negotiated_ = std::move(negotiated);
        ready_ = true;
        return {};
    }

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
            auto request = client_handshake(host, target, handshake_options_, limits_);
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
            auto response = negotiate_server_handshake(head, handshake_options_, limits_);
            if (!response) co_return terminate(response.error());
            auto configured = configure_extensions(response->negotiated);
            if (!configured) co_return terminate(configured.error());
            auto sent = co_await write_bytes(std::as_bytes(std::span(response->response.data(), response->response.size())), options);
            if (!sent) co_return sent;
            negotiated_ = std::move(response->negotiated);
        } else {
            auto validated = negotiate_client_handshake(head, key, handshake_options_, limits_);
            if (!validated) co_return terminate(validated.error());
            auto configured = configure_extensions(*validated);
            if (!configured) co_return terminate(configured.error());
            negotiated_ = std::move(*validated);
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
            if (!frame) {
                if (started) static_cast<void>(terminate(frame.error()));
                co_return fail(frame.error());
            }
            if (frame->opcode == Opcode::close) co_return std::move(*frame);
            if (frame->opcode == Opcode::ping || frame->opcode == Opcode::pong) continue;
            if (!started) { message.opcode = frame->opcode; started = true; }
            if (frame->payload.size() > limits_.max_message - message.payload.size()) {
                static_cast<void>(terminate(make_error_code(Mira::Errc::limit_exceeded)));
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
            if (std::uncaught_exceptions() > exceptions) owner.fail_exception();
        }
    };
    struct DirectionGuard {
        Connection& owner;
        bool& flag;
        int exceptions = std::uncaught_exceptions();
        DirectionGuard(Connection& value, bool& direction) : owner(value), flag(direction) { flag = true; }
        ~DirectionGuard() {
            flag = false;
            if (std::uncaught_exceptions() > exceptions) owner.fail_exception();
        }
    };
    Task<Result<void>> flush_control(OperationOptions options) {
        while (pending_pong_) {
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
        auto sent = co_await send_locked(frame, options, true);
        if (!sent) co_return sent;
        co_return co_await flush_control(options);
    }
    Result<void> configure_extensions(const Negotiated& negotiated) {
        if (!negotiated.compression.enabled) return {};
        auto outbound = negotiated.compression;
        if (role_ == Role::client) {
            // Offer hints are promises about our encoder even when the server
            // omits them or responds with a less restrictive receive limit.
            outbound.client_no_context_takeover = outbound.client_no_context_takeover ||
                handshake_options_.compression.client_no_context_takeover;
            if (handshake_options_.compression.client_max_window_bits)
                outbound.client_max_window_bits = std::min(outbound.client_max_window_bits,
                    *handshake_options_.compression.client_max_window_bits);
        }
        auto encoder = DeflateEncoder::create(role_, outbound, limits_);
        if (!encoder) return fail(encoder.error());
        auto decoder = DeflateDecoder::create(role_, negotiated.compression, limits_);
        if (!decoder) return fail(decoder.error());
        encoder_.emplace(std::move(*encoder));
        decoder_.emplace(std::move(*decoder));
        incoming_ = FrameParser(role_, limits_, true);
        return {};
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
    void fail_exception() noexcept {
        if (failed_) return;
        // Match the failure-return path: closing a capable transport releases
        // the companion operation. Preserve the original exception even if a
        // user-provided close() implementation itself throws during unwinding.
        try { static_cast<void>(terminate(make_error_code(Mira::Errc::internal))); }
        catch (...) {}
    }
    Task<Result<std::size_t>> read_bytes(std::span<std::byte> bytes, OperationOptions options) {
        Result<std::size_t> result;
        if constexpr (BoundedStream<Transport>) result = co_await transport_->read_some(bytes, options);
        else result = co_await transport_->read_some(bytes);
        if (failed_) co_return fail(make_error_code(Errc::closed));
        if (!result || *result == 0 || *result > bytes.size()) {
            auto error = !result ? result.error() : make_error_code(Errc::abnormal_close);
            if (error == make_error_code(Mira::Errc::eof)) error = make_error_code(Errc::abnormal_close);
            static_cast<void>(terminate(error));
            co_return fail(error);
        }
        co_return result;
    }
    Task<Result<void>> write_bytes(std::span<const std::byte> bytes, OperationOptions options) {
        while (!bytes.empty()) {
            if (failed_) co_return fail(make_error_code(Errc::closed));
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
        // Validate application data before advancing the compression context.
        // In compressed mode the codec owns fragmented UTF-8 and size state.
        Result<std::vector<std::byte>> wire;
        if (encoder_) {
            auto encoded = encoder_->encode(frame);
            if (!encoded) co_return terminate(encoded.error());
            wire = serialize(*encoded, role_, mask, limits_, true);
            if (!wire) co_return terminate(wire.error());
        } else {
            wire = serialize(frame, role_, mask, limits_);
            if (!wire) co_return fail(wire.error());
            if (!closing_pong) {
                auto valid = outgoing_.feed(*wire);
                if (!valid) co_return terminate(valid.error());
            }
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
            if (parsed && parsed->frame && decoder_) {
                auto decoded = decoder_->decode(std::move(*parsed->frame));
                if (!decoded) parsed = fail(decoded.error());
                else parsed->frame = std::move(*decoded);
            }
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
                static_cast<void>(terminate(error));
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
                // A queued Pong is no longer needed once the peer closes. In
                // particular, do not let it turn a completed simultaneous Close
                // exchange into an attempted write on an already closed session.
                pending_pong_.reset();
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
    HandshakeOptions handshake_options_;
    Negotiated negotiated_;
    std::optional<DeflateEncoder> encoder_;
    std::optional<DeflateDecoder> decoder_;
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
