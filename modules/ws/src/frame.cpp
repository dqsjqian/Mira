#include "mira/ws/frame.hpp"

#include <algorithm>
#include <limits>
#include <string>

namespace Mira::ws {
namespace {
class Category final : public std::error_category {
public:
    const char* name() const noexcept override { return "mira.ws"; }
    std::string message(int value) const override {
        switch (static_cast<Errc>(value)) {
        case Errc::protocol: return "WebSocket protocol error";
        case Errc::invalid_utf8: return "Invalid WebSocket UTF-8";
        case Errc::invalid_handshake: return "Invalid WebSocket handshake";
        case Errc::crypto_failure: return "WebSocket cryptography failure";
        case Errc::closed: return "WebSocket is closed";
        case Errc::abnormal_close: return "WebSocket transport closed without close frame";
        }
        return "Unknown WebSocket error";
    }
};
unsigned value(std::byte byte) { return std::to_integer<unsigned>(byte); }
bool known(Opcode op) {
    return op == Opcode::continuation || op == Opcode::text || op == Opcode::binary ||
           op == Opcode::close || op == Opcode::ping || op == Opcode::pong;
}
bool control(Opcode op) { return static_cast<unsigned>(op) >= 8; }
bool utf8(std::span<const std::byte> bytes, unsigned& remaining,
          std::uint32_t& cp, std::uint32_t& minimum) noexcept {
    for (auto byte : bytes) {
        auto c = value(byte);
        if (!remaining) {
            if (c < 0x80) continue;
            if (c >= 0xc2 && c <= 0xdf) { remaining = 1; cp = c & 31; minimum = 0x80; }
            else if (c >= 0xe0 && c <= 0xef) { remaining = 2; cp = c & 15; minimum = 0x800; }
            else if (c >= 0xf0 && c <= 0xf4) { remaining = 3; cp = c & 7; minimum = 0x10000; }
            else return false;
        } else {
            if ((c & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (c & 63);
            if (--remaining == 0 && (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)))
                return false;
        }
    }
    return true;
}
Result<void> validate_close(std::span<const std::byte> payload) {
    if (payload.size() == 1) return fail(make_error_code(Errc::protocol));
    if (payload.size() >= 2) {
        auto code = static_cast<std::uint16_t>((value(payload[0]) << 8) | value(payload[1]));
        if (!valid_close_code(code)) return fail(make_error_code(Errc::protocol));
        if (!valid_utf8(payload.subspan(2))) return fail(make_error_code(Errc::invalid_utf8));
    }
    return {};
}
}

std::error_code make_error_code(Errc value) noexcept {
    static Category category;
    return {static_cast<int>(value), category};
}
bool valid_close_code(std::uint16_t code) noexcept {
    return (code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006) ||
           (code >= 3000 && code <= 4999);
}
bool valid_utf8(std::span<const std::byte> bytes) noexcept {
    unsigned remaining = 0;
    std::uint32_t cp = 0, minimum = 0;
    return utf8(bytes, remaining, cp, minimum) && remaining == 0;
}
Result<std::vector<std::byte>> close_payload(std::uint16_t code, std::span<const std::byte> reason) {
    if (!valid_close_code(code) || reason.size() > 123) return fail(make_error_code(Errc::protocol));
    if (!valid_utf8(reason)) return fail(make_error_code(Errc::invalid_utf8));
    std::vector<std::byte> bytes{std::byte(code >> 8), std::byte(code & 255)};
    bytes.insert(bytes.end(), reason.begin(), reason.end());
    return bytes;
}
FrameParser::FrameParser(Role local_role, Limits limits) : role_(local_role), limits_(limits) {}
void FrameParser::reset() noexcept {
    header_size_ = 0; header_needed_ = 2; payload_size_ = 0; header_ready_ = false;
    frame_ = {}; fragmented_.reset(); message_size_ = 0;
    utf8_remaining_ = 0; utf8_value_ = 0; utf8_min_ = 0; closed_ = false; error_.clear();
}
Result<void> FrameParser::parse_header() {
    auto a = value(header_[0]), b = value(header_[1]);
    frame_.opcode = static_cast<Opcode>(a & 15);
    frame_.final = (a & 0x80) != 0;
    masked_ = (b & 0x80) != 0;
    if ((a & 0x70) || !known(frame_.opcode) || masked_ != (role_ == Role::server))
        return fail(make_error_code(Errc::protocol));
    std::uint64_t size = b & 127;
    std::size_t pos = 2;
    if (size == 126 || size == 127) {
        const unsigned count = size == 126 ? 2 : 8;
        if (count == 8 && (value(header_[2]) & 0x80)) return fail(make_error_code(Errc::protocol));
        size = 0;
        for (unsigned i = 0; i < count; ++i) size = (size << 8) | value(header_[pos++]);
        if ((count == 2 && size < 126) || (count == 8 && size < 65536))
            return fail(make_error_code(Errc::protocol));
    }
    if (control(frame_.opcode) && (!frame_.final || size > 125))
        return fail(make_error_code(Errc::protocol));
    if (size > limits_.max_frame || size > std::numeric_limits<std::size_t>::max())
        return fail(Mira::Errc::limit_exceeded);
    if (!control(frame_.opcode)) {
        if ((frame_.opcode == Opcode::continuation) != fragmented_.has_value())
            return fail(make_error_code(Errc::protocol));
        if (size > limits_.max_message || message_size_ > limits_.max_message - size)
            return fail(Mira::Errc::limit_exceeded);
    }
    if (masked_) std::copy_n(header_.begin() + static_cast<std::ptrdiff_t>(pos), 4, mask_.begin());
    payload_size_ = static_cast<std::size_t>(size);
    frame_.payload.reserve(payload_size_);
    header_ready_ = true;
    return {};
}
Result<void> FrameParser::validate_frame() {
    if (frame_.opcode == Opcode::close) {
        auto result = validate_close(frame_.payload);
        if (!result) return result;
        if (role_ == Role::client && frame_.payload.size() >= 2 &&
            value(frame_.payload[0]) == 3 && value(frame_.payload[1]) == 242)
            return fail(make_error_code(Errc::protocol));
        closed_ = true;
    } else if (!control(frame_.opcode)) {
        auto type = fragmented_.value_or(frame_.opcode);
        message_size_ += frame_.payload.size();
        if (type == Opcode::text &&
            (!utf8(frame_.payload, utf8_remaining_, utf8_value_, utf8_min_) ||
             (frame_.final && utf8_remaining_ != 0)))
            return fail(make_error_code(Errc::invalid_utf8));
        if (frame_.final) { fragmented_.reset(); message_size_ = 0; }
        else fragmented_ = type;
    }
    return {};
}
Result<ParseResult> FrameParser::feed(std::span<const std::byte> bytes) {
    if (error_) return fail(error_);
    if (closed_ && !bytes.empty()) return fail(make_error_code(Errc::closed));
    ParseResult result;
    while (!header_ready_) {
        if (result.consumed == bytes.size()) return result;
        header_[header_size_++] = bytes[result.consumed++];
        if (header_size_ == 2) {
            auto length = value(header_[1]) & 127;
            header_needed_ = 2 + (length == 126 ? 2 : length == 127 ? 8 : 0) +
                             ((value(header_[1]) & 0x80) ? 4 : 0);
        }
        if (header_size_ == header_needed_) {
            auto parsed = parse_header();
            if (!parsed) { error_ = parsed.error(); return fail(error_); }
        }
    }
    auto count = std::min(payload_size_ - frame_.payload.size(), bytes.size() - result.consumed);
    for (std::size_t i = 0; i < count; ++i) {
        auto byte = bytes[result.consumed++];
        if (masked_) byte ^= mask_[frame_.payload.size() % 4];
        frame_.payload.push_back(byte);
    }
    if (frame_.payload.size() == payload_size_) {
        auto checked = validate_frame();
        if (!checked) { error_ = checked.error(); return fail(error_); }
        result.frame = std::move(frame_);
        frame_ = {}; header_size_ = 0; header_needed_ = 2; header_ready_ = false;
    }
    return result;
}
Result<std::vector<std::byte>> serialize(const Frame& frame, Role sender,
    std::optional<std::array<std::byte, 4>> mask, Limits limits) {
    if (!known(frame.opcode) || (sender == Role::client) != mask.has_value() ||
        (control(frame.opcode) && (!frame.final || frame.payload.size() > 125)))
        return fail(make_error_code(Errc::protocol));
    if (frame.payload.size() > limits.max_frame ||
        (!control(frame.opcode) && frame.payload.size() > limits.max_message) ||
        frame.payload.size() > std::numeric_limits<std::size_t>::max() - 14 ||
        static_cast<std::uint64_t>(frame.payload.size()) > (std::uint64_t{1} << 63) - 1)
        return fail(Mira::Errc::limit_exceeded);
    if (frame.opcode == Opcode::close) {
        auto result = validate_close(frame.payload);
        if (!result) return fail(result.error());
        if (sender == Role::server && frame.payload.size() >= 2 &&
            value(frame.payload[0]) == 3 && value(frame.payload[1]) == 242)
            return fail(make_error_code(Errc::protocol));
    }
    if (frame.opcode == Opcode::text && frame.final && !valid_utf8(frame.payload))
        return fail(make_error_code(Errc::invalid_utf8));
    std::vector<std::byte> output;
    output.reserve(frame.payload.size() + 14);
    output.push_back(std::byte((frame.final ? 0x80 : 0) | static_cast<unsigned>(frame.opcode)));
    auto size = frame.payload.size();
    unsigned flag = mask ? 0x80 : 0;
    if (size < 126) output.push_back(std::byte(flag | static_cast<unsigned>(size)));
    else {
        unsigned count = size <= 65535 ? 2 : 8;
        output.push_back(std::byte(flag | (count == 2 ? 126 : 127)));
        for (unsigned i = count; i > 0; --i)
            output.push_back(std::byte((static_cast<std::uint64_t>(size) >> ((i - 1) * 8)) & 255));
    }
    if (mask) output.insert(output.end(), mask->begin(), mask->end());
    for (std::size_t i = 0; i < size; ++i)
        output.push_back(mask ? frame.payload[i] ^ (*mask)[i % 4] : frame.payload[i]);
    return output;
}
} // namespace Mira::ws
