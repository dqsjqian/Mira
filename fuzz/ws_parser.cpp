// Incremental WebSocket grammar and segmentation-equivalence fuzzing.
#include "mira/ws/frame.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

namespace {
constexpr Mira::ws::Limits limits{4096, 8192, 8192};
struct Observation {
    std::vector<Mira::ws::Frame> frames;
    Mira::Error error;
};
Observation parse(std::span<const std::byte> wire, Mira::ws::Role role, std::size_t chunk) {
    Mira::ws::FrameParser parser(role, limits);
    Observation result;
    std::size_t offset = 0;
    while (offset < wire.size()) {
        const auto piece = wire.subspan(offset, std::min(chunk, wire.size() - offset));
        auto parsed = parser.feed(piece);
        if (!parsed) {
            if (!parser.failed() && parsed.error() != Mira::ws::make_error_code(Mira::ws::Errc::closed)) std::abort();
            result.error = parsed.error();
            const auto repeated = parser.feed(piece);
            if (repeated || repeated.error() != result.error) std::abort();
            break;
        }
        if (parsed->consumed > piece.size() || parsed->consumed == 0) std::abort();
        offset += parsed->consumed;
        if (parsed->frame) {
            if (parsed->frame->payload.size() > limits.max_frame) std::abort();
            result.frames.push_back(std::move(*parsed->frame));
        }
    }
    parser.reset();
    if (parser.failed()) std::abort();
    return result;
}
bool same(const Observation& left, const Observation& right) {
    if (left.error != right.error || left.frames.size() != right.frames.size()) return false;
    for (std::size_t i = 0; i < left.frames.size(); ++i) {
        const auto& a = left.frames[i];
        const auto& b = right.frames[i];
        if (a.opcode != b.opcode || a.final != b.final || a.payload != b.payload) return false;
    }
    return true;
}
}
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0 || size > 8192) return 0;
    const auto bytes = std::as_bytes(std::span(data, size));
    for (auto receiver : {Mira::ws::Role::client, Mira::ws::Role::server}) {
        const auto whole = parse(bytes, receiver, size);
        if (!same(whole, parse(bytes, receiver, 1)) ||
            !same(whole, parse(bytes, receiver, 1 + size % 17))) std::abort();
    }
    // Raw mutation reaches invalid headers quickly; generated valid frames keep
    // mask processing, extended lengths, and complete payload paths reachable.
    Mira::ws::Frame frame;
    frame.opcode = (data[0] & 1U) ? Mira::ws::Opcode::binary : Mira::ws::Opcode::ping;
    const auto bound = frame.opcode == Mira::ws::Opcode::ping ? std::size_t{125} : limits.max_frame;
    const auto payload = bytes.first(std::min(size, bound));
    frame.payload.assign(payload.begin(), payload.end());
    if ((data[0] & 3U) == 3U && Mira::ws::valid_utf8(payload)) frame.opcode = Mira::ws::Opcode::text;
    const std::array<std::byte, 4> key{bytes[0], bytes[size / 2], std::byte{0}, std::byte{255}};
    for (auto sender : {Mira::ws::Role::client, Mira::ws::Role::server}) {
        const auto receiver = sender == Mira::ws::Role::client ? Mira::ws::Role::server : Mira::ws::Role::client;
        auto wire = Mira::ws::serialize(frame, sender,
            sender == Mira::ws::Role::client ? std::optional(key) : std::nullopt, limits);
        if (!wire) std::abort();
        const auto decoded = parse(*wire, receiver, 1 + size % 31);
        if (decoded.error || decoded.frames.size() != 1 || decoded.frames[0].payload != frame.payload ||
            decoded.frames[0].opcode != frame.opcode || !decoded.frames[0].final) std::abort();
    }
    (void)Mira::ws::valid_utf8(bytes);
    if (size >= 2) {
        const auto code = static_cast<std::uint16_t>((static_cast<unsigned>(data[0]) << 8) | data[1]);
        (void)Mira::ws::close_payload(code, bytes.subspan(2));
    }
    return 0;
}
