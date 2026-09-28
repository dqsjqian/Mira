#include "mira/ws/connection.hpp"
#include "mira/core/event_loop.hpp"
#include "check.hpp"

#include <algorithm>
#include <string_view>

namespace {
using namespace Mira;
using namespace Mira::ws;
constexpr std::array<std::byte, 4> test_mask_key{std::byte{0x12}, std::byte{0x34},
                                        std::byte{0x56}, std::byte{0x78}};

std::vector<std::byte> raw(std::initializer_list<unsigned> values) {
    std::vector<std::byte> out;
    for (auto value : values) out.push_back(std::byte(value));
    return out;
}

std::vector<std::byte> wire_frame(Opcode opcode, bool final,
                                  std::span<const std::byte> payload, Role local,
                                  unsigned advertised = 0) {
    const bool test_mask_keyed = local == Role::server;
    std::vector<std::byte> wire{std::byte((final ? 0x80U : 0U) | static_cast<unsigned>(opcode)),
        std::byte((test_mask_keyed ? 0x80U : 0U) | (advertised ? advertised : static_cast<unsigned>(payload.size())))};
    if (test_mask_keyed) wire.insert(wire.end(), test_mask_key.begin(), test_mask_key.end());
    for (std::size_t i = 0; i < payload.size(); ++i)
        wire.push_back(test_mask_keyed ? payload[i] ^ test_mask_key[i % 4] : payload[i]);
    return wire;
}

void close_1010_roles() {
    // Official case 7.7.8 accepts 1010 on receipt; sender restrictions are separate.
    const auto payload = close_payload(1010);
    CHECK(payload.has_value());
    if (!payload) return;
    Frame close_frame{Opcode::close, true, *payload};
    FrameParser client(Role::client);
    auto received = client.feed(wire_frame(Opcode::close, true, *payload, Role::client));
    CHECK(received && received->frame && received->frame->opcode == Opcode::close);
    CHECK(received && received->frame && received->frame->payload == *payload);
    auto server_wire = serialize(close_frame, Role::server);
    CHECK(!server_wire && server_wire.error() == make_error_code(Mira::ws::Errc::protocol));
    auto client_wire = serialize(close_frame, Role::client, test_mask_key);
    CHECK(client_wire.has_value());
    if (client_wire) {
        FrameParser server(Role::server);
        auto parsed = server.feed(*client_wire);
        CHECK(parsed && parsed->frame && parsed->frame->payload == *payload);
    }
}

void fail_fast_utf8() {
    // Cover invalid UTF-8 split across frames/TCP chunks from official 6.4.* cases.
    // These regressions do not replace the complete official suite report.
    for (auto role : {Role::client, Role::server}) {
        for (const auto& prefix : {raw({0xe0, 0x80}), raw({0xed, 0xa0}),
                                  raw({0xf0, 0x80}), raw({0xf4, 0x90}), raw({0xff})}) {
            FrameParser parser(role);
            auto wire = wire_frame(Opcode::text, true, prefix, role, 32);
            auto result = parser.feed(wire);
            CHECK(!result && result.error() == make_error_code(Mira::ws::Errc::invalid_utf8));
            CHECK(parser.failed());
            CHECK(!parser.feed({}));
            parser.reset();
            auto good = parser.feed(wire_frame(Opcode::text, true, raw({0x41}), role));
            CHECK(good && good->frame && good->frame->payload == raw({0x41}));
        }
        FrameParser fragments(role);
        auto first = fragments.feed(wire_frame(Opcode::text, false, raw({0xf4}), role));
        CHECK(first && first->frame);
        auto ping = fragments.feed(wire_frame(Opcode::ping, true, raw({0xff}), role));
        CHECK(ping && ping->frame);
        auto invalid = fragments.feed(wire_frame(Opcode::continuation, false, raw({0x90}), role));
        CHECK(!invalid && invalid.error() == make_error_code(Mira::ws::Errc::invalid_utf8));

        FrameParser valid(role);
        auto initial = valid.feed(wire_frame(Opcode::text, false, raw({0xf4}), role));
        CHECK(initial && initial->frame);
        auto control = valid.feed(wire_frame(Opcode::ping, true, raw({0xff}), role));
        CHECK(control && control->frame);
        auto final_wire = wire_frame(Opcode::continuation, true, raw({0x8f, 0xbf, 0xbf}), role);
        unsigned completed = 0;
        for (auto byte : final_wire) {
            auto result = valid.feed(std::span<const std::byte>(&byte, 1));
            CHECK(result.has_value());
            if (result && result->frame) ++completed;
        }
        CHECK(completed == 1);
        auto next = valid.feed(wire_frame(Opcode::text, true, raw({0x41}), role));
        CHECK(next && next->frame);
    }
}

struct MemoryStream {
    std::vector<std::byte> input, output;
    std::size_t position = 0;
    bool closed = false;
    Task<Result<std::size_t>> read_some(std::span<std::byte> out) {
        if (position == input.size()) co_return fail(Mira::Errc::eof);
        const auto count = std::min(out.size(), input.size() - position);
        std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(position), count, out.begin());
        position += count;
        co_return count;
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> in) {
        output.insert(output.end(), in.begin(), in.end());
        co_return in.size();
    }
    void close() { closed = true; }
};

Task<void> wire_close_code() {
    auto request = client_handshake("localhost");
    CHECK(request.has_value());
    if (!request) co_return;
    auto head = std::as_bytes(std::span(request->request));
    MemoryStream stream;
    stream.input.assign(head.begin(), head.end());
    auto invalid = wire_frame(Opcode::text, true, raw({0xf4, 0x90}), Role::server, 32);
    stream.input.insert(stream.input.end(), invalid.begin(), invalid.end());
    Connection connection(stream, Role::server);
    auto handshake = co_await connection.handshake();
    CHECK(handshake.has_value());
    stream.output.clear();
    auto result = co_await connection.read_message();
    CHECK(!result && result.error() == make_error_code(Mira::ws::Errc::invalid_utf8));
    CHECK(stream.closed);
    FrameParser replies(Role::client);
    auto close = replies.feed(stream.output);
    CHECK(close && close->frame && close->frame->opcode == Opcode::close);
    CHECK(close && close->frame && close->frame->payload == *close_payload(1007));
}
}

int main() {
    close_1010_roles();
    fail_fast_utf8();
    auto loop = Mira::EventLoop::create();
    CHECK(loop.has_value());
    if (loop) CHECK(loop->run_until_complete(wire_close_code()).has_value());
    return Mira::test::summary();
}
