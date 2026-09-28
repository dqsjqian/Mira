#include "mira/ws/compression.hpp"
#include "check.hpp"

#include <algorithm>
#include <array>
#include <string_view>
#include <type_traits>
#include <utility>

using namespace Mira;
using namespace Mira::ws;
namespace {
std::vector<std::byte> bytes(std::string_view text) {
    auto view = std::as_bytes(std::span(text.data(), text.size()));
    return {view.begin(), view.end()};
}
std::vector<std::byte> hex(std::string_view text) {
    std::vector<std::byte> result;
    const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (std::size_t i = 0; i + 1 < text.size(); i += 2)
        result.push_back(std::byte(static_cast<unsigned>((digit(text[i]) << 4) | digit(text[i + 1]))));
    return result;
}
CompressionParameters enabled() {
    CompressionParameters parameters;
    parameters.enabled = true;
    return parameters;
}
Frame data(std::string_view text, bool final = true, Opcode opcode = Opcode::text) {
    return {opcode, final, bytes(text)};
}
Frame compressed(std::string_view payload, bool final = true, Opcode opcode = Opcode::text) {
    return {opcode, final, hex(payload), opcode != Opcode::continuation};
}
void rfc_vectors() {
    // RFC7692 7.2.3.1, .3, .4, and .5, independent of our compressor.
    for (auto value : {"f248cdc9c90700", "000500faff48656c6c6f00", "f348cdc9c9070000",
                       "f24805000000ffffcac9c90700"}) {
        auto decoder = DeflateDecoder::create(Role::client, enabled());
        CHECK(decoder.has_value());
        auto frame = decoder->decode(compressed(value));
        CHECK(frame && frame->payload == bytes("Hello") && !frame->compressed);
    }
    for (auto value : {"00", "01"}) {
        auto decoder = DeflateDecoder::create(Role::client, enabled());
        auto frame = decoder->decode(compressed(value));
        CHECK(frame && frame->payload.empty());
        frame = decoder->decode(compressed("f248cdc9c90700"));
        CHECK(frame && frame->payload == bytes("Hello"));
    }
    auto encoder = DeflateEncoder::create(Role::server, enabled());
    auto encoded = encoder->encode(data("Hello"));
    CHECK(encoded && encoded->compressed && encoded->payload == hex("f248cdc9c90700"));
    auto wire = serialize(*encoded, Role::server, std::nullopt, {}, true);
    CHECK(wire && *wire == hex("c107f248cdc9c90700"));
    auto decoder = DeflateDecoder::create(Role::client, enabled());
    auto first = decoder->decode(compressed("f248cd", false));
    auto last = decoder->decode(compressed("c9c90700", true, Opcode::continuation));
    CHECK(first && last);
    if (first && last) {
        first->payload.insert(first->payload.end(), last->payload.begin(), last->payload.end());
        CHECK(first->payload == bytes("Hello"));
    }
    for (const auto& payload : {hex("f248cdc9c90700"), hex("f348cdc9c9070000")}) {
        decoder = DeflateDecoder::create(Role::client, enabled());
        std::vector<std::byte> output;
        for (std::size_t i = 0; i < payload.size(); ++i) {
            Frame piece{i ? Opcode::continuation : Opcode::text, i + 1 == payload.size(), {payload[i]}, i == 0};
            auto decoded = decoder->decode(std::move(piece));
            CHECK(decoded.has_value());
            if (decoded) output.insert(output.end(), decoded->payload.begin(), decoded->payload.end());
        }
        CHECK(output == bytes("Hello"));
    }
}
void context_takeover() {
    const auto one = compressed("4acacc4b2caa5448cecf2b49ad2851481ae58e7247b943870b00", true, Opcode::binary);
    const auto two = compressed("1ae58e7247b943970b00", true, Opcode::binary);
    std::vector<std::byte> payload;
    for (unsigned i = 0; i < 64; ++i) {
        auto part = bytes("binary context ");
        payload.insert(payload.end(), part.begin(), part.end());
    }
    for (auto local : {Role::client, Role::server}) {
        auto decoder = DeflateDecoder::create(local, enabled());
        auto first = decoder->decode(one);
        CHECK(first && first->payload == payload);
        auto plain = decoder->decode(data("uncompressed data must not update the LZ77 history"));
        CHECK(plain.has_value());
        auto second = decoder->decode(two);
        CHECK(second && second->payload == payload);
        auto encoder = DeflateEncoder::create(local == Role::client ? Role::server : Role::client, enabled());
        auto encoded_one = encoder->encode(Frame{Opcode::binary, true, payload});
        auto encoded_two = encoder->encode(Frame{Opcode::binary, true, payload});
        CHECK(encoded_one && encoded_one->payload == one.payload);
        CHECK(encoded_two && encoded_two->payload == two.payload);

        auto parameters = enabled();
        if (local == Role::server) parameters.client_no_context_takeover = true;
        else parameters.server_no_context_takeover = true;
        encoder = DeflateEncoder::create(local == Role::client ? Role::server : Role::client, parameters);
        decoder = DeflateDecoder::create(local, parameters);
        encoded_one = encoder->encode(Frame{Opcode::binary, true, payload});
        encoded_two = encoder->encode(Frame{Opcode::binary, true, payload});
        CHECK(encoded_one && encoded_two && encoded_one->payload == encoded_two->payload);
        first = decoder->decode(*encoded_one);
        second = decoder->decode(*encoded_two);
        CHECK(first && second && first->payload == payload && second->payload == payload);
        decoder = DeflateDecoder::create(local, parameters);
        CHECK(decoder->decode(one).has_value());
        CHECK(!decoder->decode(two).has_value());
    }
    // A BFINAL block must retain the same dictionary across later DEFLATE streams.
    auto decoder = DeflateDecoder::create(Role::client, enabled());
    CHECK(decoder->decode(compressed("f348cdc9c9070000")).has_value());
    auto next = decoder->decode(compressed("f200110000"));
    CHECK(next && next->payload == bytes("Hello"));
}
void fragments_and_utf8() {
    const Frame ping = data("control", true, Opcode::ping);
    auto encoder = DeflateEncoder::create(Role::server, enabled());
    auto decoder = DeflateDecoder::create(Role::client, enabled());
    Frame start{Opcode::text, false, hex("e2")};
    Frame end{Opcode::continuation, true, hex("82ac")};
    auto encoded = encoder->encode(start);
    CHECK(encoded && encoded->payload == hex("7a04000000ffff") && encoded->compressed);
    auto decoded = decoder->decode(*encoded);
    CHECK(decoded && decoded->payload == start.payload);
    auto control_encoded = encoder->encode(ping);
    auto control_decoded = decoder->decode(*control_encoded);
    CHECK(control_encoded && control_decoded && !control_encoded->compressed && control_decoded->payload == ping.payload);
    encoded = encoder->encode(end);
    CHECK(encoded && !encoded->compressed && encoded->payload == hex("6a5a0300"));
    decoded = decoder->decode(*encoded);
    CHECK(decoded && decoded->payload == end.payload);

    for (bool negotiated : {false, true}) {
        auto parameters = enabled();
        parameters.enabled = negotiated;
        encoder = DeflateEncoder::create(Role::server, parameters);
        CHECK(encoder->encode(start).has_value());
        CHECK(encoder->encode(ping).has_value());
        auto bad = encoder->encode(Frame{Opcode::continuation, true, {}});
        CHECK(!bad && bad.error() == ws::make_error_code(ws::Errc::invalid_utf8));
        auto poisoned = encoder->encode(data("valid"));
        CHECK(!poisoned && poisoned.error() == bad.error());
        decoder = DeflateDecoder::create(Role::client, parameters);
        auto first = negotiated ? compressed("7a04000000ffff", false) : start;
        CHECK(decoder->decode(first).has_value());
        CHECK(decoder->decode(ping).has_value());
        auto last = negotiated ? compressed("00", true, Opcode::continuation) : Frame{Opcode::continuation, true, {}};
        bad = decoder->decode(last);
        CHECK(!bad && bad.error() == ws::make_error_code(ws::Errc::invalid_utf8));
        poisoned = decoder->decode(data("valid"));
        CHECK(!poisoned && poisoned.error() == bad.error());
    }
    for (auto invalid : {"c0", "eda0", "f490", "e080", "f080", "80", "e228", "f09f92"}) {
        encoder = DeflateEncoder::create(Role::server, enabled());
        auto bad = encoder->encode(Frame{Opcode::text, true, hex(invalid)});
        CHECK(!bad && bad.error() == ws::make_error_code(ws::Errc::invalid_utf8));
        encoder = DeflateEncoder::create(Role::server, enabled());
        auto binary = encoder->encode(Frame{Opcode::binary, true, hex(invalid)});
        CHECK(binary.has_value());
        binary->opcode = Opcode::text;
        decoder = DeflateDecoder::create(Role::client, enabled());
        bad = decoder->decode(*binary);
        CHECK(!bad && bad.error() == ws::make_error_code(ws::Errc::invalid_utf8));
    }
}
void empty_and_binary() {
    for (bool no_context : {false, true}) {
        auto parameters = enabled();
        parameters.server_no_context_takeover = no_context;
        auto encoder = DeflateEncoder::create(Role::server, parameters);
        auto decoder = DeflateDecoder::create(Role::client, parameters);
        for (unsigned i = 0; i < 3; ++i) {
            auto encoded = encoder->encode(data(""));
            CHECK(encoded && encoded->payload == hex("00"));
            auto decoded = decoder->decode(*encoded);
            CHECK(decoded && decoded->payload.empty());
        }
        for (const auto& frame : {data("Hello", false), data("", false, Opcode::continuation),
                                  data("", true, Opcode::continuation)}) {
            auto encoded = encoder->encode(frame);
            CHECK(encoded.has_value());
            auto decoded = decoder->decode(*encoded);
            CHECK(decoded && decoded->payload == frame.payload);
        }
        std::vector<std::byte> binary;
        for (unsigned i = 0; i < 65536; ++i) binary.push_back(std::byte(i & 255));
        for (unsigned i = 0; i < 2; ++i) {
            auto encoded = encoder->encode(Frame{Opcode::binary, true, binary});
            CHECK(encoded.has_value());
            auto decoded = decoder->decode(*encoded);
            CHECK(decoded && decoded->payload == binary);
        }
    }
}
void block_boundaries() {
    std::uint32_t random = 0x12345678;
    for (unsigned bits : {9U, 12U, 15U}) {
        auto parameters = enabled();
        parameters.server_max_window_bits = bits;
        auto encoder = DeflateEncoder::create(Role::server, parameters);
        auto decoder = DeflateDecoder::create(Role::client, parameters);
        for (std::size_t size : {4095U, 4096U, 4097U, 16387U}) {
            std::vector<std::byte> payload(size);
            for (auto& value : payload) {
                random ^= random << 13;
                random ^= random >> 17;
                random ^= random << 5;
                value = std::byte(random & 255);
            }
            auto encoded = encoder->encode(Frame{Opcode::binary, true, payload});
            CHECK(encoded.has_value());
            if (!encoded) continue;
            std::vector<std::byte> output;
            std::size_t offset = 0;
            while (offset < encoded->payload.size()) {
                const auto count = std::min(encoded->payload.size() - offset,
                                            std::size_t{1} + (offset % 137));
                const auto view = std::span<const std::byte>(encoded->payload).subspan(offset, count);
                Frame fragment{offset ? Opcode::continuation : Opcode::binary,
                               offset + count == encoded->payload.size(), {view.begin(), view.end()}, offset == 0};
                auto decoded = decoder->decode(std::move(fragment));
                CHECK(decoded.has_value());
                if (decoded) output.insert(output.end(), decoded->payload.begin(), decoded->payload.end());
                offset += count;
            }
            CHECK(output == payload);
        }
    }
}
void limits() {
    auto parameters = enabled();
    for (bool frame_limit : {false, true}) {
        Limits bounds;
        if (frame_limit) bounds.max_frame = 8192;
        else bounds.max_message = 8192;
        auto decoder = DeflateDecoder::create(Role::client, parameters, bounds);
        // Python zlib raw-DEFLATE: 8193 repeated A bytes, larger than two output chunks.
        auto bomb = compressed("ecc1010d000000c2a06cef5fca1c6e400100000000000000f706", true, Opcode::binary);
        auto result = decoder->decode(bomb);
        CHECK(!result && result.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));
        auto poisoned = decoder->decode(compressed("00"));
        CHECK(!poisoned && poisoned.error() == result.error());
    }
    Limits bounds;
    bounds.max_frame = 4;
    auto encoder = DeflateEncoder::create(Role::server, parameters, bounds);
    auto result = encoder->encode(data("12345"));
    CHECK(!result && result.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));
    encoder = DeflateEncoder::create(Role::server, parameters, bounds);
    result = encoder->encode(data("1234"));
    CHECK(!result && result.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));
    bounds.max_frame = 7;
    encoder = DeflateEncoder::create(Role::server, parameters, bounds);
    CHECK(encoder->encode(data("Hello")).has_value());
    bounds.max_message = 7;
    encoder = DeflateEncoder::create(Role::server, parameters, bounds);
    CHECK(encoder->encode(data("Hello")).has_value());
    bounds.max_frame = 100;
    bounds.max_message = 10;
    encoder = DeflateEncoder::create(Role::server, parameters, bounds);
    CHECK(encoder->encode(data("a", false)).has_value());
    result = encoder->encode(data("bc", true, Opcode::continuation));
    CHECK(!result && result.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));

    bounds.max_frame = 100;
    bounds.max_message = 10;
    auto decoder = DeflateDecoder::create(Role::client, parameters, bounds);
    CHECK(decoder->decode(compressed("f248cdc9c907", false, Opcode::binary)).has_value());
    result = decoder->decode(compressed("000000ffff", true, Opcode::continuation));
    CHECK(!result && result.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));

    bounds.max_frame = 100;
    bounds.max_message = 100;
    encoder = DeflateEncoder::create(Role::server, parameters);
    decoder = DeflateDecoder::create(Role::client, parameters, bounds);
    auto first = encoder->encode(Frame{Opcode::binary, false, std::vector<std::byte>(60, std::byte{1})});
    auto last = encoder->encode(Frame{Opcode::continuation, true, std::vector<std::byte>(41, std::byte{1})});
    CHECK(decoder->decode(*first).has_value());
    result = decoder->decode(*last);
    CHECK(!result && result.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));

    bounds.max_frame = 0;
    bounds.max_message = 0;
    encoder = DeflateEncoder::create(Role::server, parameters, bounds);
    result = encoder->encode(data(""));
    CHECK(!result && result.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));
}
void malformed_and_state() {
    // Bare stream ends, reserved blocks, missing final block headers, bad stored lengths.
    for (auto invalid : {"", "f248cdc9c907", "f248cdc9c9", "06", "f348cdc9c90700",
                         "f348cdc9c9078000", "000100ffff4100", "000000ffff"}) {
        auto decoder = DeflateDecoder::create(Role::client, enabled());
        auto result = decoder->decode(compressed(invalid, true, Opcode::binary));
        CHECK(!result && result.error() == ws::make_error_code(ws::Errc::protocol));
        auto poisoned = decoder->decode(compressed("00"));
        CHECK(!poisoned && poisoned.error() == result.error());
    }
    for (const auto& invalid : {Frame{Opcode::continuation, true, {}}, Frame{Opcode::ping, false, {}},
                               Frame{Opcode::ping, true, {}, true}, Frame{Opcode::close, true, hex("03")},
                               Frame{Opcode::close, true, hex("03ed")}, Frame{static_cast<Opcode>(7), true, {}},
                               Frame{Opcode::pong, true, std::vector<std::byte>(126)}}) {
        auto encoder = DeflateEncoder::create(Role::server, enabled());
        auto decoder = DeflateDecoder::create(Role::client, enabled());
        CHECK(!encoder->encode(invalid).has_value());
        CHECK(!decoder->decode(invalid).has_value());
    }
    const auto valid = hex("f248cdc9c90700");
    for (std::size_t count = 0; count < valid.size(); ++count) {
        auto decoder = DeflateDecoder::create(Role::client, enabled());
        Frame truncated{Opcode::binary, true,
                        {valid.begin(), valid.begin() + static_cast<std::ptrdiff_t>(count)}, true};
        CHECK(!decoder->decode(std::move(truncated)).has_value());
    }
    auto encoder = DeflateEncoder::create(Role::server, enabled());
    CHECK(!encoder->encode(compressed("00")).has_value());
    auto decoder = DeflateDecoder::create(Role::client, enabled());
    CHECK(decoder->decode(compressed("", false, Opcode::binary)).has_value());
    CHECK(!decoder->decode(compressed("00")).has_value());
    decoder = DeflateDecoder::create(Role::client, enabled());
    CHECK(decoder->decode(compressed("", false, Opcode::binary)).has_value());
    Frame invalid_continuation{Opcode::continuation, true, hex("00"), true};
    CHECK(!decoder->decode(invalid_continuation).has_value());
    encoder = DeflateEncoder::create(Role::server, enabled());
    CHECK(encoder->encode(data("fragment", false)).has_value());
    CHECK(!encoder->encode(data("overlap")).has_value());
}
void frame_layer() {
    const auto hello = compressed("f248cdc9c90700");
    CHECK(!serialize(hello, Role::server).has_value());
    auto wire = serialize(hello, Role::server, std::nullopt, {}, true);
    CHECK(wire.has_value());
    FrameParser plain(Role::client);
    CHECK(!plain.feed(*wire).has_value());
    FrameParser parser(Role::client, {}, true);
    for (auto byte : *wire) {
        const std::array<std::byte, 1> input{byte};
        auto result = parser.feed(input);
        CHECK(result.has_value());
        if (result && result->frame) CHECK(result->frame->compressed && result->frame->payload == hello.payload);
    }
    for (auto bad : {"a100", "9100", "c900", "c000"}) {
        FrameParser invalid(Role::client, {}, true);
        CHECK(!invalid.feed(hex(bad)).has_value());
    }
    for (const auto& frame : {Frame{Opcode::continuation, true, {}, true}, Frame{Opcode::ping, true, {}, true}})
        CHECK(!serialize(frame, Role::server, std::nullopt, {}, true).has_value());
    parser.reset();
    CHECK(parser.feed(hex("41037a0400")).has_value());
    CHECK(parser.feed(hex("890170")).has_value());
    CHECK(parser.feed(hex("80036a5a03")).has_value());
    CHECK(!parser.feed(hex("8101ff")).has_value());
    parser.reset();
    CHECK(parser.feed(hex("4100")).has_value());
    CHECK(!parser.feed(hex("c000")).has_value());
    Limits bounds;
    bounds.max_message = 3;
    FrameParser limited(Role::client, bounds, true);
    CHECK(limited.feed(hex("41020000")).has_value());
    auto too_large = limited.feed(hex("80020000"));
    CHECK(!too_large && too_large.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));
    parser.reset();
    CHECK(!parser.feed(hex("c80303e861")).has_value());
    parser.reset();
    CHECK(!parser.feed(hex("880303e8ff")).has_value());
}
void options_and_passthrough() {
    static_assert(!std::is_copy_constructible_v<DeflateEncoder>);
    static_assert(!std::is_copy_constructible_v<DeflateDecoder>);
    static_assert(std::is_nothrow_move_constructible_v<DeflateEncoder>);
    static_assert(std::is_nothrow_move_constructible_v<DeflateDecoder>);
    for (auto local : {Role::client, Role::server}) {
        auto parameters = enabled();
        for (unsigned bits : {7U, 8U, 9U, 15U, 16U}) {
            if (local == Role::server) parameters.server_max_window_bits = bits;
            else parameters.client_max_window_bits = bits;
            CHECK(DeflateEncoder::create(local, parameters).has_value() == (bits >= 9 && bits <= 15));
            CHECK(DeflateDecoder::create(local == Role::server ? Role::client : Role::server, parameters).has_value() ==
                  (bits >= 8 && bits <= 15));
        }
    }
    auto encoder = DeflateEncoder::create(Role::server, {});
    auto decoder = DeflateDecoder::create(Role::client, {});
    auto encoded = encoder->encode(data("Hello"));
    CHECK(encoded && !encoded->compressed && encoded->payload == bytes("Hello"));
    auto decoded = decoder->decode(*encoded);
    CHECK(decoded && decoded->payload == encoded->payload);
    CHECK(!decoder->decode(compressed("00")).has_value());
    auto moved_encoder = std::move(*encoder);
    CHECK(!encoder->encode(data("moved")).has_value());
    CHECK(moved_encoder.encode(data("valid")).has_value());
    auto moved_decoder = std::move(*decoder);
    CHECK(!decoder->decode(data("moved")).has_value());
    CHECK(!moved_decoder.decode(data("poisoned")).has_value());
}
}
int main() {
    test::section("RFC7692 and Python zlib vectors"); rfc_vectors();
    test::section("Directional context takeover"); context_takeover();
    test::section("Fragmented UTF-8 and control frames"); fragments_and_utf8();
    test::section("Empty messages and binary chunks"); empty_and_binary();
    test::section("Output chunk and fragmented block boundaries"); block_boundaries();
    test::section("Input/output bounds and decompression bombs"); limits();
    test::section("Malformed DEFLATE and poisoned state"); malformed_and_state();
    test::section("RSV1 frame parser and serializer"); frame_layer();
    test::section("Window bits, moves, and default passthrough"); options_and_passthrough();
    return test::summary();
}
