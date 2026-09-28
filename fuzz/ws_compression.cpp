// Bounded raw DEFLATE mutation and compressed-frame segmentation equivalence.
#include "mira/ws/compression.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>

namespace {
constexpr Mira::ws::Limits limits{8192, 16384, 4096};
}
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (!size || size > 4096) return 0;
    const auto bytes = std::as_bytes(std::span(data, size));
    Mira::ws::CompressionParameters parameters;
    parameters.enabled = true;
    parameters.client_no_context_takeover = (data[0] & 1U) != 0;
    parameters.server_no_context_takeover = (data[0] & 2U) != 0;
    for (auto role : {Mira::ws::Role::client, Mira::ws::Role::server}) {
        const auto peer = role == Mira::ws::Role::client ? Mira::ws::Role::server : Mira::ws::Role::client;
        auto encoder = Mira::ws::DeflateEncoder::create(role, parameters, limits);
        auto decoder = Mira::ws::DeflateDecoder::create(peer, parameters, limits);
        if (!encoder || !decoder) std::abort();
        // Reuse contexts across two messages; split each message over two frames.
        for (unsigned message = 0; message < 2; ++message) {
            std::vector<std::byte> restored;
            const auto split = size / 2;
            for (unsigned piece = 0; piece < 2; ++piece) {
                auto payload = piece == 0 ? bytes.first(split) : bytes.subspan(split);
                Mira::ws::Frame input{piece == 0 ? Mira::ws::Opcode::binary : Mira::ws::Opcode::continuation,
                                      piece != 0, {payload.begin(), payload.end()}};
                auto compressed = encoder->encode(input);
                if (!compressed || compressed->compressed != (piece == 0)) std::abort();
                auto plain = decoder->decode(std::move(*compressed));
                if (!plain || plain->compressed || plain->payload.size() > limits.max_frame) std::abort();
                restored.insert(restored.end(), plain->payload.begin(), plain->payload.end());
            }
            if (!std::equal(restored.begin(), restored.end(), bytes.begin(), bytes.end())) std::abort();
        }
        auto mutated = Mira::ws::DeflateDecoder::create(role, parameters, limits);
        if (!mutated) std::abort();
        Mira::ws::Frame wire{Mira::ws::Opcode::binary, true, {bytes.begin(), bytes.end()}, true};
        auto result = mutated->decode(wire);
        if (result && result->payload.size() > limits.max_frame) std::abort();
        if (!result && mutated->decode(wire)) std::abort();
    }
    return 0;
}
