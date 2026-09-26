// Mira/fuzz/http_parser.cpp — libFuzzer entry for the request parser.
//
// The value of a protocol parser is concentrated in its negative space, and
// fuzzing is how the negative space gets explored faster than any hand-written
// negative test can. This harness feeds an incremental `RequestParser` the
// fuzzer's bytes — split into arbitrary slices, because "the same bytes in
// different chunk boundaries" is exactly where incremental-parsing bugs hide —
// and asserts only the parser's own invariants:
//
//   * a parse either fails with a named error or makes progress;
//   * one message never reports a second head;
//   * the parser never reads past what it consumed (ASan's job, but the
//     slicing below gives it more shapes to look at).
//
// Build with -DMIRA_BUILD_FUZZERS=ON and a clang that ships libFuzzer.
// Seeds live in fuzz/corpus/http_parser/ — a compact tour of the grammar:
// valid requests, chunked bodies, smuggling shapes, oversized numbers, and
// line-ending abuse.

#include "mira/core/buffer.hpp"
#include "mira/http/parser.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>

namespace {

/// Feed `data` to the parser one slice at a time, with slice boundaries
/// derived from the data itself so the fuzzer controls the chunking.
///
/// The variant byte picks a slicing strategy. Splitting the same payload
/// differently exercises the incremental state machine far harder than one
/// big slurp, and the fuzzer learns to steer the variant byte quickly.
///
/// Returns true when every observable behaviour was legal (including a named
/// parse error and a truncated input); false marks a broken invariant.
bool drive(Mira::http::RequestParser& parser, Mira::Buffer& input,
           std::string_view data, std::uint8_t strategy) {
    using Mira::http::ParseStep;

    const std::size_t split =
        strategy == 0 ? data.size()
                      : strategy == 1 ? (data.size() + 1) / 2
                                      : 1 + (data.size() % 7);  // awkward small slices

    std::size_t fed = 0;
    bool head_seen = false;
    while (fed < data.size()) {
        const std::size_t n = std::min(split, data.size() - fed);
        input.append(std::span{reinterpret_cast<const std::byte*>(data.data()) + fed, n});
        fed += n;

        bool wants_input = false;
        for (int spins = 0; spins < 64; ++spins) {
            const Mira::Result<Mira::http::ParseStep> step = parser.parse(input);
            if (!step) {
                // A named failure is the good outcome; the connection loop
                // would close here. Nothing further may be asserted about a
                // failed stream.
                return true;
            }
            switch (*step) {
            case ParseStep::head:
                if (head_seen) {
                    return false;  // one message, one head
                }
                head_seen = true;
                continue;
            case ParseStep::body:
                if (parser.body().empty()) {
                    return false;  // a body step with no bytes is a protocol lie
                }
                continue;
            case ParseStep::complete:
                return true;  // well-formed; pipelined tails are next-parser business
            case ParseStep::need_more:
                // Legal: this slice is exhausted, go append the next one.
                wants_input = true;
                break;
            }
            break;
        }
        if (!wants_input) {
            // 64 spins without asking for input and without progress: the
            // state machine looped. That is a finding.
            return false;
        }
    }
    // All bytes fed; whatever the parser still wants belongs to a truncated
    // message, which is a legal observation, not a bug.
    return true;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0 || size > 4096) {
        return 0;  // the parser's limits are unit-tested; fuzz the grammar
    }
    const std::string_view payload{reinterpret_cast<const char*>(data), size};
    const std::uint8_t strategy = static_cast<std::uint8_t>(payload[0] % 3);

    Mira::http::Limits limits;  // defaults: small on purpose, fast to hit
    Mira::http::RequestParser parser{limits};
    Mira::Buffer input;
    if (!drive(parser, input, payload, strategy)) {
        // Invariant broken: abort so libFuzzer records the input.
        std::abort();
    }
    return 0;
}
