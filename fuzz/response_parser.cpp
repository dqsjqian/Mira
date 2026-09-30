// Mira/fuzz/response_parser.cpp — libFuzzer entry for the response parser.
//
// The request parser's negative space is what a hostile client sends a
// server. The response parser's negative space is what a hostile *server*
// sends the client — the side of the connection Mira's HTTP client trusts
// least. The two grammars share framing but differ where it matters: status
// lines, informational responses, HEAD/CONNECT bodies, close-delimited
// framing. Fuzzing both keeps the pair symmetric.
//
// The harness mirrors fuzz/http_parser.cpp: the fuzzer's bytes are sliced
// by a strategy it controls, fed incrementally, and only the parser's own
// invariants are asserted:
//
//   * a parse either fails with a named error or makes progress;
//   * one message never reports a second head;
//   * a body step never reports zero bytes;
//   * each informational response resets before the final response is parsed.
//
// Build with -DMIRA_BUILD_FUZZERS=ON and a clang that ships libFuzzer.
// Seeds live in fuzz/corpus/response_parser/ — a compact tour of the
// grammar: valid responses, 1xx chains, HEAD empties, chunked trailers,
// smuggling shapes, and status-line abuse.

#include "mira/core/buffer.hpp"
#include "mira/http/response_parser.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>

namespace {

using Mira::http::Method;
using Mira::http::ParseStep;
using Mira::http::ResponseParser;

/// Feed `data` to a fresh parser one slice at a time, with slice boundaries
/// independent of the wire's first byte. After an informational message
/// (except protocol-switching 101), reset runs so state-machine reuse across
/// messages is exercised too.
///
/// Returns true when every observable behaviour was legal; false marks a
/// broken invariant.
bool drive(std::string_view data, std::uint8_t strategy) {
    const Method methods[]{Method::get, Method::head, Method::post, Method::connect};
    const Method method = methods[strategy & 3u];

    const std::size_t split =
        strategy == 0 ? data.size()
                      : strategy == 1 ? (data.size() + 1) / 2
                                      : 1 + (data.size() % 7);  // awkward small slices

    ResponseParser parser{method};
    Mira::Buffer input;
    std::size_t fed = 0;
    int heads = 0;
    int informational = 0;
    for (;;) {
        if (fed < data.size()) {
            const std::size_t n = std::min(split, data.size() - fed);
            input.append(std::span{reinterpret_cast<const std::byte*>(data.data()) + fed, n});
            fed += n;
        }
        const bool eof = fed >= data.size();

        bool wants_input = false;
        for (int spins = 0; spins < 64; ++spins) {
            const Mira::Result<ParseStep> step = parser.parse(input, eof);
            if (!step) {
                return true;  // a named failure is the good outcome
            }
            switch (*step) {
            case ParseStep::head:
                ++heads;
                if (heads > 1) return false;  // one message, one head
                continue;
            case ParseStep::body:
                if (parser.body().empty()) return false;  // a body step with no bytes lies
                continue;
            case ParseStep::complete:
                if (parser.response().status < 100 || parser.response().status >= 200 ||
                    parser.response().status == 101) {
                    return true;  // a final response or protocol switch ends this exchange
                }
                // Each 1xx is a complete message. Reset even though done() is
                // true, retaining unread bytes of the following response.
                // Cap work for fuzzing without imposing a protocol chain limit.
                parser.reset(method);
                heads = 0;
                if (++informational > 16) return true;  // pathological 1xx storm
                continue;
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
        if (eof) {
            // All bytes fed; whatever the parser still wants belongs to a
            // truncated message, which is a legal observation, not a bug.
            return true;
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0 || size > 4096) {
        return 0;  // the parser's limits are unit-tested; fuzz the grammar
    }
    const std::string_view payload{reinterpret_cast<const char*>(data), size};
    // Exercise every request-method context without consuming a selector from
    // the HTTP wire; existing literal HTTP corpus entries remain effective.
    for (std::uint8_t strategy = 0; strategy < 4; ++strategy) {
        if (!drive(payload, strategy)) std::abort();
    }
    return 0;
}
