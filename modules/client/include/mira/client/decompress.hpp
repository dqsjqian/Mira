#pragma once

// Content-Encoding decoding for HTTP clients (RFC 9110 §8.4).
//
// A response body is just bytes; what Content-Encoding says about those
// bytes is the client's job to undo. This is the explicit counterpart to
// the redirect helper: after request_with_redirects (or any exchange)
// returns a body, pass its Content-Encoding header here.
//
// Supported codings: identity, gzip, deflate. Stacked codings
// ("gzip, deflate") are decoded in reverse application order, as the RFC
// requires. Anything else (br, zstd, ...) fails with not_supported — no
// Brotli or zstd dependency is in scope.
//
// "deflate" is the zlib-wrapped form per the RFC; because servers have
// historically also sent raw deflate, a zlib-wrapped failure retries as
// raw deflate before giving up. gzip decodes a single member; trailing
// bytes after a complete member are ignored.
//
// Bounds: decoding stops with limit_exceeded once any single stage's
// output passes max_bytes, so a compression bomb cannot grow past the
// caller's budget. An empty body decodes to empty under any coding.
// Corrupt or truncated input fails with invalid_argument.
//
// zlib is optional: the build defines MIRA_CLIENT_HAS_ZLIB when it finds
// zlib, and the client target links it. Without zlib, identity still
// works and every real coding fails with not_supported, so a no-zlib
// build keeps compiling and running — it just cannot decode.

#include "mira/core/error.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef MIRA_CLIENT_HAS_ZLIB
#include <zlib.h>
#endif

namespace Mira::client {

namespace detail {

inline std::string lower_token(std::string_view token) {
    std::string result;
    result.reserve(token.size());
    for (char c : token) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        result.push_back(c);
    }
    return result;
}

inline std::string_view trim_ows(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    return value;
}

#ifdef MIRA_CLIENT_HAS_ZLIB
inline Result<std::vector<std::byte>> inflate_bytes(std::span<const std::byte> input, int window_bits,
                                                    std::size_t max_bytes) {
    z_stream stream{};
    if (inflateInit2(&stream, window_bits) != Z_OK) return fail(Errc::internal);
    struct Guard {
        z_stream* stream;
        ~Guard() { static_cast<void>(inflateEnd(stream)); }
    } guard{&stream};
    std::vector<std::byte> output;
    std::array<std::byte, 65536> chunk{};
    std::size_t offset = 0;
    int result = Z_OK;
    do {
        if (stream.avail_in == 0 && offset < input.size()) {
            const auto take =
                std::min<std::size_t>(input.size() - offset, std::numeric_limits<uInt>::max());
            stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input.data() + offset));
            stream.avail_in = static_cast<uInt>(take);
            offset += take;
        }
        const auto consumed_before = offset - stream.avail_in;
        stream.next_out = reinterpret_cast<Bytef*>(chunk.data());
        stream.avail_out = static_cast<uInt>(chunk.size());
        result = inflate(&stream, Z_NO_FLUSH);
        if (result != Z_OK && result != Z_STREAM_END && result != Z_BUF_ERROR)
            return fail(Errc::invalid_argument);
        const auto produced = chunk.size() - stream.avail_out;
        // No input consumed and no output produced without finishing means
        // the stream is truncated or corrupt; without this guard the loop
        // would spin on Z_BUF_ERROR forever.
        if (produced == 0 && result != Z_STREAM_END && offset - stream.avail_in <= consumed_before)
            return fail(Errc::invalid_argument);
        if (output.size() + produced > max_bytes) return fail(Errc::limit_exceeded);
        output.insert(output.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(produced));
    } while (result != Z_STREAM_END);
    return output;
}
#endif

}  // namespace detail

[[nodiscard]] inline Result<std::vector<std::byte>> decompress_body(std::string_view content_encoding,
                                                                    std::span<const std::byte> body,
                                                                    std::size_t max_bytes = 16 * 1024 * 1024) {
    // The no-zlib path ignores the cap (identity needs none); keep the
    // parameter named and referenced in both configurations.
    static_cast<void>(max_bytes);
    if (body.empty()) return std::vector<std::byte>{};
    std::vector<std::string> codings;
    std::size_t pos = 0;
    while (pos <= content_encoding.size()) {
        const auto comma = content_encoding.find(',', pos);
        const auto token = detail::trim_ows(content_encoding.substr(
            pos, comma == std::string_view::npos ? std::string_view::npos : comma - pos));
        if (token.empty()) return fail(Errc::invalid_argument);
        codings.push_back(detail::lower_token(token));
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    std::vector<std::byte> current(body.begin(), body.end());
    for (auto it = codings.rbegin(); it != codings.rend(); ++it) {
        if (*it == "identity") continue;
        if (*it != "gzip" && *it != "deflate") return fail(Errc::not_supported);
#ifdef MIRA_CLIENT_HAS_ZLIB
        if (*it == "gzip") {
            auto decoded = detail::inflate_bytes(current, 31, max_bytes);
            if (!decoded) return fail(decoded.error());
            current = std::move(*decoded);
        } else {
            auto wrapped = detail::inflate_bytes(current, 15, max_bytes);
            if (wrapped) {
                current = std::move(*wrapped);
            } else if (wrapped.error() == Errc::limit_exceeded || wrapped.error() == Errc::internal) {
                // A bomb or an internal failure is not a format hint: retrying
                // as raw deflate would only misreport it as corrupt input.
                return fail(wrapped.error());
            } else {
                auto raw = detail::inflate_bytes(current, -15, max_bytes);
                if (!raw) return fail(raw.error());
                current = std::move(*raw);
            }
        }
#else
        return fail(Errc::not_supported);
#endif
    }
    return current;
}

}  // namespace Mira::client
