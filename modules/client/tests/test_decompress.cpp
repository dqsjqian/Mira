// Content-Encoding decoding: round-trips through zlib when available,
// and the no-zlib fallback (identity works, real codings fail cleanly).

#include "check.hpp"
#include "mira/client/decompress.hpp"

#include <string>

#ifdef MIRA_CLIENT_HAS_ZLIB
#include <zlib.h>
#endif

using namespace Mira;
using namespace Mira::client;

namespace {

std::vector<std::byte> bytes_of(std::string_view value) {
    const auto view = std::as_bytes(std::span{value.data(), value.size()});
    return {view.begin(), view.end()};
}

std::string text_of(std::span<const std::byte> bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

#ifdef MIRA_CLIENT_HAS_ZLIB
std::vector<std::byte> compress_with(int window_bits, std::string_view input) {
    z_stream stream{};
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY) !=
        Z_OK)
        return {};
    std::vector<std::byte> output(deflateBound(&stream, static_cast<uLong>(input.size())));
    stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    stream.next_out = reinterpret_cast<Bytef*>(output.data());
    stream.avail_out = static_cast<uInt>(output.size());
    const int result = deflate(&stream, Z_FINISH);
    const auto produced = output.size() - stream.avail_out;
    deflateEnd(&stream);
    if (result != Z_STREAM_END) return {};
    output.resize(produced);
    return output;
}
#endif

void checks() {
    test::section("identity and empty input need no codec");
    const auto plain = bytes_of("hello");
    const auto identity = decompress_body("identity", plain);
    CHECK(identity.has_value() && text_of(*identity) == "hello");
    const auto empty = decompress_body("gzip", {});
    CHECK(empty.has_value() && empty->empty());

    test::section("unknown codings and malformed lists fail");
    CHECK(!decompress_body("br", plain) && decompress_body("br", plain).error() == Errc::not_supported);
    CHECK(!decompress_body("gzip,", plain) && decompress_body("gzip,", plain).error() == Errc::invalid_argument);
    CHECK(!decompress_body("", plain) && decompress_body("", plain).error() == Errc::invalid_argument);

#ifdef MIRA_CLIENT_HAS_ZLIB
    test::section("gzip round-trip, case and whitespace tolerant");
    const auto gzipped = compress_with(31, "hello gzip");
    CHECK(!gzipped.empty());
    const auto gunzipped = decompress_body(" GZip ", gzipped);
    CHECK(gunzipped.has_value() && text_of(*gunzipped) == "hello gzip");

    test::section("deflate accepts zlib-wrapped and raw streams");
    const auto wrapped = compress_with(15, "hello deflate");
    const auto unwrapped = decompress_body("deflate", wrapped);
    CHECK(unwrapped.has_value() && text_of(*unwrapped) == "hello deflate");
    const auto raw = compress_with(-15, "hello raw");
    const auto unrawed = decompress_body("deflate", raw);
    CHECK(unrawed.has_value() && text_of(*unrawed) == "hello raw");

    test::section("stacked codings decode in reverse application order");
    const auto inner = compress_with(31, "stacked");
    const auto outer = compress_with(15, std::string_view{reinterpret_cast<const char*>(inner.data()), inner.size()});
    const auto unstacked = decompress_body("gzip, deflate", outer);
    CHECK(unstacked.has_value() && text_of(*unstacked) == "stacked");

    test::section("corrupt, truncated and bomb inputs fail");
    auto corrupt = gzipped;
    corrupt[corrupt.size() / 2] = static_cast<std::byte>(static_cast<unsigned char>(corrupt[corrupt.size() / 2]) ^ 0xff);
    CHECK(!decompress_body("gzip", corrupt));
    const auto truncated = std::span<const std::byte>{gzipped}.first(gzipped.size() / 2);
    CHECK(!decompress_body("gzip", truncated));
    const auto big = compress_with(31, std::string(1024, 'a'));
    const auto capped = decompress_body("gzip", big, 16);
    CHECK(!capped && capped.error() == Errc::limit_exceeded);
    // A wrapped-deflate bomb must stay limit_exceeded, not fall through to
    // the raw retry and come back as corrupt input.
    const auto big_deflate = compress_with(15, std::string(1024, 'a'));
    const auto capped_deflate = decompress_body("deflate", big_deflate, 16);
    CHECK(!capped_deflate && capped_deflate.error() == Errc::limit_exceeded);
#else
    test::section("without zlib, real codings fail with not_supported");
    const auto gzipped = bytes_of("not really gzip");
    const auto denied = decompress_body("gzip", gzipped);
    CHECK(!denied && denied.error() == Errc::not_supported);
#endif
}

}  // namespace

int main() {
    checks();
    return test::summary();
}
