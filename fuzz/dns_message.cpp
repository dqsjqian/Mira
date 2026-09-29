// DNS wire decoding, re-encoding and DoH request extraction on hostile bytes.
#include "mira/dns/doh.hpp"
#include "mira/dns/message.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 65535) return 0;
    const auto bytes = std::as_bytes(std::span{data, size});
    Mira::dns::Limits limits;
    limits.max_records = 256;
    auto decoded = Mira::dns::decode(bytes, limits);
    if (decoded) {
        // Anything decoded must re-encode, and decode back to itself.
        auto encoded = Mira::dns::encode(*decoded);
        if (encoded) {
            auto again = Mira::dns::decode(*encoded, limits);
            if (!again || *again != *decoded) std::abort();
        }
        (void)Mira::dns::min_ttl(*decoded);
        for (const auto& question : decoded->questions) {
            auto reparsed = Mira::dns::Name::parse(question.name.to_string());
            if (!reparsed || !(*reparsed == question.name)) std::abort();
        }
    }
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    auto plain = Mira::dns::doh::base64url_decode(text);
    if (plain && Mira::dns::doh::base64url_encode(*plain) != text) std::abort();
    if (size < 4096) {
        Mira::http::Request request;
        request.target = "/dns-query?" + std::string(text);
        (void)Mira::dns::doh::decode_request(request, {});
        (void)Mira::dns::Name::parse(text);
    }
    return 0;
}
