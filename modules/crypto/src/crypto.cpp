#include "mira/crypto/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <limits>

namespace Mira::crypto {
Result<void> random_bytes(std::span<std::byte> destination) {
    while (!destination.empty()) {
        const auto count = std::min(destination.size(),
                                    static_cast<std::size_t>(std::numeric_limits<int>::max()));
        if (RAND_bytes(reinterpret_cast<unsigned char*>(destination.data()),
                       static_cast<int>(count)) != 1) return fail(Errc::internal);
        destination = destination.subspan(count);
    }
    return {};
}
Result<std::array<std::byte, 20>> sha1(std::span<const std::byte> input) {
    std::array<std::byte, 20> digest{};
    unsigned length = 0;
    if (EVP_Digest(input.data(), input.size(), reinterpret_cast<unsigned char*>(digest.data()),
                   &length, EVP_sha1(), nullptr) != 1 || length != digest.size())
        return fail(Errc::internal);
    return digest;
}
}  // namespace Mira::crypto
