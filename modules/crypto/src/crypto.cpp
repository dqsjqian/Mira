#include "mira/crypto/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <algorithm>
#include <limits>
#include <memory>
#include <vector>

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
Result<std::array<std::byte, 32>> sha256(std::span<const std::byte> input) {
    std::array<std::byte, 32> digest{};
    unsigned length = 0;
    if (EVP_Digest(input.data(), input.size(), reinterpret_cast<unsigned char*>(digest.data()),
                   &length, EVP_sha256(), nullptr) != 1 || length != digest.size())
        return fail(Errc::internal);
    return digest;
}
Result<bool> verify_signature(SignatureAlgorithm algorithm, std::span<const std::byte> public_key,
    std::span<const std::byte> message, std::span<const std::byte> signature) {
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    Key key{nullptr, EVP_PKEY_free};
    std::vector<unsigned char> der;
    const EVP_MD* digest = nullptr;
    if (signature.size() != 64) return fail(Errc::invalid_argument);
    if (algorithm == SignatureAlgorithm::ed25519) {
        if (public_key.size() != 32) return fail(Errc::invalid_argument);
        key.reset(EVP_PKEY_new_raw_public_key_ex(nullptr, "ED25519", nullptr,
            reinterpret_cast<const unsigned char*>(public_key.data()), public_key.size()));
    } else if (algorithm == SignatureAlgorithm::ecdsa_p256_sha256) {
        if (public_key.size() != 64) return fail(Errc::invalid_argument);
        std::array<unsigned char, 65> point{};
        point[0] = 4;
        std::transform(public_key.begin(), public_key.end(), point.begin() + 1,
            [](std::byte b) { return std::to_integer<unsigned char>(b); });
        std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> builder{OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free};
        if (!builder || OSSL_PARAM_BLD_push_utf8_string(builder.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1 ||
            OSSL_PARAM_BLD_push_octet_string(builder.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size()) != 1)
            return fail(Errc::internal);
        std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params{OSSL_PARAM_BLD_to_param(builder.get()), OSSL_PARAM_free};
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context{
            EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free};
        if (!params || !context || EVP_PKEY_fromdata_init(context.get()) != 1) return fail(Errc::internal);
        EVP_PKEY* raw = nullptr;
        const int imported = EVP_PKEY_fromdata(context.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get());
        key.reset(raw);
        if (imported != 1 || !key) return fail(Errc::invalid_argument);
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> check{
            EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr), EVP_PKEY_CTX_free};
        if (!check) return fail(Errc::internal);
        if (EVP_PKEY_public_check(check.get()) != 1) return fail(Errc::invalid_argument);
        std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig{ECDSA_SIG_new(), ECDSA_SIG_free};
        std::unique_ptr<BIGNUM, decltype(&BN_free)> r{BN_bin2bn(reinterpret_cast<const unsigned char*>(signature.data()), 32, nullptr), BN_free};
        std::unique_ptr<BIGNUM, decltype(&BN_free)> s{BN_bin2bn(reinterpret_cast<const unsigned char*>(signature.data() + 32), 32, nullptr), BN_free};
        if (!sig || !r || !s || ECDSA_SIG_set0(sig.get(), r.get(), s.get()) != 1) return fail(Errc::internal);
        static_cast<void>(r.release()); static_cast<void>(s.release());
        const int size = i2d_ECDSA_SIG(sig.get(), nullptr);
        if (size <= 0) return fail(Errc::internal);
        der.resize(static_cast<std::size_t>(size));
        auto* cursor = der.data();
        if (i2d_ECDSA_SIG(sig.get(), &cursor) != size) return fail(Errc::internal);
        digest = EVP_sha256();
    } else return fail(Errc::not_supported);
    if (!key) return fail(Errc::invalid_argument);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!context || EVP_DigestVerifyInit(context.get(), nullptr, digest, nullptr, key.get()) != 1)
        return fail(Errc::internal);
    const auto* bytes = der.empty() ? reinterpret_cast<const unsigned char*>(signature.data()) : der.data();
    const auto size = der.empty() ? signature.size() : der.size();
    return EVP_DigestVerify(context.get(), bytes, size,
        reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1;
}
}  // namespace Mira::crypto
