#pragma once
#include "mira/core/error.hpp"
#include <array>
#include <cstddef>
#include <span>

namespace Mira::crypto {
/// OS-seeded OpenSSL CSPRNG. Never falls back to a deterministic generator.
Result<void> random_bytes(std::span<std::byte> destination);
/// Legacy SHA-1 for protocol-required WebSocket handshake validation only.
/// Not a password hash, signature primitive or general integrity recommendation.
Result<std::array<std::byte, 20>> sha1(std::span<const std::byte> input);
/// SHA-256 摘要，不提供口令派生语义。
Result<std::array<std::byte, 32>> sha256(std::span<const std::byte> input);
enum class SignatureAlgorithm { ecdsa_p256_sha256, ed25519 };
/// 公钥为 P-256 的 x||y（各32字节），或 Ed25519 的32字节公钥；签名均为64字节。
/// ECDSA 签名为固定宽度 r||s。无效签名返回 false，格式/算法错误通过 Result 返回。
Result<bool> verify_signature(SignatureAlgorithm algorithm, std::span<const std::byte> public_key,
    std::span<const std::byte> message, std::span<const std::byte> signature);
}  // namespace Mira::crypto
