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
}  // namespace Mira::crypto
