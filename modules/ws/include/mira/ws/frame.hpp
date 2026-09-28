#pragma once

#include "mira/core/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace Mira::ws {

enum class Role { client, server };
enum class Opcode : std::uint8_t { continuation = 0, text = 1, binary = 2, close = 8, ping = 9, pong = 10 };
enum class Errc { protocol = 1, invalid_utf8, invalid_handshake, crypto_failure, closed, abnormal_close };
std::error_code make_error_code(Errc value) noexcept;

struct Limits {
    std::size_t max_frame = 1024 * 1024;
    std::size_t max_message = 4 * 1024 * 1024;
    std::size_t max_handshake = 16384;
};

struct Frame {
    Opcode opcode = Opcode::binary;
    bool final = true;
    std::vector<std::byte> payload;
    bool compressed = false; // Wire RSV1: only the first data frame of a compressed message.
};

struct ParseResult {
    std::size_t consumed = 0;
    std::optional<Frame> frame;
};

bool valid_close_code(std::uint16_t code) noexcept;
bool valid_utf8(std::span<const std::byte> bytes) noexcept;
Result<std::vector<std::byte>> close_payload(std::uint16_t code = 1000,
                                           std::span<const std::byte> reason = {});

class FrameParser {
public:
    explicit FrameParser(Role local_role, Limits limits = {}, bool allow_compression = false);
    Result<ParseResult> feed(std::span<const std::byte> bytes);
    bool failed() const noexcept { return static_cast<bool>(error_); }
    void reset() noexcept;
private:
    Result<void> parse_header();
    Result<void> validate_frame();
    Role role_;
    Limits limits_;
    bool allow_compression_ = false;
    bool message_compressed_ = false;
    std::array<std::byte, 14> header_{};
    std::size_t header_size_ = 0;
    std::size_t header_needed_ = 2;
    std::size_t payload_size_ = 0;
    bool header_ready_ = false;
    bool masked_ = false;
    std::array<std::byte, 4> mask_{};
    Frame frame_;
    std::optional<Opcode> fragmented_;
    std::size_t message_size_ = 0;
    unsigned utf8_remaining_ = 0;
    std::uint32_t utf8_value_ = 0;
    std::uint32_t utf8_min_ = 0;
    bool closed_ = false;
    Error error_;
};

// Explicit mask keys support deterministic codec tests. Network clients must use
// Connection, which obtains a fresh mask from the crypto module for every frame.
Result<std::vector<std::byte>> serialize(const Frame& frame, Role sender,
    std::optional<std::array<std::byte, 4>> mask = std::nullopt, Limits limits = {},
    bool allow_compression = false);

} // namespace Mira::ws
