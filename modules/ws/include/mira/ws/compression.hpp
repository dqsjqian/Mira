#pragma once

#include "mira/ws/frame.hpp"

#include <memory>

namespace Mira::ws {

// Window values are wire/RFC values. A valueless client window offer is
// represented separately from a numeric limit. Compression is opt-in.
struct CompressionOptions {
    bool enabled = false;
    bool server_no_context_takeover = false;
    bool client_no_context_takeover = false;
    std::optional<unsigned> server_max_window_bits;
    std::optional<unsigned> client_max_window_bits;
    bool offer_client_max_window_bits = true;
};

struct CompressionParameters {
    bool enabled = false;
    bool server_no_context_takeover = false;
    bool client_no_context_takeover = false;
    unsigned server_max_window_bits = 15;
    unsigned client_max_window_bits = 15;
};

// Each direction owns independent bounded zlib state; instances are move-only.
// Frames supplied to encode are application/plaintext frames. Frames returned
// by decode contain plaintext; RSV1 is consumed by the extension.
class DeflateEncoder {
public:
    static Result<DeflateEncoder> create(Role role, CompressionParameters parameters, Limits limits = {});
    DeflateEncoder(DeflateEncoder&&) noexcept;
    DeflateEncoder& operator=(DeflateEncoder&&) noexcept;
    ~DeflateEncoder();
    Result<Frame> encode(const Frame& frame);
private:
    struct Impl;
    explicit DeflateEncoder(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

class DeflateDecoder {
public:
    static Result<DeflateDecoder> create(Role role, CompressionParameters parameters, Limits limits = {});
    DeflateDecoder(DeflateDecoder&&) noexcept;
    DeflateDecoder& operator=(DeflateDecoder&&) noexcept;
    ~DeflateDecoder();
    Result<Frame> decode(Frame frame);
private:
    struct Impl;
    explicit DeflateDecoder(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

} // namespace Mira::ws
