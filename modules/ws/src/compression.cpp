#include "mira/ws/compression.hpp"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

namespace Mira::ws {
namespace {
constexpr std::array<std::byte, 4> flush_tail{
    std::byte{0}, std::byte{0}, std::byte{0xff}, std::byte{0xff}};

bool control(Opcode opcode) { return static_cast<unsigned>(opcode) >= 8; }
bool known(Opcode opcode) {
    return opcode == Opcode::continuation || opcode == Opcode::text || opcode == Opcode::binary ||
           opcode == Opcode::close || opcode == Opcode::ping || opcode == Opcode::pong;
}
bool valid_parameters(const CompressionParameters& parameters) {
    return parameters.server_max_window_bits >= 8 && parameters.server_max_window_bits <= 15 &&
           parameters.client_max_window_bits >= 8 && parameters.client_max_window_bits <= 15;
}
Error zlib_error(int status) {
    return status == Z_MEM_ERROR ? std::make_error_code(std::errc::not_enough_memory) :
                                  make_error_code(Errc::protocol);
}
bool fits(std::size_t current, std::size_t added, std::size_t limit) {
    return added <= limit && current <= limit - added;
}

struct MessageState {
    Limits limits;
    Error error;
    std::optional<Opcode> fragmented;
    bool compressed = false;
    std::size_t input_size = 0;
    std::size_t output_size = 0;
    unsigned utf8_remaining = 0;
    std::uint32_t utf8_value = 0;
    std::uint32_t utf8_minimum = 0;

    explicit MessageState(Limits bounds) : limits(bounds) {}

    Result<void> check(const Frame& frame, bool allow_compression) {
        if (error) return fail(error);
        if (!known(frame.opcode) ||
            (frame.compressed && (!allow_compression ||
             (frame.opcode != Opcode::text && frame.opcode != Opcode::binary))) ||
            (control(frame.opcode) && (!frame.final || frame.payload.size() > 125)))
            return fail(make_error_code(Errc::protocol));
        if (frame.payload.size() > limits.max_frame) return fail(Mira::Errc::limit_exceeded);
        if (control(frame.opcode)) {
            if (frame.opcode == Opcode::close) {
                if (frame.payload.size() == 1) return fail(make_error_code(Errc::protocol));
                if (frame.payload.size() >= 2) {
                    auto code = static_cast<std::uint16_t>(
                        (std::to_integer<unsigned>(frame.payload[0]) << 8) |
                         std::to_integer<unsigned>(frame.payload[1]));
                    if (!valid_close_code(code)) return fail(make_error_code(Errc::protocol));
                    if (!valid_utf8(std::span<const std::byte>(frame.payload).subspan(2)))
                        return fail(make_error_code(Errc::invalid_utf8));
                }
            }
            return {};
        }
        if ((frame.opcode == Opcode::continuation) != fragmented.has_value())
            return fail(make_error_code(Errc::protocol));
        if (!fits(input_size, frame.payload.size(), limits.max_message))
            return fail(Mira::Errc::limit_exceeded);
        input_size += frame.payload.size();
        if (frame.opcode != Opcode::continuation) compressed = frame.compressed;
        return {};
    }

    Result<void> text(std::span<const std::byte> bytes) {
        for (auto byte : bytes) {
            auto c = std::to_integer<unsigned>(byte);
            if (!utf8_remaining) {
                if (c < 0x80) continue;
                if (c >= 0xc2 && c <= 0xdf) { utf8_remaining = 1; utf8_value = c & 31; utf8_minimum = 0x80; }
                else if (c >= 0xe0 && c <= 0xef) { utf8_remaining = 2; utf8_value = c & 15; utf8_minimum = 0x800; }
                else if (c >= 0xf0 && c <= 0xf4) { utf8_remaining = 3; utf8_value = c & 7; utf8_minimum = 0x10000; }
                else return fail(make_error_code(Errc::invalid_utf8));
            } else {
                if ((c & 0xc0) != 0x80 ||
                    (utf8_remaining == 2 && utf8_minimum == 0x800 &&
                     ((utf8_value == 0 && c < 0xa0) || (utf8_value == 13 && c >= 0xa0))) ||
                    (utf8_remaining == 3 && utf8_minimum == 0x10000 &&
                     ((utf8_value == 0 && c < 0x90) || (utf8_value == 4 && c >= 0x90))))
                    return fail(make_error_code(Errc::invalid_utf8));
                utf8_value = (utf8_value << 6) | (c & 63);
                if (--utf8_remaining == 0 &&
                    (utf8_value < utf8_minimum || utf8_value > 0x10ffff ||
                     (utf8_value >= 0xd800 && utf8_value <= 0xdfff)))
                    return fail(make_error_code(Errc::invalid_utf8));
            }
        }
        return {};
    }

    Result<void> plaintext(const Frame& frame) {
        if (control(frame.opcode)) return {};
        if (fragmented.value_or(frame.opcode) == Opcode::text) {
            auto checked = text(frame.payload);
            if (!checked) return checked;
            if (frame.final && utf8_remaining) return fail(make_error_code(Errc::invalid_utf8));
        }
        return {};
    }

    Result<void> append(std::vector<std::byte>& output, std::span<const std::byte> bytes) {
        if (!fits(output.size(), bytes.size(), limits.max_frame) ||
            !fits(output_size, bytes.size(), limits.max_message))
            return fail(Mira::Errc::limit_exceeded);
        output.insert(output.end(), bytes.begin(), bytes.end());
        output_size += bytes.size();
        return {};
    }

    void finish(const Frame& frame) {
        if (control(frame.opcode)) return;
        if (frame.final) {
            fragmented.reset();
            compressed = false;
            input_size = 0;
            output_size = 0;
            utf8_remaining = 0;
            utf8_value = 0;
            utf8_minimum = 0;
        } else {
            fragmented = fragmented.value_or(frame.opcode);
        }
    }
};
}

struct DeflateEncoder::Impl {
    MessageState message;
    z_stream stream{};
    bool initialized = false;
    bool enabled;
    bool no_context;

    Impl(CompressionParameters parameters, Limits limits, Role role)
        : message(limits), enabled(parameters.enabled),
          no_context(role == Role::server ? parameters.server_no_context_takeover :
                                          parameters.client_no_context_takeover) {}
    ~Impl() { if (initialized) deflateEnd(&stream); }

    Result<Frame> encode(const Frame& frame) {
        auto checked = message.check(frame, false);
        if (!checked) return fail(checked.error());
        checked = message.plaintext(frame);
        if (!checked) return fail(checked.error());
        if (!enabled || control(frame.opcode)) {
            message.finish(frame);
            return frame;
        }
        Frame output{frame.opcode, frame.final, {}, frame.opcode != Opcode::continuation};
        std::array<std::byte, 4096> buffer{};
        std::array<std::byte, 4> pending{};
        std::size_t pending_size = 0;
        auto input = std::span<const std::byte>(frame.payload);
        bool flushed = false;
        do {
            auto count = static_cast<uInt>(std::min(input.size(),
                static_cast<std::size_t>(std::numeric_limits<uInt>::max())));
            stream.next_in = reinterpret_cast<Bytef*>(const_cast<std::byte*>(input.data()));
            stream.avail_in = count;
            input = input.subspan(count);
            const int flush = input.empty() ? Z_SYNC_FLUSH : Z_NO_FLUSH;
            do {
                stream.next_out = reinterpret_cast<Bytef*>(buffer.data());
                stream.avail_out = static_cast<uInt>(buffer.size());
                auto status = deflate(&stream, flush);
                if (status != Z_OK && status != Z_BUF_ERROR) return fail(zlib_error(status));
                const auto produced = buffer.size() - stream.avail_out;
                // Keep only the removable final four octets outside the bounded output.
                if (frame.final) {
                    const auto release = pending_size + produced > pending.size() ?
                        pending_size + produced - pending.size() : 0;
                    const auto old_release = std::min(release, pending_size);
                    checked = message.append(output.payload,
                        std::span<const std::byte>(pending).first(old_release));
                    if (!checked) return fail(checked.error());
                    const auto new_release = release - old_release;
                    checked = message.append(output.payload,
                        std::span<const std::byte>(buffer).first(new_release));
                    if (!checked) return fail(checked.error());
                    if (old_release)
                        std::move(pending.begin() + static_cast<std::ptrdiff_t>(old_release),
                                  pending.begin() + static_cast<std::ptrdiff_t>(pending_size), pending.begin());
                    pending_size -= old_release;
                    std::copy_n(buffer.begin() + static_cast<std::ptrdiff_t>(new_release),
                                produced - new_release,
                                pending.begin() + static_cast<std::ptrdiff_t>(pending_size));
                    pending_size += produced - new_release;
                } else {
                    checked = message.append(output.payload,
                        std::span<const std::byte>(buffer).first(produced));
                    if (!checked) return fail(checked.error());
                }
                if (status == Z_BUF_ERROR && (stream.avail_in || produced))
                    return fail(make_error_code(Errc::protocol));
                flushed = flush == Z_SYNC_FLUSH && stream.avail_in == 0 && stream.avail_out != 0;
            } while (stream.avail_in || stream.avail_out == 0);
        } while (!input.empty() || !flushed);
        if (frame.final) {
            if (pending_size == 0) {
                // Repeated empty flushes produce no bytes; an empty stored block is required.
                const std::array<std::byte, 1> empty_block{std::byte{0}};
                checked = message.append(output.payload, empty_block);
                if (!checked) return fail(checked.error());
            } else if (pending_size != flush_tail.size() || pending != flush_tail) {
                return fail(make_error_code(Errc::protocol));
            }
            if (no_context) {
                auto status = deflateReset(&stream);
                if (status != Z_OK) return fail(zlib_error(status));
            }
        }
        message.finish(frame);
        return output;
    }
};

struct DeflateDecoder::Impl {
    MessageState message;
    z_stream stream{};
    bool initialized = false;
    bool enabled;
    bool no_context;
    unsigned last_byte = 0;

    Impl(CompressionParameters parameters, Limits limits, Role role)
        : message(limits), enabled(parameters.enabled),
          no_context(role == Role::server ? parameters.client_no_context_takeover :
                                          parameters.server_no_context_takeover) {}
    ~Impl() { if (initialized) inflateEnd(&stream); }

    Result<void> inflate_bytes(std::span<const std::byte> input, std::vector<std::byte>& output,
                               bool text_message, bool synthetic_tail = false) {
        std::array<std::byte, 4096> buffer{};
        do {
            const auto count = static_cast<uInt>(std::min(input.size(),
                static_cast<std::size_t>(std::numeric_limits<uInt>::max())));
            stream.next_in = reinterpret_cast<Bytef*>(const_cast<std::byte*>(input.data()));
            stream.avail_in = count;
            input = input.subspan(count);
            for (;;) {
                auto before = stream.avail_in;
                stream.next_out = reinterpret_cast<Bytef*>(buffer.data());
                stream.avail_out = static_cast<uInt>(buffer.size());
                auto status = inflate(&stream, Z_BLOCK);
                const auto produced = buffer.size() - stream.avail_out;
                if (before != stream.avail_in) last_byte = stream.next_in[-1];
                if (status != Z_OK && status != Z_BUF_ERROR && status != Z_STREAM_END)
                    return fail(zlib_error(status));
                auto block = std::span<const std::byte>(buffer).first(produced);
                if (text_message) {
                    auto checked = message.text(block);
                    if (!checked) return checked;
                }
                auto appended = message.append(output, block);
                if (!appended) return appended;
                if ((stream.data_type & 0xc0) == 0xc0) {
                    const auto padding = static_cast<unsigned>(stream.data_type & 0x3f);
                    if (padding > 7 || (padding && (last_byte >> (8 - padding))))
                        return fail(make_error_code(Errc::protocol));
                }
                if (status == Z_STREAM_END) {
                    // RFC7692 permits BFINAL blocks followed by byte-aligned blocks.
                    // Keep the negotiated LZ77 history, but require the final stored tail below.
                    status = inflateResetKeep(&stream);
                    if (status != Z_OK) return fail(zlib_error(status));
                    if (stream.avail_in) continue;
                    break;
                }
                if (status == Z_BUF_ERROR) {
                    if (stream.avail_in || produced) return fail(make_error_code(Errc::protocol));
                    break;
                }
                if (!stream.avail_in && stream.avail_out &&
                    ((synthetic_tail && (stream.data_type & 128)) ||
                     !((stream.data_type & 128) && (stream.data_type & 127)))) break;
            }
        } while (!input.empty());
        return {};
    }

    Result<Frame> decode(Frame frame) {
        auto checked = message.check(frame, enabled);
        if (!checked) return fail(checked.error());
        if (control(frame.opcode)) return frame;
        if (message.compressed) {
            const bool text_message = message.fragmented.value_or(frame.opcode) == Opcode::text;
            std::vector<std::byte> output;
            checked = inflate_bytes(frame.payload, output, text_message);
            if (!checked) return fail(checked.error());
            if (frame.final) {
                // Z_OK alone accepts truncated streams. Before the synthetic LEN/NLEN,
                // require the byte-aligned stored-block header mandated by RFC7692.
                if (inflateSyncPoint(&stream) != 1) return fail(make_error_code(Errc::protocol));
                checked = inflate_bytes(flush_tail, output, text_message, true);
                if (!checked) return fail(checked.error());
                if (stream.data_type != 128 && stream.data_type != 192)
                    return fail(make_error_code(Errc::protocol));
                if (stream.data_type == 192) {
                    auto status = inflateResetKeep(&stream);
                    if (status != Z_OK) return fail(zlib_error(status));
                }
                if (no_context) {
                    auto status = inflateReset(&stream);
                    if (status != Z_OK) return fail(zlib_error(status));
                }
            }
            if (text_message && frame.final && message.utf8_remaining)
                return fail(make_error_code(Errc::invalid_utf8));
            frame.payload = std::move(output);
            frame.compressed = false;
        } else {
            checked = message.plaintext(frame);
            if (!checked) return fail(checked.error());
        }
        message.finish(frame);
        return frame;
    }
};

Result<DeflateEncoder> DeflateEncoder::create(Role role, CompressionParameters parameters, Limits limits) {
    const auto bits = role == Role::server ? parameters.server_max_window_bits : parameters.client_max_window_bits;
    if (parameters.enabled && (!valid_parameters(parameters) || bits < 9)) return fail(Mira::Errc::invalid_argument);
    auto impl = std::make_unique<Impl>(parameters, limits, role);
    if (parameters.enabled) {
        auto status = deflateInit2(&impl->stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                                  -static_cast<int>(bits), 8, Z_DEFAULT_STRATEGY);
        if (status != Z_OK) return fail(zlib_error(status));
        impl->initialized = true;
    }
    return DeflateEncoder(std::move(impl));
}
DeflateEncoder::DeflateEncoder(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
DeflateEncoder::DeflateEncoder(DeflateEncoder&&) noexcept = default;
DeflateEncoder& DeflateEncoder::operator=(DeflateEncoder&&) noexcept = default;
DeflateEncoder::~DeflateEncoder() = default;
Result<Frame> DeflateEncoder::encode(const Frame& frame) {
    if (!impl_) return fail(Mira::Errc::invalid_argument);
    if (impl_->message.error) return fail(impl_->message.error);
    try {
        auto result = impl_->encode(frame);
        if (!result) impl_->message.error = result.error();
        return result;
    } catch (const std::bad_alloc&) {
        impl_->message.error = std::make_error_code(std::errc::not_enough_memory);
    } catch (const std::length_error&) {
        impl_->message.error = Mira::make_error_code(Mira::Errc::limit_exceeded);
    }
    return fail(impl_->message.error);
}

Result<DeflateDecoder> DeflateDecoder::create(Role role, CompressionParameters parameters, Limits limits) {
    if (parameters.enabled && !valid_parameters(parameters)) return fail(Mira::Errc::invalid_argument);
    auto impl = std::make_unique<Impl>(parameters, limits, role);
    if (parameters.enabled) {
        const auto bits = role == Role::server ? parameters.client_max_window_bits : parameters.server_max_window_bits;
        auto status = inflateInit2(&impl->stream, -static_cast<int>(bits));
        if (status != Z_OK) return fail(zlib_error(status));
        impl->initialized = true;
    }
    return DeflateDecoder(std::move(impl));
}
DeflateDecoder::DeflateDecoder(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
DeflateDecoder::DeflateDecoder(DeflateDecoder&&) noexcept = default;
DeflateDecoder& DeflateDecoder::operator=(DeflateDecoder&&) noexcept = default;
DeflateDecoder::~DeflateDecoder() = default;
Result<Frame> DeflateDecoder::decode(Frame frame) {
    if (!impl_) return fail(Mira::Errc::invalid_argument);
    if (impl_->message.error) return fail(impl_->message.error);
    try {
        auto result = impl_->decode(std::move(frame));
        if (!result) impl_->message.error = result.error();
        return result;
    } catch (const std::bad_alloc&) {
        impl_->message.error = std::make_error_code(std::errc::not_enough_memory);
    } catch (const std::length_error&) {
        impl_->message.error = Mira::make_error_code(Mira::Errc::limit_exceeded);
    }
    return fail(impl_->message.error);
}
} // namespace Mira::ws
