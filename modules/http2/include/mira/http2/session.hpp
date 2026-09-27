#pragma once

#include "mira/core/error.hpp"
#include "mira/http2/headers.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace Mira::http2 {

enum class Role { client, server };
enum class State { open, draining, closed, failed };

struct Limits {
    std::size_t max_streams = 100;
    std::size_t max_header_bytes = 32 * 1024;
    std::size_t max_headers = 100;
    std::size_t max_body_bytes = 1024 * 1024;
    std::size_t max_queued_body_bytes = 4 * 1024 * 1024;
    std::size_t max_output_bytes = 64 * 1024;
    std::size_t max_queued_frames = 256;
};

struct Stream {
    std::int32_t id = 0;
    Headers headers;
    Headers trailers;
    std::vector<std::byte> body;
    bool headers_received = false;
    bool remote_end = false;
    bool closed = false;
    std::uint32_t wire_error = 0;
    Error error;
};

// Single-threaded, I/O-free HTTP/2 prior-knowledge engine. TLS callers must confirm ALPN=h2 first.
// Closed streams still count against the quota until release; body flow-control credit is returned
// only after take_body. Server push, CONNECT, h2c Upgrade, and sending informational/trailers are
// not supported.
class Session {
public:
    static Result<Session> create(Role role, Limits limits = {});
    ~Session();
    Session(Session&&) noexcept;
    Session& operator=(Session&&) noexcept;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    Result<std::int32_t> request(const Headers& headers, std::span<const std::byte> body = {});
    Result<void> respond(std::int32_t id, const Headers& headers,
                         std::span<const std::byte> body = {});
    Result<void> receive(std::span<const std::byte> bytes);
    Result<std::vector<std::byte>> output();
    Result<std::vector<std::byte>> take_body(std::int32_t id);
    Result<void> cancel(std::int32_t id);
    Result<void> release(std::int32_t id);
    Result<void> goaway(std::uint32_t error_code = 0);
    void close(Error reason = make_error_code(Errc::eof));

    const Stream* stream(std::int32_t id) const noexcept;
    std::vector<std::int32_t> streams() const;
    State state() const noexcept;
    Error error() const noexcept;
    std::int32_t peer_last_stream_id() const noexcept;
    std::uint32_t peer_goaway_error() const noexcept;
    bool wants_write() const noexcept;

private:
    struct Impl;
    explicit Session(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

// nghttp2 negative error codes are kept in a separate error_category.
Error engine_error(int code) noexcept;

} // namespace Mira::http2
