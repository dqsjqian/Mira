#pragma once

#include "mira/core/stream.hpp"
#include "mira/http2/session.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace Mira::http2 {

// The adapter does not own the underlying stream; the stream and the Connection must stay alive
// and at a stable address until the task finishes. Only one outstanding operation is allowed per
// instance, including while suspended; during that time session() must not be accessed, read/flush/
// pump must not be called concurrently from other tasks, and the Connection must not be moved or
// destroyed. A single pump performs one round of output, one round of input, and protocol-reply
// output. The caller polls each stream and take_body to drive all concurrent requests; it never
// blocks serially on a single request. The vector returned by output() is owned independently by
// the flush coroutine frame, so suspending across write_all does not borrow engine memory.
// I/O cancellation or a deadline terminates the connection; to cancel a single stream use
// Session::cancel.
template<BoundedStream Transport>
class Connection {
public:
    Connection(Transport& transport, Session session)
        : transport_(&transport), session_(std::move(session)) {}

    // Same contract as tls::Stream and http::ClientConnection: destroying with I/O still in flight
    // means a suspended coroutine frame still borrows transport_ and the engine, so letting it
    // run on would be use-after-free. Rather than silent UB, diagnose and abort on the spot.
    ~Connection() {
        if (in_flight_) {
            std::fputs("Mira::http2::Connection destroyed with an operation still in flight\n",
                       stderr);
            std::abort();
        }
    }

    Session& session() noexcept { return session_; }
    const Session& session() const noexcept { return session_; }

    Task<Result<void>> flush(OperationOptions options = {}) {
        if (in_flight_) co_return fail(Errc::invalid_argument);
        Guard guard{in_flight_};
        co_return co_await flush_locked(options);
    }

    Task<Result<void>> read(OperationOptions options = {}) {
        if (in_flight_) co_return fail(Errc::invalid_argument);
        Guard guard{in_flight_};
        co_return co_await read_locked(options);
    }

    Task<Result<void>> pump(OperationOptions options = {}) {
        if (in_flight_) co_return fail(Errc::invalid_argument);
        Guard guard{in_flight_};
        auto result = co_await flush_locked(options);
        if (!result) co_return result;
        result = co_await read_locked(options);
        if (!result) co_return result;
        co_return co_await flush_locked(options);
    }

private:
    // The three *_locked helpers below assume the caller already holds the in-flight guard (a public entry point or pump).
    Task<Result<void>> flush_locked(OperationOptions options) {
        while (session_.wants_write()) {
            auto bytes = session_.output();
            if (!bytes) co_return fail(bytes.error());
            if (bytes->empty()) break;
            auto result = co_await write_all(*transport_, *bytes, options);
            if (!result) {
                session_.close(result.error());
                co_return fail(result.error());
            }
        }
        co_return Result<void>{};
    }

    Task<Result<void>> read_locked(OperationOptions options) {
        std::array<std::byte, 16384> bytes{};
        auto result = co_await transport_->read_some(bytes, options);
        if (!result || *result == 0) {
            auto error = result ? make_error_code(Errc::eof) : result.error();
            session_.close(error);
            co_return fail(error);
        }
        co_return session_.receive(std::span<const std::byte>(bytes.data(), *result));
    }

    // There is no stack-unwinding safety net between co_awaits, and an early co_return would skip
    // the sequential reset code, so an RAII guard clears the in-flight flag on every exit path.
    struct Guard {
        bool& flag;
        explicit Guard(bool& f) noexcept : flag(f) { flag = true; }
        ~Guard() { flag = false; }
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
    };

    Transport* transport_;
    Session session_;
    bool in_flight_ = false;  // true while one flush/read/pump is outstanding or suspended
};

} // namespace Mira::http2
