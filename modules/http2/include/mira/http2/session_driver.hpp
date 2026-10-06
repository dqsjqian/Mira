#pragma once

#include "mira/core/stream.hpp"
#include "mira/http/session_driver.hpp"
#include "mira/http2/session.hpp"

#include <array>

namespace Mira::http2 {

// Independent read/write workers touch the Session only synchronously around
// co_await; while suspended they borrow only the independent byte buffers inside frames.
template<BoundedStream Transport>
struct SessionWire {
    Transport& transport;
    Session& session;

    Task<Result<void>> read(OperationOptions options) {
        if (session.state() == State::closed || session.state() == State::failed)
            co_return fail(session.error() ? session.error() : make_error_code(Errc::eof));
        std::array<std::byte, 16384> buffer{};
        auto result = co_await transport.read_some(buffer, options);
        if (!result || *result == 0) {
            auto error = result ? make_error_code(Errc::eof) : result.error();
            session.close(error);
            co_return fail(error);
        }
        if (*result > buffer.size()) co_return fail(std::make_error_code(std::errc::protocol_error));
        co_return session.receive(std::span<const std::byte>(buffer).first(*result));
    }
    Task<Result<void>> flush(OperationOptions options) {
        if (session.state() == State::closed || session.state() == State::failed)
            co_return fail(session.error() ? session.error() : make_error_code(Errc::eof));
        while (session.wants_write()) {
            auto bytes = session.output();
            if (!bytes) co_return fail(bytes.error());
            if (bytes->empty()) break;
            auto result = co_await write_all(transport, *bytes, options);
            if (!result) {
                session.close(result.error());
                co_return fail(result.error());
            }
        }
        co_return Result<void>{};
    }
};

// Borrows the connection's engine and transport; after construction never call
// Connection::pump/read/flush. Per-stream callers submit requests/reads for
// their own stream synchronously and then await via progress/flush without
// serializing the whole connection.
template<BoundedStream Transport>
class SessionDriver : public http::SessionDriver<SessionWire<Transport>> {
public:
    SessionDriver(EventLoop& loop, Transport& transport, Session& session,
                  std::size_t max_waiters = 256)
        : http::SessionDriver<SessionWire<Transport>>(loop, {transport, session}, max_waiters) {}
};

} // namespace Mira::http2
