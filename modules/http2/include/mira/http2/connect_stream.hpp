#pragma once

#include "mira/core/stream.hpp"
#include "mira/http2/session.hpp"

#include <cstdio>
#include <cstdlib>

namespace Mira::http2 {

// Borrows an accepted Extended CONNECT stream. The driver serializes connection
// progress/flush and honors OperationOptions. Do not mix direct body operations.
// One operation per adapter; the caller owns cross-stream scheduling and stable
// lifetimes. close/cancel reset only this stream; finish half-closes local output.
template<class Driver>
requires requires(Driver& driver, OperationOptions options) {
    { driver.progress(options) } -> std::same_as<Task<Result<void>>>;
    { driver.flush(options) } -> std::same_as<Task<Result<void>>>;
}
class ConnectStream {
public:
    ConnectStream(Session& session, std::int32_t id, Driver& driver)
        : session_(&session), id_(id), driver_(&driver) {}
    ConnectStream(const ConnectStream&) = delete;
    ConnectStream& operator=(const ConnectStream&) = delete;
    ~ConnectStream() {
        if (busy_) {
            std::fputs("Mira::http2::ConnectStream destroyed with pending operation\n", stderr);
            std::abort();
        }
    }
    Task<Result<std::size_t>> read_some(std::span<std::byte> bytes, OperationOptions options = {}) {
        if (busy_) co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        for (;;) {
            if (auto checked = check(options); !checked) co_return fail(checked.error());
            auto result = session_->read_connect(id_, bytes);
            if (result) {
                if (auto flushed = co_await driver_->flush(options); !flushed)
                    co_return fail(stop(flushed.error()));
                co_return result;
            }
            if (result.error() != Errc::would_block) co_return fail(result.error());
            if (auto progress = co_await driver_->progress(options); !progress)
                co_return fail(stop(progress.error()));
        }
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes, OperationOptions options = {}) {
        if (busy_) co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        for (;;) {
            if (auto checked = check(options); !checked) co_return fail(checked.error());
            auto result = session_->write_connect(id_, bytes);
            if (result) {
                if (auto flushed = co_await driver_->flush(options); !flushed)
                    co_return fail(stop(flushed.error()));
                co_return result;
            }
            if (result.error() != Errc::would_block) co_return fail(result.error());
            if (auto progress = co_await driver_->progress(options); !progress)
                co_return fail(stop(progress.error()));
        }
    }
    Task<Result<void>> finish(OperationOptions options = {}) {
        if (busy_) co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        if (auto checked = check(options); !checked) co_return checked;
        auto state = session_->connect_state(id_);
        if (!state || !state->accepted) co_return fail(Errc::invalid_argument);
        if (auto finished = session_->finish_body(id_); !finished) co_return finished;
        if (auto flushed = co_await driver_->flush(options); !flushed)
            co_return fail(stop(flushed.error()));
        co_return Result<void>{};
    }
    void close() { static_cast<void>(stop(make_error_code(Errc::cancelled))); }

private:
    struct Guard {
        bool& busy;
        explicit Guard(bool& value) : busy(value) { busy = true; }
        ~Guard() { busy = false; }
    };
    Error stop(Error error) {
        if (!error_) {
            error_ = error;
            static_cast<void>(session_->cancel(id_));
        }
        return error_;
    }
    Result<void> check(OperationOptions options) {
        if (error_) return fail(error_);
        if (options.stop.stop_requested()) return fail(stop(make_error_code(Errc::cancelled)));
        if (options.deadline && *options.deadline <= Clock::now())
            return fail(stop(make_error_code(Errc::timed_out)));
        return {};
    }
    Session* session_;
    std::int32_t id_;
    Driver* driver_;
    bool busy_ = false;
    Error error_;
};
} // namespace Mira::http2
