#pragma once

#include "mira/core/stream.hpp"
#include "mira/http2/session.hpp"

#include <cstdio>
#include <cstdlib>
#include <stop_token>

namespace Mira::http2 {

// Borrows an accepted Extended CONNECT. SessionDriver schedules reads and
// writes for the whole connection and allows one read and one write
// concurrently per stream; overlapping operations in the same direction are
// still rejected, and finish occupies the write direction. Legacy drivers
// without the multiplexed declaration keep the single-operation contract to
// avoid implicit pump reentry. Never mix with direct body operations;
// close/cancel RESETs only the current stream, and finish half-closes only the
// local output direction.
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
        if (reading_ || writing_) {
            std::fputs("Mira::http2::ConnectStream destroyed with pending operation\n", stderr);
            std::abort();
        }
    }
    Task<Result<std::size_t>> read_some(std::span<std::byte> bytes, OperationOptions options = {}) {
        if (reading_ || (!multiplexed && writing_)) co_return fail(Errc::invalid_argument);
        Guard guard{reading_};
        WaitOptions waiting{options, stopped_.get_token()};
        options = waiting.options;
        for (;;) {
            if (auto checked = check(options); !checked) co_return fail(checked.error());
            auto result = session_->read_connect(id_, bytes);
            if (result) {
                if constexpr (multiplexed) {
                    // Consumed input must not wait on congested output, or both
                    // directions at full window deadlock.
                    driver_->notify();
                } else {
                    if (auto flushed = co_await driver_->flush(options); !flushed)
                        co_return fail(stop(flushed.error()));
                }
                co_return result;
            }
            if (result.error() != Errc::would_block) co_return fail(result.error());
            if (auto progress = co_await driver_->progress(options); !progress)
                co_return fail(stop(progress.error()));
        }
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes, OperationOptions options = {}) {
        if (writing_ || (!multiplexed && reading_)) co_return fail(Errc::invalid_argument);
        Guard guard{writing_};
        WaitOptions waiting{options, stopped_.get_token()};
        options = waiting.options;
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
        if (writing_ || (!multiplexed && reading_)) co_return fail(Errc::invalid_argument);
        Guard guard{writing_};
        WaitOptions waiting{options, stopped_.get_token()};
        options = waiting.options;
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
    static constexpr bool multiplexed = [] {
        if constexpr (requires { Driver::multiplexed; }) return Driver::multiplexed;
        else return false;
    }();
    struct ForwardStop {
        std::stop_source source;
        void operator()() const noexcept { auto copy = source; copy.request_stop(); }
    };
    struct WaitOptions {
        std::stop_source stop;
        std::stop_callback<ForwardStop> caller;
        std::stop_callback<ForwardStop> stream;
        OperationOptions options;
        WaitOptions(OperationOptions io, std::stop_token closed)
            : caller(io.stop, ForwardStop{stop}), stream(closed, ForwardStop{stop}),
              options{.stop = stop.get_token(), .deadline = io.deadline} {}
    };
    struct Guard {
        bool& busy;
        explicit Guard(bool& value) : busy(value) { busy = true; }
        ~Guard() { busy = false; }
    };
    Error stop(Error error) {
        if (!error_) {
            error_ = error;
            static_cast<void>(session_->cancel(id_));
            if constexpr (multiplexed) driver_->notify();
            auto stopped = stopped_;
            const auto result = error_;
            stopped.request_stop();
            return result;
        }
        return error_;
    }
    Result<void> check(OperationOptions options) {
        if (error_) return fail(error_);
        if constexpr (multiplexed) {
            if (auto error = driver_->error()) return fail(stop(error));
        }
        if (options.stop.stop_requested()) return fail(stop(make_error_code(Errc::cancelled)));
        if (options.deadline && *options.deadline <= Clock::now())
            return fail(stop(make_error_code(Errc::timed_out)));
        return {};
    }
    Session* session_;
    std::int32_t id_;
    Driver* driver_;
    bool reading_ = false;
    bool writing_ = false;
    Error error_;
    std::stop_source stopped_;
};
} // namespace Mira::http2
