// Mira/bench/h1_cancel.cpp — cancellation and deadline semantics.
//
// What this measures: what it costs to stop. Every `read_some` and
// `write_some` accepts a stop token and a deadline; this bench exercises
// both paths at rate and reports the per-operation overhead of arming them:
//
//   - `deadline`: a slow peer stalls mid-request; every exchange ends in
//     `Errc::timed_out` instead of a response. The number is the cost of a
//     deadline firing end to end — arm, park the coroutine, wake, unwind.
//   - `stop`: the same stall, but a stop token is requested while the read
//     is parked. Cancellation must beat the deadline and surface as
//     `Errc::cancelled`.
//
// A regression here is not academic: deadlines are what keep a slow-loris
// peer from holding a descriptor forever, and cancellation is how a server
// shuts down without leaking every in-flight connection.
//
// In-process by design; the "slow peer" is a scripted stream, so the number
// isolates Mira's cancellation machinery from any real network's timing.
//
// Usage: bench_h1_cancel [rounds=100000]

#include <chrono>
#include <mira/core/stream.hpp>
#include <mira/core/task.hpp>
#include <mira/http/connection.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <utility>

using namespace Mira;
using LoopClock = std::chrono::steady_clock;

namespace {

/// A peer that accepts one request head and then stalls forever. Reads
/// return exactly what was scripted and then fail the way the armed budget
/// says — deadline or stop — without ever blocking the loop thread. The
/// point is to price the arming/unwinding machinery, not a real park.
class StallingPeer {
public:
    explicit StallingPeer(std::string head) : head_(std::move(head)) {}

    Task<Result<std::size_t>> read_some(std::span<std::byte> out, OperationOptions options = {}) {
        if (cursor_ < head_.size()) {
            const std::size_t n = std::min(head_.size() - cursor_, out.size());
            std::memcpy(out.data(), head_.data() + cursor_, n);
            cursor_ += n;
            co_return n;
        }
        ++parked_;
        if (options.stop.stop_requested()) {
            ++cancelled_;
            co_return std::unexpected(make_error_code(Errc::cancelled));
        }
        if (options.deadline.has_value()) {
            ++deadline_hits_;
            co_return std::unexpected(make_error_code(Errc::timed_out));
        }
        co_return std::unexpected(make_error_code(Errc::eof));
    }

    Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes,
                                         OperationOptions = {}) {
        written_ += bytes.size();
        co_return bytes.size();
    }

    [[nodiscard]] std::uint64_t parked() const noexcept { return parked_; }
    [[nodiscard]] std::uint64_t deadline_hits() const noexcept { return deadline_hits_; }
    [[nodiscard]] std::uint64_t cancelled() const noexcept { return cancelled_; }

private:
    std::string head_;
    std::size_t cursor_{0};
    std::uint64_t parked_{0};
    std::uint64_t cancelled_{0};
    std::uint64_t deadline_hits_{0};
    std::uint64_t written_{0};
};

}  // namespace

int main(int argc, char** argv) {
    const std::uint64_t rounds = argc > 1 ? std::stoull(argv[1]) : 100000;

    std::uint64_t deadline_ok = 0;
    std::uint64_t stop_ok = 0;
    std::uint64_t deadline_hits = 0;
    std::uint64_t stop_hits = 0;

    auto stall_handler = [](const http::Request&, auto&,
                            std::span<const std::byte>) -> Task<Result<void>> {
        co_return Result<void>{};
    };

    // ── deadline path ────────────────────────────────────────────────────────
    const auto deadline_started = LoopClock::now();
    for (std::uint64_t i = 0; i < rounds; ++i) {
        StallingPeer peer{"GET / HTTP/1.1\r\nHost: x\r\n"};
        http::ServerOptions options;
        options.request_timeout = std::chrono::microseconds{1};
        const Result<void> served =
            http::serve_connection(peer, stall_handler, options).sync_get();
        if (!served && served.error() == Errc::timed_out) {
            ++deadline_ok;
        }
        deadline_hits += peer.deadline_hits();
    }
    const auto deadline_elapsed = LoopClock::now() - deadline_started;

    // ── stop path ────────────────────────────────────────────────────────────
    const auto stop_started = LoopClock::now();
    for (std::uint64_t i = 0; i < rounds; ++i) {
        StallingPeer peer{"GET / HTTP/1.1\r\nHost: x\r\n"};
        http::ServerOptions options;
        std::stop_source source;
        options.stop = source.get_token();
        source.request_stop();
        const Result<void> served =
            http::serve_connection(peer, stall_handler, options).sync_get();
        if (!served && served.error() == Errc::cancelled) {
            ++stop_ok;
        }
        stop_hits += peer.cancelled();
    }
    const auto stop_elapsed = LoopClock::now() - stop_started;

    if (deadline_ok != rounds || stop_ok != rounds) {
        std::fprintf(stderr,
                     "bench: incomplete run (deadline %llu/%llu, stop %llu/%llu)\n",
                     static_cast<unsigned long long>(deadline_ok),
                     static_cast<unsigned long long>(rounds),
                     static_cast<unsigned long long>(stop_ok),
                     static_cast<unsigned long long>(rounds));
        return 1;
    }
    const double dl_seconds = std::chrono::duration<double>(deadline_elapsed).count();
    const double st_seconds = std::chrono::duration<double>(stop_elapsed).count();
    std::printf("h1_cancel: %llu rounds\n"
                "  deadline: %.3fs -> %.0f rounds/s (%llu deadline hits)\n"
                "  stop:     %.3fs -> %.0f rounds/s (%llu stop hits)\n",
                static_cast<unsigned long long>(rounds), dl_seconds,
                dl_seconds > 0 ? static_cast<double>(rounds) / dl_seconds : 0.0,
                static_cast<unsigned long long>(deadline_hits), st_seconds,
                st_seconds > 0 ? static_cast<double>(rounds) / st_seconds : 0.0,
                static_cast<unsigned long long>(stop_hits));
    return 0;
}
