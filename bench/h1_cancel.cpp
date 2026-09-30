// Measure real event-loop suspension and completion of stalled HTTP requests.
// The scripted peer supplies a partial head, then parks on a loop timer with
// the request's operation budget. Stop is posted only after the read starts.
// Usage: bench_h1_cancel [rounds=1000]
#include <mira/core/event_loop.hpp>
#include <mira/core/stream.hpp>
#include <mira/http/connection.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>

using namespace Mira;
namespace {
class StallingPeer {
public:
    StallingPeer(EventLoop& loop, std::stop_source* source) : loop_(loop), source_(source) {}
    Task<Result<std::size_t>> read_some(std::span<std::byte> out, OperationOptions options = {}) {
        constexpr std::string_view head = "GET / HTTP/1.1\r\nHost: x\r\n";
        if (cursor_ < head.size()) {
            const auto count = std::min(head.size() - cursor_, out.size());
            std::memcpy(out.data(), head.data() + cursor_, count);
            cursor_ += count;
            co_return count;
        }
        ++parked;
        if (source_) {
            auto source = *source_;
            loop_.post([source]() mutable { source.request_stop(); });
        }
        const auto waited = co_await loop_.sleep_for(std::chrono::hours{1}, options);
        if (!waited) co_return fail(waited.error());
        co_return fail(Errc::internal);
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes, OperationOptions = {}) {
        co_return bytes.size();
    }
    std::uint64_t parked = 0;
private:
    EventLoop& loop_;
    std::stop_source* source_;
    std::size_t cursor_ = 0;
};
struct Measurement { std::uint64_t completed = 0, parked = 0; double seconds = 0; };
Task<void> measure(EventLoop& loop, std::uint64_t rounds, bool stop, Measurement& result) {
    auto handler = [](const http::Request&, auto&, std::span<const std::byte>) -> Task<Result<void>> {
        co_return Result<void>{};
    };
    const auto begin = Clock::now();
    for (std::uint64_t i = 0; i < rounds; ++i) {
        std::stop_source source;
        StallingPeer peer{loop, stop ? &source : nullptr};
        http::ServerOptions options;
        // A nonzero delay gives the read a real suspended interval. This is a
        // latency measurement, not a tight-loop synthetic error-return rate.
        options.request_timeout = stop ? std::chrono::seconds{1} : std::chrono::milliseconds{1};
        if (stop) options.stop = source.get_token();
        const auto served = co_await http::serve_connection(peer, handler, options);
        if (!served && served.error() == (stop ? Errc::cancelled : Errc::timed_out)) ++result.completed;
        result.parked += peer.parked;
    }
    result.seconds = std::chrono::duration<double>(Clock::now() - begin).count();
}
}
int main(int argc, char** argv) {
    const std::uint64_t rounds = argc > 1 ? std::stoull(argv[1]) : 1000;
    if (!rounds) return 2;
    auto loop = EventLoop::create();
    if (!loop) return 1;
    Measurement deadline, stop;
    if (!loop->run_until_complete(measure(*loop, rounds, false, deadline)) ||
        !loop->run_until_complete(measure(*loop, rounds, true, stop)) ||
        deadline.completed != rounds || stop.completed != rounds ||
        deadline.parked != rounds || stop.parked != rounds || loop->outstanding() != 0) {
        std::fprintf(stderr, "bench: incomplete cancellation or suspension accounting\n");
        return 1;
    }
    std::printf("h1_cancel: %llu rounds (real loop timer suspension; deadline=1ms)\n"
                "  deadline: %.3fs, %.3f us/operation, parked=%llu\n"
                "  stop:     %.3fs, %.3f us/operation, parked=%llu\n",
                static_cast<unsigned long long>(rounds), deadline.seconds,
                deadline.seconds * 1e6 / static_cast<double>(rounds),
                static_cast<unsigned long long>(deadline.parked), stop.seconds,
                stop.seconds * 1e6 / static_cast<double>(rounds),
                static_cast<unsigned long long>(stop.parked));
}
