// Measure same-thread scheduling on one loop: a yield() round trip and a
// post()-driven resumption (schedule_on). Neither waits for I/O, so the cost
// is the loop's own bookkeeping plus any wake-up syscalls it chooses to make.
// Usage: bench_loop_wake [rounds=1000000]
#include <mira/core/event_loop.hpp>
#include <mira/core/executor.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>

using namespace Mira;
namespace {
Task<void> yields(EventLoop& loop, std::uint64_t rounds, double& seconds) {
    const auto begin = Clock::now();
    for (std::uint64_t i = 0; i < rounds; ++i) co_await loop.yield();
    seconds = std::chrono::duration<double>(Clock::now() - begin).count();
}
Task<void> posts(EventLoop& loop, std::uint64_t rounds, double& seconds) {
    const auto begin = Clock::now();
    for (std::uint64_t i = 0; i < rounds; ++i) co_await schedule_on(loop);
    seconds = std::chrono::duration<double>(Clock::now() - begin).count();
}
}
int main(int argc, char** argv) {
    const std::uint64_t rounds = argc > 1 ? std::stoull(argv[1]) : 1000000;
    if (!rounds) return 2;
    auto loop = EventLoop::create();
    if (!loop) return 1;
    double yield_seconds = 0, post_seconds = 0;
    if (!loop->run_until_complete(yields(*loop, rounds, yield_seconds)) ||
        !loop->run_until_complete(posts(*loop, rounds, post_seconds)) || loop->outstanding() != 0) {
        std::fprintf(stderr, "bench: loop did not drain\n");
        return 1;
    }
    const auto per_op = [rounds](double seconds) { return seconds * 1e9 / static_cast<double>(rounds); };
    std::printf("loop_wake: %llu rounds on one thread (%s)\n"
                "  yield:       %.3fs, %.1f ns/op\n"
                "  post->resume: %.3fs, %.1f ns/op\n",
                static_cast<unsigned long long>(rounds), io_backend_name(), yield_seconds,
                per_op(yield_seconds), post_seconds, per_op(post_seconds));
}
