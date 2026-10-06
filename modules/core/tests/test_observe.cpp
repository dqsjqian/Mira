#include "mira/core/observe.hpp"
#include "mira/core/event_loop.hpp"
#include "check.hpp"
#include <numeric>
#include <thread>

using namespace Mira;
namespace {
Task<Result<std::size_t>> completed() { co_return std::size_t{7}; }
Task<Result<std::unique_ptr<int>>> owned_result() { co_return std::make_unique<int>(42); }
Task<Result<void>> failed() { co_return fail(Errc::timed_out); }
Task<Result<void>> throwing() { throw std::runtime_error("original exception"); co_return Result<void>{}; }
struct Stream {
    bool closed = false;
    Task<Result<std::size_t>> read_some(std::span<std::byte> bytes, OperationOptions io = {}) {
        if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (bytes.empty()) co_return std::size_t{0};
        bytes[0] = std::byte{42};
        co_return std::size_t{1};
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes, OperationOptions = {}) {
        co_return bytes.size();
    }
    void close() { closed = true; }
};
static_assert(BoundedStream<ObservedStream<Stream>>);
Task<void> checks(EventLoop& loop) {
    auto metrics = std::make_shared<OperationMetrics>();
    { auto never = observe(completed(), metrics, "never"); }
    CHECK(metrics->snapshot().started == 0);
    auto size = co_await observe(completed(), metrics, "payload", 42, true);
    CHECK(size && *size == 7);
    auto error = co_await observe(failed(), metrics, "timeout");
    CHECK(!error && error.error() == Errc::timed_out);
    bool caught = false;
    try { static_cast<void>(co_await observe(throwing(), metrics, "exception")); }
    catch (const std::runtime_error& e) { caught = std::string_view{e.what()} == "original exception"; }
    CHECK(caught);
    std::stop_source stop;
    stop.request_stop();
    auto cancelled = co_await observe(loop.sleep_for(std::chrono::seconds(1), {.stop = stop.get_token()}), metrics, "cancel");
    CHECK(!cancelled && cancelled.error() == Errc::cancelled);
    auto snapshot = metrics->snapshot();
    CHECK(snapshot.started == 4 && snapshot.completed == 4 && snapshot.failed == 3);
    CHECK(snapshot.bytes == 7 && snapshot.cancelled == 1 && snapshot.timed_out == 1 && snapshot.exceptions == 1);
    CHECK(std::accumulate(snapshot.latency.begin(), snapshot.latency.end(), std::uint64_t{0}) == 4);
    auto notify = [metrics] {
        OperationEvent e;
        e.phase = OperationPhase::completed;
        for (int i = 0; i < 1000; ++i) metrics->notify(e);
    };
    { std::jthread a(notify), b(notify); }
    CHECK(metrics->snapshot().completed == 2004);
    Stream stream;
    ObservedStream observed{stream, metrics, "fixture", 42};
    std::array<std::byte, 4> buffer{};
    const auto read = co_await observed.read_some(buffer);
    CHECK(read && *read == 1 && buffer[0] == std::byte{42});
    const auto written = co_await observed.write_some(buffer);
    CHECK(written && *written == buffer.size());
    observed.close();
    CHECK(stream.closed && metrics->snapshot().bytes == 12);
    auto owned = co_await observe(owned_result(), metrics, "owned");
    CHECK(owned && **owned == 42);
}
}
int main() {
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (loop) CHECK(loop->run_until_complete(checks(*loop)).has_value());
    return test::summary();
}
