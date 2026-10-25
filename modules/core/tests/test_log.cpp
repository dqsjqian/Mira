// Log sink: direct emission, level filtering, and operation events rendered
// as log records through the observer adapter.

#include "mira/core/observe.hpp"
#include "mira/core/event_loop.hpp"
#include "check.hpp"

#include <string>
#include <vector>

using namespace Mira;
namespace {

struct Captured {
    LogLevel level;
    std::string name;
    std::string message;
    Error error;
    Clock::duration elapsed{};
    std::size_t bytes = 0;
};

struct CapturingSink final : LogSink {
    std::vector<Captured> records;
    void write(const LogRecord& record) noexcept override {
        records.push_back(Captured{record.level, std::string{record.name}, std::string{record.message},
                                   record.error, record.elapsed, record.bytes});
    }
};

Task<Result<void>> failed() { co_return fail(Errc::timed_out); }
Task<Result<void>> throwing() { throw std::runtime_error("original exception"); co_return Result<void>{}; }
Task<Result<std::size_t>> completed() { co_return std::size_t{7}; }

Task<void> checks() {
    test::section("direct log() is null-safe and preserves level, name, message and error");
    log(nullptr, LogLevel::info, "nowhere", "dropped");
    auto sink = std::make_shared<CapturingSink>();
    log(sink.get(), LogLevel::warning, "dial", "retrying", make_error_code(Errc::timed_out));
    CHECK(sink->records.size() == 1);
    CHECK(sink->records[0].level == LogLevel::warning);
    CHECK(sink->records[0].name == "dial");
    CHECK(sink->records[0].message == "retrying");
    CHECK(sink->records[0].error == Errc::timed_out);

    test::section("level order and filtering");
    CHECK(log_at_least(LogLevel::info, LogLevel::info));
    CHECK(log_at_least(LogLevel::error, LogLevel::warning));
    CHECK(!log_at_least(LogLevel::debug, LogLevel::info));
    CHECK(!log_at_least(LogLevel::info, LogLevel::error));
    auto filtered = std::make_shared<FilteringSink>(sink, LogLevel::warning);
    const auto before = sink->records.size();
    log(filtered.get(), LogLevel::info, "quiet", "dropped by the floor");
    CHECK(sink->records.size() == before);
    log(filtered.get(), LogLevel::error, "loud", "passes the floor");
    CHECK(sink->records.size() == before + 1);
    CHECK(sink->records.back().name == "loud");

    test::section("operation events render as log records");
    auto observed = std::make_shared<CapturingSink>();
    auto observer = std::make_shared<LoggingObserver>(observed);
    static_cast<void>(co_await observe(completed(), observer, "payload", 0, true));
    CHECK(observed->records.size() == 2);
    CHECK(observed->records[0].level == LogLevel::debug);
    CHECK(observed->records[0].name == "payload");
    CHECK(observed->records[0].message == "started");
    CHECK(observed->records[1].level == LogLevel::info);
    CHECK(observed->records[1].message == "completed");
    CHECK(observed->records[1].bytes == 7);
    CHECK(!observed->records[1].error);
    static_cast<void>(co_await observe(failed(), observer, "timeout"));
    CHECK(observed->records.size() == 4);
    CHECK(observed->records[3].level == LogLevel::error);
    CHECK(observed->records[3].message == "failed");
    CHECK(observed->records[3].error == Errc::timed_out);
    bool caught = false;
    try {
        static_cast<void>(co_await observe(throwing(), observer, "exception"));
    } catch (const std::runtime_error&) {
        caught = true;
    }
    CHECK(caught);
    CHECK(observed->records.size() == 6);
    CHECK(observed->records[5].level == LogLevel::error);
    CHECK(observed->records[5].message == "failed with exception");
    CHECK(observed->records[5].error == Errc::internal);
}

Task<void> root() { co_await checks(); }

}  // namespace

int main() {
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (loop) {
        CHECK(loop->run_until_complete(root()).has_value());
        CHECK(loop->outstanding() == 0);
    }
    return test::summary();
}
