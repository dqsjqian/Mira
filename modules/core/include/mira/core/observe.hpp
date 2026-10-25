#pragma once

#include "mira/core/stream.hpp"

#include <array>
#include <atomic>
#include <exception>
#include <memory>
#include <string>

namespace Mira {

enum class OperationPhase { started, completed };
struct OperationEvent {
    std::uint64_t id = 0, parent_id = 0;
    std::string_view name;
    OperationPhase phase = OperationPhase::started;
    Clock::time_point started{};
    Clock::duration elapsed{};
    Error error;
    std::size_t bytes = 0;
    bool exception = false;
};
/// Synchronous, noexcept notifications on the thread executing the operation.
/// Implementations shared across loops must be thread-safe and non-blocking.
/// Names/views are borrowed for the call. No payload, hostname or credentials
/// are collected. Do not destroy or reenter the observed operation's owner.
class OperationObserver {
public:
    virtual ~OperationObserver() = default;
    virtual void notify(const OperationEvent& event) noexcept = 0;
};
namespace observation_detail {
inline std::atomic<std::uint64_t> next_id{1};
}
/// Observe any protocol/dial/timer Task<Result<T>>, without translating errors
/// or changing its cancellation policy. A never-started task emits no events.
/// Count a size_t result as transferred bytes only when explicitly requested.
template<class T>
Task<Result<T>> observe(Task<Result<T>> operation, std::shared_ptr<OperationObserver> observer,
                        std::string name, std::uint64_t parent_id = 0, bool count_bytes = false) {
    if (!observer) co_return co_await std::move(operation);
    OperationEvent event;
    event.id = observation_detail::next_id.fetch_add(1, std::memory_order_relaxed);
    event.parent_id = parent_id;
    event.name = name;
    event.started = Clock::now();
    observer->notify(event);
    struct Complete {
        OperationObserver& observer;
        OperationEvent& event;
        int exceptions = std::uncaught_exceptions();
        ~Complete() {
            event.phase = OperationPhase::completed;
            event.elapsed = Clock::now() - event.started;
            if (std::uncaught_exceptions() > exceptions) {
                event.exception = true;
                event.error = make_error_code(Errc::internal);
            }
            observer.notify(event);
        }
    } complete{*observer, event};
    auto result = co_await std::move(operation);
    if (!result) event.error = result.error();
    if constexpr (std::same_as<T, std::size_t>) {
        if (result && count_bytes) event.bytes = *result;
    } else static_cast<void>(count_bytes);
    co_return result;
}

/// Fixed-size cross-loop counters. Independent relaxed loads form a diagnostic
/// snapshot, not an atomic transaction. Histogram counts are non-cumulative;
/// boundaries are <10us, <100us, <1ms, <10ms, <100ms, <1s, <10s, >=10s.
class OperationMetrics final : public OperationObserver {
public:
    struct Snapshot {
        std::uint64_t started = 0, completed = 0, failed = 0;
        std::uint64_t cancelled = 0, timed_out = 0, exceptions = 0, bytes = 0;
        std::array<std::uint64_t, 8> latency{};
    };
    void notify(const OperationEvent& event) noexcept override {
        if (event.phase == OperationPhase::started) { started_.fetch_add(1, std::memory_order_relaxed); return; }
        completed_.fetch_add(1, std::memory_order_relaxed);
        if (event.error) failed_.fetch_add(1, std::memory_order_relaxed);
        if (event.error == Errc::cancelled) cancelled_.fetch_add(1, std::memory_order_relaxed);
        if (event.error == Errc::timed_out) timed_out_.fetch_add(1, std::memory_order_relaxed);
        if (event.exception) exceptions_.fetch_add(1, std::memory_order_relaxed);
        bytes_.fetch_add(event.bytes, std::memory_order_relaxed);
        auto threshold = std::chrono::nanoseconds{10000};
        std::size_t bucket = 0;
        while (bucket < 7 && event.elapsed >= threshold) { ++bucket; threshold *= 10; }
        latency_[bucket].fetch_add(1, std::memory_order_relaxed);
    }
    [[nodiscard]] Snapshot snapshot() const noexcept {
        Snapshot result{started_.load(std::memory_order_relaxed), completed_.load(std::memory_order_relaxed),
                        failed_.load(std::memory_order_relaxed), cancelled_.load(std::memory_order_relaxed),
                        timed_out_.load(std::memory_order_relaxed), exceptions_.load(std::memory_order_relaxed),
                        bytes_.load(std::memory_order_relaxed)};
        for (std::size_t i = 0; i < latency_.size(); ++i) result.latency[i] = latency_[i].load(std::memory_order_relaxed);
        return result;
    }
private:
    std::atomic<std::uint64_t> started_{0}, completed_{0}, failed_{0}, cancelled_{0}, timed_out_{0}, exceptions_{0}, bytes_{0};
    std::array<std::atomic<std::uint64_t>, 8> latency_{};
};

/// Severity order: debug < info < warning < error. Sinks that filter use
/// log_at_least rather than re-declaring the order.
enum class LogLevel { debug, info, warning, error };

[[nodiscard]] constexpr bool log_at_least(LogLevel level, LogLevel floor) noexcept {
    return static_cast<int>(level) >= static_cast<int>(floor);
}

/// One log record. This is the metrics' event rendered as text's worth of
/// structure: a level, a timestamp, a component/operation name, a short
/// message, and an error code when the record is about a failure. Elapsed
/// time and byte counts are populated for operation events (see
/// LoggingObserver) and zero for direct log() calls. Names and messages are
/// borrowed for the call, exactly like OperationEvent's: the sink must copy
/// anything it keeps. No payload, hostname or credentials are ever carried
/// here — the same boundary the observer contract draws.
struct LogRecord {
    LogLevel level = LogLevel::info;
    Clock::time_point at{};
    std::string_view name;
    std::string_view message;
    Error error;
    Clock::duration elapsed{};
    std::size_t bytes = 0;
};

/// Synchronous, noexcept log receiver, in the OperationObserver mould: the
/// caller renders, the sink only receives. Implementations shared across
/// loops must be thread-safe and non-blocking. No formatting, no file I/O,
/// no network here — a sink that needs those owns a queue and a worker.
/// Do not destroy or reenter the logging operation's owner.
class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void write(const LogRecord& record) noexcept = 0;
};

/// Emit one record. Null-safe: a null sink means logging is off, not an
/// error. Takes a raw pointer because nothing is retained past the call;
/// callers holding a shared_ptr pass .get().
inline void log(LogSink* sink, LogLevel level, std::string_view name, std::string_view message,
                Error error = {}) noexcept {
    if (!sink) return;
    sink->write(LogRecord{level, Clock::now(), name, message, error, {}, 0});
}

/// An OperationObserver that renders operation events as log records, so an
/// existing sink receives operation lifecycles without a second observer
/// registration. Started events log at debug; completed events at info (or
/// the configured level); failed or throwing operations at error, with the
/// error code preserved. Duration and byte counts ride along in the record.
class LoggingObserver final : public OperationObserver {
public:
    explicit LoggingObserver(std::shared_ptr<LogSink> sink, LogLevel completed_level = LogLevel::info)
        : sink_(std::move(sink)), completed_level_(completed_level) {}
    void notify(const OperationEvent& event) noexcept override {
        if (!sink_) return;
        if (event.phase == OperationPhase::started) {
            sink_->write(LogRecord{LogLevel::debug, event.started, event.name, "started", {}, {}, 0});
            return;
        }
        LogRecord record;
        record.at = event.started + event.elapsed;
        record.name = event.name;
        record.error = event.error;
        record.elapsed = event.elapsed;
        record.bytes = event.bytes;
        if (event.exception || event.error) {
            record.level = LogLevel::error;
            record.message = event.exception ? "failed with exception" : "failed";
        } else {
            record.level = completed_level_;
            record.message = "completed";
        }
        sink_->write(record);
    }
private:
    std::shared_ptr<LogSink> sink_;
    LogLevel completed_level_;
};

/// A sink that forwards only records at or above a floor, so a verbose
/// component can stay wired to a quiet sink. The floor is fixed at
/// construction; a sink whose floor moves needs its own implementation.
class FilteringSink final : public LogSink {
public:
    FilteringSink(std::shared_ptr<LogSink> next, LogLevel floor)
        : next_(std::move(next)), floor_(floor) {}
    void write(const LogRecord& record) noexcept override {
        if (next_ && log_at_least(record.level, floor_)) next_->write(record);
    }
private:
    std::shared_ptr<LogSink> next_;
    LogLevel floor_;
};

/// Decorate any bounded stream at a chosen layer (wire bytes below TLS, plain
/// bytes above it). Ownership, duplex and cancellation remain the stream's.
/// Move neither wrapper nor transport while operations are pending.
template<BoundedStream Stream>
class ObservedStream {
public:
    ObservedStream(Stream& stream, std::shared_ptr<OperationObserver> observer,
                   std::string name = "stream", std::uint64_t parent_id = 0)
        : stream_(stream), observer_(std::move(observer)), name_(std::move(name)), parent_(parent_id) {}
    Task<Result<std::size_t>> read_some(std::span<std::byte> buffer, OperationOptions io = {}) {
        return observe(stream_.read_some(buffer, io), observer_, name_ + ".read", parent_, true);
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> buffer, OperationOptions io = {}) {
        return observe(stream_.write_some(buffer, io), observer_, name_ + ".write", parent_, true);
    }
    Task<Result<std::size_t>> writev_some(std::span<const std::span<const std::byte>> buffers,
                                         OperationOptions io = {}) requires BoundedVectorWriteStream<Stream> {
        return observe(stream_.writev_some(buffers, io), observer_, name_ + ".writev", parent_, true);
    }
    void close() requires ClosableStream<Stream> { stream_.close(); }
private:
    Stream& stream_;
    std::shared_ptr<OperationObserver> observer_;
    std::string name_;
    std::uint64_t parent_;
};

} // namespace Mira
