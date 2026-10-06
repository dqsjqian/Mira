#pragma once

// Mira/mqtt/client.hpp — an MQTT client over any bounded stream.
//
// `Client<Stream>` drives a `Session` over a caller-owned stream (TCP, TLS,
// Unix-domain...): it borrows the stream, which must outlive the client, and
// never closes it. Operations follow the streams' duplex contract: one reader
// (`receive` / `wait_for`) may run concurrently with writers (`publish`,
// `subscribe`, `unsubscribe`, `disconnect`, `keep_alive`) on the same loop.
// Writers never interleave bytes: while one writes, others append to the
// session's output and the active writer drains it before returning, so a
// writer may return once its packet is handed to that writer. A write failure
// is sticky and fails every later operation.
//
// Keep-alive needs a writer that wakes on time even while the reader waits:
// spawn `keep_alive(loop)` next to the reader. It never uses read deadlines,
// so it is safe over TLS, where a timed-out read poisons the session. When
// the server stops answering PINGREQ it returns `keep_alive_timeout`; cancel
// the reader and drop the stream.
//
// Clients must not move while an operation runs.

#include "mira/core/event_loop.hpp"
#include "mira/core/operation.hpp"
#include "mira/core/stream.hpp"
#include "mira/core/task.hpp"
#include "mira/mqtt/session.hpp"

#include <array>
#include <chrono>
#include <deque>
#include <exception>
#include <functional>
#include <iterator>
#include <limits>
#include <utility>
#include <vector>

namespace Mira::mqtt {

namespace detail {
inline std::uint64_t now_ns() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count());
}
}  // namespace detail

template<BoundedStream Stream>
class Client {
public:
    using AuthHandler = std::function<Task<Result<Auth>>(const Event&, OperationOptions)>;
    Client(Client&&) noexcept = default;
    Client& operator=(Client&&) noexcept = default;
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    /// Send CONNECT on `stream` and wait for CONNACK. A refusal fails with
    /// `MqttError::refused`; `last_connack()` then holds the reason.
    [[nodiscard]] static Task<Result<Client>> connect(Stream& stream, ClientOptions options,
                                                      OperationOptions io = {}, AuthHandler auth_handler = {}) {
        const auto event_limit = options.max_events;
        auto session = Session::create(std::move(options));
        if (!session) co_return fail(session.error());
        Client client{stream, std::move(*session)};
        client.max_events_ = event_limit;
        client.auth_handler_ = std::move(auth_handler);
        auto connected = co_await client.handshake(stream, io);
        if (!connected) co_return fail(connected.error());
        co_return std::move(client);
    }

    /// Restore a caller-persisted session, then perform CONNECT on a fresh
    /// transport. Persist scope and elapsed time according to Session::restore.
    [[nodiscard]] static Task<Result<Client>> restore(Stream& stream, ClientOptions options,
        Bytes checkpoint, std::string scope, OperationOptions io = {},
        std::uint32_t elapsed_seconds = 0, AuthHandler auth_handler = {}) {
        const auto event_limit = options.max_events;
        auto session = Session::restore(std::move(options), checkpoint, scope,
                                          16 * 1024 * 1024, elapsed_seconds);
        if (!session) co_return fail(session.error());
        auto notices = session->take_events();
        Client client{stream, std::move(*session)};
        client.max_events_ = event_limit;
        client.auth_handler_ = std::move(auth_handler);
        auto connected = co_await client.handshake(stream, io);
        if (!connected) co_return fail(connected.error());
        if (notices.size() > event_limit - client.events_.size()) co_return fail(Errc::limit_exceeded);
        for (auto it = notices.rbegin(); it != notices.rend(); ++it)
            client.events_.push_front(std::move(*it));
        co_return std::move(client);
    }

    /// Resume on a fresh stream after the previous one failed. With
    /// clean_start = false and a present session, unacknowledged publishes are
    /// resent; otherwise they are reported as discarded events.
    [[nodiscard]] Task<Result<void>> reconnect(Stream& stream, OperationOptions io = {}) {
        if (reading_ || writing_) co_return fail(Errc::invalid_argument);
        co_return co_await handshake(stream, io);
    }

    /// Returns the packet identifier (0 for QoS 0); completion arrives as a
    /// `published` event. `would_block` means the server's Receive Maximum or
    /// the output budget is full: receive acknowledgements, then retry.
    [[nodiscard]] Task<Result<std::uint16_t>> publish(std::string topic, Bytes payload,
                                                      QoS qos = QoS::at_most_once, bool retain = false,
                                                      Properties properties = {}, OperationOptions io = {}) {
        if (error_) co_return fail(error_);
        const FailureGuard failure_guard{*this};
        Publish message;
        message.topic = std::move(topic);
        message.payload = std::move(payload);
        message.qos = qos;
        message.retain = retain;
        message.properties = std::move(properties);
        auto id = session_.publish(std::move(message), retained_ids());
        if (!id) co_return fail(id.error());
        auto flushed = co_await flush(io);
        if (!flushed) co_return fail(flushed.error());
        co_return *id;
    }

    [[nodiscard]] Task<Result<std::uint16_t>> subscribe(std::vector<Subscription> subscriptions,
                                                        Properties properties = {}, OperationOptions io = {}) {
        if (error_) co_return fail(error_);
        const FailureGuard failure_guard{*this};
        auto id = session_.subscribe(std::move(subscriptions), std::move(properties), retained_ids());
        if (!id) co_return fail(id.error());
        auto flushed = co_await flush(io);
        if (!flushed) co_return fail(flushed.error());
        co_return *id;
    }

    [[nodiscard]] Task<Result<std::uint16_t>> unsubscribe(std::vector<std::string> filters,
                                                          Properties properties = {}, OperationOptions io = {}) {
        if (error_) co_return fail(error_);
        const FailureGuard failure_guard{*this};
        auto id = session_.unsubscribe(std::move(filters), std::move(properties), retained_ids());
        if (!id) co_return fail(id.error());
        auto flushed = co_await flush(io);
        if (!flushed) co_return fail(flushed.error());
        co_return *id;
    }

    /// Answer a server AUTH event (5.0 enhanced authentication).
    [[nodiscard]] Task<Result<void>> auth(std::uint8_t reason_code, Properties properties,
                                          OperationOptions io = {}) {
        if (error_) co_return fail(error_);
        const FailureGuard failure_guard{*this};
        auto sent = session_.auth(reason_code, std::move(properties));
        if (!sent) co_return fail(sent.error());
        co_return co_await flush(io);
    }

    /// Send DISCONNECT and flush it. The stream stays open for its owner.
    [[nodiscard]] Task<Result<void>> disconnect(std::uint8_t reason_code = reason::success,
                                                Properties properties = {}, OperationOptions io = {}) {
        if (error_) co_return fail(error_);
        const FailureGuard failure_guard{*this};
        auto closed = session_.disconnect(reason_code, std::move(properties));
        if (!closed) co_return fail(closed.error());
        co_return co_await flush(io);
    }

    /// The reader: every buffered event, reading until at least one exists.
    /// Fails with `eof` once the session is closed and nothing is buffered.
    [[nodiscard]] Task<Result<std::vector<Event>>> receive(OperationOptions io = {}) {
        if (reading_) co_return fail(Errc::invalid_argument);
        const FailureGuard failure_guard{*this};
        reading_ = true;
        const Guard guard{reading_};
        while (events_.empty()) {
            if (error_) co_return fail(error_);
            if (session_.state() == SessionState::closed) co_return fail(Errc::eof);
            auto read = co_await read_once(io);
            if (!read) co_return fail(read.error());
        }
        std::vector<Event> batch(std::make_move_iterator(events_.begin()), std::make_move_iterator(events_.end()));
        events_.clear();
        co_return batch;
    }

    /// The reader: the completion (published / subscribed / unsubscribed) of
    /// `packet_id`. Other events stay buffered for `receive`.
    [[nodiscard]] Task<Result<Event>> wait_for(std::uint16_t packet_id, OperationOptions io = {}) {
        if (reading_ || !packet_id) co_return fail(Errc::invalid_argument);
        const FailureGuard failure_guard{*this};
        reading_ = true;
        const Guard guard{reading_};
        std::size_t examined = 0;
        for (;;) {
            for (; examined < events_.size(); ++examined) {
                auto& candidate = events_[examined];
                if (candidate.packet_id != packet_id || candidate.kind == Event::Kind::message) continue;
                Event event = std::move(candidate);
                events_.erase(events_.begin() + static_cast<std::ptrdiff_t>(examined));
                co_return event;
            }
            if (error_) co_return fail(error_);
            if (session_.state() == SessionState::closed) co_return fail(Errc::eof);
            auto read = co_await read_once(io);
            if (!read) co_return fail(read.error());
        }
    }

    /// A writer that sends PINGREQ when the connection is idle and fails when
    /// PINGRESP is overdue. Runs until the session closes, `io` stops it, or a
    /// failure; with keep-alive 0 it returns at once.
    [[nodiscard]] Task<Result<void>> keep_alive(EventLoop& loop, OperationOptions io = {}) {
        const FailureGuard failure_guard{*this};
        for (;;) {
            if (error_) co_return fail(error_);
            const auto due = session_.next_timer();
            if (session_.state() != SessionState::connected || due == std::numeric_limits<std::uint64_t>::max())
                co_return Result<void>{};
            const auto wake = Clock::time_point{std::chrono::duration_cast<Clock::duration>(
                std::chrono::nanoseconds(static_cast<std::int64_t>(due)))};
            auto slept = co_await loop.sleep_until(wake, io);
            if (!slept) co_return fail(slept.error());
            if (auto timer = session_.handle_timer(detail::now_ns()); !timer) {
                error_ = timer.error();
                co_return fail(timer.error());
            }
            auto flushed = co_await flush(io);
            if (!flushed) co_return fail(flushed.error());
        }
    }

    /// Advanced session access: do not mutate it while client I/O is pending.
    /// A client-owned session rejects direct checkpoint calls; use the client's
    /// queue-aware checkpoint() even when accessing through this reference.
    [[nodiscard]] Session& session() noexcept { return session_; }
    [[nodiscard]] const Session& session() const noexcept { return session_; }
    /// A snapshot cannot discard events buffered by wait_for or a partially
    /// completed read/write. Drain receive() and join operations first.
    [[nodiscard]] Result<Bytes> checkpoint(std::string_view scope,
                                          std::size_t max_bytes = 16 * 1024 * 1024) const {
        if (reading_ || writing_ || !events_.empty()) return fail(Errc::would_block);
        return session_.checkpoint_impl(scope, max_bytes);
    }
    [[nodiscard]] bool closed() const noexcept { return error_ || session_.state() == SessionState::closed; }
    /// The CONNACK of the latest (re)connect attempt.
    [[nodiscard]] const Event& last_connack() const noexcept { return connack_; }

private:
    // Once a stream or allocation throws, some wire bytes or protocol state
    // may already have been consumed. Preserve the exception for its caller,
    // but reject further I/O until a fresh transport completes reconnect.
    struct FailureGuard {
        Client& client;
        int exceptions = std::uncaught_exceptions();
        ~FailureGuard() {
            if (std::uncaught_exceptions() > exceptions && !client.error_)
                client.error_ = make_error_code(Errc::internal);
        }
    };

    struct Guard {
        bool& flag;
        ~Guard() { flag = false; }
    };

    Client(Stream& stream, Session session) : stream_(&stream), session_(std::move(session)) {
        session_.client_owned_ = true;
    }

    Task<Result<void>> handshake(Stream& stream, OperationOptions io) {
        const FailureGuard failure_guard{*this};
        if (auto started = session_.connect(detail::now_ns(), events_.size()); !started) co_return fail(started.error());
        // Capacity rejection above leaves the previous transport/error intact.
        stream_ = &stream;
        error_ = {};
        auto flushed = co_await flush(io);
        if (!flushed) co_return fail(flushed.error());
        reading_ = true;
        const Guard guard{reading_};
        for (;;) {
            bool answered_auth = false;
            for (auto it = events_.begin(); it != events_.end(); ++it) {
                if (it->kind == Event::Kind::auth) {
                    if (!auth_handler_) co_return fail(Errc::not_supported);
                    Event challenge = std::move(*it);
                    events_.erase(it);
                    auto answer = co_await auth_handler_(challenge, io);
                    if (!answer) co_return fail(answer.error());
                    auto sent = co_await auth(answer->reason, std::move(answer->properties), io);
                    if (!sent) co_return sent;
                    answered_auth = true;
                    break;
                }
                if (it->kind != Event::Kind::connected) continue;
                connack_ = std::move(*it);
                events_.erase(it);
                co_return Result<void>{};
            }
            if (answered_auth) continue;
            if (session_.state() == SessionState::closed) co_return fail(error_ ? error_ : make_error_code(Errc::eof));
            auto read = co_await read_once(io);
            if (!read) {
                // A refusal is reported by the session after its CONNACK event was buffered.
                for (auto it = events_.begin(); it != events_.end(); ++it)
                    if (it->kind == Event::Kind::connected) {
                        connack_ = std::move(*it);
                        events_.erase(it);
                        break;
                    }
                co_return fail(read.error());
            }
        }
    }

    // Serialize writers: the active one drains everything appended meanwhile.
    Task<Result<void>> flush(OperationOptions io) {
        if (error_) co_return fail(error_);
        if (writing_) co_return Result<void>{};
        const FailureGuard failure_guard{*this};
        writing_ = true;
        const Guard guard{writing_};
        while (session_.has_output()) {
            if (error_) co_return fail(error_);
            const auto bytes = session_.take_output(detail::now_ns());
            std::span<const std::byte> remaining{bytes};
            while (!remaining.empty()) {
                auto written = co_await stream_->write_some(remaining, io);
                // The reader may have failed while this short write awaited.
                // Its terminal error wins, and no later fragment is submitted.
                if (error_) co_return fail(error_);
                if (!written) error_ = written.error();
                else if (*written == 0) error_ = make_error_code(Errc::eof);
                else if (*written > remaining.size()) error_ = make_error_code(Errc::invalid_argument);
                if (error_) co_return fail(error_);
                remaining = remaining.subspan(*written);
            }
        }
        co_return Result<void>{};
    }

    Task<Result<void>> read_once(OperationOptions io) {
        if (error_) co_return fail(error_);
        const FailureGuard failure_guard{*this};
        std::array<std::byte, 16384> buffer{};
        auto count = co_await stream_->read_some(std::span<std::byte>{buffer}, io);
        if (error_) co_return fail(error_);
        if (!count) {
            // Cancellation and deadlines belong to this call; anything else ends the connection.
            if (count.error() != Errc::cancelled && count.error() != Errc::timed_out) error_ = count.error();
            co_return fail(count.error());
        }
        if (*count == 0) {
            error_ = make_error_code(Errc::eof);
            co_return fail(error_);
        }
        if (*count > buffer.size()) {
            error_ = make_error_code(Errc::invalid_argument);
            co_return fail(error_);
        }
        auto fed = session_.receive(std::span<const std::byte>{buffer.data(), *count}, detail::now_ns(), events_.size());
        auto incoming = session_.take_events();
        if (events_.size() > max_events_ || incoming.size() > max_events_ - events_.size()) {
            error_ = make_error_code(Errc::limit_exceeded);
            co_return fail(error_);
        }
        for (auto& event : incoming) events_.push_back(std::move(event));
        // Acknowledgements, and a DISCONNECT explaining a violation, go out before failing.
        auto flushed = co_await flush(io);
        if (!fed) {
            if (fed.error() != make_error_code(MqttError::refused)) error_ = fed.error();
            co_return fail(fed.error());
        }
        if (!flushed) co_return fail(flushed.error());
        co_return Result<void>{};
    }

    std::vector<std::uint16_t> retained_ids() const {
        std::vector<std::uint16_t> ids;
        ids.reserve(events_.size());
        for (const auto& event : events_)
            if (event.packet_id && event.kind != Event::Kind::message) ids.push_back(event.packet_id);
        return ids;
    }
    Stream* stream_;
    Session session_;
    std::deque<Event> events_;
    std::size_t max_events_ = 4096;
    AuthHandler auth_handler_;
    Event connack_{Event::Kind::connected};
    Error error_;
    bool reading_ = false;
    bool writing_ = false;
};

}  // namespace Mira::mqtt
