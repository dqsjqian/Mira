#pragma once

#include "mira/http3/session_driver.hpp"

#include <algorithm>
#include <map>
#include <vector>

namespace Mira::http3 {

struct Response {
    Headers headers;
    Headers trailers;
    std::vector<std::byte> body;
};

// Multi-stream whole-response composition. The single event consumer routes
// packet events to requests and returns flow-control windows immediately as
// bodies are consumed. Each request has independent cancellation, deadline and
// response budget; connection I/O and QUIC timers are owned only by the driver.
// Await application tasks before stop/join; never mix with explicit pump,
// take_events or other consumers. At most 64 requests in flight (also bounded
// by smaller engine quotas), fixed peer; no 0-RTT, retries or connection pooling.
template<transport::DatagramTransport Transport>
class ClientSession {
public:
    ClientSession(EventLoop& loop, Transport& transport, Engine& engine, transport::Endpoint peer,
                  std::size_t max_response_bytes = 4 * 1024 * 1024)
        : engine_(engine), driver_(loop, transport, engine, peer), max_response_(max_response_bytes) {}
    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;
    ~ClientSession() { if (active_) std::terminate(); }

    [[nodiscard]] Task<Result<Response>> request(Headers headers, std::vector<std::byte> body = {},
                                                  OperationOptions options = {}) {
        if (driver_.error()) co_return fail(driver_.error());
        if (options.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (options.deadline && *options.deadline <= Clock::now()) co_return fail(Errc::timed_out);
        if (active_ >= 64) co_return fail(Errc::limit_exceeded);
        struct OperationGuard {
            std::size_t& count;
            explicit OperationGuard(std::size_t& value) : count(value) { ++count; }
            ~OperationGuard() { --count; }
        } operation{active_};
        while (!engine_.ready()) {
            auto progress = co_await driver_.progress(options);
            if (!progress) co_return fail(progress.error());
        }
        Upload upload;
        TaskScope send;
        const auto opened = engine_.request_stream(headers);
        if (!opened) co_return fail(opened.error());
        const auto id = *opened;
        Pending pending;
        Active guard{*this, id, pending};
        std::exception_ptr exception;
        Result<Response> result = fail(Errc::internal);
        try {
            send.spawn(send_body(id, body, upload, options));
            result = co_await receive(pending, upload, options);
        } catch (...) { exception = std::current_exception(); }
        upload.stop.request_stop();
        if (!result || exception) {
            try {
                static_cast<void>(engine_.cancel(id));
                driver_.notify();
            } catch (...) {
                if (!exception) exception = std::current_exception();
                driver_.stop(make_error_code(Errc::internal));
            }
        }
        try { co_await send.join(); } catch (...) { if (!exception) exception = std::current_exception(); }
        if (exception) std::rethrow_exception(exception);
        co_return result;
    }

    void stop() noexcept { driver_.stop(); }
    [[nodiscard]] Task<void> join() { return driver_.join(); }
    [[nodiscard]] Error error() const noexcept { return driver_.error(); }
    [[nodiscard]] Task<Result<void>> progress(OperationOptions io = {}) { return driver_.progress(io); }

private:
    struct Pending {
        Response response;
        Error error;
        bool ended = false;
    };
    struct Upload {
        std::stop_source stop;
        Error error;
        bool done = false;
    };
    struct Forward {
        std::stop_source source;
        void operator()() const noexcept { auto copy = source; copy.request_stop(); }
    };
    struct Active {
        ClientSession& owner;
        std::int64_t id;
        Active(ClientSession& value, std::int64_t stream, Pending& pending) : owner(value), id(stream) {
            try { owner.requests_.emplace(id, &pending); }
            catch (...) {
                static_cast<void>(owner.engine_.cancel(id));
                owner.driver_.notify();
                throw;
            }
        }
        ~Active() { owner.requests_.erase(id); }
    };
    Task<void> send_body(std::int64_t id, const std::vector<std::byte>& body,
                         Upload& upload, OperationOptions options) {
        std::stop_callback forward(options.stop, Forward{upload.stop});
        options.stop = upload.stop.get_token();
        try {
            std::size_t offset = 0, chunk = 1024;
            while (offset < body.size()) {
                if (options.stop.stop_requested()) { upload.error = make_error_code(Errc::cancelled); break; }
                const auto count = std::min(chunk, body.size() - offset);
                auto result = engine_.write_body(id, std::span(body).subspan(offset, count));
                if (result) {
                    offset += count;
                    chunk = 1024;
                    result = co_await driver_.flush(options);
                } else if (result.error() == Errc::would_block) {
                    if (count > 1) { chunk = count / 2; continue; }
                    result = co_await driver_.progress(options);
                }
                if (!result) { upload.error = result.error(); break; }
            }
            if (!upload.error) {
                auto result = engine_.finish_body(id);
                if (result) result = co_await driver_.flush(options);
                if (!result) upload.error = result.error();
            }
        } catch (...) {
            upload.error = make_error_code(Errc::internal);
            upload.done = true;
            driver_.notify();
            throw;
        }
        upload.done = true;
        driver_.notify();
    }
    void collect() {
        bool consumed = false;
        for (auto& event : engine_.take_events()) {
            auto it = requests_.find(event.stream_id);
            if (event.kind == Event::Kind::body) {
                auto result = engine_.consume(event.stream_id, event.data.size());
                if (!result && it != requests_.end()) it->second->error = result.error();
                consumed = true;
            }
            if (it == requests_.end()) continue;
            auto& pending = *it->second;
            if (pending.error) continue;
            switch (event.kind) {
            case Event::Kind::headers:
                if (pending.response.headers.empty()) pending.response.headers = std::move(event.fields);
                else pending.response.trailers = std::move(event.fields);
                break;
            case Event::Kind::body:
                if (event.data.size() > max_response_ - pending.response.body.size()) {
                    pending.error = make_error_code(Errc::limit_exceeded);
                    static_cast<void>(engine_.cancel(event.stream_id));
                } else {
                    pending.response.body.insert(pending.response.body.end(), event.data.begin(), event.data.end());
                }
                break;
            case Event::Kind::end: pending.ended = true; break;
            case Event::Kind::reset: pending.error = make_error_code(Errc::cancelled); break;
            case Event::Kind::goaway: break;
            }
        }
        if (consumed) driver_.notify();
    }
    Task<Result<Response>> receive(Pending& pending, const Upload& upload, OperationOptions options) {
        for (;;) {
            if (driver_.error()) co_return fail(driver_.error());
            if (upload.error) co_return fail(upload.error);
            try { collect(); }
            catch (...) {
                // The event batch has left the engine; after an exception other
                // streams must not wait for lost events.
                driver_.stop(make_error_code(Errc::internal));
                throw;
            }
            if (pending.error) co_return fail(pending.error);
            if (pending.ended && upload.done) co_return std::move(pending.response);
            auto progress = co_await driver_.progress(options);
            if (!progress) co_return fail(progress.error());
        }
    }

    Engine& engine_;
    SessionDriver<Transport> driver_;
    std::size_t max_response_;
    std::size_t active_ = 0;
    std::map<std::int64_t, Pending*> requests_;
};

} // namespace Mira::http3
