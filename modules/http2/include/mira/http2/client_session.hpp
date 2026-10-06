#pragma once

#include "mira/http2/session_driver.hpp"

#include <algorithm>
#include <map>
#include <vector>

namespace Mira::http2 {

struct Response {
    Headers headers;
    Headers trailers;
    std::vector<std::byte> body;
};

// Bounded whole-response client composition. Concurrent requests each own one
// HTTP stream and share one safe driver. Cancelling a request only RESETs its
// own stream; the response-body cap is independent of the Session receive
// budget. The engine and transport must outlive join; await application tasks
// before stop/join. Never mix with other engine consumers. At most 64 requests
// in flight (also bounded by smaller engine quotas); no queueing, no retries,
// no cross-connection routing.
template<BoundedStream Transport>
class ClientSession {
public:
    ClientSession(EventLoop& loop, Transport& transport, Session& session,
                  std::size_t max_response_bytes = 4 * 1024 * 1024)
        : session_(session), driver_(loop, transport, session), max_response_(max_response_bytes) {}
    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;
    ~ClientSession() { if (active_) std::terminate(); }

    [[nodiscard]] Task<Result<Response>> request(Headers headers, std::vector<std::byte> body = {},
                                                  OperationOptions options = {}) {
        if (driver_.error()) co_return fail(driver_.error());
        if (options.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (options.deadline && *options.deadline <= Clock::now()) co_return fail(Errc::timed_out);
        if (active_ >= 64) co_return fail(Errc::limit_exceeded);
        reap();
        Upload upload;
        TaskScope send;
        const auto opened = session_.request_stream(headers);
        if (!opened) co_return fail(opened.error());
        const auto id = *opened;
        Active guard{*this, id};
        std::exception_ptr exception;
        Result<Response> result = fail(Errc::internal);
        try {
            send.spawn(send_body(id, body, upload, options));
            result = co_await receive(id, upload, options);
        } catch (...) { exception = std::current_exception(); }
        upload.stop.request_stop();
        if (!result || exception) {
            try {
                static_cast<void>(session_.cancel(id));
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

private:
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
        std::int32_t id;
        Active(ClientSession& value, std::int32_t stream) : owner(value), id(stream) {
            try { owner.owned_.emplace(id, true); }
            catch (...) {
                static_cast<void>(owner.session_.cancel(id));
                owner.driver_.notify();
                throw;
            }
            ++owner.active_;
        }
        ~Active() {
            --owner.active_;
            owner.owned_.find(id)->second = false;
        }
    };
    void reap() {
        for (auto it = owned_.begin(); it != owned_.end();) {
            const auto* stream = session_.stream(it->first);
            if (!it->second && stream && stream->closed && session_.release(it->first))
                it = owned_.erase(it);
            else ++it;
        }
    }
    Task<void> send_body(std::int32_t id, const std::vector<std::byte>& body,
                         Upload& upload, OperationOptions options) {
        std::stop_callback forward(options.stop, Forward{upload.stop});
        options.stop = upload.stop.get_token();
        try {
            std::size_t offset = 0, chunk = 1024;
            while (offset < body.size()) {
                if (options.stop.stop_requested()) { upload.error = make_error_code(Errc::cancelled); break; }
                const auto count = std::min(chunk, body.size() - offset);
                auto result = session_.write_body(id, std::span(body).subspan(offset, count));
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
                auto result = session_.finish_body(id);
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
    Task<Result<Response>> receive(std::int32_t id, const Upload& upload, OperationOptions options) {
        Response response;
        for (;;) {
            if (driver_.error()) co_return fail(driver_.error());
            if (upload.error) co_return fail(upload.error);
            const auto* stream = session_.stream(id);
            if (!stream) co_return fail(Errc::internal);
            if (stream->error) co_return fail(stream->error);
            auto body = session_.take_body(id);
            if (!body) co_return fail(body.error());
            if (body->size() > max_response_ - response.body.size()) co_return fail(Errc::limit_exceeded);
            response.body.insert(response.body.end(), body->begin(), body->end());
            if (!body->empty()) driver_.notify();
            if (stream->remote_end && upload.done) {
                response.headers = stream->headers;
                response.trailers = stream->trailers;
                co_return response;
            }
            auto progress = co_await driver_.progress(options);
            if (!progress) co_return fail(progress.error());
        }
    }

    Session& session_;
    SessionDriver<Transport> driver_;
    std::size_t max_response_;
    std::size_t active_ = 0;
    std::map<std::int32_t, bool> owned_;
};

} // namespace Mira::http2
