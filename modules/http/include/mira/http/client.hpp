#pragma once

#include "mira/core/stream.hpp"
#include "mira/http/response_parser.hpp"
#include "mira/http/serializer.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace Mira::http {

struct ClientOptions {
    Limits limits{};
    std::size_t read_chunk = 8 * 1024;
    /// Hard cap on the input buffer, independent of the cumulative body limit;
    /// fails explicitly when it cannot hold one line.
    std::size_t max_buffer_size = 64 * 1024;
    std::size_t max_informational_responses = 16;
    /// Overall deadline for one exchange (send, 1xx, final response and body),
    /// not refreshed per read.
    Clock::duration request_timeout = Clock::duration::zero();
};

/// Sequential HTTP/1 client that does not own the stream. The stream and this
/// object must stay alive until all tasks complete. Use only on a single event
/// loop; concurrent calls return invalid_argument. read_body must be drained
/// to an empty span before the next request can be sent. Never reused after
/// cancellation or error; the caller is responsible for closing. No DNS,
/// connection pooling, retries, redirects, decompression, proxies, CONNECT,
/// Upgrade, or Expect handshake. The request body is a borrowed, known-length
/// span; the response body is a span that is truly read on demand, collecting
/// nothing.
template<BoundedStream Stream>
class ClientConnection {
public:
    explicit ClientConnection(Stream& stream, ClientOptions options = {})
        : stream_(&stream), options_(options), parser_(Method::get, options.limits) {}
    ClientConnection(const ClientConnection&) = delete;
    ClientConnection& operator=(const ClientConnection&) = delete;
    ~ClientConnection() {
        // The class documents "the stream and this object must stay alive
        // until all tasks complete" as a borrow contract; dying mid-exchange
        // means the in-flight coroutine owns a parser and a stream pointer
        // that are about to evaporate. Terminate with a diagnosis, matching
        // the library-wide contract style (Task, tls::Stream) instead of
        // dangling silently.
        if (busy_ || active_) {
            std::fputs("Mira: http::ClientConnection destroyed mid-exchange\n", stderr);
            std::abort();
        }
    }

    /// request and body must stay alive until this task completes; on return
    /// the final response head is available, but the body has not been fully read.
    [[nodiscard]] Task<Result<void>>
    start(const Request& request, std::span<const std::byte> body = {}, OperationOptions io = {}) {
        if (busy_ || active_ || !reusable_) co_return fail(Errc::invalid_argument);
        if (options_.read_chunk == 0 || options_.max_buffer_size == 0 ||
            options_.request_timeout < Clock::duration::zero())
            co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        io_ = std::move(io);
        if (options_.request_timeout != Clock::duration::zero()) {
            const auto now = Clock::now();
            const auto deadline = options_.request_timeout > Clock::time_point::max() - now
                                      ? Clock::time_point::max()
                                      : now + options_.request_timeout;
            if (!io_.deadline || deadline < *io_.deadline) io_.deadline = deadline;
        }
        if (const auto error = budget_error()) co_return invalidate(error);
        Buffer head;
        const auto serialized = write_request_head(head, request, body.size(), options_.limits);
        if (!serialized) co_return fail(serialized.error());
        // No read-ahead and no over-allocation; the fixed reserve keeps
        // Buffer's geometric growth from exceeding the input budget.
        if (input_.capacity() == 0) input_ = Buffer{options_.max_buffer_size};
        active_ = true;
        reusable_ = should_keep_alive(request);
        parser_.reset(request.method);
        eof_ = false;
        const auto sent = co_await write_all(*stream_, head.readable(), io_);
        if (!sent) co_return invalidate(sent.error());
        const auto sent_body = co_await write_all(*stream_, body, io_);
        if (!sent_body) co_return invalidate(sent_body.error());
        std::size_t informational = 0;
        for (;;) {
            auto step = co_await next();
            if (!step) co_return invalidate(step.error());
            if (*step != ParseStep::head)
                co_return invalidate(make_error_code(Errc::invalid_argument));
            if (parser_.response().status >= 200) break;
            if (++informational > options_.max_informational_responses) {
                co_return invalidate(make_error_code(Errc::limit_exceeded));
            }
            auto complete = parser_.parse(input_, eof_);
            if (!complete) co_return invalidate(complete.error());
            parser_.reset(request.method);
        }
        const auto& response = parser_.response();
        if (response.body_kind == BodyKind::close_delimited ||
            mentions(response.headers, "close") ||
            (response.version == Version::http_1_0 && !mentions(response.headers, "keep-alive"))) {
            reusable_ = false;
        }
        co_return Result<void>{};
    }

    /// Returns one body fragment; an empty fragment means completion. The span
    /// is valid until the next start/read_body or the object's destruction.
    /// trailers() is complete only after the body has been fully read; when
    /// ignoring the body, either drain it in a loop or close the underlying stream.
    [[nodiscard]] Task<Result<std::span<const std::byte>>> read_body() {
        if (busy_ || !active_) co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        const auto step = co_await next();
        if (!step) co_return invalidate(step.error());
        if (*step == ParseStep::body) co_return parser_.body();
        if (*step != ParseStep::complete)
            co_return invalidate(make_error_code(Errc::invalid_argument));
        active_ = false;
        // Extra bytes arrive although no next request was sent: they must not
        // be mistaken for the next response.
        if (!input_.empty()) reusable_ = false;
        co_return std::span<const std::byte>{};
    }

    [[nodiscard]] const Response& response() const noexcept { return parser_.response(); }
    [[nodiscard]] const HeaderMap& trailers() const noexcept { return parser_.trailers(); }
    [[nodiscard]] bool reusable() const noexcept { return reusable_ && !active_ && !busy_; }

private:
    struct Guard {
        bool& busy;
        explicit Guard(bool& value) : busy(value) { busy = true; }
        ~Guard() { busy = false; }
    };
    static bool mentions(const HeaderMap& headers, std::string_view wanted) {
        for (const auto& [name, text] : headers) {
            if (!HeaderMap::names_equal(name, "Connection")) continue;
            std::string_view rest{text};
            for (;;) {
                const auto comma = rest.find(',');
                auto token = rest.substr(0, comma);
                while (!token.empty() && (token.front() == ' ' || token.front() == '\t'))
                    token.remove_prefix(1);
                while (!token.empty() && (token.back() == ' ' || token.back() == '\t'))
                    token.remove_suffix(1);
                if (HeaderMap::names_equal(token, wanted)) return true;
                if (comma == std::string_view::npos) break;
                rest.remove_prefix(comma + 1);
            }
        }
        return false;
    }
    Error budget_error() const {
        if (io_.stop.stop_requested()) return make_error_code(Errc::cancelled);
        if (io_.deadline && Clock::now() >= *io_.deadline) return make_error_code(Errc::timed_out);
        return {};
    }
    std::unexpected<Error> invalidate(Error error) {
        reusable_ = false;
        active_ = false;
        return fail(error);
    }
    Task<Result<ParseStep>> next() {
        for (;;) {
            if (const auto error = budget_error()) co_return fail(error);
            const auto step = parser_.parse(input_, eof_);
            if (!step || *step != ParseStep::need_more) co_return step;
            if (input_.size() >= options_.max_buffer_size) co_return fail(Errc::limit_exceeded);
            const auto count =
                std::min(options_.read_chunk, options_.max_buffer_size - input_.size());
            const auto read = co_await stream_->read_some(input_.prepare(count), io_);
            if (!read) {
                input_.commit(0);
                if (read.error() != Errc::eof) co_return fail(read.error());
                eof_ = true;
            } else {
                input_.commit(*read);
                if (*read == 0) eof_ = true;
            }
        }
    }
    Stream* stream_;
    ClientOptions options_;
    ResponseParser parser_;
    Buffer input_;
    OperationOptions io_{};
    bool busy_{false};
    bool active_{false};
    bool reusable_{true};
    bool eof_{false};
};

}  // namespace Mira::http
