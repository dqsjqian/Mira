#pragma once

#include "mira/core/stream.hpp"
#include "mira/core/resource_budget.hpp"
#include <optional>
#include "mira/http/response_parser.hpp"
#include "mira/http/serializer.hpp"

#include <algorithm>
#include <array>
#include <charconv>
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
    /// Charge the fixed response input capacity for this connection's lifetime.
    /// Does not cover parser metadata, caller buffers or allocator overhead.
    std::optional<ResourceBudget> input_budget{};
};

/// Borrowed single-loop HTTP/1 client. Keep stream, object and arguments alive
/// until tasks finish. begin/send_body/finish apply per-chunk backpressure without
/// collecting the request body. Drain responses before reuse; errors forbid reuse.
/// Upload is send-first: no early response reads or Expect handshake. A peer that
/// refuses upload may require the total deadline to stop writes. Never retries.
/// DNS, pooling, redirects, decompression, proxies and upgrades are separate layers.
template<BoundedStream Stream>
class ClientConnection {
public:
    explicit ClientConnection(Stream& stream, ClientOptions options = {})
        : stream_(&stream), options_(options), parser_(Method::get, options.limits) {}
    ClientConnection(const ClientConnection&) = delete;
    ClientConnection& operator=(const ClientConnection&) = delete;
    ~ClientConnection() {
        if (busy_ || active_) {
            std::fputs("Mira: http::ClientConnection destroyed mid-exchange\n", stderr);
            std::abort();
        }
    }

    /// Send only the request head; request lifetime extends through this task.
    /// content_length must match all chunks; chunked requires HTTP/1.1 and size=0.
    /// The earlier io/request_timeout deadline covers upload, producer pauses and response.
    [[nodiscard]] Task<Result<void>> begin(const Request& request, Framing framing,
                                           std::uint64_t size = 0, OperationOptions io = {}) {
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
        const auto serialized = write_request_head(head, request, framing, size, options_.limits);
        if (!serialized) co_return fail(serialized.error());
        if (input_.capacity() == 0) {
            ResourceBudget::Reservation charge;
            if (options_.input_budget) {
                auto acquired = options_.input_budget->try_acquire(options_.max_buffer_size);
                if (!acquired) co_return fail(acquired.error());
                charge = std::move(*acquired);
            }
            input_ = Buffer{options_.max_buffer_size};
            input_charge_ = std::move(charge);
        }
        active_ = true;
        uploading_ = true;
        reusable_ = should_keep_alive(request);
        method_ = request.method;
        framing_ = framing;
        remaining_ = size;
        sent_ = 0;
        parser_.reset(method_);
        eof_ = false;
        const auto result = co_await write_bytes(head.readable());
        if (!result) co_return invalidate(result.error());
        co_return Result<void>{};
    }

    /// Borrow and finish one chunk before returning, applying producer backpressure.
    /// Empty chunks do not finish upload; size violations permanently invalidate reuse.
    [[nodiscard]] Task<Result<void>> send_body(std::span<const std::byte> body) {
        if (busy_ || !active_ || !uploading_) co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        if (const auto error = budget_error()) co_return invalidate(error);
        if (framing_ == Framing::content_length && body.size() > remaining_)
            co_return invalidate(make_error_code(Errc::invalid_argument));
        if (body.size() > options_.limits.max_body_size - sent_ ||
            (framing_ == Framing::chunked && body.size() > options_.limits.max_chunk_size))
            co_return invalidate(make_error_code(Errc::limit_exceeded));
        if (body.empty()) co_return Result<void>{};
        if (framing_ == Framing::chunked) {
            std::array<char, 2 * sizeof(std::size_t) + 2> prefix{};
            const auto encoded = std::to_chars(prefix.data(), prefix.data() + prefix.size() - 2,
                                               body.size(), 16);
            *encoded.ptr = '\r';
            *(encoded.ptr + 1) = '\n';
            const auto count = static_cast<std::size_t>(encoded.ptr - prefix.data()) + 2;
            const auto result = co_await write_bytes(std::as_bytes(std::span{prefix}.first(count)));
            if (!result) co_return invalidate(result.error());
        }
        auto result = co_await write_bytes(body);
        if (!result) co_return invalidate(result.error());
        if (framing_ == Framing::chunked) {
            result = co_await write_bytes(bytes("\r\n"));
            if (!result) co_return invalidate(result.error());
        } else {
            remaining_ -= body.size();
        }
        sent_ += body.size();
        co_return Result<void>{};
    }

    /// Finish upload and read the final response head; incomplete fixed bodies fail with eof.
    /// Only this operation writes the final chunk. Request trailers are unsupported.
    [[nodiscard]] Task<Result<void>> finish() {
        if (busy_ || !active_ || !uploading_) co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        if (const auto error = budget_error()) co_return invalidate(error);
        if (framing_ == Framing::content_length && remaining_ != 0)
            co_return invalidate(make_error_code(Errc::eof));
        if (framing_ == Framing::chunked) {
            const auto result = co_await write_bytes(bytes("0\r\n\r\n"));
            if (!result) co_return invalidate(result.error());
        }
        uploading_ = false;
        std::size_t informational = 0;
        for (;;) {
            const auto step = co_await next();
            if (!step) co_return invalidate(step.error());
            if (*step != ParseStep::head)
                co_return invalidate(make_error_code(Errc::invalid_argument));
            if (parser_.response().status >= 200) break;
            if (++informational > options_.max_informational_responses)
                co_return invalidate(make_error_code(Errc::limit_exceeded));
            const auto complete = parser_.parse(input_, eof_);
            if (!complete) co_return invalidate(complete.error());
            parser_.reset(method_);
        }
        const auto& response = parser_.response();
        if (response.body_kind == BodyKind::close_delimited ||
            mentions(response.headers, "close") ||
            (response.version == Version::http_1_0 && !mentions(response.headers, "keep-alive")))
            reusable_ = false;
        co_return Result<void>{};
    }

    /// Convenience for a borrowed contiguous body; the response must still be drained.
    [[nodiscard]] Task<Result<void>>
    start(const Request& request, std::span<const std::byte> body = {}, OperationOptions io = {}) {
        auto result = co_await begin(request, Framing::content_length, body.size(), std::move(io));
        if (!result) co_return result;
        result = co_await send_body(body);
        if (!result) co_return result;
        co_return co_await finish();
    }

    /// Return one borrowed slice, valid until begin/start/read_body; empty means complete.
    /// Trailers are available after drain. Otherwise abandon and close the underlying stream.
    [[nodiscard]] Task<Result<std::span<const std::byte>>> read_body() {
        if (busy_ || !active_ || uploading_) co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        const auto step = co_await next();
        if (!step) co_return invalidate(step.error());
        if (*step == ParseStep::body) co_return parser_.body();
        if (*step != ParseStep::complete)
            co_return invalidate(make_error_code(Errc::invalid_argument));
        active_ = false;
        if (!input_.empty()) reusable_ = false;
        co_return std::span<const std::byte>{};
    }

    /// Abandon an idle exchange; the caller must then close the stream. Rejects active I/O.
    [[nodiscard]] Result<void> abandon() noexcept {
        if (busy_) return fail(Errc::invalid_argument);
        active_ = false;
        uploading_ = false;
        reusable_ = false;
        return {};
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
    static std::span<const std::byte> bytes(std::string_view text) {
        return std::as_bytes(std::span{text.data(), text.size()});
    }
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
        uploading_ = false;
        return fail(error);
    }
    Task<Result<void>> write_bytes(std::span<const std::byte> data) {
        while (!data.empty()) {
            if (const auto error = budget_error()) co_return fail(error);
            const auto n = co_await stream_->write_some(data, io_);
            if (!n) co_return fail(n.error());
            if (*n == 0) co_return fail(Errc::eof);
            if (*n > data.size()) co_return fail(Errc::invalid_argument);
            data = data.subspan(*n);
        }
        if (const auto error = budget_error()) co_return fail(error);
        co_return Result<void>{};
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
                if (*read > count) {
                    input_.commit(0);
                    co_return fail(Errc::invalid_argument);
                }
                input_.commit(*read);
                if (*read == 0) eof_ = true;
            }
        }
    }
    Stream* stream_;
    ClientOptions options_;
    ResponseParser parser_;
    ResourceBudget::Reservation input_charge_;
    Buffer input_;
    OperationOptions io_{};
    Method method_{Method::get};
    Framing framing_{Framing::content_length};
    std::uint64_t remaining_{0};
    std::uint64_t sent_{0};
    bool busy_{false};
    bool active_{false};
    bool uploading_{false};
    bool reusable_{true};
    bool eof_{false};
};

}  // namespace Mira::http
