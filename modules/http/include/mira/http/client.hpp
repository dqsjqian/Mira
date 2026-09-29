#pragma once

#include "mira/core/event_loop.hpp"
#include "mira/core/stream.hpp"
#include "mira/core/resource_budget.hpp"
#include "mira/core/task_scope.hpp"
#include <optional>
#include "mira/http/response_parser.hpp"
#include "mira/http/serializer.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <charconv>
#include <concepts>
#include <cstdio>
#include <cstdlib>
#include <stop_token>

namespace Mira::http {

/// Pull-based request body for `ClientConnection::exchange`: each call yields
/// the next borrowed chunk, valid until the following call; empty = end of body.
template<typename Source>
concept BodySource = requires(Source& source) {
    { source() } -> std::same_as<Task<Result<std::span<const std::byte>>>>;
};

/// Duplex upload policy for `ClientConnection::exchange`.
struct UploadOptions {
    /// Send `Expect: 100-continue` and hold the body until 100 Continue, a final
    /// response, or `continue_timeout` (RFC 9110 §10.1.1). HTTP/1.1 with content only.
    bool expect_continue = false;
    /// Longest wait for 100 before sending anyway; must be positive when used.
    Clock::duration continue_timeout = std::chrono::seconds{1};
};

enum class UploadOutcome {
    /// Every body byte was written.
    complete,
    /// A final response arrived before 100 Continue; no body byte was sent.
    skipped,
    /// A final response refusing the body (status >= 300 or closing) arrived
    /// mid-upload; the remaining body was withheld.
    interrupted,
};

struct ExchangeResult {
    UploadOutcome upload = UploadOutcome::complete;
    std::uint64_t body_sent = 0;
    /// Whether 100 Continue was observed before the final response.
    bool continued = false;
};

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
/// begin/send_body/finish is send-first: it reads nothing until the body is sent.
/// `exchange` is the duplex form: it reads the response concurrently with the
/// upload, supports Expect: 100-continue, and withholds the rest of a body the
/// server has refused. It needs a stream that permits one read and one write in
/// flight at once (Mira TCP, TLS and local streams do). Never retries.
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
        Guard guard{busy_};
        co_return co_await open(request, framing, size, std::move(io), Expectation::none);
    }

    /// Duplex exchange: write the head, then upload the body pulled from `source`
    /// while a concurrent reader parses informational and final response heads.
    ///
    /// With `expect_continue`, no body byte is written until 100 Continue arrives
    /// or `continue_timeout` elapses; a final response first yields `skipped`.
    /// Mid-upload, a final response with status >= 300 or a closing connection
    /// stops the upload before the next chunk (`interrupted`); an early 2xx
    /// that keeps the connection lets the upload complete (RFC 9112 §9.5).
    /// An in-flight chunk write is never cancelled for an early response —
    /// on TLS that would invalidate the session and lose the response — so a
    /// peer that neither reads nor closes is bounded by the deadline or stop.
    /// Reader failure cancels the writer; producer failure cancels the reader.
    /// Returns once the final head is parsed; drain it with `read_body`.
    /// `skipped`/`interrupted` forbid reuse. The response body is read after
    /// the upload, not concurrently with it.
    template<BodySource Source>
    [[nodiscard]] Task<Result<ExchangeResult>>
    exchange(EventLoop& loop, const Request& request, Framing framing, std::uint64_t size,
             Source& source, UploadOptions upload = {}, OperationOptions io = {}) {
        if (busy_ || active_ || !reusable_) co_return fail(Errc::invalid_argument);
        if (upload.expect_continue && upload.continue_timeout <= Clock::duration::zero())
            co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        const auto opened = co_await open(request, framing, size, std::move(io),
                                          upload.expect_continue ? Expectation::continue_100
                                                                 : Expectation::none);
        if (!opened) co_return fail(opened.error());

        Duplex duplex;
        // The caller's stop reaches every leg; each leg can also be cut alone.
        std::stop_callback forward_reader{io_.stop, [&duplex] { duplex.reader_stop.request_stop(); }};
        std::stop_callback forward_writer{io_.stop, [&duplex] { duplex.writer_stop.request_stop(); }};
        std::stop_callback forward_wait{io_.stop, [&duplex] { duplex.wait_stop.request_stop(); }};
        TaskScope scope;
        scope.spawn(read_heads(duplex));
        auto uploaded = co_await upload_body(loop, source, upload, duplex);
        // A writer failure before the final head ends the exchange; the reader
        // is cut so the error reported is the writer's, not its echo.
        const bool reader_cut = !uploaded && !duplex.reader_done;
        if (reader_cut) duplex.reader_stop.request_stop();
        co_await scope.join();
        uploading_ = false;

        if (const auto error = budget_error(io_)) co_return invalidate(error);
        if (!duplex.final_head) {
            if (reader_cut) co_return invalidate(uploaded.error());
            if (duplex.reader_error) co_return invalidate(duplex.reader_error);
            co_return invalidate(uploaded ? make_error_code(Errc::invalid_argument)
                                          : uploaded.error());
        }
        // Only a failed stream write after the final head means the peer
        // closed on its refusal; producer and framing errors stay errors.
        if (!uploaded && !duplex.write_failed) co_return invalidate(uploaded.error());
        ExchangeResult result;
        result.continued = duplex.continued;
        result.body_sent = sent_;
        if (!uploaded) {
            result.upload = sent_ == 0 && upload.expect_continue && !duplex.continued
                                ? UploadOutcome::skipped
                                : UploadOutcome::interrupted;
        } else {
            result.upload = *uploaded;
        }
        if (result.upload != UploadOutcome::complete) reusable_ = false;
        mark_response_reuse();
        co_return result;
    }

    /// Duplex exchange of a borrowed contiguous body (content-length framing).
    [[nodiscard]] Task<Result<ExchangeResult>>
    exchange(EventLoop& loop, const Request& request, std::span<const std::byte> body,
             UploadOptions upload = {}, OperationOptions io = {}) {
        SingleChunk source{body};
        co_return co_await exchange(loop, request, Framing::content_length, body.size(), source,
                                    upload, std::move(io));
    }

    /// Borrow and finish one chunk before returning, applying producer backpressure.
    /// Empty chunks do not finish upload; size violations permanently invalidate reuse.
    [[nodiscard]] Task<Result<void>> send_body(std::span<const std::byte> body) {
        if (busy_ || !active_ || !uploading_) co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        const auto result = co_await put_chunk(body, io_);
        if (!result) co_return invalidate(result.error());
        co_return Result<void>{};
    }

    /// Finish upload and read the final response head; incomplete fixed bodies fail with eof.
    /// Only this operation writes the final chunk. Request trailers are unsupported.
    [[nodiscard]] Task<Result<void>> finish() {
        if (busy_ || !active_ || !uploading_) co_return fail(Errc::invalid_argument);
        Guard guard{busy_};
        const auto ended = co_await end_body(io_);
        if (!ended) co_return invalidate(ended.error());
        uploading_ = false;
        std::size_t informational = 0;
        for (;;) {
            const auto step = co_await next(io_);
            if (!step) co_return invalidate(step.error());
            if (*step != ParseStep::head)
                co_return invalidate(make_error_code(Errc::invalid_argument));
            if (parser_.response().status >= 200) break;
            if (const auto skipped = skip_informational(informational); !skipped)
                co_return invalidate(skipped.error());
        }
        mark_response_reuse();
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
        const auto step = co_await next(io_);
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
    /// Loop-thread state shared by the two legs of one exchange.
    struct Duplex {
        std::stop_source reader_stop;
        std::stop_source writer_stop;
        std::stop_source wait_stop;
        Error reader_error{};
        bool continued = false;
        bool final_head = false;
        bool reader_done = false;
        bool write_failed = false;
    };
    struct SingleChunk {
        std::span<const std::byte> body;
        bool given = false;
        Task<Result<std::span<const std::byte>>> operator()() {
            if (given) co_return std::span<const std::byte>{};
            given = true;
            co_return body;
        }
    };
    static std::span<const std::byte> bytes(std::string_view text) {
        return std::as_bytes(std::span{text.data(), text.size()});
    }
    /// Serialize and write the head; the caller holds the busy guard.
    Task<Result<void>> open(const Request& request, Framing framing, std::uint64_t size,
                            OperationOptions io, Expectation expectation) {
        if (options_.read_chunk == 0 || options_.max_buffer_size == 0 ||
            options_.request_timeout < Clock::duration::zero())
            co_return fail(Errc::invalid_argument);
        io_ = std::move(io);
        if (options_.request_timeout != Clock::duration::zero()) {
            const auto now = Clock::now();
            const auto deadline = options_.request_timeout > Clock::time_point::max() - now
                                      ? Clock::time_point::max()
                                      : now + options_.request_timeout;
            if (!io_.deadline || deadline < *io_.deadline) io_.deadline = deadline;
        }
        if (const auto error = budget_error(io_)) co_return invalidate(error);
        Buffer head;
        const auto serialized =
            write_request_head(head, request, framing, size, options_.limits, expectation);
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
        const auto result = co_await write_bytes(head.readable(), io_);
        if (!result) co_return invalidate(result.error());
        co_return Result<void>{};
    }
    Error chunk_error(std::size_t size) const {
        if (framing_ == Framing::content_length && size > remaining_)
            return make_error_code(Errc::invalid_argument);
        if (size > options_.limits.max_body_size - sent_ ||
            (framing_ == Framing::chunked && size > options_.limits.max_chunk_size))
            return make_error_code(Errc::limit_exceeded);
        return {};
    }
    /// Validate and frame one body chunk; never invalidates by itself.
    Task<Result<void>> put_chunk(std::span<const std::byte> body, const OperationOptions& io) {
        if (const auto error = budget_error(io)) co_return fail(error);
        if (const auto error = chunk_error(body.size())) co_return fail(error);
        if (body.empty()) co_return Result<void>{};
        if (framing_ == Framing::chunked) {
            std::array<char, 2 * sizeof(std::size_t) + 2> prefix{};
            const auto encoded = std::to_chars(prefix.data(), prefix.data() + prefix.size() - 2,
                                               body.size(), 16);
            *encoded.ptr = '\r';
            *(encoded.ptr + 1) = '\n';
            const auto count = static_cast<std::size_t>(encoded.ptr - prefix.data()) + 2;
            const auto framed =
                co_await write_bytes(std::as_bytes(std::span{prefix}.first(count)), io);
            if (!framed) co_return fail(framed.error());
        }
        // Count bytes once the chunk payload is on the wire, before its CRLF.
        auto result = co_await write_bytes(body, io);
        if (!result) co_return fail(result.error());
        sent_ += body.size();
        if (framing_ == Framing::chunked) {
            result = co_await write_bytes(bytes("\r\n"), io);
            if (!result) co_return fail(result.error());
        } else {
            remaining_ -= body.size();
        }
        co_return Result<void>{};
    }
    Task<Result<void>> end_body(const OperationOptions& io) {
        if (const auto error = budget_error(io)) co_return fail(error);
        if (framing_ == Framing::content_length && remaining_ != 0) co_return fail(Errc::eof);
        if (framing_ == Framing::chunked) {
            const auto result = co_await write_bytes(bytes("0\r\n\r\n"), io);
            if (!result) co_return fail(result.error());
        }
        co_return Result<void>{};
    }
    /// Consume a parsed 1xx head so the next head can be parsed.
    Result<void> skip_informational(std::size_t& informational) {
        if (++informational > options_.max_informational_responses)
            return fail(Errc::limit_exceeded);
        const auto complete = parser_.parse(input_, eof_);
        if (!complete) return fail(complete.error());
        parser_.reset(method_);
        return {};
    }
    /// Whether an early final response refuses the rest of the body.
    bool refuses_body() const {
        const auto& response = parser_.response();
        return response.status >= 300 || closes(response);
    }
    static bool closes(const Response& response) {
        return response.body_kind == BodyKind::close_delimited ||
               mentions(response.headers, "close") ||
               (response.version == Version::http_1_0 && !mentions(response.headers, "keep-alive"));
    }
    void mark_response_reuse() {
        if (closes(parser_.response())) reusable_ = false;
    }
    /// Reader leg: parse heads until the final one. 101 is never valid here
    /// because requests never ask to upgrade.
    Task<void> read_heads(Duplex& duplex) {
        const OperationOptions io{.stop = duplex.reader_stop.get_token(), .deadline = io_.deadline};
        std::size_t informational = 0;
        for (;;) {
            const auto step = co_await next(io);
            if (!step) {
                duplex.reader_error = step.error();
                break;
            }
            if (*step != ParseStep::head) {
                duplex.reader_error = make_error_code(Errc::invalid_argument);
                break;
            }
            const auto status = parser_.response().status;
            if (status >= 200) {
                duplex.final_head = true;
                break;
            }
            if (status == 101) {
                duplex.reader_error = make_error_code(Errc::invalid_argument);
                break;
            }
            if (status == 100 && !duplex.continued) {
                duplex.continued = true;
                duplex.wait_stop.request_stop();
            }
            if (const auto skipped = skip_informational(informational); !skipped) {
                duplex.reader_error = skipped.error();
                break;
            }
        }
        duplex.reader_done = true;
        duplex.wait_stop.request_stop();
        // A dead connection must not leave the writer blocked in a write.
        if (duplex.reader_error) duplex.writer_stop.request_stop();
    }
    /// Writer leg. Errors are raw leg errors; exchange() decides what they mean.
    template<BodySource Source>
    Task<Result<UploadOutcome>> upload_body(EventLoop& loop, Source& source,
                                            const UploadOptions& upload, Duplex& duplex) {
        const OperationOptions io{.stop = duplex.writer_stop.get_token(), .deadline = io_.deadline};
        if (upload.expect_continue && !duplex.reader_done && !duplex.continued) {
            // The wait is a cancellable sleep: the reader cuts it short on
            // 100, a final head or failure; elapsing it means "send anyway".
            const auto waited = co_await loop.sleep_for(
                upload.continue_timeout,
                {.stop = duplex.wait_stop.get_token(), .deadline = io_.deadline});
            if (!waited && waited.error() != Errc::cancelled) co_return fail(waited.error());
        }
        if (const auto error = budget_error(io_)) co_return fail(error);
        if (duplex.reader_error) co_return fail(duplex.reader_error);
        if (duplex.final_head && (upload.expect_continue ? !duplex.continued : refuses_body()))
            co_return upload.expect_continue && !duplex.continued ? UploadOutcome::skipped
                                                                  : UploadOutcome::interrupted;
        for (;;) {
            if (duplex.reader_error) co_return fail(duplex.reader_error);
            if (duplex.final_head && refuses_body()) co_return UploadOutcome::interrupted;
            auto chunk = co_await source();
            if (!chunk) co_return fail(chunk.error());
            if (duplex.reader_error) co_return fail(duplex.reader_error);
            if (duplex.final_head && refuses_body()) co_return UploadOutcome::interrupted;
            if (chunk->empty()) break;
            if (const auto error = chunk_error(chunk->size())) co_return fail(error);
            const auto put = co_await put_chunk(*chunk, io);
            if (!put) {
                duplex.write_failed = true;
                co_return fail(put.error());
            }
        }
        if (framing_ == Framing::content_length && remaining_ != 0) co_return fail(Errc::eof);
        const auto ended = co_await end_body(io);
        if (!ended) {
            duplex.write_failed = true;
            co_return fail(ended.error());
        }
        co_return UploadOutcome::complete;
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
    static Error budget_error(const OperationOptions& io) {
        if (io.stop.stop_requested()) return make_error_code(Errc::cancelled);
        if (io.deadline && Clock::now() >= *io.deadline) return make_error_code(Errc::timed_out);
        return {};
    }
    std::unexpected<Error> invalidate(Error error) {
        reusable_ = false;
        active_ = false;
        uploading_ = false;
        return fail(error);
    }
    Task<Result<void>> write_bytes(std::span<const std::byte> data, const OperationOptions& io) {
        while (!data.empty()) {
            if (const auto error = budget_error(io)) co_return fail(error);
            const auto n = co_await stream_->write_some(data, io);
            if (!n) co_return fail(n.error());
            if (*n == 0) co_return fail(Errc::eof);
            if (*n > data.size()) co_return fail(Errc::invalid_argument);
            data = data.subspan(*n);
        }
        if (const auto error = budget_error(io)) co_return fail(error);
        co_return Result<void>{};
    }
    Task<Result<ParseStep>> next(const OperationOptions& io) {
        for (;;) {
            if (const auto error = budget_error(io)) co_return fail(error);
            const auto step = parser_.parse(input_, eof_);
            if (!step || *step != ParseStep::need_more) co_return step;
            if (input_.size() >= options_.max_buffer_size) co_return fail(Errc::limit_exceeded);
            const auto count =
                std::min(options_.read_chunk, options_.max_buffer_size - input_.size());
            const auto read = co_await stream_->read_some(input_.prepare(count), io);
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
