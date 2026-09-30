#pragma once

// Mira/http/connection.hpp — serving requests over one connection.
//
// Generic over the stream type on purpose. `serve_connection` takes anything
// satisfying `Mira::AsyncStream`, so the same code serves a TCP socket, a
// TLS session once that lands, or an in-memory pipe in tests. This module
// links against `Mira::core` only — it has never seen a socket, and the
// layering check keeps it that way.
//
// Three correctness rules are enforced here rather than left to handlers,
// because getting any of them wrong corrupts the *next* request on the
// connection rather than the current one, which makes the bug look unrelated
// to its cause:
//
//   1. **The request body is always drained.** A handler that ignores the body
//      leaves those bytes in the stream, where they get parsed as the start of
//      the following request. This is the classic keep-alive desync.
//   2. **Exactly one response per request, with exactly one framing.** The
//      serializer owns Content-Length / Transfer-Encoding.
//   3. **A HEAD response carries headers but no body**, including its
//      Content-Length, which must describe what a GET *would* have returned.
//
// Usage:
//
//     auto handler = [](const Request& request, auto& writer) -> Task<Result<void>> {
//         Response response;
//         response.status = 200;
//         co_return co_await writer.send(response, body_bytes);
//     };
//     co_await serve_connection(socket, handler);

#include "mira/core/buffer.hpp"
#include "mira/core/error.hpp"
#include "mira/core/resource_budget.hpp"
#include "mira/core/stream.hpp"
#include "mira/core/task.hpp"
#include "mira/http/limits.hpp"
#include "mira/http/message.hpp"
#include "mira/http/parser.hpp"
#include "mira/http/serializer.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <limits>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace Mira::http {

/// Per-connection policy.
struct ServerOptions {
    /// Parser bounds; see `limits.hpp`. Closed by default.
    Limits limits{};

    /// External cancellation is forwarded to every read, response write, and
    /// error response.
    std::stop_token stop{};

    /// Maximum requests served on one connection before closing it.
    ///
    /// Bounded because an unbounded keep-alive connection is a resource a
    /// single client can hold forever.
    std::uint32_t max_requests_per_connection = 100;

    /// Bytes read from the stream per syscall.
    std::size_t read_chunk = 8 * 1024;

    /// Send `Connection: close` and hang up after the current response.
    bool force_close = false;

    /// How long an established connection may sit between requests.
    ///
    /// Durations rather than a deadline, because a deadline cannot express what
    /// a server actually wants: one absolute time would cover the whole
    /// connection, so the hundredth keep-alive request would inherit whatever
    /// budget the first one left. `serve_connection` turns these into a fresh
    /// absolute deadline for each request, which is the form every layer below
    /// composes without arithmetic.
    ///
    /// Expiry here is **not** an error. A keep-alive connection going quiet and
    /// being closed is how it normally ends, so this returns success — the same
    /// as the peer having closed it politely.
    ///
    /// Zero disables it. A server exposed to the internet should not leave it
    /// that way: an idle connection costs a descriptor and a buffer, and a
    /// client can open many.
    Clock::duration idle_timeout = Clock::duration::zero();

    /// How long one request may take, from its first byte to its last
    /// response byte.
    ///
    /// Mira I/O observes this deadline. A handler accepting a fourth
    /// OperationOptions argument receives the same stop token and deadline;
    /// forward them to asynchronous work to bound the complete exchange.
    /// Three-argument handlers can use writer.operation_options(). Callbacks
    /// that ignore cancellation cannot be forcibly interrupted. Expiry is an
    /// error (`Errc::timed_out`) and ends the connection.
    ///
    /// No 408 is sent. Writing a response needs the stream, and the deadline
    /// that just expired is the same one the write would carry, so the attempt
    /// would fail immediately — announcing the timeout would take a second,
    /// separate budget that the caller never granted.
    ///
    /// Zero disables it, which leaves a slow peer bounded only by `limits` —
    /// a bound on one message's size, not on the time it may take to arrive.
    Clock::duration request_timeout = Clock::duration::zero();

    /// Hard input-buffer ceiling, including an incomplete framing line.
    std::size_t max_buffer_size = 64 * 1024;
    /// Optional shared reservation for input and retained request-body bytes.
    /// Parser/header metadata, output and application allocations are excluded.
    std::optional<ResourceBudget> buffer_budget{};
};

/// Writes one response, and refuses to write two.
///
/// Templated on the stream rather than type-erased so that a handler's writes
/// go straight to the socket with no virtual dispatch and no allocation.
template<BoundedStream Stream>
class ResponseWriter {
public:
    ResponseWriter(Stream& stream,
                   bool head_request,
                   bool keep_alive,
                   OperationOptions io = {}, Version version = Version::http_1_1) noexcept
        : stream_(&stream), io_(std::move(io)), version_(version), head_request_(head_request),
          keep_alive_(keep_alive) {}

    ResponseWriter(const ResponseWriter&) = delete;
    ResponseWriter& operator=(const ResponseWriter&) = delete;

    /// Send a complete response with a known body. The common case.
    [[nodiscard]] Task<Result<void>> send(const Response& original,
                                          std::span<const std::byte> body = {}) {
        if (sent_head_) {
            co_return fail(SerializeError::framing_conflict);
        }

        Buffer out;
        std::optional<Response> announced;
        const Response& response = announce(original, announced);
        const Framing framing =
            status_forbids_body(response.status) ? Framing::none : Framing::content_length;

        // Content-Length always describes the real body, even for HEAD, where
        // the bytes themselves are withheld: a HEAD response must announce
        // what a GET would have returned.
        Result<void> head = write_response_head(out, response, framing, body.size());
        if (!head) {
            co_return fail(head.error());
        }
        sent_head_ = true;

        finished_ = true;
        // Head and body go out without being concatenated when the stream
        // can scatter (writev/WSASend); a stream without that ability keeps
        // the plain path. A HEAD response, or a status that forbids bodies,
        // carries headers only.
        if (head_request_ || body.empty() || status_forbids_body(response.status)) {
            co_return co_await write_all(*stream_, out.readable(), io_);
        }
        if constexpr (BoundedVectorWriteStream<Stream>) {
            const std::span<const std::byte> pieces[2] = {out.readable(), body};
            co_return co_await writev_all(*stream_, pieces, io_);
        } else {
            out.append(body);
            co_return co_await write_all(*stream_, out.readable(), io_);
        }
    }

    /// Begin a streaming response whose size is not yet known.
    ///
    /// Bodies then go out via `write` and are terminated by `finish`.
    [[nodiscard]] Task<Result<void>> send_head_chunked(const Response& original) {
        if (sent_head_) {
            co_return fail(SerializeError::framing_conflict);
        }

        Buffer out;
        std::optional<Response> announced;
        close_delimited_ = version_ == Version::http_1_0 && !head_request_ &&
                           !status_forbids_body(original.status);
        if (close_delimited_) keep_alive_ = false;
        const Response& response = announce(original, announced);
        Result<void> head = write_response_head(out, response,
            version_ == Version::http_1_0 ? Framing::none : Framing::chunked);
        if (!head) {
            co_return fail(head.error());
        }
        sent_head_ = true;
        chunked_ = !close_delimited_ && !status_forbids_body(response.status);

        co_return co_await write_all(*stream_, out.readable(), io_);
    }

    /// Send one piece of a streaming body.
    [[nodiscard]] Task<Result<void>> write(std::span<const std::byte> piece) {
        if (!sent_head_ || finished_) {
            co_return fail(SerializeError::framing_conflict);
        }
        if (piece.empty()) {
            co_return Result<void>{};  // nothing to frame
        }
        // A HEAD response must not carry body bytes, but the handler should not
        // have to branch on it — swallow them here.
        if (head_request_) co_return Result<void>{};
        if (close_delimited_) co_return co_await write_all(*stream_, piece, io_);
        if (!chunked_) co_return Result<void>{};

        Buffer out;
        Result<void> framed = write_chunk(out, piece);
        if (!framed) {
            co_return fail(framed.error());
        }
        co_return co_await write_all(*stream_, out.readable(), io_);
    }

    /// Terminate a streaming body.
    [[nodiscard]] Task<Result<void>> finish() {
        if (!sent_head_ || finished_) {
            co_return Result<void>{};
        }
        finished_ = true;
        if (head_request_ || !chunked_) {
            co_return Result<void>{};
        }

        Buffer out;
        write_last_chunk(out);
        co_return co_await write_all(*stream_, out.readable(), io_);
    }

    /// True once a head has gone out — the connection loop uses this to avoid
    /// sending an error response on top of a partial one.
    [[nodiscard]] bool sent_head() const noexcept { return sent_head_; }

    /// Whether the connection is expected to stay open after this response.
    [[nodiscard]] bool keep_alive() const noexcept { return keep_alive_; }
    [[nodiscard]] OperationOptions operation_options() const noexcept { return io_; }

    /// Set by `serve_connection` while a 100-continue expectation is still
    /// unanswered: a final head sent in that state refuses the body, so it
    /// announces `Connection: close` and the connection ends after it.
    void set_refuses_unread_body(bool value) noexcept { refuses_unread_body_ = value; }
    /// The streaming reader clears this once request framing is complete.
    void set_unread_body(bool value) noexcept { unread_body_ = value; }

private:
    const Response& announce(const Response& response, std::optional<Response>& scratch) {
        bool has_close = false;
        bool has_keep_alive = false;
        for (const auto& [name, value] : response.headers) {
            if (!HeaderMap::names_equal(name, "Connection")) continue;
            std::string_view tokens = value;
            do {
                const auto comma = tokens.find(',');
                auto token = tokens.substr(0, comma);
                while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.remove_prefix(1);
                while (!token.empty() && (token.back() == ' ' || token.back() == '\t')) token.remove_suffix(1);
                has_close = has_close || HeaderMap::names_equal(token, "close");
                has_keep_alive = has_keep_alive || HeaderMap::names_equal(token, "keep-alive");
                if (comma == tokens.npos) break;
                tokens.remove_prefix(comma + 1);
            } while (!tokens.empty());
        }
        // A rejecting peer may stop an upload as soon as this head arrives.
        // Announce closure now, before bytes are sent, and do not subsequently
        // wait for a body the client has been told to withhold.
        if (has_close || (refuses_unread_body_ && response.status >= 200) ||
            (unread_body_ && response.status >= 300)) keep_alive_ = false;
        const bool add_keep_alive = keep_alive_ && version_ == Version::http_1_0 && !has_keep_alive;
        if (response.version == version_ && (keep_alive_ || has_close) && !add_keep_alive) return response;
        scratch = response;
        scratch->version = version_;
        if (!keep_alive_ && !has_close) scratch->headers.append("Connection", "close");
        if (add_keep_alive) scratch->headers.append("Connection", "keep-alive");
        return *scratch;
    }

    Stream* stream_;
    /// This request's budget, applied to every write the handler causes.
    OperationOptions io_{};
    Version version_{Version::http_1_1};
    bool close_delimited_{false};
    bool head_request_{false};
    bool keep_alive_{true};
    bool sent_head_{false};
    bool chunked_{false};
    bool finished_{false};
    bool refuses_unread_body_{false};
    bool unread_body_{false};
};

/// Reads a request body incrementally while the handler runs.
///
/// The buffered path in `serve_connection` accumulates the whole body before
/// the handler sees it, which is exactly right for JSON endpoints and exactly
/// wrong for uploads: a handler that pipes bytes to disk, a proxy, or another
/// endpoint should not need the whole body in memory to make progress. Give
/// the handler a `RequestBodyReader` (by making its third parameter `auto&`
/// and calling `read`) and the connection loop hands it the body slice by
/// slice instead.
///
/// Ownership of the connection stays with `serve_connection`: the reader
/// borrows the parser and the input buffer, so a request that outlives its
/// handler is impossible by construction. Reads carry the request's own
/// budget — the same deadline the response writes use — so a slow peer
/// cannot outlive `request_timeout` by streaming a body slowly enough.
template<BoundedStream Stream>
class RequestBodyReader {
public:
    /// Pull the next slice of the body into `out`.
    ///
    /// Returns the number of bytes written; 0 means the body is fully
    /// consumed (trailers, if any, have been parsed by then). A slice larger
    /// than `out` is split transparently — the remainder is held and served
    /// by the following call — so handlers can read with a small fixed
    /// buffer regardless of what the network delivered.
    ///
    /// A protocol error (body over budget, malformed chunk) or a transport
    /// error (EOF, timeout, cancellation) fails the read. The connection is
    /// then untrustworthy: `serve_connection` closes it after the handler
    /// returns.
    [[nodiscard]] Task<Result<std::size_t>> read(std::span<std::byte> out) {
        if (finished_) {
            co_return std::size_t{0};
        }
        if (out.empty()) {
            co_return fail(Errc::invalid_argument);
        }
        // A pending 100-continue is answered by the first read: pulling the
        // body is the handler deciding it wants it. Once a final head is out
        // the client was told not to send, so no 100 follows it.
        if (continue_pending_) {
            continue_pending_ = false;
            if (writer_ != nullptr && !writer_->sent_head()) {
                writer_->set_refuses_unread_body(false);
                constexpr std::string_view interim = "HTTP/1.1 100 Continue\r\n\r\n";
                Result<void> sent = co_await write_all(
                    stream_, std::as_bytes(std::span{interim.data(), interim.size()}), io_);
                if (!sent) {
                    finished_ = true;
                    last_error_ = sent.error();
                    co_return fail(sent.error());
                }
            }
        }
        // Leftovers from a previous read come first: a slice larger than the
        // caller's buffer was already split, and ordering must be preserved.
        if (pending_pos_ < pending_.size()) {
            const std::size_t n =
                std::min(pending_.size() - pending_pos_, out.size());
            std::memcpy(out.data(), pending_.data() + pending_pos_, n);
            pending_pos_ += n;
            if (pending_pos_ == pending_.size()) {
                pending_.clear();
                pending_pos_ = 0;
            }
            co_return n;
        }
        for (;;) {
            const Result<ParseStep> step = parser_.parse(input_);
            if (!step) {
                finished_ = true;
                last_error_ = step.error();
                co_return fail(step.error());
            }
            switch (*step) {
            case ParseStep::body: {
                const std::span<const std::byte> slice = parser_.body();
                if (slice.size() <= out.size()) {
                    std::memcpy(out.data(), slice.data(), slice.size());
                    co_return slice.size();
                }
                std::memcpy(out.data(), slice.data(), out.size());
                pending_.assign(slice.begin() + static_cast<std::ptrdiff_t>(out.size()),
                                slice.end());
                pending_pos_ = 0;
                co_return out.size();
            }
            case ParseStep::complete:
                finished_ = true;
                last_error_.reset();
                if (body_writer_) body_writer_->set_unread_body(false);
                co_return std::size_t{0};
            case ParseStep::head:
                continue;  // unreachable past the head, kept for symmetry
            case ParseStep::need_more: {
                if (parser_.done()) {
                    finished_ = true;
                    last_error_.reset();
                    if (body_writer_) body_writer_->set_unread_body(false);
                    co_return std::size_t{0};
                }
                if (input_.size() >= max_buffer_size_) {
                    finished_ = true;
                    last_error_ = make_error_code(Errc::limit_exceeded);
                    co_return fail(*last_error_);
                }
                const std::span<std::byte> space = input_.prepare(
                    std::min(read_chunk_, max_buffer_size_ - input_.size()));
                Result<std::size_t> read = co_await stream_.read_some(space, io_);
                if (!read) {
                    input_.commit(0);
                    finished_ = true;
                    last_error_ = read.error();
                    co_return fail(read.error());
                }
                input_.commit(*read);
                if (*read == 0) {
                    finished_ = true;
                    last_error_ = make_error_code(Errc::eof);
                    co_return fail(Errc::eof);
                }
                continue;
            }
            }
        }
    }

    /// Read the whole body into one buffer.
    ///
    /// The parser's `max_body_size` is the real bound; this is the convenience
    /// for handlers that genuinely want everything (a disk-backed spill point
    /// being the memory-safe alternative for anything larger).
    [[nodiscard]] Task<Result<std::vector<std::byte>>> read_all() {
        std::vector<std::byte> out;
        const auto& request = parser_.request();
        if (request.body_kind == BodyKind::length &&
            request.content_length <= parser_.limits().max_body_size) {
            out.reserve(static_cast<std::size_t>(request.content_length));
        }
        std::array<std::byte, 8 * 1024> chunk{};
        for (;;) {
            Result<std::size_t> n = co_await read(chunk);
            if (!n) {
                co_return fail(n.error());
            }
            if (*n == 0) {
                co_return out;
            }
            out.insert(out.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(*n));
        }
    }

    /// True once the body is fully consumed (or has failed).
    [[nodiscard]] bool done() const noexcept { return finished_; }

    /// Why the body stopped, when it stopped on an error rather than by
    /// completing. Lets `serve_connection` tell a completed body from a
    /// failed one after the handler returns.
    [[nodiscard]] const std::optional<std::error_code>& last_error() const noexcept {
        return last_error_;
    }

    /// Trailer fields of a chunked body; meaningful after a 0-byte read.
    ///
    /// The view borrows the connection's parser: it dies with
    /// `serve_connection` (or the next request on the same connection). Copy
    /// a value out while the reader is alive if it must outlive the request.
    [[nodiscard]] const HeaderMap& trailers() const noexcept { return parser_.trailers(); }

    /// True while a 100-continue expectation has not been answered by a read.
    [[nodiscard]] bool continue_pending() const noexcept { return continue_pending_; }

public:
    RequestBodyReader(Stream& stream, Buffer& input, RequestParser& parser,
                      OperationOptions io, std::size_t read_chunk,
                      std::size_t max_buffer_size = 64 * 1024,
                      ResponseWriter<Stream>* continue_writer = nullptr,
                      ResponseWriter<Stream>* body_writer = nullptr)
        : stream_(stream), input_(input), parser_(parser), io_(std::move(io)),
          read_chunk_(read_chunk), max_buffer_size_(max_buffer_size),
          writer_(continue_writer), body_writer_(body_writer),
          continue_pending_(continue_writer != nullptr) {}

    /// Drain whatever the handler left unread.
    ///
    /// The one rule the buffered path enforces by construction — the body is
    /// always drained before the next request parses — has to be re-enforced
    /// here, because a streaming handler may legitimately stop reading (a
    /// 413 handler that saw `Content-Length: 10G` and refuses to pull it).
    /// Bytes left in the stream would be parsed as the next request, which
    /// is the keep-alive desync the connection loop exists to prevent.
    ///
    /// A reader that already failed keeps failing: `finished_` set by an
    /// error is not the same as a completed body, and the connection must
    /// not stay open just because the handler itself returned success.
    [[nodiscard]] Task<Result<void>> drain() {
        if (finished_ && last_error_) {
            co_return fail(*last_error_);
        }
        std::array<std::byte, 8 * 1024> sink{};
        while (!finished_) {
            Result<std::size_t> n = co_await read(sink);
            if (!n) {
                co_return fail(n.error());
            }
            if (*n == 0) {
                co_return Result<void>{};
            }
        }
        if (last_error_) {
            co_return fail(*last_error_);
        }
        co_return Result<void>{};
    }

    Stream& stream_;
    Buffer& input_;
    RequestParser& parser_;
    OperationOptions io_;
    std::size_t read_chunk_;
    std::size_t max_buffer_size_;
    ResponseWriter<Stream>* writer_{nullptr};
    ResponseWriter<Stream>* body_writer_{nullptr};
    bool continue_pending_{false};
    /// Remainder of a body slice that did not fit the caller's buffer, plus
    /// a read cursor: `pending_.size() - pending_pos_` bytes are owed.
    std::vector<std::byte> pending_{};
    std::size_t pending_pos_{0};
    bool finished_{false};
    /// Why the body stopped, if it stopped on an error rather than by
    /// completing. Set by `read`; consumed by `drain`.
    std::optional<std::error_code> last_error_{};
};

namespace detail {

/// Detects a handler that takes the buffered body: its third parameter is
/// `std::span<const std::byte>` (or a reference to one). Any other callable
/// third parameter gets the streaming reader — the typical signature is
/// `auto&` accepting a `RequestBodyReader`.
template<typename Handler, typename Stream>
concept kHandlerWantsBuffer = requires(Handler handler, Stream& stream) {
    handler(std::declval<const Request&>(), std::declval<ResponseWriter<Stream>&>(),
            std::declval<std::span<const std::byte>>());
} || requires(Handler handler, Stream& stream) {
    handler(std::declval<const Request&>(), std::declval<ResponseWriter<Stream>&>(),
            std::declval<std::span<const std::byte>>(), std::declval<OperationOptions>());
};


enum class RequestExpectation { none, continue_100, unsupported };

/// RFC 9110 §10.1.1: 100-continue is honoured only for HTTP/1.1 requests with
/// content (HTTP/1.0 expectations are ignored); any other member is refused.
inline RequestExpectation request_expectation(const Request& request) {
    if (request.version != Version::http_1_1) return RequestExpectation::none;
    bool wants_continue = false;
    for (const auto& [name, value] : request.headers) {
        if (!HeaderMap::names_equal(name, "Expect")) continue;
        std::string_view rest{value};
        for (;;) {
            const auto comma = rest.find(',');
            auto member = rest.substr(0, comma);
            while (!member.empty() && (member.front() == ' ' || member.front() == '\t'))
                member.remove_prefix(1);
            while (!member.empty() && (member.back() == ' ' || member.back() == '\t'))
                member.remove_suffix(1);
            if (HeaderMap::names_equal(member, "100-continue")) {
                wants_continue = true;
            } else if (!member.empty()) {
                return RequestExpectation::unsupported;
            }
            if (comma == std::string_view::npos) break;
            rest.remove_prefix(comma + 1);
        }
    }
    if (!wants_continue || request.body_kind == BodyKind::none) return RequestExpectation::none;
    return RequestExpectation::continue_100;
}

/// Send a minimal error response, used when a request cannot be understood.
///
/// Deliberately bare: a parse failure means the request is untrustworthy, so
/// the reply says as little as possible and the connection closes.
template<BoundedStream Stream>
Task<Result<void>> send_error(Stream& stream, unsigned status, OperationOptions io) {
    Response response;
    response.version = Version::http_1_1;
    response.status = status;
    response.headers.append("Connection", "close");

    Buffer out;
    Result<void> head = write_response_head(out, response, Framing::content_length, 0);
    if (!head) {
        co_return fail(head.error());
    }
    // Carries the request's own deadline: announcing a rejection must not
    // outlive the exchange it is rejecting.
    co_return co_await write_all(stream, out.readable(), std::move(io));
}

}  // namespace detail

/// Serve requests on `stream` until the connection ends.
///
/// The handler decides how the request body arrives. A third parameter of
/// `std::span<const std::byte>` gets the buffered path: the whole body is
/// accumulated (up to the parser's `max_body_size`) before the handler runs,
/// and `parser.body()` slices are appended as they parse. Any other callable
/// third parameter gets a `RequestBodyReader` instead and pulls slices as it
/// goes — the connection loop then guarantees the body is drained (or the
/// connection dropped) before the next request parses, whichever way the
/// handler stopped reading.
///
/// Returns when the peer closes, a limit is reached, or the exchange decides to
/// close. A protocol error is answered with a 4xx where possible and then ends
/// the connection — continuing to parse a stream whose framing is already in
/// doubt is how one bad request becomes several.
template<BoundedStream Stream, typename Handler>
Task<Result<void>> serve_connection(Stream& stream, Handler handler, ServerOptions options = {}) {
    if (options.read_chunk == 0 || options.max_buffer_size == 0 ||
        options.idle_timeout < Clock::duration::zero() || options.request_timeout < Clock::duration::zero()) {
        co_return fail(Errc::invalid_argument);
    }
    constexpr bool buffered_handler = detail::kHandlerWantsBuffer<Handler, Stream>;
    ResourceBudget::Reservation buffer_charge;
    if (options.buffer_budget) {
        // Reserve potential retained bytes before accepting request data. A
        // streaming reader can retain a partial slice in addition to input.
        std::size_t reservation = options.max_buffer_size;
        const auto retained = buffered_handler ? options.limits.max_body_size
                                               : static_cast<std::uint64_t>(options.max_buffer_size);
        if (retained > std::numeric_limits<std::size_t>::max() - reservation)
            co_return fail(Errc::limit_exceeded);
        reservation += static_cast<std::size_t>(retained);
        auto acquired = options.buffer_budget->try_acquire(reservation);
        if (!acquired) co_return fail(acquired.error());
        buffer_charge = std::move(*acquired);
    }
    Buffer input{options.max_buffer_size};
    RequestParser parser{options.limits};

    // Turn a configured window into an absolute deadline, or nothing when the
    // window is disabled. Every layer below composes absolute deadlines
    // without arithmetic, which is why the conversion happens exactly here and
    // exactly once per window.
    const auto deadline_in = [](Clock::duration window) -> std::optional<Clock::time_point> {
        if (window == Clock::duration::zero()) {
            return std::nullopt;
        }
        const auto now = Clock::now();
        return window > Clock::time_point::max() - now ? Clock::time_point::max() : now + window;
    };

    for (std::uint32_t served = 0; served < options.max_requests_per_connection; ++served) {
        parser.reset();

        bool head_ready = false;
        // Bytes left over from a pipelined request mean this one has already
        // begun, so it is on the request budget rather than the idle one.
        bool request_started = !input.empty();
        bool body_drained = false;
        bool continue_pending = false;
        Buffer body;  // accumulated only up to the configured limit

        // Whichever window applies right now. Recomputed when the first byte
        // arrives, so that a connection's hundredth request gets the same
        // budget as its first.
        OperationOptions io{.stop = options.stop,
                            .deadline = deadline_in(request_started ? options.request_timeout
                                                                    : options.idle_timeout)};

        // ── read and parse one request ──────────────────────────────────────
        //
        // The body phase belongs to whichever mode the handler chose. A
        // buffered handler runs the loop until the message is complete, so
        // the whole body is in memory before it is called. A streaming
        // handler takes over at the head; its `RequestBodyReader` continues
        // the same parser from exactly this state, and the drain after the
        // handler closes whatever it left open.
        constexpr bool buffered_mode = detail::kHandlerWantsBuffer<Handler, Stream>;
        while (!head_ready || (buffered_mode && !body_drained)) {
            const Result<ParseStep> step = parser.parse(input);
            if (!step) {
                // The request is malformed or over budget. Answer once with
                // the status that matches — 413 for sizes, 400 for grammar —
                // then stop: the stream position is no longer trustworthy.
                const unsigned status = step.error() == make_error_code(ParseError::limit_exceeded) ? 413u : 400u;
                static_cast<void>(co_await detail::send_error(stream, status, io));
                co_return fail(step.error());
            }

            switch (*step) {
            case ParseStep::head:
                if (!valid_request_host(parser.request())) {
                    static_cast<void>(co_await detail::send_error(stream, 400, io));
                    co_return fail(ParseError::malformed_header);
                }
                head_ready = true;
                if (const auto expectation = detail::request_expectation(parser.request());
                    expectation == detail::RequestExpectation::unsupported) {
                    // Whether content follows is now unknowable; refuse and close.
                    static_cast<void>(co_await detail::send_error(stream, 417, io));
                    co_return fail(Errc::not_supported);
                } else if (expectation == detail::RequestExpectation::continue_100) {
                    continue_pending = true;
                }
                if (buffered_mode && continue_pending) {
                    // A buffered handler always wants the body: answer now.
                    constexpr std::string_view interim = "HTTP/1.1 100 Continue\r\n\r\n";
                    Result<void> sent = co_await write_all(
                        stream, std::as_bytes(std::span{interim.data(), interim.size()}), io);
                    if (!sent) co_return fail(sent.error());
                    continue_pending = false;
                }
                if constexpr (buffered_mode) {
                    if (parser.request().body_kind == BodyKind::none) {
                        body_drained = true;
                    } else if (parser.request().body_kind == BodyKind::length) {
                        // The parser knows the declared size once the head is
                        // in; reserving it up front turns the vector's
                        // doubling growth (≈2× the body in copies for large
                        // uploads) into one allocation plus the linear copies
                        // that are structurally unavoidable (the input buffer
                        // rolls). Clamped to the configured limit: a declared
                        // size beyond it never gets read anyway, and reserving
                        // on a hostile Content-Length would be a pre-read
                        // amplification. The streaming path skips this — the
                        // handler owns buffering, not the loop.
                        const std::uint64_t declared = parser.request().content_length;
                        if (declared <= options.limits.max_body_size) {
                            body.reserve(static_cast<std::size_t>(declared));
                        }
                    }
                }
                break;

            case ParseStep::body:
                if constexpr (buffered_mode) {
                    body.append(parser.body());
                }
                break;

            case ParseStep::complete:
                body_drained = true;
                break;

            case ParseStep::need_more:
                if (parser.done()) {
                    body_drained = true;
                    break;
                }
                {
                    if (input.size() >= options.max_buffer_size)
                        co_return fail(Errc::limit_exceeded);
                    const std::span<std::byte> space = input.prepare(
                        std::min(options.read_chunk, options.max_buffer_size - input.size()));
                    Result<std::size_t> read = co_await stream.read_some(space, io);
                    if (!read) {
                        input.commit(0);
                        // Between requests, both a clean close and an idle
                        // timeout are how a keep-alive connection normally
                        // ends — neither is a failure to report. Mid-request,
                        // the same events are a truncated message and a peer
                        // that ran out of time, and both do fail.
                        if (!request_started &&
                            (read.error() == Errc::eof || read.error() == Errc::timed_out)) {
                            co_return Result<void>{};
                        }
                        co_return fail(read.error());
                    }
                    input.commit(*read);
                    if (*read == 0) {
                        // A non-empty read making no progress must not spin.
                        co_return fail(Errc::eof);
                    }
                    if (!request_started) {
                        request_started = true;
                        // The request's own budget starts at its first byte,
                        // not at whenever the connection happened to open.
                        io.deadline = deadline_in(options.request_timeout);
                    }
                }
                break;
            }
        }

        // ── run the handler ────────────────────────────────────────────────
        const Request& request = parser.request();
        const bool head_request = request.method == Method::head;
        const bool keep_alive = should_keep_alive(request) && !options.force_close &&
                                served + 1 < options.max_requests_per_connection;

        // The handler shares the request budget: a deadline that covered the
        // reading but not the responding would bound half an exchange.
        ResponseWriter<Stream> writer{stream, head_request, keep_alive, io, request.version};
        writer.set_refuses_unread_body(continue_pending);
        if constexpr (!buffered_handler) writer.set_unread_body(request.body_kind != BodyKind::none);

        // A throwing handler is an internal error, not a protocol event: the
        // exception must not escape `serve_connection` (the caller's loop has
        // no idea what to do with a half-served connection) and must not be
        // silently swallowed either. The contract, mirroring the `Result`
        // failure path below: if nothing was sent yet, answer 500 and close;
        // if a head is already on the wire the response is half-written, so
        // the only honest option is to drop the connection. Either way the
        // caller gets `Errc::internal` rather than an exception it cannot
        // attribute to a connection.
        auto run_handler = [&](auto&& body_argument) -> Task<Result<void>> {
            try {
                if constexpr (requires { handler(request, writer, body_argument, io); })
                    co_return co_await handler(request, writer, body_argument, io);
                else co_return co_await handler(request, writer, body_argument);
            } catch (...) {
                // co_await is illegal inside a catch handler, so the 500 is
                // sent after the handler — the flag carries the branch out.
                co_return fail(Errc::internal);
            }
        };

        Result<void> handled{};
        if constexpr (detail::kHandlerWantsBuffer<Handler, Stream>) {
            handled = co_await run_handler(body.readable());
        } else {
            RequestBodyReader<Stream> reader{stream, input, parser, io, options.read_chunk,
                                             options.max_buffer_size,
                                             continue_pending ? &writer : nullptr, &writer};
            handled = co_await run_handler(reader);
            // A final response sent while 100-continue was unanswered refused
            // the body: the client will not send it, so draining would wait on
            // bytes that never come. Finish the response and close instead.
            if (handled && reader.continue_pending() && writer.sent_head()) {
                Result<void> refused = co_await writer.finish();
                if (!refused) co_return fail(refused.error());
                co_return Result<void>{};
            }
            // The streaming contract's other half: whatever the handler left
            // unread is drained here (bounded by `limits`, failures included)
            // so the next request starts from trustworthy framing. A drain
            // that itself fails means the connection is already unusable —
            // and a reader that stopped on an error keeps failing here even
            // though the handler itself returned success.
            // Complete response framing before waiting for any remaining request bytes.
            if (handled && writer.sent_head()) {
                auto complete = co_await writer.finish();
                if (!complete) co_return fail(complete.error());
                if (!writer.keep_alive()) co_return Result<void>{};
            }
            if (handled && (!reader.done() || reader.last_error().has_value())) {
                Result<void> drained = co_await reader.drain();
                if (!drained) {
                    handled = fail(drained.error());
                }
            }
        }
        if (!handled && !writer.sent_head()) {
            // Nothing on the wire yet: a 500 is still possible. The catch-all
            // flag and the Result failure path converge here.
            static_cast<void>(co_await detail::send_error(stream, 500, io));
        }
        if (!handled) {
            // A head already sent means the response is half-written; the
            // only honest option is to close.
            co_return fail(handled.error());
        }

        // A handler that streamed but never terminated its body would leave the
        // connection mid-message; close it out on its behalf.
        Result<void> finished = co_await writer.finish();
        if (!finished) {
            co_return fail(finished.error());
        }

        if (!writer.keep_alive()) {
            co_return Result<void>{};
        }
    }

    co_return Result<void>{};
}

}  // namespace Mira::http