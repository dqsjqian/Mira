// An HTTP/2 prior-knowledge server, in the shape Mira intends.
//
// "Prior knowledge" is RFC 9113's polite name for skipping negotiation: no
// TLS, no ALPN, no HTTP/1.1 Upgrade — both sides simply agree to speak h2
// frames from the first byte. That makes this the thinnest possible honest
// demonstration of the http2 layer: a TCP listener, a server-role Session,
// and the explicit pump that drives it.
//
// The shape, step by step:
//
//   1. `Session::create(Role::server)` — the I/O-free engine.
//   2. Per connection: greet (the server preface is SETTINGS, sent during
//      session setup), then serve requests with `Connection::pump` — one
//      bounded round of output, input, and protocol replies per call.
//   3. Requests are polled from the session's stream list: when a stream
//      has accumulated a request body, `respond` answers it and
//      `take_body` reclaims the flow-control credit.
//
// One request per stream, answered in arrival order — a teaching server,
// not a scheduler. Concurrency still shows: curls opens several streams
// over one TCP connection, and they all ride the same pumps.
//
// Usage: mira_h2_prior_knowledge_server [port]
//   port  0 (the default) binds an ephemeral loopback port
// Interruption uses the default signal behavior, not graceful shutdown.

#include <mira/core/event_loop.hpp>
#include <mira/core/task.hpp>
#include <mira/core/task_scope.hpp>
#include <mira/http2/connection.hpp>
#include <mira/transport/tcp.hpp>

#include <algorithm>
#include <charconv>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

using Mira::EventLoop;
using Mira::Result;
using Mira::Task;
using Mira::TaskScope;
using Mira::http2::Connection;
using Mira::http2::Headers;
using Mira::http2::Role;
using Mira::http2::Session;
namespace tcp = Mira::transport::tcp;

namespace {

template <typename Integer>
bool parse_number(std::string_view text, Integer& value) {
    if (text.empty()) {
        return false;
    }
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc{} && end == text.data() + text.size();
}

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()),
                                      text.size()};
}

/// Answer one request per stream, then reclaim it once it retires.
///
/// Two phases, because the session distinguishes them:
///
///   * Answer: a stream with received headers that nobody answered yet.
///     `respond` enforces the rest. Waiting for `remote_end` here would
///     refuse half-closed peers — a HEAD or GET whose END_STREAM rides the
///     HEADERS frame has `remote_end` and `closed` set in the same
///     callback, before this coroutine ever runs (which is also why
///     answering closed streams is skipped, not asserted).
///   * Reclaim: once the response has been delivered the session closes
///     the stream; `take_body` hands flow-control credit back and
///     `release` frees the id. Both refuse a live stream, so they happen
///     here, after `stream->closed` turns true — a later pump round, not
///     the same one that answered.
///
/// `answered_` guards the first phase against double answers;
/// `retiring_` guards the second against double release. The session
/// keeps a released id reserved, so a late DATA frame for a retired
/// stream cannot resurrect it.
Task<Result<void>> serve_requests(Session& session, std::vector<std::int32_t>& answered_,
                                  std::vector<std::int32_t>& retiring_) {
    // Phase 2: reap what has finished.
    for (std::size_t i = 0; i < retiring_.size();) {
        const std::int32_t id = retiring_[i];
        const Mira::http2::Stream* stream = session.stream(id);
        if (stream == nullptr || !stream->closed) {
            ++i;
            continue;
        }
        const Result<std::vector<std::byte>> consumed = session.take_body(id);
        if (!consumed) {
            co_return Mira::fail(consumed.error());
        }
        const Result<void> released = session.release(id);
        if (!released) {
            co_return released;
        }
        retiring_.erase(retiring_.begin() + static_cast<std::ptrdiff_t>(i));
    }

    // Phase 1: answer what has arrived.
    const auto ids = session.streams();
    for (const std::int32_t id : ids) {
        if (std::find(answered_.begin(), answered_.end(), id) != answered_.end()) {
            continue;
        }
        const Mira::http2::Stream* stream = session.stream(id);
        if (stream == nullptr || !stream->headers_received || stream->closed) {
            continue;
        }

        Headers headers;
        headers.emplace_back(":status", "200");
        headers.emplace_back("content-type", "text/plain");
        std::string body{"served by Mira's HTTP/2 server, stream "};
        body += std::to_string(id);
        const Result<void> sent = session.respond(id, headers, bytes_of(body));
        if (!sent) {
            co_return sent;
        }
        answered_.push_back(id);
        retiring_.push_back(id);
    }
    co_return Result<void>{};
}

/// Drive one connection: greet, then bounded rounds of pump-and-answer.
Task<void> serve_one(tcp::Socket socket) {
    Result<Session> created = Session::create(Role::server);
    if (!created) {
        std::fprintf(stderr, "session: %s\n", created.error().message().c_str());
        co_return;
    }
    Session session = std::move(*created);
    Connection connection{socket, std::move(session)};
    std::vector<std::int32_t> answered;
    std::vector<std::int32_t> retiring;

    // The connection preface (client magic + SETTINGS) arrives as ordinary
    // input; the server preface goes out with the first flush. Pump until
    // the session retires or the peer hangs up.
    for (;;) {
        const Result<void> pumped = co_await connection.pump();
        if (!pumped) {
            if (pumped.error() != Mira::Errc::eof) {
                std::fprintf(stderr, "h2 connection ended: %s\n",
                             pumped.error().message().c_str());
            }
            break;
        }
        const Result<void> replied =
            co_await serve_requests(connection.session(), answered, retiring);
        if (!replied) {
            std::fprintf(stderr, "h2 respond: %s\n", replied.error().message().c_str());
            break;
        }
        if (connection.session().state() == Mira::http2::State::closed ||
            connection.session().state() == Mira::http2::State::failed) {
            break;
        }
    }
}

Task<void> serve(tcp::Listener& listener) {
    TaskScope scope;

    for (;;) {
        Result<tcp::Socket> accepted = co_await listener.accept();
        if (!accepted) {
            std::fprintf(stderr, "accept: %s\n", accepted.error().message().c_str());
            scope.request_stop();
            break;
        }
        tcp::Socket socket = std::move(*accepted);
        scope.spawn(serve_one(std::move(socket)));
    }
    co_await scope.join();
}

}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    if (argc > 2 || (argc > 1 && !parse_number(argv[1], port))) {
        std::fprintf(stderr, "usage: %s [port: 0..65535]\n", argv[0]);
        return 2;
    }

#ifdef SIGPIPE
    if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        std::fprintf(stderr, "could not ignore SIGPIPE\n");
        return 1;
    }
#endif

    Result<EventLoop> created = EventLoop::create();
    if (!created) {
        std::fprintf(stderr, "event loop: %s\n", created.error().message().c_str());
        return 1;
    }
    EventLoop& loop = created.value();

    Result<tcp::Listener> listener =
        tcp::Listener::bind(loop, Mira::transport::Endpoint::loopback(port));
    if (!listener) {
        std::fprintf(stderr, "bind: %s\n", listener.error().message().c_str());
        return 1;
    }

    std::printf("h2 prior-knowledge server listening on %s\n",
                listener->local_endpoint().to_string().c_str());
    std::fflush(stdout);

    const Result<void> ran = loop.run_until_complete(serve(*listener));
    if (!ran) {
        std::fprintf(stderr, "run: %s\n", ran.error().message().c_str());
        return 1;
    }
    return 0;
}