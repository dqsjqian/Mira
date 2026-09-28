#include "mira/http2/session.hpp"
#include "mira/http2/connection.hpp"
#include "mira/core/event_loop.hpp"
#include "check.hpp"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

using namespace Mira;
using namespace Mira::http2;

Headers request_headers(std::string method = "GET") {
    return {{":method", std::move(method)}, {":scheme", "https"}, {":authority", "localhost"}, {":path", "/"}};
}
std::span<const std::byte> bytes(const std::string& s) { return std::as_bytes(std::span(s)); }
Session make_session(Role role, Limits limits = {}) {
    auto result = Session::create(role, limits);
    CHECK(result.has_value());
    return std::move(*result);
}
bool transfer(Session& from, Session& to, std::size_t fragment = 7) {
    if (!from.wants_write()) return false;
    auto out = from.output();
    CHECK(out.has_value());
    if (!out || out->empty()) return false;
    CHECK(out->size() <= 64 * 1024);
    for (std::size_t i = 0; i < out->size(); i += fragment) {
        auto result = to.receive(std::span(*out).subspan(i, std::min(fragment, out->size() - i)));
        CHECK(result.has_value());
        if (!result) return false;
    }
    return true;
}
void exchange(Session& client, Session& server, std::size_t fragment = 7) {
    for (int i = 0; i < 1000; ++i) {
        bool a = transfer(client, server, fragment);
        bool b = transfer(server, client, fragment);
        if (!a && !b) return;
    }
    CHECK(false);
}

void multiplex_and_cancel() {
    auto client = make_session(Role::client);
    auto server = make_session(Role::server);
    std::string upload(40000, 'x');
    upload[5] = '\0';
    auto first = client.request(request_headers("POST"), bytes(upload));
    auto cancelled = client.request(request_headers());
    auto third = client.request(request_headers("HEAD"));
    CHECK(first.has_value() && cancelled.has_value() && third.has_value());
    CHECK(*first == 1 && *cancelled == 3 && *third == 5);
    exchange(client, server);
    CHECK(server.stream(*first)->remote_end);
    auto uploaded = server.take_body(*first);
    CHECK(uploaded && *uploaded == std::vector<std::byte>(bytes(upload).begin(), bytes(upload).end()));
    CHECK(client.cancel(*cancelled).has_value());
    exchange(client, server);
    CHECK(client.stream(*cancelled)->error == Errc::cancelled);
    CHECK(server.stream(*cancelled)->error == Errc::cancelled);
    std::string reply = "multiplexed";
    CHECK(server.respond(*third, {{":status", "200"}}, bytes(reply)).has_value());
    CHECK(server.respond(*first, {{":status", "201"}}, bytes(reply)).has_value());
    exchange(client, server, 1);
    CHECK(client.stream(*first)->closed && client.stream(*first)->remote_end);
    CHECK(!client.stream(*first)->error);
    CHECK(client.stream(*third)->body.empty());
    CHECK(client.stream(*third)->closed);
    auto response = client.take_body(*first);
    CHECK(response && *response == std::vector<std::byte>(bytes(reply).begin(), bytes(reply).end()));
    CHECK(!server.respond(*first, {{":status", "200"}}));
    CHECK(client.release(*cancelled).has_value());
    CHECK(client.stream(*cancelled) == nullptr);
    CHECK(server.goaway().has_value());
    exchange(client, server);
    CHECK(client.state() == State::draining || client.state() == State::closed);
    CHECK(client.peer_last_stream_id() == *third);
    CHECK(!client.request(request_headers()));
}

void flow_control_and_bounds() {
    Limits limits;
    limits.max_output_bytes = 16393;
    limits.max_streams = 2;
    auto client = make_session(Role::client, limits);
    auto server = make_session(Role::server, limits);
    const std::string payload(150000, 'p');
    auto id = client.request(request_headers("POST"), bytes(payload));
    CHECK(id.has_value());
    exchange(client, server, 4096);
    CHECK(!server.stream(*id)->remote_end);
    CHECK(server.stream(*id)->body.size() <= 65535);
    std::size_t received = 0;
    for (int i = 0; i < 10 && !server.stream(*id)->remote_end; ++i) {
        auto piece = server.take_body(*id);
        CHECK(piece.has_value());
        received += piece->size();
        exchange(client, server, 4096);
    }
    auto last = server.take_body(*id);
    CHECK(last.has_value());
    received += last->size();
    CHECK(received == payload.size());
    CHECK(server.stream(*id)->remote_end);
    auto second = client.request(request_headers());
    CHECK(second.has_value());
    CHECK(!client.request(request_headers()));
    CHECK(!client.release(*id));
    CHECK(server.respond(*id, {{":status", "200"}}, bytes(payload)).has_value());
    exchange(client, server, 4096);
    CHECK(!client.stream(*id)->remote_end);
    for (int i = 0; i < 10 && !client.stream(*id)->remote_end; ++i) {
        CHECK(client.take_body(*id).has_value());
        exchange(client, server, 4096);
    }
    CHECK(client.stream(*id)->remote_end);
    CHECK(client.release(*id).has_value());
    CHECK(client.request(request_headers()).has_value());

    Limits tiny;
    tiny.max_body_bytes = 32;
    auto c = make_session(Role::client);
    auto s = make_session(Role::server, tiny);
    auto big = c.request(request_headers("POST"), bytes(std::string(100, 'a')));
    auto good = c.request(request_headers());
    exchange(c, s);
    CHECK(s.stream(*big)->error == Errc::limit_exceeded);
    CHECK(c.stream(*big)->closed);
    CHECK(s.respond(*good, {{":status", "204"}}).has_value());
    exchange(c, s);
    CHECK(c.stream(*good)->closed && !c.stream(*good)->error);

    tiny.max_queued_body_bytes = 10;
    auto bounded = make_session(Role::client, tiny);
    CHECK(!bounded.request(request_headers("POST"), bytes(std::string(11, 'b'))));
}

void streaming_bodies() {
    Limits limits;
    limits.max_queued_body_bytes = 1024;
    auto client = make_session(Role::client, limits);
    auto server = make_session(Role::server, limits);
    auto headers = request_headers("POST");
    headers.push_back({"content-length", "131072"});
    auto id = client.request_stream(headers);
    auto other = client.request_stream(request_headers("POST"));
    CHECK(id && other);
    exchange(client, server);
    CHECK(!server.stream(*id)->remote_end && !server.stream(*other)->remote_end);
    CHECK(!client.wants_write());
    const std::string chunk(1024, 's');
    auto oversized = client.write_body(*id, bytes(std::string(1025, 's')));
    CHECK(!oversized && oversized.error() == Errc::would_block);
    CHECK(client.queued_body_bytes() == 0);
    std::size_t received = 0;
    for (int i = 0; i < 128; ++i) {
        CHECK(client.write_body(*id, bytes(chunk)).has_value());
        CHECK(client.queued_body_bytes() == 1024);
        auto blocked = client.write_body(*other, bytes("x"));
        CHECK(!blocked && blocked.error() == Errc::would_block);
        CHECK(client.state() == State::open);
        exchange(client, server, 4096);
        auto piece = server.take_body(*id);
        CHECK(piece && piece->size() == chunk.size());
        CHECK(std::equal(piece->begin(), piece->end(), bytes(chunk).begin()));
        received += piece->size();
        CHECK(client.queued_body_bytes() == 0);
        CHECK(client.write_body(*other, bytes("x")).has_value());
        exchange(client, server);
        auto small = server.take_body(*other);
        CHECK(small && small->size() == 1);
        CHECK(!server.stream(*id)->remote_end);
    }
    CHECK(received == 131072);
    CHECK(!client.write_body(*id, bytes("extra")));
    CHECK(client.finish_body(*id).has_value());
    CHECK(!client.finish_body(*id));
    CHECK(!client.write_body(*id, bytes("late")));
    CHECK(client.finish_body(*other).has_value());
    exchange(client, server);
    CHECK(server.stream(*id)->remote_end && server.stream(*other)->remote_end);
    CHECK(server.respond_stream(*id, {{":status", "200"}}).has_value());
    CHECK(server.respond(*other, {{":status", "204"}}).has_value());
    exchange(client, server);
    CHECK(!client.stream(*id)->remote_end && client.stream(*other)->remote_end);
    for (int i = 0; i < 128; ++i) {
        CHECK(server.write_body(*id, bytes(chunk), i == 127).has_value());
        exchange(client, server, 4096);
        auto piece = client.take_body(*id);
        CHECK(piece && piece->size() == chunk.size());
        CHECK(server.queued_body_bytes() == 0);
    }
    CHECK(client.stream(*id)->remote_end);
    auto empty = client.request_stream(request_headers("POST"));
    CHECK(empty && client.finish_body(*empty));
    auto cancelled = client.request_stream(request_headers("POST"));
    CHECK(cancelled && client.write_body(*cancelled, bytes(chunk)));
    CHECK(client.cancel(*cancelled).has_value());
    CHECK(client.queued_body_bytes() == 0);
    CHECK(!client.write_body(*cancelled, bytes("late")));
    exchange(client, server);
    CHECK(server.stream(*empty)->remote_end);
    CHECK(server.respond_stream(*empty, {{":status", "200"}}).has_value());
    exchange(client, server);
    CHECK(server.finish_body(*empty).has_value());
    exchange(client, server);
    CHECK(client.stream(*empty)->remote_end);
    auto exact = request_headers("POST");
    exact.push_back({"content-length", "3"});
    auto mismatch = client.request_stream(exact);
    CHECK(mismatch && !client.finish_body(*mismatch));
    CHECK(client.write_body(*mismatch, bytes("abc"), true).has_value());
    CHECK(client.state() == State::open);
    auto head = client.request(request_headers("HEAD"));
    CHECK(head.has_value());
    exchange(client, server);
    CHECK(server.respond_stream(*head, {{":status", "200"}, {"content-length", "9"}}).has_value());
    CHECK(!server.write_body(*head, bytes("forbidden")));
    CHECK(server.finish_body(*head).has_value());
    exchange(client, server);
    CHECK(client.stream(*head)->remote_end && !client.stream(*head)->error);
    CHECK(client.stream(*head)->body.empty());
}

void queued_cancel_and_close() {
    auto client = make_session(Role::client);
    auto server = make_session(Role::server);
    auto owned_output = client.output();
    CHECK(owned_output.has_value());
    const auto snapshot = *owned_output;
    CHECK(server.receive(*owned_output).has_value());
    auto settings = server.output();
    CHECK(settings.has_value());
    CHECK(client.receive(*settings).has_value());
    CHECK(client.output().has_value());
    CHECK(*owned_output == snapshot);
    auto cancelled = client.request(request_headers("POST"), bytes(std::string(10000, 'z')));
    CHECK(cancelled.has_value());
    CHECK(client.cancel(*cancelled).has_value());
    auto live = client.request(request_headers());
    CHECK(live.has_value());
    exchange(client, server);
    CHECK(client.stream(*cancelled)->closed);
    CHECK(client.release(*cancelled).has_value());
    CHECK(server.stream(*live)->remote_end);
    CHECK(server.respond(*live, {{":status", "200"}}).has_value());
    exchange(client, server);
    CHECK(client.stream(*live)->closed && !client.stream(*live)->error);
    auto unfinished = client.request(request_headers("POST"), bytes(std::string(10000, 'z')));
    CHECK(unfinished.has_value());
    client.close(make_error_code(Errc::timed_out));
    CHECK(client.stream(*unfinished)->error == Errc::timed_out);
    CHECK(client.release(*unfinished).has_value());
    CHECK(!client.output());
}

void header_validation() {
    auto client = make_session(Role::client);
    auto bad = request_headers();
    bad.push_back({":method", "GET"});
    CHECK(!client.request(bad));
    bad = request_headers(); bad.push_back({"Connection", "close"}); CHECK(!client.request(bad));
    bad = request_headers(); bad.push_back({"connection", "close"}); CHECK(!client.request(bad));
    bad = request_headers(); bad.push_back({"x-test", "bad\r\nvalue"}); CHECK(!client.request(bad));
    bad = request_headers(); bad.push_back({"te", "gzip"}); CHECK(!client.request(bad));
    bad = request_headers(); bad.push_back({"content-length", "9"}); CHECK(!client.request(bad));
    CHECK(!client.request(request_headers("CONNECT")));
    bad = request_headers(); std::swap(bad[0], bad[3]); bad.insert(bad.begin(), {"x-test", "v"});
    CHECK(!client.request(bad));
    Limits tiny; tiny.max_header_bytes = 80;
    auto server = make_session(Role::server, tiny);
    bad = request_headers(); bad.push_back({"x-long", std::string(100, 'a')});
    auto id = client.request(bad);
    CHECK(id.has_value());
    exchange(client, server);
    CHECK(server.stream(*id)->error == Errc::limit_exceeded);
    CHECK(client.stream(*id)->closed);
    auto invalid = Session::create(Role::client, Limits{.max_streams = 0});
    CHECK(!invalid);
}

std::vector<std::byte> raw_frame(std::uint8_t type, std::uint8_t flags, std::int32_t id,
                                 std::span<const std::byte> payload = {}) {
    std::vector<std::byte> wire(9);
    const auto size = payload.size();
    wire[0] = std::byte((size >> 16) & 255); wire[1] = std::byte((size >> 8) & 255);
    wire[2] = std::byte(size & 255); wire[3] = std::byte(type); wire[4] = std::byte(flags);
    const auto stream = static_cast<std::uint32_t>(id);
    for (unsigned i = 0; i < 4; ++i) wire[5 + i] = std::byte((stream >> (24 - i * 8)) & 255);
    wire.insert(wire.end(), payload.begin(), payload.end());
    return wire;
}
std::vector<std::byte> header_frame(Headers headers) {
    nghttp2_hd_deflater* deflater = nullptr;
    CHECK(nghttp2_hd_deflate_new(&deflater, 4096) == 0);
    std::vector<nghttp2_nv> nv;
    for (auto& h : headers) nv.push_back({reinterpret_cast<std::uint8_t*>(h.name.data()),
        reinterpret_cast<std::uint8_t*>(h.value.data()), h.name.size(), h.value.size(), NGHTTP2_NV_FLAG_NONE});
    std::vector<std::byte> encoded(nghttp2_hd_deflate_bound(deflater, nv.data(), nv.size()));
    auto n = nghttp2_hd_deflate_hd2(deflater, reinterpret_cast<std::uint8_t*>(encoded.data()),
                                    encoded.size(), nv.data(), nv.size());
    CHECK(n >= 0);
    encoded.resize(static_cast<std::size_t>(n));
    nghttp2_hd_deflate_del(deflater);
    return raw_frame(NGHTTP2_HEADERS, NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM, 1, encoded);
}
void wire_negative_cases() {
    for (int mutation = 0; mutation < 3; ++mutation) {
        auto client = make_session(Role::client);
        auto server = make_session(Role::server);
        exchange(client, server);
        auto headers = request_headers();
        if (mutation == 0) headers.push_back({":path", "/duplicate"});
        if (mutation == 1) { headers.push_back({"x-normal", "v"}); headers.push_back({":method", "GET"}); }
        if (mutation == 2) headers.push_back({"connection", "close"});
        CHECK(server.receive(header_frame(headers)).has_value());
        auto wire = server.output();
        CHECK(wire && !wire->empty());
        const auto* stream = server.stream(1);
        CHECK(stream && stream->closed && stream->error);
    }
    auto client = make_session(Role::client);
    auto server = make_session(Role::server);
    exchange(client, server);
    CHECK(server.receive(raw_frame(NGHTTP2_SETTINGS, 0, 1)).has_value());
    auto out = server.output();
    CHECK(out && !out->empty());
    CHECK(server.state() != State::open);
    CHECK(static_cast<bool>(server.error()));

    auto bad_preface = make_session(Role::server);
    auto invalid = bad_preface.receive(bytes(std::string(24, '!')));
    CHECK(!invalid && bad_preface.state() == State::failed);
    CHECK(!bad_preface.output());

    Limits tiny; tiny.max_queued_frames = 4;
    auto bounded = make_session(Role::server, tiny);
    auto c = make_session(Role::client);
    exchange(c, bounded);
    std::vector<std::byte> payload(8);
    bool rejected = false;
    for (int i = 0; i < 20; ++i) {
        if (!bounded.receive(raw_frame(NGHTTP2_PING, 0, 0, payload))) { rejected = true; break; }
    }
    CHECK(rejected && bounded.state() == State::failed);
}

struct MemoryStream {
    Session* peer;
    std::vector<std::byte> pending;
    std::size_t read_at = 0;
    int writes = 0;
    OperationOptions seen;
    Task<Result<std::size_t>> write_some(std::span<const std::byte> source, OperationOptions options = {}) {
        seen = options;
        if (options.stop.stop_requested()) co_return fail(Errc::cancelled);
        const auto n = std::min<std::size_t>(3, source.size());
        auto result = peer->receive(source.first(n));
        if (!result) co_return fail(result.error());
        ++writes;
        co_return n;
    }
    Task<Result<std::size_t>> read_some(std::span<std::byte> destination, OperationOptions options = {}) {
        seen = options;
        if (options.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (read_at == pending.size()) {
            auto out = peer->output();
            if (!out) co_return fail(out.error());
            pending = std::move(*out);
            read_at = 0;
        }
        const auto n = std::min({destination.size(), pending.size() - read_at, std::size_t{5}});
        if (!n) co_return fail(Errc::eof);
        std::copy_n(pending.data() + read_at, n, destination.data());
        read_at += n;
        co_return n;
    }
};
static_assert(BoundedStream<MemoryStream>);
Task<void> adapter_case() {
    auto server = make_session(Role::server);
    MemoryStream transport{&server, {}, 0, 0, {}};
    Connection connection(transport, make_session(Role::client));
    const auto id = connection.session().request(request_headers());
    CHECK(id.has_value());
    OperationOptions options{.deadline = Clock::now() + std::chrono::seconds(5)};
    CHECK((co_await connection.flush(options)).has_value());
    CHECK(transport.writes > 1);
    CHECK(transport.seen.deadline == options.deadline);
    CHECK(server.stream(*id)->remote_end);
    std::string body = "adapter";
    CHECK(server.respond(*id, {{":status", "200"}}, bytes(body)).has_value());
    for (int i = 0; i < 100 && !connection.session().stream(*id)->closed; ++i) {
        CHECK((co_await connection.pump(options)).has_value());
    }
    CHECK(connection.session().stream(*id)->closed);
    CHECK(connection.session().stream(*id)->body.size() == body.size());
    std::stop_source stop;
    stop.request_stop();
    auto result = co_await connection.read(OperationOptions{.stop = stop.get_token()});
    CHECK(!result && result.error() == Errc::cancelled);
    CHECK(connection.session().state() == State::closed);
}

void shared_budget() {
    Limits limits;
    limits.max_streams = 2;
    limits.max_body_bytes = 1024;
    limits.max_header_bytes = 1024;
    const auto charge = limits.max_streams * (limits.max_body_bytes + 3 * limits.max_header_bytes) +
                        limits.max_output_bytes + limits.max_queued_body_bytes;
    ResourceBudget budget{charge};
    {
        auto session = Session::create(Role::client, limits, budget);
        CHECK(session.has_value());
        CHECK(budget.used() == charge);
        auto full = Session::create(Role::server, limits, budget);
        CHECK(!full && full.error() == Errc::would_block);
        CHECK(budget.used() == charge);
    }
    CHECK(budget.used() == 0);
    limits.max_body_bytes = std::numeric_limits<std::size_t>::max();
    auto overflow = Session::create(Role::client, limits, budget);
    CHECK(!overflow && overflow.error() == Errc::limit_exceeded);
    CHECK(budget.used() == 0);
}
int main() {
    shared_budget();
    streaming_bodies();
    multiplex_and_cancel();
    flow_control_and_bounds();
    queued_cancel_and_close();
    header_validation();
    wire_negative_cases();
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    CHECK(loop->run_until_complete(adapter_case()).has_value());
    return test::summary();
}
