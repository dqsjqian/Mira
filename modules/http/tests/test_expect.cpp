// Expect: 100-continue and early final responses over real TCP.
//
// The duplex client reads while it writes, so these run against real sockets:
// a scripted stream cannot show a response overtaking an upload.

#include "check.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/http/client.hpp"
#include "mira/http/connection.hpp"
#include "mira/transport/tcp.hpp"

#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#define CHECK_VALUE(expr) CHECK(static_cast<bool>(expr))

using namespace Mira;
using namespace Mira::http;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {

std::span<const std::byte> bytes(std::string_view text) {
    return std::as_bytes(std::span{text.data(), text.size()});
}

ClientOptions large() {
    ClientOptions options;
    options.limits.max_body_size = std::uint64_t{1} << 40;
    return options;
}

Request post(std::string_view target = "/upload") {
    Request request;
    request.method = Method::post;
    request.target = std::string{target};
    request.headers.append("Host", "localhost");
    return request;
}

/// Lazily produced body of `total` bytes in `chunk`-sized pieces.
struct Repeating {
    std::size_t total;
    std::size_t chunk;
    std::size_t produced = 0;
    std::size_t fail_after = static_cast<std::size_t>(-1);
    std::vector<std::byte> data = std::vector<std::byte>(chunk, std::byte{'x'});
    Task<Result<std::span<const std::byte>>> operator()() {
        if (produced >= fail_after) co_return fail(Errc::internal);
        const auto n = std::min(chunk, total - produced);
        produced += n;
        co_return std::span<const std::byte>{data}.first(n);
    }
};

/// Raw peer helpers: the server side of these tests is written byte by byte.
struct Raw {
    tcp::Socket socket;
    std::string input;

    Task<Result<std::string>> head() {
        for (;;) {
            if (const auto end = input.find("\r\n\r\n"); end != std::string::npos) {
                auto text = input.substr(0, end + 4);
                input.erase(0, end + 4);
                co_return text;
            }
            std::array<std::byte, 4096> buffer{};
            const auto n = co_await socket.read_some(buffer);
            if (!n) co_return fail(n.error());
            input.append(reinterpret_cast<const char*>(buffer.data()), *n);
        }
    }
    Task<Result<void>> exact(std::size_t count) {
        while (input.size() < count) {
            std::array<std::byte, 16384> buffer{};
            const auto n = co_await socket.read_some(buffer);
            if (!n) co_return fail(n.error());
            input.append(reinterpret_cast<const char*>(buffer.data()), *n);
        }
        input.erase(0, count);
        co_return Result<void>{};
    }
    /// Read until EOF or error, returning the byte count beyond `input`.
    Task<std::size_t> drain() {
        std::size_t total = input.size();
        input.clear();
        std::vector<std::byte> buffer(65536);
        for (;;) {
            const auto n = co_await socket.read_some(buffer);
            if (!n) co_return total;
            total += *n;
        }
    }
    Task<Result<void>> send(std::string_view text) {
        co_return co_await write_all(socket, bytes(text), OperationOptions{});
    }
};

struct Rig {
    EventLoop& loop;
    tcp::Listener listener;
    Endpoint where;

    static Result<Rig> create(EventLoop& loop) {
        auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
        if (!listener) return fail(listener.error());
        const auto where = listener->local_endpoint();
        return Rig{loop, std::move(*listener), where};
    }
    Task<Result<tcp::Socket>> dial() { co_return co_await tcp::connect(loop, where); }
};

Task<void> serializer_rules() {
    test::section("serializer owns Expect");
    Buffer out;
    auto request = post();
    const auto written = write_request_head(out, request, Framing::content_length, 5, {},
                                            Expectation::continue_100);
    CHECK_VALUE(written);
    const std::string head{reinterpret_cast<const char*>(out.readable().data()), out.readable().size()};
    CHECK(head.find("Expect: 100-continue\r\n") != std::string::npos);
    CHECK(head.ends_with("Content-Length: 5\r\n\r\n"));
    Buffer zero;
    const auto empty = write_request_head(zero, request, Framing::content_length, 0, {},
                                          Expectation::continue_100);
    CHECK(!empty && empty.error() == Errc::invalid_argument);
    Buffer chunked;
    CHECK_VALUE(write_request_head(chunked, request, Framing::chunked, 0, {},
                                   Expectation::continue_100));
    auto old = post();
    old.version = Version::http_1_0;
    Buffer legacy;
    const auto rejected = write_request_head(legacy, old, Framing::content_length, 5, {},
                                             Expectation::continue_100);
    CHECK(!rejected && rejected.error() == Errc::not_supported);
    auto manual = post();
    manual.headers.append("Expect", "100-continue");
    Buffer caller;
    CHECK(!write_request_head(caller, manual, Framing::content_length, 5));
    co_return;
}

Task<void> expect_continue_granted(EventLoop& loop) {
    test::section("100 Continue gates the body");
    auto rig = Rig::create(loop);
    CHECK_VALUE(rig);
    bool early_bytes = true;
    std::string saw_head;
    TaskScope scope;
    auto server = [&]() -> Task<void> {
        auto accepted = co_await rig->listener.accept();
        if (!accepted) co_return;
        Raw raw{std::move(*accepted), {}};
        auto head = co_await raw.head();
        if (!head) co_return;
        saw_head = *head;
        early_bytes = !raw.input.empty();
        static_cast<void>(co_await raw.send("HTTP/1.1 100 Continue\r\n\r\n"));
        static_cast<void>(co_await raw.exact(10));
        static_cast<void>(co_await raw.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
        static_cast<void>(co_await raw.drain());
    };
    scope.spawn(server());
    auto socket = co_await rig->dial();
    CHECK_VALUE(socket);
    if (socket) {
        ClientConnection client{*socket};
        const auto started = Clock::now();
        const auto result = co_await client.exchange(
            loop, post(), bytes("0123456789"),
            {.expect_continue = true, .continue_timeout = 10s}, {.deadline = Clock::now() + 20s});
        CHECK_VALUE(result);
        if (result) {
            CHECK(result->continued);
            CHECK(result->upload == UploadOutcome::complete);
            CHECK(result->body_sent == 10);
        }
        CHECK(Clock::now() - started < 5s);
        CHECK(client.response().status == 200);
        const auto body = co_await client.read_body();
        CHECK(body && body->size() == 2);
        const auto end = co_await client.read_body();
        CHECK(end && end->empty());
        CHECK(client.reusable());
        socket->close();
    }
    co_await scope.join();
    CHECK(saw_head.find("Expect: 100-continue\r\n") != std::string::npos);
    CHECK(!early_bytes);
}

Task<void> expect_refused(EventLoop& loop) {
    test::section("final response before 100 skips the body");
    auto rig = Rig::create(loop);
    CHECK_VALUE(rig);
    std::size_t body_bytes = 99;
    TaskScope scope;
    auto server = [&]() -> Task<void> {
        auto accepted = co_await rig->listener.accept();
        if (!accepted) co_return;
        Raw raw{std::move(*accepted), {}};
        if (!(co_await raw.head())) co_return;
        static_cast<void>(
            co_await raw.send("HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n"));
        body_bytes = co_await raw.drain();
    };
    scope.spawn(server());
    auto socket = co_await rig->dial();
    CHECK_VALUE(socket);
    if (socket) {
        ClientConnection client{*socket};
        Repeating source{1 << 20, 4096};
        const auto result = co_await client.exchange(
            loop, post(), Framing::content_length, source.total, source,
            {.expect_continue = true, .continue_timeout = 10s}, {.deadline = Clock::now() + 20s});
        CHECK_VALUE(result);
        if (result) {
            CHECK(result->upload == UploadOutcome::skipped);
            CHECK(result->body_sent == 0);
            CHECK(!result->continued);
        }
        CHECK(client.response().status == 417);
        const auto end = co_await client.read_body();
        CHECK(end && end->empty());
        CHECK(!client.reusable());
        socket->close();
    }
    co_await scope.join();
    CHECK(body_bytes == 0);
}

Task<void> expect_timeout(EventLoop& loop) {
    test::section("silent server: continue_timeout sends anyway");
    auto rig = Rig::create(loop);
    CHECK_VALUE(rig);
    TaskScope scope;
    auto server = [&]() -> Task<void> {
        auto accepted = co_await rig->listener.accept();
        if (!accepted) co_return;
        Raw raw{std::move(*accepted), {}};
        if (!(co_await raw.head())) co_return;
        static_cast<void>(co_await raw.exact(3));
        static_cast<void>(co_await raw.send("HTTP/1.1 204 No Content\r\n\r\n"));
        static_cast<void>(co_await raw.drain());
    };
    scope.spawn(server());
    auto socket = co_await rig->dial();
    CHECK_VALUE(socket);
    if (socket) {
        ClientConnection client{*socket};
        const auto started = Clock::now();
        const auto result = co_await client.exchange(
            loop, post(), bytes("abc"), {.expect_continue = true, .continue_timeout = 150ms},
            {.deadline = Clock::now() + 20s});
        const auto elapsed = Clock::now() - started;
        CHECK_VALUE(result);
        if (result) {
            CHECK(!result->continued);
            CHECK(result->upload == UploadOutcome::complete);
        }
        CHECK(elapsed >= 140ms);
        CHECK(client.response().status == 204);
        const auto end = co_await client.read_body();
        CHECK(end && end->empty());
        CHECK(client.reusable());
        socket->close();
    }
    co_await scope.join();
}

Task<void> early_refusal(EventLoop& loop) {
    test::section("early 413 interrupts a streaming upload");
    constexpr std::size_t total = 64u << 20;
    for (const bool duplex : {false, true}) {
        auto rig = Rig::create(loop);
        CHECK_VALUE(rig);
        std::size_t server_received = 0;
        TaskScope scope;
        auto server = [&]() -> Task<void> {
            auto accepted = co_await rig->listener.accept();
            if (!accepted) co_return;
            Raw raw{std::move(*accepted), {}};
            if (!(co_await raw.head())) co_return;
            static_cast<void>(co_await raw.send(
                "HTTP/1.1 413 Content Too Large\r\nConnection: close\r\nContent-Length: 4\r\n\r\nbig!"));
            static_cast<void>(raw.socket.shutdown_send());
            // Lingering close: keep reading so the refusal is not reset away.
            server_received = co_await raw.drain();
        };
        scope.spawn(server());
        auto socket = co_await rig->dial();
        CHECK_VALUE(socket);
        if (socket) {
            ClientConnection client{*socket, large()};
            Repeating source{total, 64 * 1024};
            const OperationOptions io{.deadline = Clock::now() + 60s};
            if (duplex) {
                const auto result = co_await client.exchange(loop, post(), Framing::chunked, 0,
                                                             source, {}, io);
                CHECK_VALUE(result);
                if (result) {
                    CHECK(result->upload == UploadOutcome::interrupted);
                    CHECK(result->body_sent < total);
                }
            } else {
                // Send-first baseline: the refusal is only seen after every byte went out.
                auto begun = co_await client.begin(post(), Framing::chunked, 0, io);
                CHECK_VALUE(begun);
                while (begun && source.produced < total) {
                    auto chunk = co_await source();
                    begun = co_await client.send_body(*chunk);
                }
                CHECK_VALUE(begun);
                const auto finished = co_await client.finish();
                CHECK_VALUE(finished);
                CHECK(source.produced == total);
            }
            CHECK(client.response().status == 413);
            const auto body = co_await client.read_body();
            CHECK(body && body->size() == 4);
            const auto end = co_await client.read_body();
            CHECK(end && end->empty());
            CHECK(!client.reusable());
            socket->close();
        }
        co_await scope.join();
        if (duplex) CHECK(server_received < total);
        else CHECK(server_received > total);
    }
}

Task<void> early_success_continues(EventLoop& loop) {
    test::section("early 2xx keep-alive lets the upload finish");
    constexpr std::size_t total = 1u << 20;
    auto rig = Rig::create(loop);
    CHECK_VALUE(rig);
    bool second_seen = false;
    TaskScope scope;
    auto server = [&]() -> Task<void> {
        auto accepted = co_await rig->listener.accept();
        if (!accepted) co_return;
        Raw raw{std::move(*accepted), {}};
        if (!(co_await raw.head())) co_return;
        static_cast<void>(co_await raw.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
        if (!(co_await raw.exact(total))) co_return;
        auto next = co_await raw.head();
        second_seen = next && next->starts_with("GET /again ");
        static_cast<void>(co_await raw.send("HTTP/1.1 204 No Content\r\n\r\n"));
        static_cast<void>(co_await raw.drain());
    };
    scope.spawn(server());
    auto socket = co_await rig->dial();
    CHECK_VALUE(socket);
    if (socket) {
        ClientConnection client{*socket};
        Repeating source{total, 32 * 1024};
        const auto result = co_await client.exchange(loop, post(), Framing::content_length, total,
                                                     source, {}, {.deadline = Clock::now() + 20s});
        CHECK_VALUE(result);
        if (result) {
            CHECK(result->upload == UploadOutcome::complete);
            CHECK(result->body_sent == total);
        }
        const auto body = co_await client.read_body();
        CHECK(body && body->size() == 2);
        const auto end = co_await client.read_body();
        CHECK(end && end->empty());
        CHECK(client.reusable());
        Request again;
        again.target = "/again";
        again.headers.append("Host", "localhost");
        const auto second = co_await client.start(again);
        CHECK_VALUE(second);
        CHECK(client.response().status == 204);
        const auto done = co_await client.read_body();
        CHECK(done && done->empty());
        socket->close();
    }
    co_await scope.join();
    CHECK(second_seen);
}

Task<void> leg_failures(EventLoop& loop) {
    test::section("a failed leg cancels the other");
    {
        auto rig = Rig::create(loop);
        CHECK_VALUE(rig);
        bool client_done = false;
        TaskScope scope;
        auto server = [&]() -> Task<void> {
            auto accepted = co_await rig->listener.accept();
            if (!accepted) co_return;
            Raw raw{std::move(*accepted), {}};
            if (!(co_await raw.head())) co_return;
            static_cast<void>(co_await raw.send("garbage\r\n\r\n"));
            // Never read: the writer can only finish by being cancelled.
            while (!client_done) static_cast<void>(co_await loop.sleep_for(10ms));
        };
        scope.spawn(server());
        auto socket = co_await rig->dial();
        CHECK_VALUE(socket);
        if (socket) {
            ClientConnection client{*socket, large()};
            Repeating source{256u << 20, 64 * 1024};
            const auto started = Clock::now();
            const auto result = co_await client.exchange(loop, post(), Framing::chunked, 0, source,
                                                         {}, {.deadline = Clock::now() + 30s});
            CHECK(!result);
            CHECK(Clock::now() - started < 10s);
            CHECK(!client.reusable());
            socket->close();
        }
        client_done = true;
        co_await scope.join();
    }
    {
        auto rig = Rig::create(loop);
        CHECK_VALUE(rig);
        TaskScope scope;
        auto server = [&]() -> Task<void> {
            auto accepted = co_await rig->listener.accept();
            if (!accepted) co_return;
            Raw raw{std::move(*accepted), {}};
            static_cast<void>(co_await raw.drain());
        };
        scope.spawn(server());
        auto socket = co_await rig->dial();
        CHECK_VALUE(socket);
        if (socket) {
            ClientConnection client{*socket};
            Repeating source{1 << 20, 1024};
            source.fail_after = 4096;
            const auto result = co_await client.exchange(loop, post(), Framing::chunked, 0, source,
                                                         {}, {.deadline = Clock::now() + 30s});
            CHECK(!result && result.error() == Errc::internal);
            CHECK(!client.reusable());
            socket->close();
        }
        co_await scope.join();
    }
    {
        auto rig = Rig::create(loop);
        CHECK_VALUE(rig);
        TaskScope scope;
        std::stop_source stop;
        auto server = [&]() -> Task<void> {
            auto accepted = co_await rig->listener.accept();
            if (!accepted) co_return;
            Raw raw{std::move(*accepted), {}};
            if (!(co_await raw.head())) co_return;
            stop.request_stop();
            static_cast<void>(co_await raw.drain());
        };
        scope.spawn(server());
        auto socket = co_await rig->dial();
        CHECK_VALUE(socket);
        if (socket) {
            ClientConnection client{*socket};
            const auto started = Clock::now();
            const auto result = co_await client.exchange(
                loop, post(), bytes("abc"), {.expect_continue = true, .continue_timeout = 20s},
                {.stop = stop.get_token(), .deadline = Clock::now() + 30s});
            CHECK(!result && result.error() == Errc::cancelled);
            CHECK(Clock::now() - started < 10s);
            socket->close();
        }
        co_await scope.join();
    }
    {
        auto rig = Rig::create(loop);
        CHECK_VALUE(rig);
        auto socket = co_await rig->dial();
        CHECK_VALUE(socket);
        if (socket) {
            ClientConnection client{*socket};
            const auto bad = co_await client.exchange(
                loop, post(), bytes("abc"), {.expect_continue = true, .continue_timeout = 0s});
            CHECK(!bad && bad.error() == Errc::invalid_argument);
            CHECK(client.reusable());
            socket->close();
        }
    }
}

/// Mira server + Mira duplex client.
Task<void> server_expectations(EventLoop& loop) {
    test::section("serve_connection answers 100-continue");
    for (const int mode : {0, 1, 2}) {
        // 0: buffered handler; 1: streaming handler that reads; 2: streaming refusal.
        auto rig = Rig::create(loop);
        CHECK_VALUE(rig);
        Result<void> served = fail(Errc::internal);
        std::size_t handler_body = 0;
        TaskScope scope;
        auto buffered = [&](const Request&, auto& writer,
                            std::span<const std::byte> body) -> Task<Result<void>> {
            handler_body = body.size();
            Response response;
            response.status = 200;
            co_return co_await writer.send(response, bytes("done"));
        };
        auto streaming = [&](const Request&, auto& writer, auto& reader) -> Task<Result<void>> {
            Response response;
            if (mode == 2) {
                response.status = 413;
                co_return co_await writer.send(response);
            }
            auto body = co_await reader.read_all();
            if (!body) co_return fail(body.error());
            handler_body = body->size();
            response.status = 200;
            co_return co_await writer.send(response, bytes("done"));
        };
        auto server = [&]() -> Task<void> {
            auto accepted = co_await rig->listener.accept();
            if (!accepted) co_return;
            tcp::Socket peer = std::move(*accepted);
            ServerOptions options;
            options.limits.max_body_size = 4u << 20;
            if (mode == 0) served = co_await serve_connection(peer, buffered, options);
            else served = co_await serve_connection(peer, streaming, options);
        };
        scope.spawn(server());
        auto socket = co_await rig->dial();
        CHECK_VALUE(socket);
        if (socket) {
            ClientConnection client{*socket};
            Repeating source{1u << 20, 16 * 1024};
            const auto started = Clock::now();
            const auto result = co_await client.exchange(
                loop, post(), Framing::content_length, source.total, source,
                {.expect_continue = true, .continue_timeout = 10s}, {.deadline = Clock::now() + 20s});
            CHECK_VALUE(result);
            CHECK(Clock::now() - started < 5s);
            if (result && mode < 2) {
                CHECK(result->continued);
                CHECK(result->upload == UploadOutcome::complete);
                CHECK(client.response().status == 200);
            } else if (result) {
                CHECK(!result->continued);
                CHECK(result->upload == UploadOutcome::skipped);
                CHECK(result->body_sent == 0);
                CHECK(client.response().status == 413);
                CHECK(client.response().headers.get("Connection") == std::optional<std::string_view>{"close"});
            }
            for (;;) {
                const auto piece = co_await client.read_body();
                if (!piece || piece->empty()) break;
            }
            CHECK(client.reusable() == (mode < 2));
            socket->close();
        }
        co_await scope.join();
        CHECK_VALUE(served);
        CHECK(handler_body == (mode < 2 ? (1u << 20) : 0u));
    }

    test::section("serve_connection: unknown, HTTP/1.0 and bodiless expectations");
    struct Case {
        std::string_view request;
        std::string_view expect_prefix;
        bool interim;
        bool ok;
    };
    const Case cases[] = {
        {"POST / HTTP/1.1\r\nHost: a\r\nExpect: fancy\r\nContent-Length: 1\r\n\r\nx",
         "HTTP/1.1 417 ", false, false},
        {"POST / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc",
         "HTTP/1.0 200 ", false, true},
        {"GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
         "HTTP/1.1 200 ", false, true},
    };
    for (const auto& each : cases) {
        auto rig = Rig::create(loop);
        CHECK_VALUE(rig);
        Result<void> served = fail(Errc::internal);
        TaskScope scope;
        auto handler = [](const Request&, auto& writer,
                          std::span<const std::byte>) -> Task<Result<void>> {
            Response response;
            response.status = 200;
            co_return co_await writer.send(response);
        };
        auto server = [&]() -> Task<void> {
            auto accepted = co_await rig->listener.accept();
            if (!accepted) co_return;
            tcp::Socket peer = std::move(*accepted);
            served = co_await serve_connection(peer, handler);
        };
        scope.spawn(server());
        auto socket = co_await rig->dial();
        CHECK_VALUE(socket);
        if (socket) {
            Raw raw{std::move(*socket), {}};
            const auto sent = co_await raw.send(each.request);
            CHECK_VALUE(sent);
            auto head = co_await raw.head();
            CHECK_VALUE(head);
            if (head) {
                CHECK(head->starts_with(each.expect_prefix));
                CHECK(!head->starts_with("HTTP/1.1 100") || each.interim);
            }
            static_cast<void>(raw.socket.shutdown_send());
            static_cast<void>(co_await raw.drain());
            raw.socket.close();
        }
        co_await scope.join();
        CHECK(static_cast<bool>(served) == each.ok);
        if (!each.ok) CHECK(served.error() == Errc::not_supported);
    }
}

// Deterministic fault injection around the concurrent response reader.
struct FaultStream {
    EventLoop& loop;
    explicit FaultStream(EventLoop& value) : loop(value) {}
    std::stop_source response_ready;
    unsigned writes = 0;
    unsigned throw_write = 0;
    bool throw_read = false;
    bool partial_failure = false;
    bool reply = false;
    bool replied = false;
    bool reader_exited = false;
    std::string_view response = "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n";
    Task<Result<std::size_t>> read_some(std::span<std::byte> out, OperationOptions io = {}) {
        if (throw_read) throw std::runtime_error("read fault");
        if (!reply) {
            std::stop_callback forward{io.stop, [this] { response_ready.request_stop(); }};
            const auto wait = co_await loop.sleep_for(1h, {.stop = response_ready.get_token(), .deadline = io.deadline});
            if (!reply) {
                reader_exited = true;
                co_return fail(wait ? make_error_code(Errc::eof) : wait.error());
            }
        }
        if (replied) co_return fail(Errc::eof);
        CHECK(out.size() >= response.size());
        std::memcpy(out.data(), response.data(), response.size());
        replied = true;
        reader_exited = true;
        co_return response.size();
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> input, OperationOptions = {}) {
        ++writes;
        if (writes == throw_write) throw std::runtime_error("write fault");
        if (partial_failure && writes == 2) co_return std::min(std::size_t{2}, input.size());
        if (partial_failure && writes == 3) {
            reply = true;
            response_ready.request_stop();
            while (!reader_exited) co_await loop.yield();
            co_return fail(Errc::eof);
        }
        co_return input.size();
    }
};

Result<std::span<const std::byte>> throw_source_fault(bool allocation_failure) {
    if (allocation_failure) throw std::bad_alloc{};
    throw std::runtime_error("source fault");
}

Task<void> audit_callback_and_write_failures(EventLoop& loop) {
    test::section("upload exceptions always join the parked reader");
    for (const bool allocation_failure : {false, true}) {
        FaultStream stream{loop};
        ClientConnection client{stream};
        auto source = [allocation_failure]() -> Task<Result<std::span<const std::byte>>> {
            // Keep a return expression for non-void coroutine diagnostics;
            // the helper throws only when this lazy task is actually resumed.
            co_return throw_source_fault(allocation_failure);
        };
        bool caught = false;
        try { static_cast<void>(co_await client.exchange(loop, post(), Framing::content_length, 5, source)); }
        catch (const std::exception&) { caught = true; }
        CHECK(caught && stream.reader_exited && !client.reusable());
    }
    // Throwing while constructing the Task is distinct from throwing inside it.
    {
        FaultStream stream{loop};
        ClientConnection client{stream};
        auto source = []() -> Task<Result<std::span<const std::byte>>> { throw std::bad_alloc{}; };
        bool caught = false;
        try { static_cast<void>(co_await client.exchange(loop, post(), Framing::content_length, 5, source)); }
        catch (const std::bad_alloc&) { caught = true; }
        CHECK(caught && stream.reader_exited && !client.reusable());
    }
    test::section("exceptions in every client stage invalidate without destructor abort");
    for (unsigned stage = 0; stage < 5; ++stage) {
        FaultStream stream{loop};
        ClientConnection client{stream};
        Repeating source{5, 5};
        bool caught = false;
        try {
            if (stage == 0) {
                stream.throw_write = 1;
                static_cast<void>(co_await client.begin(post(), Framing::content_length, 5));
            } else if (stage == 1) {
                stream.throw_write = 2;
                static_cast<void>(co_await client.begin(post(), Framing::content_length, 5));
                static_cast<void>(co_await client.send_body(bytes("hello")));
            } else if (stage == 2) {
                static_cast<void>(co_await client.begin(post(), Framing::content_length, 0));
                stream.throw_read = true;
                static_cast<void>(co_await client.finish());
            } else if (stage == 3) {
                stream.throw_write = 2;
                static_cast<void>(co_await client.exchange(loop, post(), Framing::content_length, 5, source));
            } else {
                stream.throw_read = true;
                static_cast<void>(co_await client.exchange(loop, post(), Framing::content_length, 5, source));
            }
        } catch (const std::runtime_error&) { caught = true; }
        CHECK(caught && !client.reusable());
        if (stage == 3) CHECK(stream.reader_exited);
    }
    test::section("partial body write remains interrupted after final response");
    {
        FaultStream stream{loop};
        stream.partial_failure = true;
        ClientConnection client{stream};
        Repeating source{5, 5};
        auto result = co_await client.exchange(loop, post(), Framing::content_length, 5, source,
            {.expect_continue = true, .continue_timeout = 1ms});
        CHECK(result && result->upload == UploadOutcome::interrupted && result->body_sent == 2);
        CHECK(!client.reusable());
        CHECK((co_await client.read_body()).has_value());
    }
    test::section("request deadline reaches cooperative body source");
    {
        FaultStream stream{loop};
        ClientOptions options;
        options.request_timeout = 5ms;
        ClientConnection client{stream, options};
        bool received_options = false;
        auto source = [&](OperationOptions io) -> Task<Result<std::span<const std::byte>>> {
            received_options = io.deadline.has_value() && io.stop.stop_possible();
            auto waited = co_await loop.sleep_for(1h, io);
            CHECK(!waited);
            co_return fail(waited.error());
        };
        auto result = co_await client.exchange(loop, post(), Framing::content_length, 5, source);
        CHECK(!result && result.error() == Errc::timed_out);
        CHECK(received_options && stream.reader_exited && !client.reusable());
    }
}

Task<void> refusal_stops_cooperative_producer(EventLoop& loop) {
    test::section("early refusal cancels a parked producer while preserving the response");
    FaultStream stream{loop};
    ClientConnection client{stream};
    bool source_started = false;
    bool source_cancelled = false;
    auto source = [&](OperationOptions io) -> Task<Result<std::span<const std::byte>>> {
        source_started = true;
        const auto wait = co_await loop.sleep_for(1h, io);
        source_cancelled = !wait && wait.error() == Errc::cancelled;
        co_return wait ? Result<std::span<const std::byte>>{bytes("hello")} : fail(wait.error());
    };
    TaskScope scope;
    auto refuse = [&]() -> Task<void> {
        while (!source_started) co_await loop.yield();
        stream.reply = true;
        stream.response_ready.request_stop();
    };
    scope.spawn(refuse());
    // The safety deadline bounds an unfixed implementation; the refusal must
    // complete by cancelling just the producer, not timing out the exchange.
    auto result = co_await client.exchange(loop, post(), Framing::content_length, 5, source,
                                           {}, {.deadline = Clock::now() + 100ms});
    co_await scope.join();
    CHECK(source_started && source_cancelled);
    CHECK(result && result->upload == UploadOutcome::interrupted && result->body_sent == 0);
    CHECK(client.response().status == 413);
    CHECK(!client.reusable());
    if (result) CHECK((co_await client.read_body()).has_value());

    test::section("early keep-alive success leaves a cooperative producer running");
    FaultStream accepted{loop};
    accepted.response = "HTTP/1.1 204 No Content\r\n\r\n";
    ClientConnection accepted_client{accepted};
    bool produced = false;
    auto continuing_source = [&](OperationOptions io) -> Task<Result<std::span<const std::byte>>> {
        if (produced) co_return std::span<const std::byte>{};
        accepted.reply = true;
        accepted.response_ready.request_stop();
        auto waited = co_await loop.sleep_for(1ms, io);
        CHECK(waited.has_value());
        if (!waited) co_return fail(waited.error());
        produced = true;
        co_return bytes("hello");
    };
    auto completed = co_await accepted_client.exchange(loop, post(), Framing::content_length, 5,
        continuing_source, {}, {.deadline = Clock::now() + 100ms});
    CHECK(completed && completed->upload == UploadOutcome::complete && completed->body_sent == 5);
    if (completed) CHECK((co_await accepted_client.read_body()).has_value());
    CHECK(accepted_client.reusable());

    test::section("a refusal does not hide an independent producer error");
    FaultStream faulty{loop};
    ClientConnection faulty_client{faulty};
    auto failing_source = [&](OperationOptions io) -> Task<Result<std::span<const std::byte>>> {
        faulty.reply = true;
        faulty.response_ready.request_stop();
        static_cast<void>(co_await loop.sleep_for(1h, io));
        co_return fail(Errc::internal);
    };
    auto failed = co_await faulty_client.exchange(loop, post(), Framing::content_length, 5,
        failing_source, {}, {.deadline = Clock::now() + 100ms});
    CHECK(!failed && failed.error() == Errc::internal);
    CHECK(!faulty_client.reusable());
}

Task<void> run(EventLoop& loop) {
    co_await refusal_stops_cooperative_producer(loop);
    co_await audit_callback_and_write_failures(loop);
    co_await serializer_rules();
    co_await expect_continue_granted(loop);
    co_await expect_refused(loop);
    co_await expect_timeout(loop);
    co_await early_refusal(loop);
    co_await early_success_continues(loop);
    co_await leg_failures(loop);
    co_await server_expectations(loop);
}

}  // namespace

int main() {
    auto loop = EventLoop::create();
    if (!loop) return 1;
    const auto ran = loop->run_until_complete(run(*loop));
    if (!ran) return 1;
    return test::summary();
}
