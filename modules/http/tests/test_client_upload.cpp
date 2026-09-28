#include "check.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/http/client.hpp"

#include <cstring>
#include <string>
#include <vector>

#define CHECK_VALUE(expr) CHECK(static_cast<bool>(expr))
using namespace Mira;
using namespace Mira::http;
using namespace std::chrono_literals;

namespace {
std::span<const std::byte> bytes(std::string_view value) {
    return std::as_bytes(std::span{value.data(), value.size()});
}
struct Stream {
    std::string input = "HTTP/1.1 204 No Content\r\n\r\n";
    std::string output;
    std::vector<OperationOptions> seen;
    std::size_t cursor = 0;
    bool zero = false;
    EventLoop* loop = nullptr;
    Clock::duration delay{};
    Task<Result<std::size_t>> write_some(std::span<const std::byte> data, OperationOptions io = {}) {
        seen.push_back(io);
        if (loop && delay > Clock::duration::zero()) {
            const auto waited = co_await loop->sleep_for(delay, io);
            if (!waited) co_return fail(waited.error());
        }
        if (zero) co_return std::size_t{0};
        const auto size = std::min<std::size_t>(data.size(), 3);
        output.append(reinterpret_cast<const char*>(data.data()), size);
        co_return size;
    }
    Task<Result<std::size_t>> read_some(std::span<std::byte> data, OperationOptions io = {}) {
        seen.push_back(io);
        if (cursor == input.size()) co_return fail(Errc::eof);
        const auto size = std::min<std::size_t>({data.size(), input.size() - cursor, 2});
        std::memcpy(data.data(), input.data() + cursor, size);
        cursor += size;
        co_return size;
    }
};
Request request() {
    Request value;
    value.method = Method::post;
    value.target = "/upload";
    value.headers.append("Host", "localhost");
    return value;
}
Task<void> run(EventLoop& loop) {
    {
        ResourceBudget input_budget{128};
        ClientOptions options;
        options.max_buffer_size = 128;
        options.input_budget = input_budget;
        auto req = request();
        {
            Stream first, second;
            ClientConnection a{first, options}, b{second, options};
            CHECK_VALUE(co_await a.start(req));
            CHECK_VALUE(co_await a.read_body());
            CHECK_VALUE(input_budget.used() == 128);
            auto rejected = co_await b.begin(req, Framing::content_length);
            CHECK_VALUE(!rejected && rejected.error() == Errc::would_block);
            CHECK_VALUE(second.output.empty() && b.reusable());
        }
        CHECK_VALUE(input_budget.used() == 0);
        Stream recovered;
        ClientConnection c{recovered, options};
        CHECK_VALUE(co_await c.start(req));
        CHECK_VALUE(co_await c.read_body());
    }
    for (const auto framing : {Framing::content_length, Framing::chunked}) {
        Stream stream;
        ClientConnection client{stream};
        auto req = request();
        const auto deadline = Clock::now() + 5s;
        CHECK_VALUE(co_await client.begin(req, framing, framing == Framing::chunked ? 0 : 6,
                                          {.deadline = deadline}));
        CHECK_VALUE(stream.cursor == 0);
        CHECK_VALUE(stream.output.ends_with("\r\n\r\n"));
        CHECK_VALUE(co_await client.send_body(bytes("abc")));
        CHECK_VALUE(stream.output.ends_with(framing == Framing::chunked ? "3\r\nabc\r\n" : "abc"));
        CHECK_VALUE(co_await client.send_body({}));
        CHECK_VALUE(co_await client.send_body(bytes("def")));
        CHECK_VALUE(stream.cursor == 0);
        CHECK_VALUE(!(co_await client.read_body()));
        CHECK_VALUE(co_await client.finish());
        CHECK_VALUE(co_await client.read_body());
        CHECK_VALUE(client.reusable());
        const auto expected = framing == Framing::chunked
            ? "Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"
            : "Content-Length: 6\r\n\r\nabcdef";
        CHECK_VALUE(stream.output.ends_with(expected));
        for (const auto& io : stream.seen) CHECK_VALUE(io.deadline == deadline);
    }
    for (const bool excess : {false, true}) {
        Stream stream;
        ClientConnection client{stream};
        auto req = request();
        CHECK_VALUE(co_await client.begin(req, Framing::content_length, 3));
        Result<void> result;
        if (excess) result = co_await client.send_body(bytes("four"));
        else result = co_await client.finish();
        CHECK_VALUE(!result && result.error() == (excess ? Errc::invalid_argument : Errc::eof));
        CHECK_VALUE(!client.reusable());
        CHECK_VALUE(stream.output.ends_with("\r\n\r\n"));
    }
    {
        Stream stream;
        ClientOptions options;
        options.limits.max_body_size = 3;
        ClientConnection client{stream, options};
        auto req = request();
        CHECK_VALUE(co_await client.begin(req, Framing::chunked));
        CHECK_VALUE(co_await client.send_body(bytes("abc")));
        const auto result = co_await client.send_body(bytes("d"));
        CHECK_VALUE(!result && result.error() == Errc::limit_exceeded);
    }
    {
        Stream stream;
        ClientConnection client{stream};
        auto req = request();
        req.version = Version::http_1_0;
        CHECK_VALUE(!(co_await client.begin(req, Framing::chunked)));
        CHECK_VALUE(stream.output.empty());
        CHECK_VALUE(client.reusable());
    }
    {
        Stream stream;
        ClientConnection client{stream};
        auto req = request();
        CHECK_VALUE(co_await client.begin(req, Framing::content_length, 3));
        stream.zero = true;
        const auto result = co_await client.send_body(bytes("abc"));
        CHECK_VALUE(!result && result.error() == Errc::eof);
        CHECK_VALUE(!client.reusable());
    }
    {
        Stream stream;
        ClientOptions options;
        options.request_timeout = 10ms;
        ClientConnection client{stream, options};
        auto req = request();
        CHECK_VALUE(co_await client.begin(req, Framing::content_length, 3));
        CHECK_VALUE(co_await loop.sleep_for(20ms));
        const auto result = co_await client.send_body(bytes("abc"));
        CHECK_VALUE(!result && result.error() == Errc::timed_out);
    }
    {
        Stream stream;
        ClientConnection client{stream};
        auto req = request();
        std::stop_source stop;
        CHECK_VALUE(co_await client.begin(req, Framing::chunked, 0, {.stop = stop.get_token()}));
        stream.loop = &loop;
        stream.delay = 5s;
        auto upload = [&]() -> Task<void> {
            const auto result = co_await client.send_body(bytes("abc"));
            CHECK_VALUE(!result && result.error() == Errc::cancelled);
        };
        auto cancel = [&]() -> Task<void> {
            CHECK_VALUE(co_await loop.sleep_for(5ms));
            CHECK_VALUE(!(co_await client.send_body(bytes("overlap"))));
            CHECK_VALUE(!client.abandon());
            stop.request_stop();
        };
        TaskScope scope;
        scope.spawn(upload());
        scope.spawn(cancel());
        co_await scope.join();
        CHECK_VALUE(!client.reusable());
    }
    {
        Stream stream;
        stream.input = "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n";
        ClientConnection client{stream};
        auto req = request();
        CHECK_VALUE(co_await client.begin(req, Framing::content_length, 3));
        CHECK_VALUE(co_await client.send_body(bytes("abc")));
        CHECK_VALUE(stream.cursor == 0);
        CHECK_VALUE(co_await client.finish());
        CHECK_VALUE(client.response().status == 413);
        CHECK_VALUE(co_await client.read_body());
    }
}
}
int main() {
    auto loop = EventLoop::create();
    CHECK_VALUE(loop);
    if (loop) CHECK_VALUE(loop->run_until_complete(run(*loop)));
    return test::summary();
}
