#include "check.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/dns/doh.hpp"

#include <cstdlib>
#include <cstring>
#include <new>
#include <string>

namespace allocation_probe {

thread_local bool fail_next = false;
thread_local std::size_t failures = 0;

void* allocate(std::size_t size) {
    if (fail_next) {
        fail_next = false;
        ++failures;
        throw std::bad_alloc{};
    }
    if (void* pointer = std::malloc(size == 0 ? 1 : size)) return pointer;
    throw std::bad_alloc{};
}

}  // namespace allocation_probe

void* operator new(std::size_t size) { return allocation_probe::allocate(size); }
void* operator new[](std::size_t size) { return allocation_probe::allocate(size); }
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete[](void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }
void operator delete[](void* pointer, std::size_t) noexcept { std::free(pointer); }

namespace {

using namespace Mira;
using namespace Mira::dns;

struct Gate {
    std::coroutine_handle<> waiter;
    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept { waiter = handle; }
    void await_resume() const noexcept {}
    void release() { std::exchange(waiter, {}).resume(); }
};

struct ResponseStream {
    std::string head;
    std::vector<std::byte> body;
    bool fail_body_allocation = false;
    unsigned reads = 0;
    unsigned writes = 0;
    unsigned fail_after_write = 0;
    Gate* write_gate = nullptr;

    Task<Result<std::size_t>> read_some(std::span<std::byte> output, OperationOptions = {}) {
        ++reads;
        if (reads > 2) co_return std::size_t{0};
        const auto input = reads == 1 ? std::as_bytes(std::span{head.data(), head.size()})
                                     : std::span<const std::byte>{body};
        CHECK(output.size() >= input.size());
        if (output.size() < input.size()) co_return fail(Errc::limit_exceeded);
        std::memcpy(output.data(), input.data(), input.size());
        // The HTTP head is already parsed. After this borrowed body is returned,
        // query's response vector is the next allocation, outside HTTP's Guard.
        if (reads == 2 && fail_body_allocation) allocation_probe::fail_next = true;
        co_return input.size();
    }

    Task<Result<std::size_t>> write_some(std::span<const std::byte> input, OperationOptions = {}) {
        ++writes;
        if (writes == 1 && write_gate) co_await *write_gate;
        if (writes == fail_after_write) allocation_probe::fail_next = true;
        co_return input.size();
    }
};

http::Request request() {
    http::Request result;
    result.method = http::Method::post;
    result.target = "/allocation";
    result.headers.append("Host", "localhost");
    return result;
}

ResponseStream response() {
    return {"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n", {std::byte{'x'}}};
}

void start_allocation_failure() {
    test::section("HTTP start abandons failures between begin, send_body and finish");
    const auto head = request();
    const std::byte body[]{std::byte{'q'}};
    for (const unsigned fail_after_write : {0U, 1U, 2U}) {
        auto stream = response();
        // After the head, send_body's frame is next. After a fixed body,
        // finish's frame is next. Both allocations precede the callee's Guard.
        stream.fail_after_write = fail_after_write;
        http::ClientConnection connection{stream};
        const auto failures_before = allocation_probe::failures;
        bool caught = false;
        try {
            CHECK(connection.start(head, body).sync_get().has_value());
        } catch (const std::bad_alloc&) {
            caught = true;
        }
        allocation_probe::fail_next = false;
        CHECK(caught == (fail_after_write != 0));
        CHECK(allocation_probe::failures - failures_before == (fail_after_write != 0 ? 1U : 0U));
        if (fail_after_write != 0) {
            CHECK(stream.writes == fail_after_write);
            CHECK(stream.reads == 0);
            // send_body would still be legal if begin's active/uploading state
            // survived the exception. No retry may repair and recycle it.
            const auto next = connection.send_body({}).sync_get();
            CHECK(!next && next.error() == Errc::invalid_argument);
            CHECK(!connection.reusable());
            static_cast<void>(connection.abandon());
        } else {
            CHECK(stream.writes == 2);
            const auto chunk = connection.read_body().sync_get();
            CHECK(chunk && chunk->size() == 1 && chunk->front() == std::byte{'x'});
            const auto end = connection.read_body().sync_get();
            CHECK(end && end->empty());
            CHECK(connection.reusable());
        }
    }
}

void rejected_start_preserves_exchange() {
    test::section("HTTP start preflight preserves active and busy exchanges under allocation failure");
    const auto head = request();
    for (const bool busy : {false, true}) {
        auto stream = response();
        Gate gate;
        if (busy) stream.write_gate = &gate;
        http::ClientConnection connection{stream};
        TaskScope scope;
        bool first_finished = false;
        auto first = [&]() -> Task<void> {
            CHECK((co_await connection.start(head)).has_value());
            first_finished = true;
        };
        scope.spawn(first());
        CHECK(first_finished == !busy);
        CHECK(scope.pending() == (busy ? 1U : 0U));

        for (const bool inject : {false, true}) {
            // Allocate the competing start's own frame before arming. A
            // rejected call must not allocate a child task or clean up the
            // exchange that was already owned by another call.
            auto competing = connection.start(head);
            allocation_probe::fail_next = inject;
            bool caught = false;
            Result<void> result;
            try {
                result = std::move(competing).sync_get();
            } catch (const std::bad_alloc&) {
                caught = true;
            }
            const bool untouched = allocation_probe::fail_next == inject;
            allocation_probe::fail_next = false;
            CHECK(!caught);
            CHECK(!result && result.error() == Errc::invalid_argument);
            CHECK(untouched);
        }
        if (busy) gate.release();
        scope.join().sync_get();
        CHECK(first_finished);
        CHECK(stream.writes == 1);
        const auto chunk = connection.read_body().sync_get();
        CHECK(chunk && chunk->size() == 1 && chunk->front() == std::byte{'x'});
        const auto end = connection.read_body().sync_get();
        CHECK(end && end->empty());
        CHECK(connection.reusable());
        static_cast<void>(connection.abandon());
    }
}

void body_allocation_failure() {
    test::section("DoH response allocation failure abandons the active HTTP exchange");
    const auto question = make_query(*Name::parse("allocation.test"), type::a);
    CHECK(question.has_value());
    if (!question) return;
    auto answer = *question;
    answer.header.qr = true;
    answer.answers.push_back({question->questions.front().name, type::a, class_in, 60,
                              AData{{127, 0, 0, 1}}});
    const auto encoded = encode(answer);
    CHECK(encoded.has_value());
    if (!encoded) return;

    for (const bool inject : {false, true}) {
        ResponseStream stream{"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: " +
                                  std::to_string(encoded->size()) + "\r\n\r\n",
                              *encoded, inject};
        http::ClientConnection connection{stream};
        static_assert(noexcept(connection.abandon()));
        const auto failures_before = allocation_probe::failures;
        bool caught = false;
        try {
            const auto result = doh::query(connection, "localhost", "/dns-query", *question).sync_get();
            CHECK(result.has_value());
            if (result) CHECK(*result == answer);
        } catch (const std::bad_alloc&) {
            caught = true;
        }
        allocation_probe::fail_next = false;
        CHECK(caught == inject);
        CHECK(allocation_probe::failures - failures_before == (inject ? 1U : 0U));
        CHECK(stream.reads == 2);
        if (inject) {
            // A failed helper must have ended its exchange, not merely left it
            // active and relying on its caller to discover and abandon it.
            const auto next = connection.read_body().sync_get();
            CHECK(!next && next.error() == Errc::invalid_argument);
            CHECK(!connection.reusable());
            // Keep the regression diagnostic readable on the broken code too.
            static_cast<void>(connection.abandon());
        } else {
            CHECK(connection.reusable());
        }
    }
}

}  // namespace

int main() {
    start_allocation_failure();
    rejected_start_preserves_exchange();
    body_allocation_failure();
    return test::summary();
}
