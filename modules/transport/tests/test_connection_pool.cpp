#include "check.hpp"
#include "mira/core/connection_pool.hpp"
#include "mira/transport/reconnect.hpp"
#include <array>
#include <chrono>
#include <memory>

using namespace Mira;
using namespace std::chrono_literals;
namespace tcp = Mira::transport::tcp;
using transport::Endpoint;

Task<void> exercise(EventLoop& loop) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    ConnectionPool<tcp::Socket> pool{1};
    unsigned created = 0;
    auto factory = [&loop, endpoint = listener->local_endpoint(), &created](OperationOptions io)
        -> Task<Result<std::unique_ptr<tcp::Socket>>> {
        ++created;
        auto socket = co_await tcp::connect(loop, endpoint, {}, io);
        if (!socket) co_return fail(socket.error());
        co_return std::make_unique<tcp::Socket>(std::move(*socket));
    };
    const OperationOptions io{.deadline = Clock::now() + 2s};
    auto first = co_await pool.acquire(factory, io);
    CHECK(first.has_value());
    if (!first) co_return;
    auto peer = co_await listener->accept(io);
    CHECK(peer.has_value());
    if (!peer) co_return;
    const auto handle = first->get().native_handle();
    std::move(*first).recycle();
    auto second = co_await pool.acquire(factory, io);
    CHECK(second && created == 1 && second->get().native_handle() == handle);
    std::array<std::byte, 1> payload{std::byte{42}}, received{};
    auto sent = co_await second->get().write_some(payload, io);
    auto read = co_await peer->read_some(received, io);
    CHECK(sent && read && received == payload);
    pool.close();
    std::move(*second).recycle();
    CHECK(pool.active_and_idle() == 0);
    peer->close();

    const auto address = listener->local_endpoint();
    listener->close();
    tcp::RetryOptions retry{.attempts = 3, .initial_delay = 1ms, .max_delay = 2ms};
    auto failed = co_await tcp::connect_with_retry(loop, address, retry, {}, io);
    CHECK(!failed);
    auto timeout = co_await tcp::connect_with_retry(loop, address, retry, {},
                                                    {.deadline = Clock::now()});
    CHECK(!timeout && timeout.error() == Errc::timed_out);
    std::stop_source stop;
    stop.request_stop();
    auto cancelled = co_await tcp::connect_with_retry(loop, address, retry, {}, {.stop = stop.get_token()});
    CHECK(!cancelled && cancelled.error() == Errc::cancelled);
    auto invalid = co_await tcp::connect_with_retry(loop, address, {.attempts = 0});
    CHECK(!invalid && invalid.error() == Errc::invalid_argument);
}
int main() {
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (loop) CHECK(loop->run_until_complete(exercise(*loop)).has_value());
    return test::summary();
}
