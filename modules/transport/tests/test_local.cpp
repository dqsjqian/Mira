#include "check.hpp"
#include "mira/core/platform.hpp"
#include "mira/transport/local.hpp"
#include "mira/core/stream.hpp"
#include <array>
#include <chrono>
#if !MIRA_PLATFORM_WINDOWS
#include <unistd.h>
#endif
using namespace Mira;
using namespace std::chrono_literals;
namespace local = transport::local;
Task<void> run(EventLoop& loop, std::string path) {
    auto listener = local::Listener::bind(loop, path);
    CHECK(listener.has_value());
    if (!listener) co_return;
    CHECK(!local::Listener::bind(loop, path)); // Never unlink an existing path.
    OperationOptions io{.deadline = Clock::now() + 2s};
    auto client = co_await local::connect(loop, path, io);
    CHECK(client.has_value());
    if (!client) co_return;
    auto peer = co_await listener->accept(io);
    CHECK(peer.has_value());
    if (!peer) co_return;
    std::array<std::byte, 3> data{std::byte{0}, std::byte{42}, std::byte{255}}, got{};
    CHECK((co_await write_all(*client, data, io)).has_value());
    auto n = co_await peer->read_some(got, io);
    CHECK(n && *n == 3 && data == got);
    client->close();
    auto end = co_await peer->read_some(got, io);
    CHECK(!end && end.error() == Errc::eof);
    auto timeout = co_await listener->accept({.deadline = Clock::now()});
    CHECK(!timeout && timeout.error() == Errc::timed_out);
    CHECK(!local::Listener::bind(loop, std::string(200, 'x')));
    auto bad = co_await local::connect(loop, std::string("x\0y", 3));
    CHECK(!bad && bad.error() == Errc::invalid_argument);
}
int main() {
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
#if MIRA_PLATFORM_WINDOWS
    if (loop) {
        auto unavailable = local::Listener::bind(*loop, "unavailable");
        CHECK(!unavailable && unavailable.error() == Errc::not_supported);
    }
#else
    std::array<char, 32> directory{};
    const std::string pattern = "/tmp/mira-local-XXXXXX";
    std::copy(pattern.begin(), pattern.end(), directory.begin());
    auto* created = ::mkdtemp(directory.data());
    CHECK(created != nullptr);
    if (loop && created) {
        const std::string path = std::string(created) + "/stream";
        CHECK(loop->run_until_complete(run(*loop, path)).has_value());
        // Only this test's own socket entry and private temporary directory.
        CHECK(::unlink(path.c_str()) == 0);
        CHECK(::rmdir(created) == 0);
    }
#endif
    return test::summary();
}
