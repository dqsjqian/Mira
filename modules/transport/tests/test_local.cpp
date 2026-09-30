#include "check.hpp"
#include "mira/core/platform.hpp"
#include "mira/transport/local.hpp"
#include "mira/core/stream.hpp"
#include "mira/core/task_scope.hpp"
#include <array>
#include <chrono>
#include <memory>
#if !MIRA_PLATFORM_WINDOWS
#include <fcntl.h>
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
#if !MIRA_PLATFORM_WINDOWS
    for (const auto handle : {listener->native_handle(), client->native_handle(), peer->native_handle()}) {
        const auto flags = ::fcntl(handle, F_GETFD, 0);
        CHECK(flags >= 0 && (flags & FD_CLOEXEC) != 0);
    }
#endif
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
#if !MIRA_PLATFORM_WINDOWS
Task<void> cancel_accept(std::unique_ptr<local::Listener>& listener, bool& done) {
    const auto result = co_await listener->accept();
    CHECK(!result && result.error() == Errc::cancelled);
    listener.reset();
    done = true;
}
void test_move_reentrancy(EventLoop& loop, const std::string& path) {
    auto bound = local::Listener::bind(loop, path + "-old");
    auto replacement = local::Listener::bind(loop, path + "-new");
    CHECK(bound && replacement);
    if (!bound || !replacement) return;
    auto listener = std::make_unique<local::Listener>(std::move(*bound));
    bool done = false;
    TaskScope scope;
    scope.spawn(cancel_accept(listener, done));
    CHECK(!done);
    *listener = std::move(*replacement);
    CHECK(done);
    CHECK(!listener);
    scope.join().sync_get();
    CHECK(loop.outstanding() == 0);
    CHECK(::unlink((path + "-old").c_str()) == 0);
    CHECK(::unlink((path + "-new").c_str()) == 0);
}
#endif
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
        test_move_reentrancy(*loop, path);
        // Only this test's own socket entry and private temporary directory.
        CHECK(::unlink(path.c_str()) == 0);
        CHECK(::rmdir(created) == 0);
    }
#endif
    return test::summary();
}
