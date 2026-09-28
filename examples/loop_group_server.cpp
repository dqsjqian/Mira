// Multi-loop TCP service: each worker creates and owns an independent listener.
// Usage: mira_loop_group_server [workers=2] [connections-per-worker=64]
// Output: WORKER=<index> PORT=<ephemeral-port>, then READY. Send a line on stdin
// to request cooperative stop and join. No socket crosses a loop boundary.
#include <mira/core/loop_group.hpp>
#include <mira/core/stream.hpp>
#include <mira/transport/server.hpp>

#include <array>
#include <charconv>
#include <cstdio>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

Mira::Task<Mira::Result<void>> echo(Mira::transport::tcp::Socket& socket,
                                    Mira::OperationOptions io) {
    std::array<std::byte, 16384> buffer{};
    for (;;) {
        auto n = co_await socket.read_some(buffer, io);
        if (!n) {
            if (n.error() == Mira::Errc::eof) co_return Mira::Result<void>{};
            co_return Mira::fail(n.error());
        }
        auto sent = co_await Mira::write_all(socket, std::span<const std::byte>(buffer).first(*n), io);
        if (!sent) co_return sent;
    }
}

Mira::Task<void> serve_worker(Mira::EventLoop& loop, std::stop_token stop,
                              std::size_t index, std::size_t maximum,
                              std::shared_ptr<std::promise<Mira::Result<unsigned>>> ready) {
    auto listener = Mira::transport::tcp::Listener::bind(
        loop, Mira::transport::Endpoint::loopback(0));
    if (!listener) {
        ready->set_value(Mira::fail(listener.error()));
        co_return;
    }
    ready->set_value(static_cast<unsigned>(listener->local_endpoint().port()));
    Mira::transport::tcp::ServeOptions options;
    options.max_connections = maximum;
    options.io.stop = stop;
    auto result = co_await Mira::transport::tcp::serve(*listener, &echo, options);
    if (!result) throw std::system_error(result.error());
    std::printf("STATS worker=%zu accepted=%zu rejected=%zu completed=%zu failed=%zu peak_active=%zu\n",
                index, result->accepted, result->rejected, result->completed,
                result->failed, result->peak_active);
}

}  // namespace

int main(int argc, char** argv) {
    std::size_t values[]{2, 64};
    if (argc > 3) return 2;
    for (int i = 1; i < argc; ++i) {
        const std::string_view text{argv[i]};
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), values[i - 1]);
        if (error != std::errc{} || end != text.data() + text.size()) return 2;
    }
    if (values[0] == 0 || values[0] > 128 || values[1] == 0 || values[1] > 65536) return 2;
    auto group = Mira::LoopGroup::create({.workers = values[0], .max_tasks_per_worker = 1});
    if (!group) {
        std::fprintf(stderr, "create: %s\n", group.error().message().c_str());
        return 1;
    }
    std::vector<std::future<Mira::Result<unsigned>>> ready;
    for (std::size_t i = 0; i < values[0]; ++i) {
        auto signal = std::make_shared<std::promise<Mira::Result<unsigned>>>();
        ready.push_back(signal->get_future());
        auto posted = (*group)->try_spawn(i, [signal, i, maximum = values[1]](
            Mira::EventLoop& loop, std::stop_token stop) {
            return serve_worker(loop, stop, i, maximum, signal);
        });
        if (!posted) return 1;
    }
    for (std::size_t i = 0; i < ready.size(); ++i) {
        auto bound = ready[i].get();
        if (!bound) {
            std::fprintf(stderr, "bind: %s\n", bound.error().message().c_str());
            return 1;
        }
        std::printf("WORKER=%zu PORT=%u\n", i, *bound);
    }
    std::printf("READY\n");
    std::fflush(stdout);
    std::string command;
    std::getline(std::cin, command);
    (*group)->request_stop();
    auto joined = (*group)->join();
    if (!joined) std::fprintf(stderr, "join: %s\n", joined.error().message().c_str());
    return joined ? 0 : 1;
}
