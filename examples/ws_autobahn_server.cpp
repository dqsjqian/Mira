#include <mira/transport/server.hpp>
#include <mira/ws/connection.hpp>

#include <charconv>
#include <csignal>
#include <cstdio>
#include <string_view>

namespace {
volatile std::sig_atomic_t stopping = 0;
void stop_signal(int) { stopping = 1; }

Mira::Task<Mira::Result<void>> echo(Mira::transport::tcp::Socket& socket,
                                   Mira::OperationOptions options) {
    // Raise only harness limits for Autobahn 9.*; preserve the library's production defaults.
    Mira::ws::Limits limits{.max_frame = 64 * 1024 * 1024, .max_message = 64 * 1024 * 1024};
    Mira::ws::HandshakeOptions handshake_options;
    handshake_options.compression.enabled = true;
    Mira::ws::Connection connection(socket, Mira::ws::Role::server, limits, handshake_options);
    auto handshake = co_await connection.handshake({}, "/", options);
    if (!handshake) co_return handshake;
    for (;;) {
        auto message = co_await connection.read_message(options);
        if (!message) co_return Mira::fail(message.error());
        if (message->opcode == Mira::ws::Opcode::close) co_return Mira::Result<void>{};
        auto sent = co_await connection.send(std::move(*message), options);
        if (!sent) co_return sent;
    }
}

Mira::Task<void> watch_signal(Mira::EventLoop& loop, std::stop_source source) {
    while (!source.stop_requested() && !stopping) {
        auto slept = co_await loop.sleep_for(std::chrono::milliseconds(50),
                                             {.stop = source.get_token()});
        if (!slept) break;
    }
    source.request_stop();
}

Mira::Task<void> run(Mira::EventLoop& loop, Mira::transport::tcp::Listener& listener,
                     unsigned lifetime, int& status) {
    std::stop_source stop;
    Mira::TaskScope scope;
    scope.spawn(watch_signal(loop, stop));
    std::exception_ptr exception;
    try {
        Mira::transport::tcp::ServeOptions options;
        options.max_connections = 64;
        options.io = {.stop = stop.get_token(),
                      .deadline = Mira::Clock::now() + std::chrono::seconds(lifetime)};
        auto served = co_await Mira::transport::tcp::serve(listener, &echo, options);
        if (served) {
            std::printf("accepted=%zu completed=%zu protocol_or_io_errors=%zu rejected=%zu\n",
                        served->accepted, served->completed, served->failed, served->rejected);
            status = served->rejected == 0 ? 0 : 1;
        }
    } catch (...) { exception = std::current_exception(); }
    stop.request_stop();
    co_await scope.join();
    if (exception) std::rethrow_exception(exception);
}
}

int main(int argc, char** argv) {
    unsigned values[]{0, 3600};
    if (argc > 3) return 2;
    for (int i = 1; i < argc; ++i) {
        const std::string_view text(argv[i]);
        auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), values[i - 1]);
        if (error != std::errc{} || end != text.data() + text.size()) return 2;
    }
    if (values[0] > 65535 || !values[1] || values[1] > 86400) return 2;
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    std::signal(SIGINT, stop_signal);
    std::signal(SIGTERM, stop_signal);
    auto loop = Mira::EventLoop::create();
    if (!loop) return 1;
    auto listener = Mira::transport::tcp::Listener::bind(
        *loop, Mira::transport::Endpoint::loopback(static_cast<std::uint16_t>(values[0])));
    if (!listener) return 1;
    std::printf("PORT=%u\n", static_cast<unsigned>(listener->local_endpoint().port()));
    std::fflush(stdout);
    int status = 1;
    auto ran = loop->run_until_complete(run(*loop, *listener, values[1], status));
    return ran ? status : 1;
}
