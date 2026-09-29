// MQTT 3.1.1 / 5.0 command-line client on Mira::mqtt over TCP or TLS.
//
// Usage: mira_mqtt_client <host> <port> <command> [options]
//   pub  <topic> <message>   publish once and wait for its acknowledgement
//   sub  <filter> [count]    print "<topic> <payload>" for count messages (default 1)
//   echo <topic> <message>   subscribe, publish, and wait for the message to come back
// Options: --qos 0|1|2  --retain  --v311  --id <client-id>  --user <name> --password <secret>
//          --keepalive <seconds>  --timeout <seconds>  --tls  --ca <file>  --alpn <protocol>
//
// Exits non-zero on refusal, protocol failure or timeout (default 10 s).
#include <mira/core/task_scope.hpp>
#include <mira/mqtt/client.hpp>
#include <mira/transport/dial.hpp>
#include <mira/transport/resolver.hpp>
#if MIRA_EXAMPLE_TLS
#include <mira/tls/stream.hpp>
#endif

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <string>
#include <stop_token>
#include <string_view>
#include <utility>
#include <vector>

namespace mqtt = Mira::mqtt;
namespace tcp = Mira::transport::tcp;
using namespace std::chrono_literals;

namespace {

struct Options {
    std::string host;
    std::uint16_t port = 1883;
    std::string command, topic, message;
    unsigned count = 1;
    mqtt::QoS qos = mqtt::QoS::at_most_once;
    bool retain = false;
    bool tls = false;
    std::string ca_file, alpn;
    unsigned timeout = 10;
    mqtt::ClientOptions client;
};

bool number(std::string_view text, unsigned& value, unsigned maximum) {
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc{} && end == text.data() + text.size() && value <= maximum;
}

mqtt::Bytes bytes(std::string_view text) {
    const auto view = std::as_bytes(std::span{text.data(), text.size()});
    return mqtt::Bytes(view.begin(), view.end());
}

void print(const mqtt::Message& message) {
    std::printf("%s %.*s\n", message.topic.c_str(), static_cast<int>(message.payload.size()),
                reinterpret_cast<const char*>(message.payload.data()));
    std::fflush(stdout);
}

// Named coroutines rather than coroutine lambdas: GCC 13 crashes on the latter
// inside template coroutines.
template<typename Stream>
Mira::Task<void> keep_alive(mqtt::Client<Stream>& client, Mira::EventLoop& loop, std::stop_token stop) {
    static_cast<void>(co_await client.keep_alive(loop, {.stop = std::move(stop)}));
}

template<typename Stream>
Mira::Task<Mira::Result<void>> commands(mqtt::Client<Stream>& client, const Options& options,
                                        Mira::OperationOptions io) {
    if (options.command == "sub" || options.command == "echo") {
        std::vector<mqtt::Subscription> subscriptions(1);
        subscriptions[0].filter = options.topic;
        subscriptions[0].qos = options.qos;
        auto id = co_await client.subscribe(std::move(subscriptions), mqtt::Properties{}, io);
        if (!id) co_return Mira::fail(id.error());
        auto granted = co_await client.wait_for(*id, io);
        if (!granted) co_return Mira::fail(granted.error());
        if (granted->reasons.empty() || granted->reasons[0] >= 0x80) co_return Mira::fail(mqtt::MqttError::refused);
    }
    if (options.command == "pub" || options.command == "echo") {
        auto id = co_await client.publish(options.topic, bytes(options.message), options.qos, options.retain,
                                          mqtt::Properties{}, io);
        if (!id) co_return Mira::fail(id.error());
        if (*id) {
            auto done = co_await client.wait_for(*id, io);
            if (!done) co_return Mira::fail(done.error());
            if (done->reason >= 0x80) co_return Mira::fail(mqtt::MqttError::refused);
        }
    }
    unsigned remaining = options.command == "pub" ? 0 : options.count;
    while (remaining) {
        auto events = co_await client.receive(io);
        if (!events) co_return Mira::fail(events.error());
        for (const auto& event : *events) {
            if (event.kind == mqtt::Event::Kind::disconnected) co_return Mira::fail(mqtt::MqttError::disconnected);
            if (event.kind != mqtt::Event::Kind::message || !remaining) continue;
            print(event.message);
            --remaining;
        }
    }
    auto closed = co_await client.disconnect(mqtt::reason::success, mqtt::Properties{}, io);
    co_return closed;
}

template<typename Stream>
Mira::Task<Mira::Result<void>> session(Mira::EventLoop& loop, Stream& stream, const Options& options,
                                       Mira::OperationOptions io) {
    auto connected = co_await mqtt::Client<Stream>::connect(stream, options.client, io);
    if (!connected) co_return Mira::fail(connected.error());
    auto& client = *connected;
    std::fprintf(stderr, "connected as '%s' (keep-alive %u s)\n", client.session().client_id().c_str(),
                 static_cast<unsigned>(client.session().keep_alive()));
    // Keep-alive runs as a concurrent writer while `commands` reads.
    std::stop_source stop;
    Mira::TaskScope scope;
    scope.spawn(keep_alive(client, loop, stop.get_token()));
    auto result = co_await commands(client, options, io);
    stop.request_stop();
    co_await scope.join();
    co_return result;
}

Mira::Task<Mira::Result<void>> run(Mira::EventLoop& loop, Mira::transport::Resolver& resolver, const Options& options) {
    tcp::DialOptions dial;
    dial.io.deadline = Mira::Clock::now() + std::chrono::seconds(options.timeout);
    const auto io = dial.io;
    auto socket = co_await tcp::dial(loop, resolver, options.host, options.port, dial);
    if (!socket) co_return Mira::fail(socket.error());
    if (!options.tls) co_return co_await session(loop, *socket, options, io);
#if MIRA_EXAMPLE_TLS
    auto context = Mira::tls::Context::client(options.ca_file, options.alpn);
    if (!context) co_return Mira::fail(context.error());
    auto stream = Mira::tls::Stream<tcp::Socket>::create(loop, *socket, *context, options.host);
    if (!stream) co_return Mira::fail(stream.error());
    auto established = co_await stream->handshake(io);
    if (!established) co_return Mira::fail(established.error());
    auto result = co_await session(loop, *stream, options, io);
    static_cast<void>(co_await stream->shutdown({.deadline = Mira::Clock::now() + 1s}));
    co_return result;
#else
    co_return Mira::fail(Mira::Errc::not_supported);
#endif
}

Mira::Task<void> report(Mira::EventLoop& loop, Mira::transport::Resolver& resolver, const Options& options,
                        int& status) {
    auto result = co_await run(loop, resolver, options);
    if (!result) {
        std::fprintf(stderr, "mqtt failed: %s\n", result.error().message().c_str());
        co_return;
    }
    status = 0;
}

int usage(const char* name) {
    std::fprintf(stderr,
                 "usage: %s <host> <port> pub <topic> <message> | sub <filter> [count] | echo <topic> <message>\n"
                 "       [--qos 0|1|2] [--retain] [--v311] [--id ID] [--user U] [--password P]\n"
                 "       [--keepalive S] [--timeout S] [--tls] [--ca FILE] [--alpn PROTOCOL]\n",
                 name);
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 5) return usage(argv[0]);
    Options options;
    options.host = argv[1];
    unsigned value = 0;
    if (!number(argv[2], value, 65535) || !value) return usage(argv[0]);
    options.port = static_cast<std::uint16_t>(value);
    options.command = argv[3];
    options.topic = argv[4];
    int i = 5;
    if (options.command == "pub" || options.command == "echo") {
        if (argc < 6) return usage(argv[0]);
        options.message = argv[i++];
    } else if (options.command == "sub") {
        if (i < argc && argv[i][0] != '-') {
            if (!number(argv[i++], options.count, 1'000'000) || !options.count) return usage(argv[0]);
        }
    } else {
        return usage(argv[0]);
    }
    options.client.keep_alive = 30;
    for (; i < argc; ++i) {
        const std::string_view flag{argv[i]};
        const bool has_value = i + 1 < argc;
        if (flag == "--qos" && has_value && number(argv[i + 1], value, 2)) {
            options.qos = static_cast<mqtt::QoS>(value);
            ++i;
        } else if (flag == "--retain") options.retain = true;
        else if (flag == "--v311") options.client.version = mqtt::Version::v311;
        else if (flag == "--id" && has_value) options.client.client_id = argv[++i];
        else if (flag == "--user" && has_value) options.client.username = argv[++i];
        else if (flag == "--password" && has_value) options.client.password = bytes(argv[++i]);
        else if (flag == "--keepalive" && has_value && number(argv[i + 1], value, 65535)) {
            options.client.keep_alive = static_cast<std::uint16_t>(value);
            ++i;
        } else if (flag == "--timeout" && has_value && number(argv[i + 1], value, 3600) && value) {
            options.timeout = value;
            ++i;
        } else if (flag == "--tls") options.tls = true;
        else if (flag == "--ca" && has_value) options.ca_file = argv[++i];
        else if (flag == "--alpn" && has_value) options.alpn = argv[++i];
        else return usage(argv[0]);
    }
    if (options.client.version == mqtt::Version::v311 && options.client.client_id.empty())
        options.client.client_id = "mira-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 1'000'000);
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto loop = Mira::EventLoop::create();
    auto resolver = Mira::transport::Resolver::create();
    if (!loop || !resolver) return 1;
    int status = 1;
    const auto ran = loop->run_until_complete(report(*loop, *resolver, options, status));
    return ran ? status : 1;
}
