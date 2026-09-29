// DNS-over-HTTPS query (RFC 8484) with Mira::dns over HTTP/1.1.
// Usage: mira_doh_client <host> <port> <name> [type] [get|post] [--plain | --ca <file>]
//
// Default is HTTPS with the system trust store (ALPN http/1.1, SNI and
// hostname verification on <host>); --ca pins a CA file; --plain speaks HTTP
// for local testing only. Prints "RCODE <n>" and one "ANSWER <type> <ttl>
// <data>" line per record. 5 s total deadline; non-zero exit on failure.
#include <mira/dns/doh.hpp>
#include <mira/transport/dial.hpp>
#include <mira/transport/resolver.hpp>
#if MIRA_EXAMPLE_TLS
#include <mira/tls/stream.hpp>
#endif

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>

namespace dns = Mira::dns;
namespace tcp = Mira::transport::tcp;
using namespace std::chrono_literals;

namespace {

struct Options {
    std::string host;
    std::uint16_t port = 443;
    std::string name;
    std::uint16_t type = dns::type::a;
    dns::doh::Method method = dns::doh::Method::get;
    bool plain = false;
    std::string ca_file;
};

std::optional<std::uint16_t> type_of(std::string_view text) {
    const std::pair<std::string_view, std::uint16_t> known[] = {
        {"A", dns::type::a}, {"AAAA", dns::type::aaaa}, {"CNAME", dns::type::cname},
        {"MX", dns::type::mx}, {"NS", dns::type::ns}, {"TXT", dns::type::txt},
        {"SOA", dns::type::soa}, {"PTR", dns::type::ptr}, {"HTTPS", dns::type::https},
    };
    for (const auto& [label, value] : known)
        if (Mira::http::HeaderMap::names_equal(label, text)) return value;
    unsigned value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error == std::errc{} && end == text.data() + text.size() && value <= 65535)
        return static_cast<std::uint16_t>(value);
    return std::nullopt;
}

std::string describe(const dns::Rdata& data) {
    struct Visitor {
        std::string operator()(const dns::AData& a) const {
            return std::to_string(a.address[0]) + "." + std::to_string(a.address[1]) + "." +
                   std::to_string(a.address[2]) + "." + std::to_string(a.address[3]);
        }
        std::string operator()(const dns::AaaaData& aaaa) const {
            std::string text;
            for (std::size_t i = 0; i < 16; i += 2) {
                char group[8];
                std::snprintf(group, sizeof group, "%s%x", i ? ":" : "",
                              (static_cast<unsigned>(aaaa.address[i]) << 8) | aaaa.address[i + 1]);
                text += group;
            }
            return text;
        }
        std::string operator()(const dns::NameData& name) const { return name.name.to_string(); }
        std::string operator()(const dns::MxData& mx) const {
            return std::to_string(mx.preference) + " " + mx.exchange.to_string();
        }
        std::string operator()(const dns::TxtData& txt) const {
            std::string text;
            for (const auto& piece : txt.strings) text += "\"" + piece + "\" ";
            return text;
        }
        std::string operator()(const dns::SoaData& soa) const {
            return soa.mname.to_string() + " " + soa.rname.to_string() + " " + std::to_string(soa.serial);
        }
        std::string operator()(const dns::RawData& raw) const {
            return "\\# " + std::to_string(raw.bytes.size());
        }
    };
    return std::visit(Visitor{}, data);
}

template<typename Stream>
Mira::Task<Mira::Result<dns::Message>> ask(Stream& stream, const Options& options,
                                           Mira::OperationOptions io) {
    auto name = dns::Name::parse(options.name);
    if (!name) co_return Mira::fail(name.error());
    auto question = dns::make_query(*name, options.type, {.pad_to_block = 128});
    if (!question) co_return Mira::fail(question.error());
    Mira::http::ClientConnection client{stream};
    const auto authority = options.port == 443 ? options.host
                                               : options.host + ":" + std::to_string(options.port);
    co_return co_await dns::doh::query(client, authority, "/dns-query", std::move(*question),
                                       options.method, io);
}

Mira::Task<Mira::Result<dns::Message>> run_query(Mira::EventLoop& loop, Mira::transport::Resolver& resolver,
                                                 const Options& options) {
    tcp::DialOptions dial;
    dial.io.deadline = Mira::Clock::now() + 5s;
    const auto io = dial.io;
    auto socket = co_await tcp::dial(loop, resolver, options.host, options.port, dial);
    if (!socket) co_return Mira::fail(socket.error());
    if (options.plain) co_return co_await ask(*socket, options, io);
#if MIRA_EXAMPLE_TLS
    auto context = Mira::tls::Context::client(options.ca_file, "http/1.1");
    if (!context) co_return Mira::fail(context.error());
    auto stream = Mira::tls::Stream<tcp::Socket>::create(loop, *socket, *context, options.host);
    if (!stream) co_return Mira::fail(stream.error());
    auto established = co_await stream->handshake(io);
    if (!established) co_return Mira::fail(established.error());
    auto answer = co_await ask(*stream, options, io);
    static_cast<void>(co_await stream->shutdown({.deadline = Mira::Clock::now() + 1s}));
    co_return answer;
#else
    co_return Mira::fail(Mira::Errc::not_supported);
#endif
}

Mira::Task<void> run(Mira::EventLoop& loop, Mira::transport::Resolver& resolver, const Options& options,
                     int& status) {
    auto message = co_await run_query(loop, resolver, options);
    if (!message) {
        std::fprintf(stderr, "doh query failed: %s\n", message.error().message().c_str());
        co_return;
    }
    std::printf("RCODE %u\n", static_cast<unsigned>(message->header.rcode));
    for (const auto& record : message->answers)
        std::printf("ANSWER %u %u %s\n", static_cast<unsigned>(record.type), record.ttl,
                    describe(record.data).c_str());
    status = 0;
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    unsigned port = 0;
    if (argc < 4) {
        std::fprintf(stderr, "usage: %s <host> <port> <name> [type] [get|post] [--plain|--ca file]\n", argv[0]);
        return 2;
    }
    options.host = argv[1];
    const std::string_view port_text{argv[2]};
    const auto [end, error] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (error != std::errc{} || end != port_text.data() + port_text.size() || port == 0 || port > 65535)
        return 2;
    options.port = static_cast<std::uint16_t>(port);
    options.name = argv[3];
    for (int i = 4; i < argc; ++i) {
        const std::string_view argument{argv[i]};
        if (argument == "get") options.method = dns::doh::Method::get;
        else if (argument == "post") options.method = dns::doh::Method::post;
        else if (argument == "--plain") options.plain = true;
        else if (argument == "--ca" && i + 1 < argc) options.ca_file = argv[++i];
        else if (auto type = type_of(argument)) options.type = *type;
        else return 2;
    }
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto loop = Mira::EventLoop::create();
    auto resolver = Mira::transport::Resolver::create();
    if (!loop || !resolver) return 1;
    int status = 1;
    const auto ran = loop->run_until_complete(run(*loop, *resolver, options, status));
    return ran ? status : 1;
}
