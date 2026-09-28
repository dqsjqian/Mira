#include "mira/http3/server.hpp"
#include "mira/transport/udp.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <deque>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace Mira;
using namespace std::chrono_literals;
using quic::Bytes;
using transport::Endpoint;

namespace {
constexpr std::size_t body_budget = 16384;
constexpr std::size_t chunk_size = 4096;
constexpr std::size_t packet_limit = 1200;
constexpr std::size_t queue_limit = 256;
constexpr std::size_t queue_byte_limit = queue_limit * packet_limit;

struct Options {
    std::string certificate, key;
    std::uint64_t seed = 20260928;
    std::size_t clients = 3, payload = 131072, requests = 4, rounds = 0;
    unsigned duration_seconds = 30, round_deadline_seconds = 20;
};
struct Stats {
    std::uint64_t requests_started = 0, requests_passed = 0, rounds = 0, clean_rounds = 0;
    std::uint64_t packets = 0, sent = 0, received = 0, loss = 0, duplicate = 0;
    std::uint64_t delayed = 0, reordered = 0, actual_reorders = 0, would_block = 0;
    std::uint64_t verified_upload_bytes = 0, verified_response_bytes = 0;
    std::uint64_t fair_short_streams = 0, close_quota_rejections = 0, retry_replies = 0, retry_queue_drops = 0;
    std::uint64_t slow_overlap_short_started = 0, slow_overlap_short_completed = 0;
    std::size_t peak_connections = 0, peak_tombstones = 0, peak_routes = 0;
    std::size_t peak_queued_bytes = 0, peak_queued_packets = 0, peak_body_bytes = 0;
    std::size_t peak_application_body_bytes = 0, peak_application_body_events = 0, peak_reserved_bytes = 0;
    std::size_t peak_reserved_queue_entries = 0, peak_close_bytes = 0;
    std::size_t final_connections = 0, final_tombstones = 0, final_routes = 0;
    std::size_t final_reserved_bytes = 0, final_queued_bytes = 0;
};

void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
template<class T> T require(Result<T> result, std::string_view where) {
    if (!result) throw std::runtime_error(std::string(where) + ": " + result.error().message() +
                                          " (" + std::to_string(result.error().value()) + ")");
    return std::move(*result);
}
void require(Result<void> result, std::string_view where) {
    if (!result) throw std::runtime_error(std::string(where) + ": " + result.error().message() +
                                          " (" + std::to_string(result.error().value()) + ")");
}
std::uint64_t now() { return quic::detail::now_ns(); }
std::uint64_t number(std::string_view text) {
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    check(error == std::errc{} && end == text.data() + text.size(), "invalid numeric argument");
    return value;
}
Options parse(int argc, char** argv) {
    Options result;
    for (int i = 1; i < argc; ++i) {
        const std::string_view name(argv[i]);
        check(i + 1 < argc, "argument requires a value");
        const std::string_view value(argv[++i]);
        if (name == "--certificate") result.certificate = value;
        else if (name == "--key") result.key = value;
        else if (name == "--seed") result.seed = number(value);
        else if (name == "--clients") {
            const auto count = number(value);
            check(count >= 1 && count <= 32, "clients must be 1..32");
            result.clients = static_cast<std::size_t>(count);
        } else if (name == "--payload") {
            const auto count = number(value);
            check(count >= 65536 && count <= 64 * 1024 * 1024, "payload must be 65536..67108864 bytes");
            result.payload = static_cast<std::size_t>(count);
        } else if (name == "--requests") {
            const auto count = number(value);
            check(count >= 2 && count <= 8, "requests per client per round must be 2..8");
            result.requests = static_cast<std::size_t>(count);
        } else if (name == "--rounds") {
            const auto count = number(value);
            check(count <= 1000000, "rounds exceeds limit");
            result.rounds = static_cast<std::size_t>(count);
        } else if (name == "--duration-seconds") {
            const auto count = number(value);
            check(count <= 86400, "duration exceeds limit");
            result.duration_seconds = static_cast<unsigned>(count);
        } else if (name == "--round-deadline-seconds") {
            const auto count = number(value);
            check(count >= 1 && count <= 300, "round deadline must be 1..300 seconds");
            result.round_deadline_seconds = static_cast<unsigned>(count);
        } else throw std::runtime_error("unknown argument: " + std::string(name));
    }
    check(!result.certificate.empty() && !result.key.empty(), "certificate and key are required");
    check(result.duration_seconds != 0 || result.rounds != 0, "duration or rounds must be nonzero");
    return result;
}

std::byte pattern(std::uint64_t tag, std::size_t offset) {
    auto value = tag + static_cast<std::uint64_t>(offset) * 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return static_cast<std::byte>((value ^ (value >> 31)) & 255);
}
void verify(std::span<const std::byte> bytes, std::uint64_t tag, std::size_t offset,
            std::size_t total) {
    check(offset <= total && bytes.size() <= total - offset, "body exceeds declared length");
    for (std::size_t i = 0; i < bytes.size(); ++i)
        if (bytes[i] != pattern(tag, offset + i))
            throw std::runtime_error("body byte mismatch at offset " + std::to_string(offset + i));
}
std::string field(const http3::Headers& fields, std::string_view name) {
    for (const auto& item : fields) if (item.name == name) return item.value;
    throw std::runtime_error("missing header: " + std::string(name));
}

struct Packet {
    std::size_t client;
    bool to_server;
    std::uint64_t due, ordinal;
    Bytes bytes;
};
struct FaultQueue {
    explicit FaultQueue(std::uint64_t seed, Stats& value) : random(seed), stats(value) {
        packets.reserve(queue_limit);
    }
    std::mt19937_64 random;
    Stats& stats;
    std::vector<Packet> packets;
    std::size_t bytes = 0;
    std::uint64_t ordinal = 0;
    std::array<std::uint64_t, 64> highest_delivered{};

    bool room() const { return packets.size() + 2 <= queue_limit && bytes + 2 * packet_limit <= queue_byte_limit; }
    void append(std::size_t client, bool to_server, std::uint64_t due, Bytes data) {
        check(packets.size() < queue_limit && data.size() <= queue_byte_limit - bytes,
              "fault queue hard limit exceeded");
        bytes += data.size();
        packets.push_back({client, to_server, due, ++ordinal, std::move(data)});
        stats.peak_queued_bytes = std::max(stats.peak_queued_bytes, bytes);
        stats.peak_queued_packets = std::max(stats.peak_queued_packets, packets.size());
    }
    void enqueue(std::size_t client, bool to_server, Bytes data, bool reliable = false) {
        if (data.empty()) return;
        check(data.size() <= packet_limit, "QUIC packet exceeds harness datagram bound");
        check(room(), "poll attempted without fault queue capacity");
        ++stats.packets;
        auto due = now();
        if (!reliable) {
            if (random() % 1000 < 20) { ++stats.loss; return; }
            if (random() % 1000 < 100) {
                due += 1'000'000 + random() % 3'000'000;
                ++stats.delayed;
            }
            if (random() % 1000 < 80) {
                due += 5'000'000 + random() % 5'000'000;
                ++stats.reordered;
            }
            if (random() % 1000 < 30) {
                append(client, to_server, due + 500'000, data);
                ++stats.duplicate;
            }
        }
        append(client, to_server, due, std::move(data));
    }
    std::optional<Packet> pop(std::uint64_t stamp) {
        const auto first = std::min_element(packets.begin(), packets.end(), [](const Packet& a, const Packet& b) {
            return std::pair(a.due, a.ordinal) < std::pair(b.due, b.ordinal);
        });
        if (first == packets.end() || first->due > stamp) return std::nullopt;
        auto result = std::move(*first);
        bytes -= result.bytes.size();
        packets.erase(first);
        auto& highest = highest_delivered.at(result.client * 2 + (result.to_server ? 0u : 1u));
        if (result.ordinal < highest) ++stats.actual_reorders;
        highest = std::max(highest, result.ordinal);
        return result;
    }
};

struct Stream {
    std::int64_t id;
    std::uint64_t tag;
    std::size_t total, sent = 0, received = 0;
    bool head = false, end = false, done = false;
    bool submitted_with_slow_pending = false;
};
struct PendingBody {
    std::int64_t stream;
    std::uint64_t due;
    Bytes bytes;
};
struct Client {
    transport::udp::Socket socket;
    Endpoint peer;
    std::optional<http3::Engine> engine;
    http3::Server::Id server_id = 0;
    std::vector<Stream> streams;
    std::deque<PendingBody> pending;
    std::size_t pending_bytes = 0;
    bool fair = false;
};
struct ServerStream {
    std::uint64_t tag;
    std::size_t total, received = 0, sent = 0;
    bool end = false, responding = false;
};
using StreamKey = std::pair<http3::Server::Id, std::int64_t>;

class Harness {
public:
    Harness(EventLoop& event_loop, Options options, Stats& statistics)
        : loop(event_loop), config(std::move(options)), stats(statistics), faults(config.seed, stats),
          socket(require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)), "server bind")),
          local(require(socket.local_endpoint(), "server endpoint")),
          shared_budget(config.clients * (4 * body_budget + 4096 * 8 + 1200)),
          server(make_server()) {
        clients.reserve(config.clients);
        for (std::size_t i = 0; i < config.clients; ++i) {
            auto client_socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)), "client bind");
            auto peer = require(client_socket.local_endpoint(), "client endpoint");
            Client client;
            client.socket = std::move(client_socket);
            client.peer = peer;
            clients.push_back(std::move(client));
        }
    }

    Task<void> run() {
        const auto until = Clock::now() + std::chrono::seconds(config.duration_seconds);
        do {
            const auto deadline = Clock::now() + std::chrono::seconds(config.round_deadline_seconds);
            start_round();
            while (!round_complete() || !bodies_drained() || !faults.packets.empty()) {
                if (Clock::now() >= deadline) throw std::runtime_error(progress_message());
                co_await pump(false, deadline);
                if (Clock::now() >= deadline) throw std::runtime_error(progress_message());
            }
            if (Clock::now() >= deadline) throw std::runtime_error(progress_message());
            for (const auto& client : clients) check(client.fair, "short streams starved behind slow large stream");
            for (const auto& [key, stream] : server_streams) {
                (void)key;
                check(stream.end && stream.received == stream.total && stream.sent == stream.total,
                      "server request/response incomplete at close");
            }
            const auto close_deadline = Clock::now() + 15s;
            for (std::size_t i = 0; i < clients.size(); ++i) {
                check(faults.room(), "close queue is full");
                auto packet = require(server.close(clients[i].server_id, 0, now()), "server close");
                faults.enqueue(i, false, std::move(packet.data), true);
            }
            observe();
            check(server.size() == 0 && server.tombstone_count() == config.clients,
                  "close did not preserve bounded tombstones");
            co_await probe_closing_quota(close_deadline);
            while (!clients_closed() || !faults.packets.empty() || server.tombstone_count()) {
                check(Clock::now() < close_deadline, "close/tombstone drain deadline exceeded");
                co_await pump(true, close_deadline);
                check(Clock::now() < close_deadline, "close/tombstone drain deadline exceeded after pump");
            }
            check(Clock::now() < close_deadline, "close/tombstone drain completed after deadline");
            server_streams.clear();
            observe();
            check(!server.size() && !server.route_count() && !server.reserved_payload_bytes() &&
                      !server.reserved_queue_entries() && !shared_budget.used(),
                  "round leaked connection, CID route, or reservation");
            ++stats.rounds;
            ++stats.clean_rounds;
            for (auto& client : clients) client.engine.reset();
            if (config.rounds && stats.rounds >= config.rounds) break;
        } while (Clock::now() < until || config.duration_seconds == 0);
        observe();
    }

private:
    EventLoop& loop;
    Options config;
    Stats& stats;
    FaultQueue faults;
    transport::udp::Socket socket;
    Endpoint local;
    ResourceBudget shared_budget;
    http3::Server server;
    std::vector<Client> clients;
    std::map<StreamKey, ServerStream> server_streams;
    std::array<std::byte, 65536> receive_buffer{};
    std::array<std::byte, chunk_size> scratch{};

    static http3::Limits h3_limits() {
        http3::Limits result;
        result.max_buffered_body = body_budget;
        result.max_header_bytes = 4096;
        result.max_events = 128;
        result.max_streams = 8;
        return result;
    }
    quic::Options transport_options() const {
        quic::Options result;
        result.local = local;
        result.max_buffered_bytes = body_budget;
        result.max_streams = 8;
        result.idle_timeout_ns = 30'000'000'000;
        return result;
    }
    http3::Server make_server() {
        auto options = transport_options();
        options.certificate_file = config.certificate;
        options.private_key_file = config.key;
        quic::ListenerLimits limits;
        limits.max_connections = config.clients;
        limits.max_closing_connections = config.clients;
        limits.max_payload_bytes = shared_budget.limit();
        limits.max_queue_entries = config.clients * (8192 + 256);
        quic::RetryOptions retry;
        retry.policy = quic::RetryPolicy::required;
        return require(http3::make_server(options, limits, h3_limits(), shared_budget, retry), "make server");
    }
    http3::Engine make_client(const Endpoint& peer) const {
        auto options = transport_options();
        options.local = peer;
        options.remote = local;
        options.ca_file = config.certificate;
        options.peer_name = "localhost";
        return require(http3::Engine::create(require(quic::Engine::client(options, now()), "QUIC client"),
                                               false, h3_limits()), "HTTP/3 client");
    }
    void start_round() {
        check(server.size() == 0 && server.tombstone_count() == 0 && faults.packets.empty(),
              "new round started before draining");
        for (auto& client : clients) {
            client.engine.emplace(make_client(client.peer));
            client.server_id = 0;
            client.streams.clear();
            check(client.pending.empty() && client.pending_bytes == 0, "unconsumed slow body at churn");
            client.fair = false;
        }
    }
    void submit(Client& client, std::size_t index) {
        if (!client.engine->ready() || client.streams.size() == config.requests) return;
        if (!client.streams.empty()) {
            if (client.pending_bytes == 0) return;
            check(client.streams.front().head && !client.streams.front().end && !client.streams.front().done,
                  "short stream submission did not overlap an unfinished slow response");
        }
        const auto target = client.streams.empty() ? std::size_t{1} : config.requests;
        for (std::size_t i = client.streams.size(); i < target; ++i) {
            const auto tag = config.seed ^ ((stats.rounds + 1) * 0x9e3779b97f4a7c15ULL) ^
                             (static_cast<std::uint64_t>(index) << 16) ^ static_cast<std::uint64_t>(i);
            const auto total = i == 0 ? config.payload : 257 + 31 * i;
            http3::Headers fields{{":method", "POST"}, {":scheme", "https"}, {":authority", "localhost"},
                                 {":path", "/soak"}, {"content-length", std::to_string(total)},
                                 {"x-soak-tag", std::to_string(tag)}};
            const auto id = require(client.engine->request_stream(fields), "stream request");
            client.streams.push_back(Stream{id, tag, total});
            if (i != 0) {
                check(client.pending_bytes > 0, "short request started without slow-consumer backlog");
                client.streams.back().submitted_with_slow_pending = true;
                ++stats.slow_overlap_short_started;
            }
            ++stats.requests_started;
        }
    }
    void write_chunk(http3::Engine& engine, std::int64_t id, std::uint64_t tag,
                     std::size_t& offset, std::size_t total, std::size_t available) {
        check(offset <= available && available <= total, "invalid streaming availability");
        if (offset == available) return;
        const auto count = std::min(chunk_size, available - offset);
        for (std::size_t i = 0; i < count; ++i) scratch[i] = pattern(tag, offset + i);
        auto result = engine.write_body(id, std::span(scratch).first(count), offset + count == total);
        if (result) offset += count;
        else if (result.error() == Errc::would_block) ++stats.would_block;
        else require(std::move(result), "stream write");
    }
    Stream& client_stream(Client& client, std::int64_t id) {
        auto found = std::find_if(client.streams.begin(), client.streams.end(),
                                  [id](const Stream& stream) { return stream.id == id; });
        check(found != client.streams.end(), "unknown response stream");
        return *found;
    }
    void consume_client(Client& client, std::int64_t id, const Bytes& bytes) {
        auto& stream = client_stream(client, id);
        verify(bytes, stream.tag, stream.received, stream.total);
        stream.received += bytes.size();
        stats.verified_response_bytes += bytes.size();
        require(client.engine->consume(id, bytes.size()), "client consume");
    }
    void client_events(Client& client) {
        while (!client.pending.empty() && client.pending.front().due <= now()) {
            auto pending = std::move(client.pending.front());
            client.pending.pop_front();
            consume_client(client, pending.stream, pending.bytes);
            client.pending_bytes -= pending.bytes.size();
        }
        auto events = client.engine->take_events();
        observe_application(events);
        for (auto& event : events) {
            auto& stream = client_stream(client, event.stream_id);
            if (event.kind == http3::Event::Kind::headers) {
                check(!stream.head && field(event.fields, ":status") == "200" &&
                          number(field(event.fields, "content-length")) == stream.total,
                      "incorrect or duplicate response head");
                stream.head = true;
            } else if (event.kind == http3::Event::Kind::body) {
                check(stream.head, "response body before headers");
                if (event.stream_id == client.streams.front().id) {
                    check(event.data.size() <= body_budget - client.pending_bytes && client.pending.size() < 128,
                          "slow consumer hard payload/event limit exceeded");
                    client.pending_bytes += event.data.size();
                    client.pending.push_back({event.stream_id, now() + 20'000'000, std::move(event.data)});
                } else consume_client(client, event.stream_id, event.data);
            } else if (event.kind == http3::Event::Kind::end) {
                check(stream.head && !stream.end, "incorrect or duplicate response end");
                stream.end = true;
            } else throw std::runtime_error("unexpected reset or GOAWAY");
        }
        for (auto& stream : client.streams) {
            if (stream.done || !stream.end || stream.received != stream.total) continue;
            stream.done = true;
            ++stats.requests_passed;
            if (stream.submitted_with_slow_pending && !client.streams.front().end &&
                !client.streams.front().done && client.streams.front().received < client.streams.front().total) {
                client.fair = true;
                ++stats.fair_short_streams;
                ++stats.slow_overlap_short_completed;
            }
        }
    }
    void server_events() {
        for (const auto id : server.connections()) {
            auto* engine = server.connection(id);
            auto events = engine->take_events();
            observe_application(events);
            for (const auto& event : events) {
                const StreamKey key{id, event.stream_id};
                if (event.kind == http3::Event::Kind::headers) {
                    check(server_streams.size() < config.clients * config.requests,
                          "server application stream map exceeded hard limit");
                    check(field(event.fields, ":method") == "POST" && field(event.fields, ":path") == "/soak",
                          "request headers corrupted");
                    const auto total = number(field(event.fields, "content-length"));
                    check(total <= config.payload, "invalid request length");
                    auto [it, inserted] = server_streams.emplace(key, ServerStream{
                        number(field(event.fields, "x-soak-tag")), static_cast<std::size_t>(total)});
                    check(inserted, "duplicate request head");
                    require(engine->respond_stream(event.stream_id,
                        {{":status", "200"}, {"content-length", std::to_string(total)}}), "stream response");
                    it->second.responding = true;
                } else {
                    auto found = server_streams.find(key);
                    check(found != server_streams.end(), "request body before head");
                    auto& stream = found->second;
                    if (event.kind == http3::Event::Kind::body) {
                        verify(event.data, stream.tag, stream.received, stream.total);
                        stream.received += event.data.size();
                        stats.verified_upload_bytes += event.data.size();
                        require(engine->consume(event.stream_id, event.data.size()), "server consume");
                    } else if (event.kind == http3::Event::Kind::end) {
                        check(!stream.end && stream.received == stream.total, "truncated or duplicate request end");
                        stream.end = true;
                    } else throw std::runtime_error("unexpected request reset or GOAWAY");
                }
            }
        }
    }
    void observe_application(const std::vector<http3::Event>& events) {
        std::size_t used = 0, entries = events.size();
        check(events.size() <= 128, "engine event batch exceeded hard limit");
        for (const auto& client : clients) {
            used += client.pending_bytes;
            entries += client.pending.size();
        }
        for (const auto& event : events) used += event.data.size();
        check(used <= (config.clients + 1) * body_budget && entries <= (config.clients + 1) * 128,
              "application-held body/event accounting exceeded hard limit");
        stats.peak_application_body_bytes = std::max(stats.peak_application_body_bytes, used);
        stats.peak_application_body_events = std::max(stats.peak_application_body_events, entries);
    }
    void observe() {
        std::size_t queued = 0;
        for (const auto& client : clients) if (client.engine) {
            check(client.engine->queued_body_bytes() <= body_budget, "client retained body exceeded hard limit");
            queued += client.engine->queued_body_bytes();
        }
        for (auto id : server.connections()) {
            const auto size = server.connection(id)->queued_body_bytes();
            check(size <= body_budget, "server retained body exceeded hard limit");
            queued += size;
        }
        check(server.size() <= config.clients && server.size() + server.tombstone_count() <= config.clients,
              "connection/closing quota exceeded");
        check(server.reserved_payload_bytes() <= shared_budget.limit() &&
                  shared_budget.used() == server.reserved_payload_bytes(), "reservation accounting mismatch");
        stats.peak_body_bytes = std::max(stats.peak_body_bytes, queued);
        stats.peak_connections = std::max(stats.peak_connections, server.size());
        stats.peak_tombstones = std::max(stats.peak_tombstones, server.tombstone_count());
        stats.peak_routes = std::max(stats.peak_routes, server.route_count());
        stats.peak_reserved_bytes = std::max(stats.peak_reserved_bytes, server.reserved_payload_bytes());
        stats.peak_reserved_queue_entries = std::max(stats.peak_reserved_queue_entries, server.reserved_queue_entries());
        stats.peak_close_bytes = std::max(stats.peak_close_bytes, server.reserved_close_bytes());
        stats.final_connections = server.size();
        stats.final_tombstones = server.tombstone_count();
        stats.final_routes = server.route_count();
        stats.final_reserved_bytes = shared_budget.used();
        stats.final_queued_bytes = faults.bytes;
    }
    std::size_t peer_index(const Endpoint& peer) const {
        for (std::size_t i = 0; i < clients.size(); ++i) if (clients[i].peer == peer) return i;
        throw std::runtime_error("dispatcher changed fixed peer");
    }
    Task<void> deliver(Packet packet, bool closing, Clock::time_point deadline) {
        check(Clock::now() < deadline, "UDP delivery started after phase deadline");
        auto& client = clients.at(packet.client);
        std::size_t sent = 0;
        transport::udp::Datagram received;
        if (packet.to_server) {
            sent = require(co_await client.socket.send_to(packet.bytes, local,
                {.deadline = std::min(Clock::now() + 1s, deadline)}), "client UDP send");
            received = require(co_await socket.receive_from(receive_buffer,
                {.deadline = std::min(Clock::now() + 1s, deadline)}), "server UDP receive");
            check(received.peer == client.peer, "client UDP source changed");
        } else {
            sent = require(co_await socket.send_to(packet.bytes, client.peer,
                {.deadline = std::min(Clock::now() + 1s, deadline)}), "server UDP send");
            received = require(co_await client.socket.receive_from(receive_buffer,
                {.deadline = std::min(Clock::now() + 1s, deadline)}), "client UDP receive");
            check(received.peer == local, "server UDP source changed");
        }
        check(Clock::now() < deadline, "UDP receive completed after phase deadline");
        ++stats.sent;
        ++stats.received;
        check(sent == packet.bytes.size() && received.size == packet.bytes.size(), "UDP datagram truncated");
        const auto data = std::span(receive_buffer).first(received.size);
        check(std::equal(data.begin(), data.end(), packet.bytes.begin()), "UDP datagram bytes changed");
        if (packet.to_server) {
            const auto before_size = server.size();
            const auto before_reserved = server.reserved_payload_bytes();
            const auto before_routes = server.route_count();
            auto result = require(server.ingest(received.peer, data, now()), "server ingest");
            if (result.kind == http3::Server::Ingest::Kind::retry) {
                check(result.reply && result.reply->peer == client.peer && !result.reply->connection_id &&
                          !result.connection_id && result.reply->data.size() <= packet.bytes.size(),
                      "invalid Retry datagram");
                check(server.size() == before_size && server.reserved_payload_bytes() == before_reserved &&
                          server.route_count() == before_routes, "Retry allocated connection state");
                ++stats.retry_replies;
                if (faults.room()) faults.enqueue(packet.client, false, std::move(result.reply->data));
                else ++stats.retry_queue_drops;
            }
            if (result.kind == http3::Server::Ingest::Kind::admitted) {
                check(!closing && client.server_id == 0, "duplicate or late connection admission");
                client.server_id = result.connection_id;
            }
            if (!closing && result.kind == http3::Server::Ingest::Kind::removed)
                throw std::runtime_error("connection removed before requests completed");
        } else if (!client.engine->closed()) require(client.engine->receive(data, now()), "client ingest");
        observe();
        check(Clock::now() < deadline, "UDP ingest completed after phase deadline");
    }
    Task<void> pump(bool closing, Clock::time_point deadline) {
        check(Clock::now() < deadline, "pump started after phase deadline");
        require(server.handle_expiry(now()), "server expiry");
        for (auto& client : clients) {
            if (!client.engine->closed() && client.engine->expiry() <= now())
                require(client.engine->handle_expiry(now()), "client expiry");
            if (!closing) check(!client.engine->closed(), "client closed before completion");
        }
        if (!closing) {
            server_events();
            for (std::size_t i = 0; i < clients.size(); ++i) {
                auto& client = clients[i];
                submit(client, i);
                client_events(client);
                for (auto& stream : client.streams)
                    write_chunk(*client.engine, stream.id, stream.tag, stream.sent, stream.total, stream.total);
            }
            for (auto& [key, stream] : server_streams) if (stream.responding) {
                auto* engine = server.connection(key.first);
                check(engine != nullptr, "server connection expired before completion");
                write_chunk(*engine, key.second, stream.tag, stream.sent, stream.total, stream.received);
            }
        }
        observe();
        for (std::size_t i = 0; i < clients.size(); ++i) {
            auto& engine = *clients[i].engine;
            if (engine.closed()) continue;
            for (unsigned burst = 0; burst < 4 && faults.room(); ++burst) {
                auto packet = require(engine.poll(now()), "client poll");
                if (packet.empty()) break;
                faults.enqueue(i, true, std::move(packet));
            }
        }
        for (std::size_t burst = 0; burst < config.clients * 4 && faults.room(); ++burst) {
            auto packet = require(server.poll(now()), "server poll");
            if (!packet) break;
            const auto index = peer_index(packet->peer);
            faults.enqueue(index, false, std::move(packet->data));
        }
        for (unsigned burst = 0; burst < 64; ++burst) {
            auto packet = faults.pop(now());
            if (!packet) break;
            co_await deliver(std::move(*packet), closing, deadline);
            check(Clock::now() < deadline, "UDP delivery completed after phase deadline");
        }
        observe();
        require(co_await loop.sleep_for(1ms, {.deadline = std::min(Clock::now() + 1s, deadline)}), "pump timer");
        check(Clock::now() < deadline, "pump completed after phase deadline");
    }
    Task<void> probe_closing_quota(Clock::time_point deadline) {
        check(Clock::now() < deadline, "closing quota probe started after deadline");
        auto probe_socket = require(transport::udp::Socket::bind(loop, Endpoint::loopback(0)), "probe bind");
        const auto peer = require(probe_socket.local_endpoint(), "probe endpoint");
        auto probe = make_client(peer);
        auto packet = require(probe.poll(now()), "probe Initial");
        check(!packet.empty(), "probe has no Initial");
        const auto sent = require(co_await probe_socket.send_to(packet, local,
            {.deadline = std::min(Clock::now() + 1s, deadline)}), "probe send");
        auto input = require(co_await socket.receive_from(receive_buffer,
            {.deadline = std::min(Clock::now() + 1s, deadline)}), "probe receive");
        check(Clock::now() < deadline, "closing quota probe receive completed after deadline");
        check(sent == packet.size() && input.size == packet.size() && input.peer == peer,
              "probe UDP datagram mismatch");
        const auto before = server.reserved_payload_bytes();
        auto result = require(server.ingest(input.peer, std::span(receive_buffer).first(input.size), now()),
                              "closing quota probe");
        check(result.kind == http3::Server::Ingest::Kind::dropped && server.size() == 0 &&
                  server.reserved_payload_bytes() == before, "closing quota admitted a new connection");
        ++stats.close_quota_rejections;
        ++stats.sent;
        ++stats.received;
        observe();
        check(Clock::now() < deadline, "closing quota probe completed after deadline");
    }
    bool round_complete() const {
        for (const auto& client : clients) {
            if (client.streams.size() != config.requests) return false;
            for (const auto& stream : client.streams) if (!stream.done) return false;
        }
        return true;
    }
    bool bodies_drained() {
        for (const auto& client : clients)
            if (client.engine->queued_body_bytes() || client.pending_bytes) return false;
        for (auto id : server.connections()) if (server.connection(id)->queued_body_bytes()) return false;
        return true;
    }
    bool clients_closed() const {
        return std::all_of(clients.begin(), clients.end(), [](const Client& client) { return client.engine->closed(); });
    }
    std::string progress_message() const {
        std::string result = "round deadline: passed=" + std::to_string(stats.requests_passed) +
                             " started=" + std::to_string(stats.requests_started);
        for (std::size_t i = 0; i < clients.size(); ++i) {
            result += " client=" + std::to_string(i);
            for (const auto& stream : clients[i].streams)
                result += " stream=" + std::to_string(stream.id) + ":" + std::to_string(stream.sent) +
                          "/" + std::to_string(stream.received) + "/" + std::to_string(stream.total);
        }
        return result;
    }
};

std::string json_quote(std::string_view text) {
    std::string output = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (const char ch : text) {
        const auto byte = static_cast<unsigned char>(ch);
        if (ch == '"' || ch == '\\') { output += '\\'; output += ch; }
        else if (byte < 32) { output += "\\u00"; output += hex[byte >> 4]; output += hex[byte & 15]; }
        else output += ch;
    }
    return output + '"';
}
void summary(const Options& config, const Stats& stats, double runtime, const std::string& error) {
    std::cout << "{\"kind\":\"h3_soak_summary\",\"transport\":\"real_udp_loopback\",\"pass\":"
              << (error.empty() ? "true" : "false") << ",\"seed\":" << config.seed
              << ",\"actual_runtime_seconds\":" << runtime << ",\"requested_duration_seconds\":" << config.duration_seconds
              << ",\"clients\":" << config.clients << ",\"payload\":" << config.payload
              << ",\"requests_per_client_per_round\":" << config.requests
              << ",\"requests_started\":" << stats.requests_started << ",\"requests_passed\":" << stats.requests_passed
              << ",\"rounds\":" << stats.rounds << ",\"clean_rounds\":" << stats.clean_rounds
              << ",\"faults\":{\"loss\":" << stats.loss << ",\"duplicate\":" << stats.duplicate
              << ",\"delay\":" << stats.delayed << ",\"reorder\":" << stats.reordered
              << ",\"actual_reorders\":" << stats.actual_reorders << "}"
              << ",\"packets_generated\":" << stats.packets << ",\"udp_sent\":" << stats.sent
              << ",\"udp_received\":" << stats.received << ",\"would_block\":" << stats.would_block
              << ",\"verified_upload_bytes\":" << stats.verified_upload_bytes
              << ",\"verified_response_bytes\":" << stats.verified_response_bytes
              << ",\"fair_short_streams\":" << stats.fair_short_streams
              << ",\"slow_overlap_short_started\":" << stats.slow_overlap_short_started
              << ",\"slow_overlap_short_completed\":" << stats.slow_overlap_short_completed
              << ",\"close_quota_rejections\":" << stats.close_quota_rejections
              << ",\"retry_replies\":" << stats.retry_replies << ",\"retry_queue_drops\":" << stats.retry_queue_drops
              << ",\"retry_required\":true"
              << ",\"peaks\":{\"connections\":" << stats.peak_connections << ",\"tombstones\":" << stats.peak_tombstones
              << ",\"routes\":" << stats.peak_routes << ",\"queued_bytes\":" << stats.peak_queued_bytes
              << ",\"queued_packets\":" << stats.peak_queued_packets << ",\"retained_h3_body_bytes\":" << stats.peak_body_bytes
              << ",\"application_body_bytes\":" << stats.peak_application_body_bytes
              << ",\"application_body_events\":" << stats.peak_application_body_events
              << ",\"reserved_payload_bytes\":" << stats.peak_reserved_bytes
              << ",\"reserved_queue_entries\":" << stats.peak_reserved_queue_entries
              << ",\"reserved_close_bytes\":" << stats.peak_close_bytes << "}"
              << ",\"limits\":{\"fault_queue_bytes\":" << queue_byte_limit << ",\"fault_queue_packets\":" << queue_limit
              << ",\"body_bytes_per_engine\":" << body_budget
              << ",\"application_body_bytes\":" << (config.clients + 1) * body_budget
              << ",\"application_body_events\":" << (config.clients + 1) * 128
              << ",\"inflight_packet_bytes\":" << packet_limit
              << ",\"stream_records\":" << config.clients * config.requests
              << ",\"scratch_bytes\":" << chunk_size << ",\"udp_receive_buffer_bytes\":65536}"
              << ",\"final\":{\"connections\":" << stats.final_connections << ",\"tombstones\":" << stats.final_tombstones
              << ",\"routes\":" << stats.final_routes << ",\"reserved_payload_bytes\":" << stats.final_reserved_bytes
              << ",\"queued_bytes\":" << stats.final_queued_bytes << "}"
              << ",\"rss_cap_claimed\":false,\"error\":" << json_quote(error) << "}\n";
}
}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "h3_soak --certificate PEM --key PEM [--seed N] [--duration-seconds 30] "
                     "[--clients 3] [--payload 131072] [--requests 4] [--rounds N] [--round-deadline-seconds 20]\n";
        return 0;
    }
    Options config;
    Stats stats;
    const auto started = Clock::now();
    std::string error;
    try {
        config = parse(argc, argv);
        auto loop = require(EventLoop::create(), "event loop");
        Harness harness(loop, config, stats);
        require(loop.run_until_complete(harness.run()), "run");
        check(stats.requests_started == stats.requests_passed && stats.rounds > 0 &&
                  stats.rounds == stats.clean_rounds, "incomplete final accounting");
    } catch (const std::exception& failure) {
        error = failure.what();
        std::cerr << error << '\n';
    }
    summary(config, stats, std::chrono::duration<double>(Clock::now() - started).count(), error);
    return error.empty() ? 0 : 1;
}
