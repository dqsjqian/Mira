#include "mira/quic/engine.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace Mira;
namespace {
void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
template<class T> T require(Result<T> value) {
    if (!value) throw std::runtime_error(value.error().message());
    return std::move(*value);
}
void require(Result<void> value) {
    if (!value) throw std::runtime_error(value.error().message());
}
struct Log final : quic::QlogSink {
    std::size_t bytes = 0;
    bool final_seen = false;
    void write(std::span<const std::byte> data, bool final) noexcept override {
        bytes += data.size();
        final_seen |= final;
    }
};
void scenario(const char* certificate, const char* key, bool discovery, bool supported,
              quic::CongestionControl algorithm) {
    auto log = std::make_shared<Log>();
    {
        quic::Options c, s;
        c.local = transport::Endpoint::loopback(45100);
        c.remote = transport::Endpoint::loopback(45101);
        c.peer_name = "localhost";
        c.ca_file = certificate;
        c.max_udp_payload = discovery ? 1452 : 1200;
        c.path_mtu_discovery = discovery;
        c.max_datagram_frame_size = 1400;
        c.congestion_control = algorithm;
        c.qlog = log;
        s.local = c.remote;
        s.remote = c.local;
        s.certificate_file = certificate;
        s.private_key_file = key;
        s.max_udp_payload = c.max_udp_payload;
        s.path_mtu_discovery = discovery;
        s.max_datagram_frame_size = supported ? 1400 : 0;
        s.max_queued_datagrams = 1;
        s.max_datagram_bytes = 512;
        std::uint64_t now = 1'000'000'000;
        auto client = require(quic::Engine::client(c, now));
        check(!client.send_datagram({}, now), "DATAGRAM before handshake accepted");
        auto initial = require(client.poll(now));
        auto server = require(quic::Engine::accept(s, initial, now));
        std::size_t largest = initial.size();
        auto drive = [&] {
            now += 10'000'000;
            for (auto* from : {&client, &server}) {
                auto& to = from == &client ? server : client;
                if (from->expiry() <= now) require(from->handle_expiry(now));
                for (int n = 0; n < 32; ++n) {
                    auto packet = require(from->poll(now));
                    if (packet.empty()) break;
                    largest = (std::max)(largest, packet.size());
                    require(to.receive(packet, now));
                }
            }
        };
        for (int n = 0; n < 150; ++n) drive();
        check(client.handshake_complete() && server.handshake_complete(), "handshake incomplete");
        check(log->bytes > 0, "qlog did not observe packets");
        check(largest <= c.max_udp_payload, "packet exceeded configured ceiling");
        check(client.statistics().packets_sent > 0 && client.statistics().packets_received > 0,
              "packet statistics absent");
        if (discovery) {
            check(largest > 1200 && client.statistics().path_udp_payload > 1200,
                  "PMTUD never probed or increased the path payload");
        } else check(client.statistics().path_udp_payload == 1200, "default path changed");
        if (!supported) {
            auto rejected = client.send_datagram({}, now);
            check(!rejected && rejected.error() == Errc::not_supported, "unsupported peer accepted");
            check(!client.closed(), "unsupported DATAGRAM killed connection");
            return;
        }
        const quic::Bytes payload(128, std::byte{0x52});
        auto send = [&](std::span<const std::byte> data, bool drop = false) {
            for (int n = 0; n < 500; ++n) {
                auto output = require(client.send_datagram(data, now));
                if (!output.packet.data.empty() && !drop) require(server.receive(output.packet.data, now));
                if (output.accepted) return;
                drive();
            }
            throw std::runtime_error("DATAGRAM send did not progress");
        };
        send(payload);
        send(payload);
        auto stats = server.statistics();
        check(stats.queued_datagrams == 1 && stats.queued_datagram_bytes == payload.size() &&
              stats.datagrams_dropped == 1, "receive overflow was not bounded and counted");
        auto received = server.take_datagrams();
        check(received.size() == 1 && received[0].data == payload && !received[0].early_data,
              "DATAGRAM payload mismatch");
        check(server.statistics().queued_datagram_bytes == 0, "drain leaked queue budget");
        send({});
        received = server.take_datagrams();
        check(received.size() == 1 && received[0].data.empty(), "empty DATAGRAM lost");
        quic::Bytes oversize(client.max_datagram_payload() + 1);
        auto rejected = client.send_datagram(oversize, now);
        check(!rejected && rejected.error() == std::errc::message_size && !client.closed(),
              "oversized DATAGRAM not rejected locally");
        send(payload, true);
        for (int n = 0; n < 150; ++n) drive();
        check(server.take_datagrams().empty(), "unreliable DATAGRAM was retransmitted");
        const auto id = require(client.open_stream());
        require(client.write(id, payload, true));
        std::size_t bytes = 0;
        for (int n = 0; n < 100 && bytes != payload.size(); ++n) {
            drive();
            for (auto& event : server.take_events()) {
                if (event.kind != quic::Event::Kind::data) continue;
                bytes += event.data.size();
                require(server.consume(event.stream_id, event.data.size()));
            }
        }
        check(bytes == payload.size(), "DATAGRAM loss/overflow blocked reliable stream");
    }
    check(log->final_seen, "qlog final notification missing on destruction");
}
} // namespace
int main(int argc, char** argv) {
    try {
        check(argc == 3, "expected certificate and key");
        auto store = require(quic::MemoryReplayStore::create(1));
        std::array<std::byte, 32> key{};
        check(store->claim(key, 1, 10), "first replay key rejected");
        check(!store->claim(key, 2, 10), "duplicate replay key admitted");
        key[0] = std::byte{1};
        check(!store->claim(key, 3, 11) && store->size() == 1, "full store evicted live replay key");
        check(store->claim(key, 10, 20), "expired replay key not reclaimed");
        check(!store->claim(key, 9, 20), "clock rollback admitted");
        scenario(argv[1], argv[2], false, true, quic::CongestionControl::cubic);
        scenario(argv[1], argv[2], true, true, quic::CongestionControl::reno);
        scenario(argv[1], argv[2], false, false, quic::CongestionControl::bbr);
        quic::Options invalid;
        invalid.local = transport::Endpoint::loopback(45100);
        invalid.remote = transport::Endpoint::loopback(45101);
        invalid.peer_name = "localhost";
        invalid.ca_file = argv[1];
        invalid.max_udp_payload = 1199;
        check(!quic::Engine::client(invalid, 1), "invalid MTU accepted");
        invalid.max_udp_payload = 65528;
        check(!quic::Engine::client(invalid, 1), "oversized MTU accepted");
        std::cout << "QUIC DATAGRAM, MTU discovery, statistics and qlog passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
