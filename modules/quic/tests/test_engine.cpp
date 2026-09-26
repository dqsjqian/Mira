#include "mira/quic/engine.hpp"

#include <ngtcp2/ngtcp2.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>
using namespace Mira;
using quic::Engine;
template<class T>
T require(quic::Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message() + " (" + std::to_string(value.error().value()) +
                                 ")");
    return std::move(*value);
}
void require(quic::Result<void> value) {
    if (!value) throw std::runtime_error(value.error().message());
}
/// Test payloads are library-typed (`std::byte`) end to end; `wire` is a
/// plain span view, kept so call sites read uniformly.
std::span<const std::byte> wire(const quic::Bytes& bytes) {
    return {bytes.data(), bytes.size()};
}
void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}
int main(int argc, char** argv) {
    std::string mode = argc > 3 ? argv[3] : "normal";
    bool negative = mode == "bad-host" || mode == "untrusted" || mode == "bad-alpn";
    bool handshake_phase = true;
    try {
        if (argc < 3) return 2;
        quic::Options co, so;
        co.local = transport::Endpoint::loopback(44330);
        co.remote = transport::Endpoint::loopback(44331);
        co.ca_file = argv[1];
        co.peer_name = mode == "bad-host" ? "wrong.example" : "localhost";
        if (mode == "untrusted") co.ca_file.clear();
        if (mode == "bad-alpn") co.alpn = "not-h3";
        if (mode == "stream-limit") so.max_streams = 1;
        so.local = co.remote;
        so.remote = co.local;
        so.certificate_file = argv[1];
        so.private_key_file = argv[2];
        std::uint64_t now = 1'000'000'000;
        auto client = require(Engine::client(co, now));
        auto packet = require(client.poll(now));
        check(!packet.empty(), "missing initial");
        auto server = require(Engine::accept(so, packet, now));
        int counter = 0, dropped = 0;
        bool dropped_handshake = false;
        auto drive = [&] {
            std::vector<quic::Bytes> cp, sp;
            for (int k = 0; k < 32; ++k) {
                auto p = require(client.poll(now));
                if (p.empty()) break;
                cp.push_back(std::move(p));
            }
            for (int k = 0; k < 32; ++k) {
                auto p = require(server.poll(now));
                if (p.empty()) break;
                sp.push_back(std::move(p));
            }
            if (mode == "chaos") {
                std::reverse(cp.begin(), cp.end());
                std::reverse(sp.begin(), sp.end());
            }
            auto deliver = [&](Engine& peer, std::vector<quic::Bytes>& packets) {
                for (auto& p : packets) {
                    if (mode == "chaos" && ++counter % 17 == 0 && dropped < 10) {
                        ++dropped;
                        continue;
                    }
                    require(peer.receive(p, now));
                    if (mode == "chaos" && counter % 13 == 0) require(peer.receive(p, now));
                }
            };
            deliver(server, cp);
            if (mode == "chaos" && !dropped_handshake && !sp.empty()) {
                sp.clear();
                dropped_handshake = true;
                ++dropped;
            }
            deliver(client, sp);
            now += 1'000'000;
            if (client.expiry() <= now) require(client.handle_expiry(now));
            if (server.expiry() <= now) require(server.handle_expiry(now));
        };
        for (int i = 0; i < 10000 && !(client.handshake_complete() && server.handshake_complete());
             ++i)
            drive();
        check(client.handshake_complete() && server.handshake_complete(), "handshake incomplete");
        handshake_phase = false;
        check(!negative, "错误证书/ALPN 居然握手成功");
        check(client.negotiated_protocol() == "h3" && server.negotiated_protocol() == "h3",
              "wrong ALPN");
        if (mode == "stream-limit") {
            // 服务端只放行 1 个 bidi 流。双向 FIN 后流关闭，但未消费的
            // 接收数据保留记录期间对端额度不得归还；consume 清空记录后
            // 才补发 MAX_STREAMS。
            auto first = require(client.open_stream());
            quic::Bytes small(1024, std::byte{0xa5});
            require(client.write(first, wire(small), true));
            bool fin = false;
            std::size_t got = 0;
            for (int i = 0; i < 10000 && !fin; ++i) {
                drive();
                for (auto& e : server.take_events())
                    if (e.kind == quic::Event::Kind::data) {
                        got += e.data.size();
                        fin |= e.fin;  // 故意不 consume：记录保留，额度不归还。
                    }
                client.take_events();
            }
            check(fin && got == small.size(), "首流未完整抵达");
            require(server.write(first, {}, true));  // 回 FIN，双向关闭流 0。
            for (int i = 0; i < 2000; ++i) drive();  // 等 ACK 触发 stream_close。
            auto blocked = client.open_stream();
            check(!blocked && blocked.error().value() == NGTCP2_ERR_STREAM_ID_BLOCKED,
                  "未消费的关闭流已归还对端额度");
            require(server.consume(first, got));  // 清空记录，触发补发额度。
            bool reopened = false;
            for (int i = 0; i < 2000 && !reopened; ++i) {
                drive();
                reopened = client.open_stream().has_value();
            }
            check(reopened, "consume 后对端额度未恢复");
            std::cout << "QUIC stream-limit 延迟归还额度通过\n";
            return 0;
        }
        auto id = require(client.open_stream());
        quic::Bytes data(200000, std::byte{0x5a});
        require(client.write(id, wire(data), true));
        check(!client.write(id, data, false), "FIN 后仍可写");
        std::size_t total = 0;
        bool fin = false;
        for (int i = 0; i < 10000 && !fin; ++i) {
            drive();
            for (auto& e : server.take_events())
                if (e.kind == quic::Event::Kind::data) {
                    check(
                        std::all_of(e.data.begin(), e.data.end(), [](std::byte b) { return b == std::byte{0x5a}; }),
                        "payload corrupted");
                    total += e.data.size();
                    fin |= e.fin;
                    require(server.consume(e.stream_id, e.data.size()));
                }
            client.take_events();
        }
        check(total == data.size() && fin, "stream incomplete");
        require(server.write(id, wire(data), true));
        total = 0;
        fin = false;
        for (int i = 0; i < 10000 && !fin; ++i) {
            drive();
            for (auto& e : client.take_events())
                if (e.kind == quic::Event::Kind::data) {
                    check(
                        std::all_of(e.data.begin(), e.data.end(), [](std::byte b) { return b == std::byte{0x5a}; }),
                        "response corrupted");
                    total += e.data.size();
                    fin |= e.fin;
                    require(client.consume(e.stream_id, e.data.size()));
                }
            server.take_events();
        }
        check(total == data.size() && fin, "response incomplete");
        auto cancel_id = require(client.open_stream());
        require(client.write(cancel_id, wire(data), false));
        drive();
        for (auto& e : server.take_events())
            if (e.kind == quic::Event::Kind::data)
                require(server.consume(e.stream_id, e.data.size()));
        require(client.cancel(cancel_id, 0x10c));
        check(!client.write(cancel_id, {}, true), "取消后仍可写");
        bool reset = false;
        for (int i = 0; i < 2000 && !reset; ++i) {
            drive();
            client.take_events();
            for (auto& e : server.take_events()) {
                if (e.kind == quic::Event::Kind::data)
                    require(server.consume(e.stream_id, e.data.size()));
                if (e.kind == quic::Event::Kind::reset && e.stream_id == cancel_id &&
                    e.value == 0x10c)
                    reset = true;
            }
        }
        check(reset, "RESET_STREAM 未抵达");
        auto other = require(client.open_stream());
        require(client.write(other, {}, true));
        auto over = require(client.open_stream());
        quic::Bytes huge(co.max_buffered_bytes + 1);
        check(!client.write(over, wire(huge), false), "发送预算未执行");
        auto close = require(client.close(0, now));
        check(!close.empty(), "close 未生成数据报");
        require(server.receive(close, now));
        check(server.closed(), "远端未进入 draining");
        check(!client.poll(now), "关闭后仍可发送");
        if (mode == "chaos") check(dropped > 0, "丢包注入未触发");
        std::cout << "QUIC " << mode << " TLS1.3 双向200KB、取消、预算、关闭通过\n";
    } catch (const std::exception& ex) {
        if (negative && handshake_phase &&
            std::string(ex.what()).find("ERR_CRYPTO") != std::string::npos) {
            std::cout << "QUIC " << mode << " 拒绝握手: " << ex.what() << '\n';
            return 0;
        }
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
