#include "mira/http3/engine.hpp"

#include <algorithm>
#include <iostream>
#include <set>
#include <stdexcept>
using namespace Mira;
/// Payloads are library-typed (`std::byte`) end to end; `wire` is a plain
/// span view kept for uniform call sites.
std::span<const std::byte> wire(const quic::Bytes& bytes) {
    return {bytes.data(), bytes.size()};
}

template<class T>
T require(quic::Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message() + " (" + std::to_string(value.error().value()) +
                                 ")");
    return std::move(*value);
}
void require(quic::Result<void> value) {
    if (!value)
        throw std::runtime_error(value.error().message() + " (" + std::to_string(value.error().value()) +
                                 ")");
}
int main(int argc, char** argv) {
    try {
        if (argc < 3) return 2;
        bool chaos = argc > 3 && std::string(argv[3]) == "chaos";
        int drops = 0, packets = 0;
        quic::Options co, so;
        co.local = transport::Endpoint::loopback(44330);
        co.remote = transport::Endpoint::loopback(44331);
        co.ca_file = argv[1];
        co.peer_name = "localhost";
        so.local = co.remote;
        so.remote = co.local;
        so.certificate_file = argv[1];
        so.private_key_file = argv[2];
        if (argc > 3 && std::string(argv[3]) == "small-budget") {
            co.max_buffered_bytes = 4096;
            so.max_buffered_bytes = 4096;
        }
        std::uint64_t now = 1'000'000'000;
        auto cq = require(quic::Engine::client(co, now));
        auto initial = require(cq.poll(now));
        auto sq = require(quic::Engine::accept(so, initial, now));
        auto client = require(http3::Engine::create(std::move(cq), false));
        auto server = require(http3::Engine::create(std::move(sq), true));
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
            if (chaos) {
                std::reverse(cp.begin(), cp.end());
                std::reverse(sp.begin(), sp.end());
            }
            auto deliver = [&](http3::Engine& peer, auto& batch) {
                for (auto& p : batch) {
                    if (chaos && ++packets % 19 == 0 && drops < 12) {
                        ++drops;
                        continue;
                    }
                    require(peer.receive(p, now));
                }
            };
            deliver(server, cp);
            deliver(client, sp);
            now += 1'000'000;
            if (client.expiry() <= now) require(client.handle_expiry(now));
            if (server.expiry() <= now) require(server.handle_expiry(now));
        };
        for (int i = 0; i < 1000 && !(client.ready() && server.ready()); ++i)
            drive();
        if (!client.ready() || !server.ready()) throw std::runtime_error("HTTP3 未就绪");
        for (std::int64_t invalid_id : {std::int64_t{-1}, INT64_MAX, std::int64_t{1} << 62,
                                       std::int64_t{2}, std::int64_t{3}, std::int64_t{4000}}) {
            if (client.cancel(invalid_id) || server.cancel(invalid_id))
                throw std::runtime_error("HTTP3 接受了非法取消流编号");
        }
        for (int round = 0; round < 100; ++round) {
            quic::Bytes body(20000, std::byte(static_cast<unsigned char>(round)));
            auto id = require(client.request({{":method", "POST"},
                                              {":scheme", "https"},
                                              {":authority", "localhost"},
                                              {":path", "/echo"},
                                              {"content-length", std::to_string(body.size())}},
                                             wire(body)));
            bool request_end = false, response_end = false;
            std::size_t incoming = 0, outgoing = 0;
            bool status = false;
            for (int i = 0; i < 2000 && !response_end; ++i) {
                drive();
                for (auto& e : server.take_events()) {
                    if (e.stream_id != id) continue;
                    if (e.kind == http3::Event::Kind::body) {
                        if (!std::all_of(e.data.begin(), e.data.end(), [&](std::byte b) {
                                return b == std::byte(static_cast<unsigned char>(round));
                            }))
                            throw std::runtime_error("request body 损坏");
                        incoming += e.data.size();
                        require(server.consume(id, e.data.size()));
                    }
                    if (e.kind == http3::Event::Kind::end) request_end = true;
                }
                if (request_end) {
                    require(server.respond(
                        id,
                        {{":status", "200"}, {"content-length", std::to_string(body.size())}},
                        wire(body)));
                    request_end = false;
                }
                for (auto& e : client.take_events()) {
                    if (e.stream_id != id) continue;
                    if (e.kind == http3::Event::Kind::headers)
                        for (auto& [n, v] : e.fields)
                            if (n == ":status" && v == "200") status = true;
                    if (e.kind == http3::Event::Kind::body) {
                        if (!std::all_of(e.data.begin(), e.data.end(), [&](std::byte b) {
                                return b == std::byte(static_cast<unsigned char>(round));
                            }))
                            throw std::runtime_error("response body 损坏");
                        outgoing += e.data.size();
                        require(client.consume(id, e.data.size()));
                    }
                    if (e.kind == http3::Event::Kind::end) response_end = true;
                }
            }
            if (!response_end || !status || incoming != body.size() || outgoing != body.size())
                throw std::runtime_error("HTTP3 请求响应不完整 round=" + std::to_string(round) + " incoming=" + std::to_string(incoming) + " outgoing=" + std::to_string(outgoing));
            for (int i = 0; i < 30; ++i) {
                drive();
                client.take_events();
                server.take_events();
            }
        }
        http3::Headers get{
            {":method", "GET"}, {":scheme", "https"}, {":authority", "localhost"}, {":path", "/"}};
        quic::Bytes too_big(4 * 1024 * 1024 + 1);
        if (client.request(get, wire(too_big))) throw std::runtime_error("body 预算未生效");
        auto too_many = get;
        for (int i = 0; i < 129; ++i)
            too_many.emplace_back("x-extra", "value");
        if (client.request(too_many)) throw std::runtime_error("header 数量预算未生效");
        auto canceled = require(client.request(get));
        auto survivor = require(client.request(get));
        require(client.cancel(canceled));
        bool survivor_done = false;
        bool reset_seen = false;
        std::set<std::int64_t> answered;
        for (int i = 0; i < 3000 && !(survivor_done && reset_seen); ++i) {
            drive();
            for (auto& e : server.take_events()) {
                if (e.stream_id == canceled && e.kind == http3::Event::Kind::reset)
                    reset_seen = true;
                if (e.stream_id == survivor && e.kind == http3::Event::Kind::end &&
                    answered.insert(survivor).second)
                    require(server.respond(survivor, {{":status", "204"}}));
            }
            for (auto& e : client.take_events())
                if (e.stream_id == survivor && e.kind == http3::Event::Kind::end)
                    survivor_done = true;
        }
        if (!survivor_done || !reset_seen) throw std::runtime_error("HTTP3 取消未隔离其他并发流");
        if (chaos && !drops) throw std::runtime_error("HTTP3 丢包未触发");
        require(server.shutdown_notice());
        for (int i = 0; i < 100 && !client.peer_goaway(); ++i)
            drive();
        if (!client.peer_goaway()) throw std::runtime_error("GOAWAY 未抵达");
        require(server.shutdown());
        require(server.shutdown());
        if (server.shutdown_notice()) throw std::runtime_error("final GOAWAY 后接受 notice");
        if (!server.ready()) throw std::runtime_error("GOAWAY 错误时序污染连接");
        if (client.request({{":method", "GET"},
                            {":scheme", "https"},
                            {":authority", "localhost"},
                            {":path", "/"}}))
            throw std::runtime_error("GOAWAY 后仍接新请求");
        std::cout << "HTTP3 真实 QUIC 加密 100轮 POST 20KB 双向 body、QPACK、GOAWAY 通过\n";
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
