#include "mira/http3/engine.hpp"
#include <iostream>
#include <stdexcept>

using namespace Mira;
template<class T> T require(quic::Result<T> result) {
    if (!result) throw std::runtime_error(result.error().message());
    return std::move(*result);
}
void require(quic::Result<void> result) {
    if (!result) throw std::runtime_error(result.error().message());
}
int main(int argc, char** argv) {
    try {
        if (argc != 3) return 2;
        quic::Options co, so;
        co.local = transport::Endpoint::loopback(44330);
        co.remote = transport::Endpoint::loopback(44331);
        co.peer_name = "localhost"; co.ca_file = argv[1];
        so.local = co.remote; so.remote = co.local;
        so.certificate_file = argv[1]; so.private_key_file = argv[2]; so.max_streams = 2;
        std::uint64_t now = 1'000'000'000;
        auto client = require(quic::Engine::client(co, now));
        auto initial = require(client.poll(now));
        auto server = require(http3::Engine::create(require(quic::Engine::accept(so, initial, now)), true));
        auto drive = [&] {
            for (int k = 0; k < 64; ++k) {
                auto cp = require(client.poll(now)); if (!cp.empty()) require(server.receive(cp, now));
                auto sp = require(server.poll(now)); if (!sp.empty()) require(client.receive(sp, now));
                if (cp.empty() && sp.empty()) break;
            }
            for (auto& e : client.take_events()) if (e.kind == quic::Event::Kind::data) require(client.consume(e.stream_id, e.data.size()));
            now += 1'000'000;
            if (client.expiry() <= now) require(client.handle_expiry(now));
            if (server.expiry() <= now) require(server.handle_expiry(now));
        };
        for (int i=0; i<1000 && !(client.handshake_complete() && server.ready()); ++i) drive();
        if (!server.ready()) throw std::runtime_error("HTTP3 握手失败");
        const auto control = require(client.open_stream(true));
        // 控制流类型 0，空 SETTINGS；请求采用仅静态表的真实 QPACK 字段段。
        require(client.write(control, std::vector<std::byte>{std::byte{0},std::byte{4},std::byte{0}}, false));
        const std::vector<std::byte> request{std::byte{1},std::byte{16},std::byte{0},std::byte{0},std::byte{0xd1},std::byte{0xd7},std::byte{0x50},std::byte{9},std::byte{'l'},std::byte{'o'},std::byte{'c'},std::byte{'a'},std::byte{'l'},std::byte{'h'},std::byte{'o'},std::byte{'s'},std::byte{'t'},std::byte{0xc1}};
        for(int round=0; round<4; ++round) {
            auto id = require(client.open_stream());
            if(round == 3) {
                // PRIORITY_UPDATE_REQUEST_STREAM (0xf0700)，目标是已获 QUIC 授权的新流。
                require(client.write(control, std::vector<std::byte>{std::byte{0x80},std::byte{0x0f},std::byte{0x07},std::byte{0x00},std::byte{4},std::byte{static_cast<unsigned char>(id)},std::byte{'u'},std::byte{'='},std::byte{'3'}}, false));
            }
            require(client.write(id, request, true));
            bool ended = false;
            for(int i=0; i<1000 && !ended; ++i) {
                drive();
                for(auto& e : server.take_events()) if(e.kind == http3::Event::Kind::end && e.stream_id == id) ended = true;
            }
            if(!ended) throw std::runtime_error("动态流额度下请求无进展");
            require(server.respond(id, {{":status","204"}}));
            for(int i=0; i<100; ++i) { drive(); server.take_events(); }
        }
        std::cout << "累计 MAX_STREAMS 后合法 PRIORITY_UPDATE 通过\n";
    } catch(const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
