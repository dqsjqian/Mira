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
        http3::Limits limits;
        limits.max_buffered_body = 32768;
        auto client = require(http3::Engine::create(std::move(cq), false, limits));
        auto server = require(http3::Engine::create(std::move(sq), true, limits));
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
        if (!client.ready() || !server.ready()) throw std::runtime_error("HTTP3 not ready");
        for (std::int64_t invalid_id : {std::int64_t{-1}, INT64_MAX, std::int64_t{1} << 62,
                                       std::int64_t{2}, std::int64_t{3}, std::int64_t{4000}}) {
            if (client.cancel(invalid_id) || server.cancel(invalid_id))
                throw std::runtime_error("HTTP3 accepted an invalid cancel stream id");
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
                            throw std::runtime_error("request body corrupted");
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
                            throw std::runtime_error("response body corrupted");
                        outgoing += e.data.size();
                        require(client.consume(id, e.data.size()));
                    }
                    if (e.kind == http3::Event::Kind::end) response_end = true;
                }
            }
            if (!response_end || !status || incoming != body.size() || outgoing != body.size())
                throw std::runtime_error("HTTP3 request/response incomplete round=" + std::to_string(round) + " incoming=" + std::to_string(incoming) + " outgoing=" + std::to_string(outgoing));
            for (int i = 0; i < 30; ++i) {
                drive();
                client.take_events();
                server.take_events();
            }
        }
        http3::Headers get{
            {":method", "GET"}, {":scheme", "https"}, {":authority", "localhost"}, {":path", "/"}};
        quic::Bytes too_big(4 * 1024 * 1024 + 1);
        if (client.request(get, wire(too_big))) throw std::runtime_error("body budget not enforced");
        auto too_many = get;
        for (int i = 0; i < 129; ++i)
            too_many.emplace_back("x-extra", "value");
        if (client.request(too_many)) throw std::runtime_error("header count budget not enforced");
        auto bad = get;
        bad.push_back({":method", "GET"});
        if (client.request_stream(bad)) throw std::runtime_error("duplicate pseudo-header accepted");
        bad = get;
        bad.push_back({"content-length", "bad"});
        if (client.request_stream(bad)) throw std::runtime_error("invalid length accepted");
        const std::size_t total = 512 * 1024;
        auto upload_headers = get;
        upload_headers[0].value = "POST";
        upload_headers.push_back({"content-length", std::to_string(total)});
        auto upload = require(client.request_stream(upload_headers));
        auto short_stream = require(client.request_stream(get));
        for (int i = 0; i < 30; ++i) drive();
        bool upload_headers_seen = false;
        for (auto& e : server.take_events()) {
            if (e.stream_id == upload && e.kind == http3::Event::Kind::headers) upload_headers_seen = true;
            if (e.kind == http3::Event::Kind::end) throw std::runtime_error("paused body ended early");
        }
        if (!upload_headers_seen) throw std::runtime_error("stream headers were not sent before body");
        require(server.respond_stream(upload, {{":status", "200"}, {"content-length", std::to_string(total)}}));
        quic::Bytes chunk(16384, std::byte{0x5a});
        quic::Bytes one(1, std::byte{0x31});
        auto oversized = client.write_body(upload, quic::Bytes(limits.max_buffered_body + 1));
        if (oversized || oversized.error() != Errc::would_block || client.queued_body_bytes())
            throw std::runtime_error("oversized append was not rejected atomically");
        require(client.write_body(upload, chunk));
        require(client.write_body(upload, chunk));
        auto blocked = client.write_body(short_stream, one);
        if (blocked || blocked.error() != Errc::would_block || !client.ready())
            throw std::runtime_error("streaming backpressure poisoned connection");
        if (client.queued_body_bytes() != limits.max_buffered_body)
            throw std::runtime_error("queue accounting incorrect before ACK");
        auto pending_packet = require(client.poll(now));
        if (client.queued_body_bytes() != limits.max_buffered_body)
            throw std::runtime_error("offered chunks were freed before ACK");
        if (!pending_packet.empty()) require(server.receive(pending_packet, now));
        if (client.finish_body(upload)) throw std::runtime_error("premature content-length finish accepted");
        std::size_t sent = 32768, replied = 0, received = 0, response = 0;
        bool upload_end = false, response_end = false, short_sent = false, short_end = false;
        bool short_before_upload_end = false;
        std::size_t upload_at_short_end = 0, response_at_short_end = 0;
        for (int round = 0; round < 10000 && !(upload_end && response_end && short_end); ++round) {
            drive();
            for (auto& e : server.take_events()) {
                if (e.kind == http3::Event::Kind::body) {
                    if (e.stream_id == upload) {
                        if (!std::all_of(e.data.begin(), e.data.end(), [](std::byte b) { return b == std::byte{0x5a}; }))
                            throw std::runtime_error("streaming upload corrupted");
                        received += e.data.size();
                    }
                    require(server.consume(e.stream_id, e.data.size()));
                }
                if (e.kind == http3::Event::Kind::end && e.stream_id == upload) upload_end = true;
                if (e.kind == http3::Event::Kind::end && e.stream_id == short_stream) {
                    upload_at_short_end = received;
                    require(server.respond(short_stream, {{":status", "204"}}));
                }
            }
            for (auto& e : client.take_events()) {
                if (e.kind == http3::Event::Kind::body) {
                    if (e.stream_id == upload) {
                        if (!std::all_of(e.data.begin(), e.data.end(), [](std::byte b) { return b == std::byte{0x5a}; }))
                            throw std::runtime_error("streaming response corrupted");
                        response += e.data.size();
                    }
                    require(client.consume(e.stream_id, e.data.size()));
                }
                if (e.kind == http3::Event::Kind::end && e.stream_id == upload) response_end = true;
                if (e.kind == http3::Event::Kind::end && e.stream_id == short_stream) {
                    short_end = true;
                    short_before_upload_end = !upload_end;
                    response_at_short_end = response;
                }
            }
            if (!short_sent) {
                auto r = client.write_body(short_stream, one, true);
                if (r) short_sent = true;
                else if (r.error() != Errc::would_block) require(std::move(r));
            }
            if (sent < total) {
                auto r = client.write_body(upload, chunk, sent + chunk.size() == total);
                if (r) sent += chunk.size();
                else if (r.error() != Errc::would_block) require(std::move(r));
            }
            if (replied < total) {
                auto r = server.write_body(upload, chunk, replied + chunk.size() == total);
                if (r) replied += chunk.size();
                else if (r.error() != Errc::would_block) require(std::move(r));
            }
            if (client.queued_body_bytes() > limits.max_buffered_body || server.queued_body_bytes() > limits.max_buffered_body)
                throw std::runtime_error("streaming queue exceeded budget");
        }
        if (!upload_end || !response_end || !short_end || received != total || response != total)
            throw std::runtime_error("streaming transfer did not finish: sent=" + std::to_string(sent) +
                                     " received=" + std::to_string(received) + " response=" + std::to_string(response) +
                                     " short=" + std::to_string(short_end) + " fair=" + std::to_string(short_before_upload_end));
        if (client.finish_body(upload) || server.finish_body(upload) || client.write_body(upload, one))
            throw std::runtime_error("streaming finish was not single-use");
        for (int i = 0; i < 1000 && (client.queued_body_bytes() || server.queued_body_bytes()); ++i) drive();
        if (client.queued_body_bytes() || server.queued_body_bytes()) throw std::runtime_error("ACK did not free chunks");
        auto empty = require(client.request_stream(get));
        require(client.finish_body(empty));
        bool empty_done = false;
        for (int i = 0; i < 3000 && !empty_done; ++i) {
            drive();
            for (auto& e : server.take_events()) {
                if (e.stream_id == empty && e.kind == http3::Event::Kind::end) {
                    require(server.respond_stream(empty, {{":status", "200"}}));
                    require(server.finish_body(empty));
                }
            }
            for (auto& e : client.take_events())
                if (e.stream_id == empty && e.kind == http3::Event::Kind::end) empty_done = true;
        }
        if (!empty_done) throw std::runtime_error("empty streaming finish lost");
        auto head_headers = get;
        head_headers[0].value = "HEAD";
        auto head = require(client.request(head_headers));
        bool head_done = false;
        for (int i = 0; i < 3000 && !head_done; ++i) {
            drive();
            for (auto& e : server.take_events()) {
                if (e.stream_id == head && e.kind == http3::Event::Kind::end) {
                    require(server.respond_stream(head, {{":status", "200"}, {"content-length", "9"}}));
                    if (server.write_body(head, one)) throw std::runtime_error("HEAD body accepted");
                    require(server.finish_body(head));
                }
            }
            for (auto& e : client.take_events()) {
                if (e.stream_id == head && e.kind == http3::Event::Kind::body)
                    throw std::runtime_error("HEAD body delivered");
                if (e.stream_id == head && e.kind == http3::Event::Kind::end) head_done = true;
            }
        }
        if (!head_done) throw std::runtime_error("HEAD streaming finish lost");
        auto tiny_stream = require(client.request_stream(get));
        std::size_t tiny_received = 0;
        bool tiny_done = false;
        for (int batch = 0; batch < 16; ++batch) {
            for (int i = 0; i < 128; ++i) require(client.write_body(tiny_stream, one));
            drive();
            for (auto& e : server.take_events()) {
                if (e.kind == http3::Event::Kind::body) {
                    if (e.stream_id == tiny_stream) tiny_received += e.data.size();
                    require(server.consume(e.stream_id, e.data.size()));
                }
            }
        }
        require(client.finish_body(tiny_stream));
        for (int i = 0; i < 3000 && !tiny_done; ++i) {
            drive();
            for (auto& e : server.take_events()) {
                if (e.kind == http3::Event::Kind::body) {
                    if (e.stream_id == tiny_stream) tiny_received += e.data.size();
                    require(server.consume(e.stream_id, e.data.size()));
                }
                if (e.stream_id == tiny_stream && e.kind == http3::Event::Kind::end)
                    require(server.respond(tiny_stream, {{":status", "204"}}));
            }
            for (auto& e : client.take_events())
                if (e.stream_id == tiny_stream && e.kind == http3::Event::Kind::end) tiny_done = true;
        }
        if (!tiny_done || tiny_received != 2048) throw std::runtime_error("short streaming chunks lost");
        for (int i = 0; i < 1000 && client.queued_body_bytes(); ++i) drive();
        auto canceled = require(client.request_stream(get));
        require(client.write_body(canceled, chunk));
        auto survivor = require(client.request(get));
        auto cancel_packet = require(client.poll(now));
        if (!cancel_packet.empty()) require(server.receive(cancel_packet, now));
        require(client.cancel(canceled));
        if (client.queued_body_bytes() || client.write_body(canceled, one))
            throw std::runtime_error("cancel retained streaming chunks");
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
        if (!survivor_done || !reset_seen) throw std::runtime_error("HTTP3 cancel failed to isolate other concurrent streams");
        if (!short_before_upload_end)
            throw std::runtime_error("short stream starved behind streaming upload: upload-at-short-end=" +
                                     std::to_string(upload_at_short_end) + " response-at-short-end=" +
                                     std::to_string(response_at_short_end));
        if (chaos && !drops) throw std::runtime_error("HTTP3 packet drops never triggered");
        require(server.shutdown_notice());
        for (int i = 0; i < 100 && !client.peer_goaway(); ++i)
            drive();
        if (!client.peer_goaway()) throw std::runtime_error("GOAWAY did not arrive");
        require(server.shutdown());
        require(server.shutdown());
        if (server.shutdown_notice()) throw std::runtime_error("notice accepted after final GOAWAY");
        if (!server.ready()) throw std::runtime_error("GOAWAY wrong ordering polluted the connection");
        if (client.request({{":method", "GET"},
                            {":scheme", "https"},
                            {":authority", "localhost"},
                            {":path", "/"}}))
            throw std::runtime_error("new request accepted after GOAWAY");
        std::cout << "HTTP3 encrypted whole-body and bounded streaming, ACK retention, fairness, QPACK, GOAWAY passed\n";
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
