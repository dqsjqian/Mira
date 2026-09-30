#include "mira/ws/connection.hpp"
#include "mira/core/event_loop.hpp"
#include "check.hpp"
#include <algorithm>
#include <string_view>
#include <stdexcept>

using namespace Mira;
using namespace Mira::ws;
namespace {
std::vector<std::byte> bytes(std::string_view text) {
    auto span = std::as_bytes(std::span(text.data(), text.size()));
    return {span.begin(), span.end()};
}
std::vector<std::byte> raw(std::initializer_list<unsigned> values) {
    std::vector<std::byte> result;
    for (auto value : values) result.push_back(std::byte(value));
    return result;
}
std::array<std::byte, 4> test_mask{std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};
void codec() {
    for (std::size_t size : {0U, 1U, 125U, 126U, 65535U, 65536U}) {
        Frame frame{Opcode::binary, true, std::vector<std::byte>(size, std::byte{0xa5})};
        auto wire = serialize(frame, Role::client, test_mask);
        CHECK(wire.has_value());
        if (!wire) continue;
        FrameParser parser(Role::server);
        unsigned frames = 0;
        for (std::size_t i = 0; i < wire->size(); ++i) {
            auto parsed = parser.feed(std::span<const std::byte>(*wire).subspan(i, 1));
            CHECK(parsed.has_value());
            if (!parsed) break;
            CHECK(parsed->consumed == 1);
            if (parsed->frame) { ++frames; CHECK(parsed->frame->payload == frame.payload); }
        }
        CHECK(frames == 1);
    }
    const std::vector<std::vector<std::byte>> invalid{
        raw({0x81, 0}), raw({0xc1, 0x80, 0,0,0,0}), raw({0x83, 0x80, 0,0,0,0}),
        raw({0x89, 0xfe, 0,126, 0,0,0,0}), raw({0x09,0x80,0,0,0,0}),
        raw({0x82,0xfe,0,1,0,0,0,0}), raw({0x82,0xff,0,0,0,0,0,0,0,126,0,0,0,0}),
        raw({0x82,0xff,0x80,0,0,0,0,0,0,0,0,0,0,0}),
        raw({0x80,0x80,0,0,0,0}), raw({0x81,0x82,0,0,0,0,0xc0,0x80}),
        raw({0x88,0x81,0,0,0,0,1}), raw({0x88,0x82,0,0,0,0,3,0xed}),
        raw({0x88,0x84,0,0,0,0,3,0xe8,0xc0,0x80})};
    for (const auto& wire : invalid) {
        FrameParser parser(Role::server);
        CHECK(!parser.feed(wire).has_value());
        CHECK(!parser.feed({}).has_value());
        parser.reset();
        CHECK(!parser.failed());
    }
    for (const auto& invalid_utf8 : {raw({0xed,0xa0,0x80}), raw({0xf4,0x90,0x80,0x80}),
                                    raw({0xe0,0x80,0x80}), raw({0xf0,0x80,0x80,0x80}),
                                    raw({0x80}), raw({0xe2,0x28,0xa1}), raw({0xf0,0x9f,0x92})})
        CHECK(!valid_utf8(invalid_utf8));
    CHECK(valid_utf8(raw({0xf0,0x9f,0x92,0xa9})));
    FrameParser client(Role::client);
    auto test_masked = serialize(Frame{}, Role::client, test_mask);
    CHECK(!client.feed(*test_masked).has_value());
    Limits limits; limits.max_frame = 10;
    FrameParser limited(Role::server, limits);
    auto oversized = raw({0x82,0xfe,0,126,0,0,0,0});
    auto rejected = limited.feed(oversized);
    CHECK(!rejected && rejected.error() == Mira::make_error_code(Mira::Errc::limit_exceeded));
    FrameParser fragments(Role::server);
    Frame start{Opcode::text, false, raw({0xe2})};
    Frame continuation{Opcode::continuation, true, raw({0x82,0xac})};
    Frame ping{Opcode::ping, true, bytes("p")};
    for (const auto& frame : {start, ping, continuation}) {
        auto wire = serialize(frame, Role::client, test_mask);
        auto parsed = fragments.feed(*wire);
        CHECK(parsed && parsed->frame.has_value());
    }
    FrameParser truncated(Role::server);
    CHECK(truncated.feed(*serialize(start, Role::client, test_mask)).has_value());
    continuation.payload = raw({0x82});
    CHECK(!truncated.feed(*serialize(continuation, Role::client, test_mask)).has_value());
    FrameParser overlapping(Role::server);
    CHECK(overlapping.feed(*serialize(start, Role::client, test_mask)).has_value());
    CHECK(!overlapping.feed(*serialize(start, Role::client, test_mask)).has_value());
    Limits message_limit; message_limit.max_message = 3;
    FrameParser cumulative(Role::server, message_limit);
    Frame first_binary{Opcode::binary, false, bytes("ab")};
    Frame last_binary{Opcode::continuation, true, bytes("cd")};
    CHECK(cumulative.feed(*serialize(first_binary, Role::client, test_mask)).has_value());
    CHECK(!cumulative.feed(*serialize(last_binary, Role::client, test_mask)).has_value());
    Frame forbidden_server_close{Opcode::close, true, *close_payload(1010)};
    CHECK(!serialize(forbidden_server_close, Role::server).has_value());
    for (auto code : {1000,1001,1002,1003,1007,1008,1009,1010,1011,1012,1013,1014,3000,4999})
        CHECK(valid_close_code(static_cast<std::uint16_t>(code)));
    for (auto code : {0,999,1004,1005,1006,1015,2000,2999,5000})
        CHECK(!valid_close_code(static_cast<std::uint16_t>(code)));
}
void handshakes() {
    auto accept = accept_key("dGhlIHNhbXBsZSBub25jZQ==");
    CHECK(accept && *accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    auto generated = client_handshake("localhost", "/echo");
    CHECK(generated.has_value());
    auto response = server_handshake(generated->request);
    CHECK(response.has_value());
    CHECK(validate_server_handshake(*response, generated->key).has_value());
    auto cookies = *response;
    cookies.insert(cookies.size() - 2, "Set-Cookie: one=1\r\nSet-Cookie: two=2\r\n");
    CHECK(validate_server_handshake(cookies, generated->key).has_value());
    cookies.insert(cookies.size() - 2, "Sec-WebSocket-Accept: " + *accept_key(generated->key) + "\r\n");
    CHECK(!validate_server_handshake(cookies, generated->key));
    auto second = client_handshake("localhost");
    CHECK(generated->key != second->key);
    CHECK(!client_handshake("host\r\nInjected: yes").has_value());
    CHECK(!client_handshake("host", "/x y").has_value());
    CHECK(!accept_key("dGhlIHNhbXBsZSBub25jZR==").has_value());
    CHECK(!accept_key("abc").has_value());
    for (const auto& [from, to] : std::initializer_list<std::pair<std::string, std::string>>{
         {"GET /echo", "POST /echo"}, {"HTTP/1.1", "HTTP/1.0"}, {"Upgrade: websocket", "Upgrade: h2c"},
         {"Connection: Upgrade", "Connection: xUpgrade"}, {"Version: 13", "Version: 12"},
         {"Host: localhost", "Host: "}, {"Sec-WebSocket-Key:", "Sec-WebSocket-Key :"}}) {
        auto bad = generated->request;
        bad.replace(bad.find(from), from.size(), to);
        CHECK(!server_handshake(bad).has_value());
    }
    auto duplicate = generated->request;
    duplicate.insert(duplicate.size() - 2, "Sec-WebSocket-Key: " + generated->key + "\r\n");
    CHECK(!server_handshake(duplicate).has_value());
    auto tokens = generated->request;
    tokens.replace(tokens.find("Connection: Upgrade"), 19, "Connection: keep-alive, UpGrAdE");
    CHECK(server_handshake(tokens).has_value());
    auto invalid_response = *response;
    invalid_response.insert(invalid_response.size() - 2, "Sec-WebSocket-Extensions: permessage-deflate\r\n");
    CHECK(!validate_server_handshake(invalid_response, generated->key).has_value());
    CHECK(!validate_server_handshake(*response, second->key).has_value());
    Limits tiny; tiny.max_handshake = 4;
    CHECK(!server_handshake(generated->request, tiny).has_value());
}
struct MemoryStream {
    std::vector<std::byte> input, output;
    std::size_t pos = 0;
    bool closed = false;
    bool fail_write = false;
    bool throw_read = false;
    std::stop_source* cancel_source = nullptr;
    std::size_t cancel_at = 0;
    std::size_t reads = 0, writes = 0;
    Task<Result<std::size_t>> read_some(std::span<std::byte> out, OperationOptions options = {}) {
        ++reads;
        if (throw_read) throw std::runtime_error("test stream failure");
        if (options.stop.stop_requested()) co_return fail(Mira::Errc::cancelled);
        if (pos == input.size()) co_return fail(Mira::Errc::eof);
        out[0] = input[pos++];
        if (cancel_source && pos == cancel_at) cancel_source->request_stop();
        co_return 1;
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> in, OperationOptions options = {}) {
        ++writes;
        if (options.stop.stop_requested()) co_return fail(Mira::Errc::cancelled);
        if (fail_write) co_return fail(Mira::Errc::eof);
        output.push_back(in[0]);
        co_return 1;
    }
    void close() { closed = true; }
};
struct ClientMemoryStream : MemoryStream {
    Task<Result<std::size_t>> read_some(std::span<std::byte> out, OperationOptions options = {}) {
        if (input.empty()) {
            std::string request(reinterpret_cast<const char*>(output.data()), output.size());
            auto response = server_handshake(request);
            if (!response) co_return fail(response.error());
            input = bytes(*response);
        }
        co_return co_await MemoryStream::read_some(out, options);
    }
};
Task<void> extended_handoff() {
    HandshakeOptions options;
    options.subprotocols = {"chat"};
    options.require_subprotocol = true;
    options.compression.enabled = true;
    Negotiated negotiated;
    negotiated.subprotocol = "chat";
    negotiated.compression.enabled = true;
    MemoryStream transport;
    Connection connection(transport, Role::client, {}, options);
    CHECK(!connection.adopt_extended_connect("other", 200, negotiated));
    CHECK(!connection.adopt_extended_connect("websocket", 101, negotiated));
    CHECK(!connection.adopt_extended_connect("websocket", 300, negotiated));
    CHECK(!connection.adopt_extended_connect("websocket", 200));
    auto invalid = negotiated;
    invalid.subprotocol = "unoffered";
    CHECK(!connection.adopt_extended_connect("websocket", 200, invalid));
    CHECK(connection.adopt_extended_connect("websocket", 200, negotiated).has_value());
    CHECK(!connection.adopt_extended_connect("websocket", 200, negotiated));
    CHECK(transport.reads == 0 && transport.writes == 0);
    CHECK(connection.subprotocol() == "chat" && connection.compression_parameters().enabled);
    auto plain = Frame{Opcode::text, true, bytes("over extended connect")};
    CHECK((co_await connection.send(plain)).has_value());
    FrameParser parser(Role::server, {}, true);
    auto parsed = parser.feed(transport.output);
    CHECK(parsed && parsed->frame && parsed->frame->compressed);
    auto decoder = DeflateDecoder::create(Role::server, negotiated.compression);
    CHECK(decoder.has_value());
    if (parsed && parsed->frame && decoder) {
        auto decoded = decoder->decode(std::move(*parsed->frame));
        CHECK(decoded && decoded->payload == plain.payload);
    }
    MemoryStream default_transport;
    Connection disabled(default_transport, Role::client);
    CHECK(!disabled.adopt_extended_connect("websocket", 200, negotiated));
    negotiated = {};
    CHECK(disabled.adopt_extended_connect("websocket", 204, negotiated).has_value());
}
Task<void> connection_tests() {
    co_await extended_handoff();
    {
        MemoryStream partial;
        std::stop_source stop;
        auto first = serialize(Frame{Opcode::text, false, bytes("prefix")}, Role::server);
        auto last = serialize(Frame{Opcode::continuation, true, bytes("suffix")}, Role::server);
        partial.input = *first;
        partial.input.insert(partial.input.end(), last->begin(), last->end());
        partial.cancel_source = &stop;
        partial.cancel_at = first->size();
        Connection fragmented(partial, Role::client);
        CHECK(fragmented.adopt_extended_connect("websocket", 200).has_value());
        auto result = co_await fragmented.read_message({.stop = stop.get_token()});
        CHECK(!result && result.error() == Mira::Errc::cancelled);
        CHECK(fragmented.closed() && partial.closed);
        CHECK(!(co_await fragmented.read_message()));
    }
    auto request = client_handshake("localhost");
    MemoryStream stream;
    stream.input = bytes(request->request);
    Frame text{Opcode::text, true, bytes("echo")};
    Frame ping{Opcode::ping, true, bytes("heartbeat")};
    Frame close{Opcode::close, true, *close_payload()};
    for (const auto& frame : {ping, text, ping, close}) {
        auto wire = serialize(frame, Role::client, test_mask);
        stream.input.insert(stream.input.end(), wire->begin(), wire->end());
    }
    Connection conn(stream, Role::server);
    auto handshake = co_await conn.handshake();
    CHECK(handshake.has_value());
    auto message = co_await conn.read_message();
    CHECK(message && message->payload == text.payload);
    auto sent = co_await conn.send(text);
    CHECK(sent.has_value());
    auto closed = co_await conn.close();
    CHECK(closed.has_value());
    CHECK(conn.closed());
    auto after_close = co_await conn.send(text);
    CHECK(!after_close);
    CHECK(stream.writes == stream.output.size());
    std::string output(reinterpret_cast<const char*>(stream.output.data()), stream.output.size());
    auto boundary = output.find("\r\n\r\n") + 4;
    CHECK(validate_server_handshake(output.substr(0, boundary), request->key).has_value());
    FrameParser client(Role::client);
    auto tail = std::span<const std::byte>(stream.output).subspan(boundary);
    for (auto expected : {Opcode::pong, Opcode::text, Opcode::close, Opcode::pong}) {
        auto parsed = client.feed(tail);
        CHECK(parsed && parsed->frame && parsed->frame->opcode == expected);
        if (!parsed) break;
        tail = tail.subspan(parsed->consumed);
        if (expected == Opcode::close) client.reset();
    }
    CHECK(tail.empty());
    MemoryStream eof;
    eof.input = bytes(request->request);
    Connection broken(eof, Role::server);
    CHECK((co_await broken.handshake()).has_value());
    auto read = co_await broken.read_message();
    CHECK(!read && read.error() == ws::make_error_code(ws::Errc::abnormal_close));
    CHECK(eof.closed && broken.closed());
    MemoryStream short_fail;
    short_fail.input = bytes(request->request); short_fail.fail_write = true;
    Connection failed(short_fail, Role::server);
    CHECK(!(co_await failed.handshake()));
    CHECK(short_fail.closed && failed.closed());
    MemoryStream cancel;
    Connection cancelled(cancel, Role::client);
    std::stop_source source; source.request_stop();
    OperationOptions options{.stop = source.get_token()};
    CHECK(!(co_await cancelled.handshake("localhost", "/", options)));
    CHECK(cancel.reads == 0 && cancel.writes == 0);
    MemoryStream throws;
    throws.input = bytes(request->request);
    Connection throwing(throws, Role::server);
    CHECK((co_await throwing.handshake()).has_value());
    throws.throw_read = true;
    bool caught = false;
    try { (void)co_await throwing.read_message(); }
    catch (const std::runtime_error&) { caught = true; }
    CHECK(caught && throwing.closed());
    CHECK(!(co_await throwing.send(text)));
    MemoryStream deadline_stream;
    Connection deadline_connection(deadline_stream, Role::client);
    OperationOptions expired{.deadline = Clock::now() - std::chrono::seconds(1)};
    auto deadline_result = co_await deadline_connection.handshake("localhost", "/", expired);
    CHECK(!deadline_result && deadline_result.error() == Mira::make_error_code(Mira::Errc::timed_out));
    CHECK(deadline_stream.reads == 0 && deadline_stream.writes == 0);
    ClientMemoryStream client_stream;
    Connection client_conn(client_stream, Role::client);
    CHECK((co_await client_conn.handshake("localhost")).has_value());
    auto header_size = client_stream.output.size();
    CHECK((co_await client_conn.send(text)).has_value());
    auto first_end = client_stream.output.size();
    CHECK((co_await client_conn.send(text)).has_value());
    auto second_end = client_stream.output.size();
    CHECK((co_await client_conn.send(text)).has_value());
    auto first_wire = std::span<const std::byte>(client_stream.output).subspan(header_size, first_end - header_size);
    auto second_wire = std::span<const std::byte>(client_stream.output).subspan(first_end, second_end - first_end);
    auto third_wire = std::span<const std::byte>(client_stream.output).subspan(second_end);
    CHECK(!std::equal(first_wire.begin() + 2, first_wire.begin() + 6, second_wire.begin() + 2) ||
          !std::equal(first_wire.begin() + 2, first_wire.begin() + 6, third_wire.begin() + 2));
    FrameParser server_parser(Role::server);
    auto first_parsed = server_parser.feed(first_wire);
    auto second_parsed = server_parser.feed(second_wire);
    CHECK(first_parsed && first_parsed->frame && first_parsed->frame->payload == text.payload);
    CHECK(second_parsed && second_parsed->frame && second_parsed->frame->payload == text.payload);
}
}
int main() {
    codec(); handshakes();
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (loop) CHECK(loop->run_until_complete(connection_tests()).has_value());
    return Mira::test::summary();
}
