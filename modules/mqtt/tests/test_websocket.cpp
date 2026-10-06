#include "mira/mqtt/client.hpp"
#include "mira/ws/byte_stream.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/transport/tcp.hpp"

#include <array>
#include <iostream>
#include <stdexcept>

using namespace Mira;
using namespace std::chrono_literals;
namespace tcp = transport::tcp;
namespace {
template<class T> T require(Result<T> value) {
    if (!value) throw std::runtime_error(value.error().message());
    return std::move(*value);
}
void require(Result<void> value) {
    if (!value) throw std::runtime_error(value.error().message());
}
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
ws::HandshakeOptions options() {
    ws::HandshakeOptions result;
    result.subprotocols = {"mqtt"};
    result.require_subprotocol = true;
    return result;
}
using Binary = ws::ByteStream<tcp::Socket>;
static_assert(BoundedStream<Binary>);
Task<mqtt::Packet> read_packet(Binary& stream, mqtt::Bytes& pending, OperationOptions io) {
    for (;;) {
        auto decoded = require(mqtt::decode(pending, mqtt::Version::v5, mqtt::Role::server));
        if (decoded.packet) {
            pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(decoded.consumed));
            co_return std::move(*decoded.packet);
        }
        std::array<std::byte, 7> input{};
        const auto size = require(co_await stream.read_some(input, io));
        pending.insert(pending.end(), input.begin(), input.begin() + static_cast<std::ptrdiff_t>(size));
    }
}
Task<void> send_packet(Binary& stream, mqtt::Packet packet, OperationOptions io) {
    auto encoded = require(mqtt::encode(packet, mqtt::Version::v5));
    require(co_await write_all(stream, encoded, io));
}
Task<void> broker(tcp::Listener& listener, bool& passed) {
    const OperationOptions io{.deadline = Clock::now() + 5s};
    auto socket = require(co_await listener.accept(io));
    ws::Connection websocket{socket, ws::Role::server, ws::Limits{}, options()};
    require(co_await websocket.handshake({}, "/mqtt", io));
    Binary stream{websocket, 5};
    mqtt::Bytes pending;
    check(std::holds_alternative<mqtt::Connect>(co_await read_packet(stream, pending, io)), "CONNECT missing");
    co_await send_packet(stream, mqtt::Connack{}, io);
    auto incoming = co_await read_packet(stream, pending, io);
    auto* publish = std::get_if<mqtt::Publish>(&incoming);
    check(publish && publish->topic == "roundtrip" && publish->qos == mqtt::QoS::exactly_once &&
          publish->payload.size() == 8000, "MQTT binary payload mismatch");
    const auto id = publish->packet_id;
    co_await send_packet(stream, mqtt::Ack{mqtt::PacketType::pubrec, id, 0, {}}, io);
    auto release = co_await read_packet(stream, pending, io);
    check(std::get<mqtt::Ack>(release).type == mqtt::PacketType::pubrel, "PUBREL missing");
    co_await send_packet(stream, mqtt::Ack{mqtt::PacketType::pubcomp, id, 0, {}}, io);
    check(std::holds_alternative<mqtt::Disconnect>(co_await read_packet(stream, pending, io)), "DISCONNECT missing");
    auto close = require(co_await websocket.read_frame(io));
    check(close.opcode == ws::Opcode::close, "WS close missing");
    passed = true;
}
Task<void> client(EventLoop& loop, transport::Endpoint endpoint, bool& passed) {
    const OperationOptions io{.deadline = Clock::now() + 5s};
    auto socket = require(co_await tcp::connect(loop, endpoint, {}, io));
    ws::Connection websocket{socket, ws::Role::client, ws::Limits{}, options()};
    require(co_await websocket.handshake("localhost", "/mqtt", io));
    check(websocket.subprotocol() == "mqtt", "MQTT subprotocol missing");
    Binary stream{websocket, 97};
    mqtt::ClientOptions config;
    config.client_id = "ws-client";
    auto mqtt_client = require(co_await mqtt::Client<Binary>::connect(stream, config, io));
    mqtt::Bytes payload(8000, std::byte{0xa5});
    const auto id = require(co_await mqtt_client.publish("roundtrip", payload, mqtt::QoS::exactly_once, false, {}, io));
    require(co_await mqtt_client.wait_for(id, io));
    require(co_await mqtt_client.disconnect(0, {}, io));
    require(co_await websocket.close(1000, io));
    passed = true;
}
Task<void> run(EventLoop& loop) {
    auto listener = require(tcp::Listener::bind(loop, transport::Endpoint::loopback(0)));
    bool a = false, b = false;
    TaskScope tasks;
    tasks.spawn(broker(listener, a));
    tasks.spawn(client(loop, listener.local_endpoint(), b));
    co_await tasks.join();
    check(a && b, "both MQTT/WS peers must finish");
}
} // namespace
int main() {
    try {
        auto loop = require(EventLoop::create());
        require(loop.run_until_complete(run(loop)));
        std::cout << "MQTT QoS2 over real WebSocket binary stream passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
