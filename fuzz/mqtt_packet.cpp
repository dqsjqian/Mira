// MQTT decoding for both versions and roles, encode/decode round trips, and a
// connected client session fed hostile server bytes.
#include "mira/mqtt/session.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace mqtt = Mira::mqtt;

namespace {

// The decoder admits exactly one value the encoder refuses: a 3.1.1 CONNECT
// with an empty client identifier and no clean session, which a broker must
// answer with CONNACK 0x02 rather than a decode failure.
bool encodable_exception(const mqtt::Packet& packet) {
    const auto* connect = std::get_if<mqtt::Connect>(&packet);
    return connect && connect->version == mqtt::Version::v311 && connect->client_id.empty() && !connect->clean_start;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 65536) return 0;
    const auto bytes = std::as_bytes(std::span{data, size});
    for (const auto version : {mqtt::Version::v311, mqtt::Version::v5}) {
        for (const auto role : {mqtt::Role::client, mqtt::Role::server}) {
            auto decoded = mqtt::decode(bytes, version, role, 16384);
            if (!decoded || !decoded->packet) continue;
            if (decoded->consumed == 0 || decoded->consumed > size) std::abort();
            const auto& packet = *decoded->packet;
            const auto wire_version =
                std::holds_alternative<mqtt::Connect>(packet) ? std::get<mqtt::Connect>(packet).version : version;
            auto encoded = mqtt::encode(packet, wire_version);
            if (!encoded) {
                if (!encodable_exception(packet)) std::abort();
                continue;
            }
            auto again = mqtt::decode(*encoded, wire_version, role);
            if (!again || !again->packet || !(*again->packet == packet) || again->consumed != encoded->size())
                std::abort();
        }
    }
    for (const auto version : {mqtt::Version::v311, mqtt::Version::v5}) {
        mqtt::ClientOptions options;
        options.version = version;
        options.client_id = "fuzz";
        options.receive_maximum = std::uint16_t{4};
        options.maximum_packet_size = 4096;
        options.max_events = 64;
        if (version == mqtt::Version::v5) options.topic_alias_maximum = std::uint16_t{4};
        auto session = mqtt::Session::create(options);
        if (!session || !session->connect(0)) std::abort();
        static_cast<void>(session->take_output(0));
        auto connack = mqtt::encode(mqtt::Connack{}, version);
        if (!connack || !session->receive(*connack, 0)) std::abort();
        static_cast<void>(session->publish({"t", {}, mqtt::QoS::exactly_once}));
        static_cast<void>(session->subscribe({{"a/#", mqtt::QoS::at_least_once}}));
        // Split the input to exercise incremental reassembly.
        const auto half = size / 2;
        if (session->receive(bytes.first(half), 1)) static_cast<void>(session->receive(bytes.subspan(half), 2));
        static_cast<void>(session->handle_timer(120'000'000'000));
        const auto output = session->take_output(3);
        // Whatever the session writes must be a valid client byte stream.
        std::size_t offset = 0;
        while (offset < output.size()) {
            auto packet = mqtt::decode(std::span{output}.subspan(offset), version, mqtt::Role::server);
            if (!packet || !packet->packet) std::abort();
            offset += packet->consumed;
        }
        static_cast<void>(session->take_events());
    }
    return 0;
}
