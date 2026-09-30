// Drive HTTP/2 framing, HPACK and public stream lifetime APIs with bounded input.
#include <mira/http2/session.hpp>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 16384) return 0;
    const auto wire = std::span{reinterpret_cast<const std::byte*>(data), size};
    for (const auto role : {Mira::http2::Role::client, Mira::http2::Role::server}) {
        Mira::http2::Limits limits;
        limits.max_streams = 8;
        limits.max_header_bytes = 4096;
        limits.max_body_bytes = 16384;
        limits.max_queued_body_bytes = 32768;
        limits.enable_connect_protocol = true;
        auto session = Mira::http2::Session::create(role, limits);
        if (!session) return 0;
        if (role == Mira::http2::Role::server) {
            constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            if (!session->receive(std::as_bytes(std::span(preface.data(), preface.size())))) continue;
        } else {
            static_cast<void>(session->request({{":method", "GET"}, {":scheme", "https"},
                                                {":authority", "localhost"}, {":path", "/"}}));
        }
        for (std::size_t offset = 0; offset < size;) {
            const auto count = std::min<std::size_t>(1 + (data[offset] % 64), size - offset);
            if (!session->receive(wire.subspan(offset, count))) break;
            offset += count;
            for (const auto id : session->streams()) {
                const auto* stream = session->stream(id);
                if (!stream) continue;
                const bool closed = stream->closed;
                static_cast<void>(session->take_body(id));
                if (closed) static_cast<void>(session->release(id));
            }
            if (!session->output()) break;
        }
        static_cast<void>(session->goaway());
        static_cast<void>(session->output());
        session->close();
    }
    return 0;
}
