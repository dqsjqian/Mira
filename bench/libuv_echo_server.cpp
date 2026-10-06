// Single-loop libuv TCP echo reference with managed_echo_server's CLI protocol.
// Usage: bench_libuv_echo_server [port=0] [max-connections=64] [lifetime-ms=5000]
// Fixed 16 KiB per connection; read -> completed write -> read, no write backlog.
#include <uv.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <new>
#include <string_view>

namespace {
struct Server {
    uv_loop_t loop{};
    uv_tcp_t listener{};
    uv_timer_t deadline{};
    std::size_t maximum = 64;
    std::size_t active = 0;
    std::size_t accepted = 0;
    std::size_t rejected = 0;
    std::size_t completed = 0;
    std::size_t failed = 0;
    std::size_t peak_active = 0;
    bool stopping = false;
    int status = 0;
};
struct Peer {
    uv_tcp_t socket{};
    uv_write_t write{};
    Server* server = nullptr;
    std::array<char, 16384> buffer{};
    bool admitted = false;
};

void peer_closed(uv_handle_t* handle) {
    auto* peer = static_cast<Peer*>(handle->data);
    if (peer->admitted) {
        --peer->server->active;
        ++peer->server->completed;
    }
    delete peer;
}

void close_peer(Peer* peer, int error = 0) {
    auto* handle = reinterpret_cast<uv_handle_t*>(&peer->socket);
    if (uv_is_closing(handle)) return;
    if (peer->admitted && error != 0 && error != UV_EOF && error != UV_ECANCELED)
        ++peer->server->failed;
    // libuv drains cancelled writes before close callbacks; keep buffers alive.
    uv_close(handle, peer_closed);
}

void stop_server(Server& server, int error = 0) {
    if (server.stopping) return;
    server.stopping = true;
    if (error != 0) {
        server.status = 1;
        std::fprintf(stderr, "libuv: %s\n", uv_strerror(error));
    }
    uv_walk(&server.loop, [](uv_handle_t* handle, void* owner) {
        auto& state = *static_cast<Server*>(owner);
        if (uv_is_closing(handle)) return;
        if (handle == reinterpret_cast<uv_handle_t*>(&state.listener) ||
            handle == reinterpret_cast<uv_handle_t*>(&state.deadline)) uv_close(handle, nullptr);
        else close_peer(static_cast<Peer*>(handle->data));
    }, &server);
}

void allocate(uv_handle_t* handle, std::size_t, uv_buf_t* output) {
    auto* peer = static_cast<Peer*>(handle->data);
    *output = uv_buf_init(peer->buffer.data(), static_cast<unsigned>(peer->buffer.size()));
}
void received(uv_stream_t* stream, ssize_t count, const uv_buf_t*);

void written(uv_write_t* request, int status) {
    auto* peer = static_cast<Peer*>(request->data);
    if (uv_is_closing(reinterpret_cast<uv_handle_t*>(&peer->socket))) return;
    if (status < 0) { close_peer(peer, status); return; }
    const int started = uv_read_start(reinterpret_cast<uv_stream_t*>(&peer->socket), allocate, received);
    if (started != 0) close_peer(peer, started);
}

void received(uv_stream_t* stream, ssize_t count, const uv_buf_t*) {
    auto* peer = static_cast<Peer*>(stream->data);
    if (count < 0) { close_peer(peer, static_cast<int>(count)); return; }
    if (count == 0) return;
    const int stopped = uv_read_stop(stream);
    if (stopped != 0) { close_peer(peer, stopped); return; }
    uv_buf_t output = uv_buf_init(peer->buffer.data(), static_cast<unsigned>(count));
    const int queued = uv_write(&peer->write, stream, &output, 1, written);
    if (queued != 0) close_peer(peer, queued);
}

void connection(uv_stream_t* listener, int status) {
    auto& server = *static_cast<Server*>(listener->data);
    if (status < 0) { stop_server(server, status); return; }
    auto* peer = new (std::nothrow) Peer;
    if (peer == nullptr) { stop_server(server, UV_ENOMEM); return; }
    peer->server = &server;
    const int initialized = uv_tcp_init(&server.loop, &peer->socket);
    if (initialized != 0) { delete peer; stop_server(server, initialized); return; }
    peer->socket.data = peer;
    peer->write.data = peer;
    const int accepted = uv_accept(listener, reinterpret_cast<uv_stream_t*>(&peer->socket));
    if (accepted != 0) { close_peer(peer); stop_server(server, accepted); return; }
    ++server.accepted;
    if (server.stopping || server.active >= server.maximum) {
        ++server.rejected;
        close_peer(peer);
        return;
    }
    const int no_delay = uv_tcp_nodelay(&peer->socket, 1);
    if (no_delay != 0) { close_peer(peer); stop_server(server, no_delay); return; }
    peer->admitted = true;
    ++server.active;
    server.peak_active = std::max(server.peak_active, server.active);
    const int started = uv_read_start(reinterpret_cast<uv_stream_t*>(&peer->socket), allocate, received);
    if (started != 0) close_peer(peer, started);
}
}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view{argv[1]} == "--version") {
        std::printf("libuv %s\n", uv_version_string());
        return 0;
    }
    unsigned values[]{0, 64, 5000};
    if (argc > 4) return 2;
    for (int i = 1; i < argc; ++i) {
        const std::string_view text{argv[i]};
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), values[i - 1]);
        if (error != std::errc{} || end != text.data() + text.size()) return 2;
    }
    if (values[0] > 65535 || values[1] == 0 || values[1] > 65536 ||
        values[2] == 0 || values[2] > 3600000) return 2;
    Server server;
    server.maximum = values[1];
    if (uv_loop_init(&server.loop) != 0) return 1;
    const auto run = [&]() {
        int error = uv_tcp_init(&server.loop, &server.listener);
        if (error != 0) return error;
        server.listener.data = &server;
        sockaddr_in address{};
        if ((error = uv_ip4_addr("127.0.0.1", static_cast<int>(values[0]), &address)) != 0) return error;
        if ((error = uv_tcp_bind(&server.listener, reinterpret_cast<const sockaddr*>(&address), 0)) != 0) return error;
        if ((error = uv_listen(reinterpret_cast<uv_stream_t*>(&server.listener), 128, connection)) != 0) return error;
        int length = sizeof(address);
        if ((error = uv_tcp_getsockname(&server.listener, reinterpret_cast<sockaddr*>(&address), &length)) != 0) return error;
        if ((error = uv_timer_init(&server.loop, &server.deadline)) != 0) return error;
        server.deadline.data = &server;
        if ((error = uv_timer_start(&server.deadline, [](uv_timer_t* timer) {
                stop_server(*static_cast<Server*>(timer->data));
            }, values[2], 0)) != 0) return error;
        std::printf("PORT=%u\n", static_cast<unsigned>(ntohs(address.sin_port)));
        std::fflush(stdout);
        return 0;
    };
    if (const int error = run(); error != 0) stop_server(server, error);
    uv_run(&server.loop, UV_RUN_DEFAULT);
    if (uv_loop_close(&server.loop) != 0) return 1;
    if (server.status == 0)
        std::printf("accepted=%zu rejected=%zu completed=%zu failed=%zu peak_active=%zu\n",
                    server.accepted, server.rejected, server.completed, server.failed, server.peak_active);
    return server.status;
}
