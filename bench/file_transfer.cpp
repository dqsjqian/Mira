// In-process file transfer benchmark. Reports measurements, not a performance
// guarantee; the copy/native paths use identical payloads and receive checks.
#include "mira/core/task_scope.hpp"
#include "mira/transport/tcp.hpp"
#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <vector>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;

Task<void> exchange(EventLoop& loop, const FileSource& file, TransferMode mode,
                    bool& ok, std::size_t& native) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    if (!listener) co_return;
    const OperationOptions io{.deadline = Clock::now() + 30s};
    bool sent_ok = false, received_ok = false;
    TaskScope scope;
    auto receive = [&]() -> Task<void> {
        auto socket = co_await listener->accept(io);
        if (!socket) co_return;
        std::array<std::byte, 65536> buffer{};
        std::size_t count = 0;
        while (count < file.size()) {
            auto n = co_await socket->read_some(buffer, io);
            if (!n || *n == 0) co_return;
            for (std::size_t i = 0; i < *n; ++i)
                if (buffer[i] != std::byte{0x5a}) co_return;
            count += *n;
        }
        received_ok = count == file.size();
    };
    auto send = [&]() -> Task<void> {
        auto socket = co_await tcp::connect(loop, listener->local_endpoint(), {}, io);
        if (!socket) co_return;
        auto result = co_await socket->send_file(file, 0, static_cast<std::size_t>(file.size()),
            {.mode = mode, .chunk_size = 1024 * 1024}, io);
        if (result) { sent_ok = result->bytes == file.size(); native += result->native_bytes; }
    };
    scope.spawn(receive()); scope.spawn(send());
    co_await scope.join();
    ok = sent_ok && received_ok;
}

int main() {
    constexpr std::size_t size = 32 * 1024 * 1024;
    constexpr int repetitions = 5;
    const auto path = std::filesystem::temp_directory_path() /
        ("mira-file-bench-" + std::to_string(std::random_device{}()) + ".bin");
    struct Cleanup { std::filesystem::path path; ~Cleanup() { std::error_code e; std::filesystem::remove(path,e); } } cleanup{path};
    {
        const std::vector<char> content(size, '\x5a');
        std::ofstream out(path, std::ios::binary);
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!out) return 1;
    }
    auto file = FileSource::open(path);
    auto loop = EventLoop::create();
    if (!file || !loop) return 1;
    for (const auto mode : {TransferMode::copy, TransferMode::require_native}) {
        const auto start = Clock::now();
        std::size_t native = 0;
        for (int i = 0; i < repetitions; ++i) {
            bool ok = false;
            if (!loop->run_until_complete(exchange(*loop, *file, mode, ok, native)) || !ok) return 1;
        }
        const double seconds = std::chrono::duration<double>(Clock::now() - start).count();
        std::printf("{\"mode\":\"%s\",\"bytes\":%zu,\"seconds\":%.6f,\"MiB_per_second\":%.2f,\"native_bytes\":%zu}\n",
            mode == TransferMode::copy ? "copy" : "native", size * repetitions, seconds,
            static_cast<double>(size * repetitions) / (1024.0 * 1024.0) / seconds, native);
    }
    return 0;
}
