#include "check.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/core/stream.hpp"
#include "mira/transport/tcp.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;

struct Fixture {
    std::filesystem::path path;
    std::vector<std::byte> content;
    explicit Fixture(std::size_t size) : content(size) {
        path = std::filesystem::temp_directory_path() /
            ("mira-transfer-" + std::to_string(std::random_device{}()) + ".bin");
        for (std::size_t i = 0; i < size; ++i) content[i] = static_cast<std::byte>(i % 251);
        std::ofstream out{path, std::ios::binary};
        out.write(reinterpret_cast<const char*>(content.data()), static_cast<std::streamsize>(content.size()));
        if (!out) throw std::runtime_error("cannot prepare transfer fixture");
    }
    ~Fixture() { std::error_code ignored; std::filesystem::remove(path, ignored); }
};

Task<void> round_trip(EventLoop& loop, Fixture& fixture, TransferMode mode, bool buffer_mode,
                      TransferResult& report) {
    auto source = FileSource::open(fixture.path);
    CHECK(source.has_value());
    if (!source) co_return;
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    const std::size_t offset = buffer_mode ? 0 : 7;
    const std::size_t length = fixture.content.size() - offset;
    const OperationOptions io{.deadline = Clock::now() + 15s};
    std::vector<std::byte> received(length);
    TaskScope scope;
    auto server = [&]() -> Task<void> {
        auto peer = co_await listener->accept(io);
        CHECK(peer.has_value());
        if (!peer) co_return;
        std::size_t done = 0;
        while (done < received.size()) {
            const auto read = co_await peer->read_some(std::span{received}.subspan(done), io);
            CHECK(read.has_value());
            if (!read || *read == 0) co_return;
            done += *read;
        }
    };
    auto client = [&]() -> Task<void> {
        auto peer = co_await tcp::connect(loop, listener->local_endpoint(), {}, io);
        CHECK(peer.has_value());
        if (!peer) co_return;
        Result<TransferResult> sent = fail(Errc::invalid_argument);
        if (buffer_mode) {
            sent = co_await peer->send_buffer(fixture.content, {.mode = mode, .chunk_size = 8192}, io);
        } else {
            sent = co_await peer->send_file(*source, offset, length, {.mode = mode, .chunk_size = 8192}, io);
        }
        if (!sent) std::fprintf(stderr, "transfer mode=%d buffer=%d: %s (%d)\n",
            static_cast<int>(mode), static_cast<int>(buffer_mode), sent.error().message().c_str(), sent.error().value());
        CHECK(sent.has_value());
        if (sent) {
            report = *sent;
            CHECK(sent->bytes == length);
            CHECK(sent->native_bytes + sent->copied_bytes == length);
            if (mode == TransferMode::copy || buffer_mode) CHECK(sent->copied_bytes == length);
        }
        // A buffer becomes reusable only after completion; make early release
        // visible to the receiver if an implementation reports it too soon.
        if (buffer_mode) std::fill(fixture.content.begin(), fixture.content.end(), std::byte{0xff});
    };
    scope.spawn(server());
    scope.spawn(client());
    co_await scope.join();
    for (std::size_t i = 0; i < received.size(); ++i) {
        if (received[i] != static_cast<std::byte>((i + offset) % 251)) {
            CHECK(false);
            co_return;
        }
    }
    CHECK(true);
}

Task<void> boundaries(EventLoop& loop, Fixture& fixture) {
    auto source = FileSource::open(fixture.path);
    CHECK(source.has_value());
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!source || !listener) co_return;
    TaskScope scope;
    auto server = [&]() -> Task<void> {
        auto socket = co_await listener->accept({.deadline = Clock::now() + 5s});
        CHECK(socket.has_value());
        if (socket) co_await loop.sleep_for(60ms);
    };
    auto client = [&]() -> Task<void> {
        auto socket = co_await tcp::connect(loop, listener->local_endpoint());
        CHECK(socket.has_value());
        if (!socket) co_return;
        std::stop_source cancelled;
        cancelled.request_stop();
        const auto cancel = co_await socket->send_file(*source, 0, 0, {}, {.stop = cancelled.get_token()});
        CHECK(!cancel && cancel.error() == make_error_code(Errc::cancelled));
        const auto timeout = co_await socket->send_buffer({}, {}, {.deadline = Clock::now() - 1ms});
        CHECK(!timeout && timeout.error() == make_error_code(Errc::timed_out));
        const auto range = co_await socket->send_file(*source, source->size(), 1);
        CHECK(!range && range.error() == make_error_code(Errc::invalid_argument));
        const auto invalid = co_await socket->send_file(*source, 0, 1, {.chunk_size = 0});
        CHECK(!invalid && invalid.error() == make_error_code(Errc::invalid_argument));
        const auto strict = co_await socket->send_buffer({}, {.mode = TransferMode::require_native});
        CHECK(!strict && strict.error() == make_error_code(Errc::not_supported));
        const auto empty = co_await socket->send_file(*source, source->size(), 0);
        CHECK(empty && empty->bytes == 0);
        const auto eof = co_await loop.send_file(socket->native_handle(), source->native_handle(), source->size(), 10);
        CHECK(eof && *eof == 0);
    };
    scope.spawn(server());
    scope.spawn(client());
    co_await scope.join();
}

Task<void> cancelled_transfer(EventLoop& loop, const FileSource& file, TransferMode mode, bool cancel) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    TaskScope scope;
    std::stop_source stop;
    auto receiver = [&]() -> Task<void> {
        auto peer = co_await listener->accept({.deadline = Clock::now() + 2s});
        CHECK(peer.has_value());
        if (!peer) co_return;
        // Leave the socket unread so the sending path actually suspends.
        CHECK((co_await loop.sleep_for(80ms)).has_value());
    };
    auto canceller = [&]() -> Task<void> {
        CHECK((co_await loop.sleep_for(10ms)).has_value());
        if (cancel) stop.request_stop();
    };
    auto sender = [&]() -> Task<void> {
        auto peer = co_await tcp::connect(loop, listener->local_endpoint());
        CHECK(peer.has_value());
        if (!peer) co_return;
        OperationOptions options{.stop = stop.get_token(), .deadline = Clock::now() + (cancel ? 2s : 15ms)};
        const auto result = co_await peer->send_file(file, 0, static_cast<std::size_t>(file.size()),
            {.mode = mode, .chunk_size = 65536}, options);
        CHECK(!result && result.error() == make_error_code(cancel ? Errc::cancelled : Errc::timed_out));
    };
    scope.spawn(receiver()); scope.spawn(sender()); scope.spawn(canceller());
    co_await scope.join();
}

Task<void> close_during_transfer(EventLoop& loop, const FileSource& file, TransferMode mode) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    std::unique_ptr<tcp::Socket> socket;
    bool finished = false;
    TaskScope scope;
    auto receiver = [&]() -> Task<void> {
        auto peer = co_await listener->accept({.deadline = Clock::now() + 2s});
        CHECK(peer.has_value());
        if (peer) CHECK((co_await loop.sleep_for(50ms)).has_value());
    };
    auto sender = [&]() -> Task<void> {
        auto connected = co_await tcp::connect(loop, listener->local_endpoint());
        CHECK(connected.has_value());
        if (!connected) co_return;
        socket = std::make_unique<tcp::Socket>(std::move(*connected));
        const auto result = co_await socket->send_file(file, 0, static_cast<std::size_t>(file.size()),
            {.mode = mode, .chunk_size = 4096}, {.deadline = Clock::now() + 2s});
        CHECK(!result && result.error() == make_error_code(Errc::cancelled));
        finished = true;
    };
    auto closer = [&]() -> Task<void> {
        CHECK((co_await loop.sleep_for(5ms)).has_value());
        if (socket) {
            // Both competing transfers and close-after-yield are deterministic
            // public contracts; keep no reference to the wrapper in the sender.
            const auto busy = co_await socket->send_buffer({});
            CHECK(!busy && busy.error() == make_error_code(Errc::invalid_argument));
            auto closing = std::move(socket);
            closing.reset();
        }
    };
    scope.spawn(receiver()); scope.spawn(sender()); scope.spawn(closer());
    co_await scope.join();
    CHECK(finished);
}

int main() {
    test::section("native and copy file transfer, buffer completion lifetime");
    Fixture fixture{512 * 1024 + 13};
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (!loop) return test::summary();
    for (const auto mode : {TransferMode::copy, TransferMode::prefer_native, TransferMode::require_native}) {
        TransferResult result;
        CHECK(loop->run_until_complete(round_trip(*loop, fixture, mode, false, result)).has_value());
#if MIRA_PLATFORM_APPLE || MIRA_PLATFORM_LINUX || MIRA_PLATFORM_ANDROID || MIRA_PLATFORM_WINDOWS
        if (mode != TransferMode::copy) CHECK(result.native_bytes == fixture.content.size() - 7);
#endif
    }
    TransferResult result;
    CHECK(loop->run_until_complete(round_trip(*loop, fixture, TransferMode::prefer_native, true, result)).has_value());
    CHECK(loop->run_until_complete(boundaries(*loop, fixture)).has_value());
    Fixture large{32 * 1024 * 1024};
    auto source = FileSource::open(large.path);
    CHECK(source.has_value());
    if (source) for (const auto mode : {TransferMode::copy, TransferMode::prefer_native}) {
        CHECK(loop->run_until_complete(cancelled_transfer(*loop, *source, mode, true)).has_value());
        CHECK(loop->run_until_complete(cancelled_transfer(*loop, *source, mode, false)).has_value());
    }
    if (source) for (const auto mode : {TransferMode::copy, TransferMode::prefer_native})
        CHECK(loop->run_until_complete(close_during_transfer(*loop, *source, mode)).has_value());
    CHECK(loop->outstanding() == 0);
    CHECK(!FileSource::open(std::filesystem::temp_directory_path()));
    CHECK(!FileSource::open({}));
    return test::summary();
}
