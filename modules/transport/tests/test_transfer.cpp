#include "check.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/core/stream.hpp"
#include "mira/transport/tcp.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#if MIRA_PLATFORM_WINDOWS
#include <windows.h>
#include <winioctl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if MIRA_PLATFORM_LINUX || MIRA_PLATFORM_ANDROID
#include <pthread.h>
#include <signal.h>
#include <sys/sendfile.h>
#endif

#if MIRA_TEST_WRAP_SENDFILE
namespace {
struct SendfileProbe {
    int socket{-1};
    int file{-1};
    int injected_error{};
    std::size_t before_failure{};
    std::size_t calls{};
    std::size_t real_calls{};
    std::size_t native_bytes{};
    std::size_t failures{};
    int last_real_error{};
    bool pipe_blocked{};
    bool pipe_pending{};
    std::uint64_t failure_offset{};
};
thread_local SendfileProbe sendfile_probe;

struct ProbeScope {
    ProbeScope(int socket, int file, int error = 0, std::size_t before_failure = 0) {
        CHECK(sendfile_probe.socket == -1);
        sendfile_probe = {.socket = socket, .file = file, .injected_error = error,
                          .before_failure = before_failure};
    }
    ~ProbeScope() { sendfile_probe = {}; }
};

template <typename Offset>
ssize_t probe_sendfile(int socket, int file, Offset* offset, std::size_t count,
                      ssize_t (*native_call)(int, int, Offset*, std::size_t)) {
    auto& probe = sendfile_probe;
    if (socket != probe.socket || file != probe.file)
        return native_call(socket, file, offset, count);
    ++probe.calls;
    if (probe.injected_error != 0) {
        if (probe.native_bytes >= probe.before_failure) {
            ++probe.failures;
            if (offset != nullptr) probe.failure_offset = static_cast<std::uint64_t>(*offset);
            errno = probe.injected_error;
            return -1;
        }
        count = (std::min)(count, probe.before_failure - probe.native_bytes);
    }
    ++probe.real_calls;
    const auto result = native_call(socket, file, offset, count);
    const int saved_error = errno;
    probe.last_real_error = result < 0 ? saved_error : 0;
    if (probe.last_real_error == EPIPE) {
        sigset_t mask{}, pending{};
        probe.pipe_blocked = ::pthread_sigmask(SIG_SETMASK, nullptr, &mask) == 0 &&
                             ::sigismember(&mask, SIGPIPE) == 1;
        probe.pipe_pending = ::sigpending(&pending) == 0 && ::sigismember(&pending, SIGPIPE) == 1;
    }
    if (result > 0) probe.native_bytes += static_cast<std::size_t>(result);
    errno = saved_error;
    return result;
}
}  // namespace

extern "C" ssize_t __real_sendfile(int, int, off_t*, std::size_t);
extern "C" ssize_t __real_sendfile64(int, int, off64_t*, std::size_t);
extern "C" ssize_t __wrap_sendfile(int socket, int file, off_t* offset, std::size_t count) {
    return probe_sendfile(socket, file, offset, count, __real_sendfile);
}
extern "C" ssize_t __wrap_sendfile64(int socket, int file, off64_t* offset, std::size_t count) {
    return probe_sendfile(socket, file, offset, count, __real_sendfile64);
}
#endif

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

bool prepare_sparse_region(const Fixture& fixture, std::uint64_t offset) {
#if MIRA_PLATFORM_WINDOWS
    const HANDLE writer = ::CreateFileW(fixture.path.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(writer != INVALID_HANDLE_VALUE);
    if (writer == INVALID_HANDLE_VALUE) return false;
    DWORD returned = 0;
    const bool sparse = ::DeviceIoControl(writer, FSCTL_SET_SPARSE, nullptr, 0,
        nullptr, 0, &returned, nullptr) != 0;
    CHECK(sparse);
    bool written = false;
    if (sparse) {
        LARGE_INTEGER position{};
        position.QuadPart = static_cast<LONGLONG>(offset);
        const bool positioned = ::SetFilePointerEx(writer, position, nullptr, FILE_BEGIN) != 0;
        CHECK(positioned);
        if (positioned) {
            DWORD bytes = 0;
            written = ::WriteFile(writer, fixture.content.data(),
                static_cast<DWORD>(fixture.content.size()), &bytes, nullptr) != 0 &&
                bytes == fixture.content.size();
            CHECK(written);
        }
    }
    CHECK(::CloseHandle(writer) != 0);
    return written;
#else
    const int writer = ::open(fixture.path.c_str(), O_WRONLY | O_CLOEXEC);
    CHECK(writer >= 0);
    if (writer < 0) return false;
    const bool extended = ::ftruncate(writer, static_cast<off_t>(offset + fixture.content.size())) == 0;
    CHECK(extended);
    std::size_t done = 0;
    while (extended && done < fixture.content.size()) {
        const auto written = ::pwrite(writer, fixture.content.data() + done,
            fixture.content.size() - done, static_cast<off_t>(offset + done));
        if (written < 0 && errno == EINTR) continue;
        CHECK(written > 0);
        if (written <= 0) break;
        done += static_cast<std::size_t>(written);
    }
    struct stat info{};
    CHECK(::fstat(writer, &info) == 0);
    CHECK(info.st_blocks >= 0 && static_cast<std::uint64_t>(info.st_blocks) * 512 < 1024 * 1024);
    CHECK(::close(writer) == 0);
    return extended && done == fixture.content.size();
#endif
}

Task<void> receive_to_eof(tcp::Socket& peer, std::span<const std::byte> expected,
                          OperationOptions io) {
    std::array<std::byte, 4096> buffer{};
    std::size_t done = 0;
    for (;;) {
        const auto read = co_await peer.read_some(buffer, io);
        if (!read) {
            CHECK(read.error() == make_error_code(Errc::eof));
            break;
        }
        CHECK(*read != 0 && *read <= expected.size() - done);
        if (*read == 0 || *read > expected.size() - done) co_return;
        CHECK(std::equal(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*read),
                         expected.begin() + static_cast<std::ptrdiff_t>(done)));
        done += *read;
    }
    CHECK(done == expected.size());
}

Task<void> sparse_region_transfer(EventLoop& loop, const FileSource& file,
                                 const Fixture& fixture, std::uint64_t offset, TransferMode mode) {
    const OperationOptions io{.deadline = Clock::now() + 5s};
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    std::vector<std::byte> copied(fixture.content.size());
    const auto read = file.read_at(offset, copied);
    CHECK(read && *read == copied.size());
    CHECK(copied == fixture.content);
    TaskScope scope;
    auto receiver = [&]() -> Task<void> {
        auto peer = co_await listener->accept(io);
        CHECK(peer.has_value());
        if (peer) co_await receive_to_eof(*peer, fixture.content, io);
    };
    auto sender = [&]() -> Task<void> {
        auto peer = co_await tcp::connect(loop, listener->local_endpoint(), {}, io);
        CHECK(peer.has_value());
        if (!peer) co_return;
        const auto sent = co_await peer->send_file(file, offset, fixture.content.size(),
            {.mode = mode, .chunk_size = 1024}, io);
        CHECK(sent.has_value());
        if (sent) {
            CHECK(sent->bytes == fixture.content.size());
            CHECK(sent->native_bytes == (mode == TransferMode::copy ? 0 : fixture.content.size()));
            CHECK(sent->copied_bytes == (mode == TransferMode::copy ? fixture.content.size() : 0));
        }
        CHECK(peer->shutdown_send().has_value());
    };
    scope.spawn(receiver()); scope.spawn(sender());
    co_await scope.join();
}

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

Task<void> truncated_file_transfer(EventLoop& loop, TransferMode mode) {
    Fixture fixture{32 * 1024 + 13};
    auto source = FileSource::open(fixture.path);
    CHECK(source.has_value());
    if (!source) co_return;
#if MIRA_PLATFORM_WINDOWS
    // FileSource 不允许写共享；这里验证边界，不通过私有句柄破坏借用约定。
    const HANDLE writer = ::CreateFileW(fixture.path.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD error = ::GetLastError();
    CHECK(writer == INVALID_HANDLE_VALUE);
    if (writer != INVALID_HANDLE_VALUE) CHECK(::CloseHandle(writer) != 0);
    else CHECK(error == ERROR_SHARING_VIOLATION);
    CHECK(std::filesystem::file_size(fixture.path) == fixture.content.size());
    static_cast<void>(loop);
    static_cast<void>(mode);
#else
    // 独立 writer 在第一次传输前截断，传输中及接收完成前不修改内容。
    constexpr std::size_t remaining = 8192 + 31;
    const int writer = ::open(fixture.path.c_str(), O_WRONLY | O_CLOEXEC);
    CHECK(writer >= 0);
    if (writer < 0) co_return;
    const bool truncated = ::ftruncate(writer, static_cast<off_t>(remaining)) == 0;
    CHECK(truncated);
    CHECK(::close(writer) == 0);
    if (!truncated) co_return;
    CHECK(source->size() == fixture.content.size());
    CHECK(std::filesystem::file_size(fixture.path) == remaining);
    const OperationOptions io{.deadline = Clock::now() + 5s};
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    TaskScope scope;
    auto receiver = [&]() -> Task<void> {
        auto peer = co_await listener->accept(io);
        CHECK(peer.has_value());
        if (peer) co_await receive_to_eof(*peer, std::span{fixture.content}.first(remaining), io);
    };
    auto sender = [&]() -> Task<void> {
        auto peer = co_await tcp::connect(loop, listener->local_endpoint(), {}, io);
        CHECK(peer.has_value());
        if (!peer) co_return;
        const auto sent = co_await peer->send_file(*source, 0, fixture.content.size(),
            {.mode = mode, .chunk_size = 1024}, io);
        CHECK(!sent && sent.error() == make_error_code(Errc::eof));
        // 错误可能晚于部分线上 I/O，按 contract 关闭连接，绝不重试原始区间。
        CHECK(peer->shutdown_send().has_value());
        peer->close();
    };
    scope.spawn(receiver()); scope.spawn(sender());
    co_await scope.join();
#endif
}

#if MIRA_TEST_WRAP_SENDFILE
Task<void> unsupported_native_transfer(EventLoop& loop, Fixture& fixture, int error,
                                        TransferMode mode, std::size_t native_prefix) {
    auto source = FileSource::open(fixture.path);
    CHECK(source.has_value());
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!source || !listener) co_return;
    constexpr std::size_t offset = 7;
    const std::size_t length = fixture.content.size() - offset;
    const std::size_t expected_length = mode == TransferMode::require_native ? native_prefix : length;
    const OperationOptions io{.deadline = Clock::now() + 5s};
    TaskScope scope;
    auto receiver = [&]() -> Task<void> {
        auto peer = co_await listener->accept(io);
        CHECK(peer.has_value());
        if (peer) co_await receive_to_eof(*peer,
            std::span{fixture.content}.subspan(offset, expected_length), io);
    };
    auto sender = [&]() -> Task<void> {
        auto peer = co_await tcp::connect(loop, listener->local_endpoint(), {}, io);
        CHECK(peer.has_value());
        if (!peer) co_return;
        ProbeScope probe{peer->native_handle(), source->native_handle(), error, native_prefix};
        const auto sent = co_await peer->send_file(*source, offset, length,
            {.mode = mode, .chunk_size = 1024}, io);
        CHECK(sendfile_probe.failures == 1);
        CHECK(sendfile_probe.calls == sendfile_probe.real_calls + 1);
        CHECK(sendfile_probe.native_bytes == native_prefix);
        CHECK(sendfile_probe.failure_offset == offset + native_prefix);
        if (mode == TransferMode::require_native) {
            CHECK(!sent && sent.error() == make_error_code(Errc::not_supported));
        } else {
            CHECK(sent.has_value());
            if (sent) {
                CHECK(sent->bytes == length);
                CHECK(sent->native_bytes == native_prefix);
                CHECK(sent->copied_bytes == length - native_prefix);
            }
        }
        CHECK(peer->shutdown_send().has_value());
    };
    scope.spawn(receiver()); scope.spawn(sender());
    co_await scope.join();
}
#endif

#if MIRA_PLATFORM_LINUX || MIRA_PLATFORM_ANDROID
struct ThreadSignalMask {
    sigset_t original{};
    sigset_t pipe_set{};
    bool valid{};
    bool generated_pending{};

    ThreadSignalMask() {
        CHECK(::sigemptyset(&pipe_set) == 0);
        CHECK(::sigaddset(&pipe_set, SIGPIPE) == 0);
        valid = ::pthread_sigmask(SIG_SETMASK, nullptr, &original) == 0;
        CHECK(valid);
    }
    ~ThreadSignalMask() {
        if (!valid) return;
        if (generated_pending) {
            CHECK(::pthread_sigmask(SIG_BLOCK, &pipe_set, nullptr) == 0);
            const timespec no_wait{};
            int signal = 0;
            do { signal = ::sigtimedwait(&pipe_set, nullptr, &no_wait); }
            while (signal < 0 && errno == EINTR);
            CHECK(signal == SIGPIPE);
        }
        CHECK(::pthread_sigmask(SIG_SETMASK, &original, nullptr) == 0);
    }
};

bool same_signal_mask(const sigset_t& left, const sigset_t& right) {
    for (int signal = 1; signal < NSIG; ++signal)
        if (::sigismember(&left, signal) != ::sigismember(&right, signal)) return false;
    return true;
}

Task<void> native_broken_pipe(EventLoop& loop, const FileSource& source, bool pending_before) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) co_return;
    const OperationOptions io{.deadline = Clock::now() + 5s};
    TaskScope scope;
    auto receiver = [&]() -> Task<void> {
        auto peer = co_await listener->accept(io);
        CHECK(peer.has_value());
        if (peer) co_await receive_to_eof(*peer, {}, io);
    };
    auto sender = [&]() -> Task<void> {
        auto peer = co_await tcp::connect(loop, listener->local_endpoint(), {}, io);
        CHECK(peer.has_value());
        if (!peer) co_return;
        // 本地关闭写端可确定地产生 EPIPE，不依赖远端 FIN/RST 到达时序。
        const auto shutdown = peer->shutdown_send();
        CHECK(shutdown.has_value());
        if (!shutdown) co_return;
        ThreadSignalMask guard;
        if (!guard.valid) co_return;
        struct sigaction disposition{};
        const int disposition_result = ::sigaction(SIGPIPE, nullptr, &disposition);
        CHECK(disposition_result == 0);
        if (disposition_result != 0) co_return;
        sigset_t pending{};
        const int queried = ::sigpending(&pending);
        CHECK(queried == 0);
        const bool unexpected_pending = ::sigismember(&pending, SIGPIPE) == 1;
        CHECK(!unexpected_pending);
        if (queried != 0 || unexpected_pending) co_return;
        auto expected_mask = guard.original;
        CHECK(::sigaddset(&expected_mask, SIGUSR1) == 0);
        if (pending_before) CHECK(::sigaddset(&expected_mask, SIGPIPE) == 0);
        else CHECK(::sigdelset(&expected_mask, SIGPIPE) == 0);
        const int masked = ::pthread_sigmask(SIG_SETMASK, &expected_mask, nullptr);
        CHECK(masked == 0);
        if (masked != 0) co_return;
        if (pending_before) {
            const int raised = ::pthread_kill(::pthread_self(), SIGPIPE);
            CHECK(raised == 0);
            if (raised != 0) co_return;
            guard.generated_pending = true;
            CHECK(::sigpending(&pending) == 0);
            CHECK(::sigismember(&pending, SIGPIPE) == 1);
        }
#if MIRA_TEST_WRAP_SENDFILE
        ProbeScope probe{peer->native_handle(), source.native_handle()};
#endif
        const auto sent = co_await loop.send_file(peer->native_handle(), source.native_handle(), 0, 1024, io);
        CHECK(!sent && sent.error() == socket_error(EPIPE));
#if MIRA_TEST_WRAP_SENDFILE
        CHECK(sendfile_probe.real_calls == 1);
        CHECK(sendfile_probe.last_real_error == EPIPE);
        CHECK(sendfile_probe.pipe_blocked);
        CHECK(sendfile_probe.pipe_pending);
        CHECK(sendfile_probe.failures == 0);
#endif
        sigset_t after{};
        CHECK(::pthread_sigmask(SIG_SETMASK, nullptr, &after) == 0);
        CHECK(same_signal_mask(expected_mask, after));
        CHECK(::sigpending(&pending) == 0);
        CHECK(::sigismember(&pending, SIGPIPE) == (pending_before ? 1 : 0));
        struct sigaction disposition_after{};
        CHECK(::sigaction(SIGPIPE, nullptr, &disposition_after) == 0);
        CHECK(disposition_after.sa_handler == disposition.sa_handler);
        CHECK(disposition_after.sa_flags == disposition.sa_flags);
        CHECK(same_signal_mask(disposition_after.sa_mask, disposition.sa_mask));
    };
    scope.spawn(receiver()); scope.spawn(sender());
    co_await scope.join();
}
#endif

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

    test::section("稀疏文件超过 4 GiB 的偏移及 native/copy 记账");
    Fixture sparse{8192 + 19};
    constexpr std::uint64_t sparse_offset = (std::uint64_t{1} << 32) + 123;
    if (prepare_sparse_region(sparse, sparse_offset)) {
        auto sparse_source = FileSource::open(sparse.path);
        CHECK(sparse_source.has_value());
        if (sparse_source) {
            CHECK(sparse_source->size() == sparse_offset + sparse.content.size());
            for (const auto mode : {TransferMode::copy, TransferMode::prefer_native, TransferMode::require_native})
                CHECK(loop->run_until_complete(sparse_region_transfer(
                    *loop, *sparse_source, sparse, sparse_offset, mode)).has_value());
        }
    }

    test::section("外部截断后明确 EOF，部分内容不重放");
#if MIRA_PLATFORM_WINDOWS
    test::section("Windows FileSource 禁止写共享，外部截断必须被拒绝");
    CHECK(loop->run_until_complete(truncated_file_transfer(*loop, TransferMode::copy)).has_value());
#else
    for (const auto mode : {TransferMode::copy, TransferMode::prefer_native, TransferMode::require_native})
        CHECK(loop->run_until_complete(truncated_file_transfer(*loop, mode)).has_value());
#endif

#if MIRA_TEST_WRAP_SENDFILE
    test::section("真实 native 调用入口的 EINVAL/ENOSYS 注入与回退");
    Fixture fallback{16 * 1024 + 13};
    for (const int error : {EINVAL, ENOSYS})
        for (const auto mode : {TransferMode::prefer_native, TransferMode::require_native})
            for (const std::size_t prefix : {std::size_t{0}, std::size_t{2048}})
                CHECK(loop->run_until_complete(unsupported_native_transfer(
                    *loop, fallback, error, mode, prefix)).has_value());
#endif
#if MIRA_PLATFORM_LINUX || MIRA_PLATFORM_ANDROID
    test::section("真实 sendfile EPIPE 存活、线程掩码恢复与原 pending SIGPIPE 保留");
    auto signal_source = FileSource::open(fixture.path);
    CHECK(signal_source.has_value());
    if (signal_source) for (const bool pending_before : {false, true})
        CHECK(loop->run_until_complete(native_broken_pipe(*loop, *signal_source, pending_before)).has_value());
#endif

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
