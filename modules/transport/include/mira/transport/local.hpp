#pragma once
#include "mira/transport/tcp.hpp"
#include <string>
#include <utility>

namespace Mira::transport::local {

/// Filesystem-addressed Unix-domain byte stream. POSIX runtime support;
/// Windows factories return not_supported. No abstract namespace or FD passing.
class Socket {
public:
    Socket() = default;
    Socket(EventLoop& loop, NativeHandle handle) : stream_(loop, handle) {}
    Socket(Socket&&) noexcept = default;
    Socket& operator=(Socket&&) noexcept = default;
    Task<Result<std::size_t>> read_some(std::span<std::byte> data, OperationOptions io = {}) {
        return stream_.read_some(data, std::move(io));
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> data, OperationOptions io = {}) {
        return stream_.write_some(data, std::move(io));
    }
    Task<Result<std::size_t>> writev_some(std::span<const std::span<const std::byte>> data,
                                         OperationOptions io = {}) {
        return stream_.writev_some(data, std::move(io));
    }
    void close() noexcept { stream_.close(); }
    bool valid() const noexcept { return stream_.valid(); }
    NativeHandle native_handle() const noexcept { return stream_.native_handle(); }
private:
    tcp::Socket stream_;
};

class Listener {
public:
    /// Never removes an existing filesystem entry. After closing the listener,
    /// the caller owns removal of its socket pathname and directory.
    static Result<Listener> bind(EventLoop& loop, std::string path, int backlog = 128);
    Listener(Listener&& other) noexcept
        : loop_(std::exchange(other.loop_, nullptr)), handle_(std::exchange(other.handle_, invalid_handle)) {}
    Listener& operator=(Listener&& other) noexcept {
        if (this != &other) {
            auto previous = std::move(*this);
            loop_ = std::exchange(other.loop_, nullptr);
            handle_ = std::exchange(other.handle_, invalid_handle);
            return *this;
        }
        return *this;
    }
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;
    ~Listener() { close(); }
    Task<Result<Socket>> accept(OperationOptions io = {});
    void close() noexcept;
    NativeHandle native_handle() const noexcept { return handle_; }
private:
    Listener(EventLoop& loop, NativeHandle handle) : loop_(&loop), handle_(handle) {}
    EventLoop* loop_;
    NativeHandle handle_;
};
Task<Result<Socket>> connect(EventLoop& loop, std::string path, OperationOptions io = {});
}  // namespace Mira::transport::local
