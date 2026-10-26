#include "mira/transport/transfer.hpp"

#include <algorithm>
#include <cerrno>
#include <limits>
#if MIRA_PLATFORM_WINDOWS
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Mira::transport {
namespace {
void close_file(NativeHandle handle) noexcept {
    if (handle == invalid_handle) return;
#if MIRA_PLATFORM_WINDOWS
    (void)::CloseHandle(reinterpret_cast<HANDLE>(handle));
#else
    (void)::close(handle);
#endif
}
}  // namespace

FileSource& FileSource::operator=(FileSource&& other) noexcept {
    if (this != &other) {
        close_file(handle_);
        handle_ = std::exchange(other.handle_, invalid_handle);
        size_ = other.size_;
    }
    return *this;
}
FileSource::~FileSource() { close_file(handle_); }

Result<FileSource> FileSource::open(const std::filesystem::path& path) {
    if (path.empty() || path.native().find(typename std::filesystem::path::value_type{}) !=
        std::filesystem::path::string_type::npos) return fail(Errc::invalid_argument);
#if MIRA_PLATFORM_WINDOWS
    const HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return fail(socket_error(static_cast<int>(::GetLastError())));
    LARGE_INTEGER size{};
    if (::GetFileType(handle) != FILE_TYPE_DISK || !::GetFileSizeEx(handle, &size) || size.QuadPart < 0) {
        ::CloseHandle(handle);
        return fail(Errc::invalid_argument);
    }
    return FileSource{reinterpret_cast<NativeHandle>(handle), static_cast<std::uint64_t>(size.QuadPart)};
#else
    const int handle = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (handle < 0) return fail(socket_error(errno));
    struct stat info{};
    if (::fstat(handle, &info) != 0) {
        const int saved = errno;
        ::close(handle);
        return fail(socket_error(saved));
    }
    if (!S_ISREG(info.st_mode) || info.st_size < 0) {
        ::close(handle);
        return fail(Errc::invalid_argument);
    }
    return FileSource{handle, static_cast<std::uint64_t>(info.st_size)};
#endif
}

Result<std::size_t> FileSource::read_at(std::uint64_t offset, std::span<std::byte> output) const {
    if (handle_ == invalid_handle || offset > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
        return fail(Errc::invalid_argument);
    if (output.empty() || offset >= size_) return std::size_t{0};
    const auto count = (std::min)(output.size(), std::size_t{1024 * 1024});
#if MIRA_PLATFORM_WINDOWS
    // Exclusive ownership permits a synchronous fallback read without sharing
    // a cursor. Native TransmitFile always uses its own OVERLAPPED offset.
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!::SetFilePointerEx(reinterpret_cast<HANDLE>(handle_), position, nullptr, FILE_BEGIN))
        return fail(socket_error(static_cast<int>(::GetLastError())));
    DWORD read = 0;
    if (!::ReadFile(reinterpret_cast<HANDLE>(handle_), output.data(), static_cast<DWORD>(count), &read, nullptr))
        return fail(socket_error(static_cast<int>(::GetLastError())));
    return static_cast<std::size_t>(read);
#else
    for (;;) {
        const ssize_t read = ::pread(handle_, output.data(), count, static_cast<off_t>(offset));
        if (read >= 0) return static_cast<std::size_t>(read);
        if (errno != EINTR) return fail(socket_error(errno));
    }
#endif
}
}  // namespace Mira::transport
