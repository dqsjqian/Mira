// Event loop — Windows backend (I/O completion ports).
//
// This is where the completion-shaped public API pays for itself: `read()` is
// a `WSARecv` with an OVERLAPPED, and the loop hands the result back when the
// port reports it. No readiness emulation, no `select` fallback, no
// second-class Windows path.
//
// The OVERLAPPED trick: each in-flight operation allocates an `Operation`
// whose first member *is* an OVERLAPPED, so the pointer the kernel returns can
// be cast straight back to the owning operation. The operation is owned by the
// loop between submission and completion — a coroutine that is cancelled
// cannot free memory the kernel still writes into.
//
// NOT validated on the author's machine (macOS). CI's Windows job is the only
// thing that exercises this file; treat its first green run as the real
// verification, not this comment.

#include "mira/core/platform.hpp"

#if MIRA_PLATFORM_WINDOWS

    #include "mira/core/event_loop.hpp"

// clang-format off
#    include <winsock2.h>
#    include <windows.h>
#    include <ws2tcpip.h>
// clang-format on

    #include "loop_common.hpp"

    #include <array>
    #include <atomic>
    #include <exception>
    #include <cstring>
    #include <limits>
    #include <memory>
    #include <mswsock.h>
    #include <mutex>
    #include <optional>
    #include <unordered_map>
    #include <utility>
    #include <vector>

#if defined(_MSC_VER)
    #pragma comment(lib, "ws2_32.lib")
#endif

namespace Mira {
namespace {

[[nodiscard]] Error last_os_error() noexcept {
    return std::error_code{static_cast<int>(::GetLastError()), std::system_category()};
}

[[nodiscard]] Error last_socket_error() noexcept {
    return socket_error(::WSAGetLastError());
}

/// Completions drained per iteration — bounded so that one busy socket cannot
/// starve timers and posted work.
constexpr ULONG kEventBatch = 64;

/// Completion key used for `post()` wakeups, distinguishable from real I/O.
constexpr ULONG_PTR kWakeupKey = 1;

/// Per-endpoint slot size AcceptEx writes addresses into: a sockaddr plus the
/// 16 bytes of padding the API mandates.
constexpr DWORD kAddressSlot = sizeof(SOCKADDR_STORAGE) + 16;

/// AcceptEx and ConnectEx are not exported from a link library: they must be
/// fetched per-socket through WSAIoctl. Resolved once and cached, which is what
/// Microsoft's own documentation prescribes.
template<typename Fn>
[[nodiscard]] Result<Fn> resolve_extension(SOCKET socket, GUID guid) {
    Fn function = nullptr;
    DWORD written = 0;
    if (::WSAIoctl(socket,
                   SIO_GET_EXTENSION_FUNCTION_POINTER,
                   &guid,
                   sizeof(guid),
                   &function,
                   sizeof(function),
                   &written,
                   nullptr,
                   nullptr) == SOCKET_ERROR) {
        return fail(last_socket_error());
    }
    return function;
}

/// Winsock needs process-wide initialisation, exactly once.
[[nodiscard]] Result<void> ensure_winsock() {
    static Result<void> once = []() -> Result<void> {
        WSADATA data{};
        const int status = ::WSAStartup(MAKEWORD(2, 2), &data);
        if (status != 0) {
            return fail(std::error_code{status, std::system_category()});
        }
        return Result<void>{};
    }();
    return once;
}

}  // namespace

class EventLoop::Impl {
public:
    /// What an operation is, which decides how it resolves.
    ///
    /// The split that matters is `timer` against everything else: a timer has
    /// no completion packet, so it resolves the moment it fires, while every
    /// kernel-backed operation must wait for its packet even after being
    /// cancelled.
    enum class Kind { timer, read, write, accept, connect, receive_from, send_to };

    /// One in-flight operation.
    ///
    /// `overlapped` must stay first: the kernel hands back its address, and
    /// the loop casts it straight back to this object.
    struct Operation {
        OVERLAPPED overlapped{};
        detail::OperationId id{detail::kNoOperation};
        Kind kind{Kind::timer};
        std::coroutine_handle<> handle{};
        /// One slot or the other, depending on `kind`. A timer reports
        /// success or failure with no payload; everything else reports a byte
        /// count (or, for accept, the socket). Two pointers and a discriminant
        /// beat a variant here — the backend already knows which it submitted.
        Result<void>* void_result{nullptr};
        Result<std::size_t>* size_result{nullptr};
        WSABUF buffer{};
        // Scatter-write state: WSASend takes an array of buffers, so a
        // multi-piece write keeps its descriptors here for the duration of
        // the overlapped operation. 16 covers head + body + trailer shapes
        // without an allocation; the span shape is a convenience, not a
        // capacity promise (callers with more pieces can loop `write`).
        static constexpr std::size_t kMaxScatter = 16;
        std::array<WSABUF, kMaxScatter> scatter{};
        DWORD scatter_count{0};
        // Winsock may still write the address length and flags before the
        // asynchronous completion.
        SOCKADDR_STORAGE datagram_address{};
        int datagram_address_size{sizeof(SOCKADDR_STORAGE)};
        DWORD datagram_flags{0};
        DatagramResult* datagram_result{nullptr};
        char empty_buffer{0};
        std::size_t datagram_capacity{0};

        /// Accept-only state. AcceptEx requires the socket to exist *before*
        /// the operation is submitted, and writes both endpoint addresses into
        /// a caller-supplied buffer that must stay alive until completion —
        /// hence both living here, owned by the loop.
        /// The socket this operation was submitted on. Needed because an IOCP
        /// completion reports an NTSTATUS, and only WSAGetOverlappedResult can
        /// turn that back into a Winsock error number.
        SOCKET socket{INVALID_SOCKET};
        SOCKET accepted{INVALID_SOCKET};
        SOCKET listener{INVALID_SOCKET};
        /// Two sockaddr slots plus the 16-byte padding AcceptEx demands.
        std::array<std::byte, 2 * (sizeof(SOCKADDR_STORAGE) + 16)> address_scratch{};

        /// `detach` ran: the caller is about to close the handle, so never
        /// query Winsock with it and never `CancelIoEx` on it again.
        bool handle_closed{false};
        bool cancel_pending{false};

        /// The answer, decided before the operation could be resolved.
        ///
        /// A cancelled or timed-out kernel-backed operation stays in the table
        /// until its completion packet arrives, because until then the kernel
        /// may still be writing into the OVERLAPPED, the AcceptEx address
        /// buffer, and the caller's own buffer. When the packet finally lands,
        /// this reason is delivered instead of whatever the packet says — even
        /// if the packet says success.
        std::optional<Error> fixed_reason{};

        detail::TimerHandle wake{};
        detail::TimerHandle deadline{};

        /// True when the kernel owes this operation a completion packet.
        [[nodiscard]] bool kernel_backed() const noexcept { return kind != Kind::timer; }
    };

    explicit Impl(HANDLE port) noexcept : port_(port) {}

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    ~Impl() { shutdown(); }

    void shutdown() noexcept {
        // Idempotence cannot permit destruction from a continuation that this
        // shutdown is still dispatching: finalize still owns Impl state.
        if (dispatch_depth_ != 0) {
            detail::report_dispatch_violation("destroyed or replaced while dispatching");
        }
        if (shutting_down_.exchange(true, std::memory_order_acq_rel)) return;
        const detail::DispatchScope dispatching{dispatch_depth_};
        stop_requested_.store(true, std::memory_order_release);

        std::vector<move_only_function<void()>> discarded_work;
        std::size_t kernel_backed = 0;
        {
            const std::lock_guard lock{mutex_};
            posted_.drain_into(discarded_work);
            for (auto& entry : operations_) {
                Operation& operation = *entry.second;
                // An operation already cut short keeps the reason it was given:
                // a deadline that expired a moment ago is a truer answer than
                // "the loop went away".
                if (!operation.fixed_reason) {
                    operation.fixed_reason = make_error_code(Errc::cancelled);
                }
                if (!operation.kernel_backed()) {
                    continue;
                }
                ++kernel_backed;
                if (!operation.handle_closed) {
                    // CancelIoEx only queues completion; it does not resume
                    // user code, so no snapshot allocation is needed here.
                    ::CancelIoEx(reinterpret_cast<HANDLE>(operation.socket), &operation.overlapped);
                }
            }
        }

        // CancelIoEx only *asks*. Until the completion packet is dequeued the
        // kernel may still write into the OVERLAPPED, the AcceptEx address
        // buffer, and the caller's read or write buffer.

        // Even when a cancel reports ERROR_NOT_FOUND the operation may have
        // completed without being dequeued. Drain every kernel-backed one
        // before releasing a buffer or resuming a coroutine that might.
        //
        // Shutdown is forbidden during dispatch; after run_once returns every
        // dequeued operation has been finalized. Each remaining kernel-backed
        // operation therefore still owes exactly one packet. Timers are
        // excluded: counting them would wait for a packet that never comes.
        while (kernel_backed != 0) {
            DWORD transferred = 0;
            ULONG_PTR key = 0;
            OVERLAPPED* overlapped = nullptr;
            const BOOL ok =
                ::GetQueuedCompletionStatus(port_, &transferred, &key, &overlapped, INFINITE);
            if (overlapped == nullptr) {
                if (ok == FALSE) {
                    // Without confirmation that the kernel is finished,
                    // continuing to destruct would be a use-after-free.
                    std::terminate();
                }
                continue;
            }
            if (key == kWakeupKey) {
                continue;
            }
            // A failed I/O also returns a non-null OVERLAPPED, and it counts.
            --kernel_backed;
        }

        // The kernel has let go; only now may a coroutine that reclaims a
        // buffer run. The shutdown flag stops any of them re-submitting.
        for (;;) {
            detail::OperationId id;
            Error reason;
            {
                const std::lock_guard lock{mutex_};
                if (operations_.empty()) break;
                const auto& operation = *operations_.begin()->second;
                id = operation.id;
                reason = *operation.fixed_reason;
            }
            finalize(id, fail(reason));
        }
        discarded_work.clear();

        if (port_ != nullptr) {
            ::CloseHandle(std::exchange(port_, nullptr));
        }
    }

    // ── handle registration ─────────────────────────────────────────────────

    /// Associate the handle with the completion port. Required exactly once
    /// per handle before any overlapped operation on it.
    [[nodiscard]] Result<void> attach(NativeHandle handle) noexcept {
        if (shutting_down()) {
            return fail(Errc::cancelled);
        }
        if (handle == invalid_handle) {
            return fail(Errc::invalid_argument);
        }
        if (::CreateIoCompletionPort(reinterpret_cast<HANDLE>(handle), port_, 0, 0) == nullptr) {
            return fail(last_os_error());
        }
        // Completions must not also signal the handle, or every operation
        // would pay for an event nobody waits on.
        ::SetFileCompletionNotificationModes(reinterpret_cast<HANDLE>(handle),
                                             FILE_SKIP_SET_EVENT_ON_HANDLE);
        return Result<void>{};
    }

    void detach(NativeHandle handle) noexcept {
        // A handle cannot be removed from a completion port; cancelling its
        // outstanding operations is the closest equivalent, and the
        // completions still arrive (as ERROR_OPERATION_ABORTED) so no
        // operation leaks.
        {
            const std::lock_guard lock{mutex_};
            for (auto& entry : operations_) {
                if (entry.second->socket == static_cast<SOCKET>(handle)) {
                    entry.second->handle_closed = true;
                }
            }
        }
        ::CancelIoEx(reinterpret_cast<HANDLE>(handle), nullptr);
    }

    // ── submission ──────────────────────────────────────────────────────────

    [[nodiscard]] Result<detail::OperationId> submit_read(NativeHandle handle,
                                                          std::span<std::byte> destination,
                                                          const OperationOptions& options,
                                                          std::coroutine_handle<> coroutine,
                                                          Result<std::size_t>* result) {
        if (shutting_down()) {
            return fail(Errc::cancelled);
        }
        if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
            return fail(*rejected);
        }

        const Acquired acquired =
            acquire_operation(Kind::read, coroutine, std::nullopt, options);
        Operation* operation = acquired.operation;
        operation->size_result = result;
        operation->socket = static_cast<SOCKET>(handle);
        operation->buffer.buf = reinterpret_cast<CHAR*>(destination.data());
        operation->buffer.len = static_cast<ULONG>((std::min)(
            destination.size(), static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));

        DWORD flags = 0;
        const int status = ::WSARecv(static_cast<SOCKET>(handle),
                                     &operation->buffer,
                                     1,
                                     nullptr,
                                     &flags,
                                     &operation->overlapped,
                                     nullptr);
        if (status == 0 || ::WSAGetLastError() == WSA_IO_PENDING) {
            // Even an inline completion is posted to the port, so the
            // resumption path stays identical either way.
            return acquired.id;
        }

        const Error error = last_socket_error();
        discard(acquired.id);
        return fail(error);
    }

    [[nodiscard]] Result<detail::OperationId> submit_write(NativeHandle handle,
                                                           std::span<const std::byte> source,
                                                           const OperationOptions& options,
                                                           std::coroutine_handle<> coroutine,
                                                           Result<std::size_t>* result) {
        if (shutting_down()) {
            return fail(Errc::cancelled);
        }
        if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
            return fail(*rejected);
        }

        const Acquired acquired =
            acquire_operation(Kind::write, coroutine, std::nullopt, options);
        Operation* operation = acquired.operation;
        operation->size_result = result;
        operation->socket = static_cast<SOCKET>(handle);
        operation->buffer.buf = const_cast<CHAR*>(reinterpret_cast<const CHAR*>(source.data()));
        operation->buffer.len = static_cast<ULONG>((std::min)(
            source.size(), static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));

        const int status = ::WSASend(static_cast<SOCKET>(handle),
                                     &operation->buffer,
                                     1,
                                     nullptr,
                                     0,
                                     &operation->overlapped,
                                     nullptr);
        if (status == 0 || ::WSAGetLastError() == WSA_IO_PENDING) {
            return acquired.id;
        }

        const Error error = last_socket_error();
        discard(acquired.id);
        return fail(error);
    }

    /// Scatter form of `submit_write`: WSASend gathers the descriptors in one
    /// overlapped submission, so the pieces reach the kernel unconcatenated.
    [[nodiscard]] Result<detail::OperationId>
    submit_writev(NativeHandle handle, std::span<const std::span<const std::byte>> pieces,
                  const OperationOptions& options, std::coroutine_handle<> coroutine,
                  Result<std::size_t>* result) {
        if (shutting_down()) {
            return fail(Errc::cancelled);
        }
        if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
            return fail(*rejected);
        }
        if (std::none_of(pieces.begin(), pieces.end(), [](auto piece) { return !piece.empty(); })) {
            return fail(Errc::invalid_argument);
        }

        const Acquired acquired =
            acquire_operation(Kind::write, coroutine, std::nullopt, options);
        Operation* operation = acquired.operation;
        operation->size_result = result;
        operation->socket = static_cast<SOCKET>(handle);
        // IOCP reports a DWORD byte count for the entire submission, not
        // just for each WSABUF. Bound the complete prefix to that width.
        operation->scatter_count = static_cast<DWORD>(detail::visit_scatter_prefix(
            pieces, (std::numeric_limits<ULONG>::max)(), Operation::kMaxScatter,
            [operation](std::size_t index, std::span<const std::byte> piece) {
                operation->scatter[index].buf =
                    const_cast<CHAR*>(reinterpret_cast<const CHAR*>(piece.data()));
                operation->scatter[index].len = static_cast<ULONG>(piece.size());
            }));

        const int status = ::WSASend(static_cast<SOCKET>(handle),
                                     operation->scatter.data(),
                                     operation->scatter_count,
                                     nullptr,
                                     0,
                                     &operation->overlapped,
                                     nullptr);
        if (status == 0 || ::WSAGetLastError() == WSA_IO_PENDING) {
            return acquired.id;
        }

        const Error error = last_socket_error();
        discard(acquired.id);
        return fail(error);
    }

    [[nodiscard]] Result<detail::OperationId> submit_datagram(
        NativeHandle handle, std::span<std::byte> destination,
        std::span<const std::byte> source, std::span<const std::byte> address,
        DatagramResult* datagram, const OperationOptions& options,
        std::coroutine_handle<> coroutine, Result<std::size_t>* result) {
        if (shutting_down()) return fail(Errc::cancelled);
        if (const auto rejected = detail::rejected_before_submit(options)) return fail(*rejected);
        const bool receiving = datagram != nullptr;
        const Kind kind = receiving ? Kind::receive_from : Kind::send_to;
        const std::size_t size = receiving ? destination.size() : source.size();
        if (size > (std::numeric_limits<ULONG>::max)())
            return fail(std::make_error_code(std::errc::message_size));
        if (handle == invalid_handle || (!receiving &&
            (address.size() < sizeof(sockaddr) || address.size() > sizeof(SOCKADDR_STORAGE))))
            return fail(Errc::invalid_argument);
        {
            const std::lock_guard lock{mutex_};
            for (const auto& [id, op] : operations_) {
                if (op->socket == static_cast<SOCKET>(handle) && op->kind == kind &&
                    !op->handle_closed) return fail(Errc::invalid_argument);
            }
        }
        const Acquired acquired = acquire_operation(kind, coroutine, std::nullopt, options);
        Operation* op = acquired.operation;
        op->size_result = result;
        op->socket = static_cast<SOCKET>(handle);
        op->buffer.buf = receiving ? reinterpret_cast<char*>(destination.data())
            : const_cast<char*>(reinterpret_cast<const char*>(source.data()));
        if (size == 0) op->buffer.buf = &op->empty_buffer;
        op->buffer.len = static_cast<ULONG>(receiving && size == 0 ? 1 : size);
        op->datagram_capacity = size;
        op->datagram_result = datagram;
        int status = 0;
        if (receiving) {
            status = ::WSARecvFrom(op->socket, &op->buffer, 1, nullptr,
                &op->datagram_flags, reinterpret_cast<sockaddr*>(&op->datagram_address),
                &op->datagram_address_size, &op->overlapped, nullptr);
        } else {
            std::memcpy(&op->datagram_address, address.data(), address.size());
            op->datagram_address_size = static_cast<int>(address.size());
            status = ::WSASendTo(op->socket, &op->buffer, 1, nullptr, 0,
                reinterpret_cast<const sockaddr*>(&op->datagram_address),
                op->datagram_address_size, &op->overlapped, nullptr);
        }
        if (status == 0 || ::WSAGetLastError() == WSA_IO_PENDING) return acquired.id;
        const int error = ::WSAGetLastError();
        discard(acquired.id);
        if (error == WSAEMSGSIZE) return fail(std::make_error_code(std::errc::message_size));
        return fail(socket_error(error));
    }

    [[nodiscard]] Result<detail::OperationId> submit_accept(NativeHandle listener,
                                                            int address_family,
                                                            const OperationOptions& options,
                                                            std::coroutine_handle<> coroutine,
                                                            Result<std::size_t>* result) {
        if (shutting_down()) {
            return fail(Errc::cancelled);
        }
        if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
            return fail(*rejected);
        }

        const auto listening = static_cast<SOCKET>(listener);
        if (accept_ex_ == nullptr) {
            GUID guid = WSAID_ACCEPTEX;
            Result<LPFN_ACCEPTEX> resolved = resolve_extension<LPFN_ACCEPTEX>(listening, guid);
            if (!resolved) {
                return fail(resolved.error());
            }
            accept_ex_ = *resolved;
        }

        // AcceptEx needs the receiving socket to exist before submission —
        // unlike accept(), which manufactures one on return.
        const SOCKET accepted =
            ::WSASocketW(address_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (accepted == INVALID_SOCKET) {
            return fail(last_socket_error());
        }

        Acquired acquired;
        try {
            acquired = acquire_operation(Kind::accept, coroutine, std::nullopt, options);
        } catch (...) {
            ::closesocket(accepted);
            throw;
        }
        Operation* operation = acquired.operation;
        operation->size_result = result;
        operation->socket = listening;
        operation->accepted = accepted;
        operation->listener = listening;

        DWORD received = 0;
        const BOOL ok = accept_ex_(listening,
                                   accepted,
                                   operation->address_scratch.data(),
                                   /*dwReceiveDataLength=*/0,
                                   kAddressSlot,
                                   kAddressSlot,
                                   &received,
                                   &operation->overlapped);

        if (ok == TRUE || ::WSAGetLastError() == ERROR_IO_PENDING) {
            return acquired.id;
        }

        const Error error = last_socket_error();
        ::closesocket(accepted);
        discard(acquired.id);
        return fail(error);
    }

    [[nodiscard]] Result<detail::OperationId> submit_connect(NativeHandle handle,
                                                             std::span<const std::byte> address,
                                                             const OperationOptions& options,
                                                             std::coroutine_handle<> coroutine,
                                                             Result<std::size_t>* result) {
        if (shutting_down()) {
            return fail(Errc::cancelled);
        }
        if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
            return fail(*rejected);
        }

        const auto socket = static_cast<SOCKET>(handle);
        if (connect_ex_ == nullptr) {
            GUID guid = WSAID_CONNECTEX;
            Result<LPFN_CONNECTEX> resolved = resolve_extension<LPFN_CONNECTEX>(socket, guid);
            if (!resolved) {
                return fail(resolved.error());
            }
            connect_ex_ = *resolved;
        }

        const auto* target = reinterpret_cast<const sockaddr*>(address.data());

        // ConnectEx requires an already-bound socket; POSIX connect() binds
        // implicitly, so this step has no counterpart in the other backend.
        SOCKADDR_STORAGE local{};
        local.ss_family = static_cast<decltype(local.ss_family)>(target->sa_family);
        const int local_length = target->sa_family == AF_INET6
                                     ? static_cast<int>(sizeof(sockaddr_in6))
                                     : static_cast<int>(sizeof(sockaddr_in));
        if (::bind(socket, reinterpret_cast<const sockaddr*>(&local), local_length) ==
                SOCKET_ERROR &&
            ::WSAGetLastError() != WSAEINVAL) {
            return fail(last_socket_error());
        }

        const Acquired acquired =
            acquire_operation(Kind::connect, coroutine, std::nullopt, options);
        Operation* operation = acquired.operation;
        operation->size_result = result;
        operation->socket = socket;

        const BOOL ok = connect_ex_(socket,
                                    target,
                                    static_cast<int>(address.size()),
                                    nullptr,
                                    0,
                                    nullptr,
                                    &operation->overlapped);
        if (ok == TRUE || ::WSAGetLastError() == ERROR_IO_PENDING) {
            return acquired.id;
        }

        const Error error = last_socket_error();
        discard(acquired.id);
        return fail(error);
    }

    [[nodiscard]] Result<detail::OperationId> add_timer(detail::Clock::time_point wake_at,
                                                        const OperationOptions& options,
                                                        std::coroutine_handle<> coroutine,
                                                        Result<void>* result) {
        if (shutting_down()) {
            return fail(Errc::cancelled);
        }
        if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
            return fail(*rejected);
        }
        const Acquired acquired = acquire_operation(Kind::timer, coroutine, wake_at, options);
        acquired.operation->void_result = result;
        wake();
        return acquired.id;
    }

    [[nodiscard]] bool shutting_down() const noexcept {
        return shutting_down_.load(std::memory_order_acquire);
    }

    /// Ask for an operation to be cancelled. Safe from any thread.
    ///
    /// Never resumes: a `std::stop_callback` built on an already-stopped token
    /// runs synchronously, inside the `await_suspend` that registered it, and
    /// it may also run on a thread that is not the loop's.
    void request_cancel(detail::OperationId id) {
        const Fixed fixed = fix_reason(id, make_error_code(Errc::cancelled));
        if (!fixed.applied) {
            return;  // already resolved, or already cut short for some reason
        }
        cancel_io(fixed);
        if (fixed.resolve_now) {
            {
                const std::lock_guard lock{mutex_};
                if (auto operation = operations_.find(id); operation != operations_.end()) {
                    operation->second->cancel_pending = true;
                    ++pending_cancels_;
                }
            }
            wake();
        }
    }

    [[nodiscard]] Result<void> post(move_only_function<void()> work) {
        {
            const std::lock_guard lock{mutex_};
            if (shutting_down()) {
                return fail(Errc::cancelled);
            }
            posted_.push(std::move(work));
        }
        wake();
        return Result<void>{};
    }

    void stop() {
        stop_requested_.store(true, std::memory_order_release);
        wake();
    }

    [[nodiscard]] bool stopped() const noexcept {
        return stop_requested_.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::size_t outstanding() const noexcept {
        const std::lock_guard lock{mutex_};
        // Timers index operations rather than being work in their own right:
        // a read carrying a deadline is one outstanding thing, not two.
        return operations_.size() + posted_.size();
    }

    // ── driving ─────────────────────────────────────────────────────────────

    Result<void> run_once(Duration timeout) {
        if (shutting_down()) {
            return fail(Errc::cancelled);
        }
        if (dispatch_depth_ != 0) {
            detail::report_dispatch_violation("run_once re-entered from a resumed coroutine");
        }
        const detail::DispatchScope dispatching{dispatch_depth_};

        std::array<OVERLAPPED_ENTRY, kEventBatch> entries{};

        int timeout_ms = 0;
        {
            const std::lock_guard lock{mutex_};
            // Every queue whose arrival triggers `wake()` has to be reported
            // here. The wake-up packet is collapsed when one is already
            // pending, so it is never what guarantees progress — leaving
            // `pending_cancels_` out would let the loop block with a
            // cancellation sitting in it.
            const bool queued = !posted_.empty() || pending_cancels_ != 0 || stopped();
            timeout_ms = detail::resolve_timeout_ms(timeout, timers_.earliest(), queued);
        }

        ULONG removed = 0;
        const BOOL ok = ::GetQueuedCompletionStatusEx(
            port_,
            entries.data(),
            kEventBatch,
            &removed,
            timeout_ms < 0 ? INFINITE : static_cast<DWORD>(timeout_ms),
            FALSE);

        if (ok == FALSE) {
            const DWORD error = ::GetLastError();
            if (error != WAIT_TIMEOUT) {
                return fail(std::error_code{static_cast<int>(error), std::system_category()});
            }
            removed = 0;
        }

        // Dequeue is irreversible: fixed batches cannot throw an allocation
        // failure after the kernel has given up its completion packets.
        std::array<std::pair<detail::OperationId, Result<std::size_t>>, 2 * kEventBatch> resolved{};
        std::array<detail::TimerTarget, kEventBatch> expired{};
        std::array<detail::OperationId, kEventBatch> cancels{};
        std::size_t resolved_count = 0;
        std::size_t expired_count = 0;
        std::size_t cancel_count = 0;
        to_run_.clear();
        auto& to_run = to_run_;

        for (ULONG i = 0; i < removed; ++i) {
            const OVERLAPPED_ENTRY& entry = entries[i];
            if (entry.lpCompletionKey == kWakeupKey || entry.lpOverlapped == nullptr) {
                continue;  // a post() nudge, not an I/O completion
            }

            auto* operation = reinterpret_cast<Operation*>(entry.lpOverlapped);
            // Kernel-backed operations stay owned until their packet is
            // dequeued and finalized below, so this memory is still alive.
            const detail::OperationId id = operation->id;
            Result<std::size_t> outcome = classify(*operation, entry);
            // A reason fixed earlier wins over what the packet reports,
            // including a packet that reports success. The consequence is
            // sharp and deliberate: a cancelled read whose buffer the kernel
            // had already filled discards those bytes, which leaves a hole in
            // the stream. That is why a cancelled read or write on Windows
            // ends the connection's usefulness — see `event_loop.hpp`.
            if (const std::optional<Error> fixed = fixed_reason_of(id)) {
                outcome = fail(*fixed);
            }
            resolved[resolved_count++] = {id, outcome};
        }

        {
            const std::lock_guard lock{mutex_};
            expired_count = timers_.extract_expired(detail::Clock::now(), expired);
            if (pending_cancels_ != 0) {
                for (auto& [id, operation] : operations_) {
                    if (!operation->cancel_pending) continue;
                    cancels[cancel_count++] = id;
                    operation->cancel_pending = false;
                    --pending_cancels_;
                    if (cancel_count == cancels.size()) break;
                }
            }
            posted_.drain_into(to_run);
            wake_pending_.store(false, std::memory_order_release);
        }

        // Real completions, then deadlines, then cancellations. An operation
        // that genuinely finished in this batch is reported as finished even
        // if its deadline expired in the same instant; `finalize` is by id, so
        // the later mention of it does nothing.
        for (const auto& target : std::span(expired).first(expired_count)) {
            if (!target.is_deadline) {
                resolved[resolved_count++] = {target.operation, std::size_t{0}};
                continue;
            }
            // A deadline cannot resolve a kernel-backed operation by itself:
            // the kernel may still be writing into its buffers. Pin the answer
            // and ask for a cancel; the completion packet delivers it.
            const Fixed fixed = fix_reason(target.operation, make_error_code(Errc::timed_out));
            if (!fixed.applied) {
                continue;
            }
            cancel_io(fixed);
            if (fixed.resolve_now) {
                resolved[resolved_count++] = {target.operation, fail(Errc::timed_out)};
            }
        }
        // Everything below runs outside the lock: resumed coroutines may
        // submit more I/O, post work, or stop the loop.
        for (const auto& [id, outcome] : std::span(resolved).first(resolved_count)) {
            finalize(id, outcome);
        }
        for (const auto id : std::span(cancels).first(cancel_count)) {
            // Only timers reach this queue; kernel I/O waits for its packet.
            if (const auto fixed = fixed_reason_of(id)) finalize(id, fail(*fixed));
        }
        detail::dispatch_posts(to_run);

        return Result<void>{};
    }

private:
    /// Turn one completion packet into the outcome its caller asked for.
    [[nodiscard]] Result<std::size_t> classify(Operation& operation,
                                               const OVERLAPPED_ENTRY& entry) noexcept {
        const auto status = static_cast<DWORD>(entry.Internal);
        const DWORD transferred = entry.dwNumberOfBytesTransferred;

        // detach may have closed the socket before its completion arrived. Do
        // not query Winsock with a stale, possibly reused, handle.
        if (operation.handle_closed) {
            return fail(Errc::cancelled);
        }
        if (status != 0) {
            // `entry.Internal` is an NTSTATUS (STATUS_CONNECTION_REFUSED is
            // 0xC0000236), which is a third numbering space on top of Win32
            // and Winsock. Only WSAGetOverlappedResult maps it back to the
            // Winsock number a caller can reason about — feeding the raw
            // NTSTATUS to system_category() produces an error that matches no
            // std::errc at all.
            DWORD ignored_bytes = 0;
            DWORD ignored_flags = 0;
            if (operation.socket != INVALID_SOCKET &&
                ::WSAGetOverlappedResult(operation.socket,
                                         &operation.overlapped,
                                         &ignored_bytes,
                                         FALSE,
                                         &ignored_flags) == FALSE) {
                const int error = ::WSAGetLastError();
                if (error == WSAEMSGSIZE && (operation.kind == Kind::receive_from ||
                                             operation.kind == Kind::send_to))
                    return fail(std::make_error_code(std::errc::message_size));
                return fail(socket_error(error));
            }
            return fail(std::error_code{static_cast<int>(status), std::system_category()});
        }
        switch (operation.kind) {
        case Kind::accept:
            // An accept completes with zero bytes transferred — that is
            // success, not eof. The accepted socket also does not inherit the
            // listener's state unless told to, and skipping this leaves
            // getsockname/shutdown broken in ways that only show up much later.
            ::setsockopt(operation.accepted,
                         SOL_SOCKET,
                         SO_UPDATE_ACCEPT_CONTEXT,
                         reinterpret_cast<const char*>(&operation.listener),
                         sizeof(operation.listener));
            return static_cast<std::size_t>(operation.accepted);
        case Kind::connect:
            // A connect also completes with zero bytes. Only a recv may read
            // zero as "peer closed".
            return std::size_t{0};
        case Kind::read:
            if (transferred == 0) {
                // Zero bytes on a completed recv means the peer closed.
                return fail(Errc::eof);
            }
            return static_cast<std::size_t>(transferred);
        case Kind::receive_from:
            if ((operation.datagram_flags & (MSG_PARTIAL | MSG_TRUNC)) != 0 ||
                transferred > operation.datagram_capacity)
                return fail(std::make_error_code(std::errc::message_size));
            operation.datagram_result->size = transferred;
            operation.datagram_result->address_size =
                static_cast<std::size_t>(operation.datagram_address_size);
            std::memcpy(operation.datagram_result->address.data(), &operation.datagram_address,
                        operation.datagram_result->address_size);
            return static_cast<std::size_t>(transferred);
        case Kind::send_to:
            if (transferred != operation.buffer.len)
                return fail(std::make_error_code(std::errc::message_size));
            return static_cast<std::size_t>(transferred);
        case Kind::write:
            return static_cast<std::size_t>(transferred);
        case Kind::timer:
            // A timer has no completion packet, so it never reaches here.
            break;
        }
        return fail(Errc::not_supported);
    }

    /// Outcome of pinning an operation's answer.
    struct Fixed {
        /// This call is the one that pinned it. A second attempt reports
        /// `false`, which is what makes cancelling twice a no-op and keeps the
        /// first reason authoritative.
        bool applied{false};
        /// No completion packet is owed, so the loop may resolve it directly.
        bool resolve_now{false};
        SOCKET socket{INVALID_SOCKET};
        OVERLAPPED* overlapped{nullptr};
    };

    /// Pin an operation's answer without resolving it.
    [[nodiscard]] Fixed fix_reason(detail::OperationId id, Error reason) {
        const std::lock_guard lock{mutex_};
        auto it = operations_.find(id);
        if (it == operations_.end()) {
            return {};
        }
        Operation& operation = *it->second;
        if (operation.fixed_reason) {
            return {};
        }
        operation.fixed_reason = reason;
        // The deadline has either just fired or been overtaken; either way it
        // has nothing left to say.
        timers_.cancel(std::exchange(operation.deadline, detail::TimerHandle{}));

        Fixed out{.applied = true, .resolve_now = !operation.kernel_backed()};
        if (operation.kernel_backed() && !operation.handle_closed) {
            out.socket = operation.socket;
            out.overlapped = &operation.overlapped;
        }
        return out;
    }

    /// Ask the kernel to abandon one specific operation.
    ///
    /// Per-OVERLAPPED, never per-handle: `CancelIoEx(handle, nullptr)` would
    /// take down every operation on the socket, which is exactly what
    /// per-operation cancellation must not do.
    static void cancel_io(const Fixed& fixed) noexcept {
        if (fixed.overlapped == nullptr) {
            return;
        }
        // ERROR_NOT_FOUND is not a failure: it means the packet is already on
        // its way, which is the case this whole design is built around.
        ::CancelIoEx(reinterpret_cast<HANDLE>(fixed.socket), fixed.overlapped);
    }

    [[nodiscard]] std::optional<Error> fixed_reason_of(detail::OperationId id) {
        const std::lock_guard lock{mutex_};
        auto it = operations_.find(id);
        if (it == operations_.end()) {
            return std::nullopt;
        }
        return it->second->fixed_reason;
    }

    struct Acquired {
        detail::OperationId id{detail::kNoOperation};
        Operation* operation{nullptr};
    };

    /// Allocate an operation owned by the loop, not by the coroutine.
    ///
    /// The kernel writes into this memory until the completion arrives, so its
    /// lifetime cannot be tied to a frame that might unwind first. The
    /// `unique_ptr` is what keeps the OVERLAPPED at a fixed address across
    /// rehashes of the table.
    ///
    /// The timers are registered under the same lock as the insertion: one
    /// naming an operation that is not in the table yet would fire into
    /// nothing.
    [[nodiscard]] Acquired
    acquire_operation(Kind kind,
                      std::coroutine_handle<> coroutine,
                      std::optional<detail::Clock::time_point> wake_at = std::nullopt,
                      const OperationOptions& options = {}) {
        auto owned = std::make_unique<Operation>();
        owned->kind = kind;
        owned->handle = coroutine;
        Operation* pointer = owned.get();

        const std::lock_guard lock{mutex_};
        const detail::OperationId id = ++next_id_;
        pointer->id = id;
        const auto entry = operations_.emplace(id, std::move(owned)).first;
        try {
            if (wake_at) {
                // Two timers, not `min(wake_at, deadline)`: they mean opposite
                // things, and whichever fires first resolves the operation while
                // `take` cancels the other.
                pointer->wake = timers_.add(*wake_at, detail::TimerTarget{.operation = id});
            }
            if (options.deadline) {
                pointer->deadline =
                    timers_.add(*options.deadline,
                                detail::TimerTarget{.operation = id, .is_deadline = true});
            }
        } catch (...) {
            timers_.cancel(pointer->wake);
            timers_.cancel(pointer->deadline);
            operations_.erase(entry);
            throw;
        }
        return Acquired{id, pointer};
    }

    /// Drop an operation whose coroutine never suspended.
    ///
    /// Deliberately no resume: the submission failed, so the coroutine is
    /// still running and resuming it here would run its continuation twice.
    /// The kernel never took the OVERLAPPED, so freeing it now is safe.
    void discard(detail::OperationId id) noexcept {
        [[maybe_unused]] const std::unique_ptr<Operation> dropped = take(id);
    }

    /// The one place an operation resolves. Idempotent by id.
    ///
    /// Releasing the record — and therefore the caller's buffer view and the
    /// AcceptEx scratch space — before the coroutine runs is safe only because
    /// the kernel has already dequeued this operation's completion packet.
    void finalize(detail::OperationId id, Result<std::size_t> outcome) {
        std::unique_ptr<Operation> owned = take(id);
        if (!owned) {
            return;
        }
        // Another completion in this batch may have destroyed the listener
        // after classification. Never deliver its pre-created socket then.
        if (owned->kind == Kind::accept && owned->handle_closed) {
            outcome = fail(Errc::cancelled);
        }
        // An accept that did not succeed must not leak the socket AcceptEx
        // required it to pre-create. On success the socket travels back to the
        // caller, which owns it from then on.
        if (owned->kind == Kind::accept && !outcome.has_value() &&
            owned->accepted != INVALID_SOCKET) {
            ::closesocket(std::exchange(owned->accepted, INVALID_SOCKET));
        }
        if (owned->void_result) {
            *owned->void_result =
                outcome.has_value() ? Result<void>{} : Result<void>{fail(outcome.error())};
        }
        if (owned->size_result) {
            *owned->size_result = outcome;
        }
        const std::coroutine_handle<> handle = owned->handle;
        owned.reset();
        handle.resume();
    }

    /// Remove an operation and its timers from the table, if it is still there.
    [[nodiscard]] std::unique_ptr<Operation> take(detail::OperationId id) noexcept {
        std::unique_ptr<Operation> owned;
        {
            const std::lock_guard lock{mutex_};
            auto it = operations_.find(id);
            if (it == operations_.end()) {
                return {};
            }
            owned = std::move(it->second);
            if (owned->cancel_pending) --pending_cancels_;
            operations_.erase(it);
            timers_.cancel(owned->wake);
            timers_.cancel(owned->deadline);
        }
        return owned;  // frees at the caller, outside the lock
    }

    void wake() noexcept {
        if (wake_pending_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        ::PostQueuedCompletionStatus(port_, 0, kWakeupKey, nullptr);
    }

    HANDLE port_{nullptr};

    mutable std::mutex mutex_;
    std::unordered_map<detail::OperationId, std::unique_ptr<Operation>> operations_{};
    detail::TimerQueue timers_{};
    detail::PostQueue posted_{};
    std::size_t pending_cancels_{0};
    detail::OperationId next_id_{detail::kNoOperation};

    /// Non-zero while a batch is being delivered. Loop thread only, which is
    /// the same restriction `run_once` and destroying the loop already carry.
    std::atomic<int> dispatch_depth_{0};

    // Swapped with producer queues without allocating while dispatching.
    std::vector<move_only_function<void()>> to_run_{};

    LPFN_ACCEPTEX accept_ex_{nullptr};
    LPFN_CONNECTEX connect_ex_{nullptr};

    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> wake_pending_{false};
    std::atomic<bool> shutting_down_{false};
};

// ── EventLoop surface ────────────────────────────────────────────────────────

EventLoop::EventLoop(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
EventLoop::EventLoop(EventLoop&&) noexcept = default;
EventLoop& EventLoop::operator=(EventLoop&& other) noexcept {
    if (this != &other) {
        if (impl_) {
            impl_->shutdown();
        }
        impl_ = std::move(other.impl_);
    }
    return *this;
}
EventLoop::~EventLoop() {
    // A resumed callback may reach loop.detach() again through
    // socket.close(); shutdown must complete before the unique_ptr starts
    // destroying itself and clearing impl_.
    if (impl_) {
        impl_->shutdown();
    }
}

Result<EventLoop> EventLoop::create() {
    Result<void> winsock = ensure_winsock();
    if (!winsock) {
        return fail(winsock.error());
    }

    HANDLE port = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (port == nullptr) {
        return fail(last_os_error());
    }
    try {
        return EventLoop{std::make_unique<Impl>(port)};
    } catch (...) {
        ::CloseHandle(port);
        throw;
    }
}

Result<void> EventLoop::attach(NativeHandle handle) {
    return impl_->attach(handle);
}
void EventLoop::detach(NativeHandle handle) {
    impl_->detach(handle);
}

void EventLoop::post(move_only_function<void()> work) {
    (void)impl_->post(std::move(work));
}

Result<void> EventLoop::try_post(move_only_function<void()> work,
                                 const ResourceBudget& budget, std::size_t cost) {
    if (!impl_ || impl_->shutting_down()) return fail(Errc::cancelled);
    auto reserved = budget.try_acquire(cost);
    if (!reserved) return fail(reserved.error());
    return impl_->post(detail::budgeted_post(std::move(work), std::move(*reserved)));
}
void EventLoop::stop() {
    impl_->stop();
}
bool EventLoop::stopped() const noexcept {
    return impl_->stopped();
}
std::size_t EventLoop::outstanding() const noexcept {
    return impl_->outstanding();
}
Result<void> EventLoop::run_once(Duration timeout) {
    return impl_->run_once(timeout);
}

Result<void> EventLoop::run() {
    while (!impl_->stopped() && impl_->outstanding() > 0) {
        Result<void> iteration = impl_->run_once(Duration::min());
        if (!iteration) {
            return iteration;
        }
    }
    return Result<void>{};
}

// ── portable completion API, mapped straight onto IOCP ───────────────────────

Task<Result<std::size_t>> EventLoop::read(NativeHandle handle,
                                          std::span<std::byte> destination,
                                          OperationOptions options) {
    // Before the zero-length shortcut, not after: an operation the caller has
    // already cancelled must say so rather than quietly succeed with 0 bytes.
    if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
        co_return fail(*rejected);
    }
    if (destination.empty()) {
        co_return std::size_t{0};
    }
    // A moved-from loop owns nothing; the submit closure would dereference a
    // null Impl. Mirrors the POSIX backend's guard on every operation.
    Impl* impl = impl_.get();
    if (!impl || impl->shutting_down()) co_return fail(Errc::cancelled);
    // `options` is a by-value coroutine parameter, so capturing it by
    // reference captures a slot in this frame, which outlives the awaiter.
    auto submit = [impl, handle, destination, &options](std::coroutine_handle<> coroutine,
                                                        Result<std::size_t>* result) {
        return impl->submit_read(handle, destination, options, coroutine, result);
    };
    co_return co_await detail::await_operation<Result<std::size_t>>(
        std::move(submit), detail::cancel_through(impl), options.stop);
}

Task<Result<std::size_t>> EventLoop::write(NativeHandle handle,
                                           std::span<const std::byte> source,
                                           OperationOptions options) {
    if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
        co_return fail(*rejected);
    }
    if (source.empty()) {
        co_return std::size_t{0};
    }
    Impl* impl = impl_.get();
    if (!impl || impl->shutting_down()) co_return fail(Errc::cancelled);
    auto submit = [impl, handle, source, &options](std::coroutine_handle<> coroutine,
                                                   Result<std::size_t>* result) {
        return impl->submit_write(handle, source, options, coroutine, result);
    };
    co_return co_await detail::await_operation<Result<std::size_t>>(
        std::move(submit), detail::cancel_through(impl), options.stop);
}

Task<Result<std::size_t>> EventLoop::writev(NativeHandle handle,
                                            std::span<const std::span<const std::byte>> pieces,
                                            OperationOptions options) {
    if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
        co_return fail(*rejected);
    }
    if (std::none_of(pieces.begin(), pieces.end(), [](const auto piece) { return !piece.empty(); })) {
        co_return std::size_t{0};
    }
    Impl* impl = impl_.get();
    if (!impl || impl->shutting_down()) co_return fail(Errc::cancelled);
    auto submit = [impl, handle, pieces, &options](std::coroutine_handle<> coroutine,
                                                   Result<std::size_t>* result) {
        return impl->submit_writev(handle, pieces, options, coroutine, result);
    };
    co_return co_await detail::await_operation<Result<std::size_t>>(
        std::move(submit), detail::cancel_through(impl), options.stop);
}

Task<Result<NativeHandle>>
EventLoop::accept(NativeHandle listener, int address_family, OperationOptions options) {
    if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
        co_return fail(*rejected);
    }
    Impl* impl = impl_.get();
    if (!impl || impl->shutting_down()) co_return fail(Errc::cancelled);
    auto submit = [impl, listener, address_family, &options](std::coroutine_handle<> coroutine,
                                                             Result<std::size_t>* result) {
        return impl->submit_accept(listener, address_family, options, coroutine, result);
    };

    // The accepted socket travels back through the size_t slot; the loop has
    // already associated it with the completion port.
    Result<std::size_t> accepted = co_await detail::await_operation<Result<std::size_t>>(
        std::move(submit), detail::cancel_through(impl), options.stop);
    if (!accepted) {
        co_return fail(accepted.error());
    }
    Result<void> attached = impl->attach(static_cast<NativeHandle>(*accepted));
    if (!attached) {
        ::closesocket(static_cast<SOCKET>(*accepted));
        co_return fail(attached.error());
    }
    co_return static_cast<NativeHandle>(*accepted);
}

Task<Result<void>> EventLoop::connect(NativeHandle handle,
                                      std::span<const std::byte> address,
                                      OperationOptions options) {
    if (address.size() < sizeof(sockaddr)) {
        co_return fail(Errc::invalid_argument);
    }
    if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
        co_return fail(*rejected);
    }
    Impl* impl = impl_.get();
    if (!impl || impl->shutting_down()) co_return fail(Errc::cancelled);
    auto submit = [impl, handle, address, &options](std::coroutine_handle<> coroutine,
                                                    Result<std::size_t>* result) {
        return impl->submit_connect(handle, address, options, coroutine, result);
    };
    // Cancelling abandons the *wait*. The kernel's connect attempt carries on,
    // so the socket is left in an indeterminate state and the caller has to
    // close it; the loop never closes a handle it was lent.
    Result<std::size_t> connected = co_await detail::await_operation<Result<std::size_t>>(
        std::move(submit), detail::cancel_through(impl), options.stop);
    if (!connected) {
        co_return fail(connected.error());
    }
    // ConnectEx leaves the socket in a half-initialised state until told.
    ::setsockopt(static_cast<SOCKET>(handle), SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0);
    co_return Result<void>{};
}

Task<Result<EventLoop::DatagramResult>> EventLoop::receive_from(
    NativeHandle handle, std::span<std::byte> destination, OperationOptions options) {
    Impl* impl = impl_.get();
    if (!impl || impl->shutting_down()) co_return fail(Errc::cancelled);
    DatagramResult datagram;
    auto submit = [impl, handle, destination, &options, &datagram](
        std::coroutine_handle<> coroutine, Result<std::size_t>* result) {
        return impl->submit_datagram(handle, destination, {}, {}, &datagram,
                                     options, coroutine, result);
    };
    const auto received = co_await detail::await_operation<Result<std::size_t>>(
        std::move(submit), detail::cancel_through(impl), options.stop);
    if (!received) co_return fail(received.error());
    co_return datagram;
}

Task<Result<std::size_t>> EventLoop::send_to(
    NativeHandle handle, std::span<const std::byte> source,
    std::span<const std::byte> address, OperationOptions options) {
    Impl* impl = impl_.get();
    if (!impl || impl->shutting_down()) co_return fail(Errc::cancelled);
    auto submit = [impl, handle, source, address, &options](
        std::coroutine_handle<> coroutine, Result<std::size_t>* result) {
        return impl->submit_datagram(handle, {}, source, address, nullptr,
                                     options, coroutine, result);
    };
    co_return co_await detail::await_operation<Result<std::size_t>>(
        std::move(submit), detail::cancel_through(impl), options.stop);
}

// ── timers and scheduling ────────────────────────────────────────────────────

Task<Result<void>> EventLoop::wait_for(NativeHandle, bool, OperationOptions) {
    // No readiness concept on IOCP. The portable surface never calls this;
    // `wait_readable`/`wait_writable` are not declared on this platform.
    co_return fail(Errc::not_supported);
}

Task<Result<void>> EventLoop::sleep_until(Clock::time_point deadline, OperationOptions options) {
    // Same moved-from guard as the rest of the completion API.
    if (!impl_ || impl_->shutting_down()) co_return fail(Errc::cancelled);
    Impl* impl = impl_.get();
    auto submit = [impl, deadline, &options](std::coroutine_handle<> coroutine,
                                             Result<void>* result) {
        return impl->add_timer(deadline, options, coroutine, result);
    };
    co_return co_await detail::await_operation<Result<void>>(
        std::move(submit), detail::cancel_through(impl), options.stop);
}

Task<Result<void>> EventLoop::sleep_for(Duration delay, OperationOptions options) {
    return sleep_until(detail::deadline_after(Clock::now(), delay), std::move(options));
}

Task<void> EventLoop::yield() {
    if (!impl_ || impl_->shutting_down()) co_return;
    Impl* impl = impl_.get();
    auto submit = [impl](std::coroutine_handle<> coroutine, Result<void>* result) {
        // Keep yield in the tracked timer queue so shutdown resumes it after
        // draining kernel I/O, instead of discarding a continuation in post().
        return impl->add_timer(Clock::now(), OperationOptions{}, coroutine, result);
    };
    (void)co_await detail::await_operation<Result<void>>(
        std::move(submit), detail::cancel_never(), std::stop_token{});
    co_return;
}

}  // namespace Mira

#endif  // MIRA_PLATFORM_WINDOWS
