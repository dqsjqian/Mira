#pragma once

// Mira/core/event_loop.hpp — asynchronous I/O, timers, and coroutine
// resumption, on every supported platform.
//
// The public API is **completion-shaped**:
//
//     std::size_t n = (co_await loop.read(handle, buffer)).value();
//
// "tell me when this read has finished", not "tell me when this handle is
// readable". That choice is what makes one API work across kqueue, epoll, and
// IOCP — see `platform.hpp` for why readiness-shaped APIs cannot be ported to
// IOCP without emulating it badly.
//
// Threading contract:
//   * `post()` and `stop()` are safe from any thread.
//   * `OperationOptions::stop` may be requested from any thread; the
//     cancellation is delivered on the loop thread.
//   * everything else must be called on the thread running the loop.
//
// Resumption always happens outside the loop's internal lock, so a resumed
// coroutine may freely submit more I/O, post work, or stop the loop. It may
// not destroy or replace the loop it is being resumed by — see `~EventLoop`.

#include "mira/core/error.hpp"
#include "mira/core/operation.hpp"
#include "mira/core/platform.hpp"
#include "mira/core/task.hpp"

#include <array>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include "mira/core/functional.hpp"  // mira::move_only_function — posted work
#include <memory>
#include <span>

namespace Mira {

/// Single-threaded I/O loop: completions, timers, and posted work.
class EventLoop {
public:
    using Clock = std::chrono::steady_clock;
    using Duration = Clock::duration;

    /// Create a loop, or report why the platform refused.
    [[nodiscard]] static Result<EventLoop> create();

    EventLoop(EventLoop&&) noexcept;
    EventLoop& operator=(EventLoop&&) noexcept;
    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    /// Destroy only after the run thread is stopped. Outstanding I/O is
    /// cancelled and, on IOCP, drained before buffers/operations are released.
    /// Pending coroutine frames and borrowed buffers must remain alive until
    /// cancellation resumes them. This is not permission to destroy a pending
    /// Task independently. Do not move a loop while transports refer to it.
    ~EventLoop();

    // ── portable I/O (completion-shaped) ────────────────────────────────────
    //
    // Every operation below accepts `OperationOptions` for cancellation and a
    // deadline. Shared rules, so that each one does not restate them:
    //
    //   * The options are evaluated **before** the first syscall. An operation
    //     whose token is already stopped reports `Errc::cancelled` without
    //     touching the handle; one whose deadline has already passed reports
    //     `Errc::timed_out`. If both apply, cancellation wins — an explicit
    //     request outranks an elapsed budget. This holds for zero-length
    //     operations too, which therefore report the reason rather than 0.
    //   * Within one `run_once`, a genuine completion is delivered before a
    //     deadline or a cancellation that landed in the same batch, and an
    //     operation resolves exactly once.
    //   * Cancellation does **not** roll back I/O that already happened.

    /// Register `handle` with the loop before performing I/O on it.
    ///
    /// A no-op on reactor backends; on IOCP it associates the handle with the
    /// completion port, which must happen exactly once per handle. Transports
    /// call this when they create a socket, so protocol code never does.
    [[nodiscard]] Result<void> attach(NativeHandle handle);

    /// Stop tracking `handle`. Call before closing it.
    /// On POSIX this may synchronously resume a waiting coroutine; the
    /// continuation must not destroy or replace this loop, and must not
    /// re-enter run_once. As with normal dispatch, violations terminate.
    void detach(NativeHandle handle);

    /// Read once into `destination`, resolving with the byte count.
    ///
    /// Short reads are normal and are not an error. A clean peer close is
    /// reported as `Errc::eof` rather than a zero-length success, so that "no
    /// more data" cannot be mistaken for "nothing right now".
    [[nodiscard]] Task<Result<std::size_t>> read(NativeHandle handle,
                                                 std::span<std::byte> destination,
                                                 OperationOptions options = {});

    /// Write once from `source`, resolving with the byte count accepted.
    ///
    /// Short writes are normal; looping is the caller's business (see
    /// `write_all` in `stream.hpp`).
    [[nodiscard]] Task<Result<std::size_t>> write(NativeHandle handle,
                                                  std::span<const std::byte> source,
                                                  OperationOptions options = {});

    /// Write several buffers in one submission (writev(2) / WSASend).
    ///
    /// Same short-write semantics as `write`: resolves with the number of
    /// bytes accepted. The kernel gathers the pieces; no layer copies the
    /// body behind a handler's back. Empty pieces are skipped, and an
    /// entirely empty span is a 0-byte success, mirroring `write`.
    [[nodiscard]] Task<Result<std::size_t>>
    writev(NativeHandle handle, std::span<const std::span<const std::byte>> pieces,
           OperationOptions options = {});

    /// Accept one connection from a listening handle.
    ///
    /// The returned handle is already attached to the loop, because on IOCP an
    /// accepted socket is useless until it is associated with the completion
    /// port — leaving that to the caller would be a portability trap that only
    /// fires on one platform.
    ///
    /// `address_family` is the platform's own constant (`AF_INET`, `AF_INET6`,
    /// ...) passed straight through. The loop does not interpret it; IOCP
    /// simply needs to pre-create a socket of the right family before it can
    /// submit an accept.
    [[nodiscard]] Task<Result<NativeHandle>> accept(NativeHandle listener,
                                                    int address_family,
                                                    OperationOptions options = {});

    /// Connect `handle` to an already-encoded socket address.
    ///
    /// `address` is an opaque `sockaddr` blob: the loop memcpy's it into the
    /// syscall and never looks inside. That is what keeps `core` free of
    /// address-family knowledge while still being the only layer that talks to
    /// the OS — building the blob is the transport's job.
    ///
    /// Cancelling or timing out a connect abandons the *wait*; it does not
    /// undo the connect the kernel already started. The socket is left in an
    /// indeterminate state and the caller must close it. The loop never closes
    /// a handle it was lent.
    [[nodiscard]] Task<Result<void>> connect(NativeHandle handle,
                                             std::span<const std::byte> address,
                                             OperationOptions options = {});

    /// Datagram completion result; the address is opaque sockaddr bytes,
    /// with no dependency on the transport.
    struct DatagramResult {
        std::size_t size{0};
        alignas(std::max_align_t) std::array<std::byte, 128> address{};
        std::size_t address_size{0};
    };

    /// Receive one whole datagram. A zero-length packet succeeds; a
    /// zero-length destination still consumes one packet. An undersized
    /// buffer reports std::errc::message_size with the whole packet
    /// consumed — the tail is never returned again. Only one datagram
    /// operation per direction may be in flight on the same handle,
    /// otherwise invalid_argument. The buffer is borrowed until completion;
    /// cancellation does not revoke I/O that already happened, and on IOCP
    /// the completion packet is drained before returning.
    [[nodiscard]] Task<Result<DatagramResult>> receive_from(
        NativeHandle handle, std::span<std::byte> destination, OperationOptions options = {});

    /// Send a single datagram (zero-length packets included). The address
    /// bytes and the buffer are both borrowed until completion.
    [[nodiscard]] Task<Result<std::size_t>> send_to(
        NativeHandle handle, std::span<const std::byte> source,
        std::span<const std::byte> address, OperationOptions options = {});

    // ── timers and scheduling (portable) ────────────────────────────────────

    /// Suspend for at least `delay`.
    [[nodiscard]] Task<Result<void>> sleep_for(Duration delay, OperationOptions options = {});

    /// Suspend until `deadline`.
    ///
    /// Two distinct points in time are in play when `options.deadline` is also
    /// set, and they mean different things: reaching `deadline` is this
    /// operation *succeeding*, while reaching `options.deadline` is it being
    /// cut short with `Errc::timed_out`. Whichever comes first decides.
    [[nodiscard]] Task<Result<void>> sleep_until(Clock::time_point deadline,
                                                 OperationOptions options = {});

    /// Reschedule the caller onto the loop thread without waiting for I/O.
    ///
    /// No options: a yield waits for nothing, so there is nothing to cancel or
    /// time out. Code that loops on `yield()` must watch its own stop token.
    [[nodiscard]] Task<void> yield();

    /// Queue `work` to run on the loop thread. Safe from any thread.
    ///
    /// Move-only: a callable capturing a `Task` (itself move-only) can be
    /// posted without wrapping, which is a routine need in a coroutine
    /// library. `std::function` would demand copyability and reject it.
    void post(move_only_function<void()> work);

    // ── driving ─────────────────────────────────────────────────────────────

    /// Run until `stop()` is called or nothing is outstanding.
    Result<void> run();

    /// Run a single iteration: wait for completions (up to `timeout`), then
    /// dispatch expired timers, finished operations, and posted work.
    ///
    /// A default timeout blocks until something happens. Exposed because a
    /// host with its own main loop needs to interleave, and because tests
    /// should not depend on wall-clock races.
    Result<void> run_once(Duration timeout = Duration::min());

    /// Start `task` on this loop and pump until it finishes.
    ///
    /// The bridge from `main`. A `Task` is lazy and its awaiter owns the frame,
    /// so starting one needs a caller that outlives it — and `main` is not a
    /// coroutine. Without this, every program has to declare its own detached
    /// coroutine type, which is boilerplate no example should have to teach.
    ///
    /// `stop()` does **not** cut this short, for the same reason `stop()` is
    /// not cancellation: the root frame is started and unfinished, and
    /// abandoning it is exactly the use-after-free this library refuses to
    /// perform. Ask a server to wind down with a stop token in
    /// `OperationOptions`, which resolves its operations and lets the task
    /// return; `stop()` only concerns the pumping. One consequence worth
    /// knowing: pumping stops blocking once `stop()` has been observed, so a
    /// `stop()` with the task still in flight polls rather than waits until it
    /// unwinds.
    ///
    /// Rethrows exceptions from `task`. A pumping error is returned only if
    /// that same iteration also finished the task; otherwise it terminates
    /// rather than abandoning the root.
    ///
    /// Terminates, with a diagnostic, if the task can no longer finish: either
    /// pumping failed, or nothing is outstanding while the task is still
    /// suspended. The second case is a deadlock rather than a wait — usually a
    /// task parked on a channel or semaphore nobody will signal. Reporting it
    /// beats hanging, and the frame cannot be destroyed to recover.
    ///
    /// That diagnosis relies on the same invariant `run()` already does:
    /// anything able to resume a coroutine counts as outstanding work, *even
    /// when the resumption comes from another thread*. A facility that parks a
    /// coroutine and arranges its resumption off-thread — a name resolver
    /// handing work to a thread pool, say — has to keep the loop aware of it,
    /// or `run()` will already return while that work is still pending.
    Result<void> run_until_complete(Task<void> task);

    /// Ask the loop to return from `run()`. Safe from any thread.
    void stop();

    /// True once `stop()` has been observed.
    [[nodiscard]] bool stopped() const noexcept;

    /// Suspended operations, pending timers, and queued callables. Zero means
    /// the loop has nothing left to do.
    [[nodiscard]] std::size_t outstanding() const noexcept;

    // ── readiness extension (POSIX only, NOT portable) ──────────────────────
    //
    // Deliberately fenced off. These exist to embed a descriptor owned by some
    // other library — a database client, a device fd — into the same loop.
    // They have no IOCP equivalent: code that calls them does not build on
    // Windows, which is the honest outcome, and better than an emulation whose
    // semantics quietly differ.

#if MIRA_HAS_READINESS_API
    /// Suspend until `handle` is readable. POSIX only.
    [[nodiscard]] Task<Result<void>> wait_readable(NativeHandle handle,
                                                   OperationOptions options = {});

    /// Suspend until `handle` is writable. POSIX only.
    [[nodiscard]] Task<Result<void>> wait_writable(NativeHandle handle,
                                                   OperationOptions options = {});
#endif

private:
    class Impl;

    explicit EventLoop(std::unique_ptr<Impl> impl) noexcept;

    [[nodiscard]] Task<Result<void>>
    wait_for(NativeHandle handle, bool writable, OperationOptions options);

    std::unique_ptr<Impl> impl_;
};

}  // namespace Mira
