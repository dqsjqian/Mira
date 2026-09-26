// Event loop — POSIX backend (kqueue / epoll).
//
// The public API is completion-shaped ("tell me when this read finished"), but
// POSIX only offers readiness ("this fd is readable"). This file bridges the
// two in the one place that is allowed to know the difference: try the
// syscall, and on EAGAIN suspend on readiness and retry. That is the whole
// emulation, and it is why the Windows backend can be a direct IOCP mapping
// instead of the other way around.

#include "mira/core/platform.hpp"

#if MIRA_HAS_READINESS_API

    #include "mira/core/event_loop.hpp"
    #include "loop_common.hpp"
    #include "poller.hpp"

    #include <algorithm>
    #include <array>
    #include <atomic>
    #include <cerrno>
    #include <fcntl.h>
    #include <mutex>
    #include <sys/socket.h>
    #include <sys/uio.h>
    #include <unistd.h>
    #include <unordered_map>
    #include <utility>
    #include <vector>

namespace Mira {
namespace {

[[nodiscard]] Error last_os_error() noexcept {
    return std::error_code{errno, std::system_category()};
}

/// Completions drained per iteration.
///
/// Bounded on purpose: an unbounded batch lets one busy descriptor starve
/// timers and posted work, which surfaces as latency nobody can attribute.
constexpr std::size_t kEventBatch = 64;

}  // namespace

class EventLoop::Impl {
public:
    /// What a suspended operation is waiting for.
    ///
    /// Two kinds, not one per public call: on POSIX the loop only ever waits
    /// for readiness or for the clock. `read`, `write`, `accept` and `connect`
    /// are built *out of* readiness by the retry loops further down, so they
    /// need no state of their own here.
    enum class Kind { readiness, timer };

    /// One suspended operation. Everything that could reach the coroutine
    /// lives in exactly this record, so resolving it is one lookup and one
    /// erase rather than a sweep over several indices.
    struct Operation {
        detail::OperationId id{detail::kNoOperation};
        std::coroutine_handle<> handle{};
        /// Points into the awaiter, which lives in the suspended coroutine's
        /// frame — valid for exactly as long as the operation is registered.
        Result<void>* result{nullptr};
        Kind kind{Kind::readiness};

        int fd{-1};
        bool writable{false};
        /// True while a one-shot registration is still live in the kernel.
        /// Cleared when it fires, so that an operation resolving normally does
        /// not spend a syscall removing something already gone.
        bool armed{false};

        /// When a sleep should succeed, and when the caller's deadline cuts
        /// the operation short. Independent, and either may be absent.
        detail::TimerHandle wake{};
        detail::TimerHandle deadline{};
    };

    /// Who is waiting on each direction of a descriptor. Ids, not handles:
    /// a readiness event that arrives for a resolved operation then finds
    /// nothing instead of finding whatever reused the slot.
    struct FdWaiters {
        detail::OperationId read{detail::kNoOperation};
        detail::OperationId write{detail::kNoOperation};

        [[nodiscard]] bool empty() const noexcept {
            return read == detail::kNoOperation && write == detail::kNoOperation;
        }

        [[nodiscard]] detail::Interest interest() const noexcept {
            auto set = detail::Interest::none;
            if (read != detail::kNoOperation) {
                set = set | detail::Interest::read;
            }
            if (write != detail::kNoOperation) {
                set = set | detail::Interest::write;
            }
            return set;
        }
    };

    Impl(detail::Poller poller, int wake_read, int wake_write) noexcept
        : poller_(std::move(poller)), wake_read_(wake_read), wake_write_(wake_write) {}

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    ~Impl() {
        shutdown();
        if (wake_read_ >= 0) ::close(wake_read_);
        if (wake_write_ >= 0) ::close(wake_write_);
    }

    void shutdown() {
        // Wake everything still suspended so those coroutine frames unwind
        // rather than leak. They observe `cancelled` and are expected to
        // return promptly — the loop is already unusable by then.
        //
        // The flag is set before the dispatch check so that shutdown's own
        // `finalize` calls, which raise the depth themselves, are not mistaken
        // for a coroutine destroying the loop it is being resumed by.
        if (shutting_down_.exchange(true, std::memory_order_acq_rel)) return;
        if (dispatch_depth_ != 0) {
            detail::report_dispatch_violation("destroyed or replaced while dispatching");
        }

        std::vector<detail::OperationId> orphans;
        std::vector<move_only_function<void()>> discarded_work;
        {
            const std::lock_guard lock{mutex_};
            orphans.reserve(operations_.size());
            for (const auto& [id, operation] : operations_) {
                orphans.push_back(id);
            }
            posted_.drain_into(discarded_work);
        }

        // Resume outside the lock: a resumed coroutine may call back in. It
        // may also resolve a sibling operation, which is why this goes through
        // `finalize` by id — one that is already gone is simply not found.
        for (const detail::OperationId id : orphans) {
            finalize(id, fail(Errc::cancelled));
        }
    }

    // ── handle registration ─────────────────────────────────────────────────

    /// On POSIX the only per-handle setup is non-blocking mode, which the
    /// EAGAIN-retry loop depends on. A blocking descriptor would stall the
    /// whole loop inside a single `read()`.
    [[nodiscard]] Result<void> attach(int fd) noexcept {
        if (shutting_down()) return fail(Errc::cancelled);
        if (fd < 0) {
            return fail(Errc::invalid_argument);
        }
        const int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            return fail(last_os_error());
        }
        if ((flags & O_NONBLOCK) == 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            return fail(last_os_error());
        }
        return Result<void>{};
    }

    void detach(int fd) noexcept {
        // `detach` runs on the loop thread, but `acquire_datagram`/
        // `release_datagram` may run on a foreign thread (see their comment),
        // so this table access takes the lock like every other one.
        {
            const std::lock_guard lock{mutex_};
            if (auto it = datagrams_.find(fd); it != datagrams_.end()) {
                for (const auto& closed : it->second) if (closed) *closed = true;
                datagrams_.erase(it);
            }
        }
        // Remove kernel interest before cancellation resumes user code, which
        // can register another operation. Never disarm that new registration.
        (void)poller_.disarm(fd);
        fail_waiters(fd, make_error_code(Errc::cancelled));
    }

    // 占位覆盖整个重试循环，不随 readiness 通知提前释放。
    // Held under `mutex_`, same as `add_waiter`/`add_timer`: a coroutine that
    // migrated to another thread via `schedule_on` may call `receive_from`
    // off the loop thread, and the loop thread can be inside `detach` at the
    // same moment. The rest of the submission paths tolerate cross-thread
    // callers; this table must not be the exception.
    std::shared_ptr<bool> acquire_datagram(int fd, bool writing) {
        const std::lock_guard lock{mutex_};
        auto& slot = datagrams_[fd][writing ? 1U : 0U];
        if (slot) return {};
        slot = std::make_shared<bool>(false);
        return slot;
    }

    void release_datagram(int fd, bool writing, const std::shared_ptr<bool>& token) {
        const std::lock_guard lock{mutex_};
        auto it = datagrams_.find(fd);
        if (it == datagrams_.end()) return;
        auto& slot = it->second[writing ? 1U : 0U];
        if (slot == token) slot.reset();
        if (!it->second[0] && !it->second[1]) datagrams_.erase(it);
    }

    // ── suspension ──────────────────────────────────────────────────────────

    [[nodiscard]] Result<detail::OperationId> add_waiter(int fd,
                                                         bool writable,
                                                         const OperationOptions& options,
                                                         std::coroutine_handle<> handle,
                                                         Result<void>* result) {
        if (fd < 0) {
            return fail(Errc::invalid_argument);
        }
        if (shutting_down()) {
            return fail(Errc::cancelled);
        }
        if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
            return fail(*rejected);
        }

        detail::OperationId id = detail::kNoOperation;
        detail::Interest combined{};
        {
            const std::lock_guard lock{mutex_};
            FdWaiters& waiters = fd_waiters_[fd];
            detail::OperationId& slot = writable ? waiters.write : waiters.read;
            if (slot != detail::kNoOperation) {
                // Two coroutines waiting on the same direction of the same
                // descriptor would race over a single wakeup. Refusing beats
                // silently picking a winner.
                return fail(Errc::invalid_argument);
            }
            id = ++next_id_;
            // Record and deadline registered under one lock: a timer naming an
            // operation not yet in the table would fire into nothing.
            Operation& operation = operations_[id];
            operation = Operation{.id = id,
                                  .handle = handle,
                                  .result = result,
                                  .kind = Kind::readiness,
                                  .fd = fd,
                                  .writable = writable,
                                  .armed = true};
            if (options.deadline) {
                operation.deadline = timers_.add(
                    *options.deadline,
                    detail::TimerTarget{.operation = id, .is_deadline = true});
            }
            slot = id;
            combined = waiters.interest();
        }

        // The syscall runs outside the lock; a failure must undo the record.
        if (Result<void> armed = poller_.arm(fd, combined); !armed) {
            // `discard`, not `finalize`: the coroutine has not suspended yet,
            // so resuming it here would run its continuation twice.
            discard(id);
            return fail(armed.error());
        }
        if (options.deadline) {
            wake();  // a nearer deadline may shorten the current wait
        }
        return id;
    }

    [[nodiscard]] bool shutting_down() const noexcept {
        return shutting_down_.load(std::memory_order_acquire);
    }

    [[nodiscard]] Result<detail::OperationId> add_timer(detail::Clock::time_point wake_at,
                                                        const OperationOptions& options,
                                                        std::coroutine_handle<> handle,
                                                        Result<void>* result) {
        if (shutting_down()) return fail(Errc::cancelled);
        if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
            return fail(*rejected);
        }
        detail::OperationId id = detail::kNoOperation;
        {
            const std::lock_guard lock{mutex_};
            id = ++next_id_;
            Operation& operation = operations_[id];
            operation = Operation{
                .id = id, .handle = handle, .result = result, .kind = Kind::timer};
            // Two timers, not `min(wake_at, deadline)`: they mean opposite
            // things, and whichever fires first resolves the operation while
            // `unlink` cancels the other. One combined timer would have to
            // remember which of the two it was standing in for.
            operation.wake = timers_.add(wake_at, detail::TimerTarget{.operation = id});
            if (options.deadline) {
                operation.deadline = timers_.add(
                    *options.deadline,
                    detail::TimerTarget{.operation = id, .is_deadline = true});
            }
        }
        wake();  // a nearer deadline may shorten the current wait
        return id;
    }

    /// Ask for an operation to be cancelled. Safe from any thread.
    ///
    /// Records the request and nudges the loop, nothing more. The resumption
    /// has to happen on the loop thread, and it must not happen here at all:
    /// a `std::stop_callback` constructed on an already-stopped token runs
    /// synchronously, inside the `await_suspend` that registered it.
    void request_cancel(detail::OperationId id) {
        {
            const std::lock_guard lock{mutex_};
            if (!operations_.contains(id)) {
                return;  // already resolved
            }
            // No de-duplication: `finalize` is idempotent by id, so a repeated
            // request costs one wasted lookup and nothing else.
            pending_cancels_.push_back(id);
        }
        wake();
    }

    void post(move_only_function<void()> work) {
        {
            const std::lock_guard lock{mutex_};
            if (shutting_down()) return;
            posted_.push(std::move(work));
        }
        wake();
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

    [[nodiscard]] Result<void> arm_wakeup() noexcept {
        return poller_.arm(wake_read_, detail::Interest::read);
    }

    // ── driving ─────────────────────────────────────────────────────────────

    Result<void> run_once(Duration timeout) {
        if (shutting_down()) return fail(Errc::cancelled);
        if (dispatch_depth_ != 0) {
            detail::report_dispatch_violation("run_once re-entered from a resumed coroutine");
        }
        const detail::DispatchScope dispatching{dispatch_depth_};

        std::array<detail::ReadyEvent, kEventBatch> events{};

        int timeout_ms = 0;
        {
            const std::lock_guard lock{mutex_};
            // Every queue whose arrival triggers `wake()` has to be reported
            // here. The wake-up byte is collapsed when one is already pending
            // and drained wholesale afterwards, so it is never what guarantees
            // progress — leaving `pending_cancels_` out would let the loop
            // block with a cancellation sitting in it.
            const bool queued = !posted_.empty() || !pending_cancels_.empty() || stopped();
            timeout_ms = detail::resolve_timeout_ms(timeout, timers_.earliest(), queued);
        }

        const Result<std::size_t> ready =
            poller_.poll(std::span<detail::ReadyEvent>{events}, timeout_ms);
        if (!ready) {
            return fail(ready.error());
        }

        // `(id, outcome)` rather than anything pointing at a frame: by the
        // time these are delivered, an earlier resumption may already have
        // resolved one of them, and a stale id resolves to nothing.
        // Members, not locals: at a high event rate the per-iteration
        // construction and destruction of five vectors is five guaranteed
        // heap round-trips per loop turn. Reentrancy is impossible (a
        // resumed coroutine calling run_once terminates by contract), so
        // one set of scratch vectors is owned by the loop itself and
        // cleared at the top of every turn.
        resolved_.clear();
        to_run_.clear();
        to_rearm_.clear();
        expired_.clear();
        cancels_.clear();
        auto& resolved = resolved_;
        auto& to_run = to_run_;
        auto& to_rearm = to_rearm_;
        auto& expired = expired_;
        auto& cancels = cancels_;
        bool wakeup_fired = false;

        {
            const std::lock_guard lock{mutex_};

            /// Take whoever waits on one direction, if anyone does.
            ///
            /// Clearing the slot here — under the lock, before anything is
            /// resumed — is what lets `interest()` below describe the
            /// *remaining* waiters, and what stops a second event in the same
            /// batch from resolving the same operation twice.
            const auto claim = [&](detail::OperationId& slot) {
                if (slot == detail::kNoOperation) {
                    return;
                }
                const detail::OperationId id = std::exchange(slot, detail::kNoOperation);
                if (auto operation = operations_.find(id); operation != operations_.end()) {
                    operation->second.armed = false;  // the one-shot has fired
                }
                resolved.emplace_back(id, Result<void>{});
            };

            for (std::size_t i = 0; i < *ready; ++i) {
                const detail::ReadyEvent& event = events[i];

                if (event.fd == wake_read_) {
                    wakeup_fired = true;
                    continue;
                }

                auto it = fd_waiters_.find(event.fd);
                if (it == fd_waiters_.end()) {
                    // Nobody is waiting: the operation resolved some other way,
                    // or this is a stale one-shot left over from a descriptor
                    // number that has since been reused. Both are harmless —
                    // the retry loops treat a spurious wakeup as EAGAIN.
                    continue;
                }

                // A failed descriptor wakes both directions: the waiter learns
                // what actually went wrong from its next read or write, which
                // is where the real error lives.
                const bool take_read = event.readable || event.failed;
                const bool take_write = event.writable || event.failed;

                if (take_read) {
                    claim(it->second.read);
                }
                if (take_write) {
                    claim(it->second.write);
                }

                if (it->second.empty()) {
                    fd_waiters_.erase(it);
                } else {
                    // One-shot registration is consumed; whatever still waits
                    // on this descriptor has to be re-armed.
                    to_rearm.emplace_back(event.fd, it->second.interest());
                }
            }

            timers_.extract_expired(detail::Clock::now(), expired);
            cancels.swap(pending_cancels_);
            posted_.drain_into(to_run);
            wake_pending_.store(false, std::memory_order_release);
        }

        // Real completions, then deadlines, then cancellations — the order
        // `extract_expired` already applies within itself, extended across the
        // whole batch. An operation that genuinely finished in this batch is
        // reported as finished even if its deadline expired in the same
        // instant; `finalize` is by id, so the later mention of it does
        // nothing.
        for (const detail::TimerTarget& target : expired) {
            resolved.emplace_back(target.operation,
                                  target.is_deadline ? Result<void>{fail(Errc::timed_out)}
                                                     : Result<void>{});
        }
        for (const detail::OperationId id : cancels) {
            resolved.emplace_back(id, fail(Errc::cancelled));
        }

        Result<void> status{};
        if (wakeup_fired) {
            drain_wakeup();
            // Record the failure instead of returning here. Everything in
            // `resolved` and `to_run` has already been taken out of its queue
            // under the lock, so an early return would strand all of it:
            // coroutines suspended forever with nothing armed on their behalf.
            // (By construction — there is no way to make `arm()` fail against
            // the loop's own pipe, so this path has no test.)
            if (Result<void> rearmed = arm_wakeup(); !rearmed) {
                status = rearmed;
            }
        }

        for (const auto& [fd, interest] : to_rearm) {
            if (Result<void> rearmed = poller_.arm(fd, interest); !rearmed) {
                // Surface it rather than leaving a coroutine suspended forever
                // with nothing armed on its behalf.
                fail_waiters(fd, rearmed.error());
            }
        }

        // Everything below runs outside the lock. Resumed coroutines may
        // submit more I/O, post work, or stop the loop.
        for (const auto& [id, outcome] : resolved) {
            finalize(id, outcome);
        }
        for (auto& work : to_run) {
            work();
        }

        return status;
    }

private:
    /// Fail every waiter on `fd`, on the understanding that the descriptor has
    /// **no live registration** — the caller either just removed it or failed
    /// to install one. Marking the operations unarmed keeps `finalize` from
    /// spending syscalls putting back something that is already gone.
    void fail_waiters(int fd, Error error) {
        std::array<detail::OperationId, 2> broken{detail::kNoOperation, detail::kNoOperation};
        {
            const std::lock_guard lock{mutex_};
            auto it = fd_waiters_.find(fd);
            if (it == fd_waiters_.end()) {
                return;
            }
            broken = {it->second.read, it->second.write};
            for (const detail::OperationId id : broken) {
                if (auto operation = operations_.find(id); operation != operations_.end()) {
                    operation->second.armed = false;
                }
            }
            fd_waiters_.erase(it);
        }
        for (const detail::OperationId id : broken) {
            finalize(id, fail(error));
        }
    }

    /// What `unlink` hands back, so that the syscall and the resumption happen
    /// outside the lock.
    struct Unlinked {
        bool found{false};
        std::coroutine_handle<> handle{};
        Result<void>* result{nullptr};
        int fd{-1};
        detail::Interest remaining{detail::Interest::none};
        /// `fd` and `remaining` are meaningful only when this is set: the
        /// operation still had a live kernel registration to take back.
        bool registered{false};
    };

    /// Remove an operation from every index that names it. Caller holds the
    /// lock. Returning `found == false` is how "exactly once" is enforced:
    /// whoever gets here second finds nothing.
    [[nodiscard]] Unlinked unlink(detail::OperationId id) {
        auto it = operations_.find(id);
        if (it == operations_.end()) {
            return {};
        }
        const Operation operation = it->second;
        operations_.erase(it);

        Unlinked out{.found = true, .handle = operation.handle, .result = operation.result};
        if (operation.kind == Kind::readiness) {
            if (auto waiters = fd_waiters_.find(operation.fd); waiters != fd_waiters_.end()) {
                detail::OperationId& slot =
                    operation.writable ? waiters->second.write : waiters->second.read;
                // Only when the slot still names *this* operation: a coroutine
                // resumed earlier in the same batch may already have
                // registered a new one in it.
                if (slot == id) {
                    slot = detail::kNoOperation;
                }
                out.fd = operation.fd;
                out.remaining = waiters->second.interest();
                out.registered = operation.armed;
                if (waiters->second.empty()) {
                    fd_waiters_.erase(waiters);
                }
            }
        }
        timers_.cancel(operation.wake);
        timers_.cancel(operation.deadline);
        return out;
    }

    /// Give back the kernel registration an unlinked operation left behind.
    void release_registration(const Unlinked& unlinked) noexcept {
        if (!unlinked.registered || unlinked.fd < 0 || shutting_down()) {
            return;  // nothing live, or the poller is being torn down anyway
        }
        // `disarm` only once nothing is left: it removes *both* directions,
        // which would silently cancel a waiter on the other one.
        if (unlinked.remaining == detail::Interest::none) {
            (void)poller_.disarm(unlinked.fd);
        } else {
            (void)poller_.arm(unlinked.fd, unlinked.remaining);
        }
    }

    /// Undo a registration whose coroutine never suspended. Never resumes.
    void discard(detail::OperationId id) {
        Unlinked unlinked;
        {
            const std::lock_guard lock{mutex_};
            unlinked = unlink(id);
        }
        release_registration(unlinked);
    }

    /// The one place an operation resolves. Idempotent by id, and the
    /// resumption happens outside the lock so that the coroutine may submit
    /// more I/O, close the descriptor, or stop the loop.
    void finalize(detail::OperationId id, Result<void> outcome) {
        Unlinked unlinked;
        {
            const std::lock_guard lock{mutex_};
            unlinked = unlink(id);
        }
        if (!unlinked.found) {
            return;
        }
        release_registration(unlinked);
        if (unlinked.result) {
            *unlinked.result = outcome;
        }
        // detach 也会同步恢复续体；不能只依赖 run_once 的批次保护。
        const detail::DispatchScope dispatching{dispatch_depth_};
        unlinked.handle.resume();
    }

    /// Nudge a loop that may be blocked in `poll()`.
    ///
    /// The flag collapses bursts into a single byte, so a thousand posts do
    /// not fill the pipe.
    void wake() noexcept {
        if (wake_pending_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        const unsigned char byte = 1;
        ssize_t written = 0;
        do {
            written = ::write(wake_write_, &byte, 1);
        } while (written < 0 && errno == EINTR);
    }

    void drain_wakeup() noexcept {
        std::array<unsigned char, 64> scratch{};
        for (;;) {
            const ssize_t count = ::read(wake_read_, scratch.data(), scratch.size());
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count < static_cast<ssize_t>(scratch.size())) {
                break;
            }
        }
    }

    detail::Poller poller_;
    int wake_read_{-1};
    int wake_write_{-1};

    mutable std::mutex mutex_;
    std::unordered_map<detail::OperationId, Operation> operations_{};
    std::unordered_map<int, FdWaiters> fd_waiters_{};
    std::unordered_map<int, std::array<std::shared_ptr<bool>, 2>> datagrams_{};
    detail::TimerQueue timers_{};
    detail::PostQueue posted_{};
    std::vector<detail::OperationId> pending_cancels_{};

    // Scratch batches for `run_once`, cleared and refilled every turn.
    // Members rather than locals so a high event rate does not pay five
    // heap allocations per loop turn; see the comment at their use site.
    std::vector<std::pair<detail::OperationId, Result<void>>> resolved_{};
    std::vector<move_only_function<void()>> to_run_{};
    std::vector<std::pair<int, detail::Interest>> to_rearm_{};
    std::vector<detail::TimerTarget> expired_{};
    std::vector<detail::OperationId> cancels_{};
    detail::OperationId next_id_{detail::kNoOperation};

    /// Non-zero while a batch is being delivered. Loop thread only, which is
    /// the same restriction `run_once` and destroying the loop already carry.
    std::atomic<int> dispatch_depth_{0};

    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> wake_pending_{false};
    std::atomic<bool> shutting_down_{false};
};

// ── EventLoop surface ────────────────────────────────────────────────────────

EventLoop::EventLoop(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
EventLoop::EventLoop(EventLoop&&) noexcept = default;
EventLoop& EventLoop::operator=(EventLoop&& other) noexcept {
    if (this != &other) {
        if (impl_) impl_->shutdown();
        impl_ = std::move(other.impl_);
    }
    return *this;
}
EventLoop::~EventLoop() {
    // Complete callbacks while impl_ still refers to the live implementation.
    if (impl_) impl_->shutdown();
}

Result<EventLoop> EventLoop::create() {
    Result<detail::Poller> poller = detail::Poller::create();
    if (!poller) {
        return fail(poller.error());
    }

    // Self-pipe rather than eventfd: one code path for every POSIX platform,
    // and the loop has no use for eventfd's counter semantics.
    std::array<int, 2> wake{-1, -1};
    if (::pipe(wake.data()) != 0) {
        return fail(last_os_error());
    }
    for (const int fd : wake) {
        const int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
            ::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
            const Error error = last_os_error();
            ::close(wake[0]);
            ::close(wake[1]);
            return fail(error);
        }
    }

    auto impl = std::make_unique<Impl>(std::move(*poller), wake[0], wake[1]);
    Result<void> armed = impl->arm_wakeup();
    if (!armed) {
        return fail(armed.error());
    }
    return EventLoop{std::move(impl)};
}

Result<void> EventLoop::attach(NativeHandle handle) {
    return impl_->attach(handle);
}
void EventLoop::detach(NativeHandle handle) {
    impl_->detach(handle);
}

void EventLoop::post(move_only_function<void()> work) {
    impl_->post(std::move(work));
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
    // Returning when nothing is outstanding matches every other loop: with no
    // operations, timers, or queued work there is nothing left that could make
    // progress, and blocking forever would only hide the bug.
    while (!impl_->stopped() && impl_->outstanding() > 0) {
        Result<void> iteration = impl_->run_once(Duration::min());
        if (!iteration) {
            return iteration;
        }
    }
    return Result<void>{};
}

// ── portable completion API, emulated on readiness ───────────────────────────

Task<Result<std::size_t>> EventLoop::read(NativeHandle handle,
                                          std::span<std::byte> destination,
                                          OperationOptions options) {
    if (!impl_ || impl_->shutting_down()) co_return fail(Errc::cancelled);
    // Before the zero-length shortcut, not after: an operation the caller has
    // already cancelled must say so rather than quietly succeed with 0 bytes.
    if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
        co_return fail(*rejected);
    }
    if (destination.empty()) {
        co_return std::size_t{0};
    }
    for (;;) {
        const ssize_t count = ::read(handle, destination.data(), destination.size());
        if (count > 0) {
            co_return static_cast<std::size_t>(count);
        }
        if (count == 0) {
            // A clean close is reported as eof, never as a zero-byte success:
            // "no more data" must not be mistakable for "nothing right now".
            co_return fail(Errc::eof);
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            co_return fail(last_os_error());
        }
        Result<void> ready = co_await wait_for(handle, /*writable=*/false, options);
        if (!ready) {
            co_return fail(ready.error());
        }
    }
}

Task<Result<std::size_t>> EventLoop::write(NativeHandle handle,
                                           std::span<const std::byte> source,
                                           OperationOptions options) {
    if (!impl_ || impl_->shutting_down()) co_return fail(Errc::cancelled);
    if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
        co_return fail(*rejected);
    }
    if (source.empty()) {
        co_return std::size_t{0};
    }
    for (;;) {
        const ssize_t count = ::write(handle, source.data(), source.size());
        if (count >= 0) {
            co_return static_cast<std::size_t>(count);
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            co_return fail(last_os_error());
        }
        Result<void> ready = co_await wait_for(handle, /*writable=*/true, options);
        if (!ready) {
            co_return fail(ready.error());
        }
    }
}

Task<Result<std::size_t>> EventLoop::writev(NativeHandle handle,
                                            std::span<const std::span<const std::byte>> pieces,
                                            OperationOptions options) {
    if (!impl_ || impl_->shutting_down()) co_return fail(Errc::cancelled);
    if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
        co_return fail(*rejected);
    }
    // The kernel takes iovec arrays; this stack buffer bounds the scatter to
    // what a response needs (head + body + trailer) without an allocation.
    // A caller with more pieces than that can still loop `write` — the
    // span-of-spans shape is a convenience, not a capacity promise.
    std::array<::iovec, 16> scatter{};
    std::size_t count = 0;
    std::size_t total = 0;
    for (const std::span<const std::byte> piece : pieces) {
        if (piece.empty() || count == scatter.size()) {
            continue;
        }
        scatter[count].iov_base = const_cast<std::byte*>(piece.data());
        scatter[count].iov_len = piece.size();
        ++count;
        total += piece.size();
    }
    if (total == 0) {
        co_return std::size_t{0};
    }
    for (;;) {
        const ssize_t written = ::writev(handle, scatter.data(), static_cast<int>(count));
        if (written >= 0) {
            co_return static_cast<std::size_t>(written);
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            co_return fail(last_os_error());
        }
        Result<void> ready = co_await wait_for(handle, /*writable=*/true, options);
        if (!ready) {
            co_return fail(ready.error());
        }
    }
}

Task<Result<NativeHandle>>
EventLoop::accept(NativeHandle listener, int address_family, OperationOptions options) {
    if (!impl_ || impl_->shutting_down()) co_return fail(Errc::cancelled);
    // address_family is only needed by IOCP, which must pre-create the socket.
    // accept() reports the family itself, so POSIX ignores it.
    static_cast<void>(address_family);
    if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
        co_return fail(*rejected);
    }

    for (;;) {
        const int accepted = ::accept(listener, nullptr, nullptr);
        if (accepted >= 0) {
            // Attach before handing it over: a caller that has to remember
            // this would have code that works here and fails on Windows.
            Result<void> attached = impl_->attach(accepted);
            if (!attached) {
                ::close(accepted);
                co_return fail(attached.error());
            }
            co_return static_cast<NativeHandle>(accepted);
        }
        if (errno == EINTR) {
            continue;
        }
        // ECONNABORTED: the peer went away between the readiness notification
        // and the accept. Ordinary on a busy listener — retry rather than
        // failing the whole accept loop.
        if (errno == ECONNABORTED) {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            co_return fail(last_os_error());
        }
        Result<void> ready = co_await wait_for(listener, /*writable=*/false, options);
        if (!ready) {
            co_return fail(ready.error());
        }
    }
}

Task<Result<void>> EventLoop::connect(NativeHandle handle,
                                      std::span<const std::byte> address,
                                      OperationOptions options) {
    if (!impl_ || impl_->shutting_down()) co_return fail(Errc::cancelled);
    if (address.empty()) {
        co_return fail(Errc::invalid_argument);
    }
    if (const std::optional<Error> rejected = detail::rejected_before_submit(options)) {
        co_return fail(*rejected);
    }

    // Cancelling a connect abandons the *wait*. The kernel's attempt carries
    // on, so the socket is left in an indeterminate state and the caller has
    // to close it; the loop never closes a handle it was lent.
    const auto* target = reinterpret_cast<const sockaddr*>(address.data());
    for (;;) {
        if (::connect(handle, target, static_cast<socklen_t>(address.size())) == 0) {
            co_return Result<void>{};
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EISCONN) {
            co_return Result<void>{};  // already established
        }
        if (errno != EINPROGRESS && errno != EALREADY && errno != EWOULDBLOCK) {
            co_return fail(last_os_error());
        }

        // A non-blocking connect reports completion by becoming writable, but
        // writability alone does not mean success: the actual outcome lives in
        // SO_ERROR and must be read, or a refused connection looks connected.
        Result<void> ready = co_await wait_for(handle, /*writable=*/true, options);
        if (!ready) {
            co_return fail(ready.error());
        }

        int pending = 0;
        socklen_t length = sizeof(pending);
        if (::getsockopt(handle, SOL_SOCKET, SO_ERROR, &pending, &length) < 0) {
            co_return fail(last_os_error());
        }
        if (pending != 0) {
            co_return fail(std::error_code{pending, std::system_category()});
        }
        co_return Result<void>{};
    }
}

Task<Result<EventLoop::DatagramResult>> EventLoop::receive_from(
    NativeHandle handle, std::span<std::byte> destination, OperationOptions options) {
    Impl* impl = impl_.get();
    if (!impl || impl->shutting_down()) co_return fail(Errc::cancelled);
    if (const auto rejected = detail::rejected_before_submit(options)) co_return fail(*rejected);
    if (handle < 0) co_return fail(Errc::invalid_argument);
    auto token = impl->acquire_datagram(handle, false);
    if (!token) co_return fail(Errc::invalid_argument);
    struct Guard {
        Impl* impl;
        int fd;
        std::shared_ptr<bool> token;
        ~Guard() { impl->release_datagram(fd, false, token); }
    } guard{impl, handle, token};
    for (;;) {
        if (*token) co_return fail(Errc::cancelled);
        DatagramResult result;
        // Darwin 的零长度 iovec 不保证执行数据报接收；用一字节 scratch
        // 强制消费，非空包随后按用户容量报告截断。
        std::byte scratch{};
        iovec buffer{destination.empty() ? &scratch : destination.data(),
                     destination.empty() ? 1U : destination.size()};
        msghdr message{};
        message.msg_name = result.address.data();
        message.msg_namelen = static_cast<socklen_t>(result.address.size());
        message.msg_iov = &buffer;
        message.msg_iovlen = 1;
        const ssize_t count = ::recvmsg(handle, &message, 0);
        if (count >= 0) {
            if ((message.msg_flags & MSG_TRUNC) != 0 ||
                static_cast<std::size_t>(count) > destination.size())
                co_return fail(std::make_error_code(std::errc::message_size));
            result.size = static_cast<std::size_t>(count);
            result.address_size = message.msg_namelen;
            co_return result;
        }
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) co_return fail(last_os_error());
        const auto ready = co_await wait_for(handle, false, options);
        if (!ready) co_return fail(ready.error());
    }
}

Task<Result<std::size_t>> EventLoop::send_to(
    NativeHandle handle, std::span<const std::byte> source,
    std::span<const std::byte> address, OperationOptions options) {
    Impl* impl = impl_.get();
    if (!impl || impl->shutting_down()) co_return fail(Errc::cancelled);
    if (const auto rejected = detail::rejected_before_submit(options)) co_return fail(*rejected);
    if (handle < 0 || address.size() < sizeof(sockaddr) ||
        address.size() > sizeof(sockaddr_storage))
        co_return fail(Errc::invalid_argument);
    auto token = impl->acquire_datagram(handle, true);
    if (!token) co_return fail(Errc::invalid_argument);
    struct Guard {
        Impl* impl;
        int fd;
        std::shared_ptr<bool> token;
        ~Guard() { impl->release_datagram(fd, true, token); }
    } guard{impl, handle, token};
    for (;;) {
        if (*token) co_return fail(Errc::cancelled);
        const ssize_t count = ::sendto(handle, source.data(), source.size(), 0,
            reinterpret_cast<const sockaddr*>(address.data()),
            static_cast<socklen_t>(address.size()));
        if (count >= 0) {
            if (static_cast<std::size_t>(count) != source.size())
                co_return fail(std::make_error_code(std::errc::message_size));
            co_return static_cast<std::size_t>(count);
        }
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) co_return fail(last_os_error());
        const auto ready = co_await wait_for(handle, true, options);
        if (!ready) co_return fail(ready.error());
    }
}

// ── timers and scheduling ────────────────────────────────────────────────────

Task<Result<void>>
EventLoop::wait_for(NativeHandle handle, bool writable, OperationOptions options) {
    // A moved-from loop owns nothing: fail rather than dereference a null
    // Impl inside the submit closure. The read/write/accept/connect family
    // already guards this way; timers must not be the odd one out.
    Impl* impl = impl_.get();
    if (!impl || impl->shutting_down()) co_return fail(Errc::cancelled);
    auto submit = [impl, handle, writable, &options](std::coroutine_handle<> coroutine,
                                                     Result<void>* result) {
        return impl->add_waiter(handle, writable, options, coroutine, result);
    };
    // `options` is a by-value coroutine parameter, so capturing it by
    // reference captures a slot in this frame, which outlives the awaiter.
    co_return co_await detail::await_operation<Result<void>>(
        std::move(submit), detail::cancel_through(impl), options.stop);
}

Task<Result<void>> EventLoop::sleep_until(Clock::time_point deadline, OperationOptions options) {
    // Same moved-from guard as wait_for: the loop that was moved out of owns
    // no timers, and the submit closure would dereference a null Impl.
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
    return sleep_until(Clock::now() + delay, std::move(options));
}

Task<void> EventLoop::yield() {
    if (!impl_ || impl_->shutting_down()) co_return;
    Impl* impl = impl_.get();
    auto submit = [impl](std::coroutine_handle<> coroutine, Result<void>* result) {
        // A yield is a tracked suspension, not disposable posted work.
        // An already-due timer runs on the next pump and is cancelled/resumed
        // by shutdown, keeping child scopes joinable.
        return impl->add_timer(Clock::now(), OperationOptions{}, coroutine, result);
    };
    (void)co_await detail::await_operation<Result<void>>(
        std::move(submit), detail::cancel_never(), std::stop_token{});
    co_return;
}

    #if MIRA_HAS_READINESS_API
Task<Result<void>> EventLoop::wait_readable(NativeHandle handle, OperationOptions options) {
    return wait_for(handle, /*writable=*/false, std::move(options));
}

Task<Result<void>> EventLoop::wait_writable(NativeHandle handle, OperationOptions options) {
    return wait_for(handle, /*writable=*/true, std::move(options));
}
    #endif

}  // namespace Mira

#endif  // MIRA_HAS_READINESS_API
