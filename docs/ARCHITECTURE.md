# Mira architecture

## What this library is

An independent, coroutine-native C++23 networking library: a transport core,
and protocols that ride on it. HTTP is one protocol family, not the purpose.

### Design mandate (2026-09-23)

- Design from networking requirements, not cpp-httplib feature parity or an
  existing consumer's API. Neither cpp-httplib nor a host framework constrains
  the public interface. Consumers adapt later; breaking changes are permitted.
- C++23 is the minimum baseline. The build requires C++23 and `Result<T>`
  aliases `std::expected<T, Error>` directly. C++20 compatibility is removed;
  each target toolchain still needs explicit validation.
- Prioritize explicit ownership, structured task lifetimes, cancellation and
  deadlines, bounded buffering/backpressure, composable transports/protocols,
  and consistent cross-platform semantics. These are acceptance criteria to
  implement and verify, not claims that the current code already meets them.
- Evaluate correctness, API usability, performance and resource bounds through
  executable tests, interoperability checks and reproducible benchmarks.
  Existing libraries are comparison evidence, not the specification.
- Current phase develops Mira only. Consumer migration, removal of old
  dependencies, and public release are later phases; keep this repository
  private for now.

## Acceptance criteria, not a completeness score

The existence of a type or a passing integration test is not evidence that its
lifetime, concurrency and resource contracts are complete. Current foundations
and remaining acceptance work must be described separately.

| Concern | Current foundation | Remaining acceptance work |
|---|---|---|
| Execution and ownership | Lazy, move-only `Task` that terminates rather than destroy a started, unfinished frame; single-threaded `TaskScope` with immediate spawn and one-shot join; executor seam; single-threaded `EventLoop` whose operations carry never-reused identities | Explicit operation/buffer ownership across layers and continued join/drain validation; loop destruction during dispatch is refused rather than supported |
| Cancellation and deadlines | `OperationOptions` on every core operation, forwarded through TCP, TLS and the HTTP connection loop; `BoundedStream` distinguishes streams that can honour it; HTTP converts `idle_timeout` / `request_timeout` into a fresh deadline per request | Runtime evidence on Windows, where the IOCP semantics rest on CI alone; a cancelled IOCP read may lose bytes, so that connection must be closed; `stop()` is still a stop-pumping request, not I/O cancellation |
| Transport and composition | TCP and completion-shaped kqueue/epoll/IOCP implementations; stream concepts; message-preserving UDP datagrams with cancellation/deadline support | Equivalent observable semantics across backends, verified teardown, bounded queues; datagram contract formalized as a core concept before further UDP-based modules build on it |
| Protocols and data flow | HTTP/1.1 parser, serializer and connection loop; buffered and streaming request bodies (`RequestBodyReader`), chunked trailers, connection-loop drain guarantees; request- and response-parser fuzzing in CI | Protocol conformance evidence, slow-consumer backpressure bounds and bounded aggregate memory measurements |
| Security and robustness | Optional OpenSSL TLS stream, parser limits, negative-input tests and fuzzing of both HTTP parsers (request and response) | Lifecycle-safe TLS cancellation, fuzzing beyond the HTTP parsers, failure injection and resource-exhaustion tests |
| Engineering evidence | C++23-only build, desktop runtime CI and mobile cross-compilation jobs exist; last confirmed passing desktop baseline is `9f91060` | Fresh validation of current streaming/fuzz changes, mobile runtime evidence, reproducible interop/performance/resource measurements; no current stable ABI promise |

Rejecting ambiguous or malformed input is part of protocol correctness, not a
substitute for the other contracts. The HTTP parser rejects conflicting
`Content-Length`/`Transfer-Encoding`; parser limits do not establish bounded
memory for every queue, task tree or complete connection. Such bounds need to
be specified and measured end to end.

## The decision everything else follows from: completion, not readiness

Mira targets macOS, Linux, Windows, iOS, and Android. Those platforms do
not agree on what an asynchronous I/O API *is*:

| | Model | Shape |
|---|---|---|
| kqueue (macOS, iOS, BSD) | **reactor** | "this handle is *ready*" — you then read |
| epoll (Linux, Android) | **reactor** | same |
| IOCP (Windows) | **proactor** | "your read has *completed*" — you submitted it earlier |

This forces a choice, and getting it backwards is how libraries end up with a
first-class POSIX path and a Windows path nobody can reason about:

- A **readiness-shaped** public API (`wait_readable(fd)`) cannot be implemented
  on IOCP without badly emulating it — IOCP never answers "is it ready?".
- A **completion-shaped** public API (`read(handle, buffer)`) maps onto IOCP
  submission/completion, and onto a reactor by trying the syscall, waiting for
  readiness on `EAGAIN`, and retrying. Cancellation, close and buffer lifetime
  still require explicit backend-specific handling.

So **the public API is completion-shaped on every platform**, and readiness is
an implementation detail of the POSIX backends. Future backends such as
io_uring must satisfy the same ownership, cancellation and completion contract;
matching the I/O shape alone does not establish substitutability.

```cpp
std::size_t n = (co_await loop.read(handle, buffer)).value();   // all platforms
```

Readiness is still exposed, but fenced: `wait_readable` / `wait_writable` exist
behind `#if MIRA_HAS_READINESS_API` for embedding a descriptor owned by
another library. Code that calls them does not compile on Windows — the honest
outcome, and better than an emulation whose semantics quietly differ.

## HTTP/1.1 as the first protocol exercise

HTTP/1.1 is a concrete way to exercise incremental parsing, short transfers,
connection reuse and bounded request handling over the transport core. It is
not the product boundary, and another library's HTTP feature list is not the
acceptance plan.

RFC 9110 supplies shared HTTP semantics; RFC 9112 defines HTTP/1.1 framing.
HTTP/2 and HTTP/3 are phase-one requirements. Their optional nghttp2 and
nghttp3/ngtcp2 engines define separate framing, multiplexing, flow-control and
transport needs. HTTP/1.1 connection/body framing is not a generic HTTP contract.
Engine round trips do not complete phase-one acceptance: transport scheduling,
independent interoperability, platform execution and resource validation remain
explicit gates. TLS tests are composition evidence, not a reason to postpone
core lifetime and backpressure work.

## Layering

```
protocol   HTTP/1.1              future protocol modules
                  │                    │
                  └────────────────────┘
                      core I/O concepts
                  ┌───────────┴───────────┐
adapter       optional TLS          direct transport
                  │                       │
transport        TCP             future datagram/local transports
                  └───────────┬───────────┘
core       EventLoop · Buffer · Task · TaskScope · Executor · errors
                              │
backend                kqueue · epoll · IOCP
```

This diagram describes runtime composition, not concrete header dependencies.
Protocols and TLS depend on core concepts; application composition connects
TLS to a transport. Stream protocols must not assume every future transport is
a byte stream: datagrams need their own message-boundary and truncation
contracts. A protocol only composes with a transport whose semantics it needs.

Four dependency invariants are checked by `tools/ci/check_layering.py`.
These static checks do not prove lifetime safety or runtime substitutability:

1. **Dependencies point downwards only.** `core` must not include transport or
   protocol headers; transport must not include protocol headers. Reaching *up*
   a layer is precisely the move that makes a library unable to grow a second
   protocol later.
2. **No host framework dependency.** Mira never includes `aria/…`. Hosts
   integrate through the executor and stream seams, so the library stays usable
   standalone.
3. **Platform detection has exactly one home.** Only `platform.hpp` may test
   `_WIN32`, `__linux__`, `__APPLE__` and friends; everything else asks it via
   `MIRA_*`. Scattered `#ifdef _WIN32` is how "supports Windows" decays
   into "compiles on Windows".
4. **Protocols are platform-agnostic.** A protocol module may not include OS
   headers. The moment a parser knows what a socket is, it can no longer be
   tested over an in-memory pipe or run over TLS.

The scripts exist because every one of these failure modes is *gradual*. Nobody
decides to weld the socket loop to the parser — it happens one include at a
time, and by the time it hurts, the fix is a rewrite.

### TCP and UDP are transport, not "more protocols"

TCP and UDP belong to the transport layer, not a checklist of HTTP features.
TCP supplies stream connections. UDP supplies message-preserving datagrams
(`transport::udp::Socket`: completion-shaped send/receive with cancellation
and deadlines, truncation reported rather than silently clipped); it is a
datagram contract, not a stream-shaped wrapper. DNS and QUIC are examples of
protocols that may use datagrams; their requirements must not be imposed on
the TCP API or treated as existing functionality.

## Core seams

The executor and stream concepts live in `modules/core`. They establish useful
composition seams but do not yet express the full lifetime, cancellation,
thread-affinity and backpressure contracts below.

### `Executor` — who resumes a coroutine

```cpp
template <typename E>
concept Executor = requires(E& e, void (*work)()) {
    { e.post(work) } -> std::same_as<void>;
};
```

One function, because `post` is the smallest thing every scheduler already has.
The host chooses scheduling policy; this does not make loop-bound objects
thread-safe. `EventLoop` is single-threaded except for its documented `post()`
and `stop()` entry points. `co_await schedule_on(executor)` schedules a
continuation on the chosen executor; subsequent scheduling may move it again.
Executor/loop lifetime and permitted thread transitions must be explicit before
claiming arbitrary GUI-loop or thread-pool integration is safe.

### `AsyncStream` — what a protocol reads and writes

```cpp
template <typename S>
concept AsyncReadStream = requires(S& s, std::span<std::byte> d) {
    { s.read_some(d) } -> std::same_as<Task<Result<std::size_t>>>;
};
```

Short-transfer semantics match the underlying I/O. Protocol code depends on a
stream contract rather than a concrete socket type; TCP, TLS and in-memory
streams exercise this seam. Unix-domain sockets are a possible future
transport, not an implemented capability. Richer operations can be composed
on the minimal contract; the existing `write_all` helper is tested with a
non-socket `MemoryStream`.

`BoundedStream` refines this concept for streams that additionally accept an
`OperationOptions`. It is a refinement rather than an extension of
`AsyncStream` because the options parameter is defaulted, so every existing
one-argument call and every existing implementer stays valid. The split exists
because cancellation cannot be composed from the outside: only the layer that
waits can stop waiting, so a wrapper cannot supply the capability on behalf of
a stream that lacks it. Handing a budget to a stream that cannot honour it is
therefore a compile error, not a deadline that silently does nothing.

An asynchronous byte stream is not the same as a streamed HTTP body. A
handler chooses the delivery shape: a `std::span<const std::byte>` third
parameter gets the buffered body byte-for-byte as before, while any other
callable receives a `RequestBodyReader` and pulls slices while it runs —
chunked trailers included, the connection loop draining what the handler
left unread (or dropping the connection when the drain fails). End-to-end
streaming still leaves open buffer ownership across protocol layers and the
way slow consumers suspend producers; those are measured contracts, not
delivered ones.

### `TaskScope` — implemented single-threaded child ownership

`TaskScope` in `Mira/core/task_scope.hpp` owns child tasks, not their borrowed
resources. It is neither copyable nor movable. Scope operations, child completion
and stop callbacks must all execute on the same thread; the type is not a
cross-thread scheduler or a complete server-launch facility.

- `spawn(Task<void>)` accepts an unstarted, nonempty task, takes ownership and
  starts it immediately. Empty input throws `std::invalid_argument`; spawn after
  join has been requested throws `std::logic_error`. Completed child frames are
  reclaimed promptly instead of accumulating until scope destruction.
- `join()` can be called only once. The call immediately closes spawn intake,
  even though the returned `Task<void>` is lazy and has not yet been awaited.
  Drive that task to completion: join waits for every child and its frame cleanup.
  A second join throws `std::logic_error`.
- The first observed child exception is retained and requests cooperative stop.
  Join rethrows it only after every child has finished and released its frame;
  siblings are not abandoned when the first child fails. `Result` failures are
  values, not exceptions: a `Task<void>` adapter must handle them explicitly,
  for example by throwing `std::system_error`, as in the README example.
- `get_stop_token()` / `request_stop()` expose a `std::stop_token` signal.
  Children may inspect it or register callbacks, but pending I/O is not
  automatically cancelled and there is no deadline propagation. Requesting stop
  does not close spawn intake or replace join. Callback reentrancy can complete
  the last child and resume the join continuation synchronously.
- An untouched empty scope (neither spawn nor join used) may be destroyed.
  Every other scope must finish joining before destruction, even if all children
  completed synchronously and `pending() == 0`. Join that rethrows after cleanup
  still satisfies this requirement. Early scope destruction terminates; so does
  destroying a join task while it is waiting. Discarding an unstarted join still
  leaves the scope unjoined and causes termination at scope destruction.
  This fail-fast policy prevents silent release of child frames still referenced
  by I/O; it is not automatic asynchronous cleanup in a destructor.

Keep borrowed streams, buffers, coroutine-lambda closures and other child state
alive through join; normally keep the associated loop alive longer as well.
Do not destroy the parent task while it awaits join. Prefer free-function
coroutines for examples so a temporary lambda cannot leave a dangling closure.
Do not use `sync_get()` for real asynchronous I/O or a join that may suspend:
it terminates rather than tear down a frame the loop may still reference.
Awaiting an empty or consumed `Task<T>` throws `std::logic_error` — there is no
frame to abandon, so that case stays recoverable.

`EventLoop::yield()` uses an already-due timer rather than disposable posted
work. It counts as outstanding work, resumes on the next loop pump and is also
resumed by loop shutdown, allowing a waiting scope join to finish. Its public
return type is still `Task<void>`: shutdown's internal cancellation result is
not returned to the caller. Resumption does not authorize more work on a
shut-down loop, and `stop()` itself remains a stop-pumping request, not I/O
cancellation.

### Required lifetime and resource contracts

These are broader design/acceptance requirements, beyond the scope foundation:

- **Structured concurrency:** child operations belong to an explicit scope.
  Callers must explicitly stop when needed and join/drain before leaving that
  scope or releasing borrowed resources. `TaskScope` provides owned spawn/join
  and fail-fast misuse detection, not implicit destructor-driven I/O cancellation;
  silently detached work is not a default.
- **Ownership:** distinguish owned sockets, operation state and coroutine
  frames from borrowed streams and spans. Specify the destruction order of
  task, stream and loop, and which objects must survive kernel completion.
- **Cancellation and deadlines:** a caller's stop token and absolute deadline
  travel from `EventLoop` through TCP and TLS to the HTTP connection loop, each
  operation resolving exactly once, with the precedence of the
  close/completion/cancellation/timeout races fixed (see below). What composes
  them for free is the deadline being absolute: no layer subtracts elapsed
  time. What remains is evidence rather than mechanism — the Windows half has
  no local runtime coverage at all.
- **Backpressure:** bound outstanding operations, buffered bytes and work
  queues; define whether reaching each limit suspends or rejects a producer.
  Test slow peers and stalled consumers. A parser size limit or bounded TLS
  BIO alone is not an end-to-end resource bound.
- **Thread affinity:** identify each operation's owner executor and permitted
  handoff points. Scheduling elsewhere must not leave callbacks able to resume
  a destroyed task or access a loop-bound object from the wrong thread.

## Per-operation cancellation and deadlines

`OperationOptions` carries a `std::stop_token` and an **absolute**
`steady_clock` deadline, by value, into every `core` operation:

```cpp
co_await loop.read(handle, buffer, {.deadline = Clock::now() + 5s});
co_await loop.read(handle, buffer, {.stop = scope.get_stop_token()});
```

The member order is part of the source contract, because designated
initialisers must be written in declaration order. Pass-by-value is too: a
reference bound to a `{...}` temporary dies at the end of the expression that
creates the coroutine, which is before the coroutine first resumes. Copying
also lets the stop state outlive the `TaskScope` that owned the `stop_source`,
which an operation still winding down after a scope exits depends on.

The deadline is absolute rather than a duration so that an operation retrying
internally — `EAGAIN`, `EINTR`, a partial readiness wake-up — cannot refresh
its budget, which would let a slow peer hold it open indefinitely while every
individual wait stayed under the limit.

### Resolution rules

| Situation | Outcome |
|---|---|
| Token already stopped at submission | `Errc::cancelled`, nothing submitted |
| Deadline already past at submission | `Errc::timed_out`, nothing submitted |
| Both | `cancelled` — an explicit request outranks an elapsed budget |
| Zero-length operation with either | The reason, not a 0-byte success it never performed |
| Completion and deadline/cancel in the same `run_once` | The completion. It genuinely happened |
| Repeated cancellation | Resolved once; the extra requests find nothing |
| Loop shutdown with work suspended | Each operation's pinned reason, or `cancelled` |

Options are evaluated before an operation's first syscall and again before each
time it parks, but **not** between a readiness wake-up and the retry it
enables. An earlier revision did check there, and it made a read that became
ready in the same batch as its deadline report a timeout on POSIX while IOCP
reported success for the same program — because a completion packet is dequeued
before the timer queue is examined. Two backends disagreeing about one program
is the failure this library exists to avoid.

### What cancellation does not do

- **It does not roll back I/O that already happened.** Bytes already moved
  stay moved.
- **It does not undo a kernel `connect`.** Cancelling abandons the *wait*; the
  socket is left in an indeterminate state and the caller must close it. The
  loop never closes a handle it was lent.
- **On IOCP it can lose bytes.** A cancelled or timed-out operation stays in
  the table until its completion packet arrives, because until then the kernel
  may still be writing into the OVERLAPPED, the AcceptEx address buffer and the
  caller's buffer. The pinned reason is then delivered *even if the packet
  reports success* — so a cancelled read whose buffer the kernel had already
  filled discards those bytes, leaving a hole in the stream. **A cancelled read
  or write ends that connection's usefulness on Windows; close it rather than
  reuse it.** POSIX has no equivalent, because there the cancellation happens
  before the syscall.
- **`timed_out` may arrive later than the deadline on IOCP**, for the same
  reason. Nothing asserts an upper bound on when.
- **It is not `stop()`.** Stopping the loop asks it to return from `run()`; it
  does not cancel anything.

### Threading

A stop may be *requested* from any thread; it is *delivered* on the loop
thread. The callback records an operation id and nudges the loop, and does
nothing else — a `std::stop_callback` built on an already-stopped token runs
synchronously inside the `await_suspend` that registered it, where resuming the
coroutine would re-enter its own suspension. The same indirection is what makes
an off-thread request safe, and is why the callback holds an id rather than a
pointer to an awaiter living in a coroutine frame.

Local tests cover the loop thread and an off-thread request that is joined
before the loop is pumped. Neither is a concurrency stress test, and no claim
is made about racing a request against a resolution.

### Composition through the stack

`Socket::read_some` / `write_some`, `Listener::accept`, `connect`, and every
`tls::Stream` operation take an `OperationOptions` and forward it downwards
unchanged. That "unchanged" is the whole benefit of the deadline being
absolute: one `{.deadline = T}` given to a TLS handshake becomes the same `T`
on each of the arbitrarily many underlying reads and writes it performs, so
"no underlying operation may extend past T" composes into "this handshake must
finish by T" with no layer subtracting elapsed time. A duration would have
required that subtraction at every level, and every level would have been a
separate opportunity to get it wrong.

`tls::Stream` requires a `BoundedStream` underneath for the same reason: a TLS
operation drives its transport an unbounded number of times, so a handshake
over a transport that cannot be cut short is a hang waiting to happen. The
requirement is stated in the type rather than in a comment.

`connect` keeps `OperationOptions` separate from `ConnectOptions`. The latter
configures a socket and is meant to be reused; a stop token and an absolute
deadline belong to one call, and storing them in a reusable struct produces a
deadline that silently belongs to whichever call ran first.

### HTTP takes durations, not a deadline

`ServerOptions::idle_timeout` bounds waiting *between* requests;
`request_timeout` bounds one exchange from its first byte to its last response
byte, handler included. `serve_connection` converts whichever applies into a
fresh absolute deadline on every iteration, and re-converts when the first byte
of a request arrives.

A single deadline would have been simpler and wrong: it would cover the whole
keep-alive connection, so the hundredth request would inherit whatever budget
the first one left. Two windows also distinguish two different failures — a
peer that says nothing from a peer that says it slowly.

Their outcomes deliberately differ. Idle expiry between requests returns
**success**, because a quiet keep-alive connection being closed is how one
normally ends; it is the same answer a polite close gets, and reporting it as
an error would make every ordinary connection teardown look like a fault.
Request expiry is `Errc::timed_out` and closes the connection.

No 408 is sent on expiry. Writing one requires the stream under the deadline
that just elapsed, so announcing the timeout would need a second budget the
caller never granted — and a response written outside the caller's budget is
the thing these options exist to prevent.

Both windows default to zero, which disables them. That default is a
compatibility choice, not a recommendation: it leaves a slow peer bounded by
`limits` alone, which bounds one message's size and not the time it may take
to arrive.

## What CI found that local testing could not

Both bugs below built cleanly and passed every test on the development machine.
Both would also have passed a Windows job that only compiled — which is the
argument for running tests on every platform rather than building on them.

1. **Winsock numbers are not Win32 numbers.** MSVC's `std::system_category()`
   maps part of the Winsock space: `WSAEADDRINUSE` is in the table, so the
   exclusive-bind test passed, but `WSAECONNREFUSED` is not. A refused
   connection therefore compared equal to `std::errc::connection_refused` on
   POSIX and to nothing at all on Windows. Fixed by `Mira::socket_error`,
   which translates the Winsock codes that have a portable equivalent.

2. **IOCP completions report NTSTATUS — a third numbering space.**
   `OVERLAPPED_ENTRY::Internal` holds an NTSTATUS
   (`STATUS_CONNECTION_REFUSED` is `0xC0000236`), not a Winsock error. So
   fixing (1) alone changed nothing: the value never reached the translation.
   `WSAGetOverlappedResult` is the documented way back to a Winsock number.

3. **Nothing on this machine runs IOCP.** The per-operation cancellation work
   added a third case of the same shape, pre-emptively rather than after the
   fact. The Windows paths — a pinned reason surviving a success packet,
   `ERROR_NOT_FOUND`, accept-socket reclamation, buffer release strictly after
   the drain — are compiled locally through mingw-w64, which catches type and
   lifetime errors cheaply, but mingw is not MSVC and a compile is not a run.
   Those semantics have no local evidence of any kind.

4. **A toolchain the CI image defaults to is not the toolchain a library
   requires.** `std::stop_token` is gated behind
   `_LIBCPP_HAS_NO_EXPERIMENTAL_STOP_TOKEN` in the libc++ that NDK 27 and 28
   ship (LLVM 18 and 19), and LLVM 20 removed the gate — so the Android job
   could not build this library at any API level while it used
   `$ANDROID_NDK_ROOT`. The NDK version is now pinned.

   The instructive part is the diagnosis. `TaskScope` has used
   `std::stop_source` since it was written, so the requirement predates this
   work by some margin; it stayed invisible only because no translation unit
   the Android job compiled happened to include that header. And the first
   attempt at a fix — raising the API level — was a guess that CI disproved,
   because libc++'s availability gating is Apple-only and had nothing to do
   with it. Reading the libc++ sources for the exact gate, and then building
   against a newer NDK locally, produced the answer in minutes.

The pattern is worth naming, because it will recur: **the dangerous
portability bug is the one where every platform builds and runs, and one of
them silently fails to match the condition callers switch on.**

A corollary for the development machine: cross-compiling the backend it cannot
run is worth doing anyway. It turns a class of mistake that would otherwise
cost a twenty-minute CI round trip into a local error message, without
pretending to be verification.

## Decisions on record

| Decision | Choice | Why |
|---|---|---|
| **I/O model** | **completion-shaped public API** | A common operation contract for IOCP and reactor implementations |
| Platform scope | macOS, Linux and Windows runtime targets; iOS/Android targets currently cross-compiled | Runtime correctness must be demonstrated per platform; BSD has no dedicated CI evidence |
| Readiness API | POSIX-only, behind an explicit macro | A platform extension, not part of the portable operation contract |
| Execution model | Lazy `Task<T>` with explicit single-threaded `TaskScope` spawn / join | Owned child frames and cooperative stop are implemented; full I/O cancellation and deadlines remain acceptance work |
| Library form | Compiled library with modular public headers | Keep implementation boundaries explicit; an ABI policy must be decided before stabilization |
| Error model | `std::error_code` + `Result<T>` for operational failures | `Task` can still propagate body exceptions; this is not a no-exceptions guarantee |
| Standard floor | C++23-only build; `Result<T>` directly aliases `std::expected<T, Error>` | Validate each toolchain and standard library; no C++20 compatibility mandate |
| Buffer shape | Current `Buffer` is contiguous | Future segmented or borrowed-buffer designs need measured benefit and an explicit ownership contract |
| Framework coupling | No host-framework dependency or old Aria API compatibility promise | Consumers adapt to the independent library after its contracts are established |
| Protocol scope | HTTP/1.1 and optional TLS exercise the core; later protocols remain proposals | Stabilize lifecycle and resource semantics before broadening scope |

## Staged acceptance

Stages are gates, not completion percentages or release dates. Each gate needs
recorded evidence identifying the tested revision, toolchains, platforms and
configuration; the historical milestones below do not certify these gates.

1. **C++23 foundation and contracts.** Move the build baseline and selected
   standard-library facilities to C++23. Document ownership, thread affinity,
   error and short-transfer semantics. Compile independent minimal consumers
   without Aria or compatibility adapters.
2. **Lifecycle and structured execution.** Validate the implemented scope-owned
   tasks and explicit join; add I/O cancellation/deadline propagation and safe
   cross-layer drain. Test destruction and
   close with pending read/write/accept/connect/timer work, nested task failure,
   repeated cancellation and simultaneous completion. Require exactly-once
   completion and no dangling kernel buffers, resumptions or resource leaks
   across kqueue, epoll and IOCP, using applicable sanitizers and fault injection.
3. **Bounded composable data flow.** Incremental body consumption is delivered
   (`RequestBodyReader`); the open half is producer/consumer limits. Verify
   short transfers, partial failures,
   early termination and slow peers over memory streams, TCP and TLS; measure
   peak memory and outstanding work against configured bounds. Datagram
   semantics are defined and delivered; UDP-based modules now owe conformance
   evidence against them, not a definition.
4. **Cross-platform and protocol correctness.** Run protocol negative cases,
   fuzzing and interoperability checks; test normalized error/EOF/cancel/close
   outcomes on each desktop backend. Obtain mobile runtime evidence before
   promoting cross-compilation to runtime support. Keep TLS/mobile/BSD gaps
   explicit rather than borrowing another platform's results.
5. **Performance and API validation.** Publish reproducible benchmark inputs,
   hardware, compiler/options and limits. Measure latency distributions,
   throughput, CPU, allocations and peak memory under steady load, overload,
   connection churn and cancellation. Compare identical workloads with suitable
   baselines; do not infer performance from coroutine syntax or API shape.
   Exercise independent client/server examples and review API clarity before
   considering stabilization or additional protocol families.

Consumer migration and public release require separate approval after these
contracts and evidence are established. This plan promises neither old Aria
interfaces nor another library's feature parity.

## Implementation history, not readiness certification

The following records implementation milestones. Test counts are historical
snapshots, not current totals or evidence of complete protocol/lifecycle safety.

**v0.1 — seams.** Error model, `Task<T>`, `Buffer`, executor and stream
concepts, warning policy, layering discipline, CI across C++20/C++23 and
sanitizers.

**v0.2 — the loop.** `EventLoop` with three backends (kqueue, epoll, IOCP),
completion-shaped `read`/`write`, timers, cross-thread `post`, and a
`platform.hpp` that is the single home for platform detection. CI now builds
and *runs* tests on all three backends, and cross-compiles for iOS and Android.

The historical local kqueue run recorded 118 checks across C++20, C++23 and
ASan/UBSan. Desktop epoll/IOCP runtime coverage comes from CI, not that local
run. Neither the check count nor the existence of a CI job establishes current
revision health or full backend lifecycle correctness.

**v0.3 — the parser.** Incremental, strict HTTP/1.1 request parsing:
`message.hpp` (HTTP message types, subject to review for future protocol reuse),
`limits.hpp` (parser bounds), and a parser whose test suite is mostly published
smuggling vectors. 119 checks, and the byte-at-a-time tests assert that network
slicing cannot change the parse.

**v0.4 — TCP.** `Endpoint`, `Listener`, `Socket`, `connect`, and an explicit
exclusive-bind policy. `ListenOptions::exclusive` expresses the intent to
reject a second bind to an occupied endpoint; each backend must implement and
test that intent using its platform's socket options. `SO_REUSEADDR` has
platform-specific semantics, so copying the option name is not a portable
contract. Existing loopback tests are evidence for their tested configurations,
not a proof covering every platform, address family and socket option mix.

This milestone first exercised the Windows socket path in these tests. The
event-loop tests used `socketpair()`, which Winsock lacks, so every socket case
had been skipped there and IOCP's read/write path had never run. Loopback TCP
runs everywhere, and it immediately found two bugs unreachable from a macOS
machine — see "What CI found" above.

**v0.5 — a working server.** Response serialisation and `serve_connection`,
generic over the stream. The stack runs end to end over a real socket. Three
rules live in the loop rather than in handlers, because breaking any of them
corrupts the *next* request rather than the current one: the body is always
drained, one response per request with one framing, and a HEAD response
carries its Content-Length but no bytes.

An API defect surfaced here and is worth recording, because it is the kind
only an integration reveals: `ParseStep::need_more` meant both "out of bytes"
and "state advanced, call me again". A caller cannot tell those apart, so the
connection loop read from the socket while the buffer still held a complete
request, hit eof, and closed. The parser now advances its own state machine
and `need_more` means exactly one thing. **A state machine must not export an
ambiguous "try again".**

**TLS/HTTPS foundation.** Optional `Mira::tls` (OpenSSL 3) depends on core,
not on TCP or HTTP. A bounded memory BIO pair separates synchronous TLS state
transitions from asynchronous ciphertext reads/writes. No SSL socket BIO or
`SSL_set_fd` is used; IOCP and POSIX therefore share the same TLS pump.

Client verification is mandatory: trusted chain plus DNS/IP identity; DNS
connections also send SNI. TLS 1.2 is the minimum. OpenSSL errors are classified
immediately on the calling thread before any suspension. Fatal errors poison
the session, and ciphertext EOF without close_notify is truncation. Shutdown
sends and flushes only the local close_notify; it does not certify a two-way
shutdown. Context lifetime is retained by SSL; the borrowed transport and spans
must remain alive. One outstanding operation per TLS stream is supported;
overlapping calls are rejected rather than racing the SSL state machine.

Tests generate fresh private CA/certificate/key fixtures at runtime; no private
keys are committed. HTTPS exercises the existing HTTP loop unchanged, with
trusted/untrusted chains, DNS and IP identity mismatches, short encrypted I/O,
large payloads, orderly close and truncated TCP. The optional TLS CI matrix is
separate from the dependency-free build. iOS/Android jobs currently compile all
non-TLS libraries only; target OpenSSL and mobile TLS runtime validation remain
outstanding. BSD also has no dedicated CI evidence.

This integration also fixes HTTP EOF before the end of a partial request head
being mistaken for idle disconnect, and rejects a zero read-chunk policy.
Current request bodies remain buffered, not streamed to handlers.

**Structured task foundation.** `TaskScope` adds immediate owned spawn, one-shot
join, prompt child-frame reclamation, cooperative stop and first-exception
propagation after all children finish. Empty-task await is checked; tracked
`yield` resumes during loop shutdown.

**Per-operation cancellation and deadlines.** Operations gained never-reused
identities, timers became cancellable and stopped holding awaiter addresses,
and every `core` operation accepts a stop token and an absolute deadline with a
single resolution point. Destroying a started, unfinished `Task`, and
destroying or re-entering a dispatching loop, both became terminating refusals
rather than undefined behaviour. Two bugs that were live before this work also
went: `run_once` stranded already-extracted operations when re-arming its
wake-up pipe failed, and the HTTP grammar existed as two independent copies.
Options are now forwarded by transport, TLS and HTTP. UDP and system resolver
waits use the same cancellation/deadline foundation. Cancelling a system
resolver wait does not interrupt getaddrinfo; worker-owned state outlives the
wait without retaining the loop.

The earlier cancellation baseline registered eight regular suites with TLS (`core`,
`event_loop`, `task_scope`, `transport`, `http_parser`, `http_server`,
`http_end_to_end`, `tls_https`), or seven without TLS. Eight additional CTests
run a single contract violation each in its own process and require the exact
exit code the terminate handler installs, so that an ordinary crash cannot pass
as a deliberate fail-fast: `task_scope_pending-destruction`,
`task_scope_unobserved-failure`, `task_scope_abandoned-join`,
`task_scope_unstarted-join`, `task_contract_sync-get-suspended`,
`task_contract_abandoned-awaiter`, `event_loop_destroy-during-dispatch` and
`event_loop_reentrant-run-once`. Totals are **16 CTests with TLS and 15
without**; registration counts do not assert that this revision has passed
them.

**Known lifecycle limits.** Destroying a started, unfinished `Task` now
terminates instead of being undefined, and so does destroying, replacing or
re-entering the loop while it is dispatching a batch. Both are refusals, not
recoveries: the loop cannot make either safe by itself, so it says so loudly
instead of continuing into a use-after-free.

Cancellation now reaches every layer, but two limits are worth stating plainly.
The Windows half has no local runtime evidence, only CI. And a cancelled read
or write on IOCP can discard bytes the kernel had already moved, so that
connection is finished — a caller that reuses it reads a stream with a hole in
it. This foundation is neither production-readiness nor a complete
cancellation-safety claim.

**Remaining work, not a phase-one scope exemption.** UDP, asynchronous system
resolution, HTTP/1 client, HTTP/2 engines and request-body streaming now
exist; QUIC/HTTP3 are experimental. The current implementation still lacks a
QUIC UDP scheduling entry point, independent H2/H3 interoperability and full
platform
acceptance. Routing, native OS trust-store integration, end-to-end resource
bounds and multi-threaded loops also remain incomplete; mTLS policy is now
available on `tls::Context` but native OS trust-store integration is still open.
Judge the current tested snapshot by the repository's own CI and tests rather
than the historical counts above.
