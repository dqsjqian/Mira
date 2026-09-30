# Mira architecture

## What this library is

An independent, coroutine-native C++23 networking library: a transport core,
and protocols that ride on it. HTTP is one protocol family, not the purpose.

This document describes its source revision. Version policy and release
consumption live in the [shared release guide](RELEASES.md). Verification
evidence applies only to the revision and configuration explicitly recorded.

### Design mandate (2026-09-23, updated 2026-09-28)

- Design from networking requirements, not cpp-httplib feature parity or an
  existing consumer's API. Neither cpp-httplib nor a host framework constrains
  the public interface. Breaking source changes follow the major-version policy
  in the release guide.
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
- The library is public and released: hash-pinned source archives ship as
  release assets for every version, and downstream consumers (Aria, AriaAgent,
  AriaRead) pin those archives rather than vendoring or submoduling.

## Acceptance criteria, not a completeness score

The existence of a type or a passing integration test is not evidence that its
lifetime, concurrency and resource contracts are complete. Current foundations
and remaining acceptance work must be described separately.

| Concern | Current foundation | Remaining acceptance work |
|---|---|---|
| Execution and ownership | Lazy, move-only `Task` with constant-stack inline-completion loops and single-threaded `TaskScope`; reliable continuation posting separate from bounded application admission; `LoopGroup` owns independent thread-affine loops and bounded root tasks | Continued cross-layer join/drain validation; attached sockets cannot migrate between workers; loop destruction during dispatch is refused |
| Cancellation and deadlines | `OperationOptions` on core/TCP/HTTP operations; TLS owns independent loop timers for each application request without rearming wire I/O; `BoundedStream` exposes cancellation support; registration is rolled back on allocation failure | Maintain runtime evidence for backend-specific completion races; a cancelled IOCP read may lose bytes, so that connection cannot be resumed; `stop()` is a stop-pumping request, not I/O cancellation |
| Transport and composition | Completion-shaped TCP/UDP/local streams; `DatagramTransport` conformance assertions; bounded family-interleaved `tcp::dial`; separately composed HTTP/HTTPS client pools and grace-draining TCP serving | Maintain backend-specific teardown evidence; DNS is bounded system getaddrinfo, not independent asynchronous A/AAAA resolution |
| Protocols and data flow | HTTP/1.1 parser, serializer and connection loop; buffered and streaming request bodies (`RequestBodyReader`), chunked trailers, connection-loop drain guarantees; request- and response-parser fuzzing in CI; curl interop exercised out-of-process against the example servers — HTTP/1.1 against the file server, real-nghttp2 HTTP/2 (prior knowledge, including concurrent streams) against `examples/h2_prior_knowledge_server`, native-QUIC HTTP/3 (ngtcp2 + nghttp3) against `examples/h3_server`; HTTP/1 `Expect: 100-continue` and duplex early responses; SOCKS5 against curl and independent Python peers; DoH against curl and Python peers; MQTT 3.1.1/5.0 against an independent Python broker and mosquitto | Protocol conformance evidence, slow-consumer backpressure bounds and bounded aggregate memory measurements |
| Security and robustness | Duplex TLS with terminal cancellation, bounded parsers, shared accounting budgets, HTTP/WS/SOCKS/DNS/MQTT fuzzing, opt-in validated QUIC paths, explicit replay-safe raw-QUIC early data and HTTP/3 0-RTT with SETTINGS-bound ticket domains and automatic 425 for unsafe early requests | No complete anti-replay or process-RSS guarantee; longer exhaustion tests and mobile TLS runtime evidence remain open |
| Engineering evidence | Desktop CI, compression-inclusive Autobahn reports, sanitizer suites, Windows MSVC independent HTTP/3 curl and Retry checks, MinGW H2/H3 runtime tests; revision-specific results in the [audit record](AUDIT-2026-09-30.md) | iOS lacks signed device evidence; Android devices and multi-host/WAN remain unverified; local soak results apply only to their recorded snapshots; no stable ABI promise |

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
composition       client / client_tls          application drivers
                      │                              │
protocol  HTTP/1.1 · HTTP/2 · WS · SOCKS5      HTTP/3 / QUIC
          DNS/DoH · MQTT
                      │                              │
adapter          optional TLS                  path-aware datagrams
                      │                              │
transport          TCP / local                      UDP
                      └──────────────┬───────────────┘
core       EventLoop · Buffer · Task · TaskScope · Executor · LoopGroup
                              │
backend                kqueue · epoll · IOCP
```

This diagram describes runtime composition, not concrete header dependencies.
HTTP/1 and TLS use core stream concepts and do not depend on TCP. Shared HTTP
fields live in dependency-free `Mira::http_common`; H3 does not require H2.
`Mira::socks` and `Mira::mqtt` depend on core only and run over any bounded
stream (TCP, TLS, local); `Mira::dns` adds `Mira::http` for the DoH mapping.
`Mira::client` is a separate composition target linking HTTP, SOCKS5 and transport;
`Mira::client_tls` adds TLS only with `MIRA_ENABLE_TLS=ON`. Installed components
are `client` / `client_tls`; a base client consumer does not discover OpenSSL.
Stream protocols must not assume datagrams are byte streams: a protocol only
composes with a transport whose semantics it needs.

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
and deadlines, truncation reported rather than silently clipped); the wire
contract those sockets model is named — `transport::DatagramTransport`
(`mira/transport/datagram.hpp`) — so UDP-based protocols such as QUIC
constrain against the concept, never against the concrete socket, and a
deterministic in-memory transport can satisfy the same seam. DNS is another
example of a protocol that may use datagrams; its requirements must not be
imposed on the TCP API or treated as existing functionality.

## Core seams

The executor and stream concepts live in `modules/core`. They establish useful
composition seams but do not yet express the full lifetime, cancellation,
thread-affinity and backpressure contracts below.

### `Executor` — who resumes a coroutine

```cpp
template<typename E>
concept Executor = requires(E& executor, detail::PostedResumption&& work) {
    { executor.post(std::move(work)) } -> std::same_as<void>;
};
```

The concept checks the actual resumption closure, not merely a function pointer.
`post` is the reliable, unbounded control/continuation channel; saturation of an
application queue must never discard a coroutine resumption. `EventLoop` is
single-threaded except for `post()`, `try_post()` and `stop()`. An operation's
stop token may be requested cross-thread; its cancellation is delivered on the
loop thread. `stop()` itself only stops pumping. `schedule_on` changes
continuation scheduling, not ownership or thread safety of loop objects.

`try_post` and `BoundedExecutor` provide a separate application admission gate,
returning `would_block` on saturation. `BoundedExecutor` deliberately is not an
`Executor`. Its queued-slot and caller-declared cost reservations end before
invocation, so they do not cover asynchronous work created by callbacks.

`LoopGroup` creates/drives/destroys one independent loop per worker. Its quota
covers queued and unfinished root tasks; accepted factories survive their task
frames, while captured references remain borrowed. Tasks cooperate with the
worker stop token and remain on that worker; attached sockets, especially IOCP
associations, cannot move between workers. Stop closes admission; join drains
before threads exit. Uncooperative tasks can block shutdown. This is not several
threads pumping one `EventLoop`.

`ResourceBudget` is thread-safe shared accounting with RAII reservations and
limit/used/peak/rejected observations. It can account selected connection slots,
HTTP input, TLS buffers, H2 queues or QUIC reservations, not all allocations,
third-party internals or RSS. These independently read counters are not a
transactional snapshot or a memory-publication mechanism.

### `AsyncStream` — what a protocol reads and writes

```cpp
template <typename S>
concept AsyncReadStream = requires(S& s, std::span<std::byte> d) {
    { s.read_some(d) } -> std::same_as<Task<Result<std::size_t>>>;
};
```

Short-transfer semantics match the underlying I/O. Protocol code depends on a
stream contract rather than a concrete socket type; TCP, TLS and in-memory
streams exercise this seam. POSIX filesystem Unix-domain sockets also
implement this contract; Windows reports not_supported. Richer operations can be composed
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
left unread (or dropping the connection when the drain fails). HTTP/1 client
uploads and H2/H3 outputs now also have incremental backpressure. These local
contracts do not bound all caller buffers, third-party state or aggregate RSS;
end-to-end slow-consumer and lifetime evidence remains configuration-specific.

### `Task` — lazy execution and inline completion

Awaiting a lazy `Task<T>` starts its body on the calling thread. If the body
completes inline, `await_suspend` returns `false` and the awaiting coroutine
continues without a nested continuation resume. Repeated inline completions
therefore use constant native stack for a fixed await nesting depth, including
GCC Debug builds that do not turn symmetric transfer into a tail call.
This bounds stack growth across loop iterations, not arbitrary recursive nesting.

An atomic completion handshake handles a task that completes on another thread
before `await_suspend` finishes. If completion happens later, final suspension
transfers to the awaiting continuation. This synchronization does not make
`TaskScope`, event loops or attached I/O objects safe for concurrent use.
Regression tests cover long inline loops, exceptions, external suspension and
cross-thread completion races.

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
  for example by throwing `std::system_error`.
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
  time. Backend-specific runtime evidence must remain tied to the tested
  revision; existing Windows CI does not certify every later working-tree edit.
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

`Socket::read_some` / `write_some`, `Listener::accept` and `connect` carry
`OperationOptions` unchanged. TLS accepts the same absolute request budget but
owns a separate event-loop deadline timer for each application operation.
Ciphertext I/O does not inherit that request deadline: changing a request budget
must not cancel and replay wire I/O, which could hide transferred bytes on IOCP.
Expiry/cancellation permanently invalidates the TLS session, wakes the other
direction and drains associated work before returning. The deadline is not
refreshed across partial transfers, but kernel completion/drain may finish later
than that time; it is not a hard return-time guarantee.

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

## Current main-branch composition contracts

### Dialing, streaming uploads and owned clients

`tcp::dial` consumes a deduplicated endpoint list, preserving initial family
preference and within-family order while interleaving IPv4/IPv6. Starts are
staggered by `fallback_delay`; `max_attempts` and `max_parallel` bound work.
A failure advances the next attempt immediately. One absolute budget covers
resolution and attempts, and all losers are cancelled/joined before return,
including closing late successful sockets. The resolver overload waits for
bounded-worker system getaddrinfo first: it is not independent asynchronous
A/AAAA DNS. Cancelling the wait cannot interrupt a system call already entered.

HTTP/1 `ClientConnection::begin` sends the head, `send_body` borrows one chunk
until sent, and `finish` completes framing then reads the final response head.
Content-length and chunked uploads do not collect the whole body; size/framing
errors invalidate reuse. One absolute exchange budget covers upload and response
without reset, so time spent in a producer consumes that budget. Prefer
`source(OperationOptions)` and pass its options to asynchronous waits; legacy
zero-argument sources must arrange their own cooperative cancellation. Server
handlers can accept the extra OperationOptions argument or obtain it from
`writer.operation_options()`. Arbitrary user code that ignores those options
cannot be safely forced to stop. That trio is send-first: it reads nothing until
the body is sent.

`ClientConnection::exchange` is the duplex form. It writes the head, then pulls
the body from a producer while a concurrent reader parses 1xx and final heads,
so it needs a stream that allows one read and one write in flight (Mira TCP,
TLS and local streams do). With `expect_continue` no body byte is written until
`100 Continue`, a final response (`skipped`) or `continue_timeout`. A final
response with status >= 300 or a closing connection mid-upload withholds the
rest of the body (`interrupted`); an early 2xx that keeps the connection lets
the upload finish (RFC 9112 section 9.5). An in-flight chunk write is never
cancelled for an early response, because on TLS that would invalidate the
session and lose the response; a peer that neither reads nor closes is bounded
by the deadline or stop. Reader failure cancels the writer and producer failure
cancels the reader; `skipped`/`interrupted` forbid reuse, and the response body
is read after the upload. On the server, `serve_connection` answers
`100-continue` eagerly for buffered handlers and on the first body read for
streaming ones, closes rather than draining a refused body, and answers unknown
expectations with 417. The client upload API does not emit request trailers and no business
request is automatically retried.

`client::HttpClient` / `HttpsClient` own resolver/dial/pool composition above
HTTP's transport-independent layer. Pools use normalized host/port origins,
matching Host headers, bounded origins/connections and lazy idle expiry.
Instances never share pools, even when sharing a fixed TLS factory; HTTPS
negotiates HTTP/1.1 only, not implicit H2. One acquire budget covers DNS, TCP,
TLS, upload and response. Sessions heap-pin connection state, including through
lazy tasks. Body spans remain borrowed; started tasks must finish on the owning
loop. Recycling requires a drained reusable response and no retained session
tasks. Otherwise recycle fails; destruction discards, never silently returns a
partially consumed connection to the pool. No background reads detect idle
peer closure, and a failed reuse does not replay the request.

### QUIC paths, tickets and raw early data

`quic::Options::migration` defaults to `MigrationPolicy::fixed_peer`.
`validated` opt-in enables ngtcp2 path validation for migration/NAT rebinding;
matching a known CID alone never authorizes a new peer. Use path-aware
`receive(Path, ...)`, `poll_datagram` and `close_datagram`. Clients use
`initiate_migration`; `validated_path` and pending state expose progress.
Applications keep both required paths alive during validation and send packets
using the returned path. A fixed-local-socket adapter cannot magically move a
socket to another local endpoint. Dispatcher peer bookkeeping advances with
the validated path, while fixed-peer mode continues dropping changed sources.

`SessionCache` is a bounded, single-threaded, in-memory ticket cache with
entry/byte/per-ticket/lifetime limits, no disk export and cleansing on removal.
Resumption and 0-RTT require an explicit `ca_file`: the cache key includes a
SHA-256 fingerprint of the actual loaded store, covering certificate AUX trust
and rejection attributes plus CRLs. It does not re-read a path separately from
OpenSSL loading, avoiding a hash/load race. Replacing trust material at the same
path therefore cannot resume an old trust domain. An empty `ca_file` selects
system trust, whose lazy directory/provider sources cannot be fully snapshotted;
no tickets are stored or resumed, and a fresh authenticated handshake is required.
A loaded connection retains its trust snapshot; file edits do not revoke it.
`ServerContext` explicitly shares a server ticket domain with immutable
certificate, ALPN, scope and limits. Normal `open_stream` / `write` do not send
early data. Raw QUIC 0-RTT additionally requires `EarlyDataPolicy::replay_safe`,
a compatible cached ticket and explicit `open_early_stream` / `write_early`.
Applications inspect `early_data_status` and own the replay-safety decision;
rejected data is never replayed automatically at the QUIC layer. This provides
no anti-replay guarantee. A server engine reports `accepted` once TLS accepted
early data, the 0-RTT read key is installed and the 1-RTT write key exists; it
may then open streams for 0.5-RTT responses, still bounded by ngtcp2's
anti-amplification limit. `Options::early_data_context` is opaque application
compatibility state that a `ServerContext` pins, so engines sharing a ticket
domain must carry an identical value. Retry tokens also are not guaranteed
single-use or replay-proof.

### HTTP/3 0-RTT

Both ends opt in with `EarlyDataPolicy::replay_safe`. RFC 9114 section 7.2.4.2
lets a client either remember the server's SETTINGS or use defaults; the Mira
client remembers nothing and sends early requests under default SETTINGS
(QPACK dynamic table capacity 0, no extended CONNECT), which any compliant
server accepts. The server side is where compatibility must be decided: it may
accept 0-RTT only if SETTINGS a client remembered are still compatible. Mira
therefore requires `early_data_context = http3::early_data_context(limits)`
before creating the `ServerContext`; every ticket that context issues was
issued under identical SETTINGS, and `http3::Engine::create` / `make_server`
refuse a server whose limits produce a different context. A ticket from another
`ServerContext` cannot be decrypted, so drifted SETTINGS never meet old tickets.

A client holding a compatible ticket is `early_ready()` right after `create`:
its control/QPACK streams are opened as 0-RTT streams and `request()` sends
GET/HEAD/OPTIONS whole-body requests in 0-RTT. Other methods, streaming bodies
and extended CONNECT return `not_supported` until `ready()`;
`http3::Connection::request` instead drives the handshake (bounded by its
`OperationOptions`) and sends them in 1-RTT, and `Connection::connect` returns
before any datagram when 0-RTT is usable. If the server rejects early data,
ngtcp2 discards every early stream and stream-ID allocation, and TLS
guarantees the server processed none of it. The engine then rebuilds nghttp3
under the server's real SETTINGS and resubmits the safe requests in order,
which reproduces their stream IDs, so callers observe one normal response per
request. This is the HTTP layer deciding to resend requests it restricted to
safe methods, not the QUIC layer replaying opaque bytes.

A server that accepted 0-RTT becomes `ready()` before handshake completion
and answers in 0.5-RTT, so an accepted early request completes in one round
trip; the tests count flights to prove it. Requests whose bidirectional stream
carried 0-RTT data are surfaced with `Event::early_data`, and the application
decides whether a safe-method request may run twice (RFC 8470: answer 425 if
not). Early requests with unsafe methods, including extended CONNECT, are
answered `425 Too Early` by the engine and never surfaced; their request body
is consumed and discarded. There is no anti-replay store: a captured 0-RTT
flight can be replayed to any server sharing the ticket domain.

### H2/H3 Extended CONNECT and WebSocket

Set `Limits::enable_connect_protocol` explicitly. A client waits for actual
peer `SETTINGS_ENABLE_CONNECT_PROTOCOL` before submitting `request_stream`
with `:method=CONNECT`, `:protocol`, `:scheme`, `:authority` and `:path`.
Servers accept using `respond_stream`. Successful 2xx establishes a tunnel,
except status 204: pinned nghttp2/nghttp3 treat it as bodyless, so Mira returns
`not_supported` rather than claiming a usable tunnel. Ordinary CONNECT proxying
is not implemented. Tunnel consumption returns flow-control credit; unread and
retained output remain bounded. FIN and RESET stay distinct terminal states.

`http2::ConnectStream<Driver>` / `http3::ConnectStream<Driver>` borrow accepted
streams and stable engine/driver objects. Drivers supply
`progress(OperationOptions)` / `flush(OperationOptions)` returning
`Task<Result<void>>`, serialize connection I/O and honor budgets. One adapter
allows one operation at a time, not a simultaneous read/write pair. The caller
owns cross-stream scheduling and all borrowed lifetimes; do not mix direct body
operations with adapter I/O. `finish` half-closes local output, while
close/cancellation resets the stream. A connection-level driver failure can
still affect other streams. Destruction during a pending operation aborts.

WebSocket `extended_connect_request`, `accept_extended_connect` and
`validate_extended_connect` validate complete fields and negotiate subprotocols
and optional permessage-deflate; lower-level field-only negotiation helpers
also exist. After SETTINGS, accepted-stream and transport-security checks,
pass the resulting `Negotiated` to `Connection::adopt_extended_connect`.
No HTTP/1 Upgrade, nonce or accept-digest exchange runs on this path. These
helpers do not perform network I/O or relax ConnectStream's single-operation
contract. The default compression policy remains disabled.

### SOCKS5, DNS/DoH and MQTT

`Mira::socks` implements RFC 1928 CONNECT with RFC 1929 username/password over
any bounded stream, for both the client and the proxy side. Every message is
read at its exact length, so after a handshake the stream is positioned at the
first tunnelled byte and TLS or HTTP can follow without a pushback buffer.
Addresses are parsed and formatted strictly; non-success replies become typed
errors; the proxy side parses BIND and UDP ASSOCIATE only to refuse them.
`client::dial_via_socks5` composes `tcp::dial` and `socks::connect` under one
deadline and sends domain targets unresolved, so no lookup for the target
leaks outside the tunnel. Credentials are clear text per RFC 1929.

`Mira::dns` is an RFC 1035 / RFC 6891 codec that treats every byte as hostile:
compression pointers must point strictly backwards past the header, names stay
within 255 wire bytes, record counts are checked against limits and against
the bytes that could hold them before allocation, fixed RDATA sizes and
trailing bytes are enforced. A, AAAA, CNAME/NS/PTR, MX, TXT, SOA and EDNS(0)
(extended RCODE, RFC 8467 padding) are typed; other records round-trip as raw
RDATA. Encoding never compresses. The RFC 8484 helpers map GET/POST in both
directions with strict base64url, media-type and status checks and HTTP error
mapping; `doh::query` runs one exchange over an HTTP/1 `ClientConnection`,
including over TLS, and HTTP/2/3 callers use the request/response helpers.
Queries use id 0 and responses must answer the question.

`Mira::mqtt` covers MQTT 3.1.1 and 5.0 in three layers. The codec encodes and
decodes all fifteen packet types for both roles and refuses to emit anything
its decoder would reject: fixed-header flags, minimal Variable Byte Integers,
well-formed UTF-8 without U+0000, topic name/filter syntax (including 5.0
shared subscriptions), packet identifiers, reason codes per packet and version,
and in 5.0 the per-packet property table, property values and duplicates.
Direction is part of decoding, and an oversized packet fails from its fixed
header alone. `Session` is a socket-free client: QoS 1/2 sender and receiver
flows, packet-identifier allocation, the server's CONNACK limits (Receive
Maximum, Maximum Packet Size, Maximum QoS, Retain/Wildcard/Shared/Subscription
Identifier availability, Server Keep Alive, Assigned Client Identifier),
inbound topic aliases, keep-alive with PINGRESP supervision, enhanced AUTH
exchange, and resumption that resends unacknowledged PUBLISH (DUP) in original
order or reports them `discarded`. Replay observes the new connection's packet
size and Receive Maximum; PUBREL controls can pass quota-blocked PUBLISH packets.
Oversized retained packets fail the new connection instead of violating its
negotiated maximum. Nothing is queued invisibly:
the server's Receive Maximum, identifier exhaustion and the output bound return
`would_block`; peer violations close the session with a 5.0 DISCONNECT reason.
`Client<Stream>` borrows a caller-owned stream and follows the duplex stream
contract: one reader (`receive` / `wait_for`) beside serialized writers, with
`keep_alive(loop)` as a timer-driven writer, so keep-alive never depends on
read deadlines that would poison a TLS session. Client and Session share the
event bound, including reconnect abandonment notices. `connect` accepts an
asynchronous authentication callback `(const Event&, OperationOptions)` so
initial AUTH challenges can be answered before CONNACK; the method must match
CONNECT throughout, and callback waits should honor the operation options.
Received QoS 1 messages are
acknowledged when surfaced. Out of scope: a broker, MQTT over WebSocket,
outbound topic aliases, persistent session storage and reconnect policy.

### Managed serving and grace shutdown

`tcp::serve(loop, listener, handler, options)` stops admission, drains accept,
closes the listener and lets existing handlers finish during `grace_period`.
It then requests cooperative cancellation and joins all work. Admission
`io.deadline` is separate from optional `handler_deadline`. Zero grace cancels
immediately; a positive grace requires the EventLoop overload. Handler
exceptions skip grace and cancel siblings, then rethrow after cleanup. Grace
bounds when cancellation is requested, never forces destruction of a suspended
handler or guarantees a hard serve-return deadline.

With TLS and H2 enabled, `mira_https_managed_server` demonstrates separate
connection/handshake admission, handshake deadlines, explicit H1/H2 ALPN
dispatch, missing/unknown-ALPN refusal and drain/cancel/join. It serves one H1
request or one H2 batch per connection; it is a composition example, not a
complete production HTTP server. `mira_loop_group_server` demonstrates separate
worker loops, not cross-worker transfer of already attached sockets.

## Verification snapshots and remaining evidence

The [audit record](AUDIT-2026-09-30.md) records the latest tested revision and
hosted CI results, including Windows MSVC independent HTTP/3 and Retry
interoperability, MinGW H2/H3 runtime coverage and the Task stack regression.
Linux and macOS protocol jobs also require independent HTTP/3 curl and Retry
checks. The measurements below are historical development snapshots; they do
not replace verification of a release candidate.

- Historical 2026-09-29 phase source (HTTP/3 0-RTT, MQTT, documentation sync): local
  AppleClang Release, GCC 16 and ASan+UBSan each ran 97 tests, 95 passed and
  the 2 external HTTP/3 curl interop tests skipped (no HTTP3 curl locally), 0
  failed. GCC 13 base configuration 49/49 and GCC 14 full protocol configuration
  95 passed + 2 skipped; MinGW cross-compiled every MQTT
  target; installed-consumer and layering checks passed. `http3_early` counts
  flights to prove accepted 0-RTT completes in one round trip, rejected 0-RTT
  is resubmitted on the same stream IDs, a hand-built client's unsafe early
  POST gets 425 without surfacing, and SETTINGS drift is refused; mutations
  removing the 425 path, the resubmission or 0.5-RTT readiness each fail it.
  `http3_early_udp` repeats the client path through `http3::Connection` over
  real UDP. MQTT: codec 190 checks, session 160, real-TCP client 98, interop
  25 cases including 8 against mosquitto 2.1.2, and 145k fuzz inputs in 91 s
  under ASan+UBSan. There is no third-party HTTP/3 0-RTT peer evidence yet.

- Commit `d3424f0`: CI 17/17 and official Autobahn 25.10.1 including compression,
  517 cases per role (514 OK + 3 INFORMATIONAL), 1,034 total (1,028 OK +
  6 INFORMATIONAL), zero failures/NON-STRICT/missing/excluded cases.
- Historical 2026-09-28 source including trust-bound ticket caching: local AppleClang
  Release, GCC and ASan+UBSan each passed 85/85; installed-consumer and dependency
  isolation checks passed. macOS LeakSanitizer was not run. This is local evidence,
  not a substitute for this revision's remote cross-platform CI.
- Trust-cache fix: Release affected QUIC/H3/CONNECT regression 22/22; final
  targeted normal-resumption plus four trust tests 5/5 each on Release, GCC
  and ASan+UBSan. Tests cover same-path CA rotation with/without 0-RTT, an
  unchanged certificate with AUX serverAuth rejection, and uncached default
  system trust. macOS uses `detect_leaks=0`; this is not LeakSanitizer evidence.
- `ws.connect_network`: real TCP H2 and UDP H3, each with compression
  off/on, four passing scenarios. This is same-library networking, not an
  independent CONNECT peer. The first-Initial-flight drop setting was removed;
  this test does not establish PTO recovery.
- `build/all-main/sustained-600.json`: 600-second real-UDP H3 loopback soak,
  13,548/13,548 requests and 10,161/10,161 short streams completed during slow
  response overlap. Final connections/routes/tombstones/queued bytes/reserved
  payload bytes are all zero. One host, not multi-host/WAN or an RSS limit.
- iOS host smoke and unsigned cross-build passed; signed device execution has
  not been validated. Android device runs, multi-host/WAN and longer resource
  measurements remain without evidence. MinGW passed independent HTTP/3 and Retry
  CTest cases, but does not build a source-pinned curl in its job; that stricter
  Windows client configuration is exercised by MSVC.

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

## Next-phase goals

The 2026-09-29 phase delivered HTTP/3 0-RTT, HTTP/1 `Expect: 100-continue` with
duplex early-response handling, and the independent SOCKS5, DNS/DoH and MQTT
modules; their boundaries are recorded above. Still open: an anti-replay store
for 0-RTT, remembered server SETTINGS on the client, DoH over HTTP/2 and
HTTP/3 as a packaged query, MQTT over WebSocket and session persistence,
independent third-party interoperability for Extended CONNECT, device runs,
and multi-host/WAN measurements. gRPC, Redis and WebRTC stay ecosystem layers
above the network core. Release and downstream migrations remain separate from
work on Mira itself.

## Decisions on record

| Decision | Choice | Why |
|---|---|---|
| **I/O model** | **completion-shaped public API** | A common operation contract for IOCP and reactor implementations |
| Platform scope | Desktop runtime targets, including Windows MSVC independent H3/Retry and MinGW H2/H3; iOS host smoke/unsigned cross-build and Android cross-build | Mobile device execution is not yet evidenced; BSD has no dedicated CI evidence |
| Readiness API | POSIX-only, behind an explicit macro | A platform extension, not part of the portable operation contract |
| Execution model | Lazy `Task<T>`, single-threaded `TaskScope` spawn/join and independent-worker `LoopGroup` | Bounded root-task admission does not make one loop or its sockets multi-thread-safe; suspended tasks cannot be arbitrarily destroyed |
| Library form | Compiled library with modular public headers | Keep implementation boundaries explicit; the [release guide](RELEASES.md) defines source compatibility and requires rebuilding consumers |
| Error model | `std::error_code` + `Result<T>` for operational failures | `Task` can still propagate body exceptions; this is not a no-exceptions guarantee |
| Standard floor | C++23-only build; `Result<T>` directly aliases `std::expected<T, Error>` | Validate each toolchain and standard library; no C++20 compatibility mandate |
| Buffer shape | Current `Buffer` is contiguous | Future segmented or borrowed-buffer designs need measured benefit and an explicit ownership contract |
| Framework coupling | No host-framework dependency or old Aria API compatibility promise | Consumers adapt to the independent library after its contracts are established |
| Protocol scope | HTTP/1.1, TLS, WebSocket/WSS, HTTP/2, QUIC, HTTP/3, SOCKS5, DNS/DoH and MQTT are implemented modules | Track protocol implementation separately from independent interoperability and per-platform runtime evidence |

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
3. **Bounded composable data flow.** Incremental body consumption, HTTP/1
   uploads and bounded H2/H3 outputs are delivered; acceptance still requires
   end-to-end producer/consumer measurements. Verify short transfers, partial failures,
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

**Stage 1 — seams.** Error model, `Task<T>`, `Buffer`, executor and stream
concepts, warning policy, layering discipline, CI across C++20/C++23 and
sanitizers.

**Stage 2 — the loop.** `EventLoop` with three backends (kqueue, epoll, IOCP),
completion-shaped `read`/`write`, timers, cross-thread `post`, and a
`platform.hpp` that is the single home for platform detection. CI now builds
and *runs* tests on all three backends, and cross-compiles for iOS and Android.

The historical local kqueue run recorded 118 checks across C++20, C++23 and
ASan/UBSan. Desktop epoll/IOCP runtime coverage comes from CI, not that local
run. Neither the check count nor the existence of a CI job establishes current
revision health or full backend lifecycle correctness.

**Stage 3 — the parser.** Incremental, strict HTTP/1.1 request parsing:
`message.hpp` (HTTP message types, subject to review for future protocol reuse),
`limits.hpp` (parser bounds), and a parser whose test suite is mostly published
smuggling vectors. 119 checks, and the byte-at-a-time tests assert that network
slicing cannot change the parse.

**Stage 4 — TCP.** `Endpoint`, `Listener`, `Socket`, `connect`, and an explicit
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

**Stage 5 — a working server.** Response serialisation and `serve_connection`,
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
must remain alive. The stream also borrows its explicitly supplied EventLoop.
After handshake, one read and one write may overlap on that loop thread; same-
direction calls and overlapping handshake/shutdown are rejected. SSL calls stay
synchronous and serialized, while ciphertext read/write operations use separate
bounded buffers. Each request owns a cancellable deadline timer. A deadline
change never cancels and resubmits wire I/O: IOCP cancellation can hide bytes
already transferred. Terminal failures permanently stop both directions. Reads
wait only for output they generated, not unrelated backpressured application
writes; TLS 1.3 KeyUpdate and WSS duplex have dedicated regression coverage.

Tests generate fresh private CA/certificate/key fixtures at runtime; no private
keys are committed. HTTPS exercises the existing HTTP loop unchanged, with
trusted/untrusted chains, DNS and IP identity mismatches, short encrypted I/O,
large payloads, orderly close and truncated TCP. The optional TLS CI matrix is
separate from the dependency-free build. Mobile base-library cross-compilation
and iOS host smoke/unsigned app builds are not mobile TLS runtime validation;
iOS device execution lacks a signing profile and Android has no device evidence.
BSD also has no dedicated CI evidence.

This integration also fixes HTTP EOF before the end of a partial request head
being mistaken for idle disconnect, and rejects a zero read-chunk policy.
HTTP/1 also provides a streaming RequestBodyReader; H2/H3 expose bounded incremental outbound bodies.

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
Options now reach transport, TLS and HTTP; TLS enforces application deadlines
with its own timers rather than forwarding them to ciphertext I/O. UDP and
system resolver waits use the same cancellation/deadline foundation. Cancelling a system
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
resolution, HTTP/1 client, HTTP/2 engines and request-body streaming exist.
QUIC/HTTP3 have real UDP scheduling, CID-routed multi-client dispatchers,
closing/draining protection and optional Retry source-address validation.
Opt-in validated migration, bounded ticket resumption, raw-QUIC early data and
H2/H3 Extended CONNECT now exist, with the boundaries described above.
Mobile protocol runtime acceptance, native OS trust-store integration and
process-wide memory bounds remain incomplete. `LoopGroup` supplies independent
thread-affine loops, not concurrent pumping of one loop.
mTLS policy is available on `tls::Context`; protocol queue and payload
budgets are not hard process-RSS bounds.
Judge the current tested snapshot by the repository's own CI and tests rather
than the historical counts above.
