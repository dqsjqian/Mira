# Roadmap and deferred decisions / 路线图与暂缓决策

This file records decisions taken on 2026-10-25 for the gaps in the
Mira evaluation report, and the designs for the items deliberately
**not** landed in that round. A decision here is a decision, not an
omission: each deferred item states why it was not landed, what its
design looks like, and what "done" requires. Nothing here promises a
date; the acceptance criteria, not the calendar, define completion.

## Decisions landed in 2026-10-25

### HTTP/3 is no longer marked experimental (P1-2)

`MIRA_ENABLE_HTTP3` lost its `(experimental)` label. Evidence: independent
aioquic and curl interop, Retry interop on Linux/macOS/Windows MSVC, and
a 600-second loopback soak (13,548/13,548 requests). The option stays OFF
by default; de-labelling is a maturity signal, not an enablement.
Remaining boundaries are documented in README's "仍需验证的边界", not
hidden by the label: WAN/multi-host evidence, reverse-role Extended
CONNECT, and more implementations. The upstream ossl QUIC TLS adapter
remains experimental upstream; that caveat stays in
`modules/quic/CMakeLists.txt`.

### HTTP timeouts default to 60 seconds (P1-3)

`http::ServerOptions::idle_timeout`, `http::ServerOptions::request_timeout`,
and `http::ClientOptions::request_timeout` all default to 60 seconds
(previously zero, i.e. disabled). Rationale: Mira's own rule is "closed
by default, opened by configuration" for parser limits; time limits were
the exception, and an unbounded wait is the time-domain equivalent of an
unbounded parser. 60 seconds matches the de facto server timeout
(nginx/Apache `Timeout 60`) and is generous for one size-bounded exchange
(bodies are capped by `limits` by default). Zero still disables either
bound for callers that opt out explicitly. A client raising `limits` for
large downloads must raise `request_timeout` together; the header
comments say so.

### ABI policy (P2-10)

See `docs/RELEASES.md`, "ABI policy" subsection: source compatibility
within a major version is promised; binary compatibility is explicitly
not promised across any release, including patch releases. The reasons
are structural (templates, header-only modules, inline functions,
coroutine frame layouts), not a lack of effort. Versioned inline
namespaces plus a stable C-ABI surface plus CI ABI checks would be
required to ever change this; that is out of scope until a
major-version boundary forces the question.

## Deferred: io_uring backend (P2-2)

**Decision: not landed.** The README already states the governing rule:
backends are chosen by real bottlenecks, not by feature name. epoll
covers Linux correctness and performance today; no measured bottleneck
justifies core-loop surgery in this round, and the sandbox cannot
validate the kernel matrix (kernel >= 5.1, seccomp permitting
`io_uring_setup`) that a backend must support.

**Design sketch.** Mira's completion-based API does not change: the
backend plugs into the core event loop's poller abstraction alongside
epoll/kqueue/IOCP. Pieces: `io_uring_setup`/`io_uring_enter` via raw
syscalls (core keeps zero third-party dependencies; no liburing),
submission-queue batching, timer handling via timeout opcodes or the
existing timer wheel, fd lifecycle identical to the epoll backend, and
automatic fallback to epoll when the kernel is too old or the syscalls
are blocked. SQPOLL is an opt-in tuning knob, not the default.

**Acceptance.** The bench suite (`scripts/bench/`) shows a measured
improvement over epoll on at least one bottleneck workload (not just
"it compiles"); the full test suite stays green on gcc and clang;
the fallback path (uring unavailable -> epoll) is covered by a test;
CI covers a kernel matrix, not a single kernel.

## Deferred: zero-copy transfer (P2-3)

**Decision: not landed.** The API shape touches the transport send path
on all three platforms, and the buffer-lifetime contract (caller retains
buffers until completion) needs a design that survives the platform
matrix. No measured bottleneck justifies that blast radius now.

**Design sketch.** A transport-level `send_file` (and, separately,
zero-copy send of userspace buffers):
- Linux: `sendfile` for fd-to-socket, `splice` for pipe paths,
  `MSG_ZEROCOPY` for userspace buffers with completion delivered via the
  socket error queue — which fits Mira's completion model (completion
  fires when the kernel releases the buffer).
- macOS: `sendfile` with its different argument shape; no
  `MSG_ZEROCOPY` equivalent, so userspace buffers fall back to copy.
- Windows: `TransmitFile` for file handles; userspace buffers copy.
- Fallback everywhere: the same API performs a plain copy loop when the
  platform path is unavailable, and documents that it did. The caller
  contract is uniform: buffers stay alive until completion, on every
  platform, whether or not the kernel copied.

**Acceptance.** Byte-equality loopback tests on all three platforms;
bench shows a throughput/latency win on large transfers; the fallback
path is tested, not just documented; the completion-lifetime contract
is stated in the header and exercised by a test that reuses a buffer
after completion only.

## Deferred: TCP TLS 1.3 0-RTT / early data (P2-5)

**Decision: not landed.** QUIC/H3 0-RTT already exists and covers the
low-latency case on the H3 path. TCP early data is replayable by
design, so the feature *is* its replay safety: shipping an early-data
API without the threat model and the anti-replay store would be a
footgun. The evaluation itself recommends settling the threat model
before building.

**Design sketch.** Mirror the H3/QUIC 0-RTT contract already in the
repo, do not invent a second one: an `EarlyDataPolicy::replay_safe`
opt-in; early data only for replay-safe operations (safe methods on the
HTTP layer, explicit policy on the TLS layer); server acceptance only
with a `ReplayStore` claim (the in-process `MemoryReplayStore` concept
from QUIC, with cross-process persistence as a separate, later piece);
rejection falls back to 1-RTT automatically and replays safe requests
exactly once, as H3 does. Implementation surface: OpenSSL
`SSL_write_early_data`/`SSL_read_early_data`, session tickets and
ticket rotation, and the server-side accept/reject decision point.

**Acceptance.** A threat-model section in the docs comes first (what is
replayable, what is safe, ticket lifetime/rotation, store scope).
Interop with OpenSSL `s_client`/`s_server` early data; accept and
reject fallback tests; a replay test (same early data twice, second one
rejected when the store is enabled); the H3 0-RTT tests stay green
unchanged.

## Other deferred items (from the evaluation, unchanged)

- HTTP client cookie jar and response cache (P2-1 remainder): need an
  API-shape decision first; they must not silently change request
  semantics for existing `HttpClient` users.
- MQTT outbound topic-alias management (P2-7 remainder): needs a
  session-level alias table tied to retransmission/checkpointing.
- DNSSEC and DNS server discovery/NSS (P2-6 remainder): validation and
  trust-anchor policy first; the TCP-fallback helper landed in 2026-10-25
  is the transport piece these would build on.
- Mobile-device evidence, Windows-native behaviour, IOCP native
  evidence, H2/H3 204 tunnelling (P1-1, P1-4, P1-5, P2-9): environment
  or engine limits, not decisions; see the handoff note for the
  platform evidence each one still needs.
