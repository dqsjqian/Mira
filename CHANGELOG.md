# Changelog

Mira follows [semantic versioning](https://semver.org). While the major
version is 0, the minor version is where breaking changes land: a request for
0.3 is not satisfied by 0.2, which the package-config version file encodes as
`SameMinorVersion`.

## [Unreleased]

### Added

- Opt-in stateless QUIC Retry admission with ngtcp2 AEAD tokens, source-address
  binding, strict expiry, service-scoped key rotation and bounded reply limiting.
- Required-Retry HTTP/3 multi-client example, independent curl interoperability
  observing Retry on real UDP, and a seeded bounded fault/churn harness with JSON
  content, fairness, resource-drain and sampled-RSS evidence.
- Windows MSVC QUIC/HTTP3 runtime coverage, pinned multi-config dependency
  builds and installed-package static-library dependency propagation.
- Same-event-loop TLS and WSS duplex I/O, with independent request deadline
  timers and permanent session cancellation instead of unsafe wire retries.
  TLS `Stream::create` now requires its `EventLoop&` as the first argument.
- Bounded QUIC closing/draining tombstones retaining all issued CIDs for three
  PTOs, paced input-triggered close retransmission and shared cache accounting.
- Official Autobahn 25.10.1 client/server coverage: 301 non-compression cases per
  role (298 OK, 3 informational, zero failures/non-strict/missing cases).
  The 216 compression cases per role remain explicitly excluded.
- WebSocket framing and handshake libFuzzer harnesses, plus regression-tested
  conformance report checking and cross-platform pinned dependency extraction.
- CID-routed single-port QUIC/H3 dispatchers, bounded admission and resource
  reservations, shared payload budgets, multi-client runtime tests and example.
- H2/H3 incremental request/response bodies with bounded chunk queues,
  deferred/resumed output, ACK-safe H3 lifetimes and stream fairness tests.
- Optional RFC6455 WebSocket/WSS, secure masking/handshake primitives, framing
  and UTF-8 negative tests, independent Python interoperability and TCP duplex.
- Shareable RAII resource budgets, bounded connection leases, establishment-only
  reconnect policy, admission-controlled TCP serving and cooperative shutdown.
- SSE resume example, POSIX filesystem local streams and real socket benchmarks
  reporting throughput, latency percentiles and observed server RSS.

### Fixed

- Incremental UTF-8 validation rejects impossible text prefixes without waiting
  for the remainder of a frame or fragmented message.
- Event-loop timer/deadline registration rolls back every partially registered
  operation on allocation failure; IOCP accept also releases its pending socket.
- HTTP/2 TLS tests consume close_notify before completing the TCP shutdown,
  preventing unread ciphertext from turning successful responses into resets.
- QUIC rotates bidirectional stream output instead of starving higher stream IDs.
- Installed consumer verification restricts multi-config generators to the
  configuration actually installed, including vcpkg's configuration mappings.


## [0.5.0] — 2026-09-28

### Added

- Runnable client/server pairs for TCP, UDP, HTTP/1.1, HTTP/2 and HTTP/3.
  Smoke tests cover keep-alive, concurrent streams, zero-byte datagrams,
  connection refusal and deadlines. H3 examples require explicit certificates.
- HTTP/3 `receive_events()` exposes real request IDs in arrival order with
  bounded connection-level queues. Resets are errors, not successful EOF;
  recent consumed terminal states remain terminal on repeated reads.
- Isolated installed-SDK consumer tests, including required/optional components,
  lower-case version headers, H3 without H2, and QUIC without H3 dependencies.
- Hash-pinned independent HTTP/3 curl builder and strict Linux interoperability
  gate. A missing external client is explicitly skipped elsewhere, never passed.

### Fixed

- HTTP/1 chunk terminators reject invalid prefixes immediately rather than
  accumulating unbounded data while waiting for a newline.
- POSIX readiness batches keep pending operations cancellable until dispatch;
  closing/reusing another ready descriptor cannot redirect old I/O. Socket
  writes suppress SIGPIPE locally without changing process-wide disposition.
- Scattered writes skip trailing empty fragments instead of reporting EOF.
- Endpoint equality compares family, IP, port and IPv6 scope, not OS padding,
  BSD length bytes or flow labels.
- QUIC/H3 process already-expired timers before awaiting another datagram,
  distinguish caller deadlines from protocol timers, and keep the peer fixed.
- The overload benchmark appends short reads correctly; a configurable read
  chunk makes the fragmented-response path independently reproducible.
- Parser implementation objects now carry libFuzzer coverage instrumentation,
  rather than instrumenting only the harness translation units.

### Changed

- Shared HTTP field types live in dependency-free `Mira::http_common`; HTTP/3
  no longer requires nghttp2. H2/H3 field aliases remain source-compatible,
  but their canonical namespace changed: rebuild consumers for this minor release.
- Package components use the correct `Mira_*` variables, and QUIC/H3 have
  separate exports. `mira_h3_server` now takes port, certificate and key paths.

### Added

- CI: a UCRT64 MinGW job (GCC + OpenSSL from the ucrt64 packages, full suite
  with TLS). MSVC-only Windows coverage shipped two real MinGW-only defects
  in 0.4.0 — the resolver's empty diagnostics and a coroutine conditional
  that stalls under GCC 15 — and neither toolchain can see the other's
  blind spot.

### Fixed

- Windows: the resolver's diagnostic is never empty. `gai_strerrorA` is
  uneven across toolchains — MinGW's copy returns an empty string for
  several WSA codes (`WSATYPE_NOT_FOUND` among them) — so the category now
  falls back to a static table of the codes `getaddrinfo` documents, then
  to the raw value.
- Windows: the TLS tests no longer select the connection step with
  `co_await` inside both branches of a conditional operator. Under GCC 15
  (MinGW) the operation completes but its awaiter is never resumed, so
  every loopback exchange stalled until the deadline; plain `if/else`
  lowers correctly on every toolchain.

## [0.4.0] — 2026-09-27

The audit-hardening release: the negative space of the parsers is explored
continuously (fuzzing), the loop's own costs are measured (benchmarks), the
examples prove real interop (curl speaks to every server), and the seams the
library is built on became named, executable contracts.

### Changed

- The codebase speaks one language in its comments, diagnostics, and test
  labels: English throughout — a comment a global contributor cannot read is
  a contract nobody can check. The bilingual README stays; the code does not.
- `post()` takes `mira::move_only_function<void()>`: posted work no longer
  has to be copyable, so a callable capturing a `Task` can be posted
  directly. The library owns one backing implementation on every platform:
  toolchain feature macros cannot be trusted here — the Android NDK
  advertises `__cpp_lib_move_only_function` while its libc++ ships without
  the type, which is how a macro-gated branch compiles on the desktop and
  fails on the phone. CI on macOS/iOS/Android/Windows caught exactly that.
- The `Executor` concept now probes the exact resumption closure
  `schedule_on` posts (`detail::PostedResumption`) instead of a function
  pointer, so a type satisfying the concept is a type that actually works.
  `ExecutorFor<E, F>` is added for per-callable checks.
- **Scattered writes**: `AsyncVectorWriteStream`/`BoundedVectorWriteStream`
  concepts and `writev_all` join the stream seam; `EventLoop::writev`
  (writev(2)/WSASend) and `tcp::Socket::writev_some` implement them. A
  response head and body now leave in one submission without being
  concatenated, removing a full copy of every response body. `writev_all`
  rebuilds its tail view per short write but allocates it once per call, so
  a scattered transfer costs no malloc per iteration.
- A request body whose Content-Length is parsed reserves its size up front:
  one allocation plus linear appends instead of the vector's doubling growth.
- `Errc::internal` added: an exception that crossed a library boundary (e.g. a
  throwing HTTP handler) is reported as `internal` instead of escaping the
  connection loop. `serve_connection` answers 500 when nothing was sent and
  drops the connection when a head is already on the wire.
- `quic::Bytes` is `std::vector<std::byte>`: the wire surfaces (engine
  accept/receive/write, HTTP/3 request/respond and connection serve/write)
  speak the library-wide byte type; the C API boundaries (ngtcp2/nghttp3)
  reinterpret inside the engines' own translation units only.
- HTTP/2 and HTTP/3 share one header-list type (`http2/headers.hpp`): HPACK
  and QPACK compress the same field-section semantics, so `http3::Header` is
  `http2::Header` instead of a pair of strings. Limits stay per-protocol.
- The datagram contract is a named core seam: `transport::DatagramTransport`
  (`mira/transport/datagram.hpp`) replaces the QUIC-local concept of the
  same shape. `udp::Socket` satisfies it, deliberately broken shapes do not,
  and both directions are pinned by compile-time assertions
  (`transport/tests/test_datagram_concept.cpp`) — a concept nobody asserts
  is a comment pretending to be a contract. `quic::Connection` and
  `http3::Connection` constrain against the transport-level name now.
- Destroying a `tls::Stream` with an operation still in flight terminates
  with a diagnosis instead of leaving the borrowed state dangling silently —
  the same contract `Task` already carries.
- Destroying an `http2::Connection` with an operation still in flight aborts
  with a diagnosis, and overlapping `flush`/`read`/`pump` on one connection
  fails with `invalid_argument` instead of corrupting the session — the same
  borrow contract as `tls::Stream` and `http::ClientConnection`.
- Reusing a parsed `Request`/`Response` keeps header-string capacity:
  `HeaderMap::clear` drains entries into a bounded spare pool that `append`
  reuses, so keep-alive serving stops reallocating every header on every
  request.
- Response/request head serialisation reserves its total size up front
  instead of growing through a dozen reallocations on the way.
- In-process benchmarks land under `bench/` (opt-in via `MIRA_BUILD_BENCH`):
  HTTP/1.1 keep-alive small responses and HTTP/2 concurrent streams, with
  the blessed invocation pinned in `tools/bench/run.sh`.
- Request bodies can stream. A handler whose third parameter is
  `std::span<const std::byte>` gets the whole buffered body as before; any
  other callable gets a `RequestBodyReader` and pulls slices while it runs —
  uploads no longer need to fit in memory to make progress. Either way the
  connection loop guarantees the body is drained (or the connection dropped)
  before the next request parses, which is the keep-alive desync rule applied
  to the streaming path too. Trailers of a chunked body land on the reader
  after the final read.
- Benchmarks grew the scenarios the first two were chosen against:
  `bench_h1_churn` (full connection lifetime: accept, one exchange, close),
  `bench_h1_cancel` (deadline and stop-token teardown overhead), and
  `bench_h1_overload` (4 KiB bodies pushed through a 512 B read window —
  the price of backpressure).
- libFuzzer harnesses land under `fuzz/` (opt-in via `MIRA_BUILD_FUZZERS`,
  clang): the request parser is fuzzed across arbitrary chunk boundaries with
  seed corpus covering smuggling shapes. CI runs a short smoke pass on Linux.
- The response parser gets the same treatment — `fuzz_response_parser` —
  because a client parsing an untrusted server's bytes is the same class of
  hazard as a server parsing an untrusted client's. The harness exercises
  the documented 1xx reset loop, HEAD/CONNECT body rules and close-delimited
  framing; its minimized seed corpus (383 inputs) replays in CI alongside
  the request harness, 60s cap each.
- The examples directory earns its name: `hello_world_server` (the
  three-step minimum — accept, `serve_connection`, `run_until_complete`)
  and `tiny_file_server` (streaming both directions: uploads via
  `RequestBodyReader` to disk, downloads via chunked `send_head_chunked` /
  `write` / `finish`, directory listing, traversal refusal, a MIME table).
  Both ship with out-of-process smoke tests, and the file server's test
  includes real curl interop — an external client against Mira's stack,
  byte-compared, since that is the claim "HTTP server" makes.
- `h2_prior_knowledge_server` joins the examples (built when
  `MIRA_ENABLE_HTTP2=ON`): the thinnest honest demonstration of the http2
  layer — a TCP listener, a server-role `Session`, per-connection `pump`,
  requests answered as their headers arrive and reclaimed once the stream
  retires (`take_body`/`release`). Its test is real nghttp2 inside curl
  speaking prior-knowledge HTTP/2, single and `--parallel` concurrent
  streams, skipped with a message where no HTTP/2-capable curl exists.
- `h3_server` follows for HTTP/3 (built when `MIRA_ENABLE_HTTP3=ON`): one
  UDP socket, a startup-generated localhost certificate, `Connection::serve`
  for the QUIC handshake, request streams answered in arrival order. Its
  test is curl's native QUIC stack — ngtcp2 + nghttp3 — speaking real h3
  with `--http3-only` and `--cacert`, verifying TLS 1.3, ALPN, QPACK and
  the response framing end to end.

### Fixed

- `RequestBodyReader::trailers()` is documented as borrowing the connection's
  parser: the view dies with `serve_connection` (or moves on with the next
  request), so values that must outlive the request need copying out — the
  streaming test itself tripped on this, and its ASan build now copies before
  the connection ends.
- The CI fuzz job builds with libc++: Ubuntu's clang pairs with a system
  libstdc++ that lacks `std::expected`, which made `Result<T>` vanish and
  every core TU fail. `-stdlib=libc++` (plus `libc++-dev`) gives the harness
  a complete C++23 library; the fuzz harness also includes `<cstdlib>` for
  `std::abort`, which libc++ does not drag in transitively.
- `bench/CMakeLists.txt` no longer requires nghttp2: a bare
  `cmake -DMIRA_BUILD_BENCH=ON` used to die at generate time because
  `bench_h2_roundtrip` linked `Mira::http2` unconditionally. The bench set
  degrades to the HTTP/1.1 scenarios with a note pointing at
  `tools/bench/run.sh`.
- QUIC/HTTP/3 pump loops no longer mistake the caller's expired deadline for
  the engine timer: the operation now fails with `timed_out` instead of
  spinning the loop thread on a silent peer.
- Registering a stop callback after an irreversible submit can no longer
  cause a double-resume under allocation failure; the callback registration
  degrades instead.
- Operations on a moved-from `EventLoop` (sleep/wait/read/write/accept/
  connect/yield on every backend) now fail with `cancelled` instead of
  dereferencing a null backend.
- `datagrams_` bookkeeping in the POSIX backend is now locked, matching the
  rest of the cross-thread submission paths.
- `dispatch_depth_` is `std::atomic<int>`; the shutdown diagnostic no longer
  commits a data race of its own.
- HTTP handler exceptions can no longer escape `serve_connection`.
- Release hygiene: every version now ships its tarball as a release asset.
  The v0.1.6 and v0.3.0 releases were published without the archive the
  consumption example pins, which made the documented URL a 404; both
  archives are attached, and `Mira-0.4.0.tar.gz` ships with this release
  so the pin resolves on day one.

## [0.3.0]

### Renamed

- The project is now **Mira** (formerly `continuo`). Export sets, package
  config, and CMake options all follow the new name (`MiraConfig.cmake`,
  `MIRA_*` options).

## [0.2.0]

Initial public layout: core coroutine engine (task/scope/loop), transport
(TCP/UDP), HTTP/1.1, and optional TLS / HTTP/2 / HTTP/3 modules.
