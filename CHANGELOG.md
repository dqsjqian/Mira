# Changelog

Mira follows [semantic versioning](https://semver.org). While the major
version is 0, the minor version is where breaking changes land: a request for
0.3 is not satisfied by 0.2, which the package-config version file encodes as
`SameMinorVersion`.

## [0.3.0]

### Renamed

- The project is now **Mira** (formerly `continuo`). Export sets, package
  config, and CMake options all follow the new name (`MiraConfig.cmake`,
  `MIRA_*` options).

### Changed

- `post()` takes `std::move_only_function<void()>`: posted work no longer has
  to be copyable, so a callable capturing a `Task` can be posted directly.
- The `Executor` concept now probes the exact resumption closure
  `schedule_on` posts (`detail::PostedResumption`) instead of a function
  pointer, so a type satisfying the concept is a type that actually works.
  `ExecutorFor<E, F>` is added for per-callable checks.
- **Scattered writes**: `AsyncVectorWriteStream`/`BoundedVectorWriteStream`
  concepts and `writev_all` join the stream seam; `EventLoop::writev`
  (writev(2)/WSASend) and `tcp::Socket::writev_some` implement them. A
  response head and body now leave in one submission without being
  concatenated, removing a full copy of every response body.
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
- Destroying a `tls::Stream` with an operation still in flight terminates
  with a diagnosis instead of leaving the borrowed state dangling silently —
  the same contract `Task` already carries.
- Response/request head serialisation reserves its total size up front
  instead of growing through a dozen reallocations on the way.

### Fixed

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

## [0.2.0]

Initial public layout: core coroutine engine (task/scope/loop), transport
(TCP/UDP), HTTP/1.1, and optional TLS / HTTP/2 / HTTP/3 modules.
