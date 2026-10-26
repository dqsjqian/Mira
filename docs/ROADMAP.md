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

## File transfer and remaining kernel zero-copy work (P2-3)

**Implemented portion (2026-10-26).** `FileSource`, `tcp::Socket::send_file`
and `send_buffer` provide explicit copy/prefer-native/require-native policy
and native/copied byte accounting. Files use Linux/macOS sendfile and Windows
TransmitFile; copy mode has bounded allocation. Cancellation/deadline and
close/destruction are tested, including actual suspended transfers. The source
file must remain immutable until peer consumption; regular-file reads/page
faults can block the loop. Userspace buffers currently copy on every platform;
require-native refuses rather than misreporting this as zero-copy.

**Still not implemented.** Linux pipe splice and MSG_ZEROCOPY error-queue
completion. These remain separate from file sendfile support; P2-3 is not
represented as an entirely completed Linux zero-copy matrix. Windows native
runtime evidence for the new TransmitFile path is covered by the Windows IOCP
Debug and Release CI jobs; a MinGW cross-build alone is not that evidence.

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

## TCP TLS 1.3 0-RTT / early data (P2-5)

**状态。** 已接入真实 OpenSSL `SSL_write_early_data` / `SSL_read_early_data`
和 `tls::Engine` / `tls::Stream` 驱动。普通握手保持默认禁用；共享的
`EarlyDataPolicy`、`EarlyDataStatus`、`ReplayStore`、`MemoryReplayStore`
位于 core，QUIC 保留原命名空间别名，不增加 TLS 对 QUIC 的依赖。

**威胁模型与准入。** 早期数据可被攻击者跨连接重放，且没有前向保密。
调用方必须通过 `handshake_early_data(payload, EarlyDataPolicy::replay_safe)`
显式声明整个载荷可安全重放；TLS 不解析 HTTP 方法，HTTP 安全方法也不自动
证明业务无副作用。每次载荷最多 16 KiB。服务器必须同时配置 `replay_safe`
与共享 `ReplayStore`；缺少存储的配置被拒绝。OpenSSL 验证 PSK binder 后，
以协议域、身份/配置代次 scope 和受加密票据保护的随机 32 字节 ID 散列进行
原子 claim。同一票据即使使用新的 ClientHello 也只能接受一次早期数据；
重复、容量满、时钟回拨或存储故障均 fail closed。内置 OpenSSL 反重放缓存
不作为替代品；开启该功能后使用强制的 ReplayStore 准入门。

**票据范围、有效期及轮转。** 默认有效期 1 小时，允许 1 秒至 7 天。
票据携带同一单调纳秒时钟上的绝对到期值，claim 保留至该期限；服务端也设置
OpenSSL session timeout。客户端取本地 timeout、服务端 ticket lifetime hint
与 7 天上限的最小值，并在 resume 及首次发送前复查单调期限。
`SessionTicket` 仅内存、move-only、单次消费，与原客户端 Context 快照和对端
名称绑定，因此也绑定该快照的 CA、ALPN 和验证策略；仅 TLS 1.3 完成握手且
读操作处理 NewSessionTicket 后可取，没有票据返回空 optional 而不消耗额度。
已消费但未收到替换票据时不能再次导出同一票据。`reload_server` 为新建引擎
轮转票据密钥及身份 scope，既有引擎仍保留旧快照。共享 Context 必须保持同一
服务语义与 ALPN 兼容配置，应用语义变化也必须 reload。

**存储与认证边界。** `MemoryReplayStore` 是线程安全、有界、进程内的原子
准入存储，不是分布式防重放。所有同票据域引擎须共享存储；重启后不能恢复旧
票据密钥并配一个空存储。本实现不提供票据密钥/会话导出、跨进程恢复或后台
会话缓存。客户端只有显式 CA 且未配置 mTLS、CRL、OCSP 才允许取票据及发送
早期数据；系统信任路径不参与此功能。服务端早期数据不能与 mTLS/CRL 共用。
这些组合明确拒绝而非关闭证书校验。接收的早期载荷直到完整握手成功才交付应用。

**回退、取消与资源。** 没有兼容票据时载荷仅在 1-RTT 发送；明确拒绝后仅对
本次保留的安全字节在同连接 1-RTT 补发一次。取消、超时、网络错误或认证失败
都终止会话，不自动另连重放。这里的“一次”不是跨连接业务 exactly-once。
早期载荷缓冲按需分配，额外最多预留 16 KiB ResourceBudget，分配或预留失败
不发送/交付早期数据；正常完成/读尽、取消或销毁后释放。普通关闭功能的 TLS
连接保持原有预算，OpenSSL 内部内存仍不计入该预算。

**验收。** Apple Clang 和 GCC 的 C++23 Release 覆盖接受、拒绝/禁用/轮转
回退、同票据重复使用、跨 Context/SNI 隔离、过期、安全配置负例、短密文 I/O、
取消与超时。`tls.early_data.openssl` 实际运行 OpenSSL `s_client` 到 Mira 的
接受/同票据拒绝及 Mira 到 `s_server` 的原生早期数据互操作；原 H3 0-RTT
测试随统一全协议回归继续验收。

## Explicit client state, MQTT aliases and DNS validation

- P2-1: `RedirectOptions::state` explicitly enables bounded in-memory Cookie
  and response-cache state, default off. Cookie scope is strict origin, not a
  browser/public-suffix implementation. Cache only stores explicit fresh,
  credential-free GET/200 responses; clear invalidates in-flight writes.
- P2-7: MQTT 5 outbound topic aliases are per connection, bounded by the peer
  and local quota, and published only after output admission. Reconnect resets
  mappings; in-flight/checkpoint records retain full topics for reconstruction.
  A broker and business exactly-once semantics are not provided.
- P2-6: `MIRA_ENABLE_DNSSEC` builds optional `Mira::dnssec` with explicit DS
  trust anchors, DNSKEY/DS/RRSIG chain validation and bounded Exchange-driven
  evidence gathering. ECDSA-P256/SHA-256 and Ed25519 with SHA-256 DS are
  supported. Unknown algorithms, missing evidence, negative-answer proofs and
  wildcard expansion fail closed; this is not a complete recursive validator
  or RFC5011 automatic trust-anchor manager. Ordinary `Mira::dns` remains free
  of OpenSSL. `transport::system_dns_config` snapshots default DNS servers;
  system NSS stays with `Resolver`/getaddrinfo, not a parallel NSS engine.

## Platform evidence and unresolved boundaries

The 2026-10-26 mobile acceptance target is simulator/emulator execution, not
physical-device execution. Both iOS arm64 Simulator and Android arm64 Emulator
run the core, TCP/UDP, HTTP, TLS, MQTT, H2/H3 and DNSSEC suites through
`scripts/ci/run_mobile_tests.py`. Host-side Python interop scripts are reported
separately; Android adb-shell policy can reject filesystem Unix socket bind,
which is an environment skip, not successful local-socket evidence. No security
policy is disabled to make a test pass.

Windows native IOCP, explicit Unix-domain/ancillary rejection and link-local
zone dialing evidence from 2026-10-26 is recorded in ARCHITECTURE.md. P2-9 CONNECT
204 uses the maintained nghttp2 1.70.0-mira.1 / nghttp3 1.18.0-mira.1 forks.
Their capability macros enable 204 without status rewriting; upstream libraries
without that capability retain explicit `not_supported`. See
[protocol dependency maintenance](PROTOCOL-DEPENDENCIES.md).
P2-2 io_uring remains the Linux-specific deferred work described above.
