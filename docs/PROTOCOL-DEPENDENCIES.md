# Protocol dependency maintenance

Mira pins source versions, Git revisions and SHA256 hashes in
`scripts/protocol-dependencies.json`. The build recipes in
`scripts/_recipes/__init__.py` use the same records. CMake does not download
dependencies; `scripts/ci/build_protocol_deps.py` verifies and builds the archives.

Dependency resolution, source preparation and transactional prefix installation
use the shared [AriaDeps](https://github.com/dqsjqian/AriaDeps) package, pinned by
`requirements-build.txt`. Mira owns its protocol recipes and feature choices.
For any required third-party capability, first verify the latest upstream
release. If a reproducible defect remains, maintain a focused fork with a
failing-upstream regression, supported-platform CI, immutable releases and a
documented upstream synchronization path.

| Library | Pinned source | Purpose |
| --- | --- | --- |
| nghttp2 | [1.70.0-mira.1](https://github.com/dqsjqian/nghttp2/tree/mira) | HTTP/2 messaging and CONNECT tunnels |
| nghttp3 | [1.18.0-mira.1](https://github.com/dqsjqian/nghttp3/tree/mira) | HTTP/3 messaging and CONNECT tunnels |
| ngtcp2 | [1.22.1](https://github.com/ngtcp2/ngtcp2/releases/tag/v1.22.1) | QUIC transport and OpenSSL adapter |

## CONNECT 204

As checked on 2026-10-26, upstream nghttp2 v1.70.0 and nghttp3 v1.18.0,
including their default branches, classify a 204 response as bodyless before
applying CONNECT semantics. This rejects tunnel DATA after a successful
CONNECT 204. [RFC 9110 section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
requires every successful CONNECT 2xx response to switch to tunnel mode and
requires the recipient to ignore Content-Length in that response.

The maintenance forks apply that rule before ordinary bodyless-response handling.
Ordinary 204, HEAD and 304 retain their content restrictions; failed CONNECT
responses retain normal Content-Length checks. The public headers expose
`NGHTTP2_HAS_CONNECT_2XX_TUNNEL` and `NGHTTP3_HAS_CONNECT_2XX_TUNNEL` with value 1.
Mira enables 204 tunnels only with the corresponding capability. Builds against
upstream libraries without it return `not_supported` for CONNECT 204. Header and
library files must come from the same installation.

The numeric library version and ABI remain compatible with the upstream base.
Runtime version strings include `-mira.1` to identify the downstream build.
Mira preserves the actual response status on the wire and continues to reject
Content-Length on outgoing successful CONNECT responses.

## Updating and verifying

Each fork's `MIRA.md` describes its stable upstream base and maintenance branch.
Its source archive contains the committed source, exact recursive submodules,
license files and a `MIRA-SOURCE.json` provenance manifest. GitHub's generated
source archives omit submodule contents, so use the published `.tar.xz` asset.

Before changing a pin, run the fork's library regressions and archive CI, then
verify Mira's H2/H3 CONNECT matrix, normal HTTP traffic, runtime drivers and
independent aioquic interoperation. The CONNECT matrix includes 200, 201 and 204,
bidirectional WebSocket DATA, half-close, cancellation, backpressure and status
preservation. The independent peer check requires 204 support in CI.

Update the recipe and lock together, including the request fingerprint, revision
and archive hash. `scripts/ci/test_protocol_deps.py` checks their consistency.
Retain immutable published tags and archive hashes. When an upstream stable
release passes these regressions, review replacing the downstream patch.
