# Protocol dependency maintenance

Mira pins source versions, Git revisions and SHA256 hashes in
`scripts/protocol-dependencies.json`. Library builders and patches come from
[ForgeRecipes](https://github.com/dqsjqian/ForgeRecipes). Mira keeps only module
selection in `scripts/ci/protocol_config.py`.

[ForgeDeps](https://github.com/dqsjqian/ForgeDeps) owns source workspaces, target
identities and one current installed artifact per library/target. CMake prepares
only enabled dependencies with its actual compiler, configuration and ABI flags.
The build directory contains `forgedeps-environment.json`, not a merged third-party
prefix. OpenSSL is part of the locked dependency graph; an arbitrary
`OPENSSL_ROOT_DIR` cannot replace that library. A host OpenSSL executable may
still be used as an independent certificate-generation or interoperability tool.

Install `requirements-build.txt`, initialize a shared workspace once, and use:

```sh
python -m forgedeps init /path/to/shared-workspace
python scripts/build.py --tls --websocket --http2 --http3
```

The build runner holds artifact leases across configuration, compilation and
tests. Raw CI commands use `scripts/ci/dependency_session.py`; it discovers
receipts from build directories and reruns configuration while holding the
selected generations. `--offline` requires already verified source inputs.

The independent HTTP/3 curl is also a shared artifact, built with the exact
protocol artifact references from the consumer's environment:

```sh
python scripts/ci/build_interop_curl.py --environment build/protocols/forgedeps-environment.json
```

Its executable path is recorded in `build/interop-curl/binary.txt`; its own
`environment.json` retains all transitive generations for leased test commands.

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
