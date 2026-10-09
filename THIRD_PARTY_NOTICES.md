# Third-party licenses and redistribution

Mira's own code is licensed under [MIT](LICENSE). Its dependencies retain their
own licenses. The selected dependencies below do not require Mira's own code
to change license; this conclusion depends on preserving their terms when
redistributing their source or binaries. Mira's MIT notice does not replace
upstream notices.

This inventory was reviewed on 2026-09-30 against the CMake module dependencies
and the pinned source archives in [build_protocol_deps.py](https://github.com/dqsjqian/Mira/blob/main/scripts/ci/build_protocol_deps.py).
It is a licensing inventory, not a substitute for the license texts shipped
with the actual packages used in a downstream product.

## Runtime libraries

| Component | Used by | Reviewed license and source |
|---|---|---|
| OpenSSL 3 (`libssl`, `libcrypto`) | TLS, cryptographic WebSocket primitives, QUIC ossl adapter | [Apache-2.0](https://openssl-library.org/source/license/); the source-built CI baseline uses [OpenSSL 3.5.9](https://github.com/openssl/openssl/blob/openssl-3.5.9/LICENSE.txt) |
| zlib | WebSocket permessage-deflate | [Zlib](https://zlib.net/zlib_license.html); version comes from the selected system or package-manager installation |
| nghttp2 | HTTP/2 and HPACK | [MIT, pinned source 1.70.0](https://github.com/nghttp2/nghttp2/blob/v1.70.0/COPYING) |
| ngtcp2 and its ossl adapter | QUIC transport and OpenSSL integration | [MIT, pinned source 1.22.1](https://github.com/ngtcp2/ngtcp2/blob/v1.22.1/COPYING), plus embedded notices below |
| nghttp3 | HTTP/3 and QPACK | [MIT, pinned source 1.15.0](https://github.com/ngtcp2/nghttp3/blob/v1.15.0/COPYING), plus embedded notices below |

The base core, transport and HTTP/1 modules require no external protocol
library. Optional modules bring in the libraries listed above. OpenSSL's
pre-3.0 OpenSSL/SSLeay dual license does not describe the OpenSSL 3 dependency
selected by this project.

### Embedded code in the pinned protocol libraries

Top-level COPYING files alone do not identify every upstream contributor:

| Embedded component | Where it is used | License |
|---|---|---|
| sfparse structured-field parser | nghttp2 and nghttp3 library sources | MIT; nghttp3 carries [sfparse at its pinned submodule revision](https://github.com/ngtcp2/sfparse/blob/ff7f230e7df2844afef7dc49631cda03a30455f3/COPYING) |
| Bjoern Hoehrmann UTF-8 DFA | Both sfparse implementations | MIT notice embedded in the corresponding `sfparse.c` sources |
| PCG random generator | `ngtcp2_pcg.c` | Apache-2.0 OR MIT; Mira's dependency packaging uses the [MIT option](https://github.com/imneme/pcg-c/blob/83252d9c23df9c82ecb42210afed61a7b42402d7/LICENSE-MIT.txt) |
| Chromium/QUICHE window filter | `ngtcp2_window_filter.c` | [BSD-3-Clause at the referenced upstream revision](https://github.com/google/quiche/blob/5be974e29f7e71a196e726d6e2272676d33ab77d/LICENSE) |

The protocol dependency builder installs the original top-level and nested
license files and relevant source copyright notices under its prefix's
`share/licenses/`. It also supplies the PCG MIT and Chromium BSD license texts
referenced by the embedded code. Test-only upstream components, such as munit,
are outside these library builds.

## What distributors must retain

- **MIT components:** preserve the original copyright and permission notices
  with redistributed copies or substantial portions.
- **OpenSSL / Apache-2.0:** include the license; preserve applicable upstream
  copyright and attribution notices, any applicable NOTICE content, and mark
  modified upstream files. The license also has patent and trademark terms.
  Linking through the library interface does not require licensing Mira under
  Apache-2.0. See [sections 1, 3, 4 and 6](https://www.apache.org/licenses/LICENSE-2.0).
- **Zlib:** do not misrepresent authorship, mark modified source versions, and
  retain its notice in source distributions. Include the package's license
  information when assembling a binary distribution as well.
- **BSD-3-Clause code:** retain the copyright, conditions and disclaimer in
  source and binary distribution materials; do not imply upstream endorsement.

Mira's source archive contains Mira source and build scripts, not bundled
OpenSSL, zlib or ng-series implementations. CMake resolves external dependencies;
installing Mira does not copy standalone dependency libraries into the SDK.
However, a shared Mira library or an application can contain statically linked
dependency code. A distributor of such binaries must carry the applicable dependency
notices too. Static versus dynamic linking does not turn upstream code into
Mira-owned MIT code.

The protocol builder's license directory covers its pinned protocol builds.
If OpenSSL, zlib or another package comes from a system or vendor installation,
collect that package's actual license and notice files separately. Preserve
licenses for enabled transitive features and bundled compiler runtimes as well.
Do not treat this table as a complete binary-package bill of materials.

## Build and validation tools

These tools are used externally for development and are not linked into Mira
or included in its source release:

| Tool | Purpose | Upstream license |
|---|---|---|
| curl, including the pinned HTTP/3 client | Independent interoperability | [curl license](https://curl.se/docs/copyright.html), inspired by MIT/X but not identical |
| Autobahn Testsuite | WebSocket client/server conformance | [Apache-2.0](https://github.com/crossbario/autobahn-testsuite/blob/v25.10.1/LICENSE) |
| Eclipse Mosquitto | Independent MQTT broker tests | [EPL-2.0 OR BSD-3-Clause (EDL-1.0)](https://github.com/eclipse-mosquitto/mosquitto/blob/v2.1.2/LICENSE.txt) |
| LLVM/libFuzzer | Fuzzing and instrumentation | [Apache-2.0 with LLVM exceptions](https://llvm.org/docs/DeveloperPolicy.html#license) |

Running a separate test tool does not change Mira's license. Redistributing the
tools, their Docker images or their own dependencies requires their respective
notices and terms; those artifacts are not part of Mira's source archive.

Toolchains and operating-system libraries have separate distribution terms.
For example, [GNU libstdc++ uses GPLv3 with the GCC Runtime Library Exception](https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html),
which permits eligible compiled combinations with independent non-GPL modules.
Do not confuse that exception with a GPL-only networking dependency, or assume
Mira's MIT license grants redistribution rights to every compiler/runtime SDK.

## Updating dependencies

When changing a pinned version, TLS backend or binary-package composition,
review upstream top-level and embedded notices again. Preserve the original
texts; do not replace them with this summary or silently relicense third-party
code. Keep Mira's version source and release process in the
[release guide](https://github.com/dqsjqian/Mira/blob/main/docs/RELEASES.md).
