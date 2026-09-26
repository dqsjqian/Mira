#!/usr/bin/env bash
# tools/bench/run.sh — the blessed way to run Mira's benchmarks.
#
# In-process benches measure the library's own machinery; the numbers are
# relative (compare two commits), not absolute (not Mira vs wrk). This
# script pins the invocation so numbers quoted in issues/PRs are
# reproducible: same build type, same flags, same loop counts.
#
# Usage:
#   tools/bench/run.sh                 # run both scenarios
#   tools/bench/run.sh h1              # only the HTTP/1.1 keep-alive bench
#   tools/bench/run.sh h2 [concurr]    # only the HTTP/2 roundtrip bench

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build="${MIRA_BENCH_BUILD:-/tmp/mira-bench-build}"

echo "==> configuring (Release, bench on) in ${build}"
cmake -S "${repo}" -B "${build}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DMIRA_BUILD_BENCH=ON \
    -DMIRA_BUILD_TESTS=OFF \
    -DMIRA_ENABLE_HTTP2=ON \
    -DMIRA_ENABLE_HTTP3=ON \
    -DMIRA_ENABLE_TLS=ON

echo "==> building"
cmake --build "${build}" -j"$(nproc)"

which="${1:-all}"

if [[ "${which}" == "all" || "${which}" == "h1" ]]; then
    echo "==> bench_h1_keepalive (200k requests, keep-alive)"
    "${build}/bench/bench_h1_keepalive" 200000
fi
if [[ "${which}" == "all" || "${which}" == "h2" ]]; then
    echo "==> bench_h2_roundtrip (50k streams, 16 in flight)"
    "${build}/bench/bench_h2_roundtrip" 50000 "${2:-16}"
fi

echo "==> done. Same counts, same build type, or the comparison is void."
