#!/usr/bin/env python3
"""Unified one-shot build runner for Mira (Windows/macOS/Linux).

Usage:
    python scripts/build.py                 # Release build + tests
    python scripts/build.py debug           # Debug build + tests
    python scripts/build.py --no-test       # Build only, skip tests
    python scripts/build.py clean           # Remove all build output

Parameters:
    mode            Build mode (positional, default: release):
                    - release: Release build, output to build/release
                    - debug:   Debug build, output to build/debug
                    - clean:   Delete build/, build-gcc/, build-clang/
    --jobs N        Parallel build jobs (default: JOBS env or CPU count)
    --build-dir PATH
                    Override the build directory (default: build/<mode>).
                    Useful for side-by-side compiler builds, e.g.
                    --build-dir build/gcc and --build-dir build/clang.
    --no-test       Skip running ctest after building.
    --no-examples   Skip building examples (default: examples are built).
    --tls           Enable OpenSSL 3 TLS stream module
                    (MIRA_ENABLE_TLS=ON; requires OpenSSL 3).
    --websocket     Enable WebSocket module
                    (MIRA_ENABLE_WEBSOCKET=ON; needs OpenSSL Crypto + zlib).
    --http2         Enable nghttp2 HTTP/2 module (MIRA_ENABLE_HTTP2=ON).
    --http3         Enable QUIC/HTTP-3 modules, experimental
                    (MIRA_ENABLE_HTTP3=ON).
    --bench         Build in-process benchmarks (MIRA_BUILD_BENCH=ON).
    --warnings-as-errors / --no-warnings-as-errors
                    Treat compiler warnings as errors (default: on).
                    Auto-disabled when a GCC compiler is detected
                    (GCC 16 array-bounds false positives).
    --generator GEN CMake generator (default: Ninja if available).
    --cmake-arg -DNAME=VALUE
                    Extra CMake definition, repeatable. Example:
                    --cmake-arg -DMIRA_ENABLE_TLS=ON

Environment:
    JOBS            Parallel build jobs (default: CPU count)
    CC / CXX        C/C++ compiler selection (passed through to CMake)

Notes:
    - UDP-based tests fail in sandboxed environments (Operation not
      permitted); TCP functionality is unaffected. This is expected
      and not a build failure.
    - Feature modules (TLS/WebSocket/HTTP2/HTTP3) need their third-party
      dependencies available; see README.md and scripts/ci/dependencies.
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd, **kwargs):
    print(f"[build] {' '.join(str(c) for c in cmd)}", flush=True)
    subprocess.run(cmd, check=True, **kwargs)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("release", "debug", "clean"),
        default="release",
        help="Build mode (default: release)",
    )
    parser.add_argument("--jobs", type=int, default=int(os.environ.get("JOBS", os.cpu_count() or 4)))
    parser.add_argument("--build-dir", type=Path, help="Override build directory")
    parser.add_argument("--no-test", action="store_true", help="Skip running tests")
    parser.add_argument("--no-examples", action="store_true", help="Skip building examples")
    parser.add_argument("--tls", action="store_true", help="Enable OpenSSL 3 TLS module")
    parser.add_argument("--websocket", action="store_true", help="Enable WebSocket module")
    parser.add_argument("--http2", action="store_true", help="Enable nghttp2 HTTP/2 module")
    parser.add_argument("--http3", action="store_true", help="Enable QUIC/HTTP-3 modules (experimental)")
    parser.add_argument("--bench", action="store_true", help="Build in-process benchmarks")
    parser.add_argument("--warnings-as-errors", action=argparse.BooleanOptionalAction, default=True,
                        help="Treat compiler warnings as errors (default: on; auto-off for GCC)")
    parser.add_argument("--generator", help="CMake generator (default: Ninja if available)")
    parser.add_argument("--cmake-arg", action="append", default=[],
                        help="Extra -DNAME=VALUE passed to CMake")
    args = parser.parse_args(argv)

    if args.mode == "clean":
        build_root = ROOT / "build"
        print(f"[build] Removing {build_root}")
        shutil.rmtree(build_root, ignore_errors=True)
        # Also clean legacy per-config dirs
        for d in ("build-gcc", "build-clang"):
            shutil.rmtree(ROOT / d, ignore_errors=True)
        return 0

    build_type = "Debug" if args.mode == "debug" else "Release"
    # Unified directory scheme: build/unified/<platform>-<toolchain>-<config>-<arch>
    # Mira is native-only; toolchain defaults by host.
    host = platform.system()
    toolchain = "msvc" if host == "Windows" else "native"
    arch = platform.machine()
    suffix = f"native-{toolchain}-{build_type.lower()}-{arch}"
    build_dir = args.build_dir or (ROOT / "build" / "unified" / suffix)

    # Tool checks
    for tool in ("cmake", "git"):
        if not shutil.which(tool):
            print(f"[build] Error: {tool} is not installed or not on PATH", file=sys.stderr)
            return 1

    # GCC gets warnings-as-errors off (array-bounds false positives in GCC 16)
    cc = os.environ.get("CC", "")
    warnings_as_errors = args.warnings_as_errors
    if "gcc" in cc.lower() or (not cc and shutil.which("gcc")):
        # Auto-detect: if default compiler looks like GCC, turn off WAE
        # unless explicitly requested
        if args.warnings_as_errors:  # user didn't pass --no-warnings-as-errors
            # Check if CC is explicitly set to something non-gcc
            if not cc:
                warnings_as_errors = False
                print("[build] GCC detected: disabling -DWARNINGS_AS_ERRORS (array-bounds false positives)")

    # Configure
    configure_cmd = ["cmake", "-S", str(ROOT), "-B", str(build_dir)]
    generator = args.generator
    if generator:
        configure_cmd += ["-G", generator]
    elif shutil.which("ninja"):
        configure_cmd += ["-G", "Ninja"]

    configure_cmd += [
        f"-DCMAKE_BUILD_TYPE={build_type}",
        f"-DMIRA_BUILD_TESTS={'ON' if not args.no_test else 'OFF'}",
        f"-DMIRA_BUILD_EXAMPLES={'OFF' if args.no_examples else 'ON'}",
        f"-DMIRA_WARNINGS_AS_ERRORS={'ON' if warnings_as_errors else 'OFF'}",
        f"-DMIRA_ENABLE_TLS={'ON' if args.tls else 'OFF'}",
        f"-DMIRA_ENABLE_WEBSOCKET={'ON' if args.websocket else 'OFF'}",
        f"-DMIRA_ENABLE_HTTP2={'ON' if args.http2 else 'OFF'}",
        f"-DMIRA_ENABLE_HTTP3={'ON' if args.http3 else 'OFF'}",
        f"-DMIRA_BUILD_BENCH={'ON' if args.bench else 'OFF'}",
    ]
    for extra in args.cmake_arg:
        if not extra.startswith("-D"):
            print(f"[build] Error: --cmake-arg must start with -D: {extra}", file=sys.stderr)
            return 1
        configure_cmd.append(extra)

    print(f"[build] Configuring {build_type}")
    run(configure_cmd)

    # Build
    print(f"[build] Building with {args.jobs} jobs")
    run(["cmake", "--build", str(build_dir), "--parallel", str(args.jobs)])

    # Test
    if not args.no_test:
        print("[build] Running tests")
        result = subprocess.run(
            ["ctest", "--test-dir", str(build_dir), "--output-on-failure",
             "--parallel", str(args.jobs)],
        )
        if result.returncode != 0:
            print("[build] Some tests failed (UDP tests fail in sandboxed environments)",
                  file=sys.stderr)
            return result.returncode

    print(f"[build] Complete: {build_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
