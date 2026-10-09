#!/usr/bin/env python3
"""Unified build pipeline for Mira (Windows/macOS/Linux).

Complete pipeline: deps -> build -> test -> bench -> package.
Powered by aria_deps.build_kit (pip install aria-deps).

Usage:
    python scripts/build.py                 # Full pipeline: deps + build + test
    python scripts/build.py deps            # Only build protocol dependencies
    python scripts/build.py build           # Only configure + compile
    python scripts/build.py test            # Only run tests
    python scripts/build.py bench           # Only run benchmarks
    python scripts/build.py package         # Only create release package
    python scripts/build.py all             # Everything
    python scripts/build.py clean           # Remove all build output

Project-specific:
    --tls           Enable OpenSSL 3 TLS module
    --websocket     Enable WebSocket module
    --http2         Enable nghttp2 HTTP/2 module (builds nghttp2 in deps)
    --http3         Enable QUIC/HTTP-3 modules (builds nghttp3/ngtcp2 in deps)
    --bench         Build in-process benchmarks
    --no-examples   Skip building examples

Environment:
    JOBS            Parallel build jobs (default: CPU count)
    CC / CXX        C/C++ compiler selection
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from aria_deps.build_kit import Pipeline, is_gcc
except ImportError:
    print("Error: aria-deps is required. Install it with:", file=sys.stderr)
    print("    pip install aria-deps", file=sys.stderr)
    print("Or from source: pip install git+https://github.com/dqsjqian/AriaDeps.git",
          file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]


def extra_args(parser: argparse.ArgumentParser):
    parser.add_argument("--tls", action="store_true", help="Enable TLS module")
    parser.add_argument("--websocket", action="store_true", help="Enable WebSocket module")
    parser.add_argument("--http2", action="store_true", help="Enable HTTP/2 module")
    parser.add_argument("--http3", action="store_true", help="Enable QUIC/HTTP-3 modules")
    parser.add_argument("--bench", action="store_true", help="Build benchmarks")
    parser.add_argument("--no-examples", action="store_true", help="Skip examples")
    parser.add_argument("--warnings-as-errors", action=argparse.BooleanOptionalAction,
                        default=True)


def protocol_deps(args) -> list[str] | None:
    """Build nghttp2/nghttp3/ngtcp2 from source (only what's needed)."""
    if not (args.http2 or args.http3):
        return None
    script = ROOT / "tools" / "ci" / "build_protocol_deps.py"
    if not script.is_file():
        print(f"[build] Warning: {script} not found", file=sys.stderr)
        return None
    cmd = [sys.executable, str(script)]
    if args.http2 and not args.http3:
        cmd += ["--only", "nghttp2"]
    elif args.http3 and not args.http2:
        cmd += ["--only", "nghttp3,ngtcp2"]
    return cmd


def cmake_flags(args) -> dict:
    # GCC: disable warnings-as-errors (array-bounds false positives)
    wae = args.warnings_as_errors and not is_gcc()
    if is_gcc() and args.warnings_as_errors:
        print("[build] GCC detected: disabling warnings-as-errors")
    return {
        "MIRA_BUILD_TESTS": "OFF" if args.no_test else "ON",
        "MIRA_BUILD_EXAMPLES": "OFF" if args.no_examples else "ON",
        "MIRA_WARNINGS_AS_ERRORS": "ON" if wae else "OFF",
        "MIRA_ENABLE_TLS": "ON" if args.tls else "OFF",
        "MIRA_ENABLE_WEBSOCKET": "ON" if args.websocket else "OFF",
        "MIRA_ENABLE_HTTP2": "ON" if args.http2 else "OFF",
        "MIRA_ENABLE_HTTP3": "ON" if args.http3 else "OFF",
        "MIRA_BUILD_BENCH": "ON" if args.bench else "OFF",
    }


def main(argv=None) -> int:
    include = ROOT / "include"
    modules = ROOT / "modules"
    headers = [include] if include.is_dir() else []
    if modules.is_dir():
        headers += [m / "include" for m in modules.iterdir()
                    if (m / "include").is_dir()]

    pipeline = Pipeline(
        name="mira",
        root=ROOT,
        deps=[("protocols", protocol_deps)],
        cmake_flags=cmake_flags,
        package_include=tuple(headers),
        extra_args=extra_args,
    )
    return pipeline.run(argv)


if __name__ == "__main__":
    sys.exit(main())
