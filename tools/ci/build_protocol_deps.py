#!/usr/bin/env python3
"""Build pinned-version H2/H3 static dependencies via aria-deps.

Thin wrapper around the aria-deps package; Mira-specific recipes live in
tools/_recipes/. The CLI mirrors the original build_protocol_deps.py so
existing CI invocations keep working.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aria_deps import deps_build as deps

from _recipes import make_config

REPO = Path(__file__).resolve().parents[2]


def positive_jobs(value: str) -> int:
    jobs = int(value)
    if not 1 <= jobs <= 256:
        raise argparse.ArgumentTypeError("jobs must be between 1 and 256")
    return jobs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=REPO / "build/protocol-deps",
                        help="cache and temporary build root directory")
    parser.add_argument("--prefix", type=Path,
                        help="install directory, defaults to <path>/prefix")
    parser.add_argument("--openssl-root", type=Path,
                        help="root of an installed OpenSSL 3.5+; if omitted, CMake searches for it")
    parser.add_argument("--generator", "-G", help="CMake generator, for example Ninja")
    parser.add_argument("--architecture", "-A", help="CMake generator platform, for example x64")
    parser.add_argument("--config", choices=("Debug", "Release", "RelWithDebInfo", "MinSizeRel"),
                        default="Release", help="build/install configuration")
    parser.add_argument("--toolchain", type=Path, help="CMake toolchain file")
    parser.add_argument("--jobs", type=positive_jobs,
                        default=min(os.cpu_count() or 1, 8), help="parallel jobs, 1-256")
    parser.add_argument("--offline", action="store_true",
                        help="forbid downloads, use only hash-verified archives in <path>/cache")
    args = parser.parse_args()

    if not (sys.platform.startswith("linux") or sys.platform in ("darwin", "win32")):
        parser.error("Only Linux/macOS/Windows are supported")

    work = args.path.expanduser().resolve()
    prefix = (args.prefix.expanduser().resolve() if args.prefix
              else work / "prefix")
    # aria-deps expects a lock file; the recipes carry pinned versions,
    # so we use a stable lock path under the work dir.
    lock = work / "dependencies.json"
    source_dir = work / "sources"

    config = make_config()

    # Pass through CMake-relevant options via environment/args.
    # aria-deps handles generator/toolchain via its own CLI; here we map
    # the original flags to deps.install kwargs.
    extra_cmake = []
    if args.openssl_root:
        openssl = args.openssl_root.expanduser().resolve()
        if ";" in str(openssl) or not (openssl / "include/openssl/ssl.h").is_file():
            parser.error("--openssl-root must contain include/openssl/ssl.h")
        extra_cmake.append(f"-DOPENSSL_ROOT_DIR={openssl.as_posix()}")

    if args.generator:
        os.environ["CMAKE_GENERATOR"] = args.generator

    deps.install(
        lock, work, prefix, source_dir,
        config=config,
        profile="mira",
        offline=args.offline,
        jobs=args.jobs,
        build_config=args.config,
    )
    print(f"Done. Static libraries and headers are located in: {prefix}", flush=True)


if __name__ == "__main__":
    main()
