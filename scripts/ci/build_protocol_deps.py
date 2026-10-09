#!/usr/bin/env python3
"""Build pinned-version H2/H3 static dependencies via aria-deps.

Thin wrapper around the aria-deps package; Mira-specific recipes live in
tools/_recipes/. The CLI mirrors the original build_protocol_deps.py so
existing CI invocations keep working.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aria_deps import deps_build as deps
from aria_deps.deps_build import extract, run, sha256

from _recipes import make_config
from _recipes.protocol_support import install_compile_pdbs, install_dependency_licenses

REPO = Path(__file__).resolve().parents[2]


def positive_jobs(value: str) -> int:
    try:
        jobs = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError('jobs must be an integer between 1 and 256') from error
    if not 1 <= jobs <= 256:
        raise argparse.ArgumentTypeError("jobs must be between 1 and 256")
    return jobs


def output_path(value: Path) -> Path:
    path = deps.output_path(value)
    if path == REPO or path in REPO.parents:
        raise ValueError(f'Repository root or ancestor rejected as output directory: {path}')
    return path


@contextmanager
def cmake_environment(args):
    changes = {}
    if args.generator:
        changes['CMAKE_GENERATOR'] = args.generator
    if args.architecture:
        changes['CMAKE_GENERATOR_PLATFORM'] = args.architecture
    previous = {key: os.environ.get(key) for key in changes}
    try:
        os.environ.update(changes)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


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

    work = output_path(args.path)
    prefix = output_path(args.prefix or work / "prefix")
    lock = REPO / 'scripts/protocol-dependencies.json'
    source_dir = work / "sources"

    config = make_config()

    extra_cmake = []
    if args.openssl_root:
        openssl = args.openssl_root.expanduser().resolve()
        if ";" in str(openssl) or not (openssl / "include/openssl/ssl.h").is_file():
            parser.error("--openssl-root must contain include/openssl/ssl.h")
        extra_cmake.append(f"-DOPENSSL_ROOT_DIR={openssl.as_posix()}")

    toolchain = args.toolchain.expanduser().resolve() if args.toolchain else None
    if toolchain and (';' in str(toolchain) or not toolchain.is_file()):
        parser.error('--toolchain must name an existing file without a CMake list separator')
    with cmake_environment(args):
        deps.install(
            lock, work, prefix, source_dir,
            config=config, profile="mira", offline=args.offline,
            jobs=args.jobs, build_config=args.config,
            toolchain=str(toolchain) if toolchain else None,
            cmake_options=tuple(extra_cmake),
        )
    print(f"Done. Static libraries, headers and licenses are located in: {prefix}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'Error: {error}', file=sys.stderr)
        sys.exit(1)
