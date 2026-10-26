#!/usr/bin/env python3
"""Build Mira's locked protocol dependencies into shared ForgeDeps artifact slots.

Only the environment receipt belongs to this build tree. Every library has its
own canonical prefix in the registered shared workspace, including OpenSSL.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys

from forgedeps import deps_build as deps
from forgedeps.deps_build import extract, run, sha256
from forgedeps.environments import build_environment, write_environment
from protocol_config import make_config
from forgerecipes.protocol_support import install_compile_pdbs, install_dependency_licenses

REPO = Path(__file__).resolve().parents[2]
PROTOCOLS = 'nghttp2,nghttp3,ngtcp2'


def positive_jobs(value):
    try:
        jobs = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError('jobs must be an integer between 1 and 256') from error
    if not 1 <= jobs <= 256:
        raise argparse.ArgumentTypeError('jobs must be between 1 and 256')
    return jobs


def output_path(value):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', type=Path, default=REPO / 'build/protocol-deps',
                        help='directory for the consumer environment receipt')
    parser.add_argument('--environment', type=Path, help='receipt path (default: <path>/environment.json)')
    parser.add_argument('--home', type=Path, help='explicit shared ForgeDeps workspace')
    parser.add_argument('--prefix', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--openssl-root', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--generator', '-G')
    parser.add_argument('--architecture', '-A')
    parser.add_argument('--config', choices=('Debug', 'Release', 'RelWithDebInfo', 'MinSizeRel'), default='Release')
    parser.add_argument('--toolchain', type=Path)
    parser.add_argument('--jobs', type=positive_jobs, default=min(os.cpu_count() or 1, 8))
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--only', default=PROTOCOLS, help='recipe names, including transitive dependencies')
    parser.add_argument('--run', nargs=argparse.REMAINDER, help='run a consumer command while holding the artifact leases')
    args = parser.parse_args()
    if args.prefix or args.openssl_root:
        parser.error('--prefix/--openssl-root are no longer accepted: use the shared locked OpenSSL recipe and --environment')
    toolchain = args.toolchain.expanduser().resolve() if args.toolchain else None
    if toolchain and (';' in str(toolchain) or not toolchain.is_file()):
        parser.error('--toolchain must name an existing file without a CMake list separator')
    work = output_path(args.path)
    receipt = output_path(args.environment or work / 'environment.json')
    with cmake_environment(args):
        result = build_environment(REPO / 'scripts/protocol-dependencies.json', config=make_config(),
            home=args.home, only=args.only, offline=args.offline, configuration=args.config,
            toolchain=toolchain, jobs=args.jobs)
    with result.lease():
        write_environment(receipt, result)
        if args.run:
            command = args.run[1:] if args.run[0] == '--' else args.run
            subprocess.run(command, check=True,
                env=dict(os.environ, FORGEDEPS_ENVIRONMENT=str(receipt)))
    print(f'Dependency environment: {receipt}', flush=True)
    for artifact in result.artifacts:
        print(f'{artifact.name}: {artifact.prefix}', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'Error: {error}', file=sys.stderr)
        sys.exit(1)
