"""Mira protocol dependency recipes for aria-deps.

Builds nghttp2, nghttp3 and ngtcp2 from pinned source archives.
The aria-deps package provides the mechanism; this module supplies
everything Mira-specific: the recipe table and OpenSSL version gate.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys

from aria_deps import Dependency, ProjectConfig
from .protocol_support import install_compile_pdbs, install_dependency_licenses


def protocol_post_build(prefix: Path, source: Path, dep: Dependency) -> None:
    build = source.parent / 'build'
    if dep.name == 'ngtcp2':
        cache = (build / 'CMakeCache.txt').read_text(encoding='utf-8')
        if 'HAVE_SSL_SET_QUIC_TLS_CBS:INTERNAL=1' not in cache:
            raise ValueError('ngtcp2 requires OpenSSL 3.5+ with SSL_set_quic_tls_cbs')
    if sys.platform == 'win32':
        install_compile_pdbs(build, prefix)


def protocol_licenses(prefix: Path, source: Path, dep: Dependency) -> list[str]:
    install_dependency_licenses(source, prefix, dep.name)
    license_dir = prefix / 'share/licenses' / dep.name
    return sorted(path.relative_to(license_dir).as_posix() for path in license_dir.rglob('*')
                  if path.is_file() and path.name not in dep.license_files)


RECIPES: tuple[Dependency, ...] = (
    Dependency(
        name="nghttp2", version="1.70.0",
        url="https://github.com/nghttp2/nghttp2/releases/download/v1.70.0/nghttp2-1.70.0.tar.xz",
        sha256="e05cb1388eaca3830aded4ccf20044b6e1ac1a61411dcca11b0437c4285c8bc2",
        license="MIT", license_files=("COPYING",), root="", kind="cmake",
        options=(
            "-DBUILD_SHARED_LIBS=OFF", "-DBUILD_STATIC_LIBS=ON",
            "-DENABLE_DOC=OFF", "-DENABLE_FAILMALLOC=OFF",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
        ),
        artifacts=("lib/libnghttp2.a", "include/nghttp2/nghttp2.h"),
    ),
    Dependency(
        name="nghttp3", version="1.15.0",
        url="https://github.com/ngtcp2/nghttp3/releases/download/v1.15.0/nghttp3-1.15.0.tar.xz",
        sha256="6da0cd06b428d32a54c58137838505d9dc0371a900bb8070a46b29e1ceaf2e0f",
        license="MIT", license_files=("COPYING",), root="", kind="cmake",
        options=(
            "-DENABLE_SHARED_LIB=OFF", "-DENABLE_STATIC_LIB=ON",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
        ),
        artifacts=("lib/libnghttp3.a", "include/nghttp3/nghttp3.h"),
    ),
    Dependency(
        name="ngtcp2", version="1.22.1",
        url="https://github.com/ngtcp2/ngtcp2/releases/download/v1.22.1/ngtcp2-1.22.1.tar.xz",
        sha256="dfd2c68bd64b89847c611425b9487105c46e8447b5c21e6aeb00642c8fbe2ca8",
        license="MIT", license_files=("COPYING",), root="", kind="cmake",
        options=(
            "-DENABLE_SHARED_LIB=OFF", "-DENABLE_STATIC_LIB=ON",
            "-DENABLE_OPENSSL=ON", "-DENABLE_GNUTLS=OFF",
            "-DENABLE_BORINGSSL=OFF", "-DENABLE_PICOTLS=OFF",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
        ),
        artifacts=(
            "lib/libngtcp2.a",
            "lib/libngtcp2_crypto_ossl.a",
            "include/ngtcp2/ngtcp2.h",
        ),
    ),
)


def make_config() -> ProjectConfig:
    """Build the ProjectConfig for Mira protocol dependencies."""
    windows = sys.platform == 'win32'
    recipes = []
    for dep in RECIPES:
        options = (*dep.options, '-DENABLE_LIB_ONLY=ON', '-DBUILD_TESTING=OFF')
        if dep.name == 'ngtcp2':
            options += ('-DENABLE_WOLFSSL=OFF',)
        artifacts = dep.artifacts
        if windows:
            options += ('-DSTATIC_LIB_SUFFIX=_static',)
            artifacts = tuple(path.replace('.a', '_static.a') if path.endswith('.a') else path
                              for path in artifacts)
        recipes.append(replace(dep, options=options, artifacts=artifacts,
                               uses_libdir=True, post_build=protocol_post_build,
                               post_install=protocol_licenses))
    return ProjectConfig(
        name="mira-protocol-deps",
        recipes=tuple(recipes),
    )
