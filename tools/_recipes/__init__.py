"""Mira protocol dependency recipes for aria-deps.

Builds nghttp2, nghttp3 and ngtcp2 from pinned source archives.
The aria-deps package provides the mechanism; this module supplies
everything Mira-specific: the recipe table and OpenSSL version gate.
"""

from __future__ import annotations

from pathlib import Path

from aria_deps import Dependency, ProjectConfig


def _ngtcp2_openssl_check(prefix: Path, source: Path, dep: Dependency) -> None:
    # ngtcp2's OpenSSL backend requires SSL_set_quic_tls_cbs (OpenSSL 3.5+).
    # The original build_protocol_deps.py gated on this CMake cache entry.
    # (Hook runs after build; the cache file lives next to the build dir,
    # so we check the installed library instead.)
    pass


def ngtcp2_post_build(prefix: Path, source: Path, dep: Dependency) -> None:
    # Verify the OpenSSL backend was actually enabled: the original script
    # required HAVE_SSL_SET_QUIC_TLS_CBS in CMakeCache. We check for the
    # crypto backend library as a proxy.
    lib = prefix / "lib" / "libngtcp2_crypto_ossl.a"
    if not lib.is_file():
        # Windows uses _static suffix
        lib = prefix / "lib" / "ngtcp2_crypto_ossl_static.lib"
    if not lib.is_file():
        raise ValueError(
            "ngtcp2 OpenSSL crypto backend not built; "
            "requires OpenSSL 3.5+ with SSL_set_quic_tls_cbs"
        )


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
        post_build=ngtcp2_post_build,
    ),
)


def make_config() -> ProjectConfig:
    """Build the ProjectConfig for Mira protocol dependencies."""
    return ProjectConfig(
        name="mira-protocol-deps",
        recipes=RECIPES,
    )
