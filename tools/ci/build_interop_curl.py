#!/usr/bin/env python3
"""Build a hash-pinned HTTP/3 curl in the repository build tree for independent tests.

This is an explicit verification tool, never run by library configuration.
The existing protocol dependency prefix and OpenSSL 3.5+ are prerequisites.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import tempfile

from build_protocol_deps import extract, output_path, positive_jobs, run, sha256

VERSION = "8.16.0"
DIGEST = "40c8cddbcb6cc6251c03dea423a472a6cea4037be654ba5cf5dec6eb2d22ff1d"
REPO = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=REPO / "build/protocol-deps/prefix")
    parser.add_argument("--openssl-root", type=Path, required=True)
    parser.add_argument("--path", type=Path, default=REPO / "build/interop-curl")
    parser.add_argument("--jobs", type=positive_jobs, default=4)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    work = output_path(args.path)
    prefix = args.prefix.resolve()
    openssl = args.openssl_root.resolve()
    if not (openssl / "include/openssl/ssl.h").is_file():
        parser.error("--openssl-root must contain include/openssl/ssl.h")
    if not (prefix / "include/ngtcp2/ngtcp2_crypto_ossl.h").is_file():
        parser.error("--prefix must contain the built ngtcp2 ossl dependencies")
    cache = work / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    # curl uses underscore tags rather than the v<version> release convention.
    archive = cache / f"curl-{VERSION}.tar.xz"
    if archive.exists():
        if archive.is_symlink() or not archive.is_file() or sha256(archive) != DIGEST:
            raise ValueError("cached curl archive failed SHA256 verification")
    elif args.offline:
        raise ValueError(f"offline archive missing: {archive}")
    else:
        with tempfile.TemporaryDirectory(prefix="download-", dir=work) as temp:
            candidate = Path(temp) / archive.name
            url = f"https://github.com/curl/curl/releases/download/curl-8_16_0/{archive.name}"
            run(["curl", "-fL", "--retry", "2", "--connect-timeout", "30",
                 "--max-time", "180", url, "-o", str(candidate)])
            if sha256(candidate) != DIGEST:
                raise ValueError("downloaded curl archive failed SHA256 verification")
            candidate.replace(archive)
    with tempfile.TemporaryDirectory(prefix="source-", dir=work) as temp:
        source = extract(archive, Path(temp), f"curl-{VERSION}")
        build = Path(temp) / "build"
        install = work / "prefix"
        run(["cmake", "-S", str(source), "-B", str(build),
             "-DCMAKE_BUILD_TYPE=Release", f"-DCMAKE_PREFIX_PATH={prefix}",
             f"-DOPENSSL_ROOT_DIR={openssl}", f"-DCMAKE_INSTALL_PREFIX={install}",
             "-DCURL_USE_OPENSSL=ON", "-DUSE_NGTCP2=ON", "-DUSE_NGHTTP2=ON",
             "-DBUILD_SHARED_LIBS=OFF", "-DBUILD_STATIC_LIBS=ON", "-DBUILD_STATIC_CURL=ON",
             "-DBUILD_TESTING=OFF", "-DBUILD_LIBCURL_DOCS=OFF", "-DBUILD_MISC_DOCS=OFF",
             "-DCURL_USE_LIBPSL=OFF", "-DCURL_USE_LIBSSH2=OFF",
             "-DCURL_BROTLI=OFF", "-DCURL_ZSTD=OFF"])
        run(["cmake", "--build", str(build), "--parallel", str(args.jobs)])
        run(["cmake", "--install", str(build)])
    binary = install / "bin/curl"
    version = subprocess.check_output([str(binary), "--version"], text=True, timeout=10)
    print(version)
    if "HTTP3" not in version:
        raise RuntimeError("built curl lacks HTTP3 support")
    print(f"HTTP/3 interop client: {binary}")


if __name__ == "__main__":
    main()
