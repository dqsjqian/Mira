#!/usr/bin/env python3
"""Explicitly build pinned-version H2/H3 static dependencies; not invoked
automatically by the project's CMake.

Supports Linux/macOS, Python 3.9+, CMake, and the native C/C++ toolchain;
Windows is unverified, so running there is refused. An OpenSSL 3.5+ providing
SSL_set_quic_tls_cbs must also be preinstalled.
Only the sources of these three dependencies are pinned; byte-for-byte
identical outputs across different compilers/OpenSSL are not guaranteed.
By default all writes stay inside the repository's build/protocol-deps; the
system OpenSSL is neither installed nor modified.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


REPO = Path(__file__).resolve().parents[2]
# SHA256 of the official GitHub release assets, also verified byte-for-byte
# against local archives; all licenses are MIT.
# The COPYING at the root of each release archive is the license text.
DEPENDENCIES = (
    ("nghttp2", "1.70.0", "nghttp2/nghttp2",
     "e05cb1388eaca3830aded4ccf20044b6e1ac1a61411dcca11b0437c4285c8bc2"),
    ("nghttp3", "1.15.0", "ngtcp2/nghttp3",
     "6da0cd06b428d32a54c58137838505d9dc0371a900bb8070a46b29e1ceaf2e0f"),
    ("ngtcp2", "1.22.1", "ngtcp2/ngtcp2",
     "dfd2c68bd64b89847c611425b9487105c46e8447b5c21e6aeb00642c8fbe2ca8"),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(cache: Path, name: str, version: str, project: str,
             expected: str, offline: bool) -> Path:
    filename = f"{name}-{version}.tar.xz"
    archive = cache / filename
    if archive.exists():
        if not archive.is_file() or archive.is_symlink() or sha256(archive) != expected:
            raise ValueError(f"Cached archive failed SHA256 verification, file not overwritten: {archive}")
        print(f"Reusing verified cache: {filename}", flush=True)
        return archive
    if offline:
        raise ValueError(f"Offline cache missing: {archive}")
    url = f"https://github.com/{project}/releases/download/v{version}/{filename}"
    print(f"Downloading: {url}\nSHA256: {expected}", flush=True)
    # An interrupted download or failed verification only deletes this run's
    # temporary files; existing archives are never overwritten.
    with tempfile.TemporaryDirectory(prefix="download-", dir=cache) as temporary:
        candidate = Path(temporary) / filename
        request = urllib.request.Request(url, headers={"User-Agent": "Mira-protocol-deps"})
        with urllib.request.urlopen(request, timeout=60) as response, candidate.open("wb") as output:
            shutil.copyfileobj(response, output)
        if sha256(candidate) != expected:
            raise ValueError(f"Download failed SHA256 verification: {url}")
        candidate.replace(archive)
    return archive


def extract(archive: Path, destination: Path, root_name: str) -> Path:
    # destination is an empty directory exclusive to this run; all members are
    # validated first, then regular files are written.
    with tarfile.open(archive, "r:xz") as package:
        members = package.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                    or not path.parts or path.parts[0] != root_name
                    or not (member.isdir() or member.isfile())):
                raise ValueError(f"Unsafe archive member rejected: {member.name}")
            target = (destination / member.name).resolve()
            if destination.resolve() not in target.parents:
                raise ValueError(f"Path escaping the destination rejected: {member.name}")
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = package.extractfile(member)
            if source is None:
                raise ValueError(f"Cannot read archive member: {member.name}")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    return destination / root_name


def positive_jobs(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("--jobs must be an integer between 1 and 256") from error
    if not 1 <= number <= 256:
        raise argparse.ArgumentTypeError("--jobs must be an integer between 1 and 256")
    return number


def output_path(value: Path) -> Path:
    path = value.expanduser().resolve()
    if path in (Path.home(), REPO) or path in REPO.parents:
        raise ValueError(f"Home directory or repository root rejected as output directory: {path}")
    for system in ("/usr", "/bin", "/sbin", "/etc", "/System", "/Library", "/opt"):
        root = Path(system)
        if path == root or root in path.parents:
            raise ValueError(f"Install into a system directory rejected: {path}")
    if path.exists() and not path.is_dir():
        raise ValueError(f"Output path is not a directory: {path}")
    if ";" in str(path):
        raise ValueError("Output path must not contain the CMake list separator ';'")
    return path


def run(command: list[str]) -> None:
    print("+ " + shlex.join(command), flush=True)
    subprocess.run(command, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=REPO / "build/protocol-deps",
                        help="cache and temporary build root directory, defaults to the repository's build/protocol-deps")
    parser.add_argument("--prefix", type=Path,
                        help="install directory, defaults to <path>/prefix; must not point at a system directory")
    parser.add_argument("--openssl-root", type=Path,
                        help="root of an installed OpenSSL 3.5+; if omitted, CMake searches for it")
    parser.add_argument("--jobs", type=positive_jobs,
                        default=min(os.cpu_count() or 1, 8), help="number of parallel jobs, from 1 to 256")
    parser.add_argument("--offline", action="store_true",
                        help="forbid downloads, use only hash-verified archives in <path>/cache")
    args = parser.parse_args()
    if not (sys.platform.startswith("linux") or sys.platform == "darwin"):
        parser.error("Only Linux/macOS are supported; Windows is not yet verified")
    if shutil.which("cmake") is None:
        parser.error("Please install CMake and a C/C++ toolchain first")
    work = output_path(args.path)
    prefix = output_path(args.prefix or work / "prefix")
    openssl = args.openssl_root.expanduser().resolve() if args.openssl_root else None
    if openssl and (";" in str(openssl) or not (openssl / "include/openssl/ssl.h").is_file()):
        parser.error("--openssl-root must contain include/openssl/ssl.h and the path must not contain ';'")
    cache = work / "cache"
    if prefix == cache or cache in prefix.parents or prefix in cache.parents:
        parser.error("--prefix must not overlap the archive cache directory")
    cache.mkdir(parents=True, exist_ok=True)
    archives = [(name, version, download(cache, name, version, project, digest, args.offline))
                for name, version, project, digest in DEPENDENCIES]
    common = [f"-DCMAKE_INSTALL_PREFIX={prefix}", "-DCMAKE_INSTALL_LIBDIR=lib",
              "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
              "-DENABLE_LIB_ONLY=ON", "-DBUILD_TESTING=OFF"]
    if openssl:
        common.append(f"-DOPENSSL_ROOT_DIR={openssl}")
    # Re-extract and rebuild from the pinned archives on every run, avoiding
    # reuse of modified sources or a stale CMakeCache.
    with tempfile.TemporaryDirectory(prefix="build-", dir=work) as temporary:
        staging = Path(temporary)
        for name, version, archive in archives:
            source = extract(archive, staging, f"{name}-{version}")
            build = staging / f"{name}-build"
            options = (["-DBUILD_SHARED_LIBS=OFF", "-DBUILD_STATIC_LIBS=ON",
                        "-DENABLE_DOC=OFF", "-DENABLE_FAILMALLOC=OFF"] if name == "nghttp2"
                       else ["-DENABLE_SHARED_LIB=OFF", "-DENABLE_STATIC_LIB=ON"])
            if name == "ngtcp2":
                options += ["-DENABLE_OPENSSL=ON", "-DENABLE_GNUTLS=OFF",
                            "-DENABLE_BORINGSSL=OFF", "-DENABLE_PICOTLS=OFF",
                            "-DENABLE_WOLFSSL=OFF"]
            run(["cmake", "-S", str(source), "-B", str(build), *common, *options])
            if name == "ngtcp2":
                configuration = (build / "CMakeCache.txt").read_text()
                if "HAVE_SSL_SET_QUIC_TLS_CBS:INTERNAL=1" not in configuration:
                    raise ValueError("the ngtcp2 ossl backend requires SSL_set_quic_tls_cbs from OpenSSL 3.5+")
            run(["cmake", "--build", str(build), "--parallel", str(args.jobs)])
            run(["cmake", "--install", str(build)])
            license_dir = prefix / "share/licenses" / name
            license_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / "COPYING", license_dir / "COPYING")
    for library in ("nghttp2", "nghttp3", "ngtcp2", "ngtcp2_crypto_ossl"):
        artifact = prefix / "lib" / f"lib{library}.a"
        if not artifact.is_file():
            raise ValueError(f"Expected static library not produced: {artifact}")
    print(f"Done. Static libraries, headers, and MIT licenses are located in: {prefix}", flush=True)
    print(f"Pass -DCMAKE_PREFIX_PATH={shlex.quote(str(prefix))} explicitly when configuring the project", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
