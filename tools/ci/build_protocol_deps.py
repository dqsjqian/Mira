#!/usr/bin/env python3
"""Explicitly build pinned-version H2/H3 static dependencies; not invoked
automatically by the project's CMake.

Supports Linux/macOS and Windows with Python 3.9+, CMake, and the native
C/C++ toolchain. An OpenSSL 3.5+ providing SSL_set_quic_tls_cbs must also
be preinstalled. On Windows, use the same --config and MSVC runtime as
Mira and OpenSSL (for example, vcpkg's x64-windows with Debug and /MDd).
Only the sources of these three dependencies are pinned; byte-for-byte
identical outputs across different compilers/OpenSSL are not guaranteed.
By default all writes stay inside the repository's build/protocol-deps; the
system OpenSSL is neither installed nor modified.

Fresh CMake builds inherit CC/CXX, CFLAGS/CXXFLAGS and LDFLAGS. Sanitizer or
libFuzzer users must use the same compiler/runtime as their consumer and a
separate --path (and therefore prefix), so instrumented archives never replace
the ordinary SDK. Include matching sanitizer flags in LDFLAGS for CMake probes.
"""

from __future__ import annotations

import argparse
import hashlib
import ntpath
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


REPO = Path(__file__).resolve().parents[2]
# ntpath.isreserved replaces PurePath.is_reserved in Python 3.13+.
windows_reserved = getattr(ntpath, "isreserved", lambda name: PureWindowsPath(name).is_reserved())
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
    if archive.exists() or archive.is_symlink():
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
    # validated first, then regular files are written. Reject Windows device
    # paths, alternate data streams and name aliases even when extracting on POSIX.
    with tarfile.open(archive, "r:xz") as package:
        members = package.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                    or not path.parts or path.parts[0] != root_name
                    or any(":" in part or part.endswith((".", " "))
                           or windows_reserved(part) for part in path.parts)
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
    if path in (Path.home(), REPO, Path(path.anchor)) or path in REPO.parents:
        raise ValueError(f"Home directory, drive root or repository root rejected as output directory: {path}")
    systems = ["/usr", "/bin", "/sbin", "/etc", "/System", "/Library", "/opt"]
    if os.name == "nt":
        systems.extend(os.environ[key] for key in
                       ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData")
                       if os.environ.get(key))
    for system in systems:
        root = Path(system).resolve()
        if path == root or root in path.parents:
            raise ValueError(f"Install into a system directory rejected: {path}")
    if path.exists() and not path.is_dir():
        raise ValueError(f"Output path is not a directory: {path}")
    if ";" in str(path):
        raise ValueError("Output path must not contain the CMake list separator ';'")
    return path


def run(command: list[str]) -> None:
    display = subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command)
    print("+ " + display, flush=True)
    subprocess.run(command, check=True)


def install_compile_pdbs(build: Path, prefix: Path) -> None:
    # The pinned projects give each MSVC compiler PDB the static target's name,
    # but their install rules only copy the archive. Preserve those PDBs beside
    # the installed .lib before the temporary build tree is removed, so LINK
    # retains dependency debug information instead of reporting LNK4099.
    # Release and MinGW archives do not necessarily have compiler PDBs.
    library_dir = prefix / "lib"
    copies = []
    for archive in sorted(library_dir.glob("*_static.lib")):
        filename = archive.with_suffix(".pdb").name
        matches = sorted(build.rglob(filename))
        if len(matches) > 1:
            raise ValueError(f"Ambiguous compiler PDB for {archive.name}: {matches}")
        if matches:
            copies.append((matches[0], library_dir / filename))
    for source, destination in copies:
        shutil.copyfile(source, destination)
        print(f"Installed compiler debug symbols: {destination}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=REPO / "build/protocol-deps",
                        help="cache and temporary build root directory, defaults to the repository's build/protocol-deps")
    parser.add_argument("--prefix", type=Path,
                        help="install directory, defaults to <path>/prefix; must not point at a system directory")
    parser.add_argument("--openssl-root", type=Path,
                        help="root of an installed OpenSSL 3.5+; if omitted, CMake searches for it")
    parser.add_argument("--generator", "-G", help="CMake generator, for example Ninja or Visual Studio 17 2022")
    parser.add_argument("--architecture", "-A", help="CMake generator platform, for example x64 with Visual Studio")
    parser.add_argument("--config", choices=("Debug", "Release", "RelWithDebInfo", "MinSizeRel"),
                        default="Release", help="build/install configuration; must match the consuming MSVC build")
    parser.add_argument("--toolchain", type=Path,
                        help="CMake toolchain file, for example vcpkg's scripts/buildsystems/vcpkg.cmake")
    parser.add_argument("--jobs", type=positive_jobs,
                        default=min(os.cpu_count() or 1, 8), help="number of parallel jobs, from 1 to 256")
    parser.add_argument("--offline", action="store_true",
                        help="forbid downloads, use only hash-verified archives in <path>/cache")
    args = parser.parse_args()
    if not (sys.platform.startswith("linux") or sys.platform in ("darwin", "win32")):
        parser.error("Only Linux/macOS/Windows are supported")
    if shutil.which("cmake") is None:
        parser.error("Please install CMake and a C/C++ toolchain first")
    work = output_path(args.path)
    prefix = output_path(args.prefix or work / "prefix")
    openssl = args.openssl_root.expanduser().resolve() if args.openssl_root else None
    if openssl and (";" in str(openssl) or not (openssl / "include/openssl/ssl.h").is_file()):
        parser.error("--openssl-root must contain include/openssl/ssl.h and the path must not contain ';'")
    toolchain = args.toolchain.expanduser().resolve() if args.toolchain else None
    if toolchain and (";" in str(toolchain) or not toolchain.is_file()):
        parser.error("--toolchain must name an existing file and the path must not contain ';'")
    generator = []
    if args.generator:
        generator += ["-G", args.generator]
    if args.architecture:
        generator += ["-A", args.architecture]
    cache = work / "cache"
    if prefix == cache or cache in prefix.parents or prefix in cache.parents:
        parser.error("--prefix must not overlap the archive cache directory")
    cache.mkdir(parents=True, exist_ok=True)
    archives = [(name, version, download(cache, name, version, project, digest, args.offline))
                for name, version, project, digest in DEPENDENCIES]
    common = [f"-DCMAKE_INSTALL_PREFIX={prefix}", "-DCMAKE_INSTALL_LIBDIR=lib",
              f"-DCMAKE_BUILD_TYPE={args.config}", f"-DCMAKE_TRY_COMPILE_CONFIGURATION={args.config}",
              "-DCMAKE_POSITION_INDEPENDENT_CODE=ON", "-DENABLE_LIB_ONLY=ON", "-DBUILD_TESTING=OFF"]
    if toolchain:
        common.append(f"-DCMAKE_TOOLCHAIN_FILE={toolchain.as_posix()}")
    if sys.platform == "win32":
        # Unlike .a, .lib alone cannot distinguish a static archive from a DLL
        # import library. The upstream suffix is shared by all three projects.
        common.append("-DSTATIC_LIB_SUFFIX=_static")
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
            # nghttp3 is the framing library and does not search for TLS.
            if openssl and name != "nghttp3":
                options.append(f"-DOPENSSL_ROOT_DIR={openssl}")
            if name == "ngtcp2":
                options += ["-DENABLE_OPENSSL=ON", "-DENABLE_GNUTLS=OFF",
                            "-DENABLE_BORINGSSL=OFF", "-DENABLE_PICOTLS=OFF",
                            "-DENABLE_WOLFSSL=OFF"]
            run(["cmake", "-S", str(source), "-B", str(build), *generator, *common, *options])
            if name == "ngtcp2":
                configuration = (build / "CMakeCache.txt").read_text(encoding="utf-8")
                if "HAVE_SSL_SET_QUIC_TLS_CBS:INTERNAL=1" not in configuration:
                    raise ValueError("the ngtcp2 ossl backend requires SSL_set_quic_tls_cbs from OpenSSL 3.5+")
            run(["cmake", "--build", str(build), "--config", args.config, "--parallel", str(args.jobs)])
            run(["cmake", "--install", str(build), "--config", args.config])
            if sys.platform == "win32":
                install_compile_pdbs(build, prefix)
            license_dir = prefix / "share/licenses" / name
            license_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / "COPYING", license_dir / "COPYING")
    for library in ("nghttp2", "nghttp3", "ngtcp2", "ngtcp2_crypto_ossl"):
        filenames = ((f"{library}_static.lib", f"lib{library}_static.a")
                     if sys.platform == "win32" else (f"lib{library}.a",))
        if not any((prefix / "lib" / filename).is_file() for filename in filenames):
            raise ValueError(f"Expected static library not produced in {prefix / 'lib'}: {filenames}")
    print(f"Done. Static libraries, headers, and MIT licenses are located in: {prefix}", flush=True)
    prefix_argument = f"-DCMAKE_PREFIX_PATH={prefix}"
    quoted_prefix = (subprocess.list2cmdline([prefix_argument]) if os.name == "nt"
                     else shlex.quote(prefix_argument))
    print(f"Pass {quoted_prefix} explicitly when configuring the project", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
