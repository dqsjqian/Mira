#!/usr/bin/env python3
"""Offline regression tests for pinned protocol archive handling."""

import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import build_protocol_deps as deps
import build_interop_curl as interop
from types import SimpleNamespace


class InteropConfigurationTests(unittest.TestCase):
    def test_configuration_and_dependency_paths(self):
        args = SimpleNamespace(config="Debug", generator="Visual Studio 17 2022",
                               architecture="x64", toolchain=Path("toolchain.cmake"))
        with mock.patch.object(Path, "is_file", return_value=True):
            flags = interop.configuration_arguments(args, Path("deps"), Path("ssl"), Path("out"), True)
        self.assertIn("-DCMAKE_BUILD_TYPE=Debug", flags)
        self.assertIn("-DCMAKE_TRY_COMPILE_CONFIGURATION=Debug", flags)
        self.assertIn("Visual Studio 17 2022", flags)
        self.assertIn("x64", flags)
        self.assertIn("-DCURL_USE_SCHANNEL=OFF", flags)
        self.assertIn("-DNGTCP2_CRYPTO_OSSL_LIBRARY=deps/lib/ngtcp2_crypto_ossl_static.lib", flags)
        self.assertIn("-DNGHTTP3_LIBRARY=deps/lib/nghttp3_static.lib", flags)
        self.assertTrue(any(item.startswith("-DCMAKE_TOOLCHAIN_FILE=") for item in flags))

    def test_mingw_archive_fallback_and_missing_library(self):
        with mock.patch.object(Path, "is_file", lambda path: path.name == "libngtcp2_static.a"):
            self.assertEqual(interop.static_dependency(Path("deps"), "ngtcp2", True),
                             Path("deps/lib/libngtcp2_static.a"))
        with mock.patch.object(Path, "is_file", return_value=False):
            with self.assertRaises(ValueError):
                interop.static_dependency(Path("deps"), "ngtcp2", True)

    def test_posix_keeps_native_dependency_discovery(self):
        args = SimpleNamespace(config="Release", generator=None, architecture=None, toolchain=None)
        flags = interop.configuration_arguments(args, Path("deps"), Path("ssl"), Path("out"), False)
        self.assertIn("-DCMAKE_BUILD_TYPE=Release", flags)
        self.assertFalse(any("STATICLIB" in item or "SCHANNEL" in item for item in flags))


class ProtocolLicenseTests(unittest.TestCase):
    def test_nested_terms_and_embedded_notices_survive_source_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix = root / "prefix"
            primary = b"Upstream root license\n"
            nested = b"Nested sfparse license\r\n"
            notice = b"Nested runtime attribution\n"
            header = "/* Copyright sfparse contributors; header terms. */"
            embedded = "/* Copyright UTF-8 decoder author; embedded terms. */"
            with tempfile.TemporaryDirectory(dir=root) as staging:
                source = Path(staging)
                (source / "COPYING").write_bytes(primary)
                component = source / "lib/sfparse"
                component.mkdir(parents=True)
                (component / "COPYING").write_bytes(nested)
                (component / "NOTICE.txt").write_bytes(notice)
                (component / "sfparse.c").write_text(
                    header + "\nint fixture;\n" + embedded + "\n", encoding="utf-8")
                unused = source / "tests/dependency"
                unused.mkdir(parents=True)
                (unused / "COPYING").write_text("test-only license", encoding="utf-8")
                (unused / "test.c").write_text("/* Copyright test-only author */", encoding="utf-8")
                deps.install_dependency_licenses(source, prefix, "nghttp3")
            self.assertFalse(source.exists())
            installed = prefix / "share/licenses/nghttp3"
            self.assertEqual((installed / "COPYING").read_bytes(), primary)
            self.assertEqual((installed / "lib/sfparse/COPYING").read_bytes(), nested)
            self.assertEqual((installed / "lib/sfparse/NOTICE.txt").read_bytes(), notice)
            text = (installed / "SOURCE-NOTICES.txt").read_text(encoding="utf-8")
            self.assertIn(header, text)
            self.assertIn(embedded, text)
            self.assertIn("lib/sfparse/sfparse.c", text)
            self.assertNotIn("test-only", text)
            self.assertFalse((installed / "tests").exists())

    def test_ossl_adapter_notices_and_referenced_terms_are_installed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "COPYING").write_text("ngtcp2 root license", encoding="utf-8")
            for relative, author in (
                ("lib/ngtcp2_pcg.c", "PCG Project contributors"),
                ("lib/ngtcp2_window_filter.c", "The Chromium Authors"),
                ("crypto/shared.c", "shared crypto"),
                ("crypto/shared.h", "shared declarations"),
                ("crypto/ossl/ossl.c", "ossl adapter"),
                ("crypto/includes/ngtcp2/ngtcp2_crypto_ossl.h", "ossl declarations"),
                ("crypto/gnutls/gnutls.c", "disabled adapter"),
            ):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"/* Copyright {author}; original notice. */\n", encoding="utf-8")
            prefix = root / "prefix"
            deps.install_dependency_licenses(source, prefix, "ngtcp2")
            installed = prefix / "share/licenses/ngtcp2"
            text = (installed / "SOURCE-NOTICES.txt").read_text(encoding="utf-8")
            for author in ("PCG Project contributors", "The Chromium Authors", "shared crypto",
                           "shared declarations", "ossl adapter", "ossl declarations"):
                self.assertIn(author, text)
            self.assertNotIn("disabled adapter", text)
            resources = Path(deps.__file__).resolve().parent / "licenses"
            for filename in ("quiche-LICENSE", "pcg-LICENSE-MIT.txt", "SOURCES.md"):
                self.assertEqual((installed / filename).read_bytes(), (resources / filename).read_bytes())


class ProtocolDebugSymbolsTests(unittest.TestCase):
    def test_symbols_survive_temporary_build_cleanup_beside_archives(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix = root / "prefix"
            library_dir = prefix / "lib"
            library_dir.mkdir(parents=True)
            names = ("nghttp2_static", "nghttp3_static", "ngtcp2_static",
                     "ngtcp2_crypto_ossl_static")
            with tempfile.TemporaryDirectory(dir=root) as staging:
                build = Path(staging)
                for name in names:
                    (library_dir / f"{name}.lib").write_bytes(b"installed archive")
                    symbols = build / name / "Debug" / f"{name}.pdb"
                    symbols.parent.mkdir(parents=True)
                    symbols.write_bytes((name + " compiler debug information").encode())
                (build / "unrelated.pdb").write_bytes(b"CMake compiler probe")
                deps.install_compile_pdbs(build, prefix)
            self.assertFalse(build.exists())
            for name in names:
                self.assertEqual((library_dir / f"{name}.pdb").read_bytes(),
                                 (name + " compiler debug information").encode())
            self.assertFalse((library_dir / "unrelated.pdb").exists())

    def test_no_pdb_required_for_release_or_mingw(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            build.mkdir()
            prefix = root / "prefix"
            library_dir = prefix / "lib"
            library_dir.mkdir(parents=True)
            (library_dir / "nghttp2_static.lib").write_bytes(b"release archive")
            (library_dir / "libnghttp3_static.a").write_bytes(b"MinGW archive")
            deps.install_compile_pdbs(build, prefix)
            self.assertEqual(len(list(library_dir.iterdir())), 2)

    def test_ambiguous_symbols_do_not_replace_installed_symbols(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix = root / "prefix"
            library_dir = prefix / "lib"
            library_dir.mkdir(parents=True)
            (library_dir / "nghttp2_static.lib").write_bytes(b"archive")
            installed = library_dir / "nghttp2_static.pdb"
            installed.write_bytes(b"previous symbols")
            build = root / "build"
            for config in ("Debug", "RelWithDebInfo"):
                directory = build / config
                directory.mkdir(parents=True)
                (directory / installed.name).write_bytes(config.encode())
            with self.assertRaisesRegex(ValueError, "Ambiguous compiler PDB"):
                deps.install_compile_pdbs(build, prefix)
            self.assertEqual(installed.read_bytes(), b"previous symbols")


class ProtocolArchiveTests(unittest.TestCase):
    def test_rejects_unsafe_members_before_writing(self):
        root = "ngtcp2-test"
        members = [
            ("absolute", "/escape", tarfile.REGTYPE, ""),
            ("parent", "../escape", tarfile.REGTYPE, ""),
            ("nested-parent", f"{root}/../escape", tarfile.REGTYPE, ""),
            ("wrong-root", "other/file", tarfile.REGTYPE, ""),
            ("windows-separator", f"{root}\\escape", tarfile.REGTYPE, ""),
            ("windows-drive", "C:/escape", tarfile.REGTYPE, ""),
            ("alternate-data-stream", f"{root}/file:stream", tarfile.REGTYPE, ""),
            ("device-con", f"{root}/CON", tarfile.REGTYPE, ""),
            ("device-extension", f"{root}/nul.txt", tarfile.REGTYPE, ""),
            ("device-port", f"{root}/LPT1.txt", tarfile.REGTYPE, ""),
            ("trailing-dot", f"{root}/file.", tarfile.REGTYPE, ""),
            ("trailing-space", f"{root}/file ", tarfile.REGTYPE, ""),
            ("symlink-parent", f"{root}/link", tarfile.SYMTYPE, "../escape"),
            ("hardlink-parent", f"{root}/link", tarfile.LNKTYPE, "../escape"),
            ("fifo", f"{root}/pipe", tarfile.FIFOTYPE, ""),
        ]
        for label, name, kind, link in members:
            with self.subTest(member=label), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                archive = work / "archive.tar.xz"
                destination = work / "extracted"
                destination.mkdir()
                with tarfile.open(archive, "w:xz") as package:
                    safe = tarfile.TarInfo(f"{root}/safe.txt")
                    safe.size = 4
                    package.addfile(safe, io.BytesIO(b"safe"))
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = link
                    package.addfile(member)
                with self.assertRaisesRegex(ValueError, "Unsafe archive member"):
                    deps.extract(archive, destination, root)
                self.assertEqual(list(destination.iterdir()), [])
                self.assertFalse((work / "escape").exists())

    def test_extracts_regular_files_and_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            archive = work / "archive.tar.xz"
            destination = work / "extracted"
            destination.mkdir()
            with tarfile.open(archive, "w:xz") as package:
                directory = tarfile.TarInfo("package/bin")
                directory.type = tarfile.DIRTYPE
                package.addfile(directory)
                for name, payload, mode in (
                    ("package/COPYING", b"license", 0o644),
                    ("package/bin/tool", b"executable", 0o755),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    member.mode = mode
                    package.addfile(member, io.BytesIO(payload))
            result = deps.extract(archive, destination, "package")
            self.assertEqual(result, destination / "package")
            self.assertEqual((result / "COPYING").read_bytes(), b"license")
            self.assertEqual((result / "bin/tool").read_bytes(), b"executable")
            if os.name != "nt":
                self.assertEqual((result / "COPYING").stat().st_mode & 0o777, 0o644)
                self.assertEqual((result / "bin/tool").stat().st_mode & 0o777, 0o755)


class ProtocolDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cache = Path(self.temporary.name)
        self.archive = self.cache / "dependency-1.0.tar.xz"
        self.payload = b"verified archive bytes"
        self.digest = hashlib.sha256(self.payload).hexdigest()
        self.network = mock.patch.object(deps.urllib.request, "urlopen")
        self.urlopen = self.network.start()
        self.addCleanup(self.network.stop)

    def download(self, *, offline):
        return deps.download(self.cache, "dependency", "1.0", "example/dependency",
                             self.digest, offline)

    def test_offline_missing_archive_never_downloads(self):
        with self.assertRaisesRegex(ValueError, "Offline cache missing"):
            self.download(offline=True)
        self.urlopen.assert_not_called()
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_verified_cache_never_downloads(self):
        self.archive.write_bytes(self.payload)
        for offline in (False, True):
            with self.subTest(offline=offline):
                self.assertEqual(self.download(offline=offline), self.archive)
                self.assertEqual(self.archive.read_bytes(), self.payload)
        self.urlopen.assert_not_called()

    def test_cached_hash_mismatch_is_never_overwritten(self):
        original = b"unverified existing archive"
        self.archive.write_bytes(original)
        for offline in (False, True):
            with self.subTest(offline=offline):
                with self.assertRaisesRegex(ValueError, "file not overwritten"):
                    self.download(offline=offline)
                self.assertEqual(self.archive.read_bytes(), original)
                self.assertEqual(list(self.cache.iterdir()), [self.archive])
        self.urlopen.assert_not_called()

    def test_download_hash_mismatch_is_not_published(self):
        self.urlopen.return_value = io.BytesIO(b"corrupt downloaded archive")
        with self.assertRaisesRegex(ValueError, "Download failed SHA256 verification"):
            self.download(offline=False)
        self.urlopen.assert_called_once()
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_verified_download_is_published(self):
        self.urlopen.return_value = io.BytesIO(self.payload)
        self.assertEqual(self.download(offline=False), self.archive)
        self.assertEqual(self.archive.read_bytes(), self.payload)
        self.assertEqual(list(self.cache.iterdir()), [self.archive])
        self.urlopen.assert_called_once()
        self.assertEqual(self.urlopen.call_args.kwargs["timeout"], 60)

    def test_interrupted_download_leaves_no_partial_archive(self):
        self.urlopen.side_effect = OSError("interrupted download")
        with self.assertRaisesRegex(OSError, "interrupted download"):
            self.download(offline=False)
        self.assertEqual(list(self.cache.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
