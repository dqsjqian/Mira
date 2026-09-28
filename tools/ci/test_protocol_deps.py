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
