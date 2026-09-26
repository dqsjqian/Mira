#!/usr/bin/env python3
"""Smoke-test the tiny file server: downloads, uploads, traversal refusal, curl interop.

The curl section is the point of the file: Mira's HTTP stack serving a real
external client. It runs only when a curl is on PATH (CI and dev boxes have
one; the test degrades to socket-level checks where it doesn't).
"""

from __future__ import annotations

import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

TIMEOUT = 15


def wait_listening(process: subprocess.Popen, lines: "queue.Queue[str]") -> int:
    line = lines.get(timeout=TIMEOUT)
    match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
    if not match:
        raise AssertionError(f"unexpected startup line: {line!r}")
    return int(match.group(1))


def http_roundtrip(port: int, request: str) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as conn:
        conn.sendall(request.encode())
        response = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            response += chunk
    return response


def check_file_server(executable: str, use_curl: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="mira-fileserver-") as root:
        payload = os.urandom(256 * 1024)  # forces multi-slice streaming both ways
        with open(os.path.join(root, "blob.bin"), "wb") as f:
            f.write(payload)

        process = subprocess.Popen(
            [executable, "0", root], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        lines: "queue.Queue[str]" = queue.Queue(maxsize=4)
        assert process.stdout is not None
        reader = threading.Thread(
            target=lambda: [lines.put(process.stdout.readline(512)) for _ in range(4)],
            daemon=True,
        )
        reader.start()

        try:
            port = wait_listening(process, lines)

            # 1. Streaming download via a raw socket (no external dependency).
            head = http_roundtrip(
                port,
                "GET /blob.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            )
            status_line = head.split(b"\r\n", 1)[0]
            assert b" 200 " in status_line, f"status line: {status_line!r}"
            assert b"Transfer-Encoding: chunked" in head, "download must stream chunked"
            body_start = head.find(b"\r\n\r\n") + 4
            # De-chunk by hand: the point is that the bytes arrive framed, whole.
            body = dechunk(head[body_start:])
            assert body == payload, "downloaded bytes differ from the file"

            # 2. Traversal refusal: `..` past the root must not read /etc/passwd.
            smuggle = http_roundtrip(
                port,
                "GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            )
            assert b" 400 " in smuggle.split(b"\r\n", 1)[0], \
                f"traversal must 400: {smuggle[:80]!r}"

            # 3. Streaming upload via a raw socket.
            upload = (
                f"PUT /uploaded.bin HTTP/1.1\r\nHost: x\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            )
            with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as conn:
                conn.sendall(upload.encode())
                conn.sendall(payload)
                reply = b""
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    reply += chunk
            assert b" 201 " in reply.split(b"\r\n", 1)[0], f"upload status: {reply[:80]!r}"
            with open(os.path.join(root, "uploaded.bin"), "rb") as f:
                assert f.read() == payload, "uploaded bytes differ"

            # 4. curl interop: the external-client evidence.
            if use_curl:
                curl = subprocess.run(
                    ["curl", "-fsS", f"http://127.0.0.1:{port}/blob.bin",
                     "-o", os.devnull,
                     "-w", "%{http_code} %{size_download}"],
                    capture_output=True, text=True, timeout=TIMEOUT,
                )
                assert curl.returncode == 0, f"curl failed: {curl.stderr!r}"
                assert curl.stdout.strip() == f"200 {len(payload)}", \
                    f"curl stats: {curl.stdout!r}"
        finally:
            process.terminate()
            try:
                process.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=TIMEOUT)


def dechunk(body: bytes) -> bytes:
    """Decode a chunked body the test received in one piece."""
    out = bytearray()
    at = 0
    while at < len(body):
        line_end = body.find(b"\r\n", at)
        if line_end < 0:
            break
        try:
            size = int(body[at:line_end], 16)
        except ValueError:
            raise AssertionError(f"bad chunk header at {at}: {body[at:line_end]!r}")
        if size == 0:
            break
        out += body[line_end + 2:line_end + 2 + size]
        at = line_end + 2 + size + 2  # skip data and CRLF
    return bytes(out)


def check_cli_validation(executable: str) -> None:
    completed = subprocess.run(
        [executable, "not-a-port"], capture_output=True, text=True, timeout=TIMEOUT,
    )
    assert completed.returncode == 2, f"usage errors must exit 2, got {completed.returncode}"


def main() -> int:
    executable = sys.argv[1]
    use_curl = shutil.which("curl") is not None
    check_file_server(executable, use_curl)
    check_cli_validation(executable)
    print(f"tiny file server example: ok (curl interop={'yes' if use_curl else 'skipped'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
