#!/usr/bin/env python3
"""Interop-test the h2 prior-knowledge example: real curl speaking HTTP/2.

The point of this file is external evidence: nghttp2 inside curl — an
independent implementation of RFC 9113 — connects to Mira's http2 layer,
negotiates nothing (prior knowledge), exchanges a request, and the response
must survive curl's own strictness about framing, HPACK and stream states.

Requires curl built with HTTP/2 support. The check degrades to a skip with
a clear message where that is unavailable, because the raw-frame coverage
lives in modules/http2/tests/test_session.cpp.
"""

from __future__ import annotations

import queue
import re
import shutil
import socket
import subprocess
import sys
import threading

TIMEOUT = 20


def wait_listening(process: subprocess.Popen, lines: "queue.Queue[str]") -> int:
    line = lines.get(timeout=TIMEOUT)
    match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
    if not match:
        raise AssertionError(f"unexpected startup line: {line!r}")
    return int(match.group(1))


def curl_supports_http2(curl: str) -> bool:
    completed = subprocess.run([curl, "--version"], capture_output=True,
                               text=True, timeout=TIMEOUT)
    return "HTTP2" in completed.stdout or "nghttp2" in completed.stdout


def check_single_request(curl: str, port: int) -> None:
    """One GET over one connection; the body names its stream id."""
    completed = subprocess.run(
        [curl, "--http2-prior-knowledge", "-fsS", f"http://127.0.0.1:{port}/",
         "-w", "\n%{http_version} %{http_code}"],
        capture_output=True, text=True, timeout=TIMEOUT,
    )
    assert completed.returncode == 0, f"curl failed: {completed.stderr!r}"
    body, _, stats = completed.stdout.rpartition("\n")
    assert "served by Mira's HTTP/2 server, stream " in body, f"body: {body!r}"
    assert stats.startswith("2 "), f"curl saw a non-h2 exchange: {stats!r}"


def check_concurrent_streams(curl: str, port: int) -> None:
    """Several requests multiplexed over one connection (--parallel)."""
    urls = [f"http://127.0.0.1:{port}/stream-{i}" for i in range(3)]
    completed = subprocess.run(
        [curl, "--http2-prior-knowledge", "-fsS", "--parallel", *urls],
        capture_output=True, text=True, timeout=TIMEOUT,
    )
    assert completed.returncode == 0, f"parallel curl failed: {completed.stderr!r}"


def check_upload_window(curl: str, port: int) -> None:
    """Cross the initial 65535-byte HTTP/2 flow-control window."""
    for size in (65535, 65536, 150000):
        completed = subprocess.run(
            [curl, "--http2-prior-knowledge", "--noproxy", "*", "-fsS",
             "--max-time", "10", "--data-binary", "@-", f"http://127.0.0.1:{port}/"],
            input=b"x" * size, capture_output=True, timeout=TIMEOUT,
        )
        assert completed.returncode == 0, (size, completed.stderr)
        assert b"served by Mira's HTTP/2 server" in completed.stdout


def check_reset_reclamation(port: int) -> None:
    """HEADERS and RST in one read must not consume a permanent stream slot."""
    def frame(kind, flags, stream, body=b""):
        return len(body).to_bytes(3, "big") + bytes((kind, flags)) + stream.to_bytes(4, "big") + body

    with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as peer:
        def exact(size):
            data = b""
            while len(data) < size:
                part = peer.recv(size - len(data))
                assert part, "server closed during reset churn"
                data += part
            return data

        def until_ping(token):
            while True:
                header = exact(9)
                body = exact(int.from_bytes(header[:3], "big"))
                assert header[3] != 7, ("unexpected GOAWAY", body)
                if header[3] == 4 and not header[4] & 1:
                    peer.sendall(frame(4, 1, 0))
                if header[3:5] == b"\x06\x01" and body == token:
                    return

        # Static HPACK indices: GET, http, /; literal :authority = localhost.
        headers = b"\x82\x86\x84\x01\x09localhost"
        peer.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))
        for index in range(120):
            stream = 2 * index + 1
            token = index.to_bytes(8, "big")
            peer.sendall(frame(1, 5, stream, headers) + frame(3, 0, stream, b"\x00\x00\x00\x08") +
                         frame(6, 0, 0, token))
            until_ping(token)
        peer.sendall(frame(1, 5, 241, headers))
        response = b""
        while True:
            header = exact(9)
            body = exact(int.from_bytes(header[:3], "big"))
            assert header[3] not in (3, 7), ("stream slots leaked", header, body)
            if header[3] == 0:
                response += body
                if header[4] & 1:
                    break
        assert b"served by Mira's HTTP/2 server, stream 241" in response


def main() -> int:
    executable = sys.argv[1]
    curl = shutil.which("curl")
    if not curl or not curl_supports_http2(curl):
        print("h2 interop: SKIPPED (no HTTP/2-capable curl on PATH)")
        return 77

    process = subprocess.Popen(
        [executable, "0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
        check_single_request(curl, port)
        check_concurrent_streams(curl, port)
        check_upload_window(curl, port)
        check_reset_reclamation(port)
    finally:
        process.terminate()
        try:
            process.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=TIMEOUT)

    print("h2 interop: ok (real curl, prior knowledge)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
