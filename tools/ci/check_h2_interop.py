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


def main() -> int:
    executable = sys.argv[1]
    curl = shutil.which("curl")
    if not curl or not curl_supports_http2(curl):
        print("h2 interop: SKIPPED (no HTTP/2-capable curl on PATH)")
        return 0

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
