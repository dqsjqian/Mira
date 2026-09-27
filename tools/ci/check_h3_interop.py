#!/usr/bin/env python3
"""Interop-test the h3 example: real curl speaking HTTP/3 over QUIC.

The point is external evidence: curl's own QUIC and HTTP/3 stacks —
ngtcp2 and nghttp3, independent implementations of RFC 9000 and RFC 9114 —
connect to Mira's QUIC/h3 layers, complete the TLS 1.3 handshake with
ALPN "h3", exchange a request, and the response must survive curl's
strictness about framing, QPACK and stream states.

Requires curl built with HTTP/3 support. The check degrades to a skip
with a clear message where that is unavailable, because the raw-QUIC
coverage lives in modules/quic/tests and modules/http3/tests.
"""

from __future__ import annotations

import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading

TIMEOUT = 30


def wait_listening(process: subprocess.Popen, lines: "queue.Queue[str]"):
    line = lines.get(timeout=TIMEOUT)
    match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
    if not match:
        raise AssertionError(f"unexpected startup line: {line!r}")
    port = int(match.group(1))
    line = lines.get(timeout=TIMEOUT)
    match = re.search(r"certificate: (.+)$", line)
    if not match:
        raise AssertionError(f"unexpected certificate line: {line!r}")
    return port, match.group(1)


def curl_supports_http3(curl: str) -> bool:
    completed = subprocess.run([curl, "--version"], capture_output=True,
                               text=True, timeout=TIMEOUT)
    return "HTTP3" in completed.stdout


def check_single_request(curl: str, port: int, cert: str) -> None:
    """One GET over one QUIC connection; the body names its stream id."""
    completed = subprocess.run(
        [curl, "--http3-only", "-fsS", f"https://localhost:{port}/",
         "--cacert", cert,
         "-w", "\n%{http_version} %{http_code}"],
        capture_output=True, text=True, timeout=TIMEOUT,
    )
    assert completed.returncode == 0, f"curl failed: {completed.stderr!r}"
    body, _, stats = completed.stdout.rpartition("\n")
    assert "served by Mira's HTTP/3 server, stream " in body, f"body: {body!r}"
    assert stats.startswith("3 "), f"curl saw a non-h3 exchange: {stats!r}"


def main() -> int:
    executable = sys.argv[1]
    curl = shutil.which("curl")
    if not curl or not curl_supports_http3(curl):
        print("h3 interop: SKIPPED (no HTTP/3-capable curl on PATH)")
        return 0

    with tempfile.TemporaryDirectory(prefix="mira-h3-") as runtime:
        # The certificate the server prints must be the one it generated,
        # so point RUNTIME_DIRECTORY at a directory both sides can read.
        environment = dict(os.environ, RUNTIME_DIRECTORY=runtime)
        process = subprocess.Popen(
            [executable, "0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=environment,
        )
        lines: "queue.Queue[str]" = queue.Queue(maxsize=4)
        assert process.stdout is not None
        reader = threading.Thread(
            target=lambda: [lines.put(process.stdout.readline(512)) for _ in range(4)],
            daemon=True,
        )
        reader.start()

        try:
            port, cert = wait_listening(process, lines)
            check_single_request(curl, port, cert)
        finally:
            process.terminate()
            try:
                process.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=TIMEOUT)

    print("h3 interop: ok (real curl, QUIC + h3)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
