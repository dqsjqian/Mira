#!/usr/bin/env python3
"""Smoke-test the hello-world example: startup line, one HTTP exchange, CLI validation."""

from __future__ import annotations

import queue
import socket
import subprocess
import sys
import threading
import time

TIMEOUT = 10


def read_endpoint(process: subprocess.Popen, lines: "queue.Queue[str]") -> str:
    # The server prints "hello world server listening on 127.0.0.1:PORT"
    # once its listener is bound; the port is what the test needs.
    line = lines.get(timeout=TIMEOUT)
    if "listening on" not in line:
        raise AssertionError(f"unexpected startup line: {line!r}")
    return line.rsplit(":", 1)[1].strip()


def check_hello_world(executable: str) -> None:
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
        port = read_endpoint(process, lines)
        with socket.create_connection(("127.0.0.1", int(port)), timeout=TIMEOUT) as conn:
            request = (
                "GET / HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            conn.sendall(request.encode())
            response = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response += chunk
        text = response.decode("utf-8", "replace")
        assert "200 OK" in text, f"missing status line: {text[:120]!r}"
        assert "hello from Mira's HTTP server" in text, f"missing body: {text[-120:]!r}"
        assert "Content-Length:" in text, f"missing framing header: {text[:160]!r}"
    finally:
        process.terminate()
        try:
            process.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=TIMEOUT)


def check_cli_validation(executable: str) -> None:
    completed = subprocess.run(
        [executable, "not-a-port"], capture_output=True, text=True, timeout=TIMEOUT,
    )
    assert completed.returncode == 2, f"usage errors must exit 2, got {completed.returncode}"


def main() -> int:
    executable = sys.argv[1]
    check_hello_world(executable)
    check_cli_validation(executable)
    print("hello-world example: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
