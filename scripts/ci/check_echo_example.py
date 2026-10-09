#!/usr/bin/env python3
"""Smoke-test the echo example's finite lifetime, full writes, and CLI validation."""

from __future__ import annotations

import os
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time

TIMEOUT = 10


def check_echo(executable: str) -> None:
    process = subprocess.Popen(
        [executable, "0", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    lines: queue.Queue[str] = queue.Queue(maxsize=1)
    assert process.stdout is not None
    assert process.stderr is not None

    # A reader thread also works for Windows pipes, which select() cannot poll.
    reader = threading.Thread(
        target=lambda: lines.put(process.stdout.readline(512)), daemon=True,
    )
    reader.start()
    try:
        line = lines.get(timeout=TIMEOUT)
        endpoint = re.fullmatch(r"echo server listening on 127\.0\.0\.1:(\d+)\n", line)
        if endpoint is None:
            raise AssertionError(f"unexpected listening endpoint: {line!r}")
        port = int(endpoint.group(1))
        if not 0 < port <= 65535:
            raise AssertionError(f"invalid ephemeral port: {port}")

        # Only our own child: successful echo/exit below proves SIGPIPE was ignored.
        if hasattr(signal, "SIGPIPE"):
            os.kill(process.pid, signal.SIGPIPE)

        # Binary and larger than the example's 4096-byte buffer, including a
        # partial final chunk. Limit=1 must not cancel this last accepted socket.
        payload = bytes(range(256)) * 257 + b"last partial chunk\x00"
        with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as peer:
            peer.sendall(payload)
            peer.shutdown(socket.SHUT_WR)
            received = bytearray()
            deadline = time.monotonic() + TIMEOUT
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("timed out waiting for echo and EOF")
                peer.settimeout(remaining)
                chunk = peer.recv(8192)
                if not chunk:
                    break
                received.extend(chunk)
                if len(received) > len(payload):
                    raise AssertionError("server returned more bytes than sent")
            if received != payload:
                raise AssertionError(f"echo mismatch: {len(received)} of {len(payload)} bytes")

        reader.join(timeout=TIMEOUT)
        if reader.is_alive():
            raise TimeoutError("stdout reader did not finish")
        _, errors = process.communicate(timeout=TIMEOUT)
        if process.returncode != 0:
            raise AssertionError(f"server exited {process.returncode}: {errors}")
        if errors:
            raise AssertionError(f"unexpected server errors: {errors}")
    finally:
        # Own only this child: no process-name matching or shared port cleanup.
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=TIMEOUT)
        reader.join(timeout=TIMEOUT)
        process.stdout.close()
        process.stderr.close()


def check_bad_arguments(executable: str) -> None:
    invalid = (
        ["-1"], ["65536"], ["18446744073709551616"], ["junk"], ["12junk"],
        [""], ["+1"], [" 1"], ["1.5"],
        ["0", "-1"], ["0", "9999999999999999999999999999999999999999"],
        ["0", "junk"], ["0", "1junk"], ["0", ""], ["0", "+1"],
        ["0", " 1"], ["0", "1.5"], ["0", "1", "extra"],
    )
    for arguments in invalid:
        result = subprocess.run(
            [executable, *arguments], capture_output=True, text=True, timeout=TIMEOUT,
        )
        if result.returncode != 2:
            raise AssertionError(
                f"arguments {arguments!r}: expected exit 2, got {result.returncode}; "
                f"stderr={result.stderr!r}"
            )


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <echo-server-executable>", file=sys.stderr)
        return 2
    try:
        check_bad_arguments(sys.argv[1])
        check_echo(sys.argv[1])
    except (AssertionError, OSError, queue.Empty, subprocess.TimeoutExpired) as error:
        print(f"echo example failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    print("echo example OK: complete echo, peer EOF, finite exit, and invalid CLI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
