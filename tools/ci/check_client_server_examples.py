#!/usr/bin/env python3
"""Verify real loopback example pairs, empty UDP datagrams and bounded failure paths."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import queue
import re
import socket
import subprocess
import sys
import threading

TIMEOUT = 10


@contextmanager
def server(arguments: list[str], pattern: str):
    process = subprocess.Popen(
        arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    lines: queue.Queue[str] = queue.Queue(maxsize=1)
    reader = threading.Thread(
        target=lambda: lines.put(process.stdout.readline(512)), daemon=True,
    )
    reader.start()
    try:
        line = lines.get(timeout=TIMEOUT)
        match = re.fullmatch(pattern, line)
        if match is None or not 0 < int(match.group(1)) <= 65535:
            raise AssertionError(f"unexpected server announcement: {line!r}")
        reader.join(timeout=TIMEOUT)
        if reader.is_alive():
            raise TimeoutError("server output reader did not finish")
        yield process, int(match.group(1))
    finally:
        # Reap only this run's children, including exception and timeout paths.
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


def run_client(arguments: list[str], expected: str | None = None,
               exit_code: int = 0, expected_error: str | None = None) -> None:
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=TIMEOUT)
    if result.returncode != exit_code:
        raise AssertionError(
            f"{arguments[0]} exited {result.returncode}, expected {exit_code}; "
            f"stdout={result.stdout!r}; stderr={result.stderr!r}"
        )
    if expected is not None and expected not in result.stdout:
        raise AssertionError(f"missing {expected!r} in {result.stdout!r}")
    if exit_code == 0 and result.stderr:
        raise AssertionError(f"unexpected client errors: {result.stderr!r}")
    if exit_code != 0 and not result.stderr:
        raise AssertionError("failed client did not report an error")
    if expected_error is not None and expected_error not in result.stderr:
        raise AssertionError(f"missing error {expected_error!r} in {result.stderr!r}")


def finished(process: subprocess.Popen) -> None:
    _, errors = process.communicate(timeout=TIMEOUT)
    if process.returncode != 0 or errors:
        raise AssertionError(f"server exited {process.returncode}: {errors!r}")


def client_arguments(client: str, protocol: str, port: int, timeout: int) -> list[str]:
    arguments = [client, str(port)]
    if protocol != "http":
        arguments.append("deadline probe")
    arguments.append(str(timeout))
    return arguments


def check_failures(client: str, protocol: str) -> None:
    # Keep the socket bound without listening to avoid a free-port race.
    if protocol != "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            reserved.bind(("127.0.0.1", 0))
            run_client(client_arguments(client, protocol, reserved.getsockname()[1], 250),
                       exit_code=1)

    # Listen/bind without replying; the example's own deadline must end the wait.
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as silent:
        silent.bind(("127.0.0.1", 0))
        if protocol != "udp":
            silent.listen(1)
        run_client(client_arguments(client, protocol, silent.getsockname()[1], 250),
                   exit_code=1, expected_error="operation timed out")

    for arguments in ([], ["0"], ["65536"], ["-1"], ["12junk"]):
        run_client([client, *arguments], exit_code=2)
    invalid_timeout = [client, "1"] + ([] if protocol == "http" else ["payload"])
    for timeout in ("0", "-1", "600001", "junk"):
        run_client([*invalid_timeout, timeout], exit_code=2)


def check_tcp(server_path: str, client: str) -> None:
    with server([server_path, "0", "1"],
                r"echo server listening on 127\.0\.0\.1:(\d+)\n") as (process, port):
        # Exceed the server's 4096-byte buffer to exercise short reads and final EOF.
        message = "Mira echo " * 1025
        run_client([client, str(port), message], f"TCP echo OK: {len(message)} bytes")
        finished(process)
    with server([server_path, "0", "1"],
                r"echo server listening on 127\.0\.0\.1:(\d+)\n") as (process, port):
        run_client([client, str(port), ""], "TCP echo OK: 0 bytes")
        finished(process)
    check_failures(client, "tcp")


def check_udp(server_path: str, client: str) -> None:
    with server([server_path, "0", "2"], r"PORT=(\d+)\n") as (process, port):
        run_client([client, str(port), "UDP pair payload"],
                   "UDP echo OK: 16 bytes; response=UDP pair payload")
        run_client([client, str(port), ""], "UDP echo OK: 0 bytes; response=\n")
        finished(process)
    check_failures(client, "udp")
    run_client([server_path, "0", "1", "50"], exit_code=1,
               expected_error="operation timed out")


def check_http(server_path: str, client: str) -> None:
    with server([server_path, "0"],
                r"hello world server listening on 127\.0\.0\.1:(\d+)\n") as (process, port):
        run_client([client, str(port)], "HTTP/1.1 keep-alive OK: 2 requests on one connection")
        if process.poll() is not None:
            raise AssertionError("HTTP server exited before cleanup")
    check_failures(client, "http")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for protocol in ("tcp", "udp", "http"):
        parser.add_argument(f"--{protocol}-server")
        parser.add_argument(f"--{protocol}-client")
    arguments = parser.parse_args()
    selected = []
    for protocol, check in (("tcp", check_tcp), ("udp", check_udp), ("http", check_http)):
        server_path = getattr(arguments, f"{protocol}_server")
        client = getattr(arguments, f"{protocol}_client")
        if bool(server_path) != bool(client):
            parser.error(f"--{protocol}-server and --{protocol}-client must be provided together")
        if server_path:
            selected.append((protocol, check, server_path, client))
    if not selected:
        parser.error("provide at least one server/client pair")
    try:
        for protocol, check, server_path, client in selected:
            check(server_path, client)
            print(f"{protocol.upper()} client/server OK: loopback, validation, deadline and cleanup")
    except (AssertionError, OSError, queue.Empty, subprocess.TimeoutExpired) as error:
        print(f"client/server examples failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
