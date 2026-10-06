#!/usr/bin/env python3
"""Validate TCP echo lifecycle, admission, complete payloads and slow-reader backpressure."""
from __future__ import annotations

import argparse
import queue
import socket
import subprocess
import sys
import threading


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def launch(path, limit, lifetime):
    process = subprocess.Popen([path, "0", str(limit), str(lifetime)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8")
    startup = queue.Queue()
    threading.Thread(target=lambda: startup.put(process.stdout.readline()), daemon=True).start()
    try:
        line = startup.get(timeout=5)
        require(line.startswith("PORT="), f"invalid startup protocol: {line!r}")
        return process, int(line[5:])
    except BaseException:
        cleanup(process)
        raise


def cleanup(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=3)


def connect(port):
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return client


def exchange(client, payload):
    client.sendall(payload)
    received = bytearray()
    while len(received) < len(payload):
        data = client.recv(len(payload) - len(received))
        require(bool(data), "EOF before echo completed")
        received.extend(data)
    require(received == payload, "echo payload mismatch")


def statistics(process):
    stdout, stderr = process.communicate(timeout=5)
    require(process.returncode == 0, f"server exit {process.returncode}: {stderr}")
    lines = [line for line in stdout.splitlines() if line.startswith("accepted=")]
    require(len(lines) == 1, f"invalid statistics output: {stdout}")
    return {key: int(value) for key, value in (item.split("=") for item in lines[0].split())}


def test_admission(path):
    process, port = launch(path, 1, 1200)
    try:
        with connect(port) as first:
            exchange(first, b"accepted")
            with connect(port) as second:
                try:
                    second.sendall(b"rejected")
                    require(second.recv(1) == b"", "connection admitted beyond the limit")
                except (ConnectionResetError, BrokenPipeError):
                    pass
            exchange(first, bytes(range(251)) * 200)
            first.shutdown(socket.SHUT_WR)
            require(first.recv(1) == b"", "half-close did not yield EOF after the complete echo")
        stats = statistics(process)
        require(stats["accepted"] == 2 and stats["rejected"] == 1, f"incorrect admission counters: {stats}")
        require(stats["completed"] == 1 and stats["peak_active"] == 1, f"incorrect connection limit: {stats}")
        require(stats["failed"] == 0, f"clean session counted as failed: {stats}")
    finally:
        cleanup(process)


def test_slow_reader(path):
    process, port = launch(path, 2, 1200)
    try:
        with connect(port) as slow, connect(port) as normal:
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            slow.setblocking(False)
            block = b"s" * 65536
            for _ in range(128):
                try:
                    slow.send(block)
                except BlockingIOError:
                    break
            for size in (1, 16384, 65537, 262144):
                exchange(normal, bytes(index % 251 for index in range(size)))
            stats = statistics(process)
            require(stats["peak_active"] == 2 and stats["completed"] == 2,
                    f"shutdown did not drain pending writes: {stats}")
            require(stats["rejected"] == 0, f"connection rejected below the limit: {stats}")
    finally:
        cleanup(process)


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    args = parser.parse_args()
    for values in (["65536"], ["0", "0"], ["0", "1", "0"], ["bad"], ["0", "1", "2", "3"]):
        result = subprocess.run([args.server, *values], capture_output=True, timeout=3)
        require(result.returncode == 2, f"invalid arguments not rejected: {values}")
    test_admission(args.server)
    test_slow_reader(args.server)
    print("TCP echo reference: arguments, echo, half-close, admission, backpressure and shutdown passed")


if __name__ == "__main__":
    main()
