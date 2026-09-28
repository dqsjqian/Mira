#!/usr/bin/env python3
"""Exercise independent LoopGroup TCP workers with out-of-process clients.

Reports measured loopback throughput and end-to-end latency, not a universal
scaling claim. Each worker owns a distinct listener/port; there is no shared
accept socket, kernel reuseport balancing or cross-loop socket migration.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import platform
import queue
import re
import socket
import subprocess
import threading
import time
from pathlib import Path


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)] if ordered else None


def exchange(port, requests, payload, barrier):
    samples = []
    with socket.create_connection(("127.0.0.1", port), timeout=10) as client:
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        barrier.wait(timeout=10)
        for _ in range(requests):
            started = time.perf_counter_ns()
            client.sendall(payload)
            result = bytearray()
            while len(result) < len(payload):
                data = client.recv(len(payload) - len(result))
                if not data:
                    raise RuntimeError("early EOF from worker")
                result.extend(data)
            if result != payload:
                raise RuntimeError("worker corrupted payload")
            samples.append((time.perf_counter_ns() - started) / 1000)
    return samples


def run(args, workers):
    # One extra slot per worker permits a deliberately idle connection during
    # shutdown, proving pending reads and accepts unwind before threads join.
    slots = math.ceil(args.clients / workers) + 1
    process = subprocess.Popen(
        [str(args.server), str(workers), str(slots)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    lines = queue.Queue()
    errors = []
    observed = []

    def read_stdout():
        for line in process.stdout:
            line = line.rstrip()
            observed.append(line)
            lines.put(line)
        lines.put(None)

    def read_stderr():
        errors.append(process.stderr.read())

    stdout_reader = threading.Thread(target=read_stdout, daemon=True)
    stderr_reader = threading.Thread(target=read_stderr, daemon=True)
    stdout_reader.start()
    stderr_reader.start()
    idle = []
    try:
        ports = {}
        deadline = time.monotonic() + 15
        while True:
            line = lines.get(timeout=max(0.001, deadline - time.monotonic()))
            if line == "READY":
                break
            if line is None:
                raise RuntimeError("server exited during startup")
            match = re.fullmatch(r"WORKER=(\d+) PORT=(\d+)", line)
            if not match:
                raise RuntimeError(f"unexpected startup output: {line!r}")
            index, port = map(int, match.groups())
            if index in ports or not 0 <= index < workers or not 1 <= port <= 65535:
                raise RuntimeError(f"invalid worker endpoint: {line!r}")
            ports[index] = port
        if len(ports) != workers or len(set(ports.values())) != workers:
            raise RuntimeError("workers did not publish independent listeners")

        for port in ports.values():
            idle.append(socket.create_connection(("127.0.0.1", port), timeout=10))
        barrier = threading.Barrier(args.clients + 1)
        payload = bytes(i % 251 for i in range(args.payload))
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.clients) as pool:
            pending = [pool.submit(exchange, ports[i % workers], args.requests, payload, barrier)
                       for i in range(args.clients)]
            started = time.perf_counter()
            barrier.wait(timeout=10)
            results = [future.result(timeout=120) for future in pending]
        seconds = time.perf_counter() - started
        samples = [sample for client in results for sample in client]
        shutdown_started = time.perf_counter()
        process.stdin.write("stop\n")
        process.stdin.flush()
        process.stdin.close()
        code = process.wait(timeout=15)
        shutdown_seconds = time.perf_counter() - shutdown_started
        stdout_reader.join(timeout=5)
        stderr_reader.join(timeout=5)
        if code != 0:
            raise RuntimeError(f"server exit {code}: {''.join(errors)}")
        stats = {}
        for line in observed:
            if line.startswith("STATS "):
                values = dict(field.split("=", 1) for field in line.split()[1:])
                index = int(values.pop("worker"))
                if index in stats:
                    raise RuntimeError("duplicate worker shutdown stats")
                stats[index] = {key: int(value) for key, value in values.items()}
        if set(stats) != set(range(workers)):
            raise RuntimeError(f"missing worker shutdown stats: {stats}")
        for index, values in stats.items():
            expected = sum(i % workers == index for i in range(args.clients)) + 1
            if values["accepted"] != expected or values["completed"] != expected:
                raise RuntimeError(f"worker {index} did not finish all accepted connections: {values}")
            if values["rejected"] or values["failed"] or values["peak_active"] > slots:
                raise RuntimeError(f"worker {index} failed admission/cleanup check: {values}")
        return {
            "workers": workers, "clients": args.clients, "requests_per_client": args.requests,
            "payload_bytes": args.payload, "seconds": seconds,
            "requests_per_second": len(samples) / seconds,
            "echo_mib_per_second": len(samples) * args.payload * 2 / seconds / 1048576,
            "latency_us": {"p50": percentile(samples, .5), "p95": percentile(samples, .95),
                           "p99": percentile(samples, .99)},
            "shutdown_seconds": shutdown_seconds, "worker_stats": stats,
        }
    finally:
        for client in idle:
            client.close()
        if process.poll() is None:
            # Only the subprocess created above is controlled by this harness.
            try:
                if not process.stdin.closed:
                    process.stdin.write("stop\n")
                    process.stdin.flush()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:
                stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4])
    parser.add_argument("--clients", type=int, default=8)
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--payload", type=int, default=1024)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    args.server = args.server.resolve()
    if not args.server.is_file():
        parser.error("server must be a built mira_loop_group_server executable")
    if not 1 <= args.clients <= 256 or not 1 <= args.requests <= 1000000:
        parser.error("clients/requests out of range")
    if not 1 <= args.payload <= 1048576:
        parser.error("payload out of range")
    if any(not 1 <= count <= min(128, args.clients) for count in args.workers):
        parser.error("workers must be between 1 and min(128, clients)")
    report = {
        "scenario": "loop-group-independent-tcp-listeners", "platform": platform.platform(),
        "machine": platform.machine(), "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "note": "Python scheduling and loopback kernel I/O are included; no RSS cap or scaling guarantee.",
        "runs": [run(args, count) for count in args.workers],
    }
    text = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
