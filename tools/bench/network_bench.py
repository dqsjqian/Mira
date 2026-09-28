#!/usr/bin/env python3
"""Out-of-process TCP loopback benchmark; JSON output, no cross-library ranking.

Run a Release mira_managed_echo_server and independent Python socket clients.
Latency includes Python scheduling, client encoding and kernel I/O. RSS is the
server's observed OS high-water mark (or peak working set), not allocator accounting.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import json
import math
import os
import platform
import queue
import socket
import subprocess
import threading
import time


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)] if ordered else None


def exchange(port, iterations, payload):
    latency = []
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        for _ in range(iterations):
            start = time.perf_counter_ns()
            client.sendall(payload)
            result = bytearray()
            while len(result) < len(payload):
                chunk = client.recv(len(payload) - len(result))
                if not chunk:
                    raise RuntimeError("early EOF")
                result.extend(chunk)
            if result != payload:
                raise RuntimeError("payload corruption")
            latency.append((time.perf_counter_ns() - start) / 1000)
    return latency


def rss_kib(pid):
    if platform.system() == "Linux":
        with open(f"/proc/{pid}/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
    if platform.system() == "Darwin":
        value = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)
        return int(value.strip())
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--clients", type=int, default=8)
    parser.add_argument("--requests", type=int, default=1000, help="per client")
    parser.add_argument("--payload", type=int, default=1024)
    parser.add_argument("--slow-clients", type=int, default=0)
    parser.add_argument("--output")
    args = parser.parse_args()
    if not 1 <= args.clients <= 256 or not 1 <= args.requests <= 1000000:
        parser.error("clients/requests out of range")
    if not 1 <= args.payload <= 1048576 or not 0 <= args.slow_clients <= 256:
        parser.error("payload/slow-clients out of range")
    server = subprocess.Popen([args.server, "0", str(args.clients + args.slow_clients), "60000"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = queue.Queue()
    threading.Thread(target=lambda: lines.put(server.stdout.readline()), daemon=True).start()
    slow = []
    peak = None
    peak_lock = threading.Lock()
    finished = threading.Event()

    def sample():
        nonlocal peak
        while not finished.is_set():
            try:
                current = rss_kib(server.pid)
                if current is not None:
                    with peak_lock:
                        peak = current if peak is None else max(peak, current)
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            finished.wait(0.05)

    try:
        line = lines.get(timeout=5)
        if not line.startswith("PORT="):
            raise RuntimeError(f"bad startup {line!r}")
        port = int(line[5:])
        monitor = threading.Thread(target=sample, daemon=True)
        monitor.start()
        for _ in range(args.slow_clients):
            client = socket.create_connection(("127.0.0.1", port), timeout=2)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            client.setblocking(False)
            # Deliberately never read echoed bytes; send until the OS applies pressure.
            block = b"s" * 65536
            for _ in range(64):
                try:
                    client.send(block)
                except BlockingIOError:
                    break
            slow.append(client)
        payload = bytes(i % 251 for i in range(args.payload))
        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.clients) as executor:
            results = list(executor.map(lambda _: exchange(port, args.requests, payload),
                                        range(args.clients)))
        seconds = time.perf_counter() - start
        samples = [value for result in results for value in result]
        report = {
            "scenario": "tcp-loopback-slow-reader" if slow else "tcp-loopback",
            "platform": platform.platform(), "machine": platform.machine(),
            "python": platform.python_version(), "cpu_count": os.cpu_count(),
            "server": args.server, "clients": args.clients, "slow_clients": len(slow),
            "requests": len(samples), "payload_bytes": args.payload,
            "elapsed_seconds": seconds, "requests_per_second": len(samples) / seconds,
            "roundtrip_payload_mib_per_second": len(samples) * args.payload * 2 / seconds / 1048576,
            "latency_us": {"p50": percentile(samples, 0.5), "p99": percentile(samples, 0.99),
                           "max": max(samples)},
            "observed_server_peak_rss_kib": peak,
            "limitations": "Loopback, Python load generator, sampled macOS RSS; not a cross-library ranking.",
        }
        text = json.dumps(report, indent=2)
        print(text)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as output:
                output.write(text + "\n")
    finally:
        finished.set()
        for client in slow:
            client.close()
        if server.poll() is None:
            server.terminate()
        try:
            server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.communicate(timeout=5)


if __name__ == "__main__":
    main()
