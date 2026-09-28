#!/usr/bin/env python3
"""Run the real-loopback HTTP/3 fault harness with an independent process deadline."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="save the final JSON, including failures")
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--seed", type=int, default=20260928)
    parser.add_argument("--duration-seconds", type=int, default=30)
    parser.add_argument("--clients", type=int, default=3)
    parser.add_argument("--payload", type=int, default=131072)
    parser.add_argument("--requests", type=int, default=4)
    parser.add_argument("--rounds", type=int, default=0)
    parser.add_argument("--round-deadline-seconds", type=int, default=20)
    parser.add_argument("--timeout-seconds", type=float)
    parser.add_argument("--no-rss", action="store_true")
    result = parser.parse_args()
    if bool(result.certificate) != bool(result.key):
        parser.error("--certificate and --key must be supplied together")
    if not 0 <= result.seed <= 2**64 - 1:
        parser.error("seed must fit uint64")
    if not 0 <= result.duration_seconds <= 86400:
        parser.error("duration must be 0..86400 seconds")
    if not 0 <= result.rounds <= 1000000:
        parser.error("rounds must be 0..1000000")
    if not result.duration_seconds and not result.rounds:
        parser.error("duration or rounds must be nonzero")
    if not 1 <= result.clients <= 32 or not 2 <= result.requests <= 8:
        parser.error("clients must be 1..32; requests must be 2..8 per client per round")
    if not 65536 <= result.payload <= 64 * 1024 * 1024:
        parser.error("payload must be 65536..67108864 bytes")
    if not 1 <= result.round_deadline_seconds <= 300:
        parser.error("round deadline must be 1..300 seconds")
    if result.timeout_seconds is not None and result.timeout_seconds <= 0:
        parser.error("process timeout must be positive")
    return result


def rss_bytes(pid):
    if sys.platform.startswith("linux"):
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
        return None
    if sys.platform == "darwin":
        value = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=2
        )
        if value.returncode == 0 and value.stdout.strip():
            return int(value.stdout.strip()) * 1024
        return None
    if os.name == "nt":
        from ctypes import wintypes

        class MemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x0400 | 0x0010, False, pid)
        if not handle:
            return None
        try:
            counters = MemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return counters.WorkingSetSize
            return None
        finally:
            kernel.CloseHandle(handle)
    return None


class RssObserver:
    def __init__(self, pid, enabled):
        self.pid = pid
        self.enabled = enabled
        self.stop = threading.Event()
        self.peak = 0
        self.samples = 0
        self.error = None
        self.thread = threading.Thread(target=self.observe, daemon=True)

    def observe(self):
        if not self.enabled:
            return
        while not self.stop.is_set():
            try:
                value = rss_bytes(self.pid)
                if value is not None:
                    self.peak = max(self.peak, value)
                    self.samples += 1
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                self.error = str(error)
            if self.stop.wait(0.25):
                return

    def finish(self):
        self.stop.set()
        self.thread.join()
        return {
            "enabled": self.enabled,
            "platform": sys.platform,
            "samples": self.samples,
            "peak_rss_bytes": self.peak if self.samples else None,
            "cap_claimed": False,
            "error": self.error,
        }


def validate_summary(summary):
    if summary.get("pass") is not True:
        return "harness reported failure"
    started = summary.get("requests_started")
    passed = summary.get("requests_passed")
    if type(started) is not int or started <= 0 or type(passed) is not int or passed != started:
        return "request completion accounting mismatch or empty workload"
    rounds = summary.get("rounds")
    if type(rounds) is not int or rounds <= 0 or summary.get("clean_rounds") != rounds:
        return "connection churn did not drain completely"
    final = summary.get("final")
    expected = {"connections", "tombstones", "routes", "reserved_payload_bytes", "queued_bytes"}
    if not isinstance(final, dict) or not expected.issubset(final):
        return "missing final resource accounting"
    if any(type(value) is not int or value != 0 for value in final.values()):
        return "nonzero or invalid resources remained after final drain"
    if summary.get("retry_required") is not True or type(summary.get("retry_replies")) is not int or summary["retry_replies"] <= 0:
        return "Retry-required traffic was not observed"
    overlap_started = summary.get("slow_overlap_short_started")
    overlap_completed = summary.get("slow_overlap_short_completed")
    clients = summary.get("clients")
    requests = summary.get("requests_per_client_per_round")
    if type(clients) is not int or clients <= 0 or type(requests) is not int or requests < 2:
        return "missing workload dimensions"
    expected_started = rounds * clients * (requests - 1)
    # The harness checks every client, not just the aggregate: at least one
    # newly submitted short stream completes before its slow response ends.
    if (type(overlap_started) is not int or type(overlap_completed) is not int or
            overlap_started != expected_started or
            not rounds * clients <= overlap_completed <= overlap_started):
        return "short requests did not make progress while a slow response remained pending"
    return None


def emit(summary, args):
    text = json.dumps(summary, separators=(",", ":"), sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)


def run(args, certificate, key):
    command = [
        str(args.binary.resolve()), "--certificate", str(certificate), "--key", str(key),
        "--seed", str(args.seed), "--duration-seconds", str(args.duration_seconds),
        "--clients", str(args.clients), "--payload", str(args.payload),
        "--requests", str(args.requests), "--rounds", str(args.rounds),
        "--round-deadline-seconds", str(args.round_deadline_seconds),
    ]
    timeout = args.timeout_seconds
    if timeout is None:
        if args.duration_seconds:
            timeout = args.duration_seconds + args.round_deadline_seconds + 30
        else:
            timeout = args.rounds * (args.round_deadline_seconds + 16) + 10
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    observer = RssObserver(process.pid, not args.no_rss)
    observer.thread.start()
    timed_out = False
    try:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate()
    finally:
        rss = observer.finish()
    if stderr:
        sys.stderr.write(stderr)
        if not stderr.endswith("\n"):
            sys.stderr.write("\n")
    summary = None
    lines = stdout.splitlines()
    if lines:
        try:
            candidate = json.loads(lines[-1])
            if isinstance(candidate, dict) and candidate.get("kind") == "h3_soak_summary":
                summary = candidate
        except json.JSONDecodeError:
            pass
    for line in lines[:-1] if summary is not None else lines:
        print(line, file=sys.stderr)
    if summary is None:
        summary = {
            "kind": "h3_soak_summary", "pass": False, "seed": args.seed,
            "actual_runtime_seconds": time.monotonic() - started,
            "error": "missing final harness summary",
        }
    failure = None
    if timed_out:
        failure = f"subprocess deadline exceeded ({timeout} seconds)"
    elif process.returncode:
        failure = f"harness exited with status {process.returncode}"
    else:
        failure = validate_summary(summary)
    if failure:
        summary["pass"] = False
        summary["runner_error"] = failure
        print(failure, file=sys.stderr)
    summary["observer"] = rss
    summary["process_timeout_seconds"] = timeout
    summary["process_returncode"] = process.returncode
    summary["observer_runtime_seconds"] = time.monotonic() - started
    emit(summary, args)
    return 0 if summary.get("pass") is True else 1


def main():
    args = arguments()
    try:
        if args.certificate:
            return run(args, args.certificate.resolve(), args.key.resolve())
        openssl = shutil.which(args.openssl)
        if openssl is None:
            raise RuntimeError("openssl not found; supply --certificate and --key")
        with tempfile.TemporaryDirectory(prefix="mira-h3-soak-") as directory:
            root = Path(directory)
            certificate, key = root / "certificate.pem", root / "key.pem"
            configuration = root / "openssl.cnf"
            configuration.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="utf-8")
            generated = subprocess.run(
                [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                 "-config", str(configuration), "-keyout", str(key), "-out", str(certificate),
                 "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                capture_output=True, text=True, timeout=30,
            )
            if generated.returncode:
                raise RuntimeError("certificate generation failed: " + generated.stderr)
            return run(args, certificate, key)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        summary = {"kind": "h3_soak_summary", "pass": False,
                   "seed": args.seed, "runner_error": str(error)}
        try:
            emit(summary, args)
        except OSError as output_error:
            print(f"Cannot save failure summary: {output_error}", file=sys.stderr)
            print(json.dumps(summary))
        return 1


if __name__ == "__main__":
    sys.exit(main())
