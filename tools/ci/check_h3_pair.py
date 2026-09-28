#!/usr/bin/env python3
"""Verify two distinct H3 requests over one connection using real Mira processes."""
from __future__ import annotations

import queue
import re
import subprocess
import sys
import threading

TIMEOUT = 35


def main() -> int:
    if len(sys.argv) != 5:
        print("usage: check_h3_pair.py <server> <client> <certificate> <key>", file=sys.stderr)
        return 2
    server, client, cert, key = sys.argv[1:]
    process = subprocess.Popen([server, "0", cert, key], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    lines: queue.Queue[str] = queue.Queue()
    assert process.stdout is not None
    reader = threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True)
    reader.start()
    try:
        startup = lines.get(timeout=TIMEOUT)
        match = re.search(r"listening on 127\.0\.0\.1:(\d+)", startup)
        if not match:
            raise AssertionError(f"unexpected startup: {startup!r}")
        completed = subprocess.run([client, match.group(1), cert], capture_output=True,
                                   text=True, timeout=TIMEOUT)
        assert completed.returncode == 0, (completed.stdout, completed.stderr)
        responses = re.findall(r"stream=(\d+) path=(/\w+) status=200 verified", completed.stdout)
        assert len(responses) == 2, completed.stdout
        assert {path for _, path in responses} == {"/first", "/second"}, responses
        assert len({stream for stream, _ in responses}) == 2, responses
        assert "2 requests, verified localhost certificate" in completed.stdout, completed.stdout
        _, stderr = process.communicate(timeout=TIMEOUT)
        assert process.returncode == 0, f"server failed: {stderr}"
        print(completed.stdout, end="")
        print("h3 pair: ok (real processes, distinct streams and paths)")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
