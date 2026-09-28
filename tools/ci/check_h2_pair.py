#!/usr/bin/env python3
"""Verify two concurrent H2 streams, connection refusal, and a silent-peer deadline."""
from __future__ import annotations

import argparse
import queue
import re
import socket
import subprocess
import sys
import tempfile
import threading

TIMEOUT = 8


def check_client(client: str, port: int, timeout_ms: int = 5000) -> subprocess.CompletedProcess:
    return subprocess.run(
        [client, str(port), "127.0.0.1", str(timeout_ms)],
        capture_output=True, text=True, timeout=TIMEOUT,
    )


def stop_server(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--client", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryFile(mode="w+t") as errors:
        server = subprocess.Popen(
            [args.server, "0"], stdout=subprocess.PIPE, stderr=errors, text=True,
        )
        assert server.stdout is not None
        lines: queue.Queue[str] = queue.Queue(maxsize=1)
        reader = threading.Thread(
            target=lambda: lines.put(server.stdout.readline(512)), daemon=True,
        )
        reader.start()
        try:
            line = lines.get(timeout=TIMEOUT)
            match = re.fullmatch(
                r"h2 prior-knowledge server listening on 127\.0\.0\.1:(\d+)\n", line,
            )
            if not match:
                raise AssertionError(f"unexpected server startup output: {line!r}")
            completed = check_client(args.client, int(match.group(1)))
            if completed.returncode != 0:
                raise AssertionError(f"client failed: {completed.stdout!r} {completed.stderr!r}")
            for stream_id in (1, 3):
                expected = (
                    f"h2 stream {stream_id} status 200 body: "
                    f"served by Mira's HTTP/2 server, stream {stream_id}"
                )
                if completed.stdout.splitlines().count(expected) != 1:
                    raise AssertionError(f"unverified concurrent stream {stream_id}: {completed.stdout!r}")
            if "h2 client completed 2 concurrent requests" not in completed.stdout.splitlines():
                raise AssertionError(f"missing two-stream completion marker: {completed.stdout!r}")
            if server.poll() is not None:
                raise AssertionError("server exited unexpectedly after serving two streams")

            # Reserve a port without listening, avoiding a close-and-reconnect port race.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as refused:
                refused.bind(("127.0.0.1", 0))
                failed = check_client(args.client, refused.getsockname()[1], 500)
                if failed.returncode != 1 or "h2 client:" not in failed.stderr:
                    raise AssertionError(f"connection refusal did not return a normal error: {failed}")

            # Accept TCP handshakes without sending H2 frames; the client must time out itself.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as silent:
                silent.bind(("127.0.0.1", 0))
                silent.listen(1)
                timed_out = check_client(args.client, silent.getsockname()[1], 200)
                if timed_out.returncode != 1 or "operation timed out" not in timed_out.stderr:
                    raise AssertionError(f"silent connection did not return a normal timeout: {timed_out}")
        except Exception:
            stop_server(server)
            errors.seek(0)
            print(f"h2 server stderr: {errors.read()}", file=sys.stderr)
            raise
        finally:
            stop_server(server)
            reader.join(timeout=3)
            server.stdout.close()

    print("h2 pair: ok (two concurrent streams, connection refusal, deadline)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
