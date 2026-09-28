#!/usr/bin/env python3
"""Request two paths using HTTP/3 curl; missing capability returns CTest skip code 77."""
from __future__ import annotations

import argparse
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

TIMEOUT = 35


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server")
    parser.add_argument("--strict", action="store_true", help="fail if HTTP/3-capable curl is unavailable")
    parser.add_argument("--curl", default="curl")
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    curl = shutil.which(args.curl)
    version = subprocess.run([curl, "--version"], capture_output=True, text=True,
                             timeout=TIMEOUT) if curl else None
    if not version or version.returncode or "HTTP3" not in version.stdout:
        status = "FAILED" if args.strict else "SKIPPED"
        print(f"h3 interop: {status} (no HTTP/3-capable curl)")
        return 1 if args.strict else 77

    with tempfile.TemporaryDirectory(prefix="mira-h3-") as runtime:
        cert, key = str(Path(runtime) / "cert.pem"), str(Path(runtime) / "key.pem")
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost"],
                       capture_output=True, check=True, timeout=TIMEOUT)
        process = subprocess.Popen([args.server, "0", cert, key], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        lines: queue.Queue[str] = queue.Queue()
        assert process.stdout is not None
        reader = threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True)
        reader.start()
        try:
            startup = lines.get(timeout=TIMEOUT)
            match = re.search(r"listening on 127\.0\.0\.1:(\d+)", startup)
            assert match, f"unexpected startup: {startup!r}"
            port = match.group(1)
            completed = subprocess.run(
                [curl, "--http3-only", "-fsS", "--noproxy", "*", "--ipv4",
                 "--cacert", cert, "--max-time", "20", "-w", "\n%{http_version} %{http_code}\n",
                 f"https://localhost:{port}/first", f"https://localhost:{port}/second"],
                capture_output=True, text=True, timeout=TIMEOUT)
            assert completed.returncode == 0, completed.stderr
            responses = re.findall(r"stream (\d+), path (/\w+)", completed.stdout)
            assert len(responses) == 2 and len({s for s, _ in responses}) == 2, completed.stdout
            assert {p for _, p in responses} == {"/first", "/second"}, completed.stdout
            assert completed.stdout.count("\n3 200\n") == 2, completed.stdout
            _, stderr = process.communicate(timeout=TIMEOUT)
            assert process.returncode == 0, stderr
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    print("h3 interop: ok (real curl, two requests over QUIC + h3)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
