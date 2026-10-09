#!/usr/bin/env python3
"""Request two paths using HTTP/3 curl; missing capability returns CTest skip code 77."""
from __future__ import annotations

import argparse
import contextlib
import queue
import re
import shutil
import socket
import select
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

TIMEOUT = 35


class RetryObserver:
    """Loopback-only UDP relay; observes QUIC v1 Retry headers without decrypting."""
    def __init__(self, server_port):
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", 0))
        self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.back.connect(("127.0.0.1", server_port))
        self.port = self.front.getsockname()[1]
        self.client = None
        self.retries = 0
        self.token_initials = 0
        self.error = None
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.run)

    @staticmethod
    def has_token(packet):
        if len(packet) < 7 or packet[0] & 0xf0 != 0xc0 or packet[1:5] != b"\x00\x00\x00\x01":
            return False
        position = 6 + packet[5]
        if position >= len(packet):
            return False
        position += 1 + packet[position]
        if position >= len(packet):
            return False
        width = 1 << (packet[position] >> 6)
        if position + width > len(packet):
            return False
        value = packet[position] & 0x3f
        for byte in packet[position + 1:position + width]:
            value = (value << 8) | byte
        return value > 0 and position + width + value <= len(packet)

    def run(self):
        try:
            while not self.stop.is_set():
                readable, _, _ = select.select([self.front, self.back], [], [], 0.1)
                for sock in readable:
                    try:
                        packet, peer = sock.recvfrom(65536)
                    except ConnectionResetError:
                        # Winsock reports a late datagram to an exited curl as
                        # WSAECONNRESET on the next front-side receive. This is
                        # not a relay failure; backend resets still fail below.
                        if sock is self.front:
                            continue
                        raise
                    if sock is self.front:
                        self.client = peer
                        if self.has_token(packet):
                            self.token_initials += 1
                        self.back.send(packet)
                    elif self.client is not None:
                        if len(packet) >= 7 and packet[0] & 0xf0 == 0xf0 and packet[1:5] == b"\x00\x00\x00\x01":
                            self.retries += 1
                        self.front.sendto(packet, self.client)
        except OSError as error:
            self.error = str(error)

    def __enter__(self):
        self.worker.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.worker.join(timeout=5)
        self.front.close()
        self.back.close()
        if self.worker.is_alive():
            raise RuntimeError("Retry observation relay did not stop")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server")
    parser.add_argument("--strict", action="store_true", help="fail if HTTP/3-capable curl is unavailable")
    parser.add_argument("--multi-retry", action="store_true", help="verify a Retry-required multi-client server through a UDP observer")
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
        config = Path(runtime) / "openssl.cnf"
        config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="utf-8")
        subprocess.run([args.openssl, "req", "-config", str(config), "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost"],
                       capture_output=True, check=True, timeout=TIMEOUT)
        command = ([args.server, cert, key, "0", "--retry"] if args.multi_retry else
                   [args.server, "0", cert, key])
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        lines: queue.Queue[str] = queue.Queue()
        assert process.stdout is not None
        reader = threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True)
        reader.start()
        try:
            startup = lines.get(timeout=TIMEOUT)
            match = re.search(r"127\.0\.0\.1:(\d+)", startup)
            assert match, f"unexpected startup: {startup!r}"
            port = int(match.group(1))
            relay = RetryObserver(port) if args.multi_retry else None
            with (relay if relay else contextlib.nullcontext()):
                target_port = relay.port if relay else port
                completed = subprocess.run(
                    [curl, "--http3-only", "-fsS", "--noproxy", "*", "--ipv4",
                     "--cacert", cert, "--max-time", "20", "-w", "\n%{http_version} %{http_code}\n",
                     f"https://localhost:{target_port}/first", f"https://localhost:{target_port}/second"],
                    capture_output=True, text=True, timeout=TIMEOUT)
                assert completed.returncode == 0, completed.stderr
                assert completed.stdout.count("\n3 200\n") == 2, completed.stdout
            if relay:
                assert relay.error is None, relay.error
                assert relay.retries > 0, "successful request did not traverse a QUIC Retry"
                assert relay.token_initials > 0, "client did not send a token-bearing Initial"
                assert completed.stdout.count("Mira HTTP/3 connection ") == 2, completed.stdout
                assert process.poll() is None, "multi-client server exited unexpectedly"
                print(f"observed Retry={relay.retries}, token-bearing Initial={relay.token_initials}")
            else:
                responses = re.findall(r"stream (\d+), path (/\w+)", completed.stdout)
                assert len(responses) == 2 and len({s for s, _ in responses}) == 2, completed.stdout
                assert {p for _, p in responses} == {"/first", "/second"}, completed.stdout
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
