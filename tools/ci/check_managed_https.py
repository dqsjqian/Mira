#!/usr/bin/env python3
"""Exercise managed HTTPS with verified Python SSL/H1 and independent curl/H2."""
from __future__ import annotations

import argparse
import pathlib
import queue
import re
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from check_h2_interop import curl_supports_http2


class Server:
    def __init__(self, executable, cert, key, *, connections=8, handshakes=4,
                 lifetime=2500, handshake_timeout=500, grace=100):
        self.process = subprocess.Popen(
            [str(executable), str(cert), str(key), "0", str(connections), str(handshakes),
             str(lifetime), str(handshake_timeout), str(grace)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        try:
            self.port = int(self.event("PORT=").partition("=")[2])
        except BaseException:
            self.close()
            raise

    def _read(self):
        for line in self.process.stdout:
            self.lines.put(line.strip())
        self.lines.put(None)

    def event(self, prefix, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            line = self.lines.get(timeout=max(0, deadline - time.monotonic()))
            if line is None:
                raise AssertionError(f"server exited before {prefix!r}: {self.process.stderr.read()}")
            if line.startswith(prefix):
                return line

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=5)

    def finish(self):
        line = self.event("accepted=")
        self.process.wait(timeout=10)
        errors = self.process.stderr.read()
        assert self.process.returncode == 0, (self.process.returncode, errors)
        assert not errors, errors
        stats = {key: int(value) for key, value in re.findall(r"(\w+)=(\d+)", line)}
        assert stats["accepted"] == stats["rejected"] + stats["completed"], stats
        return stats

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        self.process.stdout.close()
        self.process.stderr.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def context(cert, protocols=("http/1.1",)):
    result = ssl.create_default_context(cafile=str(cert))
    result.minimum_version = ssl.TLSVersion.TLSv1_2
    if protocols:
        result.set_alpn_protocols(list(protocols))
    assert result.check_hostname and result.verify_mode == ssl.CERT_REQUIRED
    return result


def h1(server, cert):
    with context(cert).wrap_socket(server.connect(), server_hostname="localhost",
                                   suppress_ragged_eofs=False) as client:
        assert client.selected_alpn_protocol() == "http/1.1"
        client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        response = bytearray()
        while chunk := client.recv(4096):
            response.extend(chunk)
        head, body = bytes(response).split(b"\r\n\r\n", 1)
        assert head.startswith(b"HTTP/1.1 200"), head
        assert body == b"managed HTTPS: http/1.1\n", body


def rejected_socket(client):
    try:
        assert client.recv(1) == b"", "admission-rejected connection received application data"
    except (ConnectionResetError, ssl.SSLEOFError):
        pass


def h2(server, cert, curl):
    completed = subprocess.run(
        [curl, "--http2", "--noproxy", "*", "--cacert", str(cert),
         "--resolve", f"localhost:{server.port}:127.0.0.1", "-fsS", "--max-time", "5",
         f"https://localhost:{server.port}/", "-w", "\n%{http_version} %{http_code}"],
        capture_output=True, text=True, timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    body, _, stats = completed.stdout.rpartition("\n")
    assert body == "managed HTTPS: h2\n", completed.stdout
    assert stats == "2 200", f"ALPN did not dispatch HTTP/2: {stats!r}"


def invalid_clients(server, cert):
    for tls, hostname in ((context(cert), "wrong.invalid"),
                          (ssl.create_default_context(), "localhost")):
        tls.set_alpn_protocols(["http/1.1"])
        try:
            with tls.wrap_socket(server.connect(), server_hostname=hostname):
                raise AssertionError("untrusted certificate or hostname was accepted")
        except ssl.SSLCertVerificationError:
            pass
    try:
        with context(cert, ("unsupported-protocol",)).wrap_socket(
                server.connect(), server_hostname="localhost"):
            raise AssertionError("unsupported ALPN was accepted")
    except ssl.SSLError:
        pass
    with context(cert, ()).wrap_socket(server.connect(), server_hostname="localhost") as client:
        assert client.selected_alpn_protocol() is None
        rejected_socket(client)


def verify_handshake_limit(executable, cert, key):
    with Server(executable, cert, key, connections=4, handshakes=1,
                lifetime=1500, handshake_timeout=200) as server:
        with server.connect() as stalled:
            server.event("HANDSHAKE_START")
            with server.connect() as rejected:
                server.event("HANDSHAKE_REJECTED")
                rejected_socket(rejected)
            # Dribble a ClientHello across many reads. A per-read timeout would
            # keep resetting; only the absolute handshake budget closes it.
            outgoing = ssl.MemoryBIO()
            engine = context(cert).wrap_bio(ssl.MemoryBIO(), outgoing,
                                             server_side=False, server_hostname="localhost")
            try:
                engine.do_handshake()
            except ssl.SSLWantReadError:
                pass
            hello = outgoing.read()
            assert len(hello) > 32
            start = time.monotonic()
            sent = 0
            for byte in hello:
                try:
                    stalled.sendall(bytes((byte,)))
                except (BrokenPipeError, ConnectionResetError):
                    break
                sent += 1
                readable, _, _ = select.select([stalled], [], [], 0.025)
                if readable:
                    rejected_socket(stalled)
                    break
            assert sent < len(hello), "slow ClientHello refreshed the handshake budget"
            assert time.monotonic() - start < 3, "absolute handshake budget did not expire"
            server.event("HANDSHAKE_TIMEOUT")
            rejected_socket(stalled)
        h1(server, cert)
        stats = server.finish()
        assert stats["handshake_rejected"] == 1 and stats["handshake_timeouts"] == 1, stats
        assert stats["peak_handshakes"] == 1 and stats["h1"] == 1, stats
        assert stats["rejected"] == 0 and stats["completed"] == 3, stats


def verify_connection_limit(executable, cert, key):
    with Server(executable, cert, key, connections=1, handshakes=1,
                lifetime=600, grace=30) as server:
        with context(cert).wrap_socket(server.connect(), server_hostname="localhost") as idle:
            server.event("HANDSHAKE_READY")
            with server.connect() as rejected:
                rejected_socket(rejected)
            # Hold established TLS idle through admission stop and grace expiry.
            rejected_socket(idle)
        stats = server.finish()
        assert stats["rejected"] == 1 and stats["peak_active"] == 1, stats
        assert stats["cancelled"] == 1 and stats["handshake_rejected"] == 0, stats


def verify_pending_handshake_shutdown(executable, cert, key):
    with Server(executable, cert, key, connections=1, handshakes=1,
                lifetime=600, handshake_timeout=5000, grace=30) as server:
        with server.connect() as stalled:
            server.event("HANDSHAKE_START")
            rejected_socket(stalled)
        stats = server.finish()
        assert stats["completed"] == 1 and stats["cancelled"] == 1, stats
        assert stats["handshake_timeouts"] == 0 and stats["handshake_completed"] == 0, stats


def certificate(openssl, directory, name):
    cert = directory / f"{name}.pem"
    key = directory / f"{name}.key"
    result = subprocess.run(
        [openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-days", "1", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
         "-keyout", str(key), "-out", str(cert)],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    return cert, key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=pathlib.Path)
    parser.add_argument("--curl")
    parser.add_argument("--openssl", default=shutil.which("openssl"))
    args = parser.parse_args()
    repository = pathlib.Path(__file__).resolve().parents[2]
    candidates = [args.curl] if args.curl else [
        str(repository / "build/curl-interop/cmake/src/curl"), shutil.which("curl")]
    curl = next((candidate for candidate in candidates if candidate and
                 pathlib.Path(candidate).is_file() and curl_supports_http2(candidate)), None)
    if not args.openssl:
        print("managed HTTPS: SKIPPED (openssl certificate tool unavailable)")
        return 77
    with tempfile.TemporaryDirectory(prefix="managed-https-", dir=args.executable.resolve().parent) as name:
        directory = pathlib.Path(name)
        cert, key = certificate(args.openssl, directory, "server")
        _, wrong_key = certificate(args.openssl, directory, "other")
        invalid = subprocess.run([str(args.executable), str(cert), str(wrong_key)],
                                 capture_output=True, text=True, timeout=5)
        assert invalid.returncode != 0 and "PORT=" not in invalid.stdout, invalid
        with Server(args.executable, cert, key) as server:
            h1(server, cert)
            if curl:
                h2(server, cert, curl)
            invalid_clients(server, cert)
            stats = server.finish()
            assert stats["h1"] == 1 and stats["h2"] == (1 if curl else 0), stats
            assert stats["alpn_rejected"] == 1 and stats["failed"] >= 3, stats
        verify_handshake_limit(args.executable, cert, key)
        verify_connection_limit(args.executable, cert, key)
        verify_pending_handshake_shutdown(args.executable, cert, key)
    if not curl:
        print("managed HTTPS: H1/certificates/ALPN rejection/admission verified; H2 SKIPPED (no HTTP/2 curl)")
        return 77
    print("managed HTTPS: verified H1/H2 ALPN, certificates, handshake timeout, dual admission and joined shutdown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
