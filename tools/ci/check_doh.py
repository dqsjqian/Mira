#!/usr/bin/env python3
"""Independent DNS-over-HTTPS interoperability for Mira's DoH examples.

The Python peers encode and decode DNS messages with their own code (standard
library only), never Mira's:

* Python DoH client (urllib) -> mira_doh_server: GET/POST, NXDOMAIN, NODATA,
  400/405/415 error mapping, Cache-Control.
* mira_doh_client -> Python DoH server that answers with compression pointers.
* With --tls and an openssl CLI: the same over HTTPS with a throwaway CA, and
  curl --doh-url resolving a name through mira_doh_server before fetching a
  page from mira_hello_world_server. curl without DoH support is reported as
  skipped for that sub-case only.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import http.server
import queue
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT = 10
BODY = "hello from Mira's HTTP server"


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def build_query(name: str, qtype: int) -> bytes:
    return struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack(">HH", qtype, 1)


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels, jumped, end = [], False, offset
    for _ in range(64):
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if not jumped:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode())
        offset += length
    return ".".join(labels), (end if jumped else offset)


def parse_response(data: bytes) -> tuple[int, list[tuple[int, int, bytes]]]:
    ident, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    assert flags & 0x8000, "QR not set"
    offset = 12
    for _ in range(qd):
        _, offset = read_name(data, offset)
        offset += 4
    answers = []
    for _ in range(an):
        _, offset = read_name(data, offset)
        rtype, _, ttl, size = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        answers.append((rtype, ttl, data[offset:offset + size]))
        offset += size
    return flags & 0xF, answers


@contextlib.contextmanager
def spawn(arguments: list[str]):
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines: queue.Queue[str] = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: lines.put(process.stdout.readline(512)), daemon=True).start()
    try:
        line = lines.get(timeout=TIMEOUT)
        match = re.search(r"(?:PORT=|:)(\d+)\s*$", line)
        if not match:
            raise AssertionError(f"unexpected announcement from {arguments[0]}: {line!r}")
        yield int(match.group(1))
    finally:
        process.terminate()
        try:
            process.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=TIMEOUT)
        process.stdout.close()
        process.stderr.close()


def doh_fetch(base: str, name: str, qtype: int, method: str, context=None):
    query = build_query(name, qtype)
    if method == "GET":
        encoded = base64.urlsafe_b64encode(query).rstrip(b"=").decode()
        request = urllib.request.Request(f"{base}/dns-query?dns={encoded}",
                                         headers={"Accept": "application/dns-message"})
    else:
        request = urllib.request.Request(f"{base}/dns-query", data=query, method="POST",
                                         headers={"Content-Type": "application/dns-message",
                                                  "Accept": "application/dns-message"})
    with urllib.request.urlopen(request, timeout=TIMEOUT, context=context) as response:
        assert response.headers["Content-Type"].startswith("application/dns-message")
        cache = response.headers["Cache-Control"]
        return parse_response(response.read()), cache


def status_of(request: urllib.request.Request, context=None) -> int:
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT, context=context) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def check_mira_server(base: str, context=None) -> int:
    passed = 0
    for method in ("GET", "POST"):
        (rcode, answers), cache = doh_fetch(base, "Mira.Test", 1, method, context)
        assert rcode == 0 and answers == [(1, 60, bytes([127, 0, 0, 1]))], answers
        assert cache == "max-age=60", cache
        (rcode, answers), _ = doh_fetch(base, "mira.test", 28, method, context)
        assert rcode == 0 and answers == [], "NODATA expected"
        (rcode, answers), _ = doh_fetch(base, "absent.test", 1, method, context)
        assert rcode == 3 and answers == [], "NXDOMAIN expected"
        passed += 3
    assert status_of(urllib.request.Request(f"{base}/dns-query?x=1"), context) == 400
    assert status_of(urllib.request.Request(f"{base}/dns-query", data=build_query("a", 1), method="POST",
                                            headers={"Content-Type": "text/plain"}), context) == 415
    assert status_of(urllib.request.Request(f"{base}/dns-query", data=b"x", method="PUT",
                                            headers={"Content-Type": "application/dns-message"}),
                     context) == 405
    return passed + 3


class PythonDoh(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: list[str] = []

    def log_message(self, *args):
        pass

    def answer(self, query: bytes):
        name, offset = read_name(query, 12)
        qtype, _ = struct.unpack(">HH", query[offset:offset + 4])
        question = query[12:offset + 4]
        PythonDoh.seen.append(f"{self.command} {name.lower()} {qtype}")
        answers = b""
        count = 0
        if name.lower() == "peer.test" and qtype == 1:
            # CNAME at the question name (pointer 0x0C), then A at the alias.
            alias = b"\x05alias\xc0\x11"  # alias + pointer to "test" inside the question
            answers += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 30, len(alias)) + alias
            alias_offset = 12 + len(question) + 12
            answers += struct.pack(">H", 0xC000 | alias_offset) + struct.pack(">HHIH", 1, 1, 20, 4) + bytes([10, 1, 2, 3])
            count = 2
        rcode = 0 if count else 3
        header = struct.pack(">HHHHHH", 0, 0x8180 | rcode, 1, count, 0, 0)
        body = header + question + answers
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        encoded = self.path.split("dns=", 1)[1].split("&", 1)[0]
        self.answer(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))

    def do_POST(self):
        assert self.headers["Content-Type"] == "application/dns-message"
        self.answer(self.rfile.read(int(self.headers["Content-Length"])))


def run_client(arguments: list[str], ok: bool, expect: list[str] | None = None):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=TIMEOUT)
    if (result.returncode == 0) != ok:
        raise AssertionError(f"{arguments} exited {result.returncode}: {result.stdout!r} {result.stderr!r}")
    for line in expect or []:
        if line not in result.stdout:
            raise AssertionError(f"missing {line!r} in {result.stdout!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--http-server", required=True)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--openssl", default=shutil.which("openssl") or "openssl")
    args = parser.parse_args()
    passed = 0
    zone = ["mira.test=127.0.0.1"]
    with spawn([args.server, "0", "60000", *zone]) as port:
        passed += check_mira_server(f"http://127.0.0.1:{port}")
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PythonDoh)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        peer_port = httpd.server_address[1]
        for method in ("get", "post"):
            run_client([args.client, "127.0.0.1", str(peer_port), "peer.test", "A", method, "--plain"], True,
                       ["RCODE 0", "ANSWER 5 30 alias.test", "ANSWER 1 20 10.1.2.3"])
            run_client([args.client, "127.0.0.1", str(peer_port), "gone.test", "A", method, "--plain"], True,
                       ["RCODE 3"])
            passed += 2
        assert "GET peer.test 1" in PythonDoh.seen and "POST peer.test 1" in PythonDoh.seen
    finally:
        httpd.shutdown()
        httpd.server_close()
    tls_note = "not built"
    curl_note = "not run"
    if args.tls:
        openssl = shutil.which(args.openssl) or (args.openssl if Path(args.openssl).exists() else None)
        if not openssl:
            tls_note = "SKIPPED (no openssl CLI)"
        else:
            with tempfile.TemporaryDirectory() as directory:
                cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
                config = Path(directory) / "openssl.cnf"
                config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
                subprocess.run([openssl, "req", "-config", str(config), "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                                "-out", str(cert), "-days", "2", "-subj", "/CN=localhost",
                                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                               check=True, capture_output=True, timeout=60)
                context = ssl.create_default_context(cafile=str(cert))
                with spawn([args.server, "0", "60000", str(cert), str(key), *zone]) as port:
                    passed += check_mira_server(f"https://localhost:{port}", context)
                    run_client([args.client, "localhost", str(port), "mira.test", "A", "post", "--ca", str(cert)],
                               True, ["RCODE 0", "ANSWER 1 60 127.0.0.1"])
                    passed += 1
                    tls_note = "ran"
                    curl = shutil.which("curl")
                    if not curl:
                        curl_note = "SKIPPED (no curl)"
                    else:
                        with spawn([args.http_server, "0"]) as http_port:
                            result = subprocess.run(
                                [curl, "-sS", "--max-time", "8", "--doh-url", f"https://localhost:{port}/dns-query",
                                 "--cacert", str(cert), f"http://mira.test:{http_port}/"],
                                capture_output=True, text=True, timeout=TIMEOUT)
                        unsupported = result.returncode in (2, 4) or "doh-url" in result.stderr
                        if unsupported:
                            curl_note = f"SKIPPED (curl without DoH: {result.stderr.strip()!r})"
                        elif result.returncode != 0 or BODY not in result.stdout:
                            raise AssertionError(f"curl --doh-url failed: {result.returncode} {result.stderr!r}")
                        else:
                            passed += 1
                            curl_note = "ran"
    print(f"DoH interop: {passed} cases passed; TLS {tls_note}; curl --doh-url {curl_note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
