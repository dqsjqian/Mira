#!/usr/bin/env python3
"""Independent SOCKS5 interoperability for Mira's proxy and client examples.

Peers are written from RFC 1928/1929 with the Python standard library only,
plus system curl when present:

* curl (--socks5-hostname / socks5h://user:pass@) -> mira_socks5_server -> HTTP
* Python SOCKS5 client -> mira_socks5_server (no-auth, password, wrong password,
  unsupported command, IPv4 and domain targets)
* mira_socks5_client -> Python SOCKS5 server (no-auth, password, refused target)

curl sub-cases are skipped (reported) when curl is missing; the rest always run.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading

TIMEOUT = 10
BODY = "hello from Mira's HTTP server"


@contextmanager
def spawn(arguments: list[str], pattern: str):
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines: queue.Queue[str] = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: lines.put(process.stdout.readline(512)), daemon=True).start()
    try:
        line = lines.get(timeout=TIMEOUT)
        match = re.search(pattern, line)
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


def recv_exact(conn: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise ConnectionError("peer closed during SOCKS handshake")
        data += chunk
    return data


def encode_target(host: str, port: int) -> bytes:
    try:
        return b"\x01" + socket.inet_pton(socket.AF_INET, host) + struct.pack(">H", port)
    except OSError:
        pass
    try:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, host) + struct.pack(">H", port)
    except OSError:
        name = host.encode()
        return b"\x03" + bytes([len(name)]) + name + struct.pack(">H", port)


def read_address(conn: socket.socket) -> tuple[str, int]:
    atyp = recv_exact(conn, 1)[0]
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(conn, 4))
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(conn, 16))
    elif atyp == 3:
        host = recv_exact(conn, recv_exact(conn, 1)[0]).decode()
    else:
        raise AssertionError(f"bad ATYP {atyp}")
    return host, struct.unpack(">H", recv_exact(conn, 2))[0]


# ── independent client ────────────────────────────────────────────────────────

def python_client(proxy: int, host: str, port: int, credentials=None, command: int = 1) -> tuple[int, bytes]:
    """Return (REP or -1 for auth failure, HTTP response bytes)."""
    with socket.create_connection(("127.0.0.1", proxy), timeout=TIMEOUT) as conn:
        methods = b"\x02" if credentials else b"\x00"
        conn.sendall(b"\x05" + bytes([len(methods)]) + methods)
        version, method = recv_exact(conn, 2)
        assert version == 5, version
        if credentials:
            assert method == 2, method
            user, password = (part.encode() for part in credentials)
            conn.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
            if recv_exact(conn, 2) != b"\x01\x00":
                return -1, b""
        else:
            assert method == 0, method
        conn.sendall(b"\x05" + bytes([command]) + b"\x00" + encode_target(host, port))
        version, rep, reserved = recv_exact(conn, 3)
        assert version == 5 and reserved == 0
        read_address(conn)
        if rep != 0:
            return rep, b""
        conn.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        response = b""
        while chunk := conn.recv(65536):
            response += chunk
        return 0, response


# ── independent server ────────────────────────────────────────────────────────

class PythonProxy:
    def __init__(self, credentials=None):
        self.credentials = credentials
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.targets: list[tuple[str, int]] = []
        threading.Thread(target=self.accept_loop, daemon=True).start()

    def accept_loop(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn: socket.socket):
        with conn:
            conn.settimeout(TIMEOUT)
            version, count = recv_exact(conn, 2)
            methods = recv_exact(conn, count)
            wanted = 2 if self.credentials else 0
            if version != 5 or wanted not in methods:
                conn.sendall(b"\x05\xff")
                return
            conn.sendall(bytes([5, wanted]))
            if self.credentials:
                assert recv_exact(conn, 1) == b"\x01"
                user = recv_exact(conn, recv_exact(conn, 1)[0]).decode()
                password = recv_exact(conn, recv_exact(conn, 1)[0]).decode()
                ok = (user, password) == self.credentials
                conn.sendall(b"\x01" + (b"\x00" if ok else b"\x01"))
                if not ok:
                    return
            version, command, reserved = recv_exact(conn, 3)
            host, port = read_address(conn)
            self.targets.append((host, port))
            try:
                upstream = socket.create_connection((host, port), timeout=TIMEOUT)
            except ConnectionRefusedError:
                conn.sendall(b"\x05\x05\x00\x01" + bytes(6))
                return
            with upstream:
                local = upstream.getsockname()
                conn.sendall(b"\x05\x00\x00" + encode_target(local[0], local[1]))
                self.relay(conn, upstream)

    @staticmethod
    def relay(a: socket.socket, b: socket.socket):
        def pump(src, dst):
            try:
                while chunk := src.recv(65536):
                    dst.sendall(chunk)
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        other = threading.Thread(target=pump, args=(b, a), daemon=True)
        other.start()
        pump(a, b)
        other.join(TIMEOUT)

    def close(self):
        self.listener.close()


def run(arguments: list[str], ok: bool, expect: str | None = None, error: str | None = None):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=TIMEOUT)
    if (result.returncode == 0) != ok:
        raise AssertionError(f"{arguments} exited {result.returncode}: {result.stdout!r} {result.stderr!r}")
    if expect and expect not in result.stdout:
        raise AssertionError(f"missing {expect!r} in {result.stdout!r}")
    if error and error not in result.stderr:
        raise AssertionError(f"missing {error!r} in {result.stderr!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--http-server", required=True)
    args = parser.parse_args()
    passed = 0
    curl = shutil.which("curl")
    with spawn([args.http_server, "0"], r":(\d+)\s*$") as http_port:
        # Independent clients -> Mira proxy.
        with spawn([args.proxy, "0", "30000"], r"PORT=(\d+)") as open_proxy:
            for host in ("127.0.0.1", "localhost"):
                rep, response = python_client(open_proxy, host, http_port)
                assert rep == 0 and response.startswith(b"HTTP/1.1 200") and BODY.encode() in response
                passed += 1
            rep, _ = python_client(open_proxy, "127.0.0.1", http_port, command=2)
            assert rep == 7, rep  # BIND refused
            passed += 1
            closed = socket.create_server(("127.0.0.1", 0))
            dead_port = closed.getsockname()[1]
            closed.close()
            rep, _ = python_client(open_proxy, "127.0.0.1", dead_port)
            assert rep == 5, rep  # connection refused mapped to REP 0x05
            passed += 1
            if curl:
                run([curl, "-sS", "--max-time", "5", "--socks5-hostname", f"127.0.0.1:{open_proxy}",
                     f"http://localhost:{http_port}/"], True, BODY)
                passed += 1
        with spawn([args.proxy, "0", "30000", "alice", "s3cret"], r"PORT=(\d+)") as locked:
            rep, response = python_client(locked, "localhost", http_port, ("alice", "s3cret"))
            assert rep == 0 and BODY.encode() in response
            rep, _ = python_client(locked, "localhost", http_port, ("alice", "wrong"))
            assert rep == -1
            passed += 2
            if curl:
                run([curl, "-sS", "--max-time", "5", "--proxy", f"socks5h://alice:s3cret@127.0.0.1:{locked}",
                     f"http://localhost:{http_port}/"], True, BODY)
                run([curl, "-sS", "--max-time", "5", "--proxy", f"socks5h://alice:nope@127.0.0.1:{locked}",
                     f"http://localhost:{http_port}/"], False)
                passed += 2
        # Mira client -> independent proxy.
        proxy = PythonProxy()
        try:
            for host in ("localhost", "127.0.0.1"):
                run([args.client, str(proxy.port), host, str(http_port)], True, BODY)
                passed += 1
            assert ("localhost", http_port) in proxy.targets  # domain forwarded unresolved
            closed = socket.create_server(("127.0.0.1", 0))
            dead_port = closed.getsockname()[1]
            closed.close()
            run([args.client, str(proxy.port), "127.0.0.1", str(dead_port)], False, error="refused")
            passed += 1
        finally:
            proxy.close()
        secured = PythonProxy(("bob", "pw"))
        try:
            run([args.client, str(secured.port), "localhost", str(http_port), "bob", "pw"], True, BODY)
            run([args.client, str(secured.port), "localhost", str(http_port), "bob", "bad"], False,
                error="authentication")
            passed += 2
        finally:
            secured.close()
    print(f"SOCKS5 interop: {passed} cases passed; curl {'ran' if curl else 'SKIPPED (not found)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
