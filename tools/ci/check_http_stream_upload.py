#!/usr/bin/env python3
"""Verify HTTP/HTTPS chunk production, early sending and reuse with independent peers."""

import argparse
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading


def certificates(directory, openssl):
    # install_sw and relocatable OpenSSL builds need not ship openssl.cnf.
    config = directory / "openssl.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
    def run(*arguments):
        subprocess.run([openssl, *arguments], cwd=directory, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    for name in ("ca", "unrelated"):
        run("req", "-config", str(config), "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-pkeyopt", "ec_param_enc:named_curve",
            "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.pem", "-days", "1",
            "-subj", f"/CN=Mira {name}", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-config", str(config), "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-pkeyopt", "ec_param_enc:named_curve",
        "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=localhost")
    extension = directory / "server.ext"
    extension.write_text("basicConstraints=critical,CA:FALSE\n"
                         "keyUsage=critical,digitalSignature\n"
                         "extendedKeyUsage=serverAuth\n"
                         "subjectAltName=DNS:localhost,IP:127.0.0.1\n", encoding="ascii")
    run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-CAcreateserial", "-out", "server.pem", "-days", "1", "-extfile", "server.ext")


class Server:
    def __init__(self, directory, tls):
        self.directory = directory
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.context = None
        if tls:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.context.load_cert_chain(directory / "server.pem", directory / "server.key")
            self.context.set_alpn_protocols(["http/1.1"])
        self.stop = threading.Event()
        self.errors = []
        self.workers = []
        self.requests = []
        self.accepted = 0
        self.handshakes = 0
        self.failed_handshakes = 0
        self.lock = threading.Lock()

    def serve(self, connection, identity):
        try:
            connection.settimeout(12)
            if self.context:
                try:
                    connection = self.context.wrap_socket(connection, server_side=True)
                except ssl.SSLError:
                    with self.lock:
                        self.failed_handshakes += 1
                    return
                with self.lock:
                    self.handshakes += 1
            with connection, connection.makefile("rb") as stream:
                while not self.stop.is_set():
                    start = stream.readline(8193)
                    if not start:
                        return
                    assert len(start) <= 8192 and start.endswith(b"\r\n")
                    method, target, version = start.decode("ascii").strip().split(" ")
                    assert version == "HTTP/1.1"
                    headers = {}
                    for _ in range(101):
                        line = stream.readline(8193)
                        assert len(line) <= 8192 and line.endswith(b"\r\n")
                        if line == b"\r\n":
                            break
                        name, value = line.decode("ascii").strip().split(":", 1)
                        name = name.lower()
                        assert name not in headers
                        headers[name] = value.strip()
                    else:
                        raise AssertionError("header count limit")
                    assert headers["host"] == f"localhost:{self.port}"
                    assert not ("content-length" in headers and "transfer-encoding" in headers)
                    if target in ("/bad", "/stall"):
                        assert method == "GET" and headers["content-length"] == "0"
                        with self.lock:
                            self.requests.append((identity, target))
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
                        if target == "/bad":
                            connection.sendall(b"short")
                        else:
                            self.stop.wait(10)
                        return
                    if target == "/identity":
                        assert method == "GET" and headers["content-length"] == "0"
                    else:
                        assert method == "POST"
                        round_number = int(target.rsplit("/", 1)[1])
                        chunked = round_number % 2 == 1
                        if chunked:
                            assert headers["transfer-encoding"] == "chunked"
                        else:
                            assert headers["content-length"] == str(32 * 8192)
                        for part in range(32):
                            if chunked:
                                assert stream.readline(64) == b"2000\r\n"
                            payload = stream.read(8192)
                            assert payload == bytes([ord("a") + part % 26]) * 8192
                            if chunked:
                                assert stream.read(2) == b"\r\n"
                            if part == 0:
                                # The client cannot produce its second chunk before this marker.
                                (self.directory / f"observed.{round_number}").touch()
                        if chunked:
                            assert stream.read(5) == b"0\r\n\r\n"
                    with self.lock:
                        self.requests.append((identity, target))
                    wire = (f"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                            f"X-Connection: {identity}\r\n\r\nok").encode("ascii")
                    connection.sendall(wire)
        except Exception as error:
            with self.lock:
                self.errors.append(repr(error))
        finally:
            connection.close()

    def run(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.accepted += 1
            worker = threading.Thread(target=self.serve, args=(connection, self.accepted))
            self.workers.append(worker)
            worker.start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("peer", type=pathlib.Path)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    peer = args.peer.resolve()
    with tempfile.TemporaryDirectory(prefix="http-upload-", dir=peer.parent) as temporary:
        directory = pathlib.Path(temporary)
        if args.tls:
            certificates(directory, args.openssl)
        server = Server(directory, args.tls)
        thread = threading.Thread(target=server.run)
        thread.start()
        command = [str(peer), str(server.port), str(directory / "observed")]
        if args.tls:
            command += [str(directory / "ca.pem"), str(directory / "unrelated.pem")]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        finally:
            server.stop.set()
            server.listener.close()
            thread.join()
            for worker in server.workers:
                worker.join(15)
        assert result.returncode == 0, result.stdout + result.stderr
        assert not server.errors, server.errors
        uploads = [item for item in server.requests if item[1].startswith("/upload/")]
        assert len(uploads) == 4 and len({item[0] for item in uploads}) == 1, server.requests
        assert all((directory / f"observed.{i}").exists() for i in range(4))
        if args.tls:
            assert server.handshakes == 3, server.handshakes
            assert server.failed_handshakes == 1, server.failed_handshakes
            assert len(server.requests) == 7, server.requests
        else:
            assert server.accepted == 1, server.accepted
        print("PASS", "HTTPS" if args.tls else "HTTP",
              "known-length/chunked streaming, per-chunk observation, keep-alive, TLS isolation")


if __name__ == "__main__":
    main()
