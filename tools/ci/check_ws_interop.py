#!/usr/bin/env python3
"""Independently verify RFC6455 clients and servers using Python's standard library."""
import argparse
import base64
import hashlib
import os
import pathlib
import queue
import threading
import socket
import struct
import subprocess
import tempfile

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def exact(sock, count):
    out = bytearray()
    while len(out) < count:
        chunk = sock.recv(count - len(out))
        if not chunk:
            raise AssertionError("unexpected EOF")
        out.extend(chunk)
    return bytes(out)


def head(sock):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        assert len(result) < 16384
        result.extend(exact(sock, 1))
    lines = result.decode("ascii").split("\r\n")
    fields = {}
    for line in lines[1:-2]:
        key, value = line.split(":", 1)
        assert key.lower() not in fields
        fields[key.lower()] = value.strip()
    return lines[0], fields


def accept(key):
    assert len(base64.b64decode(key, validate=True)) == 16
    return base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")


def frame(opcode, data=b"", masked=False, final=True):
    data = bytes(data)
    size = len(data)
    prefix = bytes([(0x80 if final else 0) | opcode])
    flag = 0x80 if masked else 0
    if size < 126:
        prefix += bytes([flag | size])
    elif size < 65536:
        prefix += bytes([flag | 126]) + struct.pack("!H", size)
    else:
        prefix += bytes([flag | 127]) + struct.pack("!Q", size)
    if masked:
        mask = os.urandom(4)
        prefix += mask
        data = bytes(value ^ mask[i % 4] for i, value in enumerate(data))
    return prefix + data


def receive(sock, masked):
    a, b = exact(sock, 2)
    assert a & 0x70 == 0 and a & 0x80
    assert bool(b & 0x80) == masked
    size = b & 127
    if size == 126:
        size = struct.unpack("!H", exact(sock, 2))[0]
        assert size >= 126
    elif size == 127:
        size = struct.unpack("!Q", exact(sock, 8))[0]
        assert 65536 <= size < 2**63
    assert size <= 4 * 1024 * 1024
    mask = exact(sock, 4) if masked else None
    data = exact(sock, size)
    if mask:
        data = bytes(value ^ mask[i % 4] for i, value in enumerate(data))
    if a & 15 >= 8:
        assert len(data) <= 125
    return a & 15, data


def launch_server(binary):
    process = subprocess.Popen([binary, "0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        lines = queue.Queue()
        threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
        line = lines.get(timeout=10).strip()
        assert line.startswith("ws listening "), line
        return process, int(line.rsplit(" ", 1)[1])
    except BaseException:
        process.terminate()
        process.communicate(timeout=5)
        raise


def client_handshake(sock):
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = ("GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\n"
               "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n")
    for byte in request.encode("ascii"):
        sock.sendall(bytes([byte]))
    line, fields = head(sock)
    assert line.startswith("HTTP/1.1 101 ")
    assert fields["upgrade"].lower() == "websocket"
    assert "upgrade" in fields["connection"].lower().split(",")
    assert fields["sec-websocket-accept"] == accept(key)


def python_client(binary):
    process, port = launch_server(binary)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            client_handshake(sock)
            sock.sendall(frame(1, b"\xe2", True, False))
            sock.sendall(frame(9, b"ping", True))
            assert receive(sock, False) == (10, b"ping")
            sock.sendall(frame(0, b"\x82\xac", True))
            assert receive(sock, False) == (1, "€".encode())
            for length in (0, 125, 126, 65536):
                payload = bytes(i % 256 for i in range(length))
                sock.sendall(frame(2, payload, True))
                assert receive(sock, False) == (2, payload)
            sock.sendall(frame(8, struct.pack("!H", 1000), True))
            assert receive(sock, False) == (8, struct.pack("!H", 1000))
        out, err = process.communicate(timeout=10)
        assert process.returncode == 0, (out, err)
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)


def python_server(binary):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
        process = subprocess.Popen([binary, str(listener.getsockname()[1])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            sock, _ = listener.accept()
            with sock:
                sock.settimeout(10)
                line, fields = head(sock)
                assert line == "GET /echo HTTP/1.1"
                assert fields["upgrade"].lower() == "websocket"
                assert fields["connection"].lower() == "upgrade"
                assert fields["sec-websocket-version"] == "13"
                response = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                            "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept(fields["sec-websocket-key"]) + "\r\n\r\n")
                sock.sendall(response.encode("ascii"))
                opcode, payload = receive(sock, True)
                assert opcode == 1 and payload == b"Mira WebSocket echo"
                for byte in frame(opcode, payload):
                    sock.sendall(bytes([byte]))
                opcode, payload = receive(sock, True)
                assert opcode == 8 and payload == struct.pack("!H", 1000)
                sock.sendall(frame(opcode, payload))
            out, err = process.communicate(timeout=10)
            assert process.returncode == 0 and "echo verified" in out, (out, err)
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)


def negative_server(binary):
    for wire in (frame(1, b"unmasked"), b"\x82\xfe\x00\x01" + b"\x00" * 4,
                 frame(1, b"\xc0\x80", True), frame(8, b"\x03\xed", True)):
        process, port = launch_server(binary)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
                client_handshake(sock)
                sock.sendall(wire)
                opcode, payload = receive(sock, False)
                assert opcode == 8 and struct.unpack("!H", payload[:2])[0] in (1002, 1007)
            process.communicate(timeout=10)
            assert process.returncode != 0
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)


def negative_client(binary):
    for scenario in ("wrong_accept", "masked_server", "abrupt_close"):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            process = subprocess.Popen([binary, str(listener.getsockname()[1])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                sock, _ = listener.accept()
                with sock:
                    sock.settimeout(10)
                    _, fields = head(sock)
                    accepted = accept(fields["sec-websocket-key"])
                    if scenario == "wrong_accept":
                        accepted = "wrong"
                    response = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                                "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accepted + "\r\n\r\n")
                    sock.sendall(response.encode("ascii"))
                    if scenario != "wrong_accept":
                        opcode, payload = receive(sock, True)
                        if scenario == "masked_server":
                            sock.sendall(frame(opcode, payload, True))
                            opcode, payload = receive(sock, True)
                            assert opcode == 8 and payload[:2] == struct.pack("!H", 1002)
                process.communicate(timeout=10)
                assert process.returncode != 0
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=5)


def pair(server, client):
    process, port = launch_server(server)
    try:
        subprocess.run([client, str(port)], check=True, capture_output=True, timeout=15)
        out, err = process.communicate(timeout=10)
        assert process.returncode == 0, (out, err)
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)


def wss(binary, openssl):
    with tempfile.TemporaryDirectory(prefix="mira-wss-") as directory:
        certificate = str(pathlib.Path(directory) / "cert.pem")
        key = str(pathlib.Path(directory) / "key.pem")
        config = pathlib.Path(directory) / "openssl.cnf"
        config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="utf-8")
        subprocess.run([openssl, "req", "-config", str(config), "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                        "-out", certificate, "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                       check=True, capture_output=True, timeout=20)
        subprocess.run([binary, certificate, key], check=True, timeout=25)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server")
    parser.add_argument("--client")
    parser.add_argument("--wss")
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    if args.wss:
        wss(args.wss, args.openssl)
    else:
        if not args.server or not args.client:
            parser.error("--server and --client are required")
        python_client(args.server)
        python_server(args.client)
        negative_server(args.server)
        negative_client(args.client)
        pair(args.server, args.client)
    print("WebSocket independent interoperability verified")


if __name__ == "__main__":
    main()
