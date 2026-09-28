#!/usr/bin/env python3
"""Independently verify RFC6455 clients and servers using Python's standard library."""
import argparse
import base64
import contextlib
import hashlib
import os
import pathlib
import queue
import threading
import socket
import struct
import subprocess
import tempfile
import zlib

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


def frame(opcode, data=b"", masked=False, final=True, compressed=False):
    data = bytes(data)
    size = len(data)
    prefix = bytes([(0x80 if final else 0) | (0x40 if compressed else 0) | opcode])
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


def receive_frame(sock, masked):
    a, b = exact(sock, 2)
    assert a & 0x30 == 0
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
        assert len(data) <= 125 and a & 0x80 and not a & 0x40
    return a & 15, data, bool(a & 0x80), bool(a & 0x40)


def receive(sock, masked):
    opcode, data, final, compressed = receive_frame(sock, masked)
    assert final and not compressed
    return opcode, data


def launch_server(binary, arguments=None):
    process = subprocess.Popen([binary, *(arguments or ["0"])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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


DEFLATE_TAIL = b"\x00\x00\xff\xff"


class DeflatePeer:
    def __init__(self, *, no_context=False, window=15):
        self.no_context = no_context
        self.window = window
        self.encoder = zlib.compressobj(wbits=-window)
        self.decoder = zlib.decompressobj(wbits=-window)

    def encode(self, payload):
        wire = self.encoder.compress(payload) + self.encoder.flush(zlib.Z_SYNC_FLUSH)
        assert wire.endswith(DEFLATE_TAIL)
        if self.no_context:
            self.encoder = zlib.compressobj(wbits=-self.window)
        return wire[:-4]

    def decode(self, wire):
        payload = self.decoder.decompress(wire + DEFLATE_TAIL, 65537)
        assert not self.decoder.unconsumed_tail and not self.decoder.unused_data
        assert not self.decoder.eof and len(payload) <= 65536
        if self.no_context:
            self.decoder = zlib.decompressobj(wbits=-self.window)
        return payload


def compression_header(mode):
    if mode == "disabled":
        return None
    result = "permessage-deflate"
    if mode in ("no-context", "server-no-context"):
        result += "; server_no_context_takeover"
    if mode in ("no-context", "client-no-context"):
        result += "; client_no_context_takeover"
    if mode == "window9":
        result += "; server_max_window_bits=9; client_max_window_bits=9"
    return result


def compression_fields(value):
    assert value, "missing permessage-deflate negotiation"
    parts = [part.strip() for part in value.split(";")]
    assert parts[0] == "permessage-deflate", value
    fields = {}
    for part in parts[1:]:
        name, separator, setting = part.partition("=")
        assert name not in fields, value
        fields[name] = setting.strip('"') if separator else None
    assert set(fields) <= {"server_no_context_takeover", "client_no_context_takeover",
                           "server_max_window_bits", "client_max_window_bits"}, value
    return fields


@contextlib.contextmanager
def extension_peer(binary, role, mode="context", protocol_mode="required"):
    listener = None
    sock = None
    process = None
    try:
        if role == "server":
            process, port = launch_server(binary, ["server", "0", mode, protocol_mode])
            sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        else:
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            process = subprocess.Popen([binary, "client", str(listener.getsockname()[1]), mode, protocol_mode],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            sock, _ = listener.accept()
            sock.settimeout(10)
        yield process, sock
    finally:
        if sock:
            sock.close()
        if listener:
            listener.close()
        if process:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)


def request_extensions(sock, protocol="mira.v1, mira.v2", extension=None):
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = ("GET /extensions HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n"
               "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n")
    if protocol is not None:
        request += "Sec-WebSocket-Protocol: " + protocol + "\r\n"
    if extension is not None:
        request += "Sec-WebSocket-Extensions: " + extension + "\r\n"
    sock.sendall((request + "\r\n").encode("ascii"))
    return key


def respond_extensions(sock, fields, protocol="mira.v2", extension=None):
    response = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                "Sec-WebSocket-Accept: " + accept(fields["sec-websocket-key"]) + "\r\n")
    if protocol is not None:
        response += "Sec-WebSocket-Protocol: " + protocol + "\r\n"
    if extension is not None:
        response += "Sec-WebSocket-Extensions: " + extension + "\r\n"
    sock.sendall((response + "\r\n").encode("ascii"))


def extension_handshake(sock, role, mode, *, negotiated=True, protocol="mira.v2"):
    extension = compression_header(mode) if negotiated else None
    if role == "server":
        offer = extension
        if offer and mode != "window9":
            offer += "; client_max_window_bits"
        key = request_extensions(sock, extension=offer)
        line, fields = head(sock)
        assert line.startswith("HTTP/1.1 101 "), line
        assert fields["sec-websocket-accept"] == accept(key)
        assert fields.get("sec-websocket-protocol") == protocol, fields
        result = fields.get("sec-websocket-extensions")
        if extension:
            parameters = compression_fields(result)
            for endpoint in ("server", "client"):
                assert (endpoint + "_no_context_takeover" in parameters) == (mode in ("no-context", endpoint + "-no-context")), parameters
                assert int(parameters.get(endpoint + "_max_window_bits", "15")) == (9 if mode == "window9" else 15)
        else:
            assert result is None, fields
    else:
        line, fields = head(sock)
        assert line == "GET /extensions HTTP/1.1", line
        assert fields["sec-websocket-version"] == "13"
        assert [part.strip() for part in fields["sec-websocket-protocol"].split(",")] == ["mira.v1", "mira.v2"]
        offer = fields.get("sec-websocket-extensions")
        if mode != "disabled":
            parameters = compression_fields(offer)
            for endpoint in ("server", "client"):
                assert (endpoint + "_no_context_takeover" in parameters) == (mode in ("no-context", endpoint + "-no-context")), parameters
            if mode == "window9":
                assert parameters["server_max_window_bits"] == "9" and parameters["client_max_window_bits"] == "9"
        else:
            assert offer is None
        respond_extensions(sock, fields, protocol, extension)


def receive_extension_message(sock, role, codec):
    masked = role == "client"
    opcode = None
    wire = bytearray()
    pings = fragments = 0
    while True:
        current, data, final, compressed = receive_frame(sock, masked)
        if current == 9:
            assert data == b"mira-fragment"
            sock.sendall(frame(10, data, not masked))
            pings += 1
            continue
        if opcode is None:
            assert current in (1, 2) and compressed == (codec is not None)
            opcode = current
        else:
            assert current == 0 and not compressed
        fragments += 1
        wire.extend(data)
        if final:
            payload = codec.decode(bytes(wire)) if codec else bytes(wire)
            assert (fragments, pings) == ((2, 1) if payload else (1, 0))
            return opcode, payload, bytes(wire)


def finish_extension(process, sock, role, mode, *, negotiated=True, protocol="mira.v2"):
    masked = role == "server"
    close = struct.pack("!H", 1000)
    sock.sendall(frame(8, close, masked))
    assert receive(sock, not masked) == (8, close)
    out, err = process.communicate(timeout=10)
    assert process.returncode == 0, (out, err)
    assert "protocol=" + (protocol or "-") + " " in out, out
    assert "compression=" + str(int(negotiated and mode != "disabled")) in out, out
    if negotiated and mode != "disabled":
        for endpoint in ("server", "client"):
            assert endpoint + "_no_context=" + str(int(mode in ("no-context", endpoint + "-no-context"))) in out, out
            assert endpoint + "_window=" + str(9 if mode == "window9" else 15) in out, out


def extension_roundtrip(binary, role, mode):
    with extension_peer(binary, role, mode) as (process, sock):
        extension_handshake(sock, role, mode)
        other = "client" if role == "server" else "server"
        sender = DeflatePeer(no_context=mode in ("no-context", other + "-no-context"),
                             window=9 if mode == "window9" else 15)
        receiver = DeflatePeer(no_context=mode in ("no-context", role + "-no-context"),
                               window=9 if mode == "window9" else 15)
        masked = role == "server"
        repeated = b"".join(hashlib.sha256(str(index).encode("ascii")).digest() for index in range(6))
        payloads = [(2, repeated), (2, repeated), (1, "\u20ac\u4e2d\u6587\u538b\u7f29\U00020000".encode("utf-8")),
                    (2, b""), (2, b"boundary" * 8192)]
        for index, (opcode, payload) in enumerate(payloads):
            if opcode == 1:
                # Keep intermediate sync tails so decoded UTF-8 also crosses frames.
                wire = sender.encoder.compress(payload[:1]) + sender.encoder.flush(zlib.Z_SYNC_FLUSH)
                cut = len(wire)
                wire += sender.encode(payload[1:])
            else:
                wire = sender.encode(payload)
                cut = max(1, len(wire) // 2)
            if index == 1 and not sender.no_context and mode != "window9":
                assert len(wire) < len(payload) // 2
                try:
                    fresh = zlib.decompressobj(wbits=-15).decompress(wire + DEFLATE_TAIL)
                except zlib.error:
                    fresh = None
                assert fresh != payload, "fixture must exercise a cross-message dictionary reference"
            sock.sendall(frame(opcode, wire[:cut], masked, False, True))
            sock.sendall(frame(9, b"python-fragment", masked))
            assert receive(sock, not masked) == (10, b"python-fragment")
            sock.sendall(frame(0, wire[cut:], masked))
            received, echoed, encoded = receive_extension_message(sock, role, receiver)
            assert received == opcode and echoed == payload
            if index == 1 and not receiver.no_context and mode != "window9":
                try:
                    fresh = zlib.decompressobj(wbits=-15).decompress(encoded + DEFLATE_TAIL)
                except zlib.error:
                    fresh = None
                assert fresh != payload, "Mira encoder must retain negotiated context"
            if index == 0:
                plain = b"uncompressed-between-compressed-messages"
                sock.sendall(frame(2, plain, masked))
                assert receive_extension_message(sock, role, receiver)[:2] == (2, plain)
        finish_extension(process, sock, role, mode)


def extension_fallback(binary, role, mode):
    with extension_peer(binary, role, mode, "optional") as (process, sock):
        extension_handshake(sock, role, mode, negotiated=False)
        masked = role == "server"
        sock.sendall(frame(1, b"extensions optional", masked))
        assert receive_extension_message(sock, role, None)[:2] == (1, b"extensions optional")
        finish_extension(process, sock, role, mode, negotiated=False)


def rejected_handshake(process, sock):
    try:
        reply = sock.recv(16384)
    except ConnectionResetError:
        reply = b""
    assert not reply.startswith(b"HTTP/1.1 101"), reply
    out, err = process.communicate(timeout=10)
    assert process.returncode == 1 and "ws handshake:" in err, (out, err)
    assert "NEGOTIATED" not in out, out


def extension_optional_protocol(binary, role):
    with extension_peer(binary, role, "disabled", "optional") as (process, sock):
        if role == "server":
            key = request_extensions(sock, "unrelated.protocol", "permessage-deflate")
            line, fields = head(sock)
            assert line.startswith("HTTP/1.1 101 ") and fields["sec-websocket-accept"] == accept(key)
            assert "sec-websocket-protocol" not in fields
            assert "sec-websocket-extensions" not in fields
        else:
            _, fields = head(sock)
            respond_extensions(sock, fields, None)
        masked = role == "server"
        sock.sendall(frame(2, b"no subprotocol selected", masked))
        assert receive_extension_message(sock, role, None)[:2] == (2, b"no subprotocol selected")
        finish_extension(process, sock, role, "disabled", negotiated=False, protocol=None)


def extension_bfinal(binary, role):
    with extension_peer(binary, role) as (process, sock):
        extension_handshake(sock, role, "context")
        payload = "BFINAL \u4e0e\u5b58\u50a8\u5757\u5c3e\u90e8".encode("utf-8")
        encoder = zlib.compressobj(wbits=-15)
        # RFC7692 requires an empty stored-block header after BFINAL; Z_FINISH alone is incomplete.
        wire = encoder.compress(payload) + encoder.flush(zlib.Z_FINISH) + b"\x00"
        masked = role == "server"
        sock.sendall(frame(1, wire, masked, compressed=True))
        assert receive_extension_message(sock, role, DeflatePeer())[:2] == (1, payload)
        finish_extension(process, sock, role, "context")


def extension_reject_context_reference(binary, role):
    with extension_peer(binary, role, "no-context") as (process, sock):
        extension_handshake(sock, role, "no-context")
        sender = DeflatePeer()
        receiver = DeflatePeer(no_context=True)
        payload = b"".join(hashlib.sha256(str(index).encode("ascii")).digest() for index in range(6))
        masked = role == "server"
        sock.sendall(frame(2, sender.encode(payload), masked, compressed=True))
        assert receive_extension_message(sock, role, receiver)[:2] == (2, payload)
        dependent = sender.encode(payload)
        try:
            fresh = zlib.decompressobj(wbits=-15).decompress(dependent + DEFLATE_TAIL)
        except zlib.error:
            fresh = None
        assert fresh != payload
        sock.sendall(frame(2, dependent, masked, compressed=True))
        opcode, data = receive(sock, not masked)
        assert opcode == 8 and data[:2] == struct.pack("!H", 1002)
        out, err = process.communicate(timeout=10)
        assert process.returncode == 1 and "ws read:" in err, (out, err)


def extension_bad_client_responses(binary):
    cases = [
        ("unsolicited_protocol", "context", "none", "mira.v2", None),
        ("tampered_protocol", "context", "required", "mira.v3", None),
        ("case_sensitive_protocol", "context", "required", "Mira.v2", None),
        ("multiple_protocols", "context", "required", "mira.v1, mira.v2", None),
        ("duplicate_protocol_header", "context", "required", "mira.v2\r\nSec-WebSocket-Protocol: mira.v2", None),
        ("missing_required_protocol", "context", "required", None, None),
        ("unsolicited_compression", "disabled", "required", "mira.v2", "permessage-deflate"),
        ("unknown_extension", "context", "required", "mira.v2", "unknown-extension"),
        ("duplicate_extension", "context", "required", "mira.v2", "permessage-deflate, permessage-deflate"),
        ("duplicate_parameter", "context", "required", "mira.v2",
         "permessage-deflate; client_max_window_bits=15; client_max_window_bits=15"),
        ("unknown_parameter", "context", "required", "mira.v2", "permessage-deflate; unknown=1"),
        ("out_of_range_window", "context", "required", "mira.v2", "permessage-deflate; server_max_window_bits=16"),
        ("tampered_window_limit", "window9", "required", "mira.v2",
         "permessage-deflate; server_max_window_bits=10; client_max_window_bits=9"),
    ]
    for name, mode, protocol_mode, protocol, extension in cases:
        with extension_peer(binary, "client", mode, protocol_mode) as (process, sock):
            _, fields = head(sock)
            respond_extensions(sock, fields, protocol, extension)
            try:
                rejected_handshake(process, sock)
            except AssertionError as exc:
                raise AssertionError(name) from exc


def extension_bad_server_requests(binary):
    for name, protocol in (("missing_required_protocol", None), ("no_shared_protocol", "mira.v3"),
                           ("case_sensitive_protocol", "Mira.v2"), ("empty_protocol", "mira.v1,,mira.v2")):
        with extension_peer(binary, "server") as (process, sock):
            request_extensions(sock, protocol, "permessage-deflate")
            try:
                rejected_handshake(process, sock)
            except AssertionError as exc:
                raise AssertionError(name) from exc


def extension_bad_frames(binary, role):
    for scenario, code in (("invalid_deflate", 1002), ("truncated_deflate", 1002),
                           ("bare_bfinal", 1002), ("compressed_control", 1002),
                           ("compressed_continuation", 1002), ("invalid_utf8", 1007),
                           ("message_limit", 1009), ("fragmented_message_limit", 1009),
                           ("unnegotiated_rsv1", 1002)):
        mode = "disabled" if scenario == "unnegotiated_rsv1" else "context"
        with extension_peer(binary, role, mode) as (process, sock):
            extension_handshake(sock, role, mode)
            masked = role == "server"
            if scenario == "compressed_control":
                wire = frame(9, b"ping", masked, compressed=True)
            elif scenario == "compressed_continuation":
                payload = DeflatePeer().encode(b"continuation")
                wire = frame(2, payload[:1], masked, False, True) + frame(0, payload[1:], masked, compressed=True)
            elif scenario == "truncated_deflate":
                wire = frame(2, DeflatePeer().encode(b"truncated")[:-1], masked, compressed=True)
            elif scenario == "bare_bfinal":
                encoder = zlib.compressobj(wbits=-15)
                wire = frame(2, encoder.compress(b"bare BFINAL") + encoder.flush(zlib.Z_FINISH), masked, compressed=True)
            else:
                opcode = 1 if scenario == "invalid_utf8" else 2
                payload = b"\xff" if scenario in ("invalid_deflate", "unnegotiated_rsv1") else DeflatePeer().encode(
                    b"\xc0\x80" if scenario == "invalid_utf8" else b"x" * 65537)
                if scenario == "fragmented_message_limit":
                    cut = len(payload) // 2
                    wire = frame(opcode, payload[:cut], masked, False, True) + frame(0, payload[cut:], masked)
                else:
                    wire = frame(opcode, payload, masked, compressed=True)
            sock.sendall(wire)
            opcode, payload = receive(sock, not masked)
            assert opcode == 8 and payload[:2] == struct.pack("!H", code), (role, scenario, opcode, payload)
            out, err = process.communicate(timeout=10)
            assert process.returncode == 1 and "ws read:" in err, (role, scenario, out, err)


def extensions(binary):
    for role in ("server", "client"):
        for mode in ("context", "no-context", "server-no-context", "client-no-context", "window9"):
            extension_roundtrip(binary, role, mode)
        for mode in ("context", "disabled"):
            extension_fallback(binary, role, mode)
        extension_optional_protocol(binary, role)
        extension_bfinal(binary, role)
        extension_reject_context_reference(binary, role)
        extension_bad_frames(binary, role)
    extension_bad_client_responses(binary)
    extension_bad_server_requests(binary)
    print("WebSocket extension interoperability: 55 independent Python zlib sessions verified")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server")
    parser.add_argument("--client")
    parser.add_argument("--wss")
    parser.add_argument("--extensions-peer", help="mira_ws_extensions_peer executable for independent extension tests")
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    if args.wss:
        wss(args.wss, args.openssl)
    elif args.server or args.client:
        if not args.server or not args.client:
            parser.error("--server and --client are required together")
        python_client(args.server)
        python_server(args.client)
        negative_server(args.server)
        negative_client(args.client)
        pair(args.server, args.client)
    elif not args.extensions_peer:
        parser.error("--server/--client, --extensions-peer, or --wss is required")
    if args.extensions_peer:
        extensions(args.extensions_peer)
    print("WebSocket independent interoperability verified")


if __name__ == "__main__":
    main()
