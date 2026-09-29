#!/usr/bin/env python3
"""Independent MQTT interoperability for mira_mqtt_client.

The broker here is written from the OASIS MQTT 3.1.1 and 5.0 specifications
with the Python standard library only, and is strict about what it accepts:
minimal remaining-length encodings, fixed-header flags, UTF-8 strings, packet
identifiers and the CONNECT layout. It routes between separate client
processes, keeps retained messages, answers PINGREQ, and can require a
username and password.

Cases, for 3.1.1 and 5.0: publish -> subscriber at QoS 0/1/2, wildcard
routing, retained delivery, the echo round trip, refused credentials, and
keep-alive PINGREQs from an idle subscriber. When a `mosquitto` broker binary
is found (or --mosquitto names one), the same pub/sub cases also run against
it; otherwise that part is reported as skipped, unless MIRA_REQUIRE_MOSQUITTO=1
turns the absence into a failure (CI sets it).
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

TIMEOUT = 15


class Malformed(Exception):
    pass


def read_exact(conn: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise ConnectionError("peer closed")
        data += chunk
    return data


def encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        digit = value % 128
        value //= 128
        out.append(digit | (0x80 if value else 0))
        if not value:
            return bytes(out)


def read_packet(conn: socket.socket) -> tuple[int, int, bytes]:
    first = read_exact(conn, 1)[0]
    value, scale = 0, 1
    for index in range(4):
        digit = read_exact(conn, 1)[0]
        value += (digit & 0x7F) * scale
        if not digit & 0x80:
            if index and digit == 0:
                raise Malformed("non-minimal remaining length")
            break
        scale *= 128
    else:
        raise Malformed("remaining length longer than four bytes")
    return first >> 4, first & 0x0F, read_exact(conn, value)


class Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, count: int) -> bytes:
        if self.pos + count > len(self.data):
            raise Malformed("truncated")
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def varint(self) -> int:
        value, scale = 0, 1
        for _ in range(4):
            digit = self.u8()
            value += (digit & 0x7F) * scale
            if not digit & 0x80:
                return value
            scale *= 128
        raise Malformed("bad varint")

    def text(self) -> str:
        raw = self.take(self.u16())
        value = raw.decode("utf-8")  # Raises on ill-formed UTF-8, including surrogates.
        if "\x00" in value:
            raise Malformed("U+0000 in string")
        return value

    def binary(self) -> bytes:
        return self.take(self.u16())

    def properties(self) -> dict[int, list]:
        end = self.varint()
        block = Reader(self.take(end))
        found: dict[int, list] = {}
        while block.pos < len(block.data):
            ident = block.varint()
            if ident in (0x01, 0x17, 0x19, 0x24, 0x25, 0x28, 0x29, 0x2A):
                value = block.u8()
            elif ident in (0x13, 0x21, 0x22, 0x23):
                value = block.u16()
            elif ident in (0x02, 0x11, 0x18, 0x27):
                value = int.from_bytes(block.take(4), "big")
            elif ident == 0x0B:
                value = block.varint()
            elif ident in (0x03, 0x08, 0x12, 0x15, 0x1A, 0x1C, 0x1F):
                value = block.text()
            elif ident in (0x09, 0x16):
                value = block.binary()
            elif ident == 0x26:
                value = (block.text(), block.text())
            else:
                raise Malformed(f"unknown property {ident:#x}")
            found.setdefault(ident, []).append(value)
        return found

    def done(self) -> None:
        if self.pos != len(self.data):
            raise Malformed("trailing bytes")


def valid_topic(topic: str) -> bool:
    return bool(topic) and "+" not in topic and "#" not in topic


def valid_filter(topic_filter: str) -> bool:
    if not topic_filter:
        return False
    levels = topic_filter.split("/")
    for index, level in enumerate(levels):
        if ("+" in level or "#" in level) and len(level) != 1:
            return False
        if level == "#" and index != len(levels) - 1:
            return False
    return True


def matches(topic_filter: str, topic: str) -> bool:
    if topic.startswith("$") and topic_filter[:1] in ("+", "#"):
        return False
    filters, names = topic_filter.split("/"), topic.split("/")
    for index, level in enumerate(filters):
        if level == "#":
            return True
        if index >= len(names) or (level != "+" and level != names[index]):
            return False
    return len(filters) == len(names)


class Broker(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, credentials: tuple[str, bytes] | None = None):
        super().__init__(("127.0.0.1", 0), Session)
        self.credentials = credentials
        self.lock = threading.Lock()
        self.sessions: list[Session] = []
        self.retained: dict[str, tuple[bytes, int]] = {}
        self.pings: dict[str, int] = {}
        self.subscribed: dict[str, list[str]] = {}
        self.errors: list[str] = []
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self) -> int:
        return self.server_address[1]

    def route(self, topic: str, payload: bytes, qos: int) -> None:
        with self.lock:
            targets = list(self.sessions)
        for session in targets:
            session.deliver(topic, payload, qos)

    def wait_subscribed(self, client_id: str, topic_filter: str) -> None:
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            with self.lock:
                if topic_filter in self.subscribed.get(client_id, []):
                    return
            time.sleep(0.02)
        raise AssertionError(f"{client_id} never subscribed to {topic_filter}")


class Session(socketserver.BaseRequestHandler):
    server: Broker

    def setup(self) -> None:
        self.version = 5
        self.client_id = ""
        self.filters: dict[str, int] = {}
        self.next_id = 1
        self.write_lock = threading.Lock()
        self.connected = False

    def send(self, packet_type: int, flags: int, body: bytes) -> None:
        with self.write_lock:
            self.request.sendall(bytes([packet_type << 4 | flags]) + encode_varint(len(body)) + body)

    def props(self) -> bytes:
        return b"\x00" if self.version == 5 else b""

    def deliver(self, topic: str, payload: bytes, qos: int, retain: bool = False) -> None:
        if not self.connected:
            return
        for topic_filter, granted in list(self.filters.items()):
            if not matches(topic_filter, topic):
                continue
            level = min(qos, granted)
            body = len(topic.encode()).to_bytes(2, "big") + topic.encode()
            if level:
                with self.write_lock:
                    packet_id = self.next_id
                    self.next_id = self.next_id % 65535 + 1
                body += packet_id.to_bytes(2, "big")
            body += self.props() + payload
            self.send(3, (level << 1) | (1 if retain else 0), body)
            return  # One copy per session even with overlapping filters.

    def handle(self) -> None:
        self.request.settimeout(TIMEOUT)
        try:
            self.loop()
        except (ConnectionError, OSError, socket.timeout):
            pass
        except (Malformed, UnicodeDecodeError, ValueError) as error:
            self.server.errors.append(f"{self.client_id or '?'}: {error}")
        finally:
            with self.server.lock:
                if self in self.server.sessions:
                    self.server.sessions.remove(self)

    def loop(self) -> None:
        packet_type, flags, body = read_packet(self.request)
        if packet_type != 1 or flags:
            raise Malformed("first packet must be CONNECT")
        self.connect(Reader(body))
        while True:
            packet_type, flags, body = read_packet(self.request)
            reader = Reader(body)
            if packet_type == 3:
                self.publish(flags, reader)
            elif packet_type in (4, 5, 6, 7):
                if flags != (2 if packet_type == 6 else 0):
                    raise Malformed("acknowledgement flags")
                packet_id = reader.u16()
                if not packet_id:
                    raise Malformed("packet identifier 0")
                if packet_type == 6:
                    self.send(7, 0, packet_id.to_bytes(2, "big"))
                elif packet_type == 5:
                    self.send(6, 2, packet_id.to_bytes(2, "big"))
            elif packet_type == 8:
                self.subscribe(flags, reader)
            elif packet_type == 10:
                self.unsubscribe(flags, reader)
            elif packet_type == 12:
                if flags or body:
                    raise Malformed("PINGREQ")
                with self.server.lock:
                    self.server.pings[self.client_id] = self.server.pings.get(self.client_id, 0) + 1
                self.send(13, 0, b"")
            elif packet_type == 14:
                return
            else:
                raise Malformed(f"unexpected packet type {packet_type}")

    def connect(self, reader: Reader) -> None:
        if reader.text() != "MQTT":
            raise Malformed("protocol name")
        self.version = reader.u8()
        if self.version not in (4, 5):
            raise Malformed("protocol level")
        flags = reader.u8()
        if flags & 0x01:
            raise Malformed("reserved CONNECT flag")
        reader.u16()  # Keep alive.
        if self.version == 5:
            reader.properties()
        self.client_id = reader.text()
        if flags & 0x04:
            if self.version == 5:
                reader.properties()
            reader.text()
            reader.binary()
        username = reader.text() if flags & 0x80 else None
        password = reader.binary() if flags & 0x40 else None
        reader.done()
        assigned = b""
        if not self.client_id:
            if self.version == 4:
                raise Malformed("empty 3.1.1 client identifier")
            self.client_id = f"auto-{id(self)}"
            name = self.client_id.encode()
            assigned = b"\x12" + len(name).to_bytes(2, "big") + name
        if self.server.credentials and (username, password) != self.server.credentials:
            self.send(2, 0, b"\x00\x86\x00" if self.version == 5 else b"\x00\x04")
            raise ConnectionError("refused")
        self.send(2, 0, b"\x00\x00" + (encode_varint(len(assigned)) + assigned if self.version == 5 else b""))
        self.connected = True
        with self.server.lock:
            self.server.sessions.append(self)

    def publish(self, flags: int, reader: Reader) -> None:
        qos, retain, dup = (flags >> 1) & 3, flags & 1, flags & 8
        if qos == 3 or (qos == 0 and dup):
            raise Malformed("PUBLISH flags")
        topic = reader.text()
        packet_id = reader.u16() if qos else 0
        if qos and not packet_id:
            raise Malformed("packet identifier 0")
        if self.version == 5:
            if 0x0B in reader.properties():
                raise Malformed("subscription identifier from a client")
        if not valid_topic(topic):
            raise Malformed("topic name")
        payload = reader.take(len(reader.data) - reader.pos)
        if qos == 1:
            self.send(4, 0, packet_id.to_bytes(2, "big"))
        elif qos == 2:
            self.send(5, 0, packet_id.to_bytes(2, "big"))
        if retain:
            with self.server.lock:
                self.server.retained[topic] = (payload, qos)
        self.server.route(topic, payload, qos)

    def subscribe(self, flags: int, reader: Reader) -> None:
        if flags != 2:
            raise Malformed("SUBSCRIBE flags")
        packet_id = reader.u16()
        if self.version == 5:
            reader.properties()
        reasons = bytearray()
        added = []
        while reader.pos < len(reader.data):
            topic_filter = reader.text()
            options = reader.u8()
            if options & (0xC0 if self.version == 5 else 0xFC) or options & 3 == 3 or not valid_filter(topic_filter):
                raise Malformed("subscription")
            self.filters[topic_filter] = options & 3
            reasons.append(options & 3)
            added.append(topic_filter)
        if not packet_id or not added:
            raise Malformed("empty SUBSCRIBE")
        self.send(9, 0, packet_id.to_bytes(2, "big") + self.props() + bytes(reasons))
        with self.server.lock:
            self.server.subscribed.setdefault(self.client_id, []).extend(added)
            retained = list(self.server.retained.items())
        for topic, (payload, qos) in retained:
            self.deliver(topic, payload, qos, retain=True)

    def unsubscribe(self, flags: int, reader: Reader) -> None:
        if flags != 2:
            raise Malformed("UNSUBSCRIBE flags")
        packet_id = reader.u16()
        if self.version == 5:
            reader.properties()
        count = 0
        while reader.pos < len(reader.data):
            self.filters.pop(reader.text(), None)
            count += 1
        reasons = bytes(count) if self.version == 5 else b""
        self.send(11, 0, packet_id.to_bytes(2, "big") + self.props() + reasons)


class Runner:
    def __init__(self, client: str):
        self.client = client
        self.passed = 0

    def command(self, port: int, *arguments: str) -> list[str]:
        return [self.client, "127.0.0.1", str(port), *arguments]

    def run(self, port: int, *arguments: str, expect: int = 0) -> str:
        result = subprocess.run(self.command(port, *arguments), capture_output=True, text=True, timeout=TIMEOUT,
                                encoding="utf-8", errors="replace")
        if (result.returncode == 0) != (expect == 0):
            raise AssertionError(f"{arguments}: exit {result.returncode}\n{result.stdout}{result.stderr}")
        return result.stdout

    def pubsub(self, port: int, version: str, qos: int, wait_subscribed, label: str) -> None:
        flags = ["--v311"] if version == "3.1.1" else []
        topic = f"mira/{label}/{version}/q{qos}"
        client_id = f"sub-{label}-{version.replace('.', '')}-{qos}"
        subscriber = subprocess.Popen(
            self.command(port, "sub", topic, "1", "--qos", "2", "--id", client_id, *flags),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            wait_subscribed(client_id, topic)
            payload = f"hello {version} qos{qos}"
            self.run(port, "pub", topic, payload, "--qos", str(qos), *flags)
            out, err = subscriber.communicate(timeout=TIMEOUT)
            if subscriber.returncode != 0 or out.strip() != f"{topic} {payload}":
                raise AssertionError(f"subscriber saw {out!r} (exit {subscriber.returncode}) {err}")
        finally:
            if subscriber.poll() is None:
                subscriber.kill()
                subscriber.communicate()
        self.passed += 1


def mira_broker_cases(runner: Runner) -> None:
    broker = Broker()
    try:
        for version in ("5.0", "3.1.1"):
            flags = ["--v311"] if version == "3.1.1" else []
            for qos in (0, 1, 2):
                runner.pubsub(broker.port, version, qos, broker.wait_subscribed, "py")
            # Wildcards route across levels.
            client_id = f"wild-{version.replace('.', '')}"
            subscriber = subprocess.Popen(
                runner.command(broker.port, "sub", "wild/+/x/#", "1", "--qos", "1", "--id", client_id, *flags),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            broker.wait_subscribed(client_id, "wild/+/x/#")
            runner.run(broker.port, "pub", "wild/a/x/b/c", "deep", "--qos", "1", *flags)
            out, _ = subscriber.communicate(timeout=TIMEOUT)
            assert out.strip() == "wild/a/x/b/c deep", out
            runner.passed += 1
            # Retained messages reach later subscribers.
            runner.run(broker.port, "pub", f"retained/{version}", "kept", "--retain", "--qos", "1", *flags)
            out = runner.run(broker.port, "sub", f"retained/{version}", "1", *flags)
            assert out.strip() == f"retained/{version} kept", out
            runner.passed += 1
            out = runner.run(broker.port, "echo", f"echo/{version}", "round trip", "--qos", "2", *flags)
            assert out.strip() == f"echo/{version} round trip", out
            runner.passed += 1
        # An idle subscriber keeps the connection alive with PINGREQ.
        subscriber = subprocess.Popen(
            runner.command(broker.port, "sub", "idle/topic", "1", "--keepalive", "1", "--id", "idle"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        broker.wait_subscribed("idle", "idle/topic")
        time.sleep(2.6)
        runner.run(broker.port, "pub", "idle/topic", "late")
        out, _ = subscriber.communicate(timeout=TIMEOUT)
        assert out.strip() == "idle/topic late", out
        assert broker.pings.get("idle", 0) >= 2, broker.pings
        runner.passed += 1
        if broker.errors:
            raise AssertionError(f"broker rejected client bytes: {broker.errors}")
    finally:
        broker.shutdown()
        broker.server_close()

    secured = Broker(credentials=("mira", b"secret"))
    try:
        for flags in ([], ["--v311"]):
            runner.run(secured.port, "pub", "auth/t", "x", "--id", "bad", "--user", "mira", "--password", "wrong",
                       *flags, expect=1)
            runner.run(secured.port, "pub", "auth/t", "x", "--id", "good", "--user", "mira", "--password", "secret",
                       *flags)
            runner.passed += 2
    finally:
        secured.shutdown()
        secured.server_close()


def mosquitto_cases(runner: Runner, binary: str) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with tempfile.TemporaryDirectory() as directory:
        config = os.path.join(directory, "mosquitto.conf")
        with open(config, "w", encoding="utf-8") as handle:
            handle.write(f"listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\n")
        broker = subprocess.Popen([binary, "-c", config], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + TIMEOUT
            while time.monotonic() < deadline:
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=1).close()
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("mosquitto did not start")

            # mosquitto has no subscription introspection; a short settle stands in.
            def settle(_client: str, _filter: str) -> None:
                time.sleep(0.5)

            for version in ("5.0", "3.1.1"):
                for qos in (0, 1, 2):
                    runner.pubsub(port, version, qos, settle, "mosquitto")
                flags = ["--v311"] if version == "3.1.1" else []
                out = runner.run(port, "echo", f"mosq/echo/{version}", "via mosquitto", "--qos", "2", *flags)
                assert out.strip() == f"mosq/echo/{version} via mosquitto", out
                runner.passed += 1
        finally:
            broker.terminate()
            try:
                broker.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                broker.kill()


def find_mosquitto() -> str:
    # Package managers install the broker under sbin, which is not always on PATH.
    for candidate in (shutil.which("mosquitto"), "/usr/sbin/mosquitto", "/opt/homebrew/sbin/mosquitto",
                      "/usr/local/sbin/mosquitto"):
        if candidate and os.path.exists(candidate):
            return candidate
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True)
    parser.add_argument("--mosquitto", default=find_mosquitto())
    args = parser.parse_args()
    runner = Runner(args.client)
    mira_broker_cases(runner)
    mosquitto_note = "SKIPPED (mosquitto not found)"
    if not args.mosquitto and os.environ.get("MIRA_REQUIRE_MOSQUITTO") == "1":
        raise AssertionError("MIRA_REQUIRE_MOSQUITTO=1 but no mosquitto binary was found")
    if args.mosquitto and os.path.exists(args.mosquitto):
        before = runner.passed
        mosquitto_cases(runner, args.mosquitto)
        mosquitto_note = f"{runner.passed - before} cases passed"
    print(f"MQTT interop: {runner.passed} cases passed; mosquitto {mosquitto_note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
