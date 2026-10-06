#!/usr/bin/env python3
"""Independent QUIC/TLS/QPACK stack: aioquic 1.3.0 vs a Mira loopback peer.

Checks plain H3, accepted early GET, rejected early GET with 1-RTT fallback,
and RFC 9220 WebSocket Extended CONNECT binary/control/close exchanges.
No certificate verification bypass; missing aioquic fails, never passes/skips.
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
from pathlib import Path
import queue
import struct
import subprocess
import threading

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, ConnectionTerminated
from aioquic.quic.packet import QuicProtocolVersion


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.requests = {}
        self.ready_settings = asyncio.Event()
        self.early_accepted = None
        self.resumed = None
        self.handshake_seen = asyncio.Event()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.early_accepted = event.early_data_accepted
            self.resumed = event.session_resumed
            self.handshake_seen.set()
        if isinstance(event, ConnectionTerminated):
            for state in self.requests.values():
                for name in ("head", "end"):
                    if not state[name].done():
                        state[name].set_exception(RuntimeError(f"QUIC closed: {event.error_code} {event.reason_phrase}"))
        for item in self.h3.handle_event(event):
            state = self.requests.get(item.stream_id)
            if state is None:
                continue
            if isinstance(item, HeadersReceived):
                state["headers"].extend(item.headers)
                if not state["head"].done():
                    state["head"].set_result(None)
            if isinstance(item, DataReceived):
                state["body"].extend(item.data)
                if len(state["body"]) > 1024 * 1024:
                    raise RuntimeError("response capacity exceeded")
            if item.stream_ended and not state["end"].done():
                state["end"].set_result(None)
        settings = self.h3.received_settings
        if settings is not None and settings.get(Setting.ENABLE_CONNECT_PROTOCOL) == 1:
            self.ready_settings.set()

    def request(self, method=b"GET", protocol=None):
        stream = self._quic.get_next_available_stream_id()
        loop = asyncio.get_running_loop()
        state = {"head": loop.create_future(), "end": loop.create_future(), "headers": [], "body": bytearray()}
        self.requests[stream] = state
        headers = [(b":method", method), (b":scheme", b"https"),
                   (b":authority", b"localhost"), (b":path", b"/interop")]
        if protocol:
            headers += [(b":protocol", protocol), (b"sec-websocket-version", b"13"),
                        (b"sec-websocket-protocol", b"interop")]
        self.h3.send_headers(stream_id=stream, headers=headers, end_stream=not protocol)
        self.transmit()
        return stream, state


def frame(opcode, data):
    mask = b"\x23\x45\x67\x89"
    length = len(data)
    header = bytes([0x80 | opcode])
    if length < 126:
        header += bytes([0x80 | length])
    else:
        header += b"\xfe" + struct.pack("!H", length)
    return header + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(data))


def frames(data):
    result = []
    while data:
        if len(data) < 2 or data[1] & 0x80 or not data[0] & 0x80:
            raise RuntimeError("invalid server WebSocket frame")
        opcode, length, offset = data[0] & 15, data[1] & 127, 2
        if length == 126:
            length, offset = struct.unpack("!H", data[2:4])[0], 4
        elif length == 127:
            raise RuntimeError("unexpected oversized frame")
        if len(data) < offset + length:
            raise RuntimeError("truncated server frame")
        result.append((opcode, bytes(data[offset:offset + length])))
        data = data[offset + length:]
    return result


async def verify(port, ca):
    tickets = []
    ticket_event = asyncio.Event()
    def ticket(value):
        tickets.append(value)
        ticket_event.set()
    def configuration():
        result = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name="localhost",
                                   supported_versions=[QuicProtocolVersion.VERSION_1])
        result.load_verify_locations(cafile=str(ca))
        return result
    report = {"stack": "aioquic", "tests": [], "scope": "aioquic client to Mira server; loopback"}
    async with connect("127.0.0.1", port, configuration=configuration(), create_protocol=Peer,
                       session_ticket_handler=ticket) as client:
        _, response = client.request()
        await asyncio.wait_for(response["end"], 10)
        assert dict(response["headers"])[b":status"] == b"200"
        assert response["body"] == b"one-rtt"
        await asyncio.wait_for(ticket_event.wait(), 10)
        report["tests"].append("verified-certificate-h3")
    assert tickets and tickets[-1].max_early_data_size
    for expected in (True, False):
        config = configuration()
        config.session_ticket = tickets[-1]
        async with connect("127.0.0.1", port, configuration=config, create_protocol=Peer,
                           session_ticket_handler=ticket, wait_connected=False) as client:
            _, response = client.request()
            await asyncio.wait_for(response["end"], 10)
            # aioquic 1.3 records _connected only with an already registered
            # waiter. The event may precede a 0.5-RTT response; observe the
            # handshake event directly instead of waiting for it a second time.
            await asyncio.wait_for(client.handshake_seen.wait(), 10)
            assert client.early_accepted is expected, (client.early_accepted, expected)
            assert client.resumed is True
            assert dict(response["headers"])[b"x-mira-early"] == (b"1" if expected else b"0")
            assert response["body"] == (b"early" if expected else b"one-rtt")
            report["tests"].append("0rtt-accepted" if expected else "0rtt-rejected-1rtt-fallback")
    async with connect("127.0.0.1", port, configuration=configuration(), create_protocol=Peer) as client:
        await asyncio.wait_for(client.ready_settings.wait(), 10)
        stream, response = client.request(b"CONNECT", b"websocket")
        await asyncio.wait_for(response["head"], 10)
        headers = dict(response["headers"])
        assert headers[b":status"] == b"200" and headers[b"sec-websocket-protocol"] == b"interop"
        payload = bytes(i % 251 for i in range(8192))
        wire = frame(2, payload) + frame(9, b"ping") + frame(8, struct.pack("!H", 1000))
        client.h3.send_data(stream, wire, end_stream=True)
        client.transmit()
        await asyncio.wait_for(response["end"], 10)
        assert frames(response["body"]) == [(2, payload), (10, b"ping"), (8, struct.pack("!H", 1000))]
        report["tests"].append("extended-connect-websocket-binary-ping-close")
    report["passed"] = True
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    process = subprocess.Popen([str(args.server.resolve()), str(args.certificate.resolve()), str(args.key.resolve())],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    ready = queue.Queue()
    errors = []
    threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
    def collect():
        for line in process.stderr:
            if len(errors) < 100:
                errors.append(line.rstrip())
    stderr = threading.Thread(target=collect, daemon=True)
    stderr.start()
    try:
        line = ready.get(timeout=10)
        if not line.startswith("PORT="):
            raise RuntimeError(f"bad startup: {line!r}")
        report = asyncio.run(asyncio.wait_for(verify(int(line[5:]), args.certificate), 60))
        report["server_diagnostics"] = errors
        text = json.dumps(report, ensure_ascii=False, indent=2)
        print(text)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        if process.poll() is not None:
            raise RuntimeError(f"server exited unexpectedly: {process.returncode}")
    except Exception:
        print("server diagnostics: " + repr(errors), file=sys.stderr)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
        stderr.join(timeout=2)

if __name__ == "__main__":
    main()
