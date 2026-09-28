#!/usr/bin/env python3
"""Check the independent Retry observer without requiring HTTP/3 curl."""

import socket
import unittest

from check_h3_interop import RetryObserver


class RetryObserverTests(unittest.TestCase):
    PREFIX = bytes.fromhex("c00000000101aa01bb")

    def test_zero_token(self):
        self.assertFalse(RetryObserver.has_token(self.PREFIX + b"\x00"))

    def test_token_varint_sizes(self):
        for length in (b"\x02", b"\x40\x02", b"\x80\x00\x00\x02",
                       b"\xc0\x00\x00\x00\x00\x00\x00\x02"):
            with self.subTest(length=length):
                self.assertTrue(RetryObserver.has_token(self.PREFIX + length + b"ab"))
                self.assertFalse(RetryObserver.has_token(self.PREFIX + length + b"a"))

    def test_truncated_headers(self):
        valid = self.PREFIX + b"\x40\x02ab"
        for end in range(len(valid)):
            with self.subTest(end=end):
                self.assertFalse(RetryObserver.has_token(valid[:end]))

    def test_other_packet_types_and_versions(self):
        wire = bytearray(self.PREFIX + b"\x02ab")
        for first in (0x40, 0xd0, 0xe0, 0xf0):
            wire[0] = first
            self.assertFalse(RetryObserver.has_token(wire))
        wire[0] = 0xc0
        wire[4] = 2
        self.assertFalse(RetryObserver.has_token(wire))

    def test_real_udp_relay_and_shutdown(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(("127.0.0.1", 0))
            client.bind(("127.0.0.1", 0))
            server.settimeout(3)
            client.settimeout(3)
            with RetryObserver(server.getsockname()[1]) as relay:
                token_initial = self.PREFIX + b"\x02ab"
                client.sendto(token_initial, ("127.0.0.1", relay.port))
                data, source = server.recvfrom(65536)
                self.assertEqual(data, token_initial)
                self.assertEqual(source[0], "127.0.0.1")
                retry = bytes.fromhex("f00000000101bb01aa") + b"\x00" * 16
                server.sendto(retry, source)
                self.assertEqual(client.recvfrom(65536)[0], retry)
            self.assertEqual(relay.token_initials, 1)
            self.assertEqual(relay.retries, 1)
            self.assertIsNone(relay.error)
            self.assertFalse(relay.worker.is_alive())


if __name__ == "__main__":
    unittest.main()
