#!/usr/bin/env python3
"""Regression coverage for the interactive OpenSSL early-data runner."""

import sys
import unittest
from unittest import mock

from check_tcp_tls_early import Process, exchange_with_server


class EarlyDataRunnerTests(unittest.TestCase):
    def exchange(self, output):
        server, client = mock.Mock(), mock.Mock()
        observed = []
        completed = 0

        def peer_event(event):
            observed.append(event)
            if event.startswith('READY='):
                # Reconnect only after the previous q was consumed by s_server.
                self.assertEqual(client.send.call_count, completed)
            elif event.startswith('RECEIVED='):
                self.assertEqual(server.send.call_count, completed * 3 + 1)
            else:
                self.assertEqual(server.send.call_count, completed * 3 + 2)

        def server_event(event):
            nonlocal completed
            # Initial diagnostics cannot drive the exchange. Only application
            # markers and q's explicitly flushed acknowledgement are available.
            if event.startswith('MIRA-DRAIN-'):
                self.assertEqual(server.send.call_args, mock.call('drain-ready\n'))
                self.assertTrue(observed[-1].startswith('CLIENT='))
                return event
            self.assertEqual(event, 'DONE')
            self.assertEqual(server.send.call_args, mock.call('q\n'))
            completed += 1
            return 'DONE'

        client.event.side_effect = peer_event
        server.event.side_effect = server_event
        server.finish.return_value = output
        exchange_with_server(server, client)
        self.assertEqual(observed, ['READY=not_attempted', 'RECEIVED=not_attempted', 'CLIENT=not_attempted',
                                    'READY=accepted', 'RECEIVED=accepted', 'CLIENT=accepted'])
        self.assertEqual(server.send.call_args_list,
                         [mock.call('ticket-ready\n'), mock.call('drain-ready\n'), mock.call('q\n'),
                          mock.call('early-ready\n'), mock.call('drain-ready\n'), mock.call('q\n')])
        self.assertEqual(client.send.call_args_list, [mock.call('next\n'), mock.call('next\n')])
        client.finish.assert_called_once_with()
        server.finish.assert_called_once_with()

    def test_buffered_server_diagnostics_do_not_block_exchange(self):
        self.exchange('No early data received\nEarly data received:\nsafe-tcp\n')

    def test_missing_acceptance_and_duplicate_payload_still_fail(self):
        for output in ('No early data received\nEarly data was rejected\n',
                       'No early data received\nEarly data received:\nsafe-tcp\nsafe-tcp\n',
                       'Early data received:\nsafe-tcp\n'):
            with self.subTest(output=output), self.assertRaises(AssertionError):
                self.exchange(output)

    def test_process_reads_explicit_flush_before_buffered_diagnostics(self):
        script = (
            "import sys\n"
            "print('READY', flush=True)\n"
            "print('No early data received')\n"
            "assert input() == 'q'\n"
            "print('DONE', flush=True)\n"
        )
        with Process([sys.executable, '-c', script]) as server:
            self.assertEqual(server.event('READY'), 'READY')
            server.send('q\n')
            self.assertEqual(server.event('DONE'), 'DONE')
            self.assertIn('No early data received', server.finish())

    def test_wire_input_bypasses_windows_newline_translation(self):
        script = "import sys; assert sys.stdin.buffer.readline() == b'ticket-ready\\n'"
        with Process([sys.executable, '-c', script]) as peer:
            peer.process.stdin.reconfigure(newline='\r\n')
            peer.send('ticket-ready\n')
            peer.finish()


if __name__ == '__main__':
    unittest.main()
