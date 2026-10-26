#!/usr/bin/env python3
"""以真实 TCP 验证 OpenSSL s_client/s_server 与 Mira TLS1.3 早期数据。"""
from __future__ import annotations

import argparse
import pathlib
import queue
import re
import subprocess
import tempfile
import threading
import time


class Process:
    def __init__(self, command):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.lines = queue.Queue()
        self.output = []
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            self.output.append(line)
            self.lines.put(line.strip())
        self.lines.put(None)

    def event(self, prefix, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            try:
                line = self.lines.get(timeout=max(0.001, deadline - time.monotonic()))
            except queue.Empty as error:
                raise AssertionError(f"等待 {prefix!r} 超时：{''.join(self.output)}") from error
            if line is None:
                raise AssertionError(f"进程提前结束：{''.join(self.output)}")
            if line.startswith(prefix):
                return line

    def send(self, text):
        # These are wire-protocol bytes, not platform text. In particular, a
        # Windows TextIOWrapper must not turn LF into CRLF before s_server reads it.
        self.process.stdin.buffer.write(text.encode('ascii'))
        self.process.stdin.buffer.flush()

    def finish(self):
        self.process.wait(timeout=15)
        self.reader.join(timeout=5)
        assert self.process.returncode == 0, ''.join(self.output)
        return ''.join(self.output)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=15, **kwargs)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def exchange_with_server(server, client):
    # s_server does not flush its initial early-data diagnostic on every platform.
    # Drive its stdin from our explicitly flushed peer events instead. Windows
    # s_server also blocks on redirected stdin, so q must end each connection.
    for status, response in (('not_attempted', 'ticket-ready\n'), ('accepted', 'early-ready\n')):
        client.event(f'READY={status}')
        server.send(response)
        client.event(f'RECEIVED={status}')
        server.send('drain-ready\n')
        client.event(f'CLIENT={status}')
        # This record follows all application writes on the same TLS stream.
        # Wait until OpenSSL has read it so q cannot hide a repeated payload.
        server.event(f'MIRA-DRAIN-{status}')
        server.send('q\n')
        server.event('DONE')  # s_server flushes this acknowledgement before closing.
        client.send('next\n')
    client.finish()
    output = server.finish()
    assert 'No early data received' in output, output
    assert 'Early data received:' in output, output
    count = output.count('safe-tcp')
    assert count == 1, f'应用载荷应恰好出现一次，实际 {count} 次：\n{output}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', required=True, type=pathlib.Path)
    parser.add_argument('--openssl', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='mira-tcp-early-') as directory:
        root = pathlib.Path(directory)
        cert, key, session, payload = (root / name for name in ('cert.pem', 'key.pem', 'session.pem', 'safe.txt'))
        run([args.openssl, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
             '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
             '-keyout', str(key), '-out', str(cert)])
        payload.write_text('safe-tcp\n', encoding='ascii')
        with Process([str(args.peer), 'server', str(cert), str(key)]) as server:
            port = int(server.event('PORT=').split('=', 1)[1])
            client = [args.openssl, 's_client', '-connect', f'127.0.0.1:{port}', '-servername', 'localhost',
                      '-verify_hostname', 'localhost', '-verify_return_error', '-CAfile', str(cert),
                      '-tls1_3', '-quiet', '-ign_eof']
            warmed = run(client + ['-sess_out', str(session)], input='warm\n')
            assert 'not_attempted:warm' in warmed.stdout, warmed.stdout
            assert session.is_file(), '客户端未收到 TLS1.3 会话票据'
            accepted = run(client + ['-sess_in', str(session), '-early_data', str(payload)], input='')
            assert 'accepted:safe-tcp' in accepted.stdout, accepted.stdout
            rejected = run(client + ['-sess_in', str(session), '-early_data', str(payload)], input='')
            assert 'rejected:\n' in rejected.stdout and 'safe-tcp' not in rejected.stdout, rejected.stdout
            server.finish()
        print('通过：s_client → Mira 接受早期数据，同票据二次发送被拒绝')

        command = [args.openssl, 's_server', '-accept', '127.0.0.1:0', '-cert', str(cert), '-key', str(key),
                   '-tls1_3', '-early_data', '-max_early_data', '16384', '-num_tickets', '1', '-naccept', '2']
        with Process(command) as server:
            address = server.event('ACCEPT')
            match = re.search(r':(\d+)\s*$', address)
            assert match, address
            with Process([str(args.peer), 'client', str(cert), match.group(1)]) as client:
                exchange_with_server(server, client)
        print('通过：Mira → s_server 原生早期数据接受，应用载荷只发送一次')


if __name__ == '__main__':
    main()
