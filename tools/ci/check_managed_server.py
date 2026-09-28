#!/usr/bin/env python3
"""Verify admission rejection, existing-client progress and cooperative deadline shutdown."""
import queue
import re
import socket
import subprocess
import sys
import threading


def main():
    server = subprocess.Popen([sys.argv[1], "0", "1", "1500"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    lines = queue.Queue()
    threading.Thread(target=lambda: lines.put(server.stdout.readline()), daemon=True).start()
    clients = []
    try:
        first = lines.get(timeout=5)
        assert first.startswith("PORT="), first
        port = int(first[5:])
        active = socket.create_connection(("127.0.0.1", port), timeout=3)
        clients.append(active)
        active.sendall(b"one")
        assert active.recv(3) == b"one"
        rejected = socket.create_connection(("127.0.0.1", port), timeout=3)
        clients.append(rejected)
        try:
            assert rejected.recv(1) == b""
        except ConnectionResetError:
            pass
        active.sendall(b"two")
        assert active.recv(3) == b"two"
        # The active read is still pending when the server's deadline stops admission.
        assert active.recv(1) == b""
        output, errors = server.communicate(timeout=5)
        assert server.returncode == 0, errors
        stats = dict((k, int(v)) for k, v in re.findall(r"(\w+)=(\d+)", output))
        assert stats["accepted"] == 2 and stats["rejected"] == 1, stats
        assert stats["completed"] == 1 and stats["peak_active"] == 1, stats
    finally:
        for client in clients:
            client.close()
        if server.poll() is None:
            server.kill()
            server.wait(timeout=5)
    print("managed server: admission, continued service and joined shutdown verified")


if __name__ == "__main__":
    main()
