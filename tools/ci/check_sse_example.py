#!/usr/bin/env python3
"""Independently decode chunked SSE and reconnect using Last-Event-ID."""
import http.client
import queue
import subprocess
import sys
import threading


def main():
    server = subprocess.Popen([sys.argv[1], "0", "3"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    lines = queue.Queue()
    threading.Thread(target=lambda: lines.put(server.stdout.readline()), daemon=True).start()
    try:
        first = lines.get(timeout=5).strip()
        assert first.startswith("PORT="), first
        port = int(first[5:])
        for last, expected in [(None, [1, 2, 3]), ("3", [4, 5, 6]), ("bad", None)]:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            headers = {"Connection": "close"}
            if last is not None:
                headers["Last-Event-ID"] = last
            connection.request("GET", "/events", headers=headers)
            response = connection.getresponse()
            if expected is None:
                assert response.status == 400
                response.read()
            else:
                assert response.status == 200
                assert response.getheader("Content-Type") == "text/event-stream; charset=utf-8"
                assert response.getheader("Transfer-Encoding") == "chunked"
                text = response.read().decode("utf-8")
                ids = [int(line[4:]) for line in text.splitlines() if line.startswith("id: ")]
                assert ids == expected, text
                assert text.count("event: tick\n") == 3 and "retry: 1000\n" in text
                for number in expected:
                    assert f"data: event {number}\n\n" in text
            connection.close()
        _, errors = server.communicate(timeout=5)
        assert server.returncode == 0, errors
    finally:
        if server.poll() is None:
            server.kill()
            server.wait(timeout=5)
    print("SSE: chunk framing, event IDs, resume and invalid ID verified")


if __name__ == "__main__":
    main()
