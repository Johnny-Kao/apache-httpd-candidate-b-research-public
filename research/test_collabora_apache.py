#!/usr/bin/env python3
"""GitHub-runner-only integration check: Apache -> real Collabora proxy.php."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def read_http(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        data += sock.recv(8192)
    head, body = data.split(b"\r\n\r\n", 1)
    length = next((int(line.split(b":", 1)[1]) for line in head.split(b"\r\n")
                   if line.lower().startswith(b"content-length:")), 0)
    while len(body) < length:
        body += sock.recv(8192)
    return head + b"\r\n\r\n" + body[:length]


class CodeBackend:
    def __init__(self) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 9983))
        self.listener.listen(4)
        self.requests = 0

    def run(self) -> None:
        try:
            for _ in range(2):
                conn, _ = self.listener.accept()
                with conn:
                    request = b""
                    while b"\r\n\r\n" not in request:
                        request += conn.recv(8192)
                    self.requests += 1
                    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                    if self.requests == 1:
                        response += b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                    conn.sendall(response)
        finally:
            self.listener.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--proxy-php", required=True, type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="collabora-apache-") as tmp:
        root = Path(tmp)
        app = root / "app"
        app.mkdir()
        proxy_php = app / "proxy.php"
        proxy_php.write_bytes(args.proxy_php.read_bytes())
        backend = CodeBackend()
        backend_thread = threading.Thread(target=backend.run, daemon=True)
        backend_thread.start()
        php = subprocess.Popen(
            ["php", "-S", "127.0.0.1:18081", "-t", str(app)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env={**os.environ, "PHP_INI_SCAN_DIR": ""},
        )
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
ProxyPass / http://127.0.0.1:18081/
ProxyPassReverse / http://127.0.0.1:18081/
""")
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
            else:
                raise TimeoutError("Apache did not listen")

            with socket.create_connection(("127.0.0.1", 18080), timeout=3) as attacker:
                attacker.sendall(b"GET /proxy.php?req=/tenant-a/write/1 HTTP/1.1\r\nHost: tenant-a\r\nConnection: keep-alive\r\n\r\n")
                response_a = read_http(attacker)
            with socket.create_connection(("127.0.0.1", 18080), timeout=3) as victim:
                victim.sendall(b"GET /proxy.php?req=/tenant-b/read/1 HTTP/1.1\r\nHost: tenant-b\r\nConnection: close\r\n\r\n")
                response_b = read_http(victim)
            backend_thread.join(timeout=3)
            print(f"collabora_proxy_response_a={response_a!r}")
            print(f"collabora_proxy_response_b={response_b!r}")
            print(f"collabora_code_requests={backend.requests}")
            print("collabora_apache_tenant_boundary=observed" if not response_b.endswith(b"OK") else "collabora_apache_tenant_boundary=not_observed")
            if not response_a.endswith(b"OK"):
                raise AssertionError(f"unexpected A response: {response_a!r}")
            if response_b.endswith(b"OK"):
                raise AssertionError("B received its legitimate response; boundary not observed")
            return 0
        finally:
            apache.terminate()
            php.terminate()
            for process in (apache, php):
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
