#!/usr/bin/env python3
"""One deterministic, localhost-only Candidate B mechanics experiment."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from backend import Backend


def read_response(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        data += sock.recv(4096)
    headers, body = data.split(b"\r\n\r\n", 1)
    length = next((int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n")
                   if line.lower().startswith(b"content-length:")), 0)
    while len(body) < length:
        body += sock.recv(4096)
    return headers + b"\r\n\r\n" + body[:length]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    args = parser.parse_args()
    if not args.httpd.is_file():
        raise SystemExit(f"httpd not found: {args.httpd}")

    with tempfile.TemporaryDirectory(prefix="candidate-b-") as tmp:
        root = Path(tmp)
        backend = Backend(root / "backend.log")
        config = root / "httpd.conf"
        config.write_text(f"""\
ServerRoot \"{args.server_root}\"
Listen 127.0.0.1:18080
PidFile \"{root / 'httpd.pid'}\"
ErrorLog \"{root / 'error.log'}\"
LogLevel proxy_http:trace2
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
ProxyPass / http://127.0.0.1:{backend.port}/
ProxyPassReverse / http://127.0.0.1:{backend.port}/
""")
        thread = threading.Thread(target=backend.run, daemon=True)
        thread.start()
        proxy = subprocess.Popen(
            [str(args.httpd), "-f", str(config), "-DFOREGROUND", "-X"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "APACHE_RUN_DIR": str(root)},
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    client = socket.create_connection(("127.0.0.1", 18080), timeout=1)
                    break
                except OSError:
                    if proxy.poll() is not None:
                        raise RuntimeError(proxy.stderr.read())
            else:
                raise TimeoutError("Apache did not listen on 127.0.0.1:18080")
            with client:
                client.sendall(b"GET /a HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
                response_a = read_response(client)
                client.sendall(b"GET /b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                response_b = read_response(client)
            thread.join(timeout=2)
            if b"Content-Length: 2" not in response_a or not response_a.endswith(b"OK"):
                raise AssertionError(f"unexpected A response: {response_a!r}")
            print(f"backend_log={backend.log_path}")
            print(f"response_a={response_a!r}")
            print(f"response_b={response_b!r}")
            print("candidate_b_mechanics=observed" if b"X-Poison: from-A" in response_b
                  else "candidate_b_mechanics=not_observed")
            return 0
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxy.kill()


if __name__ == "__main__":
    raise SystemExit(main())
