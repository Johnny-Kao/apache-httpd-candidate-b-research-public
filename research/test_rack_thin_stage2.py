#!/usr/bin/env python3
"""Stage 2 prerequisite isolation for the Rack/Thin -> Apache result.

Every case is synthetic and reports an explicit result.  The script never
counts a status error, truncation, or an unproven body mismatch as
contamination.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from test_rack_thin_validation import (
    classify_victim,
    make_body_path,
    request,
    wait_for_port,
)


def start_thin(thin: Path, fixture: Path, port: int, root: Path,
               label: str, mode: str) -> subprocess.Popen[str]:
    files = root / f"files-{label}"
    files.mkdir()
    request_log = root / f"rack-{label}.log"
    log = root / f"thin-{label}.log"
    env = {
        **os.environ,
        "RACK_FILES_ROOT": str(files),
        "RACK_THIN_REQUEST_LOG": str(request_log),
        "RACK_THIN_A_MODE": mode,
    }
    proc = subprocess.Popen(
        [str(thin), "start", "-R", str(fixture / "config.ru"),
         "-a", "127.0.0.1", "-p", str(port)],
        cwd=fixture, stdout=log.open("w"), stderr=subprocess.STDOUT,
        text=True, env=env,
    )
    wait_for_port(port, proc, f"Thin-{label}", log)
    return proc


def start_apache(httpd: Path, server_root: Path, root: Path,
                 backend_a: int, backend_b: int | None,
                 disablereuse: bool = False) -> subprocess.Popen[str]:
    reuse = " disablereuse=On" if disablereuse else ""
    if backend_b is None:
        routing = f"""
ProxyPass / http://127.0.0.1:{backend_a}/ retry=0{reuse}
ProxyPassReverse / http://127.0.0.1:{backend_a}/
"""
    else:
        routing = f"""
<VirtualHost *:18080>
    ServerName tenant-a.example
    ProxyPass / http://127.0.0.1:{backend_a}/ retry=0{reuse}
    ProxyPassReverse / http://127.0.0.1:{backend_a}/
</VirtualHost>
<VirtualHost *:18080>
    ServerName tenant-b.example
    ProxyPass / http://127.0.0.1:{backend_b}/ retry=0{reuse}
    ProxyPassReverse / http://127.0.0.1:{backend_b}/
</VirtualHost>
"""
    config = root / "httpd.conf"
    config.write_text(f"""\
ServerRoot "{server_root}"
Listen 127.0.0.1:18080
PidFile "{root / 'httpd.pid'}"
ErrorLog "{root / 'error.log'}"
LogLevel proxy:trace5 proxy_http:trace5
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LogFormat "rid=%{{X-Probe-ID}}i host=%{{Host}}i peer=%{{proxy-source-port}}n status=%>s bytes=%B" probe
CustomLog "{root / 'access.log'}" probe
{routing}
""")
    proc = subprocess.Popen(
        [str(httpd), "-f", str(config), "-DFOREGROUND"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "APACHE_RUN_DIR": str(root)},
    )
    wait_for_port(18080, proc, "Apache", root / "error.log")
    return proc


def access_correlation(path: Path, iterations: int) -> dict[str, int]:
    records: dict[str, dict[str, str]] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            fields = dict(item.split("=", 1) for item in line.split()
                          if "=" in item)
            if fields.get("rid"):
                records[fields["rid"]] = fields
    pairs = same = 0
    for i in range(iterations):
        a = records.get(f"probe-{i:04d}")
        b = records.get(f"probe-{i:04d}-victim")
        if a and b and a.get("peer") and b.get("peer"):
            pairs += 1
            same += int(a["peer"] == b["peer"])
    return {"pairs": pairs, "same_backend_source_port": same}


def run_case(args: argparse.Namespace, case: dict[str, object],
             root: Path) -> dict[str, object]:
    name = str(case["name"])
    mode = str(case["mode"])
    iterations = int(case["iterations"])
    separate = bool(case.get("separate"))
    fast_victim = bool(case.get("fast_victim"))
    expected_attacker = bool(case.get("expected_attacker"))
    thin_a = thin_b = proxy = None
    case_root = root / name
    case_root.mkdir()
    old_fast = os.environ.get("RACK_THIN_FAST_VICTIM")
    if fast_victim:
        os.environ["RACK_THIN_FAST_VICTIM"] = "1"
    else:
        os.environ.pop("RACK_THIN_FAST_VICTIM", None)
    try:
        thin_a = start_thin(args.thin, args.fixture, 18181, case_root,
                            "a", mode)
        if separate:
            thin_b = start_thin(args.thin, args.fixture, 18182, case_root,
                                "b", "async_malformed")
        marker = b"A0000_CANARY"
        direct = request(18181, make_body_path(marker), "direct-0000",
                         "tenant-a.example", collect_extra=True)
        direct_extra = direct.get("prefetched_extra", b"")
        direct_tail = isinstance(direct_extra, bytes) and bool(direct_extra)
        proxy = start_apache(
            args.httpd, args.server_root, case_root, 18181,
            18182 if separate else None,
        )
        counts: dict[str, int] = {}
        samples: dict[str, object] = {}
        for i in range(iterations):
            rid = f"probe-{i:04d}"
            marker = f"A{i:04d}_CANARY".encode()
            attack = request(18080, make_body_path(marker), rid,
                             "tenant-a.example")
            if attack.get("kind") != "complete":
                category = "attack_" + str(attack.get("kind", "error"))
            else:
                victim_rid = rid + "-victim"
                victim = request(18080, "/victim", victim_rid,
                                 "tenant-b.example")
                category = classify_victim(
                    victim, victim_rid, b"\x98\x83" + marker[:8],
                    b"VICTIM-OWN",
                )
                samples.setdefault(category, {
                    "victim_kind": victim.get("kind"),
                    "victim_status": victim.get("status"),
                    "victim_headers": victim.get("headers"),
                    "victim_body_hex": victim.get("body", b"").hex(),
                })
            counts[category] = counts.get(category, 0) + 1
        correlation = access_correlation(case_root / "access.log", iterations)
        attacker_hits = counts.get("attacker_bytes_in_victim_body", 0)
        complete_clean = set(counts) == {"clean_victim_response"}
        if expected_attacker:
            result = "PASS" if attacker_hits else "FAIL"
        elif "attack_incomplete_headers" in counts or "truncated_body" in counts:
            result = "INCONCLUSIVE"
        else:
            result = "PASS" if attacker_hits == 0 and complete_clean else "INCONCLUSIVE"
        output = {
            "case": name,
            "mode": mode,
            "separate_backend": separate,
            "fast_victim": fast_victim,
            "direct": {
                "kind": direct.get("kind"),
                "status": direct.get("status"),
                "declared": direct.get("declared"),
                "body_len": len(direct.get("body", b"")),
                "tail_prefix": direct_extra[:32].hex() if isinstance(direct_extra, bytes) else "",
                "tail_present": direct_tail,
            },
            "classification": counts,
            "samples": samples,
            "apache_backend_correlation": correlation,
            "result": result,
        }
        print("case_result=" + json.dumps(output, sort_keys=True))
        if (case_root / "error.log").exists():
            trace = (case_root / "error.log").read_text()
            print(f"case_trace_tail[{name}]=" + trace[-4000:])
        return output
    finally:
        if old_fast is None:
            os.environ.pop("RACK_THIN_FAST_VICTIM", None)
        else:
            os.environ["RACK_THIN_FAST_VICTIM"] = old_fast
        if proxy is not None:
            proxy.terminate()
            try:
                proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxy.kill()
        for proc in (thin_a, thin_b):
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--thin", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    args = parser.parse_args()
    cases = [
        {"name": "shared_async_delayed", "mode": "async_malformed",
         "iterations": 50, "expected_attacker": True},
        {"name": "shared_async_fast_victim", "mode": "async_malformed",
         "iterations": 20, "fast_victim": True},
        {"name": "shared_correct_length_delayed", "mode": "correct_length",
         "iterations": 20},
        {"name": "shared_buffered_malformed_delayed",
         "mode": "buffered_malformed", "iterations": 20},
        {"name": "separate_backend_async_delayed", "mode": "async_malformed",
         "iterations": 20, "separate": True},
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix="rack-thin-stage2-") as tmp:
        root = Path(tmp)
        for case in cases:
            results.append(run_case(args, case, root))
    print("stage2_summary=" + json.dumps([
        {"case": item["case"], "result": item["result"],
         "classification": item["classification"]}
        for item in results
    ], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
