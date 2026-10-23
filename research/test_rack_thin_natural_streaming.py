#!/usr/bin/env python3
"""Final natural Rack/Thin streaming validation.

The A response keeps the previously established malformed/delayed prerequisite.
The new C case uses a standard Rack Enumerable body (`String#each_line`) for B,
with a correct Content-Length and no timer. It is not enough for a body to be
different: only a complete B response with the A canary and B identity counts
as confirmed contamination.
"""

from __future__ import annotations

import argparse
import hashlib
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


STREAM_BODY = (b"B_STREAM_CHUNK_0000\n" * 16_384)


def start_thin(thin: Path, fixture: Path, port: int, root: Path,
               label: str, mode: str, victim_mode: str,
               fast_victim: bool) -> subprocess.Popen[str]:
    files = root / f"files-{label}"
    files.mkdir()
    request_log = root / f"rack-{label}.log"
    log = root / f"thin-{label}.log"
    env = {
        **os.environ,
        "RACK_FILES_ROOT": str(files),
        "RACK_THIN_REQUEST_LOG": str(request_log),
        "RACK_THIN_A_MODE": mode,
        "RACK_THIN_VICTIM_MODE": victim_mode,
    }
    if fast_victim:
        env["RACK_THIN_FAST_VICTIM"] = "1"
    else:
        env.pop("RACK_THIN_FAST_VICTIM", None)
    proc = subprocess.Popen(
        [str(thin), "start", "-R", str(fixture / "config.ru"),
         "-a", "127.0.0.1", "-p", str(port)],
        cwd=fixture, stdout=log.open("w"), stderr=subprocess.STDOUT,
        text=True, env=env,
    )
    wait_for_port(port, proc, f"Thin-{label}", log)
    return proc


def start_apache(httpd: Path, server_root: Path, root: Path,
                 disablereuse: bool) -> subprocess.Popen[str]:
    reuse = " disablereuse=On" if disablereuse else ""
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


def result_category(victim: dict[str, object], rid: str,
                    canary_prefix: bytes, expected: bytes) -> tuple[str, str]:
    kind = str(victim.get("kind", "unknown"))
    if kind != "complete":
        return "HTTP ERROR", kind
    if victim.get("status") != 200:
        return "HTTP ERROR", f"status={victim.get('status')}"
    headers = victim.get("headers")
    if not isinstance(headers, dict):
        return "INCONCLUSIVE", "missing_headers"
    if headers.get("x-probe-id") != rid or headers.get("x-tenant") != "B":
        return "INCONCLUSIVE", "victim_identity_mismatch"
    body = victim.get("body")
    if not isinstance(body, bytes):
        return "INCONCLUSIVE", "missing_body"
    if canary_prefix in body:
        return "CONFIRMED CONTAMINATION", "A_canary_in_complete_B_response"
    if body == expected:
        return "CLEAN RESPONSE", "exact_expected_B_body"
    return "RESPONSE CORRUPTION WITHOUT PROVENANCE", "unexpected_B_body"


def save_sample(evidence_dir: Path, case: str, category: str,
                rid: str, victim: dict[str, object], reason: str) -> dict[str, object]:
    body = victim.get("body", b"")
    if not isinstance(body, bytes):
        body = b""
    safe_category = category.lower().replace(" ", "_")
    raw_path = evidence_dir / f"{case}-{safe_category}.body"
    if not raw_path.exists():
        raw_path.write_bytes(body)
    return {
        "request_id": rid,
        "category": category,
        "reason": reason,
        "status": victim.get("status"),
        "headers": victim.get("headers", {}),
        "body_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_prefix_hex": body[:128].hex(),
        "body_suffix_hex": body[-128:].hex() if body else "",
        "raw_body_artifact": str(raw_path.name),
    }


def run_case(args: argparse.Namespace, case: dict[str, object], root: Path,
             evidence_dir: Path) -> dict[str, object]:
    name = str(case["name"])
    victim_mode = str(case["victim_mode"])
    iterations = int(case["iterations"])
    fast_victim = bool(case.get("fast_victim"))
    disablereuse = bool(case.get("disablereuse"))
    case_root = root / name
    case_root.mkdir()
    thin = proxy = None
    try:
        thin = start_thin(args.thin, args.fixture, 18181, case_root, "a",
                          "async_malformed", victim_mode, fast_victim)
        direct = request(18181, make_body_path(b"NATURAL_DIRECT"),
                         "direct-0000", "tenant-a.example", collect_extra=True)
        direct_extra = direct.get("prefetched_extra", b"")
        proxy = start_apache(args.httpd, args.server_root, case_root,
                             disablereuse)
        counts: dict[str, int] = {}
        samples: dict[str, dict[str, object]] = {}
        for i in range(iterations):
            rid = f"probe-{i:04d}"
            marker = f"A{i:04d}_CANARY".encode()
            attack = request(18080, make_body_path(marker), rid,
                             "tenant-a.example")
            if attack.get("kind") != "complete":
                category, reason = "HTTP ERROR", f"attack_{attack.get('kind')}"
                counts[category] = counts.get(category, 0) + 1
                continue
            victim_rid = rid + "-victim"
            victim = request(18080, "/victim", victim_rid,
                             "tenant-b.example")
            category, reason = result_category(
                victim, victim_rid, b"\x98\x83" + marker[:8],
                STREAM_BODY if victim_mode == "enumerable_stream" else b"VICTIM-OWN",
            )
            counts[category] = counts.get(category, 0) + 1
            if category not in samples:
                samples[category] = save_sample(
                    evidence_dir, name, category, victim_rid, victim, reason)
        correlation = access_correlation(case_root / "access.log", iterations)
        output = {
            "case": name,
            "victim_mode": victim_mode,
            "iterations": iterations,
            "disablereuse": disablereuse,
            "direct": {
                "kind": direct.get("kind"),
                "declared": direct.get("declared"),
                "body_len": len(direct.get("body", b"")),
                "tail_present": bool(direct_extra),
                "tail_prefix_hex": direct_extra[:32].hex() if isinstance(direct_extra, bytes) else "",
            },
            "classification": counts,
            "samples": samples,
            "apache_backend_correlation": correlation,
        }
        print("natural_case_result=" + json.dumps(output, sort_keys=True))
        if (case_root / "error.log").exists():
            trace = (case_root / "error.log").read_text()
            print(f"natural_case_trace_tail[{name}]=" + trace[-3000:])
        return output
    finally:
        if proxy is not None:
            proxy.terminate()
            try:
                proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxy.kill()
        if thin is not None:
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
    args = parser.parse_args()
    cases = [
        {"name": "A_reference_delayed_fixture", "victim_mode": "plain",
         "iterations": 10},
        {"name": "B_ordinary_buffered_victim", "victim_mode": "plain",
         "iterations": 10, "fast_victim": True},
        {"name": "C_legitimate_enumerable_stream", "victim_mode": "enumerable_stream",
         "iterations": 20},
        {"name": "D_stream_reuse_disabled", "victim_mode": "enumerable_stream",
         "iterations": 10, "disablereuse": True},
    ]
    with tempfile.TemporaryDirectory(prefix="rack-thin-natural-") as tmp:
        root = Path(tmp)
        evidence_dir = root / "evidence"
        evidence_dir.mkdir()
        results = [run_case(args, case, root, evidence_dir) for case in cases]
        manifest = {
            "synthetic_only": True,
            "raw_body_files": sorted(path.name for path in evidence_dir.glob("*.body")),
            "cases": results,
        }
        (evidence_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        print("natural_streaming_summary=" + json.dumps([
            {"case": item["case"], "classification": item["classification"],
             "correlation": item["apache_backend_correlation"]}
            for item in results
        ], sort_keys=True))
        # Copy evidence before the reference assertion so an unexpected
        # harness failure still leaves raw synthetic responses for diagnosis.
        output_dir = Path(os.environ.get("NATURAL_EVIDENCE_DIR", "natural-evidence"))
        output_dir.mkdir(parents=True, exist_ok=True)
        for path in evidence_dir.iterdir():
            target = output_dir / path.name
            target.write_bytes(path.read_bytes())
        # The reference must still prove the harness is live. Other outcomes
        # are reported, not converted into a pass/fail assertion.
        reference = results[0]["classification"]
        if not reference.get("CONFIRMED CONTAMINATION"):
            raise SystemExit("reference baseline did not reproduce contamination")
        print("natural_streaming_reference=PASS")
        print(f"natural_streaming_evidence_dir={evidence_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
