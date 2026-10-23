#!/usr/bin/env python3
"""Stage 3: application acceptance and synthetic JSON decision integrity."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

from test_rack_thin_validation import (
    classify_victim,
    make_body_path,
    request,
    start_apache,
    wait_for_port,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd", required=True, type=Path)
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--thin", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--iterations", type=int, default=30)
    args = parser.parse_args()

    expected = b'{"tenant":"B","allowed":false,"secret":"B_SYNTHETIC_SECRET"}'
    with tempfile.TemporaryDirectory(prefix="rack-thin-stage3-") as tmp:
        root = Path(tmp)
        files = root / "files"
        files.mkdir()
        thin_log = root / "thin.log"
        env = {**os.environ, "RACK_FILES_ROOT": str(files),
               "RACK_THIN_VICTIM_MODE": "json"}
        thin = subprocess.Popen(
            [str(args.thin), "start", "-R", str(args.fixture / "config.ru"),
             "-a", "127.0.0.1", "-p", "18181"],
            cwd=args.fixture, stdout=thin_log.open("w"), stderr=subprocess.STDOUT,
            text=True, env=env,
        )
        proxy = None
        try:
            wait_for_port(18181, thin, "Thin", thin_log)
            direct = request(18181, make_body_path(b"A0000_CANARY"),
                             "direct-0000", "tenant-a.example",
                             collect_extra=True)
            proxy = start_apache(args.httpd, args.server_root, root, False)
            categories: dict[str, int] = {}
            valid_json = 0
            contaminated_valid_json = 0
            accepted_decision_changes = 0
            for i in range(args.iterations):
                rid = f"probe-{i:04d}"
                marker = f"A{i:04d}_CANARY".encode()
                attack = request(18080, make_body_path(marker), rid,
                                 "tenant-a.example")
                victim_rid = rid + "-victim"
                victim = request(18080, "/victim", victim_rid,
                                 "tenant-b.example")
                category = classify_victim(
                    victim, victim_rid, b"\x98\x83" + marker[:8], expected,
                )
                categories[category] = categories.get(category, 0) + 1
                body = victim.get("body", b"")
                if victim.get("kind") == "complete" and isinstance(body, bytes):
                    try:
                        parsed = json.loads(body)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        pass
                    else:
                        valid_json += 1
                        if category == "attacker_bytes_in_victim_body":
                            contaminated_valid_json += 1
                        if (category == "attacker_bytes_in_victim_body"
                                and parsed.get("allowed") is not False):
                            accepted_decision_changes += 1
            output = {
                "direct": {
                    "kind": direct.get("kind"),
                    "declared": direct.get("declared"),
                    "tail_prefix": direct.get("prefetched_extra", b"")[:32].hex(),
                },
                "classification": categories,
                "valid_json": valid_json,
                "contaminated_valid_json": contaminated_valid_json,
                "accepted_security_decision_changes": accepted_decision_changes,
                "expected_json": expected.decode(),
                "result": "PASS" if contaminated_valid_json == 0 and accepted_decision_changes == 0 else "FAIL",
            }
            print("stage3_json=" + json.dumps(output, sort_keys=True))
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
