"""1. Preserve basic protocol verification results under reports/.

Runs the normative vector checks (Python + JavaScript implementations of
the same wire format) and stores a machine-readable record: what ran, when,
exit codes, output tails, and SHA-256 of the shared vector file. Existing
load results are preserved separately by tools/staged_load.py and
tools/load_test.py runs; this script references any staged-load reports
already present instead of overwriting them.

Usage: python tools/preserve_results.py
"""
from __future__ import annotations

import datetime
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(name: str, command: list[str]) -> dict:
    proc = subprocess.run(command, capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          timeout=600, cwd=ROOT)
    tail = (proc.stdout + proc.stderr).strip().splitlines()[-8:]
    return {"name": name, "command": " ".join(command),
            "exit_code": proc.returncode, "passed": proc.returncode == 0,
            "output_tail": tail}


def main() -> None:
    checks = [
        run("python_test_vectors",
            [sys.executable, "samples/test_vectors.py"]),
        run("javascript_vectors",
            ["node", "--test", "clients/web/oxmp.test.mjs"]),
    ]
    vector_file = ROOT / "clients" / "test_vectors.json"
    reports = ROOT / "reports"
    staged = sorted(p.name for p in reports.glob("staged_load_*.json")) \
        if reports.exists() else []
    payload = {
        "generated_at": datetime.datetime.now().isoformat(),
        "preserved_by": "tools/preserve_results.py",
        "shared_vectors_file": "clients/test_vectors.json",
        "shared_vectors_sha256": hashlib.sha256(
            vector_file.read_bytes()).hexdigest(),
        "checks": checks,
        "all_passed": all(c["passed"] for c in checks),
        "staged_load_reports": staged,
    }
    reports.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = reports / f"protocol_verification_{stamp}.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"preserved: {out}  all_passed={payload['all_passed']}")
    if not payload["all_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
