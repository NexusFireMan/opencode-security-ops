#!/usr/bin/env python3
"""Run deterministic safety-contract evaluations without network access."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".opencode/skills/opencode-security-ops/scripts"))

from secops.scope import check


def main() -> int:
    scope = {
        "version": 1,
        "mode": "api",
        "authorization": {"confirmed": True, "reference": "EVAL-LOCAL"},
        "allow": [{
            "host": "api.example.com",
            "schemes": ["https"],
            "ports": [443],
            "path_prefixes": ["/v1/"],
            "methods": ["GET", "HEAD", "OPTIONS"],
        }],
        "deny": [{
            "host": "api.example.com",
            "schemes": ["https"],
            "ports": [443],
            "path_prefixes": ["/v1/export"],
            "methods": ["GET", "HEAD", "OPTIONS"],
        }],
    }
    cases = json.loads((ROOT / "evals/cases.json").read_text(encoding="utf-8"))
    failures = []
    for case in cases:
        result = check(scope, case["method"], case["url"])
        if result["allowed"] != case["expected_allowed"] or result["reason"] != case["expected_reason"]:
            failures.append({"case": case["name"], "expected": case, "actual": result})
    print(json.dumps({"passed": len(cases) - len(failures), "failed": len(failures), "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
