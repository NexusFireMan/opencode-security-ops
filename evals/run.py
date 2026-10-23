#!/usr/bin/env python3
"""Run deterministic safety-contract evaluations without network access."""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".opencode/skills/opencode-security-ops/scripts"))

from secops.scope import check
from secops.store import Store


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

    contracts = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store = Store(root / "state.db")
        eid = store.init_engagement(
            "eval", "api", str(root / "scope.json"), "abc", "2099-01-01T00:00:00+00:00"
        )
        artifact = root / "artifact.txt"
        artifact.write_text("sanitized")
        try:
            store.add_test(
                eid, "WAF stopped after first probe", "complete", positive=artifact,
                notes="A blocked probe must not become a complete negative result",
            )
            controls_enforced = False
        except ValueError:
            controls_enforced = True
        contracts.append({"name": "complete tests require controls and context", "passed": controls_enforced})

        hypothesis_id = store.add_hypothesis(eid, "Possible injection")
        try:
            store.update_hypothesis(eid, hypothesis_id, "incomplete", None)
            resolution_enforced = False
        except ValueError:
            resolution_enforced = True
        contracts.append({"name": "incomplete hypotheses require an explicit reason", "passed": resolution_enforced})
        store.close()

    for contract in contracts:
        if not contract["passed"]:
            failures.append({"case": contract["name"], "expected": True, "actual": False})
    total = len(cases) + len(contracts)
    print(json.dumps({
        "passed": total - len(failures), "failed": len(failures), "contracts": contracts, "failures": failures,
    }, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
