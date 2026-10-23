import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".opencode/skills/opencode-security-ops/scripts"))

from secops.budget import budget_status
from secops.gates import evaluate
from secops.scope import scope_hash
from secops.store import Store


class BudgetGateTests(unittest.TestCase):
    def test_expiry_means_stop(self):
        now = datetime.now(timezone.utc)
        result = budget_status((now - timedelta(seconds=1)).isoformat(), now)
        self.assertTrue(result["expired"])
        self.assertEqual(result["directive"], "STOP_ACTIVE_WORK_AND_HANDOFF")

    def test_testing_gate_requires_scope_and_hashed_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_path = root / "scope.json"
            scope = {"version": 1, "mode": "api", "authorization": {"confirmed": True, "reference": "T"}, "allow": [{"host": "api.example.com"}], "deny": []}
            scope_path.write_text(json.dumps(scope))
            store = Store(root / "state.db")
            eid = store.init_engagement("demo", "api", str(scope_path), scope_hash(scope), (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
            engagement = store.engagement("demo")
            self.assertFalse(evaluate(store, engagement, "testing")["passed"])
            store.log_event(eid, "planning", "scope-check", "allowed")
            positive = root / "positive.txt"
            negative = root / "negative.txt"
            context = root / "context.json"
            positive.write_text("redacted positive")
            negative.write_text("redacted negative")
            context.write_text(json.dumps({
                "version": 1, "kind": "http", "source": "test client", "method": "GET",
                "endpoint": "https://api.example.com/", "headers_complete": True,
                "cookies_complete": True, "body_complete": True, "sensitive_data_redacted": True,
            }))
            store.add_test(
                eid, "bounded", "complete", positive=positive, negative=negative,
                context=context, context_complete=True, variable_changed="resource owner",
            )
            self.assertTrue(evaluate(store, engagement, "testing")["passed"])
            store.close()
