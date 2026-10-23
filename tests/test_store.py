import sys
import tempfile
import unittest
import json
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".opencode/skills/opencode-security-ops/scripts"))

from secops.store import Store, file_sha256


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / "state.db")
        self.eid = self.store.init_engagement("demo", "api", str(self.root / "scope.json"), "abc", "2099-01-01T00:00:00+00:00")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_event_artifact_is_hashed(self):
        artifact = self.root / "evidence.txt"
        artifact.write_text("sanitized evidence")
        event_id = self.store.log_event(self.eid, "testing", "test", "bounded test", artifact=artifact)
        row = self.store.conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        self.assertEqual(row["artifact_sha256"], file_sha256(artifact))

    def test_confirmed_finding_requires_evidence(self):
        with self.assertRaises(ValueError):
            self.store.add_finding(self.eid, "Unproven", "high", "confirmed")
        evidence = self.root / "evidence.txt"
        evidence.write_text("sanitized")
        with self.assertRaises(ValueError):
            self.store.add_finding(self.eid, "Still unproven", "high", "confirmed", evidence=evidence)

    def test_complete_test_and_confirmed_finding_require_controls(self):
        positive = self.root / "positive.txt"
        negative = self.root / "negative.txt"
        context = self.root / "context.json"
        evidence = self.root / "evidence.txt"
        for path in (positive, negative, evidence):
            path.write_text("sanitized")
        context.write_text(json.dumps({
            "version": 1, "kind": "http", "source": "test client", "method": "GET",
            "endpoint": "https://api.example.com/item", "headers_complete": True,
            "cookies_complete": True, "body_complete": True, "sensitive_data_redacted": True,
        }))
        with self.assertRaises(ValueError):
            self.store.add_test(self.eid, "incomplete context", "complete", positive=positive, negative=negative)
        test_id = self.store.add_test(
            self.eid, "cross-account access", "complete", positive=positive, negative=negative,
            context=context, context_complete=True, variable_changed="authenticated account",
        )
        finding_id = self.store.add_finding(
            self.eid, "Cross-account access", "high", "confirmed", evidence=evidence,
            validation_note="Reproduced twice", test_id=test_id, root_cause="owner not checked",
            security_boundary="account isolation", attacker_gain="reads another test account",
        )
        row = self.store.conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        self.assertEqual(row["test_id"], test_id)

    def test_candidate_can_be_promoted_without_rewriting_history(self):
        candidate_id = self.store.add_finding(self.eid, "Candidate IDOR", "medium")
        positive = self.root / "positive-promote.txt"
        negative = self.root / "negative-promote.txt"
        context = self.root / "context-promote.json"
        evidence = self.root / "evidence-promote.txt"
        for path in (positive, negative, evidence):
            path.write_text("sanitized")
        context.write_text(json.dumps({
            "version": 1, "kind": "http", "source": "test client", "method": "GET",
            "endpoint": "https://api.example.com/item", "headers_complete": True,
            "cookies_complete": True, "body_complete": True, "sensitive_data_redacted": True,
        }))
        test_id = self.store.add_test(
            self.eid, "candidate validation", "complete", positive=positive, negative=negative,
            context=context, context_complete=True, variable_changed="object owner",
        )
        self.store.update_finding(
            self.eid, candidate_id, severity="high", status="confirmed", evidence=evidence,
            validation_note="reproduced", test_id=test_id, root_cause="missing owner check",
            security_boundary="account", attacker_gain="read controlled peer object",
        )
        row = self.store.conn.execute("SELECT * FROM findings WHERE id=?", (candidate_id,)).fetchone()
        self.assertEqual(row["status"], "confirmed")

    def test_new_database_is_owner_only(self):
        mode = stat.S_IMODE(self.store.path.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_hypothesis_terminal_states_require_resolution(self):
        hypothesis_id = self.store.add_hypothesis(self.eid, "Possible IDOR")
        with self.assertRaises(ValueError):
            self.store.update_hypothesis(self.eid, hypothesis_id, "incomplete", None)
        self.store.update_hypothesis(self.eid, hypothesis_id, "incomplete", "second account unavailable")
        row = self.store.conn.execute("SELECT * FROM hypotheses WHERE id=?", (hypothesis_id,)).fetchone()
        self.assertEqual(row["status"], "incomplete")

    def test_sequence_items_are_hashed_and_ordered(self):
        sequence_id = self.store.create_sequence(self.eid, "revocation window")
        artifact = self.root / "step.txt"
        artifact.write_text("sanitized response")
        self.store.add_sequence_item(self.eid, sequence_id, 1, "before revocation", artifact)
        with self.assertRaises(Exception):
            self.store.add_sequence_item(self.eid, sequence_id, 1, "duplicate position", artifact)
        exported = self.store.export(self.eid)
        self.assertEqual(exported["evidence_sequence_items"][0]["artifact_sha256"], file_sha256(artifact))

    def test_sequence_timestamps_follow_position_order(self):
        sequence_id = self.store.create_sequence(self.eid, "ordered timeline")
        artifact = self.root / "timeline.txt"
        artifact.write_text("sanitized")
        self.store.add_sequence_item(
            self.eid, sequence_id, 1, "first", artifact, "2026-01-01T10:00:00+00:00"
        )
        with self.assertRaises(ValueError):
            self.store.add_sequence_item(
                self.eid, sequence_id, 2, "earlier clock", artifact, "2026-01-01T09:59:59+00:00"
            )

    def test_finding_cannot_link_test_from_another_engagement(self):
        other = self.store.init_engagement(
            "other", "api", str(self.root / "other-scope.json"), "def", "2099-01-01T00:00:00+00:00"
        )
        positive = self.root / "other-positive.txt"
        negative = self.root / "other-negative.txt"
        context = self.root / "other-context.json"
        positive.write_text("sanitized")
        negative.write_text("sanitized")
        context.write_text(json.dumps({
            "version": 1, "kind": "http", "source": "test client", "method": "GET",
            "endpoint": "https://api.example.com/item", "headers_complete": True,
            "cookies_complete": True, "body_complete": True, "sensitive_data_redacted": True,
        }))
        test_id = self.store.add_test(
            other, "other test", "complete", positive=positive, negative=negative,
            context=context, context_complete=True, variable_changed="account",
        )
        with self.assertRaises(ValueError):
            self.store.add_finding(self.eid, "Bad cross-link", "medium", test_id=test_id)

    def test_lead_requires_resolution(self):
        lead_id = self.store.add_lead(self.eid, "/candidate", "manual")
        with self.assertRaises(ValueError):
            self.store.close_lead(self.eid, lead_id, "because")
        self.store.close_lead(self.eid, lead_id, "tested-clean")
        self.assertEqual(self.store.summary(self.eid)["open_leads"], 0)
