import sys
import tempfile
import unittest
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

    def test_lead_requires_resolution(self):
        lead_id = self.store.add_lead(self.eid, "/candidate", "manual")
        with self.assertRaises(ValueError):
            self.store.close_lead(self.eid, lead_id, "because")
        self.store.close_lead(self.eid, lead_id, "tested-clean")
        self.assertEqual(self.store.summary(self.eid)["open_leads"], 0)
