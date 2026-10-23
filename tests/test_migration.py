import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".opencode/skills/opencode-security-ops/scripts"))

from secops.store import Store


class MigrationTests(unittest.TestCase):
    def test_v01_database_is_upgraded_without_data_loss(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            conn = sqlite3.connect(path)
            conn.executescript("""
                CREATE TABLE engagements (
                  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, mode TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'active', scope_path TEXT NOT NULL,
                  scope_sha256 TEXT NOT NULL, started_at TEXT NOT NULL, stop_at TEXT NOT NULL,
                  stop_reason TEXT
                );
                CREATE TABLE findings (
                  id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL, title TEXT NOT NULL,
                  severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'candidate',
                  evidence_path TEXT, evidence_sha256 TEXT, validation_note TEXT,
                  UNIQUE(engagement_id,title)
                );
                INSERT INTO engagements VALUES (
                  1,'legacy','api','active','scope.json','abc','2026-01-01T00:00:00+00:00',
                  '2099-01-01T00:00:00+00:00',NULL
                );
            """)
            conn.commit()
            conn.close()
            store = Store(path)
            row = store.engagement("legacy")
            self.assertEqual(row["platform"], "other")
            self.assertEqual(row["name"], "legacy")
            finding_columns = {item["name"] for item in store.conn.execute("PRAGMA table_info(findings)")}
            self.assertIn("test_id", finding_columns)
            store.close()
