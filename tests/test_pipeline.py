import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".opencode/skills/opencode-security-ops/scripts"))

from secops.pipeline import load_pipeline, validate_pipeline


class PipelineTests(unittest.TestCase):
    def test_shipped_pipelines_validate(self):
        for path in (ROOT / "pipelines").glob("*.json"):
            with self.subTest(path=path):
                self.assertEqual(load_pipeline(path)["version"], 1)

    def test_active_step_requires_approval(self):
        data = {"version": 1, "name": "bad", "steps": [{"id": "x", "action": "bounded-test", "active": True, "approval_required": False}]}
        with self.assertRaises(ValueError):
            validate_pipeline(data)

    def test_state_changes_rejected(self):
        data = {"version": 1, "name": "bad", "steps": [{"id": "x", "action": "bounded-test", "state_changing": True}]}
        with self.assertRaises(ValueError):
            validate_pipeline(data)
