import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / ".opencode/skills/opencode-security-ops/scripts"


class CliTests(unittest.TestCase):
    def run_cli(self, root, *args, expected=0):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SCRIPTS)
        result = subprocess.run(
            [sys.executable, "-m", "secops", "--db", str(root / "state.db"), *args],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stderr or result.stdout)
        stream = result.stdout if result.stdout else result.stderr
        return json.loads(stream)

    def test_end_to_end_and_scope_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = {
                "version": 1,
                "mode": "api",
                "authorization": {"confirmed": True, "reference": "TEST-CLI"},
                "allow": [{"host": "api.example.com", "path_prefixes": ["/v1/"], "methods": ["GET"]}],
                "deny": [],
            }
            scope_path = root / "scope.json"
            scope_path.write_text(json.dumps(scope))
            self.run_cli(root, "init", "--name", "demo", "--scope", str(scope_path), "--minutes", "10")
            allowed = self.run_cli(
                root,
                "scope-check",
                "--engagement",
                "demo",
                "--method",
                "GET",
                "--url",
                "https://api.example.com/v1/status",
            )
            self.assertTrue(allowed["allowed"])

            scope["allow"][0]["methods"].append("POST")
            scope_path.write_text(json.dumps(scope))
            changed = self.run_cli(
                root,
                "scope-check",
                "--engagement",
                "demo",
                "--method",
                "GET",
                "--url",
                "https://api.example.com/v1/status",
                expected=2,
            )
            self.assertEqual(changed["reason"], "SCOPE_DOCUMENT_CHANGED")

    def test_stop_blocks_scope_check_and_handoff_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_path = root / "scope.json"
            scope_path.write_text(json.dumps({
                "version": 1,
                "mode": "api",
                "authorization": {"confirmed": True, "reference": "TEST-STOP"},
                "allow": [{"host": "api.example.com"}],
                "deny": [],
            }))
            self.run_cli(root, "init", "--name", "demo", "--scope", str(scope_path), "--minutes", "10")
            self.run_cli(root, "stop", "--engagement", "demo", "--reason", "operator request")
            blocked = self.run_cli(
                root,
                "scope-check",
                "--engagement",
                "demo",
                "--method",
                "GET",
                "--url",
                "https://api.example.com/",
                expected=2,
            )
            self.assertEqual(blocked["reason"], "ENGAGEMENT_NOT_ACTIVE")
            handoff = root / "handoff.md"
            self.run_cli(root, "handoff", "--engagement", "demo", "--output", str(handoff))
            self.assertIn("operator request", handoff.read_text())
