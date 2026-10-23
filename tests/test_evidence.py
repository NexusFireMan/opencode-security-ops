import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".opencode/skills/opencode-security-ops/scripts"))

from secops.evidence import load_context_manifest, load_poc_manifest


class EvidenceManifestTests(unittest.TestCase):
    def test_complete_http_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "context.json"
            path.write_text(json.dumps({
                "version": 1, "kind": "http", "source": "real client flow",
                "method": "GET", "endpoint": "https://api.example.com/v1/item",
                "headers_complete": True, "cookies_complete": True, "body_complete": True,
                "sensitive_data_redacted": True,
            }))
            self.assertEqual(load_context_manifest(path)["kind"], "http")

    def test_incomplete_http_context_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "context.json"
            path.write_text(json.dumps({
                "version": 1, "kind": "http", "source": "simplified curl",
                "method": "GET", "endpoint": "https://api.example.com/v1/item",
                "headers_complete": False, "cookies_complete": True, "body_complete": True,
                "sensitive_data_redacted": True,
            }))
            with self.assertRaises(ValueError):
                load_context_manifest(path)

    def test_portable_poc_and_local_proxy_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "poc.py"
            script.write_text("print('check mode')\n")
            manifest = {
                "version": 1, "kind": "script", "entrypoint": "poc.py",
                "dependencies": [], "required_environment": ["TARGET_URL"],
                "check_mode": True, "timeout_seconds": 10, "uses_local_proxy": False,
                "destructive_by_default": False, "clean_environment_tested": True,
            }
            path = root / "poc.json"
            path.write_text(json.dumps(manifest))
            self.assertEqual(load_poc_manifest(path)["kind"], "script")
            script.write_text("proxy = 'http://127.0.0.1:8090'\n")
            with self.assertRaises(ValueError):
                load_poc_manifest(path)
