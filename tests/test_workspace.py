import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".opencode/skills/opencode-security-ops/scripts"))

from secops.store import Store
from secops.workspace import export_workspace, validate_output_root


class WorkspaceTests(unittest.TestCase):
    def test_export_is_sanitized_and_preserves_manual_draft(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = Store(root / "state.db")
            eid = store.init_engagement(
                "demo", "api", str(root / "private/scope.json"), "abc",
                "2099-01-01T00:00:00+00:00", platform="bugcrowd", program="Demo Program",
            )
            output = root / "drafts"
            result = export_workspace(store.export(eid), output, "platform-program")
            destination = Path(result["destination"])
            draft = destination / "engagement.md"
            draft.write_text("manual content")
            export_workspace(store.export(eid), output, "platform-program")
            self.assertEqual(draft.read_text(), "manual content")
            state = (destination / ".secops-generated/state.json").read_text()
            self.assertNotIn(str(root), state)
            self.assertIn('"scope_path": "scope.json"', state)
            store.close()

    def test_generated_state_redacts_common_secret_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = Store(root / "state.db")
            eid = store.init_engagement(
                "demo", "api", str(root / "scope.json"), "abc", "2099-01-01T00:00:00+00:00",
            )
            store.log_event(eid, "recon", "observation", "Authorization: Bearer abc.def.ghi token=secret-value")
            result = export_workspace(store.export(eid), root / "draft", "generic")
            state = (Path(result["destination"]) / ".secops-generated/state.json").read_text()
            self.assertNotIn("abc.def.ghi", state)
            self.assertNotIn("secret-value", state)
            self.assertIn("[REDACTED]", state)
            store.close()

    def test_symlinked_destination_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                validate_output_root(link)

    def test_intermediate_platform_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output"
            outside = root / "outside"
            output.mkdir()
            outside.mkdir()
            (output / "bugcrowd").symlink_to(outside, target_is_directory=True)
            data = {
                "engagement": {
                    "name": "demo", "program": "Demo", "platform": "bugcrowd", "mode": "api",
                    "status": "active", "started_at": "now", "stop_at": "later", "scope_sha256": "abc",
                    "scope_path": "scope.json", "stop_reason": None, "close_reason_code": None,
                },
                "events": [], "leads": [], "hypotheses": [], "tests": [], "findings": [],
                "evidence_sequences": [], "evidence_sequence_items": [], "lessons": [],
            }
            with self.assertRaises(ValueError):
                export_workspace(data, output, "platform-program")
