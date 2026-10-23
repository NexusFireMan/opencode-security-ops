import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class OpenCodeFilesTests(unittest.TestCase):
    def test_skill_identity(self):
        text = (ROOT / ".opencode/skills/opencode-security-ops/SKILL.md").read_text()
        self.assertRegex(text, r"(?m)^name: opencode-security-ops$")
        self.assertRegex(text, r"(?m)^description: .+")

    def test_agents_use_v2_permissions(self):
        for path in (ROOT / ".opencode/agents").glob("*.md"):
            text = path.read_text()
            with self.subTest(path=path):
                self.assertIn("permissions:", text)
                self.assertNotRegex(text, r"(?m)^permission:")
                self.assertNotIn("action: bash", text)
                self.assertNotIn("action: task", text)

    def test_reviewers_are_default_deny(self):
        for name in ("secops-reviewer.md", "secops-evidence-reviewer.md"):
            text = (ROOT / ".opencode/agents" / name).read_text()
            self.assertIn('action: "*"\n    resource: "*"\n    effect: deny', text)
            self.assertIn("action: external_directory\n    resource: \"*\"\n    effect: deny", text)

    def test_orchestrator_requires_approval_by_default(self):
        text = (ROOT / ".opencode/agents/secops-orchestrator.md").read_text()
        self.assertIn('action: "*"\n    resource: "*"\n    effect: ask', text)
        self.assertIn("action: browser\n    resource: \"*\"\n    effect: deny", text)

    def test_commands_are_namespaced_and_have_no_shell_expansion(self):
        commands = list((ROOT / ".opencode/commands/secops").glob("*.md"))
        self.assertEqual(
            {path.stem for path in commands},
            {"engage", "audit", "validate", "report", "intake", "hypothesis", "retest", "close", "lessons"},
        )
        for path in commands:
            self.assertNotIn("!`", path.read_text())
