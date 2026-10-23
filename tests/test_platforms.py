import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".opencode/skills/opencode-security-ops/scripts"))

from secops.platforms import normalize_platform, validate_intake, validate_platform_rating


class PlatformTests(unittest.TestCase):
    def test_aliases_and_ratings(self):
        self.assertEqual(normalize_platform("YWH"), "yeswehack")
        validate_platform_rating("bugcrowd", "P3")
        with self.assertRaises(ValueError):
            validate_platform_rating("bugcrowd", "critical")

    def test_intake_constraints_are_explicit(self):
        data = validate_intake({
            "version": 1, "platform": "H1", "program": "Demo",
            "constraints": {"submission_limit": 2, "excluded_techniques": ["DoS"]},
        })
        self.assertEqual(data["platform"], "hackerone")
        with self.assertRaises(ValueError):
            validate_intake({"version": 1, "platform": "hackerone", "program": "Demo", "constraints": {"token": "secret"}})
