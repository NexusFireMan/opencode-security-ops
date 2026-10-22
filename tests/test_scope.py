import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".opencode/skills/opencode-security-ops/scripts"))

from secops.scope import ScopeError, check, load_scope, validate_scope_document


def base_scope():
    return {
        "version": 1,
        "mode": "api",
        "authorization": {"confirmed": True, "reference": "TEST-1"},
        "allow": [{
            "host": "api.example.com", "schemes": ["https"], "ports": [443],
            "path_prefixes": ["/v1/"], "methods": ["GET", "HEAD"]
        }],
        "deny": [{
            "host": "api.example.com", "schemes": ["https"], "ports": [443],
            "path_prefixes": ["/v1/export"], "methods": ["GET", "HEAD"]
        }],
        "limits": {"requests_per_second": 1, "max_concurrency": 1},
    }


class ScopeTests(unittest.TestCase):
    def test_exact_allow(self):
        self.assertTrue(check(base_scope(), "GET", "https://api.example.com/v1/status")["allowed"])

    def test_deny_wins(self):
        result = check(base_scope(), "GET", "https://api.example.com/v1/export/42")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "DENY_RULE")

    def test_path_prefix_respects_segment_boundary(self):
        scope = base_scope()
        scope["allow"][0]["path_prefixes"] = ["/v1"]
        self.assertTrue(check(scope, "GET", "https://api.example.com/v1/status")["allowed"])
        self.assertFalse(check(scope, "GET", "https://api.example.com/v10/status")["allowed"])

    def test_method_port_path_and_subdomain_default_deny(self):
        urls = [
            ("POST", "https://api.example.com/v1/status"),
            ("GET", "https://api.example.com:8443/v1/status"),
            ("GET", "https://api.example.com/admin"),
            ("GET", "https://child.api.example.com/v1/status"),
        ]
        for method, url in urls:
            with self.subTest(url=url):
                self.assertFalse(check(base_scope(), method, url)["allowed"])

    def test_wildcard_does_not_include_apex(self):
        scope = base_scope()
        scope["allow"][0]["host"] = "*.example.com"
        self.assertTrue(check(scope, "GET", "https://api.example.com/v1/status")["allowed"])
        self.assertFalse(check(scope, "GET", "https://example.com/v1/status")["allowed"])

    def test_private_and_embedded_credentials_blocked(self):
        scope = base_scope()
        scope["allow"][0]["host"] = "127.0.0.1"
        self.assertFalse(check(scope, "GET", "https://127.0.0.1/v1/status")["allowed"])
        self.assertFalse(check(base_scope(), "GET", "https://user:pass@api.example.com/v1/status")["allowed"])

    def test_ambiguous_paths_are_blocked(self):
        urls = [
            "https://api.example.com/v1/../admin",
            "https://api.example.com/v1/%252e%252e/admin",
            "https://api.example.com/v1/%5cadmin",
            "https://api.example.com/v1/status#fragment",
        ]
        for url in urls:
            with self.subTest(url=url):
                result = check(base_scope(), "GET", url)
                self.assertFalse(result["allowed"])
                self.assertEqual(result["reason"], "INVALID_TARGET")

    def test_authorization_required(self):
        scope = base_scope()
        scope["authorization"]["confirmed"] = False
        with self.assertRaises(ScopeError):
            validate_scope_document(scope)

    def test_ambiguous_scope_rules_are_rejected(self):
        invalid_rules = [
            {"host": "*.*.example.com"},
            {"host": " api.example.com"},
            {"host": "api.example.com/path"},
            {"host": "api.example.com", "methods": [""]},
            {"host": "api.example.com", "path_prefixes": ["/v1/%2e%2e/admin"]},
            {"host": "api.example.com", "path_prefixes": ["/v1?admin=true"]},
        ]
        for rule in invalid_rules:
            with self.subTest(rule=rule):
                scope = base_scope()
                scope["allow"] = [rule]
                with self.assertRaises(ScopeError):
                    validate_scope_document(scope)

    def test_load_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps(base_scope()))
            self.assertEqual(load_scope(path)["mode"], "api")
