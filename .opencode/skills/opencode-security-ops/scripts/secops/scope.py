"""Exact, deny-first scope validation with no network access."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


class ScopeError(ValueError):
    pass


def load_scope(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_scope_document(data)
    return data


def scope_hash(scope: dict) -> str:
    canonical = json.dumps(scope, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def validate_scope_document(scope: dict) -> None:
    if scope.get("version") != 1:
        raise ScopeError("scope.version must be 1")
    auth = scope.get("authorization")
    if not isinstance(auth, dict) or auth.get("confirmed") is not True:
        raise ScopeError("authorization.confirmed must be true")
    if not isinstance(auth.get("reference"), str) or not auth["reference"].strip():
        raise ScopeError("authorization.reference is required (ticket or non-secret reference)")
    mode = scope.get("mode")
    if mode not in {"web", "api", "cloud-external", "code-audit"}:
        raise ScopeError("mode must be web, api, cloud-external, or code-audit")
    allow = scope.get("allow")
    if mode != "code-audit" and (not isinstance(allow, list) or not allow):
        raise ScopeError("network modes require at least one allow rule")
    for section in ("allow", "deny"):
        rules = scope.get(section, [])
        if not isinstance(rules, list):
            raise ScopeError(f"{section} must be a list")
        for rule in rules:
            _validate_rule(rule, section)
    limits = scope.get("limits", {})
    if not isinstance(limits, dict):
        raise ScopeError("limits must be an object")
    for key in ("requests_per_second", "max_concurrency"):
        if key in limits and (not isinstance(limits[key], (int, float)) or limits[key] <= 0):
            raise ScopeError(f"limits.{key} must be positive")


def _validate_rule(rule: dict, section: str) -> None:
    if not isinstance(rule, dict):
        raise ScopeError(f"{section} rules must be objects")
    host = rule.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ScopeError(f"{section} rule host is required")
    if host != host.strip() or any(char in host for char in "/@?#"):
        raise ScopeError("rule hosts must not contain whitespace, URL delimiters, or credentials")
    if "*" in host and (not host.startswith("*.") or host.count("*") != 1 or len(host) <= 2):
        raise ScopeError("wildcards are allowed only as a leading '*.'")
    schemes = rule.get("schemes", ["https"])
    if not schemes or any(s not in {"http", "https"} for s in schemes):
        raise ScopeError("schemes may contain only http and https")
    ports = rule.get("ports", [])
    if any(not isinstance(p, int) or p < 1 or p > 65535 for p in ports):
        raise ScopeError("ports must be integers from 1 to 65535")
    methods = rule.get("methods", [])
    if any(not isinstance(m, str) or not m or m.upper() != m for m in methods):
        raise ScopeError("methods must be non-empty uppercase strings")
    prefixes = rule.get("path_prefixes", ["/"])
    if not prefixes or any(not isinstance(p, str) or not p.startswith("/") for p in prefixes):
        raise ScopeError("path_prefixes must be non-empty absolute URL paths")
    for prefix in prefixes:
        if unquote(prefix) != prefix:
            raise ScopeError("path_prefixes must be decoded, unambiguous paths")
        if any(char in prefix for char in "\\\x00?#"):
            raise ScopeError("path_prefixes must not contain backslashes, NUL, query strings, or fragments")
        if any(segment in {".", ".."} for segment in prefix.split("/")):
            raise ScopeError("path_prefixes must not contain dot segments")


@dataclass(frozen=True)
class RequestTarget:
    scheme: str
    host: str
    port: int
    path: str
    method: str


def parse_target(method: str, url: str) -> RequestTarget:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ScopeError(f"invalid URL: {exc}") from exc
    if parsed.scheme not in {"http", "https"}:
        raise ScopeError("only http and https URLs are supported")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ScopeError("URL must have a hostname and no embedded credentials")
    if parsed.fragment:
        raise ScopeError("URL fragments are not allowed")
    host = parsed.hostname.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved):
        raise ScopeError("private, local, reserved, and metadata-address targets are excluded")
    raw_path = parsed.path or "/"
    normalized_path = unquote(raw_path)
    if unquote(normalized_path) != normalized_path:
        raise ScopeError("multiply encoded paths are not allowed")
    if "\x00" in normalized_path:
        raise ScopeError("NUL bytes are not allowed in paths")
    if "\\" in normalized_path:
        raise ScopeError("backslashes are not allowed in paths")
    if any(segment in {".", ".."} for segment in normalized_path.split("/")):
        raise ScopeError("dot path segments are not allowed")
    return RequestTarget(
        scheme=parsed.scheme,
        host=host,
        port=port or (443 if parsed.scheme == "https" else 80),
        path=normalized_path,
        method=method.upper(),
    )


def _host_matches(pattern: str, host: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host != suffix and host.endswith("." + suffix)
    return host == pattern


def _rule_matches(rule: dict, target: RequestTarget) -> bool:
    if not _host_matches(rule["host"], target.host):
        return False
    if target.scheme not in rule.get("schemes", ["https"]):
        return False
    ports = rule.get("ports") or [443 if target.scheme == "https" else 80]
    if target.port not in ports:
        return False
    methods = rule.get("methods") or ["GET", "HEAD", "OPTIONS"]
    if target.method not in methods:
        return False
    def path_matches(prefix: str) -> bool:
        if prefix == "/":
            return True
        if prefix.endswith("/"):
            return target.path.startswith(prefix)
        return target.path == prefix or target.path.startswith(prefix + "/")

    return any(path_matches(prefix) for prefix in rule.get("path_prefixes", ["/"]))


def check(scope: dict, method: str, url: str) -> dict:
    validate_scope_document(scope)
    if scope["mode"] == "code-audit":
        return {"allowed": False, "reason": "CODE_AUDIT_HAS_NO_NETWORK_SCOPE"}
    try:
        target = parse_target(method, url)
    except ScopeError as exc:
        return {"allowed": False, "reason": "INVALID_TARGET", "detail": str(exc)}
    for index, rule in enumerate(scope.get("deny", [])):
        if _rule_matches(rule, target):
            return {"allowed": False, "reason": "DENY_RULE", "rule_index": index}
    for index, rule in enumerate(scope.get("allow", [])):
        if _rule_matches(rule, target):
            return {"allowed": True, "reason": "ALLOW_RULE", "rule_index": index}
    return {"allowed": False, "reason": "DEFAULT_DENY"}
