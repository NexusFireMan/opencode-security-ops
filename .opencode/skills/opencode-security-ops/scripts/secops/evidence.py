"""Validation for sanitized test-context and portable-PoC manifests."""

from __future__ import annotations

import json
import re
from pathlib import Path


def load_context_manifest(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_context_manifest(data)
    return data


def validate_context_manifest(data: dict) -> None:
    if data.get("version") != 1:
        raise ValueError("context.version must be 1")
    kind = data.get("kind")
    if kind not in {"http", "source", "manual"}:
        raise ValueError("context.kind must be http, source, or manual")
    if data.get("sensitive_data_redacted") is not True:
        raise ValueError("context must confirm sensitive_data_redacted=true")
    if not isinstance(data.get("source"), str) or not data["source"].strip():
        raise ValueError("context.source is required")
    if kind == "http":
        for field in ("method", "endpoint"):
            if not isinstance(data.get(field), str) or not data[field].strip():
                raise ValueError(f"HTTP context requires {field}")
        for field in ("headers_complete", "cookies_complete", "body_complete"):
            if data.get(field) is not True:
                raise ValueError(f"HTTP context requires {field}=true; otherwise record the test as incomplete")
    elif kind == "source":
        if not isinstance(data.get("repository_revision"), str) or not data["repository_revision"].strip():
            raise ValueError("source context requires repository_revision")
        locations = data.get("locations")
        if not isinstance(locations, list) or not locations:
            raise ValueError("source context requires non-empty locations")
    elif not isinstance(data.get("description"), str) or not data["description"].strip():
        raise ValueError("manual context requires description")


def load_poc_manifest(path: str | Path) -> dict:
    manifest = Path(path).resolve(strict=True)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    validate_poc_manifest(data, manifest.parent)
    return data


def validate_poc_manifest(data: dict, base_dir: str | Path) -> None:
    if data.get("version") != 1:
        raise ValueError("poc.version must be 1")
    kind = data.get("kind")
    if kind not in {"script", "manual-http", "continuous-evidence"}:
        raise ValueError("poc.kind must be script, manual-http, or continuous-evidence")
    for field, expected in (
        ("clean_environment_tested", True),
        ("destructive_by_default", False),
    ):
        if data.get(field) is not expected:
            raise ValueError(f"poc.{field} must be {str(expected).lower()}")
    timeout = data.get("timeout_seconds")
    if not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("poc.timeout_seconds must be a positive integer")
    if kind == "script":
        if data.get("check_mode") is not True:
            raise ValueError("script PoCs require check_mode=true")
        if data.get("uses_local_proxy") is not False:
            raise ValueError("script PoCs require uses_local_proxy=false")
        entrypoint = data.get("entrypoint")
        if not isinstance(entrypoint, str) or not entrypoint.strip():
            raise ValueError("script PoCs require entrypoint")
        entrypoint_path = (Path(base_dir) / entrypoint).resolve(strict=True)
        root = Path(base_dir).resolve(strict=True)
        if entrypoint_path != root and root not in entrypoint_path.parents:
            raise ValueError("poc.entrypoint escapes the manifest directory")
        if not entrypoint_path.is_file():
            raise ValueError("poc.entrypoint is not a file")
        text = entrypoint_path.read_text(encoding="utf-8", errors="replace")
        suspicious = []
        checks = {
            "local proxy reference": r"(?:127\.0\.0\.1|localhost):\d+",
            "Unix home path": r"/(?:home|Users)/[^/\s]+/",
            "Windows absolute path": r"[A-Za-z]:\\(?:Users|Documents and Settings)\\",
        }
        for label, pattern in checks.items():
            if re.search(pattern, text):
                suspicious.append(label)
        if suspicious:
            raise ValueError("PoC portability check found: " + ", ".join(suspicious))
        for field in ("dependencies", "required_environment"):
            if not isinstance(data.get(field), list) or any(not isinstance(item, str) for item in data[field]):
                raise ValueError(f"script PoCs require {field} as a list of strings")
