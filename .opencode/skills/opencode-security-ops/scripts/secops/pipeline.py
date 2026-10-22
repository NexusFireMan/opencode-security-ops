"""Declarative pipeline validation and planning. Pipelines never auto-execute."""

from __future__ import annotations

import json
from pathlib import Path


SAFE_ACTIONS = {"inspect", "scope-check", "passive-recon", "bounded-test", "validate", "report"}


def load_pipeline(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_pipeline(data)
    return data


def validate_pipeline(data: dict) -> None:
    if data.get("version") != 1 or not isinstance(data.get("name"), str):
        raise ValueError("pipeline requires version 1 and a name")
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("pipeline requires steps")
    seen = set()
    for step in steps:
        sid = step.get("id")
        if not isinstance(sid, str) or not sid or sid in seen:
            raise ValueError("step IDs must be unique non-empty strings")
        seen.add(sid)
        if step.get("action") not in SAFE_ACTIONS:
            raise ValueError(f"unsupported action in step {sid}")
        if step.get("active") and not step.get("approval_required", True):
            raise ValueError(f"active step {sid} must require approval")
        if step.get("state_changing"):
            raise ValueError(f"state-changing step {sid} is not allowed in v1")
        unknown = set(step.get("depends_on", [])) - seen
        if unknown:
            raise ValueError(f"step {sid} depends on unknown or later steps: {sorted(unknown)}")


def plan(data: dict) -> list[dict]:
    validate_pipeline(data)
    return [
        {
            "id": step["id"],
            "action": step["action"],
            "active": bool(step.get("active")),
            "approval_required": bool(step.get("active") or step.get("approval_required")),
            "description": step.get("description", ""),
        }
        for step in data["steps"]
    ]
