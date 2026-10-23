"""Optional, generic draft workspace export with symlink and overwrite guards."""

from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path

from .report import render


LAYOUTS = {"generic", "platform-program"}
DIRECTORIES = ("scope", "recon", "hypotheses", "findings", "reports", "evidence", "scripts", "references")


def slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not result:
        raise ValueError("name cannot be converted to a safe path component")
    return result[:80]


def validate_output_root(path: str | Path) -> Path:
    raw = Path(path).expanduser()
    if raw.exists() and raw.is_symlink():
        raise ValueError("output directory must not be a symlink")
    resolved = raw.resolve(strict=False)
    if resolved == Path(resolved.anchor):
        raise ValueError("filesystem root cannot be used as an output directory")
    return resolved


def destination_for(output_root: str | Path, layout: str, engagement: dict) -> Path:
    if layout not in LAYOUTS:
        raise ValueError(f"layout must be one of: {', '.join(sorted(LAYOUTS))}")
    root = validate_output_root(output_root)
    if layout == "platform-program":
        return root / slug(engagement.get("platform") or "other") / slug(engagement.get("program") or engagement["name"])
    return root


def _ensure_directory(path: Path) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise ValueError(f"refusing unsafe output path: {path}")
    path.mkdir(parents=True, exist_ok=True)


def _write_atomic(path: Path, content: str, *, replace: bool) -> bool:
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing symlinked output file: {path}")
    if path.exists() and not replace:
        return False
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return True


def sanitized_export(data: dict) -> dict:
    clean = json.loads(json.dumps(data))
    engagement = clean["engagement"]
    for key in ("scope_path", "output_dir"):
        if engagement.get(key):
            engagement[key] = Path(engagement[key]).name
    for table, fields in {
        "events": ("artifact",),
        "tests": ("positive_artifact", "negative_artifact", "context_artifact"),
        "findings": ("evidence_path", "poc_manifest_path"),
        "evidence_sequence_items": ("artifact",),
    }.items():
        for row in clean.get(table, []):
            for field in fields:
                if row.get(field):
                    row[field] = Path(row[field]).name
    secret_patterns = (
        (re.compile(r"(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]+"), r"\1 [REDACTED]"),
        (re.compile(r"(?i)\b(authorization|cookie|set-cookie|api[_-]?key|token|password)\s*[:=]\s*[^\s,;]+"), r"\1=[REDACTED]"),
    )

    def redact(value):
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, str):
            for pattern, replacement in secret_patterns:
                value = pattern.sub(replacement, value)
        return value

    return redact(clean)


def export_workspace(data: dict, output_root: str | Path, layout: str) -> dict:
    root = validate_output_root(output_root)
    _ensure_directory(root)
    destination = destination_for(root, layout, data["engagement"])
    # Create/check each managed component separately so an existing intermediate
    # symlink cannot redirect a platform-program export outside the chosen root.
    current = root
    for component in destination.relative_to(root).parts:
        current = current / component
        _ensure_directory(current)
    for dirname in DIRECTORIES:
        _ensure_directory(destination / dirname)
    generated = destination / ".secops-generated"
    _ensure_directory(generated)

    clean = sanitized_export(data)
    state_path = generated / "state.json"
    handoff_path = generated / "handoff.md"
    _write_atomic(state_path, json.dumps(clean, indent=2, sort_keys=True) + "\n", replace=True)
    _write_atomic(handoff_path, render(clean), replace=True)

    draft = destination / "engagement.md"
    created = _write_atomic(
        draft,
        (
            f"# {data['engagement'].get('program') or data['engagement']['name']}\n\n"
            f"- Platform: `{data['engagement'].get('platform') or 'other'}`\n"
            f"- Engagement: `{data['engagement']['name']}`\n\n"
            "## Scope\n\n<!-- Operator-maintained draft. Generated state is under .secops-generated/. -->\n\n"
            "## Recon\n\n## Hypotheses\n\n## Findings\n\n## Lessons\n"
        ),
        replace=False,
    )
    return {
        "destination": str(destination),
        "created_engagement_draft": created,
        "generated": [str(state_path), str(handoff_path)],
        "policy": "generated files refreshed; operator-maintained files never overwritten",
    }
