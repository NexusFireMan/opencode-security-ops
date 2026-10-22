"""Generate a factual Markdown handoff from recorded state."""

from __future__ import annotations

from pathlib import Path


def render(data: dict) -> str:
    engagement = data["engagement"]
    findings = data["findings"]
    leads = data["leads"]
    events = data["events"]
    lines = [
        f"# Security engagement handoff: {engagement['name']}",
        "",
        "## Status",
        "",
        f"- Mode: `{engagement['mode']}`",
        f"- State: `{engagement['status']}`",
        f"- Started: `{engagement['started_at']}`",
        f"- Stop time: `{engagement['stop_at']}`",
        f"- Stop reason: {engagement.get('stop_reason') or 'Not stopped'}",
        f"- Scope SHA-256: `{engagement['scope_sha256']}`",
        "",
        "## Confirmed findings",
        "",
    ]
    confirmed = [f for f in findings if f["status"] == "confirmed"]
    if not confirmed:
        lines.append("No confirmed findings are recorded.")
    for finding in confirmed:
        lines.extend([
            f"### {finding['title']}",
            f"- Severity: **{finding['severity']}**",
            f"- Validation: {finding.get('validation_note') or 'Missing'}",
            f"- Evidence: `{finding.get('evidence_path') or 'Missing'}`",
            f"- Evidence SHA-256: `{finding.get('evidence_sha256') or 'Missing'}`",
            "",
        ])
    lines.extend(["## Open leads", ""])
    open_leads = [lead for lead in leads if lead["status"] == "open"]
    if not open_leads:
        lines.append("No open leads.")
    for lead in open_leads:
        lines.append(f"- `{lead['value']}` (source: {lead['source']})")
    lines.extend(["", "## Evidence log", ""])
    for event in events:
        lines.append(
            f"- `{event['created_at']}` [{event['phase']}/{event['kind']}] {event['summary']}"
            + (f" — `{event['artifact_sha256']}`" if event.get("artifact_sha256") else "")
        )
    lines.extend(["", "## Boundaries", "", "This handoff contains only recorded observations. Unverified leads are not findings, and no unobserved impact is claimed.", ""])
    return "\n".join(lines)


def write(data: dict, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render(data), encoding="utf-8")
    return destination
