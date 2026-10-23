"""Generate a factual Markdown handoff from recorded state."""

from __future__ import annotations

from pathlib import Path


def render(data: dict) -> str:
    engagement = data["engagement"]
    findings = data.get("findings", [])
    leads = data.get("leads", [])
    hypotheses = data.get("hypotheses", [])
    tests = data.get("tests", [])
    events = data.get("events", [])
    lessons = data.get("lessons", [])
    sequences = data.get("evidence_sequences", [])
    sequence_items = data.get("evidence_sequence_items", [])
    lines = [
        f"# Security engagement handoff: {engagement['name']}",
        "",
        "## Status",
        "",
        f"- Platform: `{engagement.get('platform') or 'other'}`",
        f"- Program: {engagement.get('program') or 'Not specified'}",
        f"- Mode: `{engagement['mode']}`",
        f"- State: `{engagement['status']}`",
        f"- Started: `{engagement['started_at']}`",
        f"- Stop time: `{engagement['stop_at']}`",
        f"- Close reason: `{engagement.get('close_reason_code') or 'not-closed'}`",
        f"- Stop/detail: {engagement.get('stop_reason') or 'Not stopped'}",
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
            f"- Platform rating: `{finding.get('platform_rating') or 'not specified'}`",
            f"- Root cause: {finding.get('root_cause') or 'Missing'}",
            f"- Security boundary: {finding.get('security_boundary') or 'Missing'}",
            f"- Demonstrated attacker gain: {finding.get('attacker_gain') or 'Missing'}",
            f"- Comparative test: `#{finding.get('test_id') or 'Missing'}`",
            f"- Validation: {finding.get('validation_note') or 'Missing'}",
            f"- Evidence: `{finding.get('evidence_path') or 'Missing'}`",
            f"- Evidence SHA-256: `{finding.get('evidence_sha256') or 'Missing'}`",
            f"- PoC manifest SHA-256: `{finding.get('poc_manifest_sha256') or 'not supplied'}`",
            "",
        ])

    lines.extend(["## Other finding records", ""])
    other_findings = [f for f in findings if f["status"] != "confirmed"]
    if not other_findings:
        lines.append("No candidate, rejected, or duplicate findings.")
    for finding in other_findings:
        suffix = f"; duplicate of: {finding['duplicate_of']}" if finding.get("duplicate_of") else ""
        lines.append(f"- **{finding['title']}** — `{finding['status']}` / `{finding['severity']}`{suffix}")

    lines.extend(["", "## Hypotheses and limitations", ""])
    if not hypotheses:
        lines.append("No hypotheses recorded.")
    for hypothesis in hypotheses:
        resolution = hypothesis.get("resolution") or "No resolution note"
        lines.append(f"- `#{hypothesis['id']}` **{hypothesis['title']}** — `{hypothesis['status']}`: {resolution}")

    lines.extend(["", "## Comparative tests", ""])
    if not tests:
        lines.append("No tests recorded.")
    for test in tests:
        controls = "positive+negative hashed" if test.get("positive_sha256") and test.get("negative_sha256") else "controls incomplete"
        context = "complete context" if test.get("context_complete") else "context incomplete"
        lines.append(f"- `#{test['id']}` **{test['title']}** — `{test['status']}`; {controls}; {context}; changed: {test.get('variable_changed') or 'not recorded'}")

    lines.extend(["", "## Open leads", ""])
    open_leads = [lead for lead in leads if lead["status"] == "open"]
    if not open_leads:
        lines.append("No open leads.")
    for lead in open_leads:
        lines.append(f"- `{lead['value']}` (source: {lead['source']})")

    lines.extend(["", "## Continuous evidence sequences", ""])
    if not sequences:
        lines.append("No continuous evidence sequences recorded.")
    for sequence in sequences:
        lines.append(f"### {sequence['label']}")
        for item in [entry for entry in sequence_items if entry["sequence_id"] == sequence["id"]]:
            lines.append(f"- `{item['captured_at']}` step {item['position']}: {item['summary']} — `{item['artifact_sha256']}`")

    lines.extend(["", "## Evidence log", ""])
    if not events:
        lines.append("No events recorded.")
    for event in events:
        lines.append(
            f"- `{event['created_at']}` [{event['phase']}/{event['kind']}] {event['summary']}"
            + (f" — `{event['artifact_sha256']}`" if event.get("artifact_sha256") else "")
        )

    lines.extend(["", "## Reusable lessons", ""])
    reusable = [lesson for lesson in lessons if lesson.get("reusable")]
    if not reusable:
        lines.append("No reusable lessons recorded.")
    for lesson in reusable:
        lines.append(f"- **{lesson['category']}**: {lesson['summary']}")

    lines.extend([
        "", "## Boundaries", "",
        "This handoff contains only recorded observations. Unverified leads are not findings, incomplete or blocked tests are not negative results, and no unobserved impact is claimed.",
        "",
    ])
    return "\n".join(lines)


def write(data: dict, path: str | Path) -> Path:
    destination = Path(path)
    if destination.exists() and destination.is_symlink():
        raise ValueError("refusing symlinked handoff destination")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render(data), encoding="utf-8")
    return destination
