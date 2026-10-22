"""Evidence-oriented phase gates that do not force unnecessary testing."""

from __future__ import annotations

from pathlib import Path

from .budget import budget_status
from .scope import load_scope, scope_hash


PHASES = {"planning", "recon", "testing", "validation", "reporting"}


def evaluate(store, engagement, phase: str) -> dict:
    if phase not in PHASES:
        raise ValueError(f"unknown phase: {phase}")
    failures: list[str] = []
    budget = budget_status(engagement["stop_at"])
    if engagement["status"] != "active" and phase != "reporting":
        failures.append("engagement is not active")
    if budget["expired"] and phase not in {"validation", "reporting"}:
        failures.append("time budget expired: stop active work and create a handoff")

    eid = engagement["id"]
    scope_path = Path(engagement["scope_path"])
    if not scope_path.is_file():
        failures.append("scope document is missing")
    else:
        try:
            if scope_hash(load_scope(scope_path)) != engagement["scope_sha256"]:
                failures.append("scope document changed after engagement initialization")
        except (ValueError, OSError):
            failures.append("scope document is no longer valid")
    scope_checks = store.conn.execute(
        "SELECT COUNT(*) FROM events WHERE engagement_id=? AND kind='scope-check'", (eid,)
    ).fetchone()[0]
    if phase in {"recon", "testing", "validation", "reporting"} and scope_checks == 0:
        failures.append("no successful scope-check event recorded")

    if phase in {"testing", "validation", "reporting"}:
        tested = store.conn.execute(
            "SELECT COUNT(*) FROM events WHERE engagement_id=? AND kind='test' AND artifact_sha256 IS NOT NULL",
            (eid,),
        ).fetchone()[0]
        if tested == 0:
            failures.append("no bounded test with hashed evidence recorded")

    if phase in {"validation", "reporting"}:
        invalid = store.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE engagement_id=? AND status='confirmed' AND (evidence_sha256 IS NULL OR validation_note IS NULL)",
            (eid,),
        ).fetchone()[0]
        if invalid:
            failures.append(f"{invalid} confirmed finding(s) lack evidence or validation notes")

    if phase == "reporting":
        open_leads = store.conn.execute(
            "SELECT COUNT(*) FROM leads WHERE engagement_id=? AND status='open'", (eid,)
        ).fetchone()[0]
        if open_leads:
            failures.append(f"{open_leads} lead(s) remain open; close with an explicit reason or report as pending")

    return {"passed": not failures, "phase": phase, "failures": failures, "budget": budget}
