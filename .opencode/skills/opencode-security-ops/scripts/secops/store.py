"""SQLite state and tamper-evident evidence records."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


HYPOTHESIS_STATUSES = {
    "untested", "in-progress", "incomplete", "blocked", "negative",
    "candidate", "confirmed", "rejected",
}
TEST_STATUSES = {"complete", "incomplete", "blocked"}
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
CLOSE_REASONS = {
    "surface-exhausted", "credentials-unavailable", "payment-gate",
    "platform-blocked", "submission-capacity", "testing-incomplete",
    "out-of-scope-dependency", "operator-request", "authorization-withdrawn",
    "time-expired", "other",
}


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS engagements (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  mode TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  scope_path TEXT NOT NULL,
  scope_sha256 TEXT NOT NULL,
  started_at TEXT NOT NULL,
  stop_at TEXT NOT NULL,
  stop_reason TEXT,
  platform TEXT NOT NULL DEFAULT 'other',
  program TEXT,
  output_dir TEXT,
  output_layout TEXT,
  close_reason_code TEXT,
  intake_json TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  created_at TEXT NOT NULL,
  phase TEXT NOT NULL,
  kind TEXT NOT NULL,
  command TEXT,
  exit_code INTEGER,
  duration_ms INTEGER,
  artifact TEXT,
  artifact_sha256 TEXT,
  summary TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leads (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  value TEXT NOT NULL,
  source TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  resolution TEXT,
  UNIQUE(engagement_id, value)
);
CREATE TABLE IF NOT EXISTS hypotheses (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'untested',
  surface TEXT,
  root_cause TEXT,
  security_boundary TEXT,
  attacker_gain TEXT,
  resolution TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(engagement_id, title)
);
CREATE TABLE IF NOT EXISTS tests (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  hypothesis_id INTEGER REFERENCES hypotheses(id),
  created_at TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  positive_artifact TEXT,
  positive_sha256 TEXT,
  negative_artifact TEXT,
  negative_sha256 TEXT,
  context_artifact TEXT,
  context_sha256 TEXT,
  context_complete INTEGER NOT NULL DEFAULT 0,
  variable_changed TEXT,
  notes TEXT
);
CREATE TABLE IF NOT EXISTS evidence_sequences (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  label TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(engagement_id, label)
);
CREATE TABLE IF NOT EXISTS evidence_sequence_items (
  id INTEGER PRIMARY KEY,
  sequence_id INTEGER NOT NULL REFERENCES evidence_sequences(id),
  position INTEGER NOT NULL,
  captured_at TEXT NOT NULL,
  summary TEXT NOT NULL,
  artifact TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL,
  UNIQUE(sequence_id, position)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'candidate',
  evidence_path TEXT,
  evidence_sha256 TEXT,
  validation_note TEXT,
  test_id INTEGER REFERENCES tests(id),
  root_cause TEXT,
  security_boundary TEXT,
  attacker_gain TEXT,
  platform_rating TEXT,
  duplicate_of TEXT,
  poc_manifest_path TEXT,
  poc_manifest_sha256 TEXT,
  UNIQUE(engagement_id, title)
);
CREATE TABLE IF NOT EXISTS lessons (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  created_at TEXT NOT NULL,
  category TEXT NOT NULL,
  summary TEXT NOT NULL,
  reusable INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_events_engagement ON events(engagement_id, id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_engagement_status ON hypotheses(engagement_id, status);
CREATE INDEX IF NOT EXISTS idx_tests_engagement_status ON tests(engagement_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_engagement_status ON findings(engagement_id, status);
"""


MIGRATION_COLUMNS = {
    "engagements": {
        "platform": "TEXT NOT NULL DEFAULT 'other'",
        "program": "TEXT",
        "output_dir": "TEXT",
        "output_layout": "TEXT",
        "close_reason_code": "TEXT",
        "intake_json": "TEXT",
    },
    "findings": {
        "test_id": "INTEGER",
        "root_cause": "TEXT",
        "security_boundary": "TEXT",
        "attacker_gain": "TEXT",
        "platform_rating": "TEXT",
        "duplicate_of": "TEXT",
        "poc_manifest_path": "TEXT",
        "poc_manifest_sha256": "TEXT",
    },
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact(path: str | Path | None) -> tuple[str | None, str | None]:
    if not path:
        return None, None
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"artifact is not a regular file: {resolved}")
    return str(resolved), file_sha256(resolved)


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()
        self.conn = sqlite3.connect(self.path)
        if not existed:
            os.chmod(self.path, 0o600)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Add v0.2 columns to v0.1 databases without discarding state."""
        for table, columns in MIGRATION_COLUMNS.items():
            present = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})")}
            for name, declaration in columns.items():
                if name not in present:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def init_engagement(self, name: str, mode: str, scope_path: str, scope_sha: str, stop_at: str,
                        *, platform: str = "other", program: str | None = None,
                        output_dir: str | None = None, output_layout: str | None = None,
                        intake: dict | None = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO engagements(
               name,mode,scope_path,scope_sha256,started_at,stop_at,platform,program,
               output_dir,output_layout,intake_json
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (name, mode, scope_path, scope_sha, utcnow(), stop_at, platform, program,
             output_dir, output_layout, json.dumps(intake, sort_keys=True) if intake else None),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def engagement(self, name: str):
        return self.conn.execute("SELECT * FROM engagements WHERE name=?", (name,)).fetchone()

    def set_output(self, engagement_id: int, output_dir: str, layout: str) -> None:
        self.conn.execute(
            "UPDATE engagements SET output_dir=?, output_layout=? WHERE id=?",
            (output_dir, layout, engagement_id),
        )
        self.conn.commit()

    def close_engagement(self, engagement_id: int, reason_code: str, detail: str) -> None:
        if reason_code not in CLOSE_REASONS:
            raise ValueError(f"invalid close reason: {reason_code}")
        if not detail.strip():
            raise ValueError("close detail is required")
        self.conn.execute(
            "UPDATE engagements SET status='closed', close_reason_code=?, stop_reason=? WHERE id=?",
            (reason_code, detail, engagement_id),
        )
        self.conn.commit()

    def log_event(self, engagement_id: int, phase: str, kind: str, summary: str, *, command=None,
                  exit_code=None, duration_ms=None, artifact=None) -> int:
        artifact_path, artifact_hash = _artifact(artifact)
        cur = self.conn.execute(
            "INSERT INTO events(engagement_id,created_at,phase,kind,command,exit_code,duration_ms,artifact,artifact_sha256,summary) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (engagement_id, utcnow(), phase, kind, command, exit_code, duration_ms, artifact_path, artifact_hash, summary),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def add_lead(self, engagement_id: int, value: str, source: str) -> int:
        cur = self.conn.execute("INSERT INTO leads(engagement_id,value,source) VALUES(?,?,?)", (engagement_id, value, source))
        self.conn.commit()
        return int(cur.lastrowid)

    def close_lead(self, engagement_id: int, lead_id: int, resolution: str) -> None:
        if resolution not in {"tested-clean", "confirmed-finding", "false-positive", "out-of-scope", "duplicate", "incomplete", "blocked"}:
            raise ValueError("invalid lead resolution")
        cur = self.conn.execute(
            "UPDATE leads SET status='closed', resolution=? WHERE id=? AND engagement_id=?",
            (resolution, lead_id, engagement_id),
        )
        if cur.rowcount != 1:
            raise ValueError("lead not found")
        self.conn.commit()

    def add_hypothesis(self, engagement_id: int, title: str, *, status: str = "untested",
                       surface: str | None = None, root_cause: str | None = None,
                       security_boundary: str | None = None, attacker_gain: str | None = None) -> int:
        if status not in HYPOTHESIS_STATUSES:
            raise ValueError("invalid hypothesis status")
        now = utcnow()
        cur = self.conn.execute(
            """INSERT INTO hypotheses(
               engagement_id,title,status,surface,root_cause,security_boundary,attacker_gain,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (engagement_id, title, status, surface, root_cause, security_boundary, attacker_gain, now, now),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def update_hypothesis(self, engagement_id: int, hypothesis_id: int, status: str, resolution: str | None,
                          *, surface: str | None = None, root_cause: str | None = None,
                          security_boundary: str | None = None, attacker_gain: str | None = None) -> None:
        if status not in HYPOTHESIS_STATUSES:
            raise ValueError("invalid hypothesis status")
        if status in {"incomplete", "blocked", "negative", "confirmed", "rejected"} and not (resolution or "").strip():
            raise ValueError(f"hypothesis status {status} requires a resolution note")
        cur = self.conn.execute(
            """UPDATE hypotheses SET status=?, resolution=?, updated_at=?,
               surface=COALESCE(?,surface), root_cause=COALESCE(?,root_cause),
               security_boundary=COALESCE(?,security_boundary), attacker_gain=COALESCE(?,attacker_gain)
               WHERE id=? AND engagement_id=?""",
            (status, resolution, utcnow(), surface, root_cause, security_boundary, attacker_gain,
             hypothesis_id, engagement_id),
        )
        if cur.rowcount != 1:
            raise ValueError("hypothesis not found")
        self.conn.commit()

    def add_test(self, engagement_id: int, title: str, status: str, *, hypothesis_id: int | None = None,
                 positive=None, negative=None, context=None, context_complete: bool = False,
                 variable_changed: str | None = None, notes: str | None = None) -> int:
        if status not in TEST_STATUSES:
            raise ValueError("invalid test status")
        if hypothesis_id is not None:
            row = self.conn.execute(
                "SELECT id FROM hypotheses WHERE id=? AND engagement_id=?", (hypothesis_id, engagement_id)
            ).fetchone()
            if not row:
                raise ValueError("hypothesis not found")
        positive_path, positive_hash = _artifact(positive)
        negative_path, negative_hash = _artifact(negative)
        context_path, context_hash = _artifact(context)
        if status == "complete":
            missing = []
            if not positive_path:
                missing.append("positive control artifact")
            if not negative_path:
                missing.append("negative control artifact")
            if not context_path or not context_complete:
                missing.append("complete request-context artifact")
            if not (variable_changed or "").strip():
                missing.append("single changed variable")
            if missing:
                raise ValueError("complete tests require: " + ", ".join(missing))
            # Keep the invariant even when Store is used directly rather than through the CLI.
            from .evidence import load_context_manifest
            load_context_manifest(context_path)
        cur = self.conn.execute(
            """INSERT INTO tests(
               engagement_id,hypothesis_id,created_at,title,status,positive_artifact,positive_sha256,
               negative_artifact,negative_sha256,context_artifact,context_sha256,context_complete,
               variable_changed,notes
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (engagement_id, hypothesis_id, utcnow(), title, status, positive_path, positive_hash,
             negative_path, negative_hash, context_path, context_hash, int(context_complete),
             variable_changed, notes),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def create_sequence(self, engagement_id: int, label: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO evidence_sequences(engagement_id,label,created_at) VALUES(?,?,?)",
            (engagement_id, label, utcnow()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def add_sequence_item(self, engagement_id: int, sequence_id: int, position: int,
                          summary: str, artifact, captured_at: str | None = None) -> int:
        if position < 1:
            raise ValueError("sequence position must be positive")
        sequence = self.conn.execute(
            "SELECT id FROM evidence_sequences WHERE id=? AND engagement_id=?", (sequence_id, engagement_id)
        ).fetchone()
        if not sequence:
            raise ValueError("evidence sequence not found")
        artifact_path, artifact_hash = _artifact(artifact)
        captured = captured_at or utcnow()
        parsed = datetime.fromisoformat(captured)
        if parsed.tzinfo is None:
            raise ValueError("sequence captured_at must include a timezone")
        previous = self.conn.execute(
            "SELECT captured_at FROM evidence_sequence_items WHERE sequence_id=? AND position<? ORDER BY position DESC LIMIT 1",
            (sequence_id, position),
        ).fetchone()
        following = self.conn.execute(
            "SELECT captured_at FROM evidence_sequence_items WHERE sequence_id=? AND position>? ORDER BY position ASC LIMIT 1",
            (sequence_id, position),
        ).fetchone()
        if previous and parsed < datetime.fromisoformat(previous["captured_at"]):
            raise ValueError("sequence timestamp precedes the previous position")
        if following and parsed > datetime.fromisoformat(following["captured_at"]):
            raise ValueError("sequence timestamp follows the next position")
        cur = self.conn.execute(
            """INSERT INTO evidence_sequence_items(
               sequence_id,position,captured_at,summary,artifact,artifact_sha256
               ) VALUES(?,?,?,?,?,?)""",
            (sequence_id, position, captured, summary, artifact_path, artifact_hash),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def add_lesson(self, engagement_id: int, category: str, summary: str, reusable: bool = True) -> int:
        cur = self.conn.execute(
            "INSERT INTO lessons(engagement_id,created_at,category,summary,reusable) VALUES(?,?,?,?,?)",
            (engagement_id, utcnow(), category, summary, int(reusable)),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def possible_duplicates(self, engagement_id: int, root_cause: str) -> list[dict]:
        if not root_cause.strip():
            return []
        rows = self.conn.execute(
            "SELECT id,title,status,root_cause FROM findings WHERE engagement_id=? AND lower(trim(root_cause))=lower(trim(?))",
            (engagement_id, root_cause.strip()),
        )
        return [dict(row) for row in rows]

    def add_finding(self, engagement_id: int, title: str, severity: str, status: str = "candidate",
                    evidence=None, validation_note=None, *, test_id: int | None = None,
                    root_cause: str | None = None, security_boundary: str | None = None,
                    attacker_gain: str | None = None, platform_rating: str | None = None,
                    duplicate_of: str | None = None, poc_manifest=None) -> int:
        if severity not in SEVERITIES:
            raise ValueError("invalid severity")
        if status not in {"candidate", "confirmed", "rejected", "duplicate"}:
            raise ValueError("invalid finding status")
        evidence_path, evidence_hash = _artifact(evidence)
        poc_path, poc_hash = _artifact(poc_manifest)
        if poc_path:
            from .evidence import load_poc_manifest
            load_poc_manifest(poc_path)
        linked_test = None
        if test_id is not None:
            linked_test = self.conn.execute(
                "SELECT * FROM tests WHERE id=? AND engagement_id=?", (test_id, engagement_id)
            ).fetchone()
            if not linked_test:
                raise ValueError("finding test does not belong to this engagement")
        if status == "confirmed":
            required = {
                "evidence": evidence_path,
                "validation note": (validation_note or "").strip(),
                "root cause": (root_cause or "").strip(),
                "security boundary": (security_boundary or "").strip(),
                "attacker gain": (attacker_gain or "").strip(),
                "complete comparative test": test_id,
            }
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ValueError("confirmed findings require: " + ", ".join(missing))
            test = linked_test
            if not test or test["status"] != "complete" or not test["positive_sha256"] or not test["negative_sha256"] or not test["context_complete"]:
                raise ValueError("confirmed finding test must be complete with positive/negative controls and full context")
        if status == "duplicate" and not (duplicate_of or "").strip():
            raise ValueError("duplicate findings require duplicate_of")
        cur = self.conn.execute(
            """INSERT INTO findings(
               engagement_id,title,severity,status,evidence_path,evidence_sha256,validation_note,
               test_id,root_cause,security_boundary,attacker_gain,platform_rating,duplicate_of,
               poc_manifest_path,poc_manifest_sha256
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (engagement_id, title, severity, status, evidence_path, evidence_hash, validation_note,
             test_id, root_cause, security_boundary, attacker_gain, platform_rating, duplicate_of,
             poc_path, poc_hash),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def update_finding(self, engagement_id: int, finding_id: int, *, severity: str, status: str,
                       evidence=None, validation_note=None, test_id: int | None = None,
                       root_cause: str | None = None, security_boundary: str | None = None,
                       attacker_gain: str | None = None, platform_rating: str | None = None,
                       duplicate_of: str | None = None, poc_manifest=None) -> None:
        if severity not in SEVERITIES:
            raise ValueError("invalid severity")
        if status not in {"candidate", "confirmed", "rejected", "duplicate"}:
            raise ValueError("invalid finding status")
        current = self.conn.execute(
            "SELECT * FROM findings WHERE id=? AND engagement_id=?", (finding_id, engagement_id)
        ).fetchone()
        if not current:
            raise ValueError("finding not found")
        evidence_path, evidence_hash = _artifact(evidence) if evidence else (current["evidence_path"], current["evidence_sha256"])
        poc_path, poc_hash = _artifact(poc_manifest) if poc_manifest else (current["poc_manifest_path"], current["poc_manifest_sha256"])
        if poc_path:
            from .evidence import load_poc_manifest
            load_poc_manifest(poc_path)
        values = {
            "validation_note": validation_note if validation_note is not None else current["validation_note"],
            "test_id": test_id if test_id is not None else current["test_id"],
            "root_cause": root_cause if root_cause is not None else current["root_cause"],
            "security_boundary": security_boundary if security_boundary is not None else current["security_boundary"],
            "attacker_gain": attacker_gain if attacker_gain is not None else current["attacker_gain"],
            "platform_rating": platform_rating if platform_rating is not None else current["platform_rating"],
            "duplicate_of": duplicate_of if duplicate_of is not None else current["duplicate_of"],
        }
        linked_test = None
        if values["test_id"] is not None:
            linked_test = self.conn.execute(
                "SELECT * FROM tests WHERE id=? AND engagement_id=?", (values["test_id"], engagement_id)
            ).fetchone()
            if not linked_test:
                raise ValueError("finding test does not belong to this engagement")
        if status == "confirmed":
            required = {
                "evidence": evidence_path,
                "validation note": (values["validation_note"] or "").strip(),
                "root cause": (values["root_cause"] or "").strip(),
                "security boundary": (values["security_boundary"] or "").strip(),
                "attacker gain": (values["attacker_gain"] or "").strip(),
                "complete comparative test": values["test_id"],
            }
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ValueError("confirmed findings require: " + ", ".join(missing))
            test = linked_test
            if not test or test["status"] != "complete" or not test["positive_sha256"] or not test["negative_sha256"] or not test["context_complete"]:
                raise ValueError("confirmed finding test must be complete with positive/negative controls and full context")
        if status == "duplicate" and not (values["duplicate_of"] or "").strip():
            raise ValueError("duplicate findings require duplicate_of")
        self.conn.execute(
            """UPDATE findings SET severity=?,status=?,evidence_path=?,evidence_sha256=?,validation_note=?,
               test_id=?,root_cause=?,security_boundary=?,attacker_gain=?,platform_rating=?,duplicate_of=?,
               poc_manifest_path=?,poc_manifest_sha256=? WHERE id=? AND engagement_id=?""",
            (severity, status, evidence_path, evidence_hash, values["validation_note"], values["test_id"],
             values["root_cause"], values["security_boundary"], values["attacker_gain"],
             values["platform_rating"], values["duplicate_of"], poc_path, poc_hash,
             finding_id, engagement_id),
        )
        self.conn.commit()

    def summary(self, engagement_id: int) -> dict:
        def count(sql: str) -> int:
            return int(self.conn.execute(sql, (engagement_id,)).fetchone()[0])
        return {
            "events": count("SELECT COUNT(*) FROM events WHERE engagement_id=?"),
            "open_leads": count("SELECT COUNT(*) FROM leads WHERE engagement_id=? AND status='open'"),
            "open_hypotheses": count("SELECT COUNT(*) FROM hypotheses WHERE engagement_id=? AND status IN ('untested','in-progress','incomplete','blocked','candidate')"),
            "incomplete_tests": count("SELECT COUNT(*) FROM tests WHERE engagement_id=? AND status!='complete'"),
            "findings": count("SELECT COUNT(*) FROM findings WHERE engagement_id=?"),
            "confirmed_findings": count("SELECT COUNT(*) FROM findings WHERE engagement_id=? AND status='confirmed'"),
            "lessons": count("SELECT COUNT(*) FROM lessons WHERE engagement_id=?"),
        }

    def export(self, engagement_id: int) -> dict:
        engagement_row = self.conn.execute("SELECT * FROM engagements WHERE id=?", (engagement_id,)).fetchone()
        if not engagement_row:
            raise ValueError("engagement not found")
        data = {"engagement": dict(engagement_row)}
        for table in ("events", "leads", "hypotheses", "tests", "findings", "evidence_sequences", "lessons"):
            data[table] = [dict(row) for row in self.conn.execute(
                f"SELECT * FROM {table} WHERE engagement_id=? ORDER BY id", (engagement_id,)
            )]
        sequence_ids = [row["id"] for row in data["evidence_sequences"]]
        if sequence_ids:
            placeholders = ",".join("?" for _ in sequence_ids)
            data["evidence_sequence_items"] = [dict(row) for row in self.conn.execute(
                f"SELECT * FROM evidence_sequence_items WHERE sequence_id IN ({placeholders}) ORDER BY sequence_id,position",
                sequence_ids,
            )]
        else:
            data["evidence_sequence_items"] = []
        return data
