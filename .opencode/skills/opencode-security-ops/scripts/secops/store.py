"""SQLite state and tamper-evident evidence records."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


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
  stop_reason TEXT
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
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'candidate',
  evidence_path TEXT,
  evidence_sha256 TEXT,
  validation_note TEXT,
  UNIQUE(engagement_id, title)
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def init_engagement(self, name: str, mode: str, scope_path: str, scope_sha: str, stop_at: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO engagements(name,mode,scope_path,scope_sha256,started_at,stop_at) VALUES(?,?,?,?,?,?)",
            (name, mode, scope_path, scope_sha, utcnow(), stop_at),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def engagement(self, name: str):
        return self.conn.execute("SELECT * FROM engagements WHERE name=?", (name,)).fetchone()

    def log_event(self, engagement_id: int, phase: str, kind: str, summary: str, *, command=None,
                  exit_code=None, duration_ms=None, artifact=None) -> int:
        artifact_path = str(Path(artifact).resolve()) if artifact else None
        artifact_hash = file_sha256(artifact_path) if artifact_path else None
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
        if resolution not in {"tested-clean", "confirmed-finding", "false-positive", "out-of-scope", "duplicate"}:
            raise ValueError("invalid lead resolution")
        cur = self.conn.execute(
            "UPDATE leads SET status='closed', resolution=? WHERE id=? AND engagement_id=?",
            (resolution, lead_id, engagement_id),
        )
        if cur.rowcount != 1:
            raise ValueError("lead not found")
        self.conn.commit()

    def add_finding(self, engagement_id: int, title: str, severity: str, status: str = "candidate",
                    evidence=None, validation_note=None) -> int:
        if severity not in {"critical", "high", "medium", "low", "informational"}:
            raise ValueError("invalid severity")
        if status not in {"candidate", "confirmed", "rejected"}:
            raise ValueError("invalid finding status")
        if status == "confirmed" and (not evidence or not validation_note or not validation_note.strip()):
            raise ValueError("confirmed findings require evidence and a validation note")
        evidence_path = str(Path(evidence).resolve()) if evidence else None
        evidence_hash = file_sha256(evidence_path) if evidence_path else None
        cur = self.conn.execute(
            "INSERT INTO findings(engagement_id,title,severity,status,evidence_path,evidence_sha256,validation_note) VALUES(?,?,?,?,?,?,?)",
            (engagement_id, title, severity, status, evidence_path, evidence_hash, validation_note),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def summary(self, engagement_id: int) -> dict:
        def count(sql: str) -> int:
            return int(self.conn.execute(sql, (engagement_id,)).fetchone()[0])
        return {
            "events": count("SELECT COUNT(*) FROM events WHERE engagement_id=?"),
            "open_leads": count("SELECT COUNT(*) FROM leads WHERE engagement_id=? AND status='open'"),
            "findings": count("SELECT COUNT(*) FROM findings WHERE engagement_id=?"),
            "confirmed_findings": count("SELECT COUNT(*) FROM findings WHERE engagement_id=? AND status='confirmed'"),
        }

    def export(self, engagement_id: int) -> dict:
        engagement = dict(self.conn.execute("SELECT * FROM engagements WHERE id=?", (engagement_id,)).fetchone())
        data = {"engagement": engagement}
        for table in ("events", "leads", "findings"):
            data[table] = [dict(row) for row in self.conn.execute(f"SELECT * FROM {table} WHERE engagement_id=? ORDER BY id", (engagement_id,))]
        return data
