"""Command-line interface for deterministic security engagement state."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from .budget import budget_status, stop_at
from .gates import evaluate
from .pipeline import load_pipeline, plan
from .report import write as write_report
from .scope import ScopeError, check, load_scope, scope_hash
from .store import Store
from . import __version__


def emit(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def require_engagement(store: Store, name: str):
    engagement = store.engagement(name)
    if not engagement:
        raise ValueError(f"engagement not found: {name}")
    return engagement


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secops", description="Safe OpenCode security engagement controls")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--db", default=".secops/state.db", help="SQLite state path")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("--name", required=True)
    init.add_argument("--scope", required=True)
    init.add_argument("--minutes", type=int, required=True)

    scope_cmd = sub.add_parser("scope-check")
    scope_cmd.add_argument("--engagement", required=True)
    scope_cmd.add_argument("--method", required=True)
    scope_cmd.add_argument("--url", required=True)

    status = sub.add_parser("status")
    status.add_argument("--engagement", required=True)

    log = sub.add_parser("log")
    log.add_argument("--engagement", required=True)
    log.add_argument("--phase", required=True)
    log.add_argument("--kind", choices=["scope-check", "observation", "tool", "test", "validation", "decision"], required=True)
    log.add_argument("--summary", required=True)
    log.add_argument("--command-line")
    log.add_argument("--exit-code", type=int)
    log.add_argument("--duration-ms", type=int)
    log.add_argument("--artifact")

    lead = sub.add_parser("lead-add")
    lead.add_argument("--engagement", required=True)
    lead.add_argument("--value", required=True)
    lead.add_argument("--source", required=True)

    close = sub.add_parser("lead-close")
    close.add_argument("--engagement", required=True)
    close.add_argument("--id", type=int, required=True)
    close.add_argument("--resolution", required=True)

    finding = sub.add_parser("finding-add")
    finding.add_argument("--engagement", required=True)
    finding.add_argument("--title", required=True)
    finding.add_argument("--severity", required=True)
    finding.add_argument("--status", default="candidate")
    finding.add_argument("--evidence")
    finding.add_argument("--validation-note")

    gate = sub.add_parser("gate")
    gate.add_argument("--engagement", required=True)
    gate.add_argument("--phase", required=True)

    stop = sub.add_parser("stop")
    stop.add_argument("--engagement", required=True)
    stop.add_argument("--reason", required=True)

    handoff = sub.add_parser("handoff")
    handoff.add_argument("--engagement", required=True)
    handoff.add_argument("--output", required=True)

    pipeline = sub.add_parser("pipeline-plan")
    pipeline.add_argument("--file", required=True)
    return parser


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "pipeline-plan":
        emit(plan(load_pipeline(args.file)))
        return

    store = Store(args.db)
    exit_code = 0
    try:
        if args.command == "init":
            scope_path = Path(args.scope).resolve()
            scope = load_scope(scope_path)
            eid = store.init_engagement(args.name, scope["mode"], str(scope_path), scope_hash(scope), stop_at(args.minutes))
            emit({"engagement_id": eid, "name": args.name, "status": "active"})
        else:
            engagement = require_engagement(store, args.engagement)
            eid = engagement["id"]
            if args.command == "scope-check":
                scope = load_scope(engagement["scope_path"])
                if scope_hash(scope) != engagement["scope_sha256"]:
                    result = {"allowed": False, "reason": "SCOPE_DOCUMENT_CHANGED"}
                elif engagement["status"] != "active":
                    result = {"allowed": False, "reason": "ENGAGEMENT_NOT_ACTIVE"}
                elif budget_status(engagement["stop_at"])["expired"]:
                    result = {"allowed": False, "reason": "TIME_BUDGET_EXPIRED", "directive": "STOP_ACTIVE_WORK_AND_HANDOFF"}
                else:
                    result = check(scope, args.method, args.url)
                if result["allowed"]:
                    store.log_event(eid, "planning", "scope-check", f"Allowed {args.method.upper()} {args.url}")
                else:
                    exit_code = 2
                emit(result)
            elif args.command == "status":
                emit({"engagement": dict(engagement), "budget": budget_status(engagement["stop_at"]), "summary": store.summary(eid)})
            elif args.command == "log":
                if budget_status(engagement["stop_at"])["expired"] and args.kind in {"tool", "test"}:
                    raise ValueError("time budget expired: active tool/test logging is blocked; create a handoff")
                event_id = store.log_event(eid, args.phase, args.kind, args.summary, command=args.command_line,
                                           exit_code=args.exit_code, duration_ms=args.duration_ms, artifact=args.artifact)
                emit({"event_id": event_id})
            elif args.command == "lead-add":
                emit({"lead_id": store.add_lead(eid, args.value, args.source)})
            elif args.command == "lead-close":
                store.close_lead(eid, args.id, args.resolution)
                emit({"closed": args.id, "resolution": args.resolution})
            elif args.command == "finding-add":
                fid = store.add_finding(eid, args.title, args.severity, args.status, args.evidence, args.validation_note)
                emit({"finding_id": fid})
            elif args.command == "gate":
                result = evaluate(store, engagement, args.phase)
                exit_code = 0 if result["passed"] else 2
                emit(result)
            elif args.command == "stop":
                store.conn.execute("UPDATE engagements SET status='stopped', stop_reason=? WHERE id=?", (args.reason, eid))
                store.conn.commit()
                emit({"status": "stopped", "reason": args.reason, "directive": "CREATE_HANDOFF"})
            elif args.command == "handoff":
                output = write_report(store.export(eid), args.output)
                emit({"handoff": str(output.resolve())})
    except (ValueError, ScopeError, OSError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        exit_code = 1
    finally:
        store.close()
    raise SystemExit(exit_code)
