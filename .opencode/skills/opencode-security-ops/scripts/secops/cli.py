"""Command-line interface for deterministic security engagement state."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .budget import budget_status, stop_at
from .evidence import load_context_manifest, load_poc_manifest
from .gates import evaluate
from .pipeline import load_pipeline, plan
from .platforms import normalize_platform, profile, validate_intake, validate_platform_rating
from .report import write as write_report
from .scope import ScopeError, check, load_scope, scope_hash
from .store import CLOSE_REASONS, HYPOTHESIS_STATUSES, Store
from .workspace import LAYOUTS, export_workspace, validate_output_root


def emit(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def require_engagement(store: Store, name: str):
    engagement = store.engagement(name)
    if not engagement:
        raise ValueError(f"engagement not found: {name}")
    return engagement


def require_active(engagement) -> None:
    if engagement["status"] != "active":
        raise ValueError("engagement is not active")
    if budget_status(engagement["stop_at"])["expired"]:
        raise ValueError("time budget expired: active testing is blocked; create a handoff")


def _engagement_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--engagement", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secops", description="Safe OpenCode security engagement controls")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--db", default=".secops/state.db", help="SQLite state path")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Initialize an engagement")
    init.add_argument("--name", required=True)
    init.add_argument("--scope", required=True)
    init.add_argument("--minutes", type=int, required=True)
    init.add_argument("--platform", default="other")
    init.add_argument("--program")
    init.add_argument("--intake", help="Optional sanitized platform/program intake JSON")
    init.add_argument("--output-dir", help="Optional user-selected draft destination")
    init.add_argument("--layout", choices=sorted(LAYOUTS), default="generic")

    platform_cmd = sub.add_parser("platform-profile", help="Show generic platform metadata")
    platform_cmd.add_argument("--platform", required=True)

    scope_cmd = sub.add_parser("scope-check")
    _engagement_argument(scope_cmd)
    scope_cmd.add_argument("--method", required=True)
    scope_cmd.add_argument("--url", required=True)

    status = sub.add_parser("status")
    _engagement_argument(status)

    log = sub.add_parser("log")
    _engagement_argument(log)
    log.add_argument("--phase", required=True)
    log.add_argument("--kind", choices=["scope-check", "observation", "tool", "test", "validation", "decision"], required=True)
    log.add_argument("--summary", required=True)
    log.add_argument("--command-line")
    log.add_argument("--exit-code", type=int)
    log.add_argument("--duration-ms", type=int)
    log.add_argument("--artifact")

    lead = sub.add_parser("lead-add")
    _engagement_argument(lead)
    lead.add_argument("--value", required=True)
    lead.add_argument("--source", required=True)

    lead_close = sub.add_parser("lead-close")
    _engagement_argument(lead_close)
    lead_close.add_argument("--id", type=int, required=True)
    lead_close.add_argument("--resolution", required=True)

    hypothesis = sub.add_parser("hypothesis-add")
    _engagement_argument(hypothesis)
    hypothesis.add_argument("--title", required=True)
    hypothesis.add_argument("--status", choices=sorted(HYPOTHESIS_STATUSES), default="untested")
    hypothesis.add_argument("--surface")
    hypothesis.add_argument("--root-cause")
    hypothesis.add_argument("--security-boundary")
    hypothesis.add_argument("--attacker-gain")

    hypothesis_update = sub.add_parser("hypothesis-update")
    _engagement_argument(hypothesis_update)
    hypothesis_update.add_argument("--id", type=int, required=True)
    hypothesis_update.add_argument("--status", choices=sorted(HYPOTHESIS_STATUSES), required=True)
    hypothesis_update.add_argument("--resolution")
    hypothesis_update.add_argument("--surface")
    hypothesis_update.add_argument("--root-cause")
    hypothesis_update.add_argument("--security-boundary")
    hypothesis_update.add_argument("--attacker-gain")

    test = sub.add_parser("test-record", help="Record a comparative test or an explicit incomplete/blocked result")
    _engagement_argument(test)
    test.add_argument("--title", required=True)
    test.add_argument("--status", choices=["complete", "incomplete", "blocked"], required=True)
    test.add_argument("--hypothesis-id", type=int)
    test.add_argument("--positive")
    test.add_argument("--negative")
    test.add_argument("--context")
    test.add_argument("--context-complete", action="store_true")
    test.add_argument("--variable-changed")
    test.add_argument("--notes")
    test.add_argument("--retest", action="store_true")

    sequence = sub.add_parser("sequence-create")
    _engagement_argument(sequence)
    sequence.add_argument("--label", required=True)

    sequence_item = sub.add_parser("sequence-add")
    _engagement_argument(sequence_item)
    sequence_item.add_argument("--sequence-id", type=int, required=True)
    sequence_item.add_argument("--position", type=int, required=True)
    sequence_item.add_argument("--summary", required=True)
    sequence_item.add_argument("--artifact", required=True)
    sequence_item.add_argument("--captured-at")

    finding = sub.add_parser("finding-add")
    _engagement_argument(finding)
    finding.add_argument("--title", required=True)
    finding.add_argument("--severity", required=True)
    finding.add_argument("--status", default="candidate")
    finding.add_argument("--evidence")
    finding.add_argument("--validation-note")
    finding.add_argument("--test-id", type=int)
    finding.add_argument("--root-cause")
    finding.add_argument("--security-boundary")
    finding.add_argument("--attacker-gain")
    finding.add_argument("--platform-rating")
    finding.add_argument("--duplicate-of")
    finding.add_argument("--poc-manifest")

    finding_update = sub.add_parser("finding-update")
    _engagement_argument(finding_update)
    finding_update.add_argument("--id", type=int, required=True)
    finding_update.add_argument("--severity", required=True)
    finding_update.add_argument("--status", required=True)
    finding_update.add_argument("--evidence")
    finding_update.add_argument("--validation-note")
    finding_update.add_argument("--test-id", type=int)
    finding_update.add_argument("--root-cause")
    finding_update.add_argument("--security-boundary")
    finding_update.add_argument("--attacker-gain")
    finding_update.add_argument("--platform-rating")
    finding_update.add_argument("--duplicate-of")
    finding_update.add_argument("--poc-manifest")

    root_cause = sub.add_parser("root-cause-check")
    _engagement_argument(root_cause)
    root_cause.add_argument("--root-cause", required=True)

    poc = sub.add_parser("poc-check")
    poc.add_argument("--manifest", required=True)

    lesson = sub.add_parser("lesson-add")
    _engagement_argument(lesson)
    lesson.add_argument("--category", required=True)
    lesson.add_argument("--summary", required=True)
    lesson.add_argument("--engagement-specific", action="store_true")

    gate = sub.add_parser("gate")
    _engagement_argument(gate)
    gate.add_argument("--phase", required=True)

    stop = sub.add_parser("stop")
    _engagement_argument(stop)
    stop.add_argument("--reason", required=True)

    close = sub.add_parser("close")
    _engagement_argument(close)
    close.add_argument("--reason-code", choices=sorted(CLOSE_REASONS), required=True)
    close.add_argument("--detail", required=True)

    output = sub.add_parser("output-set")
    _engagement_argument(output)
    output.add_argument("--directory", required=True)
    output.add_argument("--layout", choices=sorted(LAYOUTS), default="generic")

    export = sub.add_parser("draft-export")
    _engagement_argument(export)

    handoff = sub.add_parser("handoff")
    _engagement_argument(handoff)
    handoff.add_argument("--output", required=True)

    pipeline = sub.add_parser("pipeline-plan")
    pipeline.add_argument("--file", required=True)
    return parser


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "pipeline-plan":
            emit(plan(load_pipeline(args.file)))
            return
        if args.command == "platform-profile":
            emit(profile(args.platform))
            return
        if args.command == "poc-check":
            data = load_poc_manifest(args.manifest)
            emit({"passed": True, "manifest": str(Path(args.manifest).resolve()), "kind": data["kind"]})
            return
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from None

    store = Store(args.db)
    exit_code = 0
    try:
        if args.command == "init":
            scope_path = Path(args.scope).resolve()
            scope = load_scope(scope_path)
            intake = None
            if args.intake:
                intake = validate_intake(json.loads(Path(args.intake).read_text(encoding="utf-8")))
            platform = normalize_platform(intake["platform"] if intake else args.platform)
            program = intake["program"] if intake else args.program
            output_dir = str(validate_output_root(args.output_dir)) if args.output_dir else None
            eid = store.init_engagement(
                args.name, scope["mode"], str(scope_path), scope_hash(scope), stop_at(args.minutes),
                platform=platform, program=program, output_dir=output_dir,
                output_layout=args.layout if output_dir else None, intake=intake,
            )
            emit({"engagement_id": eid, "name": args.name, "status": "active", "platform": platform,
                  "program": program, "output_dir": output_dir})
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
                if args.kind in {"tool", "test"}:
                    require_active(engagement)
                event_id = store.log_event(eid, args.phase, args.kind, args.summary, command=args.command_line,
                                           exit_code=args.exit_code, duration_ms=args.duration_ms, artifact=args.artifact)
                emit({"event_id": event_id})
            elif args.command == "lead-add":
                emit({"lead_id": store.add_lead(eid, args.value, args.source)})
            elif args.command == "lead-close":
                store.close_lead(eid, args.id, args.resolution)
                emit({"closed": args.id, "resolution": args.resolution})
            elif args.command == "hypothesis-add":
                hid = store.add_hypothesis(
                    eid, args.title, status=args.status, surface=args.surface, root_cause=args.root_cause,
                    security_boundary=args.security_boundary, attacker_gain=args.attacker_gain,
                )
                emit({"hypothesis_id": hid, "status": args.status})
            elif args.command == "hypothesis-update":
                store.update_hypothesis(
                    eid, args.id, args.status, args.resolution, surface=args.surface,
                    root_cause=args.root_cause, security_boundary=args.security_boundary,
                    attacker_gain=args.attacker_gain,
                )
                emit({"hypothesis_id": args.id, "status": args.status})
            elif args.command == "test-record":
                require_active(engagement)
                if args.context_complete:
                    if not args.context:
                        raise ValueError("--context-complete requires --context")
                    load_context_manifest(args.context)
                tid = store.add_test(
                    eid, args.title, args.status, hypothesis_id=args.hypothesis_id,
                    positive=args.positive, negative=args.negative, context=args.context,
                    context_complete=args.context_complete, variable_changed=args.variable_changed,
                    notes=args.notes,
                )
                store.log_event(
                    eid, "testing", "test", f"{'Retest' if args.retest else 'Test'} #{tid}: {args.title} [{args.status}]",
                    artifact=args.positive or args.context,
                )
                emit({"test_id": tid, "status": args.status, "retest": args.retest})
            elif args.command == "sequence-create":
                emit({"sequence_id": store.create_sequence(eid, args.label), "label": args.label})
            elif args.command == "sequence-add":
                item_id = store.add_sequence_item(
                    eid, args.sequence_id, args.position, args.summary, args.artifact, args.captured_at,
                )
                emit({"sequence_item_id": item_id, "position": args.position})
            elif args.command == "finding-add":
                validate_platform_rating(engagement["platform"], args.platform_rating)
                if args.poc_manifest:
                    load_poc_manifest(args.poc_manifest)
                duplicates = store.possible_duplicates(eid, args.root_cause or "")
                fid = store.add_finding(
                    eid, args.title, args.severity, args.status, args.evidence, args.validation_note,
                    test_id=args.test_id, root_cause=args.root_cause,
                    security_boundary=args.security_boundary, attacker_gain=args.attacker_gain,
                    platform_rating=args.platform_rating, duplicate_of=args.duplicate_of,
                    poc_manifest=args.poc_manifest,
                )
                emit({"finding_id": fid, "possible_same_root_cause": duplicates})
            elif args.command == "finding-update":
                validate_platform_rating(engagement["platform"], args.platform_rating)
                if args.poc_manifest:
                    load_poc_manifest(args.poc_manifest)
                store.update_finding(
                    eid, args.id, severity=args.severity, status=args.status, evidence=args.evidence,
                    validation_note=args.validation_note, test_id=args.test_id, root_cause=args.root_cause,
                    security_boundary=args.security_boundary, attacker_gain=args.attacker_gain,
                    platform_rating=args.platform_rating, duplicate_of=args.duplicate_of,
                    poc_manifest=args.poc_manifest,
                )
                emit({"finding_id": args.id, "status": args.status})
            elif args.command == "root-cause-check":
                duplicates = store.possible_duplicates(eid, args.root_cause)
                emit({"root_cause": args.root_cause, "matches": duplicates, "pivot_recommended": bool(duplicates)})
            elif args.command == "lesson-add":
                lesson_id = store.add_lesson(eid, args.category, args.summary, not args.engagement_specific)
                emit({"lesson_id": lesson_id, "reusable": not args.engagement_specific})
            elif args.command == "gate":
                result = evaluate(store, engagement, args.phase)
                exit_code = 0 if result["passed"] else 2
                emit(result)
            elif args.command == "stop":
                store.conn.execute("UPDATE engagements SET status='stopped', stop_reason=? WHERE id=?", (args.reason, eid))
                store.conn.commit()
                emit({"status": "stopped", "reason": args.reason, "directive": "CREATE_HANDOFF"})
            elif args.command == "close":
                store.close_engagement(eid, args.reason_code, args.detail)
                emit({"status": "closed", "reason_code": args.reason_code, "detail": args.detail})
            elif args.command == "output-set":
                output_dir = str(validate_output_root(args.directory))
                store.set_output(eid, output_dir, args.layout)
                emit({"output_dir": output_dir, "layout": args.layout, "written": False})
            elif args.command == "draft-export":
                if not engagement["output_dir"] or not engagement["output_layout"]:
                    raise ValueError("no output destination configured; use output-set first")
                emit(export_workspace(store.export(eid), engagement["output_dir"], engagement["output_layout"]))
            elif args.command == "handoff":
                output = write_report(store.export(eid), args.output)
                emit({"handoff": str(output.resolve())})
    except (ValueError, ScopeError, OSError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        exit_code = 1
    finally:
        store.close()
    raise SystemExit(exit_code)
