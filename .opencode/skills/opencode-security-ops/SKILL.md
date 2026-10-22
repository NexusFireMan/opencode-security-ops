---
name: opencode-security-ops
description: Safely orchestrate authorized web, API, external-cloud security engagements and defensive source-code audits in OpenCode V2. Use whenever the user asks to start, resume, track, validate, or report a security assessment and needs exact scope enforcement, hard time limits, hashed evidence, SQLite state, or Claude-BugHunter routing. This skill never auto-installs tools, never skips authorization or scope, and excludes DoS, persistence, internal AD, lateral movement, social engineering, and post-exploitation.
license: MIT
compatibility: OpenCode V2 and Python 3.10+
---

# OpenCode Security Ops

Coordinate security work; do not replace operator judgment or tool permissions.

## Non-negotiable boundaries

- Require a versioned scope document with `authorization.confirmed: true` before network activity.
- Treat scope as exact and deny-first. A bare host does not imply subdomains; `*.example.com` does not include the apex.
- Never use a prompt flag to skip authorization, scope, approval, or time limits.
- Stop active work when the budget expires. Generate a handoff; do not “push harder.”
- Ask before every active phase. State-changing requests are excluded from v1.
- Do not install tools, use `sudo`, or execute downloaded scripts.
- Do not perform DoS, credential stuffing, persistence, internal AD, lateral movement, social engineering, malware, stealth/evasion, or post-exploitation.
- Keep observations, hypotheses, tests, evidence, and conclusions separate.
- Never confirm a finding without a sanitized evidence artifact and validation note.

## Runtime

Supporting code is bundled relative to this file:

```bash
SKILL_DIR="<base directory shown by the skill tool>"
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops --help
```

Use `.secops/state.db` inside the active repository by default. Do not store credentials, cookies, tokens, SOW documents, or unredacted PII in SQLite or evidence artifacts.

## Workflow

### 1. Choose mode

- Local filesystem/repository → `code-audit`; no network scope.
- Authorized URL/host → `web`, `api`, or `cloud-external`.
- If both appear, ask which mode to run first.

### 2. Create scope

Copy `references/scope.example.json`, then ask the user only for the precise allow/deny boundaries and a non-secret authorization reference such as a ticket ID. Never request the engagement letter itself.

Validate and initialize:

```bash
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops init \
  --name <engagement> --scope <scope.json> --minutes <maximum-minutes>
```

Before each network request, run `scope-check` with the exact method and URL. A nonzero result is a hard stop.

### 3. Route knowledge lazily

Use Claude-BugHunter as an optional knowledge layer when its skills are installed. Load no more than five skills initially:

1. one methodology skill;
2. up to two stack/platform skills supported by evidence;
3. up to two vulnerability-class skills matching the current hypothesis.

Prefer `bb-methodology` for WAPT, `recon-scope-triage` for supplied recon, and the narrowest relevant `hunt-*` skill. Load `triage-validation` and `evidence-hygiene` only during validation; load reporting skills only during reporting. If these skills are unavailable, continue with the local workflow rather than fetching dependencies.

### 4. Plan, then approve

Pipeline files are plans, not executors. Render with:

```bash
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops pipeline-plan --file <pipeline.json>
```

Show active steps, expected request volume, rate, concurrency, evidence destination, and stop conditions. Obtain approval before active work.

### 5. Record evidence

Log a successful scope check and each meaningful observation/test. Tests require sanitized artifacts so they receive a SHA-256 hash. Never treat scanner output alone as confirmation.

```bash
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops log \
  --engagement <name> --phase testing --kind test \
  --summary "bounded description" --artifact <sanitized-file>
```

Track discovered but unexplored pathways as leads. Newly discovered hosts are report-only until the user adds them to scope.

### 6. Validate and report

Run the phase gate. A failing gate lists missing evidence; it does not authorize more aggressive testing. Confirmed findings require evidence and a validation note.

When time expires, scope changes, authorization is withdrawn, a stop condition fires, or the user asks to stop:

```bash
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops stop --engagement <name> --reason "..."
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops handoff --engagement <name> --output <handoff.md>
```

## Output standard

Report confirmed findings first, then rejected candidates and open leads. Cite artifact paths and hashes. Clearly state untested surfaces and limitations. Never claim exhaustive coverage solely because a checklist or gate passed.
