---
name: opencode-security-ops
description: Safely orchestrate authorized web, API, external-cloud security engagements and defensive source-code audits in OpenCode V2. Use whenever the user starts, resumes, tracks, validates, retests, closes, or reports a security assessment, especially for HackerOne, Bugcrowd, YesWeHack, Intigriti, private programs, exact scope enforcement, hard time limits, comparative controls, hashed evidence, SQLite state, optional local draft exports, or Claude-BugHunter routing. Never auto-install tools, skip authorization, submit reports, or perform DoS, persistence, internal AD, lateral movement, social engineering, or post-exploitation.
license: MIT
compatibility: OpenCode V2 and Python 3.10+
---

# OpenCode Security Ops

Coordinate security work without replacing operator judgment, platform rules, or OpenCode permissions.

## Non-negotiable boundaries

- Require a versioned scope document with `authorization.confirmed: true` before network activity.
- Treat scope as exact and deny-first. A bare host does not imply subdomains; `*.example.com` does not include the apex.
- Never use a prompt flag to skip authorization, scope, approval, or time limits.
- Stop active work when the budget expires. Generate a handoff rather than “pushing harder.”
- Ask before every active phase. State-changing production requests are excluded.
- Do not install tools, use `sudo`, or execute downloaded installers.
- Exclude DoS, credential stuffing, persistence, internal AD, lateral movement, social engineering, malware, evasion, and post-exploitation.
- Keep observations, hypotheses, tests, evidence, conclusions, and reusable lessons separate.
- Treat incomplete or blocked probes as incomplete or blocked—not as negative results.
- Never confirm a finding without a complete comparative test, sanitized evidence, and a validation note.
- Never submit or disclose a report automatically.

## Runtime

Supporting code is bundled relative to this file:

```bash
SKILL_DIR="<base directory shown by the skill tool>"
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops --help
```

State defaults to `.secops/state.db` in the active repository. Do not store credentials, cookies, tokens, engagement letters, or unredacted PII in SQLite, manifests, or evidence artifacts.

## Workflow

### 1. Intake and mode

- Local repository → `code-audit`; no network scope.
- Authorized URL/host → `web`, `api`, or `cloud-external`.
- If both appear, ask which mode to run first.
- Record the platform as `hackerone`, `bugcrowd`, `yeswehack`, `intigriti`, `private`, or `other`.
- Treat platform profiles as metadata and terminology only; program-specific policy always wins.

Use `references/intake.example.json` for optional sanitized program constraints. Never scrape or submit to a platform automatically.

### 2. Scope and initialize

Copy `references/scope.example.json`, then ask only for precise allow/deny boundaries and a non-secret authorization reference. Never request the engagement letter itself.

```bash
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops init \
  --name <engagement> --scope <scope.json> --minutes <maximum-minutes> \
  --platform <platform> --program <program-name>
```

An optional user-selected draft destination may be supplied with `--output-dir` and `--layout generic|platform-program`. The skill must not assume a vault, directory convention, or output destination.

Before every network request, run `scope-check` with the exact method and URL. A nonzero result is a hard stop.

### 3. Route knowledge lazily

Use Claude-BugHunter only when its skills are already installed. Initially load no more than five: one methodology skill, up to two evidence-supported platform/stack skills, and up to two skills matching the current hypothesis. Load validation, evidence, and reporting skills only in their phases. Continue locally when optional skills are unavailable.

### 4. Plan and approve

Pipeline files are plans, not executors:

```bash
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops pipeline-plan --file <pipeline.json>
```

Show active steps, expected volume, rate, concurrency, evidence destination, and stop conditions. Obtain approval before active work.

### 5. Track hypotheses precisely

Use these states literally:

- `untested`: no meaningful probe yet.
- `in-progress`: active work is underway.
- `incomplete`: some planned checks did not run or context was insufficient.
- `blocked`: a control such as WAF, access, account, or environment prevented the test.
- `negative`: a complete test did not demonstrate the hypothesis.
- `candidate`: promising result awaiting full validation.
- `confirmed`: impact and broken boundary are demonstrated.
- `rejected`: false positive, invalid premise, or non-security behavior.

Record the surface, suspected root cause, security boundary, and concrete attacker gain. Before pursuing a variant, use `root-cause-check`; if the same cause already exists, pivot unless the new path crosses a distinct boundary or produces distinct impact.

### 6. Record comparative tests

A complete test needs:

1. a sanitized positive artifact;
2. a sanitized negative-control artifact;
3. a context manifest based on `references/context.example.json`;
4. one explicitly identified changed variable.

If headers, cookies, body, source revision, or other required context cannot be reproduced, record the test as `incomplete`. A WAF response alone is not a negative control.

For revocation, expiry, race, or other time-sensitive behavior, create an evidence sequence and add each step in capture order. Hashes protect integrity; they do not prove interpretation.

### 7. Validate PoCs and findings

Executable PoCs should have a manifest based on `references/poc.example.json`. Run `poc-check` before linking one to a finding. The check rejects implicit local proxies, user-specific absolute paths, missing timeouts, destructive defaults, and undocumented runtime requirements. Manual HTTP reproduction remains valid when no script is needed.

A confirmed finding must identify:

- a complete comparative test;
- sanitized evidence and SHA-256;
- root cause;
- security boundary crossed;
- demonstrated attacker gain;
- validation note;
- coherent internal severity and optional platform rating.

Platform rating and internal severity are separate fields. Never request a platform rating that conflicts with the demonstrated impact.

### 8. Export drafts only when requested

SQLite is the operational state. Filesystem drafts are optional:

```bash
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops output-set \
  --engagement <name> --directory <user-selected-path> --layout <layout>
PYTHONPATH="$SKILL_DIR/scripts" python3 -m secops draft-export --engagement <name>
```

Exports create generic program folders and sanitized generated snapshots. Generated files live under `.secops-generated/`; operator-maintained drafts are never overwritten. Refuse symlinked destinations and never infer a private knowledge-base path.

### 9. Close, retest, and learn

Use explicit close reasons such as `surface-exhausted`, `credentials-unavailable`, `payment-gate`, `platform-blocked`, `submission-capacity`, `testing-incomplete`, or `out-of-scope-dependency`. Record retests as new comparative tests rather than rewriting history. Store reusable process lessons separately from target-specific notes.

When time expires, authorization changes, a stop condition fires, or the user asks to stop, stop active work and create a handoff.

## Output standard

Report confirmed findings first, then other finding records, hypotheses and limitations, comparative tests, open leads, continuous evidence, event history, and reusable lessons. Cite hashes. Explicitly list incomplete, blocked, and untested work. Never claim exhaustive coverage because a checklist or gate passed.
