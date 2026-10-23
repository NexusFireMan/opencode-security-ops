# opencode-security-ops

Safe, evidence-oriented engagement orchestration for **OpenCode V2**.

It combines exact scope controls, hard-stop time budgets, SQLite state, precise hypothesis states, comparative testing, hashed evidence, declarative pipelines, factual handoffs, optional local draft workspaces, and optional routing into Claude-BugHunter's specialist knowledge. It deliberately excludes autonomous “full offensive” modes and never installs security tools or submits reports.

## Design principles

- **Authorization cannot be bypassed by a prompt flag.**
- **Deny wins; everything else defaults to denied.** Scope can restrict scheme, exact host/wildcard, port, path prefix, and HTTP method.
- **Time is a maximum, not a target.** Expiry blocks active work and directs the operator to a handoff.
- **Incomplete is not negative.** Interrupted, context-poor, or WAF-blocked probes remain explicitly incomplete or blocked.
- **Controls before claims.** Confirmation requires positive and negative controls, complete sanitized context, one changed variable, and hashed evidence.
- **Pipelines plan; humans approve.** No pipeline automatically executes network commands.
- **SQLite first, optional files.** Drafts are exported only to a user-selected destination; no private vault layout is assumed.
- **No surprise installation or submission.** No `sudo`, package managers, shell-profile edits, downloaded installers, or platform submissions.
- **OpenCode V2 native.** Uses current `permissions`, `shell`, and `subagent` fields.

## Scope

Included:

- Defensive source-code audits.
- Authorized web and API assessments.
- External cloud configuration review.
- Passive-first reconnaissance, bounded read-only validation, triage, reporting, retesting, and handoff.
- Generic workflow metadata for HackerOne, Bugcrowd, YesWeHack, Intigriti, private programs, and other platforms.

Excluded:

- DoS/stress testing, credential stuffing, internal AD, lateral movement, persistence, C2, malware, evasion, social engineering, physical security, and post-exploitation.
- State-changing production requests.
- Automated disclosure or submission.

## Quick start

Requirements: OpenCode V2 and Python 3.10+. Runtime code uses only the Python standard library.

```bash
git clone https://github.com/NexusFireMan/opencode-security-ops.git
cd opencode-security-ops
bash install.sh --check
bash install.sh --global
```

The installer adds:

- skill: `opencode-security-ops`
- agents: `secops-orchestrator`, `secops-reviewer`, `secops-evidence-reviewer`
- commands: `/secops/engage`, `/secops/audit`, `/secops/intake`, `/secops/hypothesis`, `/secops/validate`, `/secops/retest`, `/secops/report`, `/secops/close`, `/secops/lessons`

## CLI workflow

From a clone:

```bash
export PYTHONPATH="$PWD/.opencode/skills/opencode-security-ops/scripts"
python3 -m secops --help
python3 -m secops pipeline-plan --file pipelines/web-api.json
python3 -m secops init \
  --name demo --scope examples/scope.web.json --minutes 60 \
  --platform hackerone --program "Example Program"
python3 -m secops scope-check \
  --engagement demo --method GET --url https://api.example.com/v1/public/status
```

State defaults to `.secops/state.db` in the active repository. Existing v0.1 databases are upgraded in place; back up important engagement state before any application upgrade.

### Precise hypothesis states

`untested`, `in-progress`, `incomplete`, `blocked`, `negative`, `candidate`, `confirmed`, and `rejected` distinguish actual negative evidence from work that never completed.

```bash
python3 -m secops hypothesis-add \
  --engagement demo --title "Possible cross-account access" \
  --root-cause "owner not checked" --security-boundary "account isolation" \
  --attacker-gain "read another controlled test account"
```

### Comparative tests and temporal evidence

A `complete` test requires sanitized positive and negative artifacts, a validated context manifest, and one changed variable. Use evidence sequences for revocation, expiry, race, and other time-sensitive behavior.

```bash
python3 -m secops test-record \
  --engagement demo --title "Cross-account object read" --status complete \
  --positive evidence/positive.txt --negative evidence/negative.txt \
  --context evidence/context.json --context-complete \
  --variable-changed "authenticated test account"
```

### Portable PoCs

Executable PoCs can be checked with a small JSON manifest:

```bash
python3 -m secops poc-check --manifest poc/poc.json
```

The validator rejects implicit local proxies, user-specific absolute paths, destructive defaults, missing timeouts, missing check mode, and undocumented dependencies/environment variables.

### Optional draft destination

The project never assumes a knowledge-base path. Select a destination explicitly:

```bash
python3 -m secops output-set \
  --engagement demo --directory ~/security-drafts --layout platform-program
python3 -m secops draft-export --engagement demo
```

The export creates generic program folders. Machine-generated, sanitized snapshots are refreshed under `.secops-generated/`; operator-maintained files such as `engagement.md` are never overwritten. Symlinked managed paths are refused.

## Platform profiles

Profiles provide rating labels and closure terminology only:

```bash
python3 -m secops platform-profile --platform bugcrowd
```

Program-specific policy always wins. The project does not connect to platform APIs or automate disclosure.

## Claude-BugHunter integration

Claude-BugHunter is optional and is not vendored. When its skills are already installed, the orchestrator loads the narrowest relevant methodology, platform, or vulnerability skills with an initial five-skill context budget. Without it, scope, evidence, state, pipelines, and reporting continue to work.

## Testing

```bash
bash install.sh --check
```

CI validates unit tests, Python and shell syntax, deterministic safety evaluations, OpenCode V2 frontmatter, pipeline safety, migration behavior, evidence controls, output-path guards, and the installer lifecycle in an isolated home directory.

## Project status

Version `0.2.0` remains intentionally conservative. See [`docs/architecture.md`](docs/architecture.md), [`docs/threat-model.md`](docs/threat-model.md), and [`CHANGELOG.md`](CHANGELOG.md).

## License and attribution

MIT. The architecture is original code informed by lessons from Claude-BugHunter and opencode-pentester; neither project is vendored. See [`NOTICE`](NOTICE).
