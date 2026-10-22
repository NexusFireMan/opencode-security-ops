# opencode-security-ops

Safe, evidence-oriented engagement orchestration for **OpenCode V2**.

It combines exact scope controls, hard-stop time budgets, SQLite state, hashed evidence, declarative pipelines, factual handoffs, and optional routing into Claude-BugHunter's specialist knowledge. It deliberately excludes autonomous “full offensive” modes and never installs security tools.

## Design principles

- **Authorization cannot be bypassed by a prompt flag.**
- **Deny wins; everything else defaults to denied.** Scope can restrict scheme, exact host/wildcard, port, path prefix, and HTTP method.
- **Time is a maximum, not a target.** Expiry blocks active work and directs the operator to a handoff.
- **Pipelines plan; humans approve.** No pipeline automatically executes network commands.
- **Evidence before claims.** Confirmed findings need a sanitized artifact, SHA-256, and validation note.
- **No surprise installation.** No `sudo`, package managers, shell-profile edits, or downloaded installers.
- **OpenCode V2 native.** Uses current `permissions`, `shell`, and `subagent` fields.

## Scope of v1

Included:

- Defensive source-code audits.
- Authorized web and API assessments.
- External cloud configuration review.
- Passive-first reconnaissance, bounded read-only validation, triage, reporting, and handoff.

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
- commands: `/secops/engage`, `/secops/audit`, `/secops/validate`, `/secops/report`

Example:

```text
/secops/audit src/auth
/secops/engage API assessment for api.example.com, scope file examples/scope.web.json, 60 minute maximum
```

## CLI

From a clone:

```bash
export PYTHONPATH="$PWD/.opencode/skills/opencode-security-ops/scripts"
python3 -m secops --help
python3 -m secops pipeline-plan --file pipelines/web-api.json
python3 -m secops init --name demo --scope examples/scope.web.json --minutes 60
python3 -m secops scope-check --engagement demo --method GET --url https://api.example.com/v1/public/status
```

State defaults to `.secops/state.db` in the active repository.

## Claude-BugHunter integration

Claude-BugHunter is optional and is not vendored. When its skills are already installed, the orchestrator loads the narrowest relevant methodology/platform/vulnerability skills with an initial five-skill context budget. Without it, scope, evidence, state, pipelines, and reporting continue to work.

## Testing

```bash
bash install.sh --check
```

CI validates unit tests, Python syntax, shell syntax, OpenCode V2 frontmatter, pipeline safety, and installer behavior in an isolated home directory.

## Project status

Version `0.1.0` is intentionally conservative. See [`docs/architecture.md`](docs/architecture.md) and [`docs/threat-model.md`](docs/threat-model.md).

## License and attribution

MIT. The architecture is original code informed by lessons from Claude-BugHunter and opencode-pentester; neither project is vendored. See [`NOTICE`](NOTICE).
