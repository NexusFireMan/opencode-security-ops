# Architecture

## Components

1. **OpenCode skill** — defines engagement boundaries and lazy specialist-skill routing.
2. **OpenCode agents** — an orchestrator plus read-only source and evidence reviewers using V2 permissions.
3. **Namespaced commands** — stable intake, engagement, hypothesis, validation, retest, report, close, and lessons entry points.
4. **Scope engine** — offline, deny-first validation of exact HTTP requests.
5. **SQLite store** — engagements, events, leads, hypotheses, comparative tests, findings, temporal evidence sequences, and lessons.
6. **Hard-stop budget** — expiration blocks active tool/test recording and requests handoff.
7. **Phase gates** — require evidence prerequisites without claiming exhaustive coverage.
8. **PoC/context validators** — enforce portable PoC metadata and complete sanitized test context.
9. **Platform profiles** — generic terminology for HackerOne, Bugcrowd, YesWeHack, Intigriti, private engagements, and other programs.
10. **Pipeline planner** — validates JSON DAGs and renders approval requirements; never executes them.
11. **Handoff renderer** — creates a factual Markdown record from persisted state.
12. **Optional draft exporter** — creates a generic or platform/program workspace only at a user-selected path.

## Trust boundaries

- User-provided targets, paths, manifests, program rules, and artifacts are untrusted data.
- Skills and pipelines never grant tool permission; OpenCode V2 remains the enforcement layer.
- SQLite records are evidence indexes, not proof by themselves. Hashes establish artifact integrity after capture; validation establishes meaning.
- The project does not resolve DNS, make network requests, access platform APIs, or submit reports.
- Filesystem exports are optional. Managed paths reject symlinks, generated files are isolated, and operator-maintained drafts are not overwritten.
- Platform profiles never override a program's current published rules.

## State model

An engagement is `active`, `stopped`, or `closed`. A stopped engagement is an immediate operational halt; a closed engagement has a normalized closure reason.

Hypotheses use `untested`, `in-progress`, `incomplete`, `blocked`, `negative`, `candidate`, `confirmed`, or `rejected`. This prevents an interrupted or blocked probe from becoming an accidental claim of safety.

Tests are `complete`, `incomplete`, or `blocked`. A complete test requires positive and negative artifacts, full sanitized context, and one identified changed variable. Findings are separate records. Confirmation additionally requires root cause, security boundary, attacker gain, evidence, and validation.

Phases are evaluated independently: planning, recon, testing, validation, and reporting. Gates may block advancement but never instruct broader testing. A handoff can be generated at any point, including after a deadline.

## Persistence and migration

SQLite schema creation is idempotent. v0.2 adds columns and tables to a v0.1 database without deleting existing rows. Migrations are intentionally additive; future breaking transformations should use explicit schema versions and backup guidance.

The optional draft workspace is not a second source of truth. `.secops-generated/state.json` and `handoff.md` are sanitized projections of SQLite state; manual drafts remain operator-owned.
