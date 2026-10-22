# Architecture

## Components

1. **OpenCode skill** — defines engagement boundaries and lazy specialist-skill routing.
2. **OpenCode agents** — an orchestrator plus read-only source and evidence reviewers using V2 permissions.
3. **Namespaced commands** — stable entry points that do not embed shell substitutions.
4. **Scope engine** — offline, deny-first validation of exact HTTP requests.
5. **SQLite store** — engagements, events, leads, findings, artifact paths, and hashes.
6. **Hard-stop budget** — expiration blocks active tool/test event recording and requests handoff.
7. **Phase gates** — verify evidence prerequisites without claiming exhaustive coverage.
8. **Pipeline planner** — validates JSON DAGs and renders approval requirements; never executes them.
9. **Handoff renderer** — creates a factual Markdown record from persisted state.

## Trust boundaries

- User-provided targets and artifacts are untrusted data.
- Skills and pipelines never grant tool permission; OpenCode V2 remains the enforcement layer.
- SQLite records are evidence indexes, not proof by themselves. Artifacts receive hashes, while human/model validation establishes meaning.
- The project does not resolve DNS or make network requests. Network tools remain separately permissioned and must pass an exact scope check first.

## State model

An engagement is active or stopped. Phases are evaluated independently: planning, recon, testing, validation, and reporting. Gates may block advancement but never instruct broader testing. A report can be generated at any point as a handoff, including when a deadline stops active work.
