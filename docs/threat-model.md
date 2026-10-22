# Threat model

## Risks addressed

- Prompt text attempting to bypass authorization or approvals.
- Scope expansion from apex domains to unlisted subdomains.
- Requests escaping allowed paths, ports, schemes, or HTTP methods.
- Continuing active work after a deadline.
- Scanner output or HTTP status codes being promoted to confirmed findings.
- Evidence tampering or accidental omission.
- Secrets and personal data leaking into reports.
- Supply-chain exposure from automatic tool installation.
- Agent fan-out consuming context or losing scope.

## Controls

- No “dangerous” or “full-offensive” bypass flag exists.
- Authorization is a required field in a validated scope document.
- Deny-first exact matching and default deny.
- Active event logging is blocked after budget expiry.
- Confirmed findings require an evidence file and validation note.
- Evidence paths and SHA-256 hashes are recorded.
- Pipelines reject state-changing steps and active steps without approval.
- Installer copies local files only and defaults to check-only mode.
- Agents use V2 permissions and cannot silently install or elevate tools.

## Residual risks

- A dishonest scope declaration cannot be independently verified by software.
- A hash proves artifact integrity after capture, not that its interpretation is correct.
- OpenCode shell permission matching is best effort; global policies should hard-deny `sudo` and other prohibited commands where stronger enforcement is required.
- DNS can change after an offline scope check. Operators should use network tooling that pins and verifies resolved addresses at execution time.
