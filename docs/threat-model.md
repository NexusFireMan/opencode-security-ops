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
- Interrupted or WAF-blocked probes being misclassified as negative results.
- False negatives caused by missing headers, cookies, body, or source revision.
- PoCs depending on local proxies, absolute paths, or undocumented state.
- Draft exports overwriting operator notes or escaping through symlinks.
- Platform terminology being mistaken for program authorization.

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
- Hypotheses and tests preserve incomplete and blocked states explicitly.
- Complete tests require positive/negative controls, full context, and one changed variable.
- PoC manifests require timeouts, check mode, non-destructive defaults, and portable paths.
- Draft exports require a user-selected path, isolate generated files, preserve manual drafts, and reject managed symlinks.
- Platform profiles provide metadata only and never connect to submission APIs.

## Residual risks

- A dishonest scope declaration cannot be independently verified by software.
- A hash proves artifact integrity after capture, not that its interpretation is correct.
- OpenCode shell permission matching is best effort; global policies should hard-deny `sudo` and other prohibited commands where stronger enforcement is required.
- DNS can change after an offline scope check. Operators should use network tooling that pins and verifies resolved addresses at execution time.
- Sanitization is a human responsibility; schema validation cannot reliably detect every secret embedded in free text or artifacts.
- Static PoC portability checks catch common local dependencies but cannot prove semantic safety; operators must still read the code.
- SQLite additive migration preserves state but does not replace backups for important engagements.
