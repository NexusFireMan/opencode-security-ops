# Contributing

Contributions should preserve the project's deny-first safety model.

## Development

Requirements: Python 3.10+ and Bash. The runtime has no third-party Python dependencies.

```bash
bash install.sh --check
python3 evals/run.py
```

Before opening a pull request:

1. Add tests for behavior changes and scope edge cases.
2. Keep pipelines declarative; they must not execute tools or network requests.
3. Do not add authorization, scope, approval, or time-budget bypasses.
4. Do not add automatic package installation, `sudo`, downloaded-script execution, or shell-profile edits.
5. Use OpenCode V2 fields (`permissions`, `shell`, and `subagent`).
6. Avoid real target data, secrets, credentials, session material, and unredacted evidence.

Security-sensitive changes should explain the threat being addressed and any residual risk. Report vulnerabilities through the process in [`SECURITY.md`](SECURITY.md), not a public issue.
