# Safety model

## Allowed in v1

- Defensive local source review.
- Passive public-source reconnaissance for explicitly authorized assets.
- Bounded, approved web/API requests inside exact scope.
- External cloud configuration review when the account/resource is explicitly listed.
- Reproduction with researcher-controlled accounts and sanitized evidence.

## Excluded in v1

- Denial of service or stress testing.
- Credential stuffing, password spraying, or broad brute force.
- Internal Active Directory, lateral movement, persistence, C2, malware, or evasion.
- Social engineering and physical security.
- State-changing production requests.
- Automatically publishing findings or contacting third parties.

## Stop conditions

Stop active work and create a handoff when the budget expires, authorization is withdrawn, scope is ambiguous, rate limits or instability appear, production data is unexpectedly exposed, or a request would mutate target state.
