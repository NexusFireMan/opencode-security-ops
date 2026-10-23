---
description: Validate a candidate finding for scope, evidence sufficiency, redaction, and severity
agent: secops-evidence-reviewer
subagent: true
---

Validate this candidate finding and its supplied evidence:

$ARGUMENTS

Return PASS, REJECT, DOWNGRADE, or NEEDS-EVIDENCE. Require a complete comparative test, full sanitized context, one changed variable, root cause, broken security boundary, and demonstrated attacker gain. Check that internal severity and platform rating match the evidence. Do not run tools, reproduce secrets, or invent missing impact.
