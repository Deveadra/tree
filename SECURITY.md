# Security Policy

## Reporting a Vulnerability
Please report vulnerabilities privately by emailing **security@example.com** with:
- Affected version/commit.
- Reproduction steps / proof of concept.
- Impact assessment (confidentiality/integrity/availability).
- Suggested remediation (optional).

Do **not** open public issues for unpatched vulnerabilities.

## Disclosure Process
1. **Acknowledge** report within 3 business days.
2. **Triage** severity and exploitability within 7 business days.
3. **Mitigate** with fix + regression tests.
4. **Coordinate disclosure** with reporter after patch release.

## Internal Triage Workflow
- Intake: assign tracking ID and owner.
- Validation: reproduce in a clean environment.
- Classification: score risk (critical/high/medium/low).
- Containment: short-term guards/config toggles if needed.
- Remediation: implement code fix and tests.
- Verification: run CI + security scans.
- Release: publish patch notes and advisories.
