# Support SLA / SLO Targets

## SLA (external commitments)

- **P1 (data loss risk / blocked cleanup in production):** first response within **2 hours**, workaround or mitigation within **8 hours**.
- **P2 (major degraded behavior):** first response within **8 hours**, mitigation within **2 business days**.
- **P3 (minor bugs / doc gaps):** first response within **2 business days**, fix scheduled within **2 sprints**.

## SLO (internal operational goals)

- 95% of P1 tickets acknowledged in <= 60 minutes.
- 90% of diagnostic bundles reviewed within 1 business day.
- 85% of confirmed defects triaged with owner+severity within 2 business days.
- 80% of regressions resolved in the release immediately following triage.

## Defect turnaround policy

- Security/privacy defects: hotfix path, target <= 7 days.
- Data integrity defects: patch release target <= 14 days.
- Non-critical UX/docs defects: bundled into next planned minor release.
