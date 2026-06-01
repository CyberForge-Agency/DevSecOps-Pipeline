# Corrective Actions Log

**Document Owner:** Security Lead
**Last Reviewed:** 2026-03-15
**Review Cadence:** Monthly, or after any new finding is logged
**Version:** 1.0
**ISO 27001 Reference:** Clause 10.2

---

## 1. Purpose

This log tracks all nonconformities, corrective actions, and preventive actions (CAPA) identified within the CyberForge ISMS. It provides a single, auditable record of how nonconformities are identified, investigated, corrected, and verified to prevent recurrence.

This log satisfies the ISO 27001 Clause 10.2 requirement to:

- React to nonconformities and take action to control and correct them.
- Evaluate the need for action to eliminate the causes of nonconformities.
- Implement any action needed.
- Review the effectiveness of corrective actions taken.
- Make changes to the ISMS if necessary.

---

## 2. Scope

This log covers corrective actions arising from all sources within the ISMS:

| Source | Description |
|---|---|
| **Internal audit** | Findings from the internal audit program ([internal-audit-program.md](internal-audit-program.md)) |
| **Management review** | Action items from management review meetings ([management-review-template.md](management-review-template.md)) |
| **Incident** | Nonconformities identified during or after security incidents ([crisis-management-plan.md](crisis-management-plan.md)) |
| **Access review** | Issues found during periodic access reviews ([access-review-procedure.md](access-review-procedure.md)) |
| **External audit** | Findings from certification body or other external audits |
| **Customer complaint** | Security-related complaints or concerns raised by clients |

---

## 3. Status Definitions

| Status | Definition |
|---|---|
| **Open** | Finding has been logged; corrective action not yet defined or started |
| **In Progress** | Corrective action has been defined and implementation is underway |
| **Completed** | Corrective action has been implemented; awaiting verification |
| **Verified** | Corrective action effectiveness has been verified by an independent reviewer |
| **Closed** | Finding is closed; no further action required |

---

## 4. Severity Definitions

| Severity | Definition | Response Timeline |
|---|---|---|
| **Major** | Significant failure to meet an ISO 27001 requirement; raises doubt about ISMS effectiveness | Root cause analysis within 5 business days; corrective action plan within 10 business days; implementation within 60 days |
| **Minor** | Partial failure to meet a requirement; does not by itself raise significant doubt about ISMS effectiveness | Corrective action plan within 15 business days; implementation within 90 days |

---

## 5. Corrective Actions Log

| CAPA ID | Source | Finding | Severity | Root Cause | Corrective Action | Owner | Target Date | Completion Date | Verification | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| CAPA-001 (EXAMPLE) | Internal audit (IA-2026-Q1, F-2026-Q1-003) | Access review for Q4 2025 was not completed on schedule. No evidence of privileged access review for GitHub Org Owners and Azure Subscription Owners for the period. Control A.5.18 / A.8.2 partially non-conforming. | Minor | Manual process with no automated reminder. Founders were occupied with client delivery and the review was overlooked. No calendar reminder or ticketing system trigger existed. | 1. Implement quarterly automated export scripts that generate access review snapshots from GitHub API and Azure CLI. 2. Create calendar reminders 2 weeks before each review deadline. 3. Add access review status as a standing agenda item in management reviews. | Security Lead | 2026-04-30 | -- | -- | Open |
| CAPA-002 (EXAMPLE) | Incident (INC-2026-007) | Trivy SCA scan failed to detect CVE-2026-XXXXX in a transitive dependency because the Trivy vulnerability database was 9 days stale. The CVE was published 7 days prior. The vulnerability was discovered during a manual review, not by automated scanning. Control A.8.8 partially non-conforming. | Major | Trivy database update step in the build-and-scan workflow did not include a freshness check. Network issues on GitHub-hosted runner prevented the database update, but the scan proceeded with a stale database without raising an error. | 1. Add a Trivy database freshness check step in `.github/workflows/build-and-scan.yml` that fails the pipeline if the database is more than 48 hours old. 2. Add a `--skip-db-update=false` flag to enforce database download. 3. Implement a weekly automated job that verifies Trivy database currency and alerts the Security Lead if stale. 4. Update the vulnerability management policy to include database freshness as a control requirement. | Security Lead | 2026-04-15 | -- | -- | Open |

---

## 6. Process

### 6.1 Logging a New Finding

1. Assign the next sequential CAPA ID (CAPA-NNN).
2. Record the source, finding description, and severity.
3. Assign an owner responsible for investigation and correction.
4. Set a target date consistent with the severity-based response timeline.

### 6.2 Root Cause Analysis

1. The CAPA owner investigates the root cause of the nonconformity.
2. Root cause analysis techniques include: 5 Whys, fishbone diagram, or timeline analysis.
3. The root cause is documented in the log.
4. The root cause must address why the nonconformity occurred, not just what happened.

### 6.3 Corrective Action Definition

1. The CAPA owner defines specific, measurable corrective actions.
2. Corrective actions must address the root cause (not just the symptoms).
3. Where applicable, corrective actions should include preventive measures to avoid recurrence.
4. The corrective action plan is reviewed and approved by CyberForge Management for Major findings.

### 6.4 Implementation

1. The CAPA owner implements the corrective actions.
2. Progress is tracked in this log.
3. The completion date is recorded when all actions are implemented.
4. Status changes from "Open" to "In Progress" to "Completed".

### 6.5 Verification

1. Verification is performed by someone other than the CAPA owner (cross-audit principle).
2. The verifier confirms that:
   - The corrective action has been fully implemented.
   - The corrective action addresses the root cause.
   - The nonconformity has not recurred.
   - No new issues have been introduced by the corrective action.
3. Verification evidence is documented.
4. Status changes from "Completed" to "Verified" and then to "Closed".

---

## 7. Metrics

The following metrics are tracked and reported at each management review:

| Metric | Description |
|---|---|
| Total open CAPAs | Number of corrective actions not yet closed |
| Overdue CAPAs | Number of CAPAs past their target date |
| Average time to close | Mean duration from finding to closure |
| CAPAs by source | Distribution of findings across source types |
| CAPAs by severity | Distribution of Major vs. Minor findings |
| Recurrence rate | Percentage of closed CAPAs with recurrence of the same finding |

---

## 8. Compliance Mapping

| Requirement | Framework Reference |
|---|---|
| Nonconformity and corrective action | ISO 27001 Clause 10.2 |
| Continual improvement | ISO 27001 Clause 10.1 |
| Monitoring, measurement, analysis and evaluation | ISO 27001 Clause 9.1 |
| Incident handling | NIS2 Art.21.2.b |
| ICT-related incident management | DORA Art.17 |

---

## 9. Related Documents

- [Internal Audit Program](internal-audit-program.md)
- [Management Review Template](management-review-template.md)
- [Crisis Management Plan](crisis-management-plan.md)
- [Access Review Procedure](access-review-procedure.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Risk Register](risk-register.md)

---

## 10. Revision History

| Date | Change | Author |
|---|---|---|
| 2026-03-15 | Initial version with CAPA template and 2 example entries | CyberForge Security Lead |
