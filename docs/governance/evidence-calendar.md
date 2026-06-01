# Evidence Collection Calendar

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Document Owner   | CTO                                        |
| Approved By      | CyberForge Management                      |
| Version          | 1.0                                        |
| Effective Date   | 2026-03-15                                 |
| Review Cycle     | Annually, or after changes to control scope |

---

## 1. Purpose

This calendar defines the recurring schedule for evidence collection activities required to demonstrate operating effectiveness of CyberForge's controls. Consistent, timely evidence collection is essential for SOC 2 Type II readiness and ongoing compliance with DORA, NIS2, and ISO 27001.

## 2. Scope

This calendar covers all evidence collection activities related to the control domains defined in the [SOC 2 Control Matrix](soc2-control-matrix.md) and the system boundary described in the [SOC 2 System Description](soc2-system-description.md).

---

## 3. Type I vs. Type II: Evidence Collection Requirements

SOC 2 Type I assesses whether controls are suitably designed at a point in time. SOC 2 Type II assesses whether controls are operating effectively over a period (minimum 6 months, typically 12 months).

**Type II requires:**

- Evidence collected consistently throughout the audit period, not assembled retroactively.
- Demonstrated pattern of recurring activities (reviews completed on schedule, SLAs met, gates enforced).
- Documentation of exceptions, failures, and remediations as they occur.

This calendar is designed to support Type II readiness. All activities must be completed on schedule and evidenced with dated artifacts. Gaps in the evidence trail weaken the Type II assertion.

---

## 4. Per Release (Continuous)

These activities are automated and execute on every pipeline run. They produce evidence without manual intervention.

| Activity | Owner | SOC 2 Criterion | Evidence Artifact |
|---|---|---|---|
| Evidence pack generation | Pipeline (automated) | CC7.1, CC8.1 | Evidence pack ZIP, `manifest.sha256`, compliance matrix |
| Security gate execution (Phase 1) | Pipeline (automated) | CC5 | `security-report.json`, workflow logs |
| Build and scan execution (Phase 2) | Pipeline (automated) | CC5, CC7.2 | `dependency-review.json`, coverage report, `security-report.json` |
| Artifact signing and attestation (Phase 3) | Pipeline (automated) | CC9.1 | Cosign signature, `sbom.cyclonedx.json`, `provenance.intoto.jsonl` |
| Signature verification and deployment (Phase 4) | Pipeline (automated) | CC7.1, PI1.4 | `cosign-verification.log`, deployment logs |
| DAST scan (Phase 5) | Pipeline (automated) | CC7.2, PI1.3 | `zap-report.json` |
| Compliance matrix generation | Pipeline (automated) | PI1.5 | `compliance-matrix.json` |

---

## 5. Monthly

| Activity | Owner | SOC 2 Criterion | Evidence Artifact | Due By |
|---|---|---|---|---|
| Pipeline health review (success/failure rate, gate bypass attempts) | Security Lead | CC7.1 | Pipeline metrics dashboard export, failure analysis summary | Last business day of each month |
| Vulnerability scan summary (open vulnerabilities by severity, SLA compliance rate, MTTR) | Security Lead | CC7.2 | Vulnerability metrics report per [Vulnerability Management Policy](vulnerability-management-policy.md) Section 8 | Last business day of each month |

---

## 6. Quarterly

| Activity | Owner | SOC 2 Criterion | Evidence Artifact | Next Due |
|---|---|---|---|---|
| Privileged access review (GitHub Org Owners, Azure Owners/Contributors) | Security Lead | CC6.1 | Org member export + RBAC export + sign-off record per [Access Review Procedure](access-review-procedure.md) | 2026-06-15 |
| Service principal review (pipeline SP roles, federated credentials) | DevOps Lead | CC6.1, CC6.3 | SP + federated credential export + sign-off record | 2026-06-15 |
| Vendor risk review (update register, DPA status verification) | CTO | CC9 | Updated [Vendor Risk Register](vendor-risk-register.md), DPA compliance check output | 2026-06-15 |
| Risk register review (reassess likelihood/impact, update treatments) | CTO | CC3 | Updated [Risk Register](risk-register.md) with review date and notes | 2026-06-15 |
| Exception register review (verify active/expired exceptions) | Security Lead | CC3 | Updated exception register with review record | 2026-06-15 |
| Branch protection verification (main branch rules intact) | DevOps Lead | CC8.1 | Branch protection config export via `export-github-security-config.sh` | 2026-06-15 |

---

## 7. Semi-Annually

| Activity | Owner | SOC 2 Criterion | Evidence Artifact | Next Due |
|---|---|---|---|---|
| Standard access review (all GitHub team memberships, all Azure RBAC assignments) | Security Lead | CC6.2 | Team export + RBAC export + sign-off record per [Access Review Procedure](access-review-procedure.md) | 2026-09-15 |
| Policy review (update governance documents for accuracy and relevance) | CTO | CC1.4 | Policy change log, PR history for `docs/governance/` | 2026-09-15 |
| Security training completion check | CTO | CC1.4 | Training completion records | 2026-09-15 |

---

## 8. Annually

| Activity | Owner | SOC 2 Criterion | Evidence Artifact | Next Due |
|---|---|---|---|---|
| Full risk assessment | CTO | CC3 | Updated [Risk Register](risk-register.md), risk assessment report | 2027-03-15 |
| Internal audit (cross-audit or external) | External / Cross-audit | CC4 | Internal audit report with findings and recommendations | 2027-03-15 |
| Management review | CTO + Security Lead | CC1.2 | Management review meeting minutes, action items | 2027-03-15 |
| ISMS scope review | CTO | CC1.1 | Updated ISMS scope document | 2027-03-15 |
| SOC 2 system description review | CTO | CC1.1 | Updated [SOC 2 System Description](soc2-system-description.md) | 2027-03-15 |
| BC/DR drill (pipeline recovery, infrastructure rebuild) | DevOps Lead | CC7.1 | Drill execution record, recovery time metrics, lessons learned | 2027-03-15 |
| Control ownership matrix review | CTO | CC1.3 | Updated [Control Owners](control-owners.md) | 2027-03-15 |

---

## 9. Calendar Summary

| Frequency | Activity Count | Primary Responsibility |
|---|---|---|
| Per Release (Continuous) | 7 | Pipeline (automated) |
| Monthly | 2 | Security Lead |
| Quarterly | 6 | Security Lead, CTO, DevOps Lead |
| Semi-Annually | 3 | Security Lead, CTO |
| Annually | 7 | CTO, External, DevOps Lead |

---

## 10. Evidence Storage and Retention

All evidence artifacts are stored in the following locations:

| Evidence Type | Storage Location | Retention Period |
|---|---|---|
| Pipeline-generated evidence packs | Azure Blob Storage (WORM) | Per WORM immutability policy (minimum 3 years) |
| Access review exports and sign-offs | `evidence/access-review-YYYY-QN/` directory + governance archive | Minimum 3 years |
| Policy and governance documents | Git repository (`docs/governance/`) with full version history | Indefinite (version controlled) |
| Meeting minutes and management reviews | Governance archive | Minimum 3 years |

---

## 11. Missed Evidence Collection

If a scheduled evidence collection activity is missed:

1. The activity owner documents the reason for the miss.
2. The activity is completed as soon as practicable.
3. The delay is noted in the evidence artifact with an explanation.
4. If the miss affects SOC 2 audit coverage, the CTO is notified and the impact is assessed.

Repeated misses indicate a process failure and must be addressed through corrective action.

---

## Revision History

| Date | Change | Author |
|------|--------|--------|
| 2026-03-15 | Initial version | CyberForge Engineering |

---

## Related Documents

- [SOC 2 Control Matrix](soc2-control-matrix.md)
- [SOC 2 System Description](soc2-system-description.md)
- [Control Owners](control-owners.md)
- [Access Review Procedure](access-review-procedure.md)
- [Access Review Schedule](access-review-schedule.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [Risk Register](risk-register.md)
