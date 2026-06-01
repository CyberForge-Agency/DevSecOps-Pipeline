# Control Ownership Matrix

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Document Owner   | CTO                                        |
| Approved By      | CyberForge Management                      |
| Version          | 1.0                                        |
| Effective Date   | 2026-03-15                                 |
| Review Cycle     | Annually, or on organizational changes     |

---

## 1. Purpose

This document assigns ownership of each control domain within the CyberForge DevSecOps Pipeline to a named role. Clear ownership ensures that every control has a responsible party for implementation, monitoring, evidence collection, and escalation. It satisfies the SOC 2 requirement (CC1.3) that management establishes accountability for internal controls.

## 2. Scope

This matrix covers all control domains mapped in the [SOC 2 Control Matrix](soc2-control-matrix.md) and applies to the system boundary defined in the [SOC 2 System Description](soc2-system-description.md).

---

## 3. Ownership Matrix

| Control Domain | Primary Owner | Backup Owner | Responsibilities |
|---|---|---|---|
| Pipeline Security (Phases 1-6) | Security Lead | CTO | Maintain workflow configurations, review scan findings, approve exceptions, validate gate effectiveness |
| Infrastructure (Terraform) | DevOps Lead | CTO | Manage Azure resources, RBAC assignments, Terraform state, infrastructure change review |
| Access Management | Security Lead | CTO | JML process execution, access reviews (quarterly/semi-annual), MFA enforcement verification |
| Vulnerability Management | Security Lead | CTO | Triage findings, track remediation SLAs, manage risk acceptances, report metrics |
| Vendor / Supplier Risk | CTO | Security Lead | Vendor due diligence, DPA tracking, contract reviews, exit plan maintenance |
| Incident Response | Security Lead | CTO | Incident classification, escalation, containment, post-incident review |
| Evidence and Compliance | CTO | Security Lead | Evidence pack integrity, compliance matrix accuracy, audit preparation, SOC 2 system description maintenance |
| Change Management | DevOps Lead | Security Lead | PR review process enforcement, deployment approvals, emergency change tracking, rollback coordination |

---

## 4. Startup Dual-Role Note

CyberForge operates as a small startup. With two founders, one person may hold multiple roles simultaneously (for example, the CTO may also act as DevOps Lead for infrastructure tasks). Where dual roles are unavoidable, the following compensating controls mitigate the reduction in separation of duties:

- **Mandatory two-reviewer PR approval** -- no individual can approve and merge their own change, even if they hold both the Primary Owner and Backup Owner roles for a given domain.
- **CODEOWNERS enforcement** -- security-sensitive paths (`.github/workflows/`, `infra/`, `policies/`, `Dockerfile`) require review from the security team, preventing unilateral changes to critical configurations.
- **Cross-review between founders** -- the CTO and Security Lead cross-review each other's changes through the standard PR process. This is documented in PR review history.
- **Signed commits** -- all commits to the main branch must be cryptographically signed, providing non-repudiation for every change.
- **Audit log retention** -- GitHub Audit Log and Azure Activity Log capture all administrative actions, ensuring accountability even when role separation is limited.

When dual-role conflicts arise (for example, the CTO must approve their own vendor risk decision), the conflict is documented and the alternative reviewer (Security Lead, or vice versa) provides the approval.

---

## 5. Escalation Path

Control-related issues follow this escalation path:

```
Control Owner (Primary)
    |
    v
Control Owner (Backup)
    |
    v
CTO (management escalation)
    |
    v
External Advisor (legal, compliance, or audit counsel)
```

Escalation triggers:

| Condition | Escalation Target | Timeframe |
|---|---|---|
| Control failure detected (e.g., gate bypassed) | Backup Owner | Immediate |
| Control owner unable to resolve within SLA | CTO | Within 24 hours |
| Regulatory or legal implication | External Advisor | As soon as identified |
| Conflict of interest (owner is the subject of the finding) | CTO or alternative owner | Immediate |

---

## 6. Control Domain to Control ID Mapping

This section maps each control domain to the specific control IDs defined in the [SOC 2 Control Matrix](soc2-control-matrix.md) for traceability.

| Control Domain | Control IDs |
|---|---|
| Pipeline Security (Phases 1-6) | CC5-01, CC5-02, CC5-04, CC5-05, CC7-02, CC7-03, CC9-01, CC9-02 |
| Infrastructure (Terraform) | CC5-03, CC7-01, CC7-05, CC8-03, CC8-04 |
| Access Management | CC6-01 through CC6-09 |
| Vulnerability Management | CC7-02, CC7-03, PI1-03 |
| Vendor / Supplier Risk | CC9-03, CC9-04, CC9-05 |
| Incident Response | CC7-04 |
| Evidence and Compliance | CC7-05, PI1-05 |
| Change Management | CC8-01 through CC8-05 |

---

## 7. Review Process

This ownership matrix is reviewed:

- **Annually** as part of the governance review cycle.
- **On any organizational change** (new hire, role change, departure) that affects control ownership.
- **After any audit finding** that identifies ownership gaps.

Changes to this matrix require approval from the CTO and CyberForge Management.

---

## Revision History

| Date | Change | Author |
|------|--------|--------|
| 2026-03-15 | Initial version | CyberForge Engineering |

---

## Related Documents

- [SOC 2 Control Matrix](soc2-control-matrix.md)
- [SOC 2 System Description](soc2-system-description.md)
- [IAM Governance Policy](iam-governance.md)
- [Evidence Calendar](evidence-calendar.md)
- [Access Review Schedule](access-review-schedule.md)
- [Change Management Procedure](change-management-procedure.md)
