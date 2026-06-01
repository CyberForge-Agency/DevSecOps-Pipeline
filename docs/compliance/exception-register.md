# Security Exception Register

**Document Owner:** Security Lead
**Last Reviewed:** 2026-03-15
**Review Cadence:** Quarterly (all Active entries), plus ad-hoc upon new approvals
**Version:** 1.0

## Purpose

This is the master register of all accepted security exceptions in the CyberForge DevSecOps Pipeline project. Every approved risk acceptance is recorded here to provide a single point of reference for audits, management reviews, and compliance assessments.

## Instructions

- **Adding entries:** Add a new row when a risk acceptance request is approved via the GitHub Issue process defined in the [Risk Acceptance Process](../governance/risk-acceptance-process.md).
- **Quarterly review:** Review all entries with `Active` status quarterly. Verify that compensating controls remain effective, the risk context has not changed, and expiry dates are not approaching without a remediation or renewal plan.
- **Expired entries:** Entries that reach their expiry date must be re-evaluated. Update the status to `Remediated` if the vulnerability has been fixed, or submit a new risk acceptance request if continued acceptance is justified.
- **Audit readiness:** Each entry links to a GitHub Issue containing the full approval history, compensating controls, and audit trail.

## Exception Register

| ID | Vuln ID | Component | Severity | Owner | Approver | Justification | Compensating Controls | Approved Date | Expiry Date | Status | Issue Link |
|----|---------|-----------|----------|-------|----------|---------------|-----------------------|---------------|-------------|--------|------------|
| EXC-001 | CVE-2024-99999 | lodash@4.17.20 in app/package.json | Medium | Jan Kowalski | Anna Nowak (CTO) | No upstream patch available; lodash prototype pollution path not reachable in application code due to input validation layer | Input validation middleware blocks all user-controlled object key injection; WAF rule OWASP-CRS-944-130 active; monitoring alert configured for prototype pollution patterns | 2026-03-15 | 2026-09-15 | Active | [#42](https://github.com/cyberforge/pipeline/issues/42) |

> **Note:** The entry above (EXC-001) is an illustrative example to demonstrate the required format. Replace or remove it when recording actual risk acceptances.

## Status Definitions

| Status | Meaning |
|--------|---------|
| **Active** | Risk acceptance is currently in effect. Compensating controls must be maintained. |
| **Expired** | Expiry date has passed. Entry must be re-evaluated: remediate, renew, or escalate. |
| **Remediated** | The underlying vulnerability has been fixed. The risk acceptance is no longer needed. |

## Compliance Mapping

| Requirement | Framework Reference |
|-------------|---------------------|
| ICT risk management framework | DORA Art.16.1.a |
| Risk treatment planning | ISO 27001 Clause 6.1.2 |
| Risk assessment and mitigation | SOC 2 CC3.2 |

## Related Documents

- [Risk Acceptance Process](../governance/risk-acceptance-process.md)
- [Vulnerability Management Policy](../governance/vulnerability-management-policy.md)
- [Vulnerability Disclosure Policy](../governance/vulnerability-disclosure-policy.md)
- `app/.trivyignore`
