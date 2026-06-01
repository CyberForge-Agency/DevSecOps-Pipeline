# Risk Acceptance Process

**Document Owner:** Security Lead
**Last Reviewed:** 2026-03-15
**Review Cadence:** Annually, or after any major incident involving an accepted risk
**Version:** 1.0

## 1. Purpose

This document defines the process for formally accepting security risks when a vulnerability cannot be remediated within the SLA, when a finding is confirmed as a false positive requiring permanent suppression, or when a business decision is made to accept a known risk with compensating controls.

Risk acceptance is not a bypass mechanism. It is a governance control that ensures every deviation from remediation standards is documented, justified, approved, time-limited, and auditable.

## 2. When Risk Acceptance Applies

A risk acceptance is required in the following situations:

| Situation | Example |
|-----------|---------|
| Vulnerability cannot be fixed within SLA | No upstream patch available; dependency migration required |
| False positive requiring permanent suppression | Trivy flags a CVE that does not apply to the component's usage |
| Business risk accepted with compensating controls | Legacy component cannot be updated without breaking changes; network segmentation applied instead |
| Pipeline gate suppression | Adding a CVE to `app/.trivyignore` to unblock the build |

Risk acceptance is **never** appropriate for:

- Vulnerabilities with known active exploitation and no compensating controls
- Findings that can be trivially remediated within the SLA
- Suppressing findings to meet a deployment deadline without documented justification

## 3. Required Fields

Every risk acceptance record must include the following fields:

| Field | Description | Requirement |
|-------|-------------|-------------|
| **Vulnerability ID** | CVE identifier or tool-specific finding ID (e.g., CVE-2024-12345, CodeQL finding ID, ZAP alert ID) | Required |
| **Affected Component** | The specific package, image, file, or infrastructure resource affected | Required |
| **Severity** | Critical, High, Medium, or Low (per the Vulnerability Management Policy) | Required |
| **Risk Owner** | Named individual who owns the risk and is accountable for monitoring it | Required |
| **Approver** | Named individual who approves the acceptance; must be different from the risk owner; minimum authority: CTO or security lead | Required |
| **Business Justification** | Clear explanation of why remediation is not feasible within the SLA and why the risk is acceptable | Required |
| **Compensating Controls** | Specific technical or procedural measures that reduce the residual risk (e.g., WAF rule, network segmentation, monitoring alert, restricted access) | Required |
| **Expiry Date** | Date by which the acceptance expires and must be re-reviewed; maximum 12 months from approval date | Required |
| **Status** | One of: **Active**, **Expired**, **Remediated** | Required |

## 4. Process

### 4.1 Submission

1. The risk owner creates a GitHub Issue using the **Risk Acceptance Request** issue template (`.github/ISSUE_TEMPLATE/risk-acceptance.yml`).
2. The issue must be filled out completely. Incomplete submissions will be returned for additional information.
3. The issue is automatically labeled `risk-acceptance` and `security`.

### 4.2 Review and Approval

1. The designated approver (CTO or security lead, different from the risk owner) reviews the submission.
2. The approver evaluates:
   - Whether remediation is genuinely infeasible within the SLA.
   - Whether the compensating controls are adequate to reduce residual risk to an acceptable level.
   - Whether the expiry date is appropriate (no longer than 12 months).
3. Approval is recorded as a comment on the GitHub Issue, including the approver's explicit statement of approval, the approved expiry date, and any conditions.
4. The issue is labeled `approved` upon acceptance.

### 4.3 Rejection

If the approver determines the risk acceptance is not justified:

1. The approver comments with the reason for rejection.
2. The issue is labeled `rejected`.
3. The vulnerability must be remediated within the original SLA, or a revised risk acceptance must be submitted addressing the approver's concerns.

### 4.4 Activation

Once approved:

1. The risk owner adds the entry to the [Exception Register](../compliance/exception-register.md).
2. If the acceptance involves a `.trivyignore` entry, the corresponding line in `app/.trivyignore` must include a VEX comment referencing the approved GitHub Issue number:

```
# VEX: not_affected - Component not reachable in our configuration
# Risk Acceptance: https://github.com/<org>/<repo>/issues/<number>
CVE-2024-XXXXX
```

3. The compensating controls must be implemented and verified before the accepted vulnerability is suppressed in the pipeline.

## 5. Expiry and Re-review

- All risk acceptances have a maximum duration of **12 months**.
- The security lead reviews all Active entries **quarterly** to determine whether:
  - A fix has become available and the vulnerability should be remediated.
  - The compensating controls remain effective.
  - The risk context has changed (e.g., new threat intelligence, increased exposure).
- At expiry, the risk acceptance **must** be one of:
  - **Remediated:** The vulnerability has been fixed. Status updated to `Remediated`. The `.trivyignore` entry (if any) is removed.
  - **Renewed:** A new risk acceptance request is submitted with updated justification and a new expiry date. The original issue is closed and the new issue is cross-referenced.
  - **Escalated:** If neither remediation nor renewal is appropriate, the matter is escalated to the CTO for a decision.
- Expired risk acceptances that are not renewed or remediated are treated as SLA violations.

## 6. Link to .trivyignore

The `app/.trivyignore` file is the mechanism by which Trivy SCA scan findings are suppressed in the pipeline. The following rules apply:

- Every entry in `.trivyignore` **must** reference an approved risk acceptance GitHub Issue number in a comment above it.
- Entries without an associated approved risk acceptance are non-compliant and must be remediated or have a risk acceptance submitted.
- The `.trivyignore` file is subject to code review via the standard pull request process. Reviewers must verify the referenced risk acceptance issue exists and is in `approved` status.
- During quarterly reviews, the security lead cross-references `.trivyignore` entries against the Exception Register to identify stale or expired entries.

## 7. Audit Trail

All risk acceptance activity is captured in the GitHub Issue history, providing a complete audit trail:

- Submission timestamp and submitter identity
- Approval or rejection comments with approver identity
- Any modifications to compensating controls or expiry dates
- Status transitions (Active, Expired, Remediated)
- Cross-references to related pull requests (e.g., `.trivyignore` changes)

This audit trail is preserved in the repository and is available for internal audits, management reviews, and external compliance assessments.

## 8. Compliance Mapping

| Requirement | Framework Reference |
|-------------|---------------------|
| ICT risk management framework and risk controls | DORA Art.16.1.a |
| Risk treatment planning and risk acceptance | ISO 27001 Clause 6 (Clause 6.1.2 - Risk Treatment) |
| Risk assessment and mitigation | SOC 2 CC3.2 |

## 9. Related Documents

- [Vulnerability Management Policy](./vulnerability-management-policy.md)
- [Vulnerability Disclosure Policy](./vulnerability-disclosure-policy.md)
- [Exception Register](../compliance/exception-register.md)
- `.github/ISSUE_TEMPLATE/risk-acceptance.yml`
- `app/.trivyignore`
