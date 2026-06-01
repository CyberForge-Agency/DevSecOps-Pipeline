# Joiner / Mover / Leaver (JML) Process

| Field            | Value                          |
|------------------|--------------------------------|
| Document Owner   | Security Lead                  |
| Approved By      | CyberForge Management          |
| Version          | 1.0                            |
| Effective Date   | 2026-03-15                     |
| Parent Policy    | [IAM Governance](iam-governance.md) |

---

## 1. Purpose

This document defines the process for managing the identity lifecycle of all personnel who access CyberForge pipeline systems. It covers onboarding (Joiner), internal role changes (Mover), and offboarding (Leaver) to ensure that access is granted, modified, and revoked in a controlled, auditable, and timely manner.

## 2. Scope

This process applies to:

- GitHub organization membership and repository/team access.
- Azure AD/Entra ID accounts and Azure RBAC role assignments.
- Any external tooling accounts associated with the CyberForge pipeline (monitoring, logging, artifact registries).

It covers all identity types defined in the [IAM Governance Policy](iam-governance.md): developers, security team members, management, and external identities (auditors, contractors).

---

## 3. Joiner (Onboarding)

### Trigger

A new team member joins the CyberForge project, or an external party (auditor, contractor) requires access.

### Process

| Step | Action | Responsible | Details |
|------|--------|-------------|---------|
| 1 | Submit access request | Requesting Manager | Create a GitHub Issue with the `iam` label, or submit via internal access request form. Include: person's name, role, team, required access, business justification. |
| 2 | Approve request | Security Lead | Review the request against the role definition in [IAM Governance](iam-governance.md). Verify that requested access follows least privilege. Approve or request modification. |
| 3 | Provision GitHub access | Security Lead / Admin | Add user to the GitHub organization. Assign to the appropriate team(s). Team membership grants repository access per the team-based model. |
| 4 | Provision Azure access | Security Lead / Admin | Create or invite Azure AD/Entra ID account. Assign RBAC roles scoped to the minimum required resources per [IAM Governance](iam-governance.md) Section 6.2. |
| 5 | Verify MFA enrollment | Security Lead | Confirm that the user has enrolled in MFA on both GitHub and Azure before granting production or sensitive access. No access to protected resources until MFA is verified. |
| 6 | Record access confirmation | Security Lead | Document the provisioned access: screenshot of team membership, API export of role assignments, or equivalent evidence. Attach to the access request issue. |
| 7 | Notify requester | Security Lead | Close the access request issue with confirmation. Notify the new team member of their access and any onboarding documentation. |

### SLA

Complete all provisioning steps within **2 business days** of an approved request.

### Required Documentation

Each Joiner request must include:

- Full name and contact email of the person.
- Role title and team assignment.
- Specific access required (GitHub teams, Azure RBAC roles).
- Business justification for the access.
- Approver name and approval date.

---

## 4. Mover (Role Change)

### Trigger

An existing team member changes role, team, or project within CyberForge.

### Process

| Step | Action | Responsible | Details |
|------|--------|-------------|---------|
| 1 | Notify of role change | Current/New Manager | Inform the Security Lead of the role change, including the new role, team, and effective date. Create a GitHub Issue with the `iam` label. |
| 2 | Review current access | Security Lead | Export and review the person's current GitHub team memberships and Azure RBAC role assignments. Compare against the new role requirements. |
| 3 | Remove excess access | Security Lead / Admin | Remove GitHub team memberships and Azure RBAC roles that are no longer required for the new role. Apply the principle of least privilege. |
| 4 | Grant new access | Security Lead / Admin | Provision any additional access required for the new role. Follow the same approval flow as the Joiner process (Step 2 above). |
| 5 | Record changes | Security Lead | Document all access changes (removed and added) in the GitHub Issue. Attach before/after evidence (API exports or screenshots). |

### SLA

Complete all access modifications within **3 business days** of notification.

### Key Principle

A Mover event is not simply additive. Access from the previous role that is not required for the new role **must be removed**. This prevents privilege accumulation over time.

---

## 5. Leaver (Offboarding)

### Trigger

A team member leaves the CyberForge project or organization, or an external engagement ends.

### Process

| Step | Action | Responsible | Details |
|------|--------|-------------|---------|
| 1 | Notify Security Lead | Departing person's Manager | Notify the Security Lead of the departure, ideally **before** the person's last working day. Create a GitHub Issue with the `iam` label. |
| 2 | Revoke GitHub access | Security Lead / Admin | Remove the person from the GitHub organization. This automatically removes all repository and team access. Verify removal via API. |
| 3 | Disable Azure AD account | Security Lead / Admin | Disable (and subsequently delete) the person's Azure AD/Entra ID account. This revokes all Azure RBAC access and SSO sessions. |
| 4 | Rotate shared secrets | Security Lead | Verify whether the person had access to any shared secrets. With OIDC federation this should be none, but confirm. Rotate any secrets the person could have accessed. |
| 5 | Remove external tool access | Security Lead / Admin | Remove the person from any external tools, monitoring dashboards, artifact registries, or communication channels. |
| 6 | Verify complete revocation | Security Lead | Run access export scripts ([export-github-security-config.sh](../../scripts/export-github-security-config.sh), [export-azure-rbac.sh](../../scripts/export-azure-rbac.sh)) to confirm the person no longer appears in any access lists. Attach evidence to the issue. |

### SLA

| Leaver Type                  | Revocation SLA           |
|------------------------------|--------------------------|
| Standard departure           | Within **48 hours** of last working day |
| Critical (sensitive role)    | Within **24 hours** of last working day |
| Emergency (termination for cause) | **Immediate** revocation upon notification |

### Emergency Leaver Procedure

For terminations with cause or suspected security compromise:

1. Security Lead is notified immediately (phone/direct message, not email alone).
2. GitHub organization membership is revoked within minutes.
3. Azure AD account is disabled within minutes.
4. Active sessions are terminated where possible (Azure AD: revoke sign-in sessions).
5. Incident review is conducted to determine if any unauthorized actions occurred during the notice period.

---

## 6. Audit Trail

All JML actions are tracked to provide a complete audit trail for compliance evidence.

### Tracking Method

- **Primary**: GitHub Issues with the `iam` label in the CyberForge repository.
- **Alternative**: Equivalent entries in an internal ticketing system, linked to the GitHub Issue for traceability.

### Required Records

Each JML issue must contain:

| Field                | Description                                          |
|----------------------|------------------------------------------------------|
| Request date         | When the JML action was requested                    |
| Requester            | Manager or person who initiated the request          |
| Approver             | Security Lead or delegate who approved               |
| Action type          | Joiner, Mover, or Leaver                             |
| Person affected      | Name and email of the person                         |
| Access granted/removed | Specific teams, roles, and systems affected         |
| Completion date      | When all provisioning/deprovisioning was completed   |
| Evidence             | API exports, screenshots, or links to access reports |

### Retention

JML records are retained for a minimum of **3 years** to support audit and compliance requirements across all applicable frameworks (DORA, NIS2, ISO 27001, SOC 2).

---

## 7. Compliance Mapping

| Requirement         | Framework Control   | How This Process Addresses It                     |
|---------------------|---------------------|---------------------------------------------------|
| Identity management | ISO 27001 A.8.2     | Formal onboarding/offboarding with approval flow  |
| Access provisioning | SOC 2 CC6.2         | Documented request, approval, and provisioning    |
| Access modification | SOC 2 CC6.3         | Mover process ensures access is reviewed on change |
| Access revocation   | ISO 27001 A.8.2     | Leaver process with defined SLAs                   |
| ICT risk management | DORA Art.16.1.a     | Controlled identity lifecycle reduces access risk  |
| Access control      | NIS2 Art.21.2.i     | Least privilege enforced at every lifecycle stage  |

---

## Related Documents

- [IAM Governance Policy](iam-governance.md)
- [Access Review Procedure](access-review-procedure.md)
- [GitHub Security Config Export](../../scripts/export-github-security-config.sh)
- [Azure RBAC Export](../../scripts/export-azure-rbac.sh)
