# Access Review Schedule

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Document Owner   | Security Lead                              |
| Approved By      | CyberForge Management                      |
| Version          | 1.0                                        |
| Effective Date   | 2026-03-15                                 |
| Parent Policy    | [IAM Governance](iam-governance.md)        |

---

## 1. Purpose

This document consolidates all recurring access review activities into a single schedule with explicit due dates, SOC 2 criterion mappings, and evidence artifact references. It provides an operational view of when each review must be completed, who is responsible, and what evidence must be produced.

For the detailed review procedure (export, distribute, review, remediate, sign-off), see [Access Review Procedure](access-review-procedure.md).

## 2. Scope

This schedule covers access reviews for all systems within the CyberForge DevSecOps Pipeline system boundary:

- GitHub organization membership, team memberships, and repository permissions.
- Azure RBAC role assignments and Azure AD/Entra ID group memberships.
- CI/CD service principals, federated credential configurations, and automation identities.
- Branch protection rules and CODEOWNERS file accuracy.

---

## 3. Review Schedule

| Review Type | Scope | Frequency | Next Due | Owner | SOC 2 Criterion | Evidence Artifact |
|---|---|---|---|---|---|---|
| Privileged: GitHub Org Owners | Organization owner list (maximum 2) | Quarterly | 2026-06-15 | Security Lead | CC6.1 | Org member export via `export-github-security-config.sh` + sign-off record |
| Privileged: Azure roles | Owner and Contributor role assignments at subscription and resource group level | Quarterly | 2026-06-15 | Security Lead | CC6.1 | RBAC export via `export-azure-rbac.sh` + sign-off record |
| Service principals | Pipeline SP role assignments, federated credential configurations, token lifetime verification | Quarterly | 2026-06-15 | DevOps Lead | CC6.1, CC6.3 | SP export + federated credential export via `export-azure-rbac.sh` + sign-off record |
| Standard: GitHub teams | All team memberships and repository access grants | Semi-annually | 2026-09-15 | Security Lead | CC6.2 | Team membership export via `export-github-security-config.sh` + sign-off record |
| Standard: Azure RBAC | All role assignments (Reader, custom roles, limited-scope roles) | Semi-annually | 2026-09-15 | Security Lead | CC6.2 | Full RBAC export via `export-azure-rbac.sh` + sign-off record |
| Branch protection | Main branch protection rules (reviewer count, signed commits, force push disabled, required status checks) | Quarterly | 2026-06-15 | DevOps Lead | CC8.1 | Branch protection config export via `export-github-security-config.sh` |
| CODEOWNERS | File accuracy -- verify listed owners match current team structure and security-sensitive paths are covered | Semi-annually | 2026-09-15 | Security Lead | CC6.1, CC8.1 | CODEOWNERS review record (PR or issue documenting the review and any changes) |

---

## 4. Upcoming Due Dates

### Q2 2026 (Due: 2026-06-15)

- [ ] Privileged: GitHub Org Owners
- [ ] Privileged: Azure roles
- [ ] Service principals
- [ ] Branch protection

### Q3 2026 (Due: 2026-09-15)

- [ ] Standard: GitHub teams
- [ ] Standard: Azure RBAC
- [ ] CODEOWNERS

### Q4 2026 (Due: 2026-12-15)

- [ ] Privileged: GitHub Org Owners
- [ ] Privileged: Azure roles
- [ ] Service principals
- [ ] Branch protection

### Q1 2027 (Due: 2027-03-15)

- [ ] Standard: GitHub teams
- [ ] Standard: Azure RBAC
- [ ] CODEOWNERS
- [ ] Privileged: GitHub Org Owners
- [ ] Privileged: Azure roles
- [ ] Service principals
- [ ] Branch protection

---

## 5. Export Scripts

The following scripts produce the access state snapshots required for each review type:

| Script | Location | Exports |
|---|---|---|
| `export-github-security-config.sh` | [scripts/export-github-security-config.sh](../../scripts/export-github-security-config.sh) | Org members, repo collaborators, team memberships, branch protection rules, MFA enforcement status |
| `export-azure-rbac.sh` | [scripts/export-azure-rbac.sh](../../scripts/export-azure-rbac.sh) | RBAC role assignments, service principal listings, federated credential configurations |

Usage:

```bash
# GitHub access export
./scripts/export-github-security-config.sh <org> <repo> ./evidence/access-review-YYYY-QN/

# Azure RBAC export
./scripts/export-azure-rbac.sh <subscription_id> ./evidence/access-review-YYYY-QN/
```

All exports are timestamped and stored in the dated evidence directory.

---

## 6. Review Completion Criteria

A review is considered complete when:

1. Access state exports have been generated and stored in the evidence directory.
2. Each access entry has been reviewed and marked as Confirmed or Flagged by the responsible reviewer.
3. All flagged items have been investigated and remediated (revoked, reduced, or justified with documentation).
4. A sign-off record has been produced, signed by the Security Lead and approved by CyberForge Management.
5. Any open action items have been logged in GitHub Issues with the `iam` label.

For the full step-by-step procedure, see [Access Review Procedure](access-review-procedure.md) Sections 4-6.

---

## 7. SLA for Review Completion

| Activity | SLA |
|---|---|
| Export generation | Within 2 business days of the review due date |
| Reviewer assessment | Within 10 business days of receiving access lists |
| Flagged item remediation | Within 5 business days of flag |
| Sign-off record completion | Within 15 business days of the review due date |

SLA timelines are defined in the [Access Review Procedure](access-review-procedure.md).

---

## 8. Ad-Hoc Reviews

In addition to scheduled reviews, ad-hoc reviews must be initiated when:

- A security incident involving unauthorized access or credential compromise occurs.
- A significant organizational change takes place (team restructuring, project scope change).
- An audit finding identifies access control weaknesses.
- A Leaver event raises concerns about residual access.

Ad-hoc reviews follow the same procedure and produce the same evidence artifacts as scheduled reviews. They are documented separately and tagged with the triggering event.

---

## 9. Compliance Mapping

| Requirement | Framework Control | How This Schedule Addresses It |
|---|---|---|
| Periodic access verification | SOC 2 CC6.1 | Quarterly privileged access reviews with evidence |
| Access provisioning review | SOC 2 CC6.2 | Semi-annual standard access reviews confirm provisioned access matches roles |
| Access modification monitoring | SOC 2 CC6.3 | Service principal reviews verify automation access remains appropriate |
| Change management verification | SOC 2 CC8.1 | Branch protection and CODEOWNERS reviews verify change controls |
| Identity management | ISO 27001 A.8.2 | Scheduled reviews verify identity lifecycle compliance |
| ICT risk management | DORA Art.16.1.a | Regular access reviews detect and remediate access drift |
| Access control | NIS2 Art.21.2.i | Least privilege verified through recurring reviews |

---

## Revision History

| Date | Change | Author |
|------|--------|--------|
| 2026-03-15 | Initial version | CyberForge Engineering |

---

## Related Documents

- [IAM Governance Policy](iam-governance.md)
- [Access Review Procedure](access-review-procedure.md)
- [JML Process](jml-process.md)
- [Evidence Calendar](evidence-calendar.md)
- [Control Owners](control-owners.md)
- [GitHub Security Config Export Script](../../scripts/export-github-security-config.sh)
- [Azure RBAC Export Script](../../scripts/export-azure-rbac.sh)
