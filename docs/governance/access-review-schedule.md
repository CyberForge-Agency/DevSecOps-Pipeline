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
| Privileged: GitHub Org Owners | Organization owner list (maximum 2) | Quarterly | 2026-09-16 | Security Lead | CC6.1 | Org member export via `export-github-security-config.sh` + sign-off record |
| Privileged: Azure roles | Owner and Contributor role assignments at subscription and resource group level | Quarterly | 2026-09-16 | Security Lead | CC6.1 | RBAC export via `export-azure-rbac.sh` + sign-off record |
| Service principals | Pipeline SP role assignments, federated credential configurations, token lifetime verification | Quarterly | 2026-09-16 | DevOps Lead | CC6.1, CC6.3 | SP export + federated credential export via `export-azure-rbac.sh` + sign-off record |
| Standard: GitHub teams | All team memberships and repository access grants | Semi-annually | 2026-09-15 | Security Lead | CC6.2 | Team membership export via `export-github-security-config.sh` + sign-off record |
| Standard: Azure RBAC | All role assignments (Reader, custom roles, limited-scope roles) | Semi-annually | 2026-09-15 | Security Lead | CC6.2 | Full RBAC export via `export-azure-rbac.sh` + sign-off record |
| Branch protection | Main branch protection rules (reviewer count, signed commits, force push disabled, required status checks) | Quarterly | 2026-09-16 | DevOps Lead | CC8.1 | Branch protection config export via `export-github-security-config.sh` |
| CODEOWNERS | File accuracy -- verify listed owners match current team structure and security-sensitive paths are covered | Semi-annually | 2026-09-15 | Security Lead | CC6.1, CC8.1 | CODEOWNERS review record (PR or issue documenting the review and any changes) |

---

## 4. Upcoming Due Dates

### Q2 2026 (Due: 2026-06-15) -- COMPLETED 2026-06-16

- [x] Privileged: GitHub Org Owners -- reviewed 2026-06-16 (see Section 4a log)
- [x] Privileged: Azure roles -- reviewed 2026-06-16 (GitHub-side verified; Azure RBAC export pending portal access, see log)
- [x] Service principals -- reviewed 2026-06-16 (federated-credential config in deploy.yml verified; SP export pending portal access, see log)
- [x] Branch protection -- reviewed 2026-06-16 (gap identified: native enforcement unavailable on current plan, see log)

### Q3 2026 (Due: 2026-09-15 / privileged & branch protection re-cert 2026-09-16)

- [ ] Standard: GitHub teams
- [ ] Standard: Azure RBAC
- [ ] CODEOWNERS
- [ ] Privileged: GitHub Org Owners (next quarterly re-cert)
- [ ] Privileged: Azure roles (next quarterly re-cert)
- [ ] Service principals (next quarterly re-cert)
- [ ] Branch protection (next quarterly re-cert)

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

## 4a. Access Review Log

This log records completed access reviews. Each entry captures the review date,
reviewer, what was inspected (with verified facts), findings, and the resulting
sign-off. It is the execution-truth companion to the cadence schedule in Section 3:
the schedule proves reviews are in-cycle; this log proves they were performed.

### 2026-06-16 -- Q2 2026 Privileged Access & Branch Protection Review

| Field            | Value                                                        |
|------------------|--------------------------------------------------------------|
| Review period    | Q2 2026 (cycle due 2026-06-15)                               |
| Date completed   | 2026-06-16                                                   |
| Reviewer         | Security Lead (Szymon Mytych)                                |
| Final approver   | CyberForge Management (Szymon Mytych) -- countersignature pending |
| Scope            | GitHub repo access, GitHub org owners, branch protection, Azure RBAC / service principals (GitHub-verifiable portion) |
| Method           | Read-only GitHub API queries (`gh api`) against `Xornee/CyberForge-Priv`; commit-signature inspection (`git log --format=%G?`); workflow OIDC config inspection (`deploy.yml`) |

**Identities reviewed (GitHub, verified via `gh api repos/Xornee/CyberForge-Priv/collaborators`):**

| Principal | Type | Access | Justification | Verdict |
|---|---|---|---|---|
| `Xornee` (Szymon Mytych) | Human / founder | Repo **admin** (full control); GitHub account owner | Founder, Security Lead + CTO dual-role per [control-owners.md](control-owners.md) S.4 | Confirmed -- least-privilege appropriate (sole owner of a 2-person startup) |
| `stormy0012` | Human / founder | Repo **write** (push, no admin) | Second founder; write needed for day-to-day commits; admin intentionally withheld (separation of duties) | Confirmed -- correctly scoped below admin |

**Azure access (federated OIDC, verified via `deploy.yml`):** Pipeline authenticates to
Azure via GitHub OIDC federated credentials (`vars.AZURE_CLIENT_ID` / `AZURE_TENANT_ID`
/ `AZURE_SUBSCRIPTION_ID`, `deploy.yml:60-64,226-297`) -- no long-lived SP secrets stored
in repo (verified: `gh api .../actions/secrets` returns zero secrets). The RBAC role
assignments and SP federated-credential subject conditions on the Azure side were NOT
re-certified in this cycle because that requires Azure portal / `az` access, which is out
of scope for this reviewer. **Action item AR-2026Q2-01** (below) tracks the Azure-side
re-certification for a reviewer with portal access.

**Findings:**

1. **FINDING (Medium) -- Branch protection not natively enforced.** `gh api
   repos/Xornee/CyberForge-Priv/branches/main/protection` returns HTTP 403 ("Upgrade to
   GitHub Pro or make this repository public to enable this feature"). The protections
   documented in Section 3 (required reviewers, signed commits, force-push disabled,
   required status checks) are therefore NOT technically enforced on the current private/
   free plan. Compensating control: the 2-founder team operates a manual two-reviewer PR
   convention ([control-owners.md](control-owners.md) S.4). Tracked as **AR-2026Q2-02**.
2. **FINDING (Low) -- Commits to `main` are not signed.** `git log --format=%G?`
   over recent history shows no `G` (good-signature) commits. The "signed commits"
   control in Section 3 is aspirational until commit signing is configured. Tracked as
   **AR-2026Q2-03**.
3. No unexpected collaborators, no stale/leaver access, no over-privileged grants found.
   Access matches the documented 2-person ownership model.

**Action items (also tracked via GitHub Issues, `iam` label):**

| ID | Finding | Required action | Owner | Deadline | Status |
|---|---|---|---|---|---|
| AR-2026Q2-01 | Azure RBAC / SP not re-certified (no portal access this cycle) | Re-certify Owner/Contributor assignments + federated-credential subject conditions in Azure portal | DevOps Lead | 2026-09-16 | Open |
| AR-2026Q2-02 | Branch protection not natively enforced (free plan) | Enable native branch protection (upgrade plan or make repo public) OR formally accept risk with the manual 2-reviewer compensating control | DevOps Lead | 2026-09-16 | Open |
| AR-2026Q2-03 | Commits to `main` not signed | Configure and enforce commit signing for both founders | Security Lead | 2026-09-16 | Open |

**Sign-off:** Reviewed and confirmed by the Security Lead on 2026-06-16. The GitHub-side
access state is correct and least-privilege for a 2-person startup. Open items above are
tracked to the next quarterly cycle (2026-09-16). **Management countersignature required:
Szymon (CyberForge Management) must confirm acceptance of findings AR-2026Q2-02 and
AR-2026Q2-03 (or fund remediation) to close this review per Section 6 criterion 4.**

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
| 2026-06-16 | Performed Q2 2026 privileged access & branch-protection review; added Section 4a access-review log; advanced quarterly `Next Due` to 2026-09-16 | Security Lead (Szymon Mytych) |

---

## Related Documents

- [IAM Governance Policy](iam-governance.md)
- [Access Review Procedure](access-review-procedure.md)
- [JML Process](jml-process.md)
- [Evidence Calendar](evidence-calendar.md)
- [Control Owners](control-owners.md)
- [GitHub Security Config Export Script](../../scripts/export-github-security-config.sh)
- [Azure RBAC Export Script](../../scripts/export-azure-rbac.sh)
