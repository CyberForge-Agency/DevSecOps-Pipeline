# Access Review Procedure

| Field            | Value                          |
|------------------|--------------------------------|
| Document Owner   | Security Lead                  |
| Approved By      | CyberForge Management          |
| Version          | 1.0                            |
| Effective Date   | 2026-03-15                     |
| Parent Policy    | [IAM Governance](iam-governance.md) |

---

## 1. Purpose

This procedure defines how CyberForge periodically verifies that all access grants remain appropriate, follow the principle of least privilege, and align with current role assignments. Access reviews are a key detective control that identifies stale, excessive, or unauthorized access before it can be exploited.

## 2. Scope

This procedure covers access reviews for:

- **GitHub organization** -- organization membership, repository permissions, team memberships.
- **Azure subscription** -- RBAC role assignments, Azure AD/Entra ID group memberships.
- **CI/CD service principals** -- role assignments, federated credential configurations, token lifetimes.

## 3. Review Schedule

| Review Type         | Frequency      | Scope                                                                                      | Reviewer       |
|---------------------|----------------|--------------------------------------------------------------------------------------------|----------------|
| Privileged Access   | Quarterly      | GitHub Org Owners, Azure Subscription Owners/Contributors, service principal role assignments | Security Lead  |
| Standard Access     | Semi-annually  | GitHub team memberships, Azure Reader/limited roles                                        | Team Leads     |
| Ad-hoc              | As needed      | Any scope, triggered by specific events                                                     | Security Lead  |

### Ad-hoc Review Triggers

An ad-hoc access review must be initiated when:

- A security incident involving unauthorized access or credential compromise occurs.
- A significant organizational change takes place (team restructuring, project scope change).
- An audit finding identifies access control weaknesses.
- A Leaver event raises concerns about residual access.

## 4. Review Process

### Step 1: Export Current Access State

Run the access export scripts to generate current-state snapshots:

```bash
# Export GitHub security configuration
./scripts/export-github-security-config.sh <org> <repo> ./evidence/access-review-YYYY-QN/

# Export Azure RBAC configuration
./scripts/export-azure-rbac.sh <subscription_id> ./evidence/access-review-YYYY-QN/
```

Scripts:
- [export-github-security-config.sh](../../scripts/export-github-security-config.sh) -- exports org members, repo collaborators, teams, branch protection, and MFA enforcement status.
- [export-azure-rbac.sh](../../scripts/export-azure-rbac.sh) -- exports RBAC role assignments, service principals, and federated credentials.

All exports are timestamped and stored in a dated evidence directory.

### Step 2: Distribute Access Lists

The Security Lead distributes the exported access lists to the responsible reviewers:

| Access Type                    | Distributed To       |
|--------------------------------|----------------------|
| GitHub Org Owner list          | CyberForge Management |
| GitHub team memberships        | Respective Team Leads |
| Azure privileged roles         | CyberForge Management |
| Azure standard roles           | Respective Team Leads |
| Service principal assignments  | Security Lead (self-review with management approval) |

Distribution is via a secure internal channel (not unencrypted email for privileged access lists).

### Step 3: Manager/Lead Review

Each reviewer examines the access list for their area of responsibility and confirms or flags each entry:

| Decision   | Meaning                                                        |
|------------|----------------------------------------------------------------|
| Confirmed  | Access is appropriate for the person's current role and duties |
| Flagged    | Access may be excessive, stale, or unjustified -- requires investigation |

Reviewers must complete their assessment within **10 business days** of receiving the access list.

### Step 4: Investigate and Remediate Flagged Access

For each flagged entry:

1. Security Lead contacts the person and their manager to determine if the access is still required.
2. If the access is no longer justified, it is revoked immediately.
3. If the access is justified but was not previously documented, a justification record is created.
4. If the access level is higher than required, it is reduced to the minimum necessary level.

Remediation must be completed within **5 business days** of the flag being raised.

### Step 5: Document Results and Sign-Off

The Security Lead compiles the review results into a summary report containing:

- Review period and date of completion.
- Total number of identities reviewed (by category).
- Number of access grants confirmed vs. flagged.
- Actions taken for each flagged item (revoked, reduced, justified, or pending).
- Any systemic findings or recommendations.

The summary report is signed off by:
- The Security Lead (as review coordinator).
- CyberForge Management (as final approver).

### Step 6: Track Action Items

Any unresolved findings from the review are tracked as action items:

| Field            | Description                                     |
|------------------|-------------------------------------------------|
| Finding          | Description of the access issue                 |
| Affected Identity | Person or service account involved              |
| Required Action  | Revoke, reduce, justify, or investigate further |
| Owner            | Person responsible for resolution               |
| Deadline         | Date by which the action must be completed      |
| Status           | Open, In Progress, Resolved                     |

Action items are tracked via GitHub Issues with the `iam` label or an equivalent tracking system. Open items from previous reviews are checked at the start of each new review cycle.

## 5. Evidence Artifacts

Each access review cycle produces the following evidence artifacts:

| Artifact                                  | Format          | Source Script / Method                      |
|-------------------------------------------|-----------------|---------------------------------------------|
| GitHub org/repo/team membership export    | JSON            | `export-github-security-config.sh`          |
| GitHub MFA enforcement status             | JSON            | `export-github-security-config.sh`          |
| GitHub branch protection configuration    | JSON            | `export-github-security-config.sh`          |
| Azure RBAC role assignment export         | JSON            | `export-azure-rbac.sh`                      |
| Service principal credential listing      | JSON            | `export-azure-rbac.sh`                      |
| Federated credential configuration        | JSON            | `export-azure-rbac.sh`                      |
| Reviewer sign-off record                  | PDF / Markdown  | Manual (compiled by Security Lead)          |
| Action items and resolution log           | Issue history   | GitHub Issues with `iam` label              |

All evidence artifacts are stored in the evidence pack directory and/or the governance archive with a retention period of at least **3 years**.

For the full catalog of evidence types, see [Access Review Evidence Catalog](../compliance/access-review-evidence-catalog.md).

## 6. Roles and Responsibilities

| Role                  | Responsibility                                                    |
|-----------------------|-------------------------------------------------------------------|
| Security Lead         | Coordinate reviews, run export scripts, compile results, track findings |
| Team Leads / Managers | Review access lists for their teams, confirm or flag entries      |
| CyberForge Management | Final sign-off on review results, approve privileged access       |
| All Personnel         | Respond promptly to access review inquiries                       |

## 7. Compliance Mapping

| Requirement         | Framework Control   | How This Procedure Addresses It                         |
|---------------------|---------------------|---------------------------------------------------------|
| ICT risk management | DORA Art.16.1.a     | Periodic review detects and remediates access drift     |
| Access control      | NIS2 Art.21.2.i     | Verifies least privilege is maintained over time        |
| Identity management | ISO 27001 A.8.2     | Formal review of all identity access grants             |
| Logical access      | SOC 2 CC6.1         | Evidence of periodic access verification                |
| Access provisioning | SOC 2 CC6.2         | Review confirms provisioned access matches approved roles |

---

## Related Documents

- [IAM Governance Policy](iam-governance.md)
- [JML Process](jml-process.md)
- [Access Review Evidence Catalog](../compliance/access-review-evidence-catalog.md)
- [GitHub Security Config Export Script](../../scripts/export-github-security-config.sh)
- [Azure RBAC Export Script](../../scripts/export-azure-rbac.sh)
