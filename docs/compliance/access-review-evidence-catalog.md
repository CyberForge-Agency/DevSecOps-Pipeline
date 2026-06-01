# Access Review Evidence Catalog

| Field            | Value                          |
|------------------|--------------------------------|
| Document Owner   | Security Lead                  |
| Version          | 1.0                            |
| Effective Date   | 2026-03-15                     |
| Parent Documents | [IAM Governance](../governance/iam-governance.md), [Access Review Procedure](../governance/access-review-procedure.md) |

---

## 1. Purpose

This catalog provides a comprehensive inventory of all evidence artifacts produced by access review activities. It defines the source, format, collection method, frequency, storage location, and compliance use for each evidence type. Auditors and compliance reviewers can use this catalog to locate and verify access control evidence.

## 2. Evidence Catalog

| Evidence Type | Source | Format | Collection Method | Frequency | Storage | Compliance Use |
|---|---|---|---|---|---|---|
| GitHub org membership | GitHub API | JSON | `export-github-security-config.sh` | Quarterly | Evidence Pack / governance archive | SOC 2 CC6.1, ISO 27001 A.8.2 |
| GitHub repo permissions | GitHub API | JSON | `export-github-security-config.sh` | Quarterly | Evidence Pack / governance archive | SOC 2 CC6.1, ISO 27001 A.8.4 |
| GitHub team memberships | GitHub API | JSON | `export-github-security-config.sh` | Quarterly | Evidence Pack / governance archive | ISO 27001 A.8.2 |
| GitHub branch protection status | GitHub API | JSON | `export-github-security-config.sh` | Quarterly | Evidence Pack / governance archive | SOC 2 CC8.1, ISO 27001 A.8.4 |
| GitHub MFA enforcement | GitHub API | JSON | `export-github-security-config.sh` | Quarterly | Evidence Pack / governance archive | NIS2 Art.21.2.j, SOC 2 CC6.1 |
| Azure RBAC role assignments | Azure CLI | JSON | `export-azure-rbac.sh` | Quarterly | Evidence Pack / governance archive | SOC 2 CC6.1, ISO 27001 A.8.2 |
| Azure service principal credentials | Azure CLI | JSON | `export-azure-rbac.sh` | Quarterly | Evidence Pack / governance archive | DORA Art.16.1.a |
| Azure AD conditional access policies | Azure Portal / CLI | JSON / Screenshot | Manual export | Semi-annually | Governance archive | NIS2 Art.21.2.j |
| Access review sign-off | Internal | PDF / Markdown | Manual | Per review cycle | Governance archive | All frameworks |
| JML action log | GitHub Issues | Issue history | Automated | Continuous | GitHub | ISO 27001 A.8.2, SOC 2 CC6.2 |

## 3. Evidence Details

### 3.1 GitHub Org Membership

- **What it proves**: Complete list of all users with access to the GitHub organization, including their role (Owner, Member).
- **Collection**: `export-github-security-config.sh` calls `gh api orgs/{org}/members --paginate` and saves the result.
- **Key fields**: login, role, two_factor_enabled.
- **Compliance value**: Demonstrates that organizational access is inventoried and reviewable.

### 3.2 GitHub Repo Permissions

- **What it proves**: All collaborators who have access to the repository and their permission level (Admin, Write, Read).
- **Collection**: `export-github-security-config.sh` calls `gh api repos/{org}/{repo}/collaborators --paginate`.
- **Key fields**: login, permissions (admin, push, pull).
- **Compliance value**: Verifies that repository access follows least privilege and team-based assignment.

### 3.3 GitHub Team Memberships

- **What it proves**: Team structure and membership, which is the primary access control mechanism.
- **Collection**: `export-github-security-config.sh` enumerates teams and their members via the GitHub API.
- **Key fields**: team name, team slug, member logins, member role (maintainer, member).
- **Compliance value**: Confirms that access is managed through defined groups rather than ad-hoc individual grants.

### 3.4 GitHub Branch Protection Status

- **What it proves**: Branch protection rules are active and enforced (required reviewers, signed commits, no force push).
- **Collection**: `export-github-security-config.sh` calls `gh api repos/{org}/{repo}/branches/main/protection`.
- **Key fields**: required_pull_request_reviews, required_signatures, enforce_admins, restrictions.
- **Compliance value**: Demonstrates change management controls on the main branch.

### 3.5 GitHub MFA Enforcement

- **What it proves**: The organization requires MFA for all members.
- **Collection**: `export-github-security-config.sh` calls `gh api orgs/{org}` and extracts `two_factor_requirement_enabled`.
- **Key fields**: two_factor_requirement_enabled (boolean).
- **Compliance value**: Proves authentication strength requirement is enforced at the organizational level.

### 3.6 Azure RBAC Role Assignments

- **What it proves**: All role assignments within the Azure subscription, showing who has what level of access to which resources.
- **Collection**: `export-azure-rbac.sh` calls `az role assignment list --all`.
- **Key fields**: principalName, roleDefinitionName, scope.
- **Compliance value**: Demonstrates that Azure access follows RBAC and can be reviewed against documented role definitions.

### 3.7 Azure Service Principal Credentials

- **What it proves**: Service principals used by the pipeline, their credential type (federated vs. secret), and expiration.
- **Collection**: `export-azure-rbac.sh` lists service principals and their federated credentials.
- **Key fields**: displayName, servicePrincipalType, keyCredentials, federatedCredentials.
- **Compliance value**: Confirms that service accounts use OIDC federation (no static secrets) and credentials are properly managed.

### 3.8 Azure AD Conditional Access Policies

- **What it proves**: MFA and other conditional access requirements are enforced for Azure AD users.
- **Collection**: Manual export from Azure Portal or via `az rest` / Microsoft Graph API (requires appropriate license and permissions).
- **Key fields**: policy name, state (enabled/disabled), conditions, grant controls.
- **Compliance value**: Proves that authentication policies enforce MFA and other security requirements.

### 3.9 Access Review Sign-Off

- **What it proves**: A responsible person has reviewed the access exports and confirmed that all access is appropriate.
- **Collection**: Manual process -- Security Lead compiles the review summary, reviewers sign off.
- **Key fields**: review period, reviewer name, date, findings, actions taken.
- **Compliance value**: Provides the human attestation layer that automated exports alone cannot provide.

### 3.10 JML Action Log

- **What it proves**: All identity lifecycle events (Joiner, Mover, Leaver) are tracked with timestamps and approvals.
- **Collection**: GitHub Issues with the `iam` label, created as part of the [JML Process](../governance/jml-process.md).
- **Key fields**: issue title, labels, assignee, created date, closed date, comments (approval, evidence).
- **Compliance value**: Demonstrates a formal, auditable process for access provisioning and deprovisioning.

## 4. Storage and Retention

| Storage Location          | Contents                                    | Retention Period |
|---------------------------|---------------------------------------------|------------------|
| Evidence Pack (per pipeline run) | Automated exports (JSON)               | Per evidence retention policy (minimum 1 year) |
| Governance archive        | Review sign-offs, conditional access exports, action item logs | Minimum 3 years |
| GitHub Issues              | JML action log                             | Retained indefinitely in repository history |

## 5. Collection Scripts

| Script | Location | Purpose |
|--------|----------|---------|
| `export-github-security-config.sh` | [`scripts/export-github-security-config.sh`](../../scripts/export-github-security-config.sh) | Exports GitHub org membership, repo permissions, teams, branch protection, MFA status |
| `export-azure-rbac.sh` | [`scripts/export-azure-rbac.sh`](../../scripts/export-azure-rbac.sh) | Exports Azure RBAC role assignments, service principals, federated credentials |

## 6. Compliance Cross-Reference

| Framework Control   | Evidence Types Used                                                |
|---------------------|--------------------------------------------------------------------|
| DORA Art.16.1.a     | Azure service principal credentials, RBAC role assignments         |
| NIS2 Art.21.2.i     | Org membership, repo permissions, RBAC role assignments, JML log   |
| NIS2 Art.21.2.j     | MFA enforcement, conditional access policies                      |
| ISO 27001 A.8.2     | Org membership, team memberships, RBAC role assignments, JML log   |
| ISO 27001 A.8.4     | Repo permissions, branch protection status                        |
| SOC 2 CC6.1         | Org membership, repo permissions, MFA enforcement, RBAC role assignments |
| SOC 2 CC6.2         | JML action log, access review sign-off                            |
| SOC 2 CC8.1         | Branch protection status                                          |

---

## Related Documents

- [IAM Governance Policy](../governance/iam-governance.md)
- [JML Process](../governance/jml-process.md)
- [Access Review Procedure](../governance/access-review-procedure.md)
