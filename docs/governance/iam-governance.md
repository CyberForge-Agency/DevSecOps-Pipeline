# IAM Governance Policy

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Document Owner   | Security Lead                              |
| Approved By      | CyberForge Management                      |
| Version          | 1.0                                        |
| Effective Date   | 2026-03-15                                 |
| Review Cycle     | Annually, or after a security incident involving access |

---

## 1. Purpose

This policy establishes the identity and access management (IAM) governance framework for all systems used in CyberForge pipeline operations. It defines how identities are created, authenticated, authorized, reviewed, and deprovisioned to protect CyberForge assets and satisfy regulatory obligations.

## 2. Scope

This policy applies to:

- **GitHub Organization** -- repositories, teams, organization membership, and Actions workflows.
- **Azure Subscription** -- resource groups, RBAC role assignments, Azure AD/Entra ID accounts, and conditional access policies.
- **CI/CD Service Principals** -- GitHub Actions OIDC service principals, Terraform service principals, and any automation identity used by the pipeline.
- **All personnel** who interact with the above systems, including developers, security team members, management, and external parties (auditors, contractors).

## 3. Principles

| Principle              | Description                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------------|
| Least Privilege        | Every identity receives only the minimum permissions required to perform its function.         |
| Separation of Duties   | No single person can approve and execute a privileged change without independent review.       |
| Need-to-Know           | Access to data and systems is granted only when there is a demonstrated business need.         |
| Defense in Depth       | Multiple layers of access control (MFA, RBAC, network restrictions) reduce single-point-of-failure risk. |

## 4. Identity Types

### 4.1 Human Users

| Role            | Typical Access                                              |
|-----------------|-------------------------------------------------------------|
| Developer       | GitHub repo Write, Azure Contributor (scoped to dev/staging resource groups) |
| Security Team   | GitHub repo Admin (security-sensitive paths via CODEOWNERS), Azure Security Reader |
| Management      | GitHub repo Read, Azure Reader, dashboard and reporting access |

### 4.2 Service Accounts

| Identity                     | Purpose                                    | Authentication Method         |
|------------------------------|--------------------------------------------|-------------------------------|
| GitHub Actions OIDC SP       | Pipeline workload identity for Azure       | OIDC federation (no static secret) |
| Terraform Service Principal  | Infrastructure provisioning via Terraform  | OIDC federation (no static secret) |

Service accounts MUST NOT have interactive login capabilities and MUST NOT use static credentials.

### 4.3 External Identities

| Identity   | Access Level | Constraints                                        |
|------------|--------------|----------------------------------------------------|
| Auditors   | Read-only    | Time-bound (maximum 30 days per engagement), scoped to evidence repositories and dashboards only |

External access is provisioned through a formal request and removed immediately upon engagement completion. See the JML process in [jml-process.md](jml-process.md).

## 5. Authentication Requirements

### 5.1 Multi-Factor Authentication (MFA)

MFA is **mandatory** for all human users on both GitHub and Azure.

- GitHub: Organization-level MFA enforcement enabled (`two_factor_requirement_enabled: true`).
- Azure: Conditional access policy requiring MFA for all users, all cloud apps.
- MFA enrollment must be verified before granting any access (see [jml-process.md](jml-process.md), Joiner step 4).

### 5.2 Single Sign-On (SSO)

SSO via Azure AD/Entra ID is the preferred authentication method where available. GitHub SAML SSO should be enabled when the organization license supports it.

### 5.3 Service Account Authentication

- **OIDC federation only** -- no static client secrets or certificates stored in repositories or CI/CD variables.
- **Short-lived tokens** -- maximum lifetime of 1 hour for all service account tokens.
- OIDC subject claims must be scoped to specific repositories and branches where possible (e.g., `repo:org/repo:ref:refs/heads/main`).

### 5.4 SSH Keys

- Minimum key strength: **Ed25519** (preferred) or **RSA-4096**.
- Keys must be rotated **annually**.
- Passphrase protection is required for all SSH private keys.
- SSH keys must be registered to individual user accounts (no shared keys).

## 6. Authorization Model

### 6.1 GitHub

| Level         | Roles                        | Assignment Method       |
|---------------|------------------------------|-------------------------|
| Organization  | Owner, Member                | Direct assignment       |
| Repository    | Admin, Write (Maintain), Read | Team-based (preferred) or direct |
| Team          | Maintainer, Member           | Team membership         |

- **Team-based access** is the standard method for granting repository permissions. Direct collaborator assignments should be avoided except for external auditors.
- Repository-level permissions are enforced through team membership.
- `CODEOWNERS` file enforces mandatory security team review for changes to `.github/workflows/`, `infra/`, `policies/`, and `Dockerfile`.

### 6.2 Azure

| Role                              | Scope                          | Assigned To                |
|-----------------------------------|--------------------------------|----------------------------|
| Contributor                       | Pipeline resource groups       | Pipeline service principal |
| AcrPush                           | Container registry             | Pipeline service principal |
| Storage Blob Data Contributor     | Evidence storage account       | Pipeline service principal |
| Reader                            | Subscription                   | Developers, auditors       |

- All RBAC assignments must be scoped to the minimum required resource (resource group or individual resource level preferred over subscription level).
- Custom roles should be created when built-in roles grant excessive permissions.
- Pipeline service principal roles are documented in the project `SETUP.md`.

### 6.3 Pipeline Service Principal

The pipeline service principal uses OIDC federation and holds the following Azure RBAC roles:

- `Contributor` on the target resource group(s) for infrastructure deployment.
- `AcrPush` on the Azure Container Registry for image publishing.
- `Storage Blob Data Contributor` on the evidence storage account for evidence pack upload.

No additional roles should be assigned without a documented justification and security lead approval.

## 7. Privileged Access

### 7.1 GitHub Organization Owner

- **Maximum 2 people** may hold the Organization Owner role at any time.
- Each assignment requires documented business justification.
- Org Owner actions are logged via GitHub Audit Log and reviewed quarterly.

### 7.2 Azure Subscription Owner / Contributor

- **Maximum 2 people** may hold Subscription-level Owner or Contributor roles.
- **Just-In-Time (JIT) access** is recommended for Azure privileged roles using Azure AD Privileged Identity Management (PIM) where the license tier supports it.
- When JIT is not available, privileged access must be reviewed quarterly.

### 7.3 Logging and Accountability

- All privileged actions must be logged and reviewable.
- GitHub Audit Log must be retained and exported per the evidence retention policy.
- Azure Activity Log must be retained for a minimum of 90 days (365 days recommended).
- Privileged access usage is reviewed as part of the quarterly access review (see [access-review-procedure.md](access-review-procedure.md)).

## 8. Account Lifecycle

All identity lifecycle events -- onboarding, role changes, and offboarding -- follow the Joiner/Mover/Leaver (JML) process documented in [jml-process.md](jml-process.md).

Key requirements:

- No account is provisioned without an approved request.
- No account remains active after the associated person has left the organization or project.
- Role changes trigger a review of existing access to enforce least privilege.

## 9. Review Cadence

| Review Type         | Frequency      | Scope                                                              | Owner         |
|---------------------|----------------|--------------------------------------------------------------------|---------------|
| Privileged Access   | Quarterly      | GitHub Org Owners, Azure Owners/Contributors, SP role assignments  | Security Lead |
| Standard Access     | Semi-annually  | GitHub team memberships, Azure Reader/limited roles                | Team Leads    |
| Service Principals  | Quarterly      | Federated credential configuration, role assignments               | Security Lead |
| Ad-hoc              | As needed      | After security incident or organizational change                   | Security Lead |

The detailed review procedure is documented in [access-review-procedure.md](access-review-procedure.md).

## 10. Compliance Mapping

| Requirement           | Framework Control                  | How This Policy Addresses It                              |
|-----------------------|------------------------------------|-----------------------------------------------------------|
| ICT risk management   | DORA Art.16.1.a                    | Comprehensive IAM controls reduce unauthorized access risk |
| Access control        | NIS2 Art.21.2.i                    | Least privilege, MFA, authorization model                  |
| Authentication        | NIS2 Art.21.2.j                    | MFA mandatory, SSO, OIDC federation                        |
| Identity management   | ISO 27001 A.8.2                    | Account lifecycle (JML), review cadence                    |
| Access rights         | ISO 27001 A.8.3                    | Privileged access controls, JIT access                     |
| Access restriction    | ISO 27001 A.8.4                    | RBAC, team-based access, CODEOWNERS                        |
| Logical access        | SOC 2 CC6.1                        | Authentication requirements, authorization model           |
| Access provisioning   | SOC 2 CC6.2                        | JML process, approval workflow                             |
| Access modification   | SOC 2 CC6.3                        | Mover process, access reviews                              |

## 11. Policy Review

This policy is reviewed:

- **Annually** as part of the governance review cycle.
- **After any security incident** involving unauthorized access or access control failure.
- **After significant organizational change** (e.g., team restructuring, new system adoption).

Changes to this policy require approval from the Security Lead and CyberForge Management.

---

## Related Documents

- [JML Process](jml-process.md)
- [Access Review Procedure](access-review-procedure.md)
- [Branch Protection Configuration](../../.github/branch-protection.json)
- [CODEOWNERS](../../.github/CODEOWNERS)
