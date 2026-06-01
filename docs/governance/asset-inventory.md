# Asset Inventory

| Field          | Value                                                        |
|----------------|--------------------------------------------------------------|
| Document Owner | Security Lead                                                |
| Approved By    | CyberForge Management                                        |
| Version        | 1.0                                                          |
| Effective Date | 2026-03-15                                                   |
| Review Cycle   | Annually, or after significant infrastructure changes        |
| Compliance     | NIS2 Art.21.2.i, ISO 27001 A.5.9, DORA Art.16, SOC 2 CC6.1 |

---

## 1. Purpose

This document provides a comprehensive inventory of CyberForge's information, technology, and people assets. It satisfies the asset management requirements of NIS2 Art.21.2.i and supports the broader ICT risk management obligations under DORA, ISO 27001, and SOC 2.

A complete and accurate asset inventory is a prerequisite for effective risk assessment, access control, business continuity planning, and incident response. Without knowing what assets exist and who is responsible for them, no security control can be applied consistently.

---

## 2. Data Classification Scheme

All information assets are classified according to the following scheme. Classification determines handling requirements, access restrictions, and retention obligations.

| Classification        | Definition                                                                                        | Examples                                          |
|-----------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------|
| Strictly Confidential | Compromise would cause severe damage. Access restricted to named individuals with explicit need.  | Secrets, credentials, access tokens               |
| Confidential          | Compromise would cause significant damage. Access restricted to authorized personnel.             | Source code, evidence packs, scan results, client data |
| Internal              | Not sensitive but not intended for public disclosure. Access restricted to CyberForge personnel.  | Governance docs, SBOM, container images, logs     |
| Public                | No damage from disclosure. May be freely shared.                                                  | Open-source components, published policies        |

Classification is assigned by the asset owner at the time of creation and reviewed during annual asset inventory reviews.

---

## 3. Information Assets

| Asset ID | Asset Name           | Description                                              | Classification        | Owner          | Location                          | Backup                              |
|----------|----------------------|----------------------------------------------------------|-----------------------|----------------|-----------------------------------|--------------------------------------|
| IA-001   | Source Code           | CyberForge pipeline repository                           | Confidential          | CTO            | GitHub (EU)                       | Git distributed (multiple clones)    |
| IA-002   | Client Source Code    | Client repositories using CyberForge templates           | Client Confidential   | Client         | Client GitHub org                 | Client responsibility                |
| IA-003   | Pipeline Secrets      | OIDC federation config, Azure SP credentials             | Strictly Confidential | Security Lead  | Azure AD / GitHub vars            | Azure AD redundancy                  |
| IA-004   | Evidence Packs        | Compliance audit evidence archives                       | Confidential          | Security Lead  | Azure Blob (WORM, Poland Central) | WORM immutability                    |
| IA-005   | Terraform State       | Infrastructure state files                               | Confidential          | DevOps Lead    | Azure Blob (Poland Central)       | GRS replication                      |
| IA-006   | Container Images      | Built Docker images                                      | Internal              | DevOps Lead    | Azure ACR (Poland Central)        | ACR geo-replication (if enabled)     |
| IA-007   | SBOM/Provenance       | Software composition and provenance data                 | Internal              | Security Lead  | Azure ACR + Evidence Pack         | Evidence Pack WORM                   |
| IA-008   | Security Scan Results | SAST/SCA/DAST findings                                   | Confidential          | Security Lead  | GitHub Actions artifacts + Evidence Pack | Evidence Pack WORM              |
| IA-009   | Governance Documents  | Policies, procedures, runbooks                           | Internal              | CTO            | GitHub repository                 | Git distributed                      |
| IA-010   | Pipeline Logs         | CI/CD execution logs                                     | Internal              | DevOps Lead    | GitHub Actions (90 days) + Evidence Pack | Evidence Pack WORM              |

### Information Asset Notes

- **IA-002 (Client Source Code):** CyberForge does not store or process client source code directly. Clients use CyberForge pipeline templates within their own GitHub organizations. CyberForge has no access to client repositories unless explicitly granted for consulting engagements, subject to time-bound access per the [JML Process](jml-process.md).
- **IA-003 (Pipeline Secrets):** No static secrets are stored in GitHub repositories or CI/CD variables. All cloud authentication uses OIDC federation. See the [IAM Governance Policy](iam-governance.md), Section 5.3.
- **IA-004 (Evidence Packs):** Evidence Packs are archived with WORM (Write Once, Read Many) immutability policies to prevent tampering. SHA256 checksum manifests provide tamper detection.
- **IA-005 (Terraform State):** State files may contain sensitive resource identifiers. Access is restricted to the pipeline service principal and infrastructure administrators.

---

## 4. Technology Assets

| Asset ID | Asset Name                 | Type               | Version/Details                          | Owner          | Criticality | Vendor                |
|----------|----------------------------|--------------------|------------------------------------------|----------------|-------------|-----------------------|
| TA-001   | GitHub Organization        | Cloud Service      | GitHub Enterprise/Team                   | CTO            | Critical    | Microsoft/GitHub      |
| TA-002   | Azure Subscription         | Cloud Platform     | Pay-as-you-go                            | CTO            | Critical    | Microsoft             |
| TA-003   | Azure Container Registry   | Container Registry | Standard SKU, Poland Central             | DevOps Lead    | High        | Microsoft             |
| TA-004   | Azure Container Apps       | Compute            | Consumption plan                         | DevOps Lead    | High        | Microsoft             |
| TA-005   | Azure Key Vault            | Secret Management  | Standard, RBAC                           | Security Lead  | Critical    | Microsoft             |
| TA-006   | Azure Blob Storage (WORM)  | Evidence Archive   | Standard, WORM policy                    | Security Lead  | Critical    | Microsoft             |
| TA-007   | Terraform                  | IaC Tool           | v1.x, AzureRM provider                  | DevOps Lead    | High        | HashiCorp             |
| TA-008   | GitHub Actions Workflows   | CI/CD Engine       | Reusable workflows (7 files)             | Security Lead  | Critical    | Microsoft/GitHub      |
| TA-009   | Security Scanning Tools    | OSS Tools          | Trivy, CodeQL, ZAP, TruffleHog, Checkov, MegaLinter | Security Lead | High | Various (OSS) |
| TA-010   | Cosign/Sigstore            | Signing Tools      | Keyless OIDC signing                     | Security Lead  | High        | Linux Foundation      |

### Technology Asset Notes

- **TA-001 and TA-002** are critical dependencies. Loss of either service halts all pipeline operations. Exit plans are documented in the [Vendor Risk Register](vendor-risk-register.md).
- **TA-005 (Azure Key Vault)** stores no static pipeline secrets (OIDC federation is used), but serves as the designated secret management service for any future operational secrets.
- **TA-008 (GitHub Actions Workflows)** consists of 7 reusable workflow files implementing the 6-phase pipeline. All GitHub Actions are pinned to full SHA to prevent supply chain attacks. Updates are managed by Renovate.
- **TA-009 (Security Scanning Tools)** are open-source tools that execute locally on ephemeral GitHub Actions runners. No scan data leaves the build environment except through Evidence Pack archival. See the [Vendor Risk Register](vendor-risk-register.md) for individual tool assessments.

---

## 5. People Assets

| Asset ID | Role                           | Responsibilities                                                       | Access Level                                              | Training Required                                                |
|----------|--------------------------------|------------------------------------------------------------------------|-----------------------------------------------------------|------------------------------------------------------------------|
| PA-001   | CTO / Co-founder               | Strategic oversight, vendor management, risk ownership                 | GitHub Org Owner, Azure Owner                             | Management cybersecurity training (NIS2 Art.20)                  |
| PA-002   | Security Lead / Co-founder     | Pipeline security, vuln mgmt, access reviews, incident response        | GitHub Org Owner, Azure Contributor                       | ISO 27001 awareness, incident response                           |
| PA-003   | Future: DevOps Engineer        | Pipeline development, Terraform, deployments                           | GitHub Write, Azure Contributor (scoped)                  | Secure coding, CI/CD security                                    |
| PA-004   | Future: External Auditor       | Audit access                                                           | GitHub Read (time-bound), Azure Reader (time-bound)       | Audit methodology                                                |

### People Asset Notes

- **PA-001 and PA-002** are currently the only active personnel. Both hold co-founder roles and share responsibilities. As the team grows, separation of duties must be enforced per the [IAM Governance Policy](iam-governance.md).
- **PA-003 and PA-004** are planned roles. Access will be provisioned through the [JML Process](jml-process.md) when positions are filled.
- Training requirements are tracked in [NIS2 Management Training Records](nis2-management-training-records.md) for management and in the [Security Training Program](security-training-program.md) (Task 29) for all personnel.
- Maximum 2 persons may hold GitHub Organization Owner or Azure Subscription Owner roles at any time (see [IAM Governance Policy](iam-governance.md), Section 7).

---

## 6. Asset Ownership Responsibilities

Asset owners are accountable for:

1. Maintaining accurate inventory records for their assigned assets.
2. Applying the appropriate data classification and ensuring handling requirements are met.
3. Ensuring access to the asset follows the principle of least privilege.
4. Reporting any unauthorized access, loss, or compromise to the Security Lead immediately.
5. Participating in periodic asset inventory reviews.
6. Ensuring adequate backup and recovery procedures are in place and tested.

---

## 7. Review Process

### 7.1 Scheduled Review

The asset inventory is reviewed **annually** by the Security Lead and CTO. The review verifies:

- All assets are still accurately recorded (no additions or removals missed).
- Classification levels remain appropriate.
- Ownership assignments are current.
- Backup and recovery arrangements are adequate.
- New assets introduced since the last review have been added to the inventory.

### 7.2 Trigger-Based Review

The inventory must also be reviewed after:

- Any significant infrastructure change (new Azure services, new CI/CD tools, new vendors).
- Organizational changes (personnel joining, leaving, or changing roles).
- Security incidents involving asset compromise, loss, or unauthorized access.
- Changes to the data classification scheme.

### 7.3 Review Record

| Date       | Reviewer       | Changes                                         |
|------------|----------------|--------------------------------------------------|
| 2026-03-15 | Initial creation | Full asset inventory established                |

---

## 8. Compliance Mapping

| Requirement                          | Framework Reference     | How This Document Addresses It                                |
|--------------------------------------|-------------------------|---------------------------------------------------------------|
| Asset management and access control  | NIS2 Art.21.2.i         | Complete inventory with classification, ownership, access levels |
| ICT risk management                  | DORA Art.16             | Asset identification as foundation for risk assessment        |
| Inventory of information assets      | ISO 27001 A.5.9         | Structured inventory with classification scheme               |
| Classification of information        | ISO 27001 A.5.12        | Four-tier classification scheme with handling requirements     |
| Ownership of assets                  | ISO 27001 A.5.9         | Named owners for all assets                                   |
| Logical and physical access controls | SOC 2 CC6.1             | Access levels documented per asset and role                   |

---

## 9. Related Documents

- [IAM Governance Policy](iam-governance.md)
- [JML Process](jml-process.md)
- [Access Review Procedure](access-review-procedure.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [Risk Assessment Methodology](risk-assessment-methodology.md)
- [NIS2 Management Training Records](nis2-management-training-records.md)
- [Security Training Program](security-training-program.md) (Task 29)
- [Scope and Limitations](../compliance/scope-and-limitations.md)
