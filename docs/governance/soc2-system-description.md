# SOC 2 System Description

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Document Owner   | CTO                                        |
| Approved By      | CyberForge Management                      |
| Version          | 1.0                                        |
| Effective Date   | 2026-03-15                                 |
| Review Cycle     | Annually, or after material changes to system scope |

---

## A. Nature of Services

CyberForge is a Polish startup providing DevSecOps pipeline implementation and CI/CD hardening services. CyberForge helps software development organizations build secure, auditable, and compliant software delivery pipelines that generate machine-readable evidence for regulatory and audit purposes.

The system in scope is the **CyberForge DevSecOps Pipeline platform** -- a compliance-enabling CI/CD and software supply chain control subsystem used to build, test, scan, sign, deploy, and generate audit evidence for client software. The platform is deployed on GitHub Actions and Microsoft Azure.

The service model consists of two components:

1. **Implementation consulting** -- CyberForge engineers design and deploy hardened CI/CD pipelines tailored to client regulatory requirements (DORA, NIS2, ISO 27001, SOC 2, GDPR).
2. **Managed pipeline templates** -- CyberForge maintains reusable GitHub Actions workflow templates, Terraform infrastructure modules, OPA compliance policies, and evidence generation scripts that form the pipeline platform.

The pipeline executes six phases per release cycle:

| Phase | Name | Purpose |
|-------|------|---------|
| 1 | Security Gate | Pre-merge checks: secret scanning, IaC scanning, linting, PII detection, commit signature verification |
| 2 | Build and Scan | Compilation, unit tests with coverage gate, SAST (CodeQL), SCA (Trivy), container image scanning |
| 3 | Sign and Attest | SBOM generation (Syft), cryptographic image signing (Cosign), SLSA build provenance attestation |
| 4 | Deploy | Pre-deploy signature verification, Terraform infrastructure provisioning, container deployment |
| 5 | DAST | Dynamic application security testing (OWASP ZAP) against the deployed application |
| 6 | Evidence Pack | Automated evidence collection, checksum manifest, compliance matrix, immutable archival to Azure Blob WORM storage |

---

## B. Principal Service Commitments and System Requirements

CyberForge makes the following principal service commitments relevant to the Trust Services Criteria:

### Security

- Protect client source code, secrets, and deployment credentials from unauthorized access, disclosure, and modification.
- Enforce zero static secrets through OIDC federation between GitHub Actions and Azure.
- Require cryptographic signing and verification for all deployed artifacts.
- Enforce multi-factor authentication for all human users on GitHub and Azure.
- Enforce branch protection with minimum two reviewer approvals and signed commits.

### Availability

- The pipeline must be operational for CI/CD workflows during business hours (CET/CEST, Monday through Friday).
- Pipeline availability depends on sub-service organization availability (GitHub Actions, Microsoft Azure).
- CyberForge monitors pipeline health and communicates outages to affected clients.

### Processing Integrity

- The pipeline must correctly execute all security gates and produce accurate, complete evidence for each release.
- All six pipeline phases must complete successfully before a release is considered fully evidenced.
- Test coverage must meet the 80% minimum threshold.
- Evidence packs must include a SHA256 checksum manifest for tamper detection.

### Confidentiality

- Client source code, configuration, and pipeline outputs are treated as confidential information.
- Access to client repositories and Azure resources follows the principle of least privilege.
- Evidence packs are archived to immutable (WORM) storage with controlled access.
- Log sanitization removes PII from archived evidence artifacts.

---

## C. Components of the System

### C.1 Infrastructure

| Component | Provider | Purpose |
|-----------|----------|---------|
| Azure Container Registry (ACR) | Microsoft Azure | Stores signed container images |
| Azure Container Apps | Microsoft Azure | Hosts deployed applications |
| Azure Key Vault | Microsoft Azure | Manages secrets with in-memory injection |
| Azure Blob Storage (WORM) | Microsoft Azure | Immutable evidence pack archival |
| GitHub Actions | GitHub (Microsoft) | CI/CD workflow execution |
| GitHub Advanced Security | GitHub (Microsoft) | CodeQL SAST, secret scanning, dependency review |
| GitHub Organization | GitHub (Microsoft) | Source code hosting, access control, audit logging |

All infrastructure is hosted in the EU (Azure Poland Central region; GitHub EU data residency).

### C.2 Software

| Component | Description |
|-----------|-------------|
| Node.js demo application | TypeScript Express application used for pipeline demonstration and testing |
| GitHub Actions workflows | Six reusable workflow files implementing the pipeline phases |
| Terraform modules | Infrastructure-as-code for Azure resource provisioning and configuration |
| OPA/Rego policies | Compliance gate policies for deployment verification and retention checks |
| Evidence generation scripts | Bash scripts for evidence collection, log sanitization, DPA checks, and data flow mapping |
| Renovate | Automated dependency update management |
| Pipeline security tools | TruffleHog, Checkov, MegaLinter, Trivy, CodeQL, Syft, Cosign, OWASP ZAP |

### C.3 People

CyberForge operates as a small startup with the following roles relevant to the system:

| Role | Responsibilities |
|------|-----------------|
| CTO | System architecture, infrastructure management, vendor risk oversight, management review |
| Security Lead | Pipeline security configuration, vulnerability management, access reviews, incident response |
| DevOps Lead | Workflow maintenance, deployment operations, infrastructure changes |
| Developer | Application code, pipeline testing, code review |

Roles are defined in detail in the [IAM Governance Policy](iam-governance.md). In a startup environment, individuals may hold multiple roles. Compensating controls (such as mandatory two-reviewer PR approval and CODEOWNERS enforcement) mitigate the risk of insufficient separation of duties.

### C.4 Procedures

**Automated procedures (pipeline-enforced):**

- Pre-merge security gate execution (Phase 1)
- Build, test, and scan execution (Phase 2)
- Artifact signing and attestation (Phase 3)
- Signature verification and deployment (Phase 4)
- Dynamic application security testing (Phase 5)
- Evidence pack generation and archival (Phase 6)

**Manual procedures:**

- Quarterly privileged access reviews ([access-review-procedure.md](access-review-procedure.md))
- Semi-annual standard access reviews ([access-review-procedure.md](access-review-procedure.md))
- Vulnerability triage and remediation tracking ([vulnerability-management-policy.md](vulnerability-management-policy.md))
- Incident response and classification
- Quarterly vendor risk register review ([vendor-risk-register.md](vendor-risk-register.md))
- Annual management review
- Joiner/mover/leaver identity lifecycle ([jml-process.md](jml-process.md))

### C.5 Data

| Data Category | Description | Classification |
|---------------|-------------|----------------|
| Source code | Client and CyberForge application source code | Confidential |
| Container images | Built and signed Docker images | Confidential |
| SBOM | Software Bill of Materials (CycloneDX format) | Internal |
| Provenance attestations | SLSA build provenance (in-toto format) | Internal |
| Security scan results | SAST, SCA, DAST, IaC scan outputs | Confidential |
| Evidence packs | Archived ZIP containing all release evidence | Confidential |
| Pipeline logs | GitHub Actions workflow run metadata | Internal |
| Secrets | API keys, signing credentials (stored in Key Vault) | Restricted |
| DPA compliance records | Processor agreement status for pipeline vendors | Internal |

---

## D. Boundaries of the System

### D.1 In Scope

- CyberForge GitHub organization and all repositories containing pipeline code, workflows, policies, and infrastructure definitions.
- Azure subscription resources: ACR, Container Apps, Key Vault, Blob Storage, networking, and RBAC configuration.
- CI/CD pipeline execution across all six phases.
- Evidence generation, packaging, and immutable archival.
- Identity and access management for GitHub and Azure within the CyberForge organization.
- Vendor risk management for pipeline tool providers.

### D.2 Out of Scope

- **Client application business logic** -- CyberForge scans and deploys client code but is not responsible for the functional correctness of client applications.
- **Client-managed infrastructure** -- infrastructure outside the CyberForge Azure subscription is not in scope.
- **End-user-facing applications** -- the pipeline deploys applications, but the runtime behavior of those applications under end-user load is outside the pipeline system boundary.
- **Physical security** -- all infrastructure is hosted in cloud environments; physical security is the responsibility of the cloud provider (see Section G).
- **Client employee access management** -- CyberForge manages access within its own organization; client-side access controls are Complementary User Entity Controls (see Section F).

### D.3 Sub-Service Organizations

CyberForge uses the **carve-out method** for the following sub-service organizations. Their controls are excluded from this system description, and CyberForge relies on their independent SOC 2 Type II reports.

| Sub-Service Organization | Services Used | Reliance |
|--------------------------|---------------|----------|
| GitHub (Microsoft) | GitHub Actions, Advanced Security, source code hosting | SOC 2 Type II report for GitHub |
| Microsoft Azure | ACR, Container Apps, Key Vault, Blob Storage, Entra ID | SOC 2 Type II report for Microsoft Azure |

---

## E. Relevant Aspects of Internal Control

### E.1 Control Environment

- CyberForge leadership maintains a security-first culture with documented policies and procedures.
- Roles and responsibilities are defined in the IAM Governance Policy.
- All personnel are expected to follow documented security procedures and escalate concerns.
- The CTO provides oversight of the overall control environment.

### E.2 Risk Assessment

- CyberForge maintains a risk register documenting identified risks, their likelihood, impact, and treatment plans.
- Risk assessments are conducted annually and after material changes to the pipeline or its operating environment.
- The vendor risk register tracks third-party risks with criticality ratings and exit plans.
- Risk acceptance follows a documented process with approval requirements and expiration dates.

### E.3 Information and Communication

- Procedures and runbooks are documented in the project repository under `docs/`.
- Policy changes are communicated through repository pull requests with required reviews.
- Incident communications follow documented escalation paths.

### E.4 Monitoring Activities

- Pipeline gate outcomes (pass/fail) are recorded for every execution.
- Evidence packs provide a complete audit trail for each release.
- Access reviews verify that access grants remain appropriate on a quarterly and semi-annual basis.
- Vulnerability scan results are tracked with remediation SLAs.
- Monthly pipeline health reviews assess success/failure rates.

### E.5 Control Activities

- **Automated pipeline gates** -- security scanning, test coverage, and policy enforcement block non-compliant changes.
- **Code review** -- all changes require minimum two reviewer approvals before merge.
- **Signed commits** -- all commits to the main branch must be cryptographically signed.
- **OIDC authentication** -- no static secrets are stored; all cloud authentication uses short-lived OIDC tokens.
- **CODEOWNERS enforcement** -- security-sensitive paths (workflows, infrastructure, policies, Dockerfile) require security team review.
- **Artifact signing and verification** -- container images are signed with Cosign and verified before deployment.
- **Immutable evidence archival** -- evidence packs are stored in Azure Blob Storage with WORM policies.

---

## F. Complementary User Entity Controls (CUECs)

CyberForge's controls are designed with the expectation that clients implement the following controls within their own environments. The effectiveness of CyberForge's controls depends, in part, on the assumption that these controls are in place.

### Mandatory CUECs

1. **Credential protection** -- clients must protect their own GitHub and Azure credentials and must not share credentials with unauthorized parties.
2. **Secure coding practices** -- clients must follow secure coding practices and address security findings identified by the pipeline.
3. **Pipeline finding review** -- clients must review pipeline scan results and take appropriate action on identified vulnerabilities within agreed SLAs.
4. **Access control management** -- clients must manage their own user access controls, including onboarding, offboarding, and periodic reviews for their personnel.

### Recommended CUECs

5. **Branch protection** -- clients should configure branch protection rules on their repositories consistent with CyberForge recommendations (minimum two reviewers, signed commits, no force push).
6. **MFA enforcement** -- clients should enable and enforce multi-factor authentication on their GitHub and Azure accounts.
7. **Security awareness** -- clients should ensure their developers receive security awareness training relevant to their role.

---

## G. Complementary Subservice Organization Controls (CSOCs)

### GitHub (Microsoft)

CyberForge relies on GitHub (Microsoft) for the following controls:

- Physical and logical security of GitHub data center infrastructure.
- Availability and disaster recovery for GitHub Actions and GitHub Advanced Security.
- Network security and DDoS protection for the GitHub platform.
- Encryption of data at rest and in transit within the GitHub environment.
- Incident management and notification for GitHub platform security events.

GitHub publishes a SOC 2 Type II report that covers these controls. CyberForge reviews the GitHub SOC 2 report annually as part of vendor risk management.

### Microsoft Azure

CyberForge relies on Microsoft Azure for the following controls:

- Physical security of Azure data center facilities (Poland Central region).
- Logical security and isolation of Azure compute, storage, and networking resources.
- Availability and disaster recovery for Azure services (ACR, Container Apps, Key Vault, Blob Storage).
- Encryption of data at rest (Azure Storage Service Encryption, Key Vault HSM) and in transit (TLS).
- Identity and authentication infrastructure (Azure AD/Entra ID).
- Compliance certifications relevant to EU regulatory requirements.

Microsoft publishes a SOC 2 Type II report that covers these controls. CyberForge reviews the Microsoft Azure SOC 2 report annually as part of vendor risk management.

---

## Revision History

| Date | Change | Author |
|------|--------|--------|
| 2026-03-15 | Initial version | CyberForge Engineering |

---

## Related Documents

- [IAM Governance Policy](iam-governance.md)
- [Access Review Procedure](access-review-procedure.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [JML Process](jml-process.md)
- [SOC 2 Control Matrix](soc2-control-matrix.md)
- [Control Owners](control-owners.md)
- [Evidence Calendar](evidence-calendar.md)
- [Scope and Limitations](../compliance/scope-and-limitations.md)
- [Framework Boundaries](../compliance/framework-boundaries.md)
- [Compliance Matrix](../compliance-matrix.md)
