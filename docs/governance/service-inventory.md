# Service Inventory

| Field          | Value                                                          |
|----------------|----------------------------------------------------------------|
| Document Owner | Security Lead                                                  |
| Approved By    | CyberForge Management                                          |
| Version        | 1.0                                                            |
| Effective Date | 2026-03-15                                                     |
| Review Cycle   | Annually, or after significant changes to services or suppliers |
| Compliance     | NIS2 Art.21.2.i, DORA Art.28-30, ISO 27001 A.5.9, SOC 2 CC9  |

---

## 1. Purpose

This document inventories all internal and external services that comprise or support the CyberForge DevSecOps Pipeline. It maps service dependencies, defines SLA targets, and identifies single points of failure. Together with the [Asset Inventory](asset-inventory.md), it provides the foundation for risk assessment, business continuity planning, and supply chain oversight.

---

## 2. Internal Services (CyberForge Operated)

| Service ID | Service Name            | Description                                                           | Dependencies                                             | SLA Target                    | Owner          | NIS2 Relevance   |
|------------|-------------------------|-----------------------------------------------------------------------|----------------------------------------------------------|-------------------------------|----------------|------------------|
| SVC-001    | DevSecOps Pipeline      | 6-phase CI/CD pipeline for build, scan, sign, deploy, test, evidence  | GitHub Actions, Azure, all scanning tools                | 99% during business hours     | Security Lead  | Core service     |
| SVC-002    | Evidence Pack Generation | Automated compliance evidence archival                                | Pipeline phases 1-6, Azure Blob, OPA policies            | Per-release generation        | Security Lead  | Audit evidence   |
| SVC-003    | Infrastructure Management | Terraform-managed Azure resources                                   | Azure subscription, Terraform state backend              | 4h RTO                        | DevOps Lead    | Supporting       |
| SVC-004    | Security Scanning       | Continuous vulnerability detection                                    | Trivy, CodeQL, ZAP, TruffleHog, Checkov                 | Per-pipeline-run              | Security Lead  | Core security    |
| SVC-005    | Access Management       | IAM lifecycle and review processes                                    | GitHub org admin, Azure AD                               | 2-day provisioning SLA        | Security Lead  | Supporting       |

### Internal Service Details

**SVC-001: DevSecOps Pipeline**
The pipeline executes six phases in sequence:
1. Security Gate (pre-merge scanning: secrets, IaC, linting, PII)
2. Build and Scan (compilation, unit tests, SAST, SCA, container image scan, SBOM)
3. Sign and Attest (Cosign keyless signing, SLSA provenance attestation)
4. Deploy (Terraform infrastructure, Container Apps deployment, signature verification)
5. DAST (OWASP ZAP dynamic application security testing)
6. Evidence (evidence pack generation, OPA policy evaluation, WORM archival)

Pipeline availability depends on GitHub Actions uptime and Azure service availability. Degraded mode is not currently supported -- a failure in any critical phase halts the pipeline.

**SVC-002: Evidence Pack Generation**
Each successful pipeline run produces an Evidence Pack containing 11+ artifacts (scan results, SBOM, provenance, test results, compliance matrix). Packs are archived to Azure Blob Storage with WORM immutability and SHA256 checksum manifests.

**SVC-003: Infrastructure Management**
All Azure infrastructure is defined in Terraform and versioned in Git. State is stored in Azure Blob Storage with GRS replication. Infrastructure changes follow the same PR-based review process as application code.

**SVC-004: Security Scanning**
Six scanning tools operate within the pipeline. All tools run locally on ephemeral GitHub Actions runners with no external data transmission (except Sigstore transparency log entries for signing). Vulnerability findings are governed by the [Vulnerability Management Policy](vulnerability-management-policy.md).

**SVC-005: Access Management**
Identity lifecycle follows the [JML Process](jml-process.md). Access reviews are conducted quarterly for privileged access and semi-annually for standard access per the [Access Review Procedure](access-review-procedure.md).

---

## 3. External Services (Third-Party)

| Service ID | Provider              | Service                                                      | Dependency Type                                    | Criticality | Alternative                                 | SLA/Uptime      |
|------------|-----------------------|--------------------------------------------------------------|----------------------------------------------------|-------------|---------------------------------------------|-----------------|
| EXT-001    | GitHub (Microsoft)    | Source control, CI/CD execution, security features           | Critical dependency                                | Critical    | GitLab CI (documented exit plan)            | 99.9%           |
| EXT-002    | Microsoft Azure       | Cloud infrastructure (ACR, Container Apps, Key Vault, Blob)  | Critical dependency                                | Critical    | AWS/GCP (requires Terraform rewrite)        | 99.95% (regional) |
| EXT-003    | Sigstore              | Transparency log, keyless signing                            | Non-critical (signing works offline if needed)     | Medium      | Self-hosted Rekor/Fulcio                    | Best-effort     |
| EXT-004    | NVD/OSV               | Vulnerability databases (used by Trivy)                      | Important for scan quality                         | High        | GitHub Advisory Database                    | Best-effort     |

### External Service Details

**EXT-001: GitHub (Microsoft)**
GitHub provides source control, CI/CD execution (GitHub Actions), code review, and security features (CodeQL, secret scanning, Dependabot). It is the most critical external dependency. Loss of GitHub access prevents all pipeline operations including code changes, builds, and deployments.

Exit plan: Migration to GitLab CI is documented in the [Vendor Risk Register](vendor-risk-register.md) (EP-001). Estimated migration time: 2-4 weeks for pipeline rewrite, plus additional time for organizational migration.

**EXT-002: Microsoft Azure**
Azure provides the deployment target (Container Apps), container registry (ACR), secret management (Key Vault), evidence storage (Blob with WORM), and identity services (Azure AD/Entra ID for OIDC federation). Loss of Azure access prevents deployments and evidence archival but does not block code changes or security scanning.

Exit plan: Migration to AWS or GCP requires Terraform provider rewrite and OIDC federation reconfiguration. Estimated migration time: 4-8 weeks. See [Vendor Risk Register](vendor-risk-register.md) (EP-002).

**EXT-003: Sigstore**
Sigstore provides the public transparency log (Rekor) and certificate authority (Fulcio) for keyless signing. If Sigstore is unavailable, signing operations fail but the pipeline can be configured to proceed without signing in an emergency (requires explicit override and risk acceptance).

**EXT-004: NVD/OSV**
Trivy uses NVD (National Vulnerability Database) and OSV (Open Source Vulnerabilities) as vulnerability data sources. If these databases are temporarily unavailable, Trivy uses its local cache. Prolonged unavailability degrades scan quality but does not block the pipeline.

---

## 4. Service Dependency Map

```
                    External Services
                    ================
    +------------------+     +------------------+
    | EXT-001: GitHub  |     | EXT-002: Azure   |
    | (Source, CI/CD)  |     | (Infra, Storage) |
    +--------+---------+     +--------+---------+
             |                        |
    +--------v------------------------v--------+
    |                                          |
    |    SVC-001: DevSecOps Pipeline           |
    |    (6-phase CI/CD)                       |
    |                                          |
    +--+-------+-------+-------+-----------+---+
       |       |       |       |           |
       v       v       v       v           v
   SVC-004  SVC-003  SVC-005  SVC-002   EXT-003
   Security  Infra   Access   Evidence  Sigstore
   Scanning  Mgmt    Mgmt     Packs    (Signing)
       |                         |
       v                         v
   EXT-004                   EXT-002
   NVD/OSV                   Azure Blob
   (Vuln DBs)               (WORM)
```

### Dependency Analysis

| Service    | Depends On                                  | Depended On By                    | Single Point of Failure |
|------------|---------------------------------------------|-----------------------------------|------------------------|
| SVC-001    | EXT-001, EXT-002, SVC-004, EXT-003          | SVC-002, SVC-003                  | Yes -- requires both GitHub and Azure |
| SVC-002    | SVC-001, EXT-002                            | Audit processes                   | No -- evidence can be regenerated from git history |
| SVC-003    | EXT-002                                     | SVC-001 (deploy phase)            | Partially -- IaC is versioned in git |
| SVC-004    | EXT-004 (degraded without)                  | SVC-001                           | No -- individual tools can be substituted |
| SVC-005    | EXT-001 (GitHub admin), EXT-002 (Azure AD)  | All services (access control)     | Yes -- access management requires both platforms |

### Critical Path

The critical path for a release is: SVC-001 (pipeline) -> EXT-001 (GitHub Actions) -> EXT-002 (Azure deployment). Both external services must be available for a successful release. Security scanning (SVC-004) and evidence generation (SVC-002) are mandatory phases but have fallback mechanisms for temporary external service degradation.

---

## 5. Service Continuity

Service continuity and disaster recovery planning for these services is addressed in the BC/DR Plan (planned, Task 25). Until that document is implemented, the following interim measures apply:

- **GitHub outage:** Pipeline operations are paused. Code remains available in local git clones. No manual workaround for CI/CD execution.
- **Azure outage:** Deployments are blocked. Existing deployed applications continue running until Container Apps scaling events require Azure API access. Evidence packs queue locally.
- **Sigstore outage:** Signing is skipped with documented risk acceptance. Pipeline continues without attestation.
- **NVD/OSV outage:** Trivy uses cached vulnerability database. Scan quality may be degraded for newly disclosed vulnerabilities.

---

## 6. Review Process

### 6.1 Scheduled Review

The service inventory is reviewed **annually** by the Security Lead and CTO. The review verifies:

- All services are accurately recorded (no additions or removals missed).
- Dependency relationships remain current.
- SLA targets are achievable and aligned with business requirements.
- Alternatives and exit plans are viable and up to date.

### 6.2 Trigger-Based Review

The inventory must also be reviewed after:

- Addition or removal of an external service provider.
- Significant changes to internal service architecture.
- Service outages exceeding SLA targets.
- Changes to NIS2 or DORA requirements affecting service classification.

### 6.3 Review Record

| Date       | Reviewer       | Changes                                         |
|------------|----------------|--------------------------------------------------|
| 2026-03-15 | Initial creation | Full service inventory established              |

---

## 7. Compliance Mapping

| Requirement                            | Framework Reference  | How This Document Addresses It                                    |
|----------------------------------------|----------------------|-------------------------------------------------------------------|
| Asset management (services)            | NIS2 Art.21.2.i      | Complete service inventory with ownership and dependencies        |
| ICT third-party service provider register | DORA Art.28(3)    | External service inventory with criticality and exit plans        |
| Supplier relationship management       | ISO 27001 A.5.19     | Service dependencies, SLA targets, alternatives                   |
| Inventory of information assets        | ISO 27001 A.5.9      | Services as operational assets with ownership                     |
| Risk mitigation (vendors)              | SOC 2 CC9            | Dependency analysis, single point of failure identification       |
| Business continuity                    | NIS2 Art.21.2.c      | Service continuity measures (interim, pending Task 25)            |

---

## 8. Related Documents

- [Asset Inventory](asset-inventory.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [Vendor Exit Plan Template](vendor-exit-plan-template.md)
- [ICT Third-Party Contract Controls](ict-third-party-contract-controls.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [IAM Governance Policy](iam-governance.md)
- [Crisis Management Plan](crisis-management-plan.md)
- [Scope and Limitations](../compliance/scope-and-limitations.md)
- BC/DR Plan (planned, Task 25)
- Incident Handling Runbooks (planned, Task 24, `docs/runbooks/`)
