# SOC 2 Control Matrix

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Document Owner   | CTO                                        |
| Approved By      | CyberForge Management                      |
| Version          | 1.0                                        |
| Effective Date   | 2026-03-15                                 |
| Review Cycle     | Annually, or after material changes to controls |

---

## Purpose

This document maps Trust Services Criteria (TSC) to specific controls implemented or planned within the CyberForge DevSecOps Pipeline. Each control is assigned an owner, evidence source, frequency, and implementation status.

For the overall compliance scope and limitations, see [scope-and-limitations.md](../compliance/scope-and-limitations.md). For the SOC 2 system description, see [soc2-system-description.md](soc2-system-description.md).

---

## Control Types

| Type | Definition |
|------|------------|
| Preventive | Control designed to prevent an undesirable event from occurring |
| Detective | Control designed to detect an undesirable event that has occurred |
| Corrective | Control designed to correct an undesirable event after detection |

## Implementation Status Definitions

| Status | Definition |
|--------|------------|
| Implemented | Control is fully operational and producing evidence |
| Partially Implemented | Control exists but requires additional configuration or process maturity |
| Planned | Control is designed but not yet operational |

---

## CC5: Control Activities

| TSC | Criterion | Control ID | Control Description | Control Type | Control Owner | Evidence Source | Frequency | Implementation Status |
|-----|-----------|------------|---------------------|--------------|---------------|-----------------|-----------|----------------------|
| CC5 | CC5.1 | CC5-01 | Pipeline security gates (Phase 1) automatically execute pre-merge checks including secret scanning (TruffleHog), IaC scanning (Checkov), linting (MegaLinter), and PII detection. Failing checks block the merge. | Preventive | Security Lead | `security-report.json`, GitHub Actions workflow logs | Per commit/PR | Implemented |
| CC5 | CC5.1 | CC5-02 | OPA/Rego policies enforce compliance gates for deployment verification and evidence retention checks. Policy violations block pipeline progression. | Preventive | Security Lead | OPA policy evaluation logs, `pipeline-run.json` | Per deployment | Implemented |
| CC5 | CC5.1 | CC5-03 | Terraform change control requires all infrastructure changes to be defined in code, scanned by Checkov, reviewed by two approvers (including security team via CODEOWNERS), and applied through the pipeline. | Preventive | DevOps Lead | Terraform plan/apply logs, PR review records | Per infrastructure change | Implemented |
| CC5 | CC5.2 | CC5-04 | Automated security scanning (Trivy SCA, Trivy image scan, CodeQL SAST) runs on every build. Critical and High severity findings block the pipeline. | Detective | Security Lead | `dependency-review.json`, `security-report.json`, GitHub Security alerts | Per build | Implemented |
| CC5 | CC5.2 | CC5-05 | Unit test execution with 80% minimum coverage threshold. Builds failing the coverage gate are rejected. | Preventive | DevOps Lead | Jest coverage report, `pipeline-run.json` | Per build | Implemented |

---

## CC6: Logical and Physical Access Controls

| TSC | Criterion | Control ID | Control Description | Control Type | Control Owner | Evidence Source | Frequency | Implementation Status |
|-----|-----------|------------|---------------------|--------------|---------------|-----------------|-----------|----------------------|
| CC6 | CC6.1 | CC6-01 | OIDC federation between GitHub Actions and Azure eliminates static cloud credentials. All pipeline authentication uses short-lived tokens (maximum 1-hour lifetime) with repository and branch-scoped subject claims. | Preventive | DevOps Lead | OIDC configuration export, `pipeline-run.json` | Continuous | Implemented |
| CC6 | CC6.1 | CC6-02 | Branch protection enforces minimum two reviewer approvals for all changes to the main branch. Force push is disabled. Required status checks must pass before merge. | Preventive | Security Lead | Branch protection configuration export (via `export-github-security-config.sh`) | Continuous (verified quarterly) | Implemented |
| CC6 | CC6.1 | CC6-03 | CODEOWNERS file enforces mandatory security team review for changes to security-sensitive paths: `.github/workflows/`, `infra/`, `policies/`, and `Dockerfile`. | Preventive | Security Lead | CODEOWNERS file, PR review history | Continuous (verified semi-annually) | Implemented |
| CC6 | CC6.1 | CC6-04 | Cryptographic commit signing is required for all commits to the main branch. Unsigned commits are rejected by branch protection rules. | Preventive | Security Lead | Branch protection config, Git log with signature verification | Continuous | Implemented |
| CC6 | CC6.1 | CC6-05 | GitHub organization access is controlled through team-based permissions. Maximum two people hold the Organization Owner role. | Preventive | Security Lead | GitHub org member export (via `export-github-security-config.sh`) | Continuous (verified quarterly) | Implemented |
| CC6 | CC6.2 | CC6-06 | Azure RBAC assignments follow least privilege. Pipeline service principal roles are scoped to specific resource groups and resources. Custom roles are used when built-in roles grant excessive permissions. | Preventive | DevOps Lead | Azure RBAC export (via `export-azure-rbac.sh`) | Continuous (verified quarterly) | Implemented |
| CC6 | CC6.2 | CC6-07 | MFA is mandatory for all human users on both GitHub (organization-level enforcement) and Azure (conditional access policy). | Preventive | Security Lead | GitHub MFA enforcement status, Azure conditional access policy export | Continuous (verified quarterly) | Implemented |
| CC6 | CC6.3 | CC6-08 | Privileged access reviews conducted quarterly covering GitHub Org Owners, Azure Owners/Contributors, and service principal role assignments. | Detective | Security Lead | Access review sign-off records, `export-github-security-config.sh` and `export-azure-rbac.sh` outputs | Quarterly | Implemented |
| CC6 | CC6.3 | CC6-09 | Standard access reviews conducted semi-annually covering GitHub team memberships and Azure Reader/limited roles. | Detective | Security Lead | Access review sign-off records | Semi-annually | Implemented |

---

## CC7: System Operations

| TSC | Criterion | Control ID | Control Description | Control Type | Control Owner | Evidence Source | Frequency | Implementation Status |
|-----|-----------|------------|---------------------|--------------|---------------|-----------------|-----------|----------------------|
| CC7 | CC7.1 | CC7-01 | Pre-deploy Cosign signature verification confirms that only signed and attested container images are deployed. Deployment is blocked if signature verification fails. | Preventive | DevOps Lead | `cosign-verification.log`, `pipeline-run.json` | Per deployment | Implemented |
| CC7 | CC7.2 | CC7-02 | Vulnerability scanning (Trivy SCA, Trivy image, CodeQL SAST) detects known vulnerabilities in dependencies, container images, and source code. Critical and High findings block the pipeline. | Detective | Security Lead | `dependency-review.json`, `security-report.json` | Per build | Implemented |
| CC7 | CC7.2 | CC7-03 | Dynamic application security testing (OWASP ZAP) scans the deployed application for runtime vulnerabilities. HIGH and CRITICAL findings create security incident issues with SLA targets. | Detective | Security Lead | `zap-report.json`, GitHub Issues | Per deployment | Implemented |
| CC7 | CC7.3 | CC7-04 | SIEM integration for GitHub Audit Log and Azure Activity Log ingestion with alerting rules for security-relevant events. | Detective | Security Lead | SIEM alert logs, dashboard exports | Continuous | Planned |
| CC7 | CC7.4 | CC7-05 | Evidence pack generation (Phase 6) collects all pipeline artifacts, generates a SHA256 checksum manifest, and archives the evidence pack to Azure Blob WORM storage for tamper-evident retention. | Detective | DevOps Lead | Evidence pack ZIP, `manifest.sha256`, Azure Blob metadata | Per release | Implemented |

---

## CC8: Change Management

| TSC | Criterion | Control ID | Control Description | Control Type | Control Owner | Evidence Source | Frequency | Implementation Status |
|-----|-----------|------------|---------------------|--------------|---------------|-----------------|-----------|----------------------|
| CC8 | CC8.1 | CC8-01 | All changes follow a PR-based workflow: developer creates a feature branch, opens a PR, pipeline runs automated checks, two reviewers approve, and merge triggers the full pipeline. | Preventive | DevOps Lead | PR history, GitHub Actions workflow logs, `pipeline-run.json` | Per change | Implemented |
| CC8 | CC8.1 | CC8-02 | Required status checks (security gate, build, test, scan) must pass before a PR can be merged. Branch protection enforces this requirement. | Preventive | Security Lead | Branch protection config, GitHub Actions check results | Per change | Implemented |
| CC8 | CC8.1 | CC8-03 | Post-deployment verification includes smoke tests to confirm the deployed application responds correctly. Deployment failures trigger alerts. | Detective | DevOps Lead | Smoke test logs, `pipeline-run.json` | Per deployment | Implemented |
| CC8 | CC8.1 | CC8-04 | Rollback capability is maintained through container image tagging in ACR (previous versions retained) and Terraform state management for infrastructure changes. | Corrective | DevOps Lead | ACR image tags, Terraform state history | As needed | Implemented |
| CC8 | CC8.1 | CC8-05 | Emergency change procedure defines authorization (CTO verbal approval, written justification within 24 hours), expedited review, and mandatory post-change retrospective within 48 hours. | Corrective | CTO | Emergency change log entries, retrospective records | As needed | Partially Implemented |

---

## CC9: Risk Mitigation

| TSC | Criterion | Control ID | Control Description | Control Type | Control Owner | Evidence Source | Frequency | Implementation Status |
|-----|-----------|------------|---------------------|--------------|---------------|-----------------|-----------|----------------------|
| CC9 | CC9.1 | CC9-01 | SBOM generation (Syft, CycloneDX format) produces a complete software component inventory for every built artifact, enabling supply chain transparency and vulnerability tracking. | Detective | Security Lead | `sbom.cyclonedx.json` | Per build | Implemented |
| CC9 | CC9.1 | CC9-02 | Supply chain signing and provenance: container images are signed with Cosign (keyless OIDC) and SLSA build provenance attestations are generated, providing cryptographic proof of artifact origin. | Preventive | Security Lead | Cosign signature records, `provenance.intoto.jsonl` | Per build | Implemented |
| CC9 | CC9.2 | CC9-03 | Vendor risk register tracks all third-party ICT service providers and open-source tools with risk ratings, criticality classifications, DPA status, and exit plan references. | Detective | CTO | [vendor-risk-register.md](vendor-risk-register.md) | Quarterly review | Implemented |
| CC9 | CC9.2 | CC9-04 | DPA compliance checks verify the data processing agreement status of pipeline processors and flag any vendors with expired or missing DPAs. | Detective | CTO | `dpa-compliance-check.json` | Per release (automated) + quarterly (manual review) | Implemented |
| CC9 | CC9.2 | CC9-05 | Automated dependency updates (Renovate) keep all pipeline dependencies current, with GitHub Actions pinned to full SHA to prevent supply chain attacks through tag mutation. | Preventive | DevOps Lead | Renovate PR history, `renovate.json` configuration | Continuous | Implemented |

---

## PI1: Processing Integrity

| TSC | Criterion | Control ID | Control Description | Control Type | Control Owner | Evidence Source | Frequency | Implementation Status |
|-----|-----------|------------|---------------------|--------------|---------------|-----------------|-----------|----------------------|
| PI1 | PI1.1 | PI1-01 | Unit tests with Jest enforce 80% minimum code coverage. Builds that fail to meet the coverage threshold are rejected. | Preventive | DevOps Lead | Jest coverage report, `pipeline-run.json` | Per build | Implemented |
| PI1 | PI1.2 | PI1-02 | Integration smoke tests verify that the deployed application responds correctly after deployment. Test failures block the pipeline from proceeding to evidence generation. | Detective | DevOps Lead | Smoke test logs, deployment verification output | Per deployment | Implemented |
| PI1 | PI1.3 | PI1-03 | DAST (OWASP ZAP) validates the deployed application against OWASP security benchmarks, testing processing integrity of the running system. | Detective | Security Lead | `zap-report.json` | Per deployment | Implemented |
| PI1 | PI1.4 | PI1-04 | Only Cosign-verified (signed) container images are deployed to production. The deploy phase verifies the image signature before executing Terraform apply. | Preventive | DevOps Lead | `cosign-verification.log`, `pipeline-run.json` | Per deployment | Implemented |
| PI1 | PI1.5 | PI1-05 | Evidence completeness validation checks that all required evidence artifacts are present in the evidence pack before archival. The compliance matrix maps evidence to requirements. | Detective | Security Lead | `compliance-matrix.json`, `manifest.sha256`, evidence pack README | Per release | Implemented |

---

## Control Summary

| TSC Category | Total Controls | Implemented | Partially Implemented | Planned |
|--------------|---------------|-------------|----------------------|---------|
| CC5 (Control Activities) | 5 | 5 | 0 | 0 |
| CC6 (Logical Access) | 9 | 9 | 0 | 0 |
| CC7 (System Operations) | 5 | 4 | 0 | 1 |
| CC8 (Change Management) | 5 | 4 | 1 | 0 |
| CC9 (Risk Mitigation) | 5 | 5 | 0 | 0 |
| PI1 (Processing Integrity) | 5 | 5 | 0 | 0 |
| **Total** | **34** | **32** | **1** | **1** |

---

## Revision History

| Date | Change | Author |
|------|--------|--------|
| 2026-03-15 | Initial version | CyberForge Engineering |

---

## Related Documents

- [SOC 2 System Description](soc2-system-description.md)
- [Control Owners](control-owners.md)
- [Evidence Calendar](evidence-calendar.md)
- [IAM Governance Policy](iam-governance.md)
- [Access Review Procedure](access-review-procedure.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [Scope and Limitations](../compliance/scope-and-limitations.md)
- [Framework Boundaries](../compliance/framework-boundaries.md)
- [Compliance Matrix](../compliance-matrix.md)
