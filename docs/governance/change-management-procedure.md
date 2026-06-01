# Change Management Procedure

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Document Owner   | DevOps Lead                                |
| Approved By      | CyberForge Management                      |
| Version          | 1.0                                        |
| Effective Date   | 2026-03-15                                 |
| Review Cycle     | Annually, or after a significant change process failure |

---

## 1. Purpose

This procedure defines the formal change management process for the CyberForge DevSecOps Pipeline. It ensures that all changes to application code, infrastructure, security configurations, and pipeline workflows are authorized, tested, reviewed, deployed through the pipeline, and evidenced. This procedure satisfies SOC 2 CC8.1 requirements for change management controls.

## 2. Scope

This procedure applies to all changes within the CyberForge DevSecOps Pipeline system boundary as defined in the [SOC 2 System Description](soc2-system-description.md), including:

- Application source code and configuration.
- GitHub Actions workflow files (`.github/workflows/`).
- Terraform infrastructure definitions (`infra/`).
- OPA/Rego compliance policies (`policies/`).
- Dockerfile and container configuration.
- Evidence generation scripts (`scripts/`).
- Governance documentation (`docs/`).

---

## 3. Change Categories

| Category | Examples | Approval Required | Pipeline Execution |
|---|---|---|---|
| Standard | Application code, dependency updates, configuration files | 2 PR reviewers | Full (Phases 1-6) |
| Infrastructure | Terraform modules, Azure resource definitions, networking changes | 2 PR reviewers + security team (via CODEOWNERS) | Full (Phases 1-6) |
| Security-sensitive | Workflow files, OPA policies, Dockerfile, CODEOWNERS, branch protection changes | 2 PR reviewers + security team (via CODEOWNERS) | Full (Phases 1-6) |
| Emergency | Active incident hotfixes, critical production failures | CTO verbal approval + written justification within 24 hours | Expedited (see Section 6) |

### Category Determination

The change category is determined automatically by the files affected:

- Changes to `.github/workflows/`, `infra/`, `policies/`, or `Dockerfile` are classified as **Infrastructure** or **Security-sensitive** and trigger CODEOWNERS review requirements.
- All other code changes default to **Standard**.
- **Emergency** classification is a manual override applied only in the circumstances defined in Section 6.

---

## 4. Standard Change Process

The standard change process applies to Standard, Infrastructure, and Security-sensitive categories. The only difference between these categories is the reviewer requirements (defined by CODEOWNERS).

### Step-by-Step Process

| Step | Phase | Action | Actor | Gate |
|---|---|---|---|---|
| 1 | Pre-pipeline | Developer creates a feature branch from `main` | Developer | -- |
| 2 | Pre-pipeline | Developer opens a Pull Request to `main` | Developer | -- |
| 3 | Phase 1: Security Gate | Pre-merge checks auto-execute: secret scanning (TruffleHog), IaC scanning (Checkov), linting (MegaLinter), PII detection, commit signature verification | Pipeline (automated) | PR blocked if any check fails |
| 4 | Phase 2: Build and Scan | Compilation, unit tests (80% coverage gate), SAST (CodeQL), SCA (Trivy), container image scanning (Trivy) | Pipeline (automated) | PR blocked if any check fails |
| 5 | Pre-merge | Two reviewers approve the PR. For security-sensitive paths, CODEOWNERS enforces security team review | Reviewers | PR blocked until approval count met |
| 6 | Pre-merge | Signed commits verified. Unsigned commits are rejected by branch protection | Branch protection (automated) | PR blocked if commits unsigned |
| 7 | Merge | PR is merged to `main`. Merge triggers the full deployment pipeline | Developer (after approvals) | -- |
| 8 | Phase 3: Sign and Attest | SBOM generation (Syft), cryptographic image signing (Cosign), SLSA build provenance attestation | Pipeline (automated) | Pipeline fails if signing fails |
| 9 | Phase 4: Deploy | Pre-deploy Cosign signature verification, Terraform infrastructure apply, container deployment, smoke test | Pipeline (automated) | Pipeline fails if verification or smoke test fails |
| 10 | Phase 5: DAST | Dynamic application security testing (OWASP ZAP) against deployed application | Pipeline (automated) | HIGH/CRITICAL findings create security incident issues |
| 11 | Phase 6: Evidence Pack | Evidence collection, SHA256 checksum manifest, compliance matrix, immutable archival to Azure Blob WORM storage | Pipeline (automated) | Pipeline fails if evidence pack generation fails |
| 12 | Complete | Change is fully deployed and evidenced | -- | -- |

### Controls Enforced at Each Stage

- **Branch protection** prevents direct pushes to `main`, force pushes, and merges without required reviews and status checks.
- **CODEOWNERS** ensures the correct reviewers are required for each file path.
- **Pipeline gates** (Phases 1-2) block non-compliant code from being merged.
- **Deployment gates** (Phases 3-4) block unsigned or unverified artifacts from being deployed.
- **Evidence archival** (Phase 6) creates an immutable audit trail for every change.

---

## 5. Rollback Procedure

Rollback is a change and must be documented through the standard change process where time permits.

### Application Rollback

1. Identify the previous known-good container image tag in Azure Container Registry (ACR).
2. Open a PR that updates the deployment configuration to reference the previous image tag.
3. If time permits, follow the standard PR process (review, merge, pipeline execution).
4. If time does not permit (active incident), follow the Emergency Change Process (Section 6) and deploy the previous image directly.

### Infrastructure Rollback

1. Identify the previous Terraform state or configuration version in Git history.
2. Open a PR that reverts the Terraform changes.
3. Follow the standard PR process. Terraform plan output will show the rollback changes for reviewer verification.
4. If time does not permit, follow the Emergency Change Process.

### Post-Rollback Requirements

- Verify the rollback resolved the issue (smoke tests, manual verification).
- Document the rollback in the incident record or change log.
- If the rollback was performed via Emergency Change Process, complete the post-change requirements in Section 6.

---

## 6. Emergency Change Process

### Definition

An emergency change is authorized only when:

- An **active security incident** requires immediate remediation (e.g., exploitation of a known vulnerability, credential compromise).
- A **critical production failure** is causing service disruption that cannot wait for the standard review process.

Emergency changes should be rare. Frequent use of the emergency process indicates a systemic issue that must be addressed.

### Authorization

| Step | Action | Responsible |
|---|---|---|
| 1 | Verbal authorization from the CTO | CTO |
| 2 | Written justification documenting the incident, proposed change, and risk assessment | Change author |
| 3 | Written justification filed within 24 hours of the verbal authorization | Change author |

### Expedited Process

| Step | Action | Notes |
|---|---|---|
| 1 | Developer creates the hotfix branch | Standard branch from `main` |
| 2 | Developer opens a PR with the `emergency` label | Label triggers expedited review path |
| 3 | Single reviewer approves (instead of the standard two reviewers) | Reviewer should be someone other than the change author |
| 4 | Pipeline executes (Phases 1-6 still run) | If pipeline must be bypassed due to urgency, document the justification |
| 5 | Merge and deploy | Standard merge process |

If the situation is so urgent that even the expedited PR process is too slow:

- Direct push to `main` may be authorized by the CTO as a last resort.
- This must be documented immediately with a full justification.
- A follow-up PR must be created within 24 hours to run the full pipeline against the change.

### Post-Emergency Requirements

| Requirement | Deadline | Responsible |
|---|---|---|
| Written justification filed | Within 24 hours | Change author |
| Retrospective conducted | Within 48 hours | Security Lead + CTO |
| Full pipeline validation of the change | Within 48 hours | DevOps Lead |
| Incident record updated with change details | Within 48 hours | Security Lead |
| Process improvement actions identified | At retrospective | Security Lead + CTO |

### Tracking

Emergency changes are tracked with the `emergency` label in GitHub Issues. The frequency of emergency changes is reported in the monthly pipeline health review. A high frequency of emergency changes (more than 2 per quarter) triggers a process review.

---

## 7. Change Records and Evidence

Every change produces the following evidence trail:

| Evidence | Source | Retention |
|---|---|---|
| PR history (description, reviews, comments, approvals) | GitHub | Indefinite (Git history) |
| Pipeline execution logs (Phases 1-6) | GitHub Actions | Per GitHub retention policy |
| Security scan results | `security-report.json`, `dependency-review.json`, `zap-report.json` | Archived in evidence pack (WORM) |
| Cosign signature and provenance | Rekor transparency log, `provenance.intoto.jsonl` | Archived in evidence pack (WORM) |
| Evidence pack with checksum manifest | Azure Blob Storage (WORM) | Per WORM immutability policy (minimum 3 years) |
| Emergency change justifications | GitHub Issues with `emergency` label | Minimum 3 years |

---

## 8. Separation of Duties

The change management process enforces separation of duties through the following controls:

| Control | Enforcement Mechanism |
|---|---|
| No self-approval | Branch protection requires minimum 2 reviewers; the PR author cannot be a reviewer |
| Security team review for sensitive paths | CODEOWNERS file enforces mandatory security team review |
| No self-merge without review | Branch protection blocks merge without required approvals |
| Signed commits | Branch protection requires cryptographic commit signatures |
| Pipeline gates cannot be bypassed | Required status checks must pass before merge is allowed |

For the startup dual-role considerations and compensating controls, see [Control Owners](control-owners.md) Section 4.

---

## 9. Compliance Mapping

| Requirement | Framework Reference | How This Procedure Addresses It |
|---|---|---|
| Change management controls | SOC 2 CC8.1 | Full PR-based workflow with automated gates, review requirements, and evidence archival |
| Authorized changes only | SOC 2 CC8.1 | Branch protection, reviewer approvals, CODEOWNERS enforcement |
| Emergency changes controlled | SOC 2 CC8.1 | Defined emergency process with authorization, justification, and retrospective |
| Secure system development | ISO 27001 A.8.32 | Security scanning at every pipeline phase, mandatory security review for sensitive paths |
| ICT change management | DORA Art.16.1.a | Formal change process with audit trail and evidence |
| ICT system updates | DORA Art.16.1.a | Pipeline enforces security testing before deployment |
| Secure development practices | NIS2 Art.21.2.e | Automated security gates, code review, signed commits |

---

## 10. Procedure Review

This procedure is reviewed:

- **Annually** as part of the governance review cycle.
- **After any significant change process failure** (e.g., unauthorized change, bypassed gate, failed rollback).
- **After any emergency change retrospective** that identifies process improvements.

Changes to this procedure require approval from the DevOps Lead and CyberForge Management.

---

## Revision History

| Date | Change | Author |
|------|--------|--------|
| 2026-03-15 | Initial version | CyberForge Engineering |

---

## Related Documents

- [SOC 2 Control Matrix](soc2-control-matrix.md)
- [SOC 2 System Description](soc2-system-description.md)
- [Control Owners](control-owners.md)
- [Evidence Calendar](evidence-calendar.md)
- [IAM Governance Policy](iam-governance.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Access Review Schedule](access-review-schedule.md)
