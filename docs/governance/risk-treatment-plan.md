# Risk Treatment Plan

**Document Owner:** Security Lead
**Last Reviewed:** 2026-03-15
**Review Cadence:** Semi-annually, aligned with High risk review schedule
**Version:** 1.0
**ISO 27001 Reference:** Clauses 6.1.3, 8.3

---

## 1. Purpose

This document details the risk treatment plans for all High and Critical risks identified in the [Risk Register](risk-register.md). Each plan specifies the selected treatment option, the controls implemented to reduce risk, the residual risk after treatment, measurable effectiveness indicators, and the responsible owner.

Treatment plans are developed using the methodology and risk appetite defined in [risk-assessment-methodology.md](risk-assessment-methodology.md).

---

## 2. Scope

This plan covers risks R-001, R-002, and R-005, which are the three High-level risks identified in the current risk register. No Critical-level risks have been identified at this time.

Medium-level risks (R-003, R-004, R-006, R-007, R-008, R-009, R-010) are treated through existing controls documented in the risk register and are reviewed annually. If any Medium risk is re-assessed as High or Critical, a treatment plan entry must be created in this document.

---

## 3. Treatment Plans

### 3.1 R-001: Secret Exposure in Source Code

| Field | Detail |
|---|---|
| **Risk ID** | R-001 |
| **Risk Description** | Developers may inadvertently commit API keys, tokens, or passwords to source code repositories |
| **Inherent Risk** | Likelihood 3 x Impact 5 = 15 (High) |
| **Treatment Option** | Mitigate |

#### Controls Implemented

| Control | Description | Implementation Reference |
|---|---|---|
| C-001.1 | TruffleHog secret scanning runs as part of the Security Gate phase on every pull request and push to protected branches. The pipeline fails if any secret is detected. | `.github/workflows/security-gate.yml` |
| C-001.2 | Pre-commit hooks configured to run TruffleHog locally before code reaches the remote repository. Developer onboarding includes hook installation. | `docs/governance/security-hygiene-baseline.md` |
| C-001.3 | `.gitignore` enforcement for common secret file patterns (`.env`, `*.pem`, `credentials.json`, `*.key`). CODEOWNERS requires Security Lead approval for `.gitignore` modifications. | Repository `.gitignore`, `CODEOWNERS` |
| C-001.4 | Vulnerability Management Policy defines SLAs for secret exposure incidents: immediate revocation within 1 hour, root cause analysis within 24 hours. | `docs/governance/vulnerability-management-policy.md` |
| C-001.5 | GitHub Advanced Security secret scanning (push protection) enabled at the organization level as an additional detection layer. | GitHub organization settings |
| C-001.6 | Zero static credentials architecture: all pipeline authentication uses OIDC federation with short-lived tokens. No long-lived secrets stored in GitHub Actions secrets. | `docs/governance/iam-governance.md` |

#### Residual Risk Assessment

| Factor | Inherent | Residual | Justification |
|---|---|---|---|
| Likelihood | 3 (Possible) | 1 (Rare) | Multi-layer detection (pre-commit, Security Gate, GitHub push protection) makes undetected secret commit extremely unlikely. OIDC-only architecture eliminates the most common secret types. |
| Impact | 5 (Catastrophic) | 3 (Moderate) | Short-lived OIDC tokens limit blast radius. Immediate revocation SLA (1 hour) limits exposure window. However, some secret types (third-party API keys) could still cause significant damage if exposed. |
| **Residual Score** | **15 (High)** | **3 (Low)** | Within risk appetite. No further treatment required. |

#### Effectiveness Indicators

| Metric | Target | Measurement Method | Frequency |
|---|---|---|---|
| TruffleHog pass rate | 100% of pipeline runs pass with no secrets detected | Pipeline run statistics from GitHub Actions | Monthly |
| Secret incidents | 0 confirmed secret exposures per quarter | Incident log review | Quarterly |
| Pre-commit hook adoption | 100% of developers have hooks installed | Developer workstation audit | Semi-annually |
| Mean time to revocation | Less than 1 hour from detection | Incident response records | Per incident |

#### Review Schedule

| Activity | Frequency | Responsible |
|---|---|---|
| Control effectiveness review | Semi-annually | Security Lead |
| TruffleHog rule updates | Quarterly (or as new patterns emerge) | Security Lead |
| Full risk re-assessment | Annually | Security Lead with CyberForge Management |

**Owner:** Security Lead

---

### 3.2 R-002: Supply Chain Compromise

| Field | Detail |
|---|---|
| **Risk ID** | R-002 |
| **Risk Description** | Third-party GitHub Actions or dependencies could be compromised, injecting malicious code into the pipeline |
| **Inherent Risk** | Likelihood 2 x Impact 5 = 10 (High) |
| **Treatment Option** | Mitigate |

#### Controls Implemented

| Control | Description | Implementation Reference |
|---|---|---|
| C-002.1 | All GitHub Actions pinned to full SHA (not tags). This prevents tag-based supply chain attacks where an attacker overwrites a tag with a compromised version. | `.github/workflows/*.yml` (all workflow files) |
| C-002.2 | Renovate automated dependency update management with mandatory code review before merge. Updates are submitted as PRs, not auto-merged. | Renovate configuration, branch protection rules |
| C-002.3 | SBOM (Software Bill of Materials) generated for every container image build using Syft. Provides transparency into all dependencies included in production artifacts. | `.github/workflows/build-and-scan.yml` |
| C-002.4 | Cosign keyless signing of all container images. Signature verification is enforced before deployment. | `.github/workflows/sign-and-attest.yml` |
| C-002.5 | Trivy SCA (Software Composition Analysis) scanning of all dependencies for known vulnerabilities on every build. | `.github/workflows/build-and-scan.yml` |
| C-002.6 | Vendor Risk Register maintains a complete inventory of all third-party tools and services with risk ratings, alternative tools, and exit plans. | `docs/governance/vendor-risk-register.md` |
| C-002.7 | OPA deployment gate policy enforces that only signed, scanned, and attested artifacts can be deployed. | `policies/deployment-gate.rego` |
| C-002.8 | Trivy container image scanning checks the final built image for vulnerabilities in OS packages and application dependencies. | `.github/workflows/build-and-scan.yml` |

#### Residual Risk Assessment

| Factor | Inherent | Residual | Justification |
|---|---|---|---|
| Likelihood | 2 (Unlikely) | 1 (Rare) | SHA pinning eliminates tag-based attacks. Renovate with review prevents automated introduction of compromised updates. SBOM and image scanning detect known-bad dependencies. |
| Impact | 5 (Catastrophic) | 3 (Moderate) | Cosign signature verification and OPA deployment gates prevent unsigned artifacts from reaching production. SBOM enables rapid identification of affected builds if a compromised dependency is later discovered. However, a sophisticated zero-day supply chain attack could still cause moderate damage before detection. |
| **Residual Score** | **10 (High)** | **3 (Low)** | Within risk appetite. No further treatment required. |

#### Effectiveness Indicators

| Metric | Target | Measurement Method | Frequency |
|---|---|---|---|
| SHA pinning compliance | 100% of Actions pinned to SHA | Automated workflow linting | Per PR |
| SBOM generation rate | 100% of container builds include SBOM | Pipeline run statistics | Monthly |
| Image signature verification | 100% of deployments verified against Cosign signature | Deployment logs | Per deployment |
| Dependency update review SLA | 100% of Renovate PRs reviewed within 7 days | GitHub PR metrics | Monthly |
| Vendor risk register currency | All vendors reviewed within last quarter | Vendor Risk Register review date | Quarterly |

#### Review Schedule

| Activity | Frequency | Responsible |
|---|---|---|
| Control effectiveness review | Semi-annually | Security Lead |
| Vendor Risk Register review | Quarterly | Security Lead |
| Supply chain threat intelligence review | Quarterly | Security Lead |
| Full risk re-assessment | Annually | Security Lead with CyberForge Management |

**Owner:** Security Lead

---

### 3.3 R-005: Dependency Vulnerability

| Field | Detail |
|---|---|
| **Risk ID** | R-005 |
| **Risk Description** | A critical CVE in a direct or transitive dependency could go undetected and be exploited in production |
| **Inherent Risk** | Likelihood 3 x Impact 4 = 12 (High) |
| **Treatment Option** | Mitigate |

#### Controls Implemented

| Control | Description | Implementation Reference |
|---|---|---|
| C-005.1 | Trivy SCA scanning on every build detects known vulnerabilities in application dependencies (direct and transitive). Pipeline fails on Critical/High severity findings. | `.github/workflows/build-and-scan.yml` |
| C-005.2 | Trivy container image scanning checks the final container image for OS-level and application-level vulnerabilities. | `.github/workflows/build-and-scan.yml` |
| C-005.3 | CodeQL SAST analysis identifies code-level security issues that may arise from vulnerable dependency usage patterns. | `.github/workflows/build-and-scan.yml` |
| C-005.4 | Renovate automated dependency updates ensure dependencies are kept current. Automated PRs are generated when new versions are available. | Renovate configuration |
| C-005.5 | Vulnerability Management Policy defines severity-based SLAs: Critical (24h), High (7d), Medium (30d), Low (90d). | `docs/governance/vulnerability-management-policy.md` |
| C-005.6 | OWASP ZAP DAST scanning in Phase 5 detects runtime-exploitable vulnerabilities that may originate from dependency issues. | `.github/workflows/dast.yml` |

#### Residual Risk Assessment

| Factor | Inherent | Residual | Justification |
|---|---|---|---|
| Likelihood | 3 (Possible) | 1 (Rare) | Multi-layer scanning (SCA, image, SAST, DAST) across multiple pipeline phases provides defense in depth. Renovate keeps dependencies current, reducing the window of exposure to known CVEs. |
| Impact | 4 (Major) | 2 (Minor) | SLA-driven remediation limits exposure window. Pipeline gates prevent deployment of images with unresolved Critical/High CVEs. SBOM enables rapid impact assessment when new CVEs are disclosed. |
| **Residual Score** | **12 (High)** | **2 (Low)** | Within risk appetite. No further treatment required. |

#### Effectiveness Indicators

| Metric | Target | Measurement Method | Frequency |
|---|---|---|---|
| Vulnerability SLA compliance | 95% or higher of vulnerabilities remediated within SLA | Vulnerability tracking metrics | Monthly |
| Trivy scan pass rate | 100% of builds scanned; 0 Critical/High CVEs in deployed images | Pipeline run statistics | Per build |
| Dependency currency | Less than 5% of dependencies more than 2 minor versions behind | Renovate dashboard | Monthly |
| Mean time to remediation (Critical) | Less than 24 hours | Vulnerability tracking log | Per incident |
| DAST scan coverage | 100% of deployments followed by DAST scan | Pipeline run statistics | Per deployment |

#### Review Schedule

| Activity | Frequency | Responsible |
|---|---|---|
| Control effectiveness review | Semi-annually | Security Lead |
| Vulnerability SLA compliance audit | Monthly | Security Lead |
| Trivy database freshness verification | Weekly (automated) | Automated / Security Lead |
| Full risk re-assessment | Annually | Security Lead with CyberForge Management |

**Owner:** Security Lead

---

## 4. Treatment Plan Summary

| Risk ID | Inherent Score | Treatment | Residual Score | Residual Level | Status |
|---|---|---|---|---|---|
| R-001 | 15 (High) | Mitigate | 3 (Low) | Accepted | Active -- controls operational |
| R-002 | 10 (High) | Mitigate | 3 (Low) | Accepted | Active -- controls operational |
| R-005 | 12 (High) | Mitigate | 2 (Low) | Accepted | Active -- controls operational |

All residual risks are within the CyberForge risk appetite as defined in the [Risk Assessment Methodology](risk-assessment-methodology.md) Section 9.

---

## 5. Approval

Risk treatment plans are approved by CyberForge Management during the management review cycle. Changes to treatment plans require re-approval.

| Role | Name | Date | Signature |
|---|---|---|---|
| Security Lead | ___________________ | ___________________ | ___________________ |
| CyberForge Management | ___________________ | ___________________ | ___________________ |

---

## 6. Compliance Mapping

| Requirement | Framework Reference |
|---|---|
| Information security risk treatment | ISO 27001 Clause 6.1.3 |
| Operational planning and control | ISO 27001 Clause 8.3 |
| Risk analysis and information system security policies | NIS2 Art.21.2.a |
| ICT risk management framework | DORA Art.5, Art.16 |
| Risk mitigation | SOC 2 CC3.2 |

---

## 7. Related Documents

- [Risk Register](risk-register.md)
- [Risk Assessment Methodology](risk-assessment-methodology.md)
- [Risk Acceptance Process](risk-acceptance-process.md)
- [Statement of Applicability](statement-of-applicability.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [IAM Governance Policy](iam-governance.md)

---

## 8. Revision History

| Date | Change | Author |
|---|---|---|
| 2026-03-15 | Initial version with treatment plans for R-001, R-002, R-005 | CyberForge Security Lead |
