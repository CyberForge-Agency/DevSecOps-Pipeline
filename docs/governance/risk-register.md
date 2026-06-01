# Risk Register

**Document Owner:** Security Lead
**Last Reviewed:** 2026-03-15
**Review Cadence:** Semi-annually for High risks, annually for Medium/Low risks, or after a major incident or significant change
**Version:** 1.0
**ISO 27001 Reference:** Clauses 6.1.2, 8.2

---

## 1. Purpose

This register documents all identified information security risks within the CyberForge ISMS scope. Each risk is assessed using the methodology defined in [risk-assessment-methodology.md](risk-assessment-methodology.md) and tracked through its lifecycle from identification to treatment and residual risk acceptance.

---

## 2. Scope

This register covers risks to the confidentiality, integrity, and availability of information assets within the ISMS scope as defined in [isms-scope.md](isms-scope.md).

---

## 3. Risk Register

| Risk ID | Asset | Threat | Vulnerability / Exposure | Likelihood (1-5) | Impact (1-5) | Risk Score | Risk Level | Treatment | Control Reference | Owner | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| R-001 | Source code repositories | Secret exposure (T-02) | Developers may inadvertently commit API keys, tokens, or passwords to source code | 3 | 5 | 15 | High | Mitigate | TruffleHog secret scanning in Phase 1 Security Gate; pre-commit hooks; `.gitignore` enforcement; [Vulnerability Management Policy](vulnerability-management-policy.md) | Security Lead | Active |
| R-002 | CI/CD pipeline (GitHub Actions) | Supply chain compromise (T-01) | Third-party GitHub Actions or dependencies could be compromised, injecting malicious code into the pipeline | 2 | 5 | 10 | High | Mitigate | All Actions pinned to full SHA; Renovate automated dependency updates with review; SBOM generation; Cosign image signing; [Vendor Risk Register](vendor-risk-register.md) | Security Lead | Active |
| R-003 | Production environment | Unauthorized deployment (T-03) | An actor could bypass pipeline gates and deploy unverified or malicious artifacts to production | 2 | 4 | 8 | Medium | Mitigate | Branch protection (2 reviewers, signed commits, no force push); Cosign signature verification before deploy; CODEOWNERS enforcement; OPA deployment policies | Security Lead | Active |
| R-004 | Evidence packs | Evidence tampering (T-04) | Evidence pack artifacts could be modified or deleted to misrepresent compliance status after generation | 1 | 5 | 5 | Medium | Mitigate | SHA256 checksum manifest (`manifest.sha256`); Azure Blob Storage WORM immutability policy; tamper-evident archival; integrity verification script | Security Lead | Active |
| R-005 | Application dependencies | Dependency vulnerability (T-06) | A critical CVE in a direct or transitive dependency could go undetected and be exploited in production | 3 | 4 | 12 | High | Mitigate | Trivy SCA scanning (Phase 2); Trivy image scanning (Phase 2); Renovate automated updates; [Vulnerability Management Policy](vulnerability-management-policy.md) with SLAs; CodeQL SAST | Security Lead | Active |
| R-006 | Azure OIDC federation | Identity compromise (T-08) | OIDC federation between GitHub Actions and Azure could be compromised through token theft or misconfigured subject claims | 1 | 5 | 5 | Medium | Mitigate | Short-lived tokens (1h maximum); OIDC subject claims scoped to specific repos and branches; least-privilege RBAC; no static credentials; [IAM Governance Policy](iam-governance.md) | Security Lead | Active |
| R-007 | Source code, production environment | Insider threat (T-05) | A trusted insider deploys malicious code by bypassing review controls or abusing privileged access | 1 | 5 | 5 | Medium | Mitigate | 2-reviewer PR requirement; signed commits; CODEOWNERS for sensitive paths; quarterly privileged access review; [Access Review Procedure](access-review-procedure.md); GitHub audit log | CyberForge Management | Active |
| R-008 | Azure infrastructure | Cloud misconfiguration (T-07) | Azure resources are deployed with overly permissive RBAC, public endpoints, missing encryption, or other security misconfigurations | 2 | 4 | 8 | Medium | Mitigate | Checkov IaC scanning (Phase 1); Terraform version-controlled infrastructure; code review of all `infra/` changes; CODEOWNERS enforcement for infrastructure files | Security Lead | Active |
| R-009 | Pipeline operations, governance processes | Key person loss (T-09) | Loss of a critical team member with concentrated knowledge creates operational gaps and single points of failure | 3 | 3 | 9 | Medium | Mitigate | Comprehensive documentation in `docs/`; cross-training between founders; documented runbooks; infrastructure as code (reproducible); [Security Training Program](security-training-program.md) | CyberForge Management | Active |
| R-010 | CI/CD pipeline tools | Third-party discontinuation (T-10) | A key open-source tool (Trivy, Checkov, Syft, etc.) or cloud service is discontinued, abandoned, or materially changes licensing | 2 | 3 | 6 | Medium | Transfer / Accept | Vendor exit plans documented for all 10 vendors in [Vendor Risk Register](vendor-risk-register.md); alternative tools identified; open-source tools with active communities preferred | Security Lead | Active |

---

## 4. Risk Summary by Level

| Risk Level | Count | Risk IDs |
|---|---|---|
| Critical (16-25) | 0 | -- |
| High (10-15) | 3 | R-001, R-002, R-005 |
| Medium (5-9) | 7 | R-003, R-004, R-006, R-007, R-008, R-009, R-010 |
| Low (1-4) | 0 | -- |

---

## 5. Risk Treatment Summary

All High risks require a treatment plan documented in [risk-treatment-plan.md](risk-treatment-plan.md).

Medium risks are treated through existing controls as documented in the Control Reference column. Medium risks are reviewed annually. If residual risk after treatment is Low, the risk is considered adequately controlled.

For risk treatment decisions and acceptance criteria, see [risk-assessment-methodology.md](risk-assessment-methodology.md) Section 9 (Risk Appetite Statement).

---

## 6. Review Schedule

| Activity | Frequency | Responsible |
|---|---|---|
| Full risk register review | Annually | Security Lead with CyberForge Management |
| High risk review | Semi-annually | Security Lead |
| Incremental assessment (triggered by change or incident) | As needed | Security Lead |
| Management approval of risk register updates | Annually (at management review) | CyberForge Management |

---

## 7. How to Add a New Risk

1. Identify the asset, threat, and vulnerability/exposure.
2. Assess likelihood and impact using the scales in [risk-assessment-methodology.md](risk-assessment-methodology.md).
3. Calculate the risk score (Likelihood x Impact) and determine the risk level.
4. Assign the next sequential Risk ID (R-0XX).
5. Document the treatment decision and control references.
6. Assign a risk owner.
7. If the risk is High or Critical, create an entry in [risk-treatment-plan.md](risk-treatment-plan.md).
8. Present the updated register for management review and approval.

---

## 8. Compliance Mapping

| Requirement | Framework Reference |
|---|---|
| Information security risk assessment | ISO 27001 Clause 6.1.2 |
| Operational planning and control (risk) | ISO 27001 Clause 8.2 |
| Risk analysis and information system security policies | NIS2 Art.21.2.a |
| ICT risk management framework | DORA Art.5, Art.16 |
| Risk assessment and mitigation | SOC 2 CC3.1, CC3.2 |

---

## 9. Related Documents

- [Risk Assessment Methodology](risk-assessment-methodology.md)
- [Risk Treatment Plan](risk-treatment-plan.md)
- [Risk Acceptance Process](risk-acceptance-process.md)
- [ISMS Scope](isms-scope.md)
- [Statement of Applicability](statement-of-applicability.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [IAM Governance Policy](iam-governance.md)
- [Access Review Procedure](access-review-procedure.md)

---

## 10. Revision History

| Date | Change | Author |
|---|---|---|
| 2026-03-15 | Initial version with 10 identified risks | CyberForge Security Lead |
