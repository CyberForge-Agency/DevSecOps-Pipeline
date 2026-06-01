# Security Training Program

**Document Owner:** CyberForge Management
**Last Reviewed:** 2026-03-15
**Review Cadence:** Annually, or after significant changes to roles, tools, or regulatory requirements
**Version:** 1.0
**ISO 27001 Reference:** Clauses 7.2, 7.3

---

## 1. Purpose

This document defines the security training and awareness program for all CyberForge personnel. The program ensures that all personnel:

- Are competent to perform their information security responsibilities.
- Are aware of the ISMS, information security policies, and their individual contributions to ISMS effectiveness.
- Receive role-specific training on the tools, technologies, and processes relevant to their function.
- Fulfill the management training obligations required by NIS2 Art.20.

---

## 2. Scope

This program applies to:

- All CyberForge employees (including founders).
- Contractors and temporary personnel with access to CyberForge systems.
- Management body members (for NIS2 Art.20 compliance).

---

## 3. Training Types

### 3.1 Security Awareness Training

| Field | Detail |
|---|---|
| **Audience** | All personnel |
| **Frequency** | Annually (with onboarding for new joiners) |
| **Duration** | 2--4 hours |
| **Format** | Online course with knowledge assessment |
| **Assessment** | Multiple-choice quiz; 80% pass threshold |

**Topics covered:**

- Information security principles (confidentiality, integrity, availability)
- CyberForge ISMS overview and security policies
- Password and authentication hygiene (MFA, no shared credentials)
- Phishing and social engineering recognition
- Acceptable use of information assets
- Incident reporting procedures
- Data classification and handling
- Remote working security requirements
- Supply chain security awareness
- RODO/GDPR personal data protection basics

### 3.2 Role-Specific Training: Secure Coding and CI/CD Security

| Field | Detail |
|---|---|
| **Audience** | Developers, security engineers, pipeline operators |
| **Frequency** | Annually, and when new tools or frameworks are adopted |
| **Duration** | 4--8 hours |
| **Format** | Hands-on workshop with practical exercises |
| **Assessment** | Practical exercise: identify and fix vulnerabilities in sample code; configure a secure pipeline |

**Topics covered:**

- OWASP Top 10 and common vulnerability patterns
- Secure coding practices (input validation, output encoding, parameterized queries)
- Secret management (OIDC federation, Key Vault, no hardcoded credentials)
- Dependency management and supply chain security (SHA pinning, SBOM, Renovate)
- Container security (minimal base images, non-root execution, image scanning)
- Infrastructure as code security (Checkov, Terraform best practices)
- Code review for security (what to look for in PR reviews)
- Vulnerability triage and remediation (SLA compliance)
- Signed commits and artifact attestation (Cosign, Sigstore)

### 3.3 Tool-Specific Training

| Field | Detail |
|---|---|
| **Audience** | Personnel who directly operate or configure the tool |
| **Frequency** | Upon onboarding, and when tools are upgraded or replaced |
| **Duration** | 1--2 hours per tool |
| **Format** | Hands-on lab or vendor documentation walkthrough |
| **Assessment** | Practical: demonstrate correct tool configuration and output interpretation |

**Tools covered:**

| Tool | Training Focus |
|---|---|
| **GitHub** (Actions, Advanced Security, organization administration) | Workflow authoring, SHA pinning, branch protection, CODEOWNERS, secret scanning, audit log review |
| **Azure** (Entra ID, ACR, Container Apps, Key Vault, Blob Storage) | OIDC federation setup, RBAC configuration, Key Vault secret/key management, WORM policy configuration |
| **Trivy** | SCA and image scanning configuration, severity filtering, database management, CI integration |
| **Checkov** | IaC policy scanning, custom check authoring, baseline management |
| **TruffleHog** | Secret detection configuration, custom detectors, pre-commit hook setup |
| **Cosign** | Keyless signing setup, signature verification, attestation workflows |
| **Syft** | SBOM generation, output format configuration, integration with Grype |
| **OPA/Rego** | Policy authoring, testing with `opa test`, deployment gate integration |
| **CodeQL** | Query suite configuration, custom query authoring, result interpretation |
| **OWASP ZAP** | DAST scan configuration, baseline profiles, result interpretation |
| **Terraform** | State management, module usage, plan/apply workflow, drift detection |

### 3.4 Management Training (NIS2 Art.20)

| Field | Detail |
|---|---|
| **Audience** | All management body members (founders) |
| **Frequency** | Annually |
| **Duration** | 4--8 hours |
| **Format** | Structured training session (internal or external provider) |
| **Assessment** | Documented completion; optional certification |

**Topics covered:**

- NIS2 Art.20 obligations for management bodies
- Cybersecurity risk management principles
- ISMS governance and management review responsibilities
- Risk assessment methodology and risk appetite
- Incident management and regulatory reporting obligations (NIS2, DORA, RODO)
- Supply chain security oversight
- Business continuity and crisis management
- Legal and regulatory landscape (NIS2, DORA, RODO/GDPR, ISO 27001)
- Management liability under NIS2

Training records for management are maintained in [NIS2 Management Training Records](nis2-management-training-records.md).

---

## 4. New Joiner Induction

All new personnel must complete security induction within their first week of employment or engagement. The induction program includes:

| Day | Activity | Duration | Responsible |
|---|---|---|---|
| Day 1 | ISMS overview: scope, policies, security objectives | 1 hour | Security Lead |
| Day 1 | Account provisioning and MFA setup (per [JML Process](jml-process.md)) | 30 minutes | Security Lead |
| Day 1 | Security hygiene baseline walkthrough ([security-hygiene-baseline.md](security-hygiene-baseline.md)) | 30 minutes | Security Lead |
| Day 1--3 | Security awareness training (Section 3.1) | 2--4 hours | Self-paced with assessment |
| Day 1--5 | Tool-specific training for assigned tools (Section 3.3) | 1--2 hours per tool | Buddy / Security Lead |
| Day 3--5 | Role-specific training: secure coding and CI/CD security (Section 3.2) | 4--8 hours | Security Lead |
| Day 5 | Induction completion confirmation and records update | 15 minutes | Security Lead |

New joiners must not be granted access to production systems or sensitive repositories until security awareness training and relevant tool-specific training are completed.

---

## 5. Training Records

### 5.1 Training Records Template

| Date | Name | Training | Provider | Duration | Assessment | Evidence |
|---|---|---|---|---|---|---|
| | | | | | | |
| | | | | | | |
| | | | | | | |

**Field definitions:**

| Field | Description |
|---|---|
| **Date** | Date training was completed |
| **Name** | Full name of the trainee |
| **Training** | Training type and title (e.g., "Security Awareness 2026", "Trivy Tool Training") |
| **Provider** | Internal (Security Lead) or external provider name |
| **Duration** | Actual duration in hours |
| **Assessment** | Assessment type and result (e.g., "Quiz: 90%", "Practical: Pass", "Attendance confirmed") |
| **Evidence** | Reference to evidence artifact (certificate, quiz result export, attendance record, screenshot) |

### 5.2 Records Storage and Retention

| Record Type | Storage Location | Retention Period |
|---|---|---|
| Training completion records | `docs/governance/training-records/` | 5 years after the training date |
| Assessment results | `docs/governance/training-records/` | 5 years after the training date |
| NIS2 management training records | `docs/governance/nis2-management-training-records.md` | 5 years after the training date |
| Certificates (external training) | `docs/governance/training-records/` | 5 years after the training date |
| Induction completion confirmations | `docs/governance/training-records/` | Duration of employment plus 2 years |

---

## 6. Assessment Methods

| Training Type | Assessment Method | Pass Criteria |
|---|---|---|
| Security awareness | Multiple-choice quiz (online) | 80% correct answers |
| Secure coding / CI/CD security | Practical exercise (identify and remediate vulnerabilities) | All critical vulnerabilities identified and correctly remediated |
| Tool-specific | Practical demonstration (configure tool, interpret output) | Correct configuration and accurate interpretation demonstrated |
| Management (NIS2 Art.20) | Documented completion; optional external certification | Completion confirmed by training provider |

Personnel who do not meet the pass criteria must retake the training within 2 weeks. If a second attempt is unsuccessful, the Security Lead and management will determine an individualized training plan.

---

## 7. Training Effectiveness Evaluation

The training program is evaluated annually using the following indicators:

| Indicator | Target | Measurement |
|---|---|---|
| Training completion rate | 100% of required training completed on schedule | Training records review |
| Assessment pass rate (first attempt) | 90% or higher | Assessment results analysis |
| Security incident rate attributable to human error | Decreasing trend year-over-year | Incident root cause analysis |
| Phishing simulation click rate (if implemented) | Less than 10% | Phishing simulation results |
| New joiner induction completion within first week | 100% | Induction records |

Results are reported at management reviews ([management-review-template.md](management-review-template.md)).

---

## 8. Compliance Mapping

| Requirement | Framework Reference |
|---|---|
| Competence | ISO 27001 Clause 7.2 |
| Awareness | ISO 27001 Clause 7.3 |
| Information security awareness, education and training | ISO 27001 Annex A, A.6.3 |
| Management body training | NIS2 Art.20(2) |
| Regular training for employees | NIS2 Art.20(2) |
| Staff awareness and training | DORA Art.13.6 |
| Security awareness training | SOC 2 CC1.4 |

---

## 9. Related Documents

- [ISMS Scope](isms-scope.md)
- [Security Hygiene Baseline](security-hygiene-baseline.md)
- [NIS2 Management Training Records](nis2-management-training-records.md)
- [JML Process](jml-process.md)
- [IAM Governance Policy](iam-governance.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Crisis Management Plan](crisis-management-plan.md)
- [Internal Audit Program](internal-audit-program.md)

---

## 10. Revision History

| Date | Change | Author |
|---|---|---|
| 2026-03-15 | Initial version | CyberForge Management |
