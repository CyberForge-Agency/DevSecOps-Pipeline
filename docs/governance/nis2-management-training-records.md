# NIS2 Management Training Records

| Field          | Value                                                    |
|----------------|----------------------------------------------------------|
| Document Owner | CTO                                                      |
| Approved By    | CyberForge Management                                    |
| Version        | 1.0                                                      |
| Effective Date | 2026-03-15                                               |
| Review Cycle   | Annually, or after changes to management composition     |
| Compliance     | NIS2 Art.20, DORA Art.5, ISO 27001 Clause 7.2, SOC 2 CC1 |

---

## 1. Purpose

This document tracks cybersecurity training obligations for CyberForge management bodies as required by NIS2 Art.20. It ensures that all members of management have sufficient cybersecurity knowledge to approve and oversee risk-management measures, and that training completion is evidenced for audit and regulatory purposes.

---

## 2. Regulatory Basis

### NIS2 Art.20 -- Governance

NIS2 Art.20(1) states:

> "Member States shall ensure that the members of the management bodies of essential and important entities approve the cybersecurity risk-management measures taken by those entities in order to comply with Article 21, oversee its implementation and can be held liable for infringements by those entities of that Article."

NIS2 Art.20(2) states:

> "Member States shall ensure that the members of the management bodies of essential and important entities are required to follow training, and shall encourage essential and important entities to offer similar training to their employees on a regular basis, in order to gain sufficient knowledge and skills to enable them to identify risks and assess cybersecurity risk-management practices and their impact on the services provided by the entity."

### Key Implications for CyberForge

1. **Personal liability:** Management body members can be held personally liable for infringements of NIS2 Art.21 (cybersecurity risk-management measures).
2. **Mandatory training:** Management must follow cybersecurity training -- this is not optional.
3. **Sufficient knowledge:** Training must enable management to identify risks and assess the impact of cybersecurity risk-management practices on services.
4. **Employee training encouraged:** NIS2 encourages (but does not mandate at the same level) similar training for all employees. CyberForge addresses this through the [Security Training Program](security-training-program.md) (Task 29) and the [Security Hygiene Baseline](security-hygiene-baseline.md).

### DORA Art.5 -- Complementary Requirement

DORA Art.5 requires that the management body of financial entities (and their ICT service providers, where applicable) "approve and periodically review" ICT risk management frameworks. While CyberForge is not a financial entity, its clients may be, making management competence a supply chain trust requirement.

---

## 3. Training Requirements for CyberForge Management

Management body members at CyberForge currently comprise the CTO (co-founder) and the Security Lead (co-founder). As the organization grows, all persons serving in management roles with decision-making authority over cybersecurity measures must complete the training requirements below.

| Training Area              | Description                                                              | Target Audience    | Frequency | Provider                 |
|----------------------------|--------------------------------------------------------------------------|--------------------|-----------|--------------------------|
| Cybersecurity fundamentals | Threats, attacks, defense strategies relevant to DevSecOps and software supply chains | All management     | Annual    | Internal or external     |
| Regulatory obligations     | DORA, NIS2, ISO 27001, SOC 2 requirements and CyberForge's specific obligations | All management     | Annual    | Internal + legal counsel |
| Risk management            | ICT risk assessment, treatment, appetite, and management oversight responsibilities | All management     | Annual    | Internal                 |
| Incident management        | Classification, escalation, regulatory notification obligations and timelines | All management     | Annual    | Internal                 |
| Supply chain security      | Third-party risk, supply chain attacks, controls, and vendor management | All management     | Annual    | Internal                 |
| Data protection            | GDPR basics, DPA requirements, breach notification obligations          | All management     | Annual    | Internal + DPO/legal     |

### Training Content Guidelines

Training must cover, at minimum:

**Cybersecurity fundamentals:**
- Current threat landscape relevant to CI/CD pipelines and software supply chains
- Common attack vectors: dependency confusion, typosquatting, compromised GitHub Actions, credential theft
- Defense-in-depth strategies implemented in the CyberForge pipeline
- Zero-trust principles and their application in cloud-native environments

**Regulatory obligations:**
- NIS2 scope, obligations, and enforcement (including Polish implementation timeline)
- DORA ICT risk management and third-party oversight requirements
- ISO 27001 ISMS requirements and certification process
- SOC 2 Trust Services Criteria and attestation process
- GDPR obligations relevant to CyberForge's processing activities

**Risk management:**
- CyberForge's [Risk Assessment Methodology](risk-assessment-methodology.md)
- Risk appetite definition and application
- Risk treatment options and residual risk acceptance
- Management's role in risk oversight and approval

**Incident management:**
- CyberForge's [Crisis Management Plan](crisis-management-plan.md)
- Incident classification and escalation procedures
- Regulatory notification timelines: NIS2 (24h/72h/1mo), DORA (4h/72h/1mo), GDPR (72h)
- Evidence preservation and post-incident review

**Supply chain security:**
- CyberForge's [Vendor Risk Register](vendor-risk-register.md) and third-party risk management process
- Software supply chain attack patterns and mitigations
- SBOM, provenance, and signing controls in the pipeline
- Vendor exit planning and concentration risk

**Data protection:**
- CyberForge's data processing activities and legal bases
- Data subject rights and response procedures
- DPA requirements for third-party processors
- Personal data breach identification and notification

---

## 4. Training Records

All training completions are recorded in the table below. Each entry must include sufficient evidence to demonstrate that training was completed.

| Date | Attendee | Role | Training Title | Provider | Duration | Assessment | Certificate/Evidence |
|------|----------|------|----------------|----------|----------|------------|----------------------|
| | | | | | | | |

### Instructions for Record Keeping

1. **Date:** The date training was completed (not the date of enrollment).
2. **Attendee:** Full name of the management body member.
3. **Role:** Current role at CyberForge (e.g., CTO, Security Lead).
4. **Training Title:** Descriptive title of the training session or course.
5. **Provider:** Internal (CyberForge self-study or internal workshop) or external provider name.
6. **Duration:** Total training duration in hours.
7. **Assessment:** Pass, Fail, or N/A (if no formal assessment was conducted).
8. **Certificate/Evidence:** Link to certificate, attendance record, or internal evidence. For internal training, a signed attendance sheet or digital confirmation is acceptable.

---

## 5. Evidence Requirements

To satisfy NIS2 Art.20 audit requirements, the following evidence must be maintained:

| Evidence Type          | Description                                                        | Retention Period                    |
|------------------------|--------------------------------------------------------------------|-------------------------------------|
| Attendance records     | Signed (physical or digital) confirmation of training attendance   | Duration of tenure + 3 years        |
| Training materials     | Slides, handouts, course outlines, or links to course content      | Duration of tenure + 3 years        |
| Assessment results     | Test scores, quiz results, or practical assessment outcomes        | Duration of tenure + 3 years        |
| Certificates           | External training certificates or completion confirmations         | Duration of tenure + 3 years        |
| Training plan          | Annual training plan showing scheduled training for each manager   | Duration of tenure + 3 years        |

### Retention Period Rationale

Training records must be retained for the duration of the individual's management tenure plus 3 years. This retention period accounts for:
- Regulatory audit lookback periods.
- The possibility that NIS2 enforcement actions may reference historical management competence.
- Alignment with general document retention practices for governance records.

---

## 6. Compliance Verification

### 6.1 Annual Compliance Check

At the start of each calendar year, the document owner verifies:

1. All current management body members are listed in the training records.
2. Each member has completed all six training areas within the preceding 12 months.
3. Any gaps are documented with a remediation plan and target completion date.
4. Evidence for all completed training is accessible and complete.

### 6.2 New Management Member Onboarding

When a new person joins the management body:

1. They must complete all six training areas within 90 days of assuming the management role.
2. Interim coverage: the existing management body retains decision authority until the new member's training is complete.
3. Training completion is a prerequisite for the new member to independently approve cybersecurity risk-management measures.

### 6.3 Non-Compliance Escalation

If a management body member has not completed required training within the specified timeframe:

1. The document owner issues a written reminder with a 30-day deadline.
2. If still incomplete after 30 days, the matter is escalated to the full management body.
3. Persistent non-compliance is documented as a governance risk in the risk register.
4. The non-compliant member's authority to approve cybersecurity measures may be suspended until training is completed.

---

## 7. Relationship to Other Training Programs

This document specifically tracks **management body** training required by NIS2 Art.20. It is distinct from, but complementary to:

- **[Security Training Program](security-training-program.md)** (Task 29): Covers training for all CyberForge personnel, including technical training, security awareness, and role-specific training. Management training recorded here also satisfies the management-specific requirements in that program.
- **[Security Hygiene Baseline](security-hygiene-baseline.md)**: Defines basic cyber hygiene practices that all personnel (including management) must follow. Management must acknowledge the baseline as part of their training obligations.

Management body members must complete both the management-specific training documented here and the general personnel training documented in the Security Training Program.

---

## 8. Compliance Mapping

| Requirement                                 | Framework Reference      | How This Document Addresses It                              |
|---------------------------------------------|--------------------------|-------------------------------------------------------------|
| Management body training (mandatory)        | NIS2 Art.20(2)           | Training requirements, records, evidence retention          |
| Management body oversight and liability     | NIS2 Art.20(1)           | Training enables informed oversight and demonstrates due diligence |
| Management body ICT risk management review  | DORA Art.5               | Risk management training area covers oversight responsibilities |
| Competence                                  | ISO 27001 Clause 7.2     | Training records demonstrate competence of management       |
| Awareness                                   | ISO 27001 Clause 7.3     | All six training areas contribute to security awareness     |
| Control environment                         | SOC 2 CC1                | Management competence supports the control environment      |

---

## 9. Related Documents

- [Crisis Management Plan](crisis-management-plan.md)
- [Risk Assessment Methodology](risk-assessment-methodology.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [IAM Governance Policy](iam-governance.md)
- [Security Hygiene Baseline](security-hygiene-baseline.md)
- [Security Training Program](security-training-program.md) (Task 29)
- [Framework Boundaries](../compliance/framework-boundaries.md)
- [Scope and Limitations](../compliance/scope-and-limitations.md)

---

## 10. Revision History

| Date       | Change             | Author                  |
|------------|--------------------|-------------------------|
| 2026-03-15 | Initial version    | CyberForge Engineering  |
