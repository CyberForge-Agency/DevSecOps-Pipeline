# Internal Audit Program

**Document Owner:** CyberForge Management
**Last Reviewed:** 2026-03-15
**Review Cadence:** Annually, or after significant changes to the ISMS scope
**Version:** 1.0
**ISO 27001 Reference:** Clauses 9.2.1, 9.2.2

---

## 1. Purpose

This document defines the internal audit program for the CyberForge ISMS. The program verifies that the ISMS:

- Conforms to the requirements of ISO/IEC 27001:2022 and the organization's own information security requirements.
- Is effectively implemented and maintained.
- Meets the objectives defined in the ISMS scope.
- Adequately addresses the risks identified in the risk register.
- Demonstrates that Annex A controls documented in the Statement of Applicability are operating as intended.

---

## 2. Scope

The audit program covers all ISMS processes, Annex A controls, and governance documents within the scope defined in [isms-scope.md](isms-scope.md). This includes:

- CI/CD pipeline security controls and workflows
- Cloud infrastructure security (Azure)
- Identity and access management
- Vendor and supply chain management
- Evidence generation and archival
- Governance documentation and processes
- Personnel competence and awareness

---

## 3. Audit Program Principles

### 3.1 Independence and Objectivity

For a 2-person startup, full independence is not achievable internally. CyberForge addresses this through the following approach:

| Approach | Description | When Used |
|---|---|---|
| **Cross-audit** | Founder A audits areas owned by Founder B, and vice versa. Neither founder audits their own work. | Default approach for internal audits |
| **External auditor** | An independent external auditor is engaged to conduct the audit or specific audit modules. | Annually for at least one full cycle; always for certification-readiness audits |

As the organization grows, a dedicated internal auditor or internal audit function will be established.

### 3.2 Competence

Internal auditors must have:

- Understanding of ISO 27001:2022 requirements and audit techniques.
- Familiarity with the ISMS scope, processes, and controls.
- No direct responsibility for the area being audited (where practicable).

Cross-audit training is included in the [Security Training Program](security-training-program.md).

### 3.3 Evidence-Based Approach

All audit findings must be supported by objective evidence. Evidence types include:

- Pipeline run logs and reports
- Configuration screenshots or exports
- Access review records
- Governance document review
- Interviews with process owners
- Tool output (Trivy, Checkov, CodeQL, TruffleHog reports)

---

## 4. Annual Audit Plan

The annual audit cycle groups Annex A controls and ISMS clauses by theme across four quarters. Each quarter covers a manageable subset of controls for a small team.

### 4.1 Audit Schedule

| Quarter | Theme | Annex A Controls | ISMS Clauses | Estimated Effort |
|---|---|---|---|---|
| **Q1** (Jan--Mar) | Organizational controls | A.5.1 -- A.5.37 | 4 (Context), 5 (Leadership), 6 (Planning) | 3--5 days |
| **Q2** (Apr--Jun) | People and physical controls | A.6.1 -- A.6.8, A.7.1 -- A.7.14 | 7 (Support: competence, awareness, communication, documented information) | 2--3 days |
| **Q3** (Jul--Sep) | Technological controls (part 1) | A.8.1 -- A.8.17 | 8 (Operation: risk assessment, risk treatment) | 3--5 days |
| **Q4** (Oct--Dec) | Technological controls (part 2) | A.8.18 -- A.8.34 | 9 (Performance evaluation), 10 (Improvement) | 3--5 days |

### 4.2 Audit Plan Detail

#### Q1: Organizational Controls

| Audit Area | Key Controls | Evidence to Review |
|---|---|---|
| Information security policies | A.5.1, A.5.4, A.5.37 | Policy documents, version history, approval records |
| Roles and responsibilities | A.5.2, A.5.3 | Role assignments, segregation of duties documentation |
| Asset management | A.5.9, A.5.10, A.5.11, A.5.12, A.5.13 | Asset inventory, classification records, return-of-assets evidence |
| Access control | A.5.15, A.5.16, A.5.17, A.5.18 | Access review records, IAM governance policy compliance |
| Supplier management | A.5.19, A.5.20, A.5.21, A.5.22, A.5.23 | Vendor risk register, DPA status, due diligence checklists |
| Incident management | A.5.24, A.5.25, A.5.26, A.5.27, A.5.28 | Incident log, response records, evidence collection procedures |
| Continuity and compliance | A.5.29, A.5.30, A.5.31, A.5.32, A.5.33, A.5.34, A.5.35, A.5.36 | Continuity plans, compliance mapping, records protection evidence |
| Risk management | Clause 6.1, 6.2 | Risk register, risk treatment plan, risk assessment records |
| ISMS scope and context | Clause 4.1, 4.2, 4.3 | ISMS scope document, context analysis |
| Leadership and commitment | Clause 5.1, 5.2, 5.3 | Management review minutes, policy approval records |

#### Q2: People and Physical Controls

| Audit Area | Key Controls | Evidence to Review |
|---|---|---|
| Personnel security | A.6.1, A.6.2, A.6.4, A.6.5, A.6.6 | Screening records, employment terms, NDA records, leaver process evidence |
| Awareness and training | A.6.3 | Training records, assessment results, training program documentation |
| Remote working | A.6.7 | Security hygiene baseline compliance, device security evidence |
| Event reporting | A.6.8 | Reporting procedure, event log |
| Physical controls (N/A verification) | A.7.1 -- A.7.14 | Cloud provider SOC 2 report, exclusion justifications in SoA |
| Competence and awareness | Clause 7.2, 7.3 | Training records, competence assessments |
| Communication | Clause 7.4 | Communication records, stakeholder engagement evidence |
| Documented information | Clause 7.5 | Document control process, version history, retention compliance |

#### Q3: Technological Controls (Part 1)

| Audit Area | Key Controls | Evidence to Review |
|---|---|---|
| Endpoint security | A.8.1 | Device compliance records, security hygiene baseline checks |
| Access controls (technical) | A.8.2, A.8.3, A.8.4, A.8.5 | RBAC configurations, repository permissions, MFA enforcement, CODEOWNERS |
| Capacity and malware | A.8.6, A.8.7 | Capacity metrics, runner hygiene (ephemeral status), endpoint protection |
| Vulnerability management | A.8.8 | Trivy scan results, vulnerability SLA compliance, remediation records |
| Configuration management | A.8.9 | Checkov scan results, Terraform state, OPA policy enforcement |
| Data management | A.8.10, A.8.11, A.8.12, A.8.13 | Data lifecycle policies, DLP controls, backup verification |
| Infrastructure | A.8.14 | Redundancy architecture, availability metrics |
| Logging and monitoring | A.8.15, A.8.16, A.8.17 | Log retention, monitoring coverage, clock synchronization |
| Operational risk assessment | Clause 8.2 | Risk assessment execution records |
| Risk treatment implementation | Clause 8.3 | Risk treatment plan status, control effectiveness evidence |

#### Q4: Technological Controls (Part 2)

| Audit Area | Key Controls | Evidence to Review |
|---|---|---|
| System administration | A.8.18, A.8.19 | Privileged utility controls, software installation controls |
| Network security | A.8.20, A.8.21, A.8.22, A.8.23 | VNet configuration, NSG rules, TLS enforcement, web filtering |
| Cryptography | A.8.24 | Cosign signing verification, Key Vault configuration, TLS certificates |
| Secure development | A.8.25, A.8.26, A.8.27, A.8.28 | Pipeline phase evidence, security requirements, architecture documentation, CodeQL results |
| Testing and deployment | A.8.29, A.8.30, A.8.31, A.8.32 | Test results (SAST, SCA, DAST), environment separation, change management records |
| Data protection in testing | A.8.33, A.8.34 | Test data management, audit testing safeguards |
| Performance evaluation | Clause 9.1 | Monitoring and measurement results, security objectives progress |
| Internal audit review | Clause 9.2 | This audit program execution, findings from earlier quarters |
| Management review | Clause 9.3 | Management review minutes and action items |
| Improvement | Clause 10.1, 10.2 | Corrective actions log, continual improvement evidence |

---

## 5. Audit Process

### 5.1 Phase 1: Planning

| Activity | Output | Responsible |
|---|---|---|
| Define audit scope for the quarter | Audit scope statement | Lead auditor |
| Review previous audit findings and open corrective actions | Prior findings summary | Lead auditor |
| Prepare audit checklist based on applicable controls | Audit checklist | Lead auditor |
| Schedule audit activities and notify auditees | Audit schedule | Lead auditor |
| Gather pre-audit documentation | Documentation package | Auditee |

### 5.2 Phase 2: Execution

| Activity | Output | Responsible |
|---|---|---|
| Review documentation against requirements | Documentation review notes | Lead auditor |
| Interview process owners | Interview notes | Lead auditor |
| Inspect configurations, logs, and tool outputs | Inspection evidence | Lead auditor |
| Sample-test controls (e.g., verify a random PR followed the review process) | Sample test results | Lead auditor |
| Identify conformities, nonconformities, and observations | Finding notes | Lead auditor |

### 5.3 Phase 3: Reporting

| Activity | Output | Responsible |
|---|---|---|
| Classify findings by severity | Classified findings list | Lead auditor |
| Draft audit report | Audit report | Lead auditor |
| Present findings to management | Presentation / meeting | Lead auditor |
| Obtain management acknowledgment | Signed audit report | CyberForge Management |

### 5.4 Phase 4: Follow-Up

| Activity | Output | Responsible |
|---|---|---|
| Log corrective actions in corrective actions log | Updated [Corrective Actions Log](corrective-actions-log.md) | Lead auditor |
| Track corrective action implementation | Status updates | CAPA owner |
| Verify corrective action effectiveness | Verification evidence | Lead auditor (next cycle) |
| Close findings when verified as effective | Closed findings | Lead auditor |

---

## 6. Finding Classification

| Classification | Definition | Required Action | Timeline |
|---|---|---|---|
| **Major Nonconformity** | A significant failure to fulfill an ISO 27001 requirement, or a situation that raises significant doubt about the ability of the ISMS to achieve its intended outcomes | Corrective action required; root cause analysis mandatory; escalation to management | Root cause analysis within 5 business days; corrective action plan within 10 business days; implementation within 60 days |
| **Minor Nonconformity** | A partial failure to fulfill an ISO 27001 requirement that does not, by itself, raise significant doubt about ISMS effectiveness | Corrective action required; root cause analysis recommended | Corrective action plan within 15 business days; implementation within 90 days |
| **Observation** | A factual statement made during the audit that does not constitute a nonconformity but indicates potential for improvement or a trend that could become a nonconformity | Consideration recommended; no mandatory action | Review at next audit cycle |
| **Opportunity for Improvement** | A suggestion for enhancing the ISMS beyond current requirements | Optional action at management discretion | No mandatory timeline |

---

## 7. Audit Report Template

Each quarterly audit report follows this structure:

```
1. Audit Report Header
   - Report ID: IA-YYYY-QN (e.g., IA-2026-Q1)
   - Audit dates
   - Lead auditor
   - Auditee(s)
   - Scope (quarter theme and specific controls audited)

2. Executive Summary
   - Overall ISMS conformance assessment
   - Number of findings by classification
   - Key strengths observed
   - Key areas for improvement

3. Audit Scope and Criteria
   - Controls and clauses audited
   - Audit criteria (ISO 27001:2022, internal policies)
   - Methods used (document review, interview, inspection, sampling)

4. Findings
   For each finding:
   - Finding ID: F-YYYY-QN-NNN
   - Classification (Major/Minor/Observation/OFI)
   - Control reference (Annex A or Clause number)
   - Finding description
   - Objective evidence
   - Recommended corrective action (for nonconformities)

5. Positive Observations
   - Controls operating effectively
   - Best practices noted

6. Conclusion
   - Overall assessment
   - Recommendation for next review

7. Distribution List

8. Sign-Off
   - Lead auditor signature and date
   - Management acknowledgment signature and date
```

---

## 8. Records Management

| Record | Retention Period | Storage |
|---|---|---|
| Audit reports | 5 years | `docs/governance/audit-reports/` (version-controlled) |
| Audit checklists and working papers | 5 years | `docs/governance/audit-reports/` |
| Corrective action records | 5 years | `docs/governance/corrective-actions-log.md` |
| Management acknowledgment records | 5 years | Audit report sign-off section |
| Interview notes | 5 years | Audit working papers |

All audit records are retained for a minimum of 5 years from the date of the audit report, consistent with the records retention requirements of the ISMS.

---

## 9. Relationship to External Audits

Internal audits serve as preparation for external ISO 27001 certification audits. The internal audit program is designed to:

- Identify and resolve nonconformities before external audit.
- Build organizational familiarity with the audit process.
- Generate evidence of continual improvement required by ISO 27001 Clause 10.
- Provide input to the management review process (Clause 9.3).

External audit results and certification body findings are also tracked in the [Corrective Actions Log](corrective-actions-log.md).

---

## 10. Compliance Mapping

| Requirement | Framework Reference |
|---|---|
| Internal audit | ISO 27001 Clause 9.2.1, 9.2.2 |
| Monitoring, measurement, analysis and evaluation | ISO 27001 Clause 9.1 |
| Nonconformity and corrective action | ISO 27001 Clause 10.2 |
| Audit and supervision | NIS2 Art.32, Art.33 |
| ICT audit | DORA Art.26 |

---

## 11. Related Documents

- [ISMS Scope](isms-scope.md)
- [Statement of Applicability](statement-of-applicability.md)
- [Risk Register](risk-register.md)
- [Risk Treatment Plan](risk-treatment-plan.md)
- [Corrective Actions Log](corrective-actions-log.md)
- [Management Review Template](management-review-template.md)
- [Security Training Program](security-training-program.md)

---

## 12. Revision History

| Date | Change | Author |
|---|---|---|
| 2026-03-15 | Initial version with annual audit plan (Q1--Q4) | CyberForge Management |
