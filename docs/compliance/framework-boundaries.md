# Framework Boundaries — Control Classification by Tier

**Document Owner:** CyberForge Engineering
**Last Updated:** 2026-03-15
**Review Cadence:** Annually or after material changes to pipeline scope or target frameworks

---

## 1. Purpose

This document classifies compliance controls into three tiers for each target framework, making it clear which controls are implemented by the pipeline, which require both pipeline and organizational effort, and which are entirely outside pipeline scope.

For the overall scope statement and approved claim language, see [Scope and Limitations](scope-and-limitations.md).
For detailed per-control evidence mapping, see [Compliance Matrix](../compliance-matrix.md).

---

## 2. Control Tiers

| Tier | Label | Description |
|---|---|---|
| 1 | **Implemented in Pipeline** | Technical controls directly enforced by CI/CD workflows. Evidence generated automatically. |
| 2 | **Partially Supported (Pipeline + Org)** | Pipeline provides controls or evidence, but organizational processes are also required. |
| 3 | **Outside Pipeline Scope** | Governance, legal, or organizational controls not addressable by CI/CD. |

---

## 3. DORA (EU 2022/2554)

### Tier 1: Implemented in Pipeline

| Control Area | DORA Reference | Pipeline Implementation |
|---|---|---|
| ICT risk preventive controls | Art.16.1.a | Pre-merge gates (SAST, SCA, secret scanning, IaC scanning) block risky code |
| System/component currency | Art.16.1.c | Trivy SCA, Trivy image scan, Renovate automated dependency updates |
| Software supply chain integrity | Art.28 (partial) | SBOM generation (Syft), Cosign signing, SLSA provenance attestation |
| Cryptographic protection | Art.16.1.c | OIDC federation (no static secrets), keyless signing, signature verification before deploy |
| Immutable evidence retention | Art.16 (audit support) | Evidence Pack archived to Azure Blob WORM storage with SHA256 manifest |

### Tier 2: Partially Supported (Pipeline + Org)

| Control Area | DORA Reference | Pipeline Contribution | Organizational Addition Required |
|---|---|---|---|
| Anomaly detection | Art.16.1.d | Pipeline emits run metadata, gate outcomes, failure alerts | SIEM integration, alert routing, on-call procedures, threshold tuning |
| ICT incident management | Art.17 | DAST creates GitHub Issues for HIGH/CRITICAL findings | Incident classification, escalation, roles, post-incident review, SLA tracking |
| Third-party ICT risk | Art.28-30 | SBOM, provenance, DPA status checks | Supplier register, due diligence, contract clauses, exit plans, periodic reviews |
| Vulnerability remediation | Art.16.1.c | Trivy/CodeQL/ZAP detect vulnerabilities and block on CRITICAL | Remediation SLA governance, exception process, vulnerability tracking |
| Change traceability | Art.16.1.a | PR-based workflow, signed commits, deployment verification | Change advisory board (if required), emergency change procedures |

### Tier 3: Outside Pipeline Scope

| Control Area | DORA Reference | What Must Be Added |
|---|---|---|
| Management body accountability | Art.5 | Leadership oversight procedures, board reporting, management training |
| Major incident reporting | Art.19 | Regulatory notification within 4h/72h/1mo, authority-specific templates, legal review |
| Operational resilience testing | Art.24 | Scenario testing, recovery testing, advanced resilience testing governance |
| BC/DR program | Art.11-12 | BIA, RTO/RPO, crisis management, recovery drills, evidence retention |
| Full ICT third-party lifecycle | Art.28-30 | Contract negotiations, concentration risk assessment, regulatory register |

---

## 4. NIS2 (EU 2022/2555)

### Tier 1: Implemented in Pipeline

| Control Area | NIS2 Reference | Pipeline Implementation |
|---|---|---|
| Secure development (SSDLC) | Art.21.2.e | Enforced CI/CD gates: SAST, SCA, tests, DAST, deployment verification |
| Software supply chain controls | Art.21.2.d | SBOM, signed attestations, provenance, dependency scanning, action pinning |
| Cryptography | Art.21.2.h | OIDC federation, keyless Cosign signing, signature verification before deploy |
| Effectiveness evidence | Art.21.2.f (partial) | Repeatable evidence generation, pass/fail gate outcomes, compliance matrix |

### Tier 2: Partially Supported (Pipeline + Org)

| Control Area | NIS2 Reference | Pipeline Contribution | Organizational Addition Required |
|---|---|---|---|
| Incident handling | Art.21.2.b | DAST findings create incident issues, evidence pack preserves logs | IR runbooks, severity model, escalation, on-call, postmortems |
| Risk analysis | Art.21.2.a | OPA policies enforce risk treatment, design docs document controls | Formal risk analysis process, risk register, treatment tracking |
| Vulnerability handling/disclosure | Art.21.2.e | Pipeline gates detect and block vulnerable code | Disclosure policy, remediation SLAs, exception governance |
| Access control | Art.21.2.i | Repository governance (CODEOWNERS, branch protection, signed commits) | JML process, access reviews, CMDB/asset inventory, HR controls |
| Cyber hygiene | Art.21.2.g | Renovate patch hygiene, automated scanning | Security awareness training, device management, network controls |

### Tier 3: Outside Pipeline Scope

| Control Area | NIS2 Reference | What Must Be Added |
|---|---|---|
| Management oversight and training | Art.20 | Management cybersecurity training, oversight procedures, policy approvals |
| Incident reporting to authorities | Art.23 | Early warning (24h), notification (72h), final report (1mo), authority contacts |
| Business continuity and DR | Art.21.2.c | Backup procedures, DR architecture, recovery drills, crisis management |
| Asset management | Art.21.2.i | Complete asset inventory (hardware, software, data, personnel) |
| MFA/secure communications governance | Art.21.2.j | Organization-wide MFA/SSO enforcement, secure communication policies |

---

## 5. ISO/IEC 27001:2022

### Tier 1: Implemented in Pipeline

| Control Area | ISO 27001 Reference | Pipeline Implementation |
|---|---|---|
| Secure development lifecycle | A.8.25 | Enforced pipeline with security gates, test coverage threshold, evidence generation |
| Configuration management | A.8.9 | Terraform IaC versioned in Git, Checkov scanning, deployment verification |
| Change management | A.8.32 | PR-based workflow, required reviews, signed commits, deployment traceability |
| Secure coding | A.8.28 (partial) | CodeQL SAST, MegaLinter linting, OWASP ZAP DAST, PII scanning |
| Operation (CI/CD subsystem) | Clause 8 (partial) | Pipeline is a direct operational control for software delivery changes |

### Tier 2: Partially Supported (Pipeline + Org)

| Control Area | ISO 27001 Reference | Pipeline Contribution | Organizational Addition Required |
|---|---|---|---|
| Access to source code | A.8.4 | Branch protection, CODEOWNERS, signed commits | Access review process, JML, organization-wide IAM governance |
| Technical vulnerability management | A.8.8 | SCA, SAST, DAST, image scan gates | Remediation SLAs, exception approvals, vulnerability tracking process |
| Logging | A.8.15 | Pipeline run metadata, audit artifacts | Central logging standards, SIEM, retention/monitoring for all systems |
| Monitoring | A.8.16 | Workflow gate outcomes, planned SIEM integration | Central monitoring coverage, on-call, alert tuning |
| Performance evaluation | Clause 9 | Evidence pack, verification logs, compliance matrix | Internal audits, management review, KPI dashboards |

### Tier 3: Outside Pipeline Scope

| Control Area | ISO 27001 Reference | What Must Be Added |
|---|---|---|
| ISMS scope and context | Clause 4 | Formal ISMS scope, interested parties, boundaries, issues register |
| Leadership and commitment | Clause 5 | ISMS policy approval, role assignment, leadership accountability |
| Risk assessment and treatment | Clause 6 | Risk methodology, risk register, treatment plan, Statement of Applicability |
| Competence and awareness | Clause 7 | Training records, communication processes, document control |
| Internal audit | Clause 9.2 | Annual audit program, auditor independence, findings tracking |
| Management review | Clause 9.3 | Periodic review meetings, input/output records, action tracking |
| Continual improvement | Clause 10 | CAPA process, improvement governance, tracked corrective actions |

---

## 6. SOC 2 (Trust Services Criteria)

### Tier 1: Implemented in Pipeline

| Control Area | SOC 2 Reference | Pipeline Implementation |
|---|---|---|
| Control activities (CI/CD) | CC5 | CI/CD gates, OPA policies, Terraform change control, automated scanning |
| Change management | CC8 | PR-based flow, required checks, signed artifacts, deploy verification, traceability |
| Processing integrity (releases) | PI1.1 | Jest tests with coverage gate, smoke tests, DAST, signed deployments |

### Tier 2: Partially Supported (Pipeline + Org)

| Control Area | SOC 2 Reference | Pipeline Contribution | Organizational Addition Required |
|---|---|---|---|
| Logical access controls | CC6.1 | Repository governance, signed commits, OIDC (no static credentials) | IAM governance, access reviews, MFA evidence, vendor physical security docs |
| System operations | CC7.1 | Signature verification, scan gates, DAST, evidence packaging | On-call, incident operations, monitoring coverage, operational runbooks |
| Risk mitigation (vendors) | CC9 | SBOM, provenance, SCA, DPA checks | Vendor management program, due diligence, contract reviews |
| Risk assessment | CC3 | Technical gates reflect risk treatment intent | Risk assessment methodology, risk register, periodic reassessment |
| Monitoring activities | CC4 | Repeatable evidence, pass/fail outcomes | Formal control monitoring program, remediation tracking |

### Tier 3: Outside Pipeline Scope

| Control Area | SOC 2 Reference | What Must Be Added |
|---|---|---|
| Control environment | CC1 | Governance, ethics, organizational structure, control ownership |
| Communication | CC2 | Formal policy communication, acknowledgement, training programs |
| System description | — | Scoped system boundaries, sub-service orgs, data flows, infrastructure |
| Type II evidence | — | Period-based operating effectiveness evidence (not point-in-time) |
| External attestation | — | CPA firm engagement, examination, opinion letter |

---

## 7. RODO/GDPR (EU 2016/679)

### Tier 1: Implemented in Pipeline

| Control Area | GDPR Reference | Pipeline Implementation |
|---|---|---|
| Data minimization (CI/CD logs) | Art.5.1.c | Log sanitization script redacts PII from evidence artifacts |
| Processor DPA tracking | Art.28 (partial) | DPA compliance check script verifies status of pipeline processors |

### Tier 2: Partially Supported (Pipeline + Org)

| Control Area | GDPR Reference | Pipeline Contribution | Organizational Addition Required |
|---|---|---|---|
| Data protection by design | Art.25 | PII scanner in code, data-flow diagram generation | DPIA methodology, privacy requirements process, product design reviews |
| Storage limitation | Art.5.1.e | Retention metadata checks, WORM storage with lifecycle | Legal retention schedule validation, destruction procedures |
| Security of processing | Art.32 | Security gates, signing, OIDC, scanning | Broader technical/organizational security across all systems |
| Records of processing | Art.30 | Pipeline metadata provides CI/CD processing traceability | Formal RoPA covering all business processing |

### Tier 3: Outside Pipeline Scope

| Control Area | GDPR Reference | What Must Be Added |
|---|---|---|
| Legal basis for processing | Art.6 | Legal basis determination for each processing activity |
| Data subject rights | Art.15-22 | Request handling procedures, response SLAs, identity verification |
| Data Protection Impact Assessments | Art.35 | DPIA methodology, threshold criteria, remediation tracking |
| Breach notification | Art.33-34 | Authority notification (72h), data subject notification, assessment process |
| International transfers | Art.44-49 | Transfer impact assessments, safeguard mechanisms (SCCs, adequacy) |

---

## 8. Using This Document

### For Engineers
Reference the Tier 1 columns to understand which controls are already enforced by the pipeline code you work with daily.

### For Sales and Client-Facing Staff
Use the tier classification to accurately position the pipeline's value. Always pair pipeline capabilities (Tier 1) with the acknowledgment that Tier 2 and Tier 3 controls are needed for full compliance.

### For Compliance/GRC Stakeholders
Use Tier 2 and Tier 3 as a gap analysis checklist. Each "Organizational Addition Required" entry is a workstream that must be addressed before claiming audit readiness.

### For Auditors
This document provides transparent boundaries. The pipeline supports audit evidence collection for Tier 1 and Tier 2 controls. Tier 3 controls require separate organizational evidence.

---

## 9. Revision History

| Date | Change | Author |
|---|---|---|
| 2026-03-15 | Initial version | CyberForge Engineering |
