# Compliance Scope and Limitations

**Document Owner:** CyberForge Engineering
**Last Updated:** 2026-03-15
**Review Cadence:** Annually or after material changes to pipeline scope

---

## 1. Purpose

This document defines the compliance scope, limitations, and approved claim language for the CyberForge DevSecOps Pipeline. It ensures that all internal communications, client-facing materials, and audit documentation accurately represent what the pipeline does and does not cover.

---

## 2. What This Pipeline Is

The CyberForge DevSecOps Pipeline is a **compliance-enabling CI/CD and software supply chain control subsystem**. It implements technical controls within the software delivery lifecycle and generates machine-readable audit evidence ("Evidence Packs") to support compliance readiness for:

- DORA (EU 2022/2554)
- NIS2 (EU 2022/2555)
- ISO/IEC 27001:2022
- SOC 2 (Trust Services Criteria)
- RODO/GDPR (EU 2016/679) — supporting controls only

---

## 3. What the Pipeline Covers Well

### 3.1 Secure Software Development Lifecycle (SSDLC)

- Pre-merge security gates: secret scanning (TruffleHog), IaC scanning (Checkov), linting (MegaLinter), PII detection, commit signature verification
- Static analysis (CodeQL SAST), dependency scanning (Trivy SCA), container image scanning (Trivy)
- Unit test enforcement with coverage threshold (80%)
- Dynamic application security testing (OWASP ZAP)

### 3.2 Software Supply Chain Integrity

- Software Bill of Materials generation (Syft, CycloneDX format)
- Cryptographic image signing (Cosign, keyless OIDC)
- SLSA build provenance attestation
- Pre-deploy signature verification
- Action pinning to full SHA (managed by Renovate)

### 3.3 Change Traceability and Access Control

- PR-based workflow with required reviews and status checks
- Branch protection enforcement (2 reviewers, signed commits, no force push)
- CODEOWNERS for security-sensitive paths
- Git-based audit trail for all changes

### 3.4 Zero-Secret Cloud Authentication

- OIDC federation between GitHub Actions and Azure (no static cloud credentials)
- In-memory secret injection via Azure Key Vault
- Keyless signing via Sigstore/Fulcio

### 3.5 Automated Audit Evidence Collection

- Evidence Pack generation with 11+ artifacts per release
- SHA256 checksum manifest for tamper detection
- Immutable archival to Azure Blob Storage (WORM policy)
- Machine-generated compliance matrix mapping evidence to requirements
- Log sanitization for data minimization (PII redaction)
- DPA compliance verification for third-party processors

---

## 4. What the Pipeline Does NOT Cover

The following are required for genuine compliance readiness but are outside the scope of a CI/CD pipeline. These are tracked as Phase F workstreams in the implementation plan.

### 4.1 Management Governance and Accountability

- DORA Art.5 / NIS2 Art.20: Management body oversight and training
- ISO 27001 Clause 5: Leadership commitment and policy approval
- SOC 2 CC1: Control environment and organizational governance

### 4.2 Incident Reporting and Response

- DORA Art.17/19: ICT incident management and regulatory notification (4h/72h/1mo timelines)
- NIS2 Art.23: Incident reporting to national authorities (24h/72h/1mo timelines)
- GDPR Art.33/34: Personal data breach notification

### 4.3 Business Continuity and Disaster Recovery

- DORA Art.11/12: Operational resilience testing program
- NIS2 Art.21.2.c: Continuity, backup, and crisis management
- ISO 27001 A.5.29-A.5.30: Business continuity planning

### 4.4 Organization-Wide IAM Governance

- Joiner/mover/leaver processes
- Periodic access recertification
- MFA/SSO enforcement evidence across all systems
- Privileged access management beyond repository scope

### 4.5 Supplier and Third-Party Risk Lifecycle

- DORA Art.28-30: Full ICT third-party risk management and contract controls
- Vendor due diligence, periodic reassessment, exit planning
- Subprocessor management beyond DPA status verification

### 4.6 ISO 27001 ISMS (Clauses 4-10)

- ISMS scope definition, risk assessment methodology, risk register
- Risk treatment plan and Statement of Applicability
- Internal audit program and management review
- Corrective action and continual improvement process

### 4.7 SOC 2 Attestation Requirements

- System description (scoped boundaries, sub-service organizations)
- Control ownership and evidence calendar
- Period-based operating effectiveness evidence (Type II)
- External CPA firm attestation

### 4.8 Full GDPR Program

- Data Protection Impact Assessments (DPIAs)
- Legal basis determination and records of processing
- Data subject rights handling
- International transfer assessments

---

## 5. Approved Claim Language

### 5.1 Approved for Use (Sales, Marketing, Documentation)

- "Compliance-enabling DevSecOps pipeline for DORA/NIS2/ISO 27001/SOC 2 evidence and CI/CD hardening"
- "Implements a secure CI/CD and software supply-chain control layer with audit evidence packaging"
- "Supports audit readiness for software delivery controls"
- "Supports selected technical control requirements and audit evidence collection"
- "Accelerates compliance readiness by automating evidence generation for security and supply chain controls"

### 5.2 Prohibited (Must Not Be Used)

- "This pipeline makes you DORA compliant"
- "Full DORA compliance"
- "NIS2 compliance by itself"
- "ISO 27001 certification readiness by pipeline alone"
- "SOC 2 compliant pipeline = SOC 2 compliant company"
- "GDPR compliant CI/CD"
- Any language implying the pipeline alone satisfies a complete regulatory framework

### 5.3 Guidance for Client Communications

When discussing compliance with clients:

1. Always position the pipeline as a **subsystem** that supports broader compliance programs
2. Explicitly state which controls the pipeline implements directly vs. which require organizational processes
3. Reference the framework-boundaries document for detailed per-framework control classification
4. Recommend legal/compliance counsel review for regulatory interpretation

---

## 6. Coverage Classification Model

This project uses a four-tier coverage classification:

| Coverage Type | Definition |
|---|---|
| **Direct (Pipeline)** | The pipeline design directly implements a technical control. Evidence is generated automatically. |
| **Partial (Pipeline + Org)** | The pipeline contributes technical controls or evidence, but organizational controls are also required for full compliance. |
| **Phase F / Org Required** | The requirement is primarily outside the pipeline. Must be addressed in governance, runbooks, or organizational processes. |
| **Out of Scope** | Important requirement, but not a CI/CD pipeline responsibility (e.g., physical security, HR controls). |

For detailed per-framework, per-control classification, see [Framework Boundaries](framework-boundaries.md).

---

## 7. Related Documents

- [Framework Boundaries](framework-boundaries.md) — Three-tier control classification per framework
- [Compliance Matrix](../compliance-matrix.md) — Detailed per-control design intent mapping
- [Implementation Progress](../plans/2026-02-26-implementation-progress.md) — Current implementation status
- [Vendor Risk Register](../governance/vendor-risk-register.md) — Third-party supplier risk inventory

---

## 8. Revision History

| Date | Change | Author |
|---|---|---|
| 2026-03-15 | Initial version | CyberForge Engineering |
