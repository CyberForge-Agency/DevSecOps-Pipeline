# ICT Third-Party Contract Controls

**Document Owner:** Security Lead / Legal Counsel
**Last Reviewed:** 2026-03-15
**Review Cadence:** Annually and upon regulatory changes
**Compliance Scope:** DORA Art.28-30, NIS2 Art.21.2.d, ISO 27001 A.5.19-A.5.23, SOC 2 CC9

---

## Purpose

This document defines the minimum contractual control requirements for all ICT
third-party service providers used within the CyberForge DevSecOps Pipeline. These
controls must be present in vendor contracts, service agreements, or Data Processing
Agreements before a vendor is approved for use.

For open-source tools running locally without external data transmission, contractual
controls are not applicable. These tools are governed instead by the license compliance
and supply chain assessment sections of the
[vendor-due-diligence-checklist.md](vendor-due-diligence-checklist.md).

---

## Applicability

| Vendor Type | Contract Controls Required | Applicable Sections |
|-------------|---------------------------|-------------------|
| Cloud service providers (SaaS/PaaS/IaaS) | Yes - Full | All sections |
| Managed service providers | Yes - Full | All sections |
| OSS tools with cloud component (e.g., Renovate via GitHub App) | Partial - Covered by host platform DPA | Sections 1, 2 (via host platform) |
| OSS tools running locally (e.g., Trivy, Checkov, Syft) | No | N/A - See due diligence checklist |

---

## 1. Security Terms

### 1.1 Incident Management

- [ ] **Security incident notification**: Vendor must notify within **24 hours** of
  detecting a confirmed security incident affecting customer data, and within
  **72 hours** for suspected incidents under investigation.
  _[DORA Art.28(7), ISO 27001 A.5.20]_

- [ ] **Incident response cooperation**: Vendor must cooperate with customer's incident
  response team, provide forensic evidence upon request, and participate in joint
  post-incident reviews.
  _[DORA Art.28(7)]_

- [ ] **Incident reporting format**: Vendor must provide structured incident reports
  including: timeline, scope of impact, data affected, root cause analysis, and
  remediation actions.
  _[DORA Art.28(7), NIS2 Art.21.2(d)]_

### 1.2 Subprocessor Management

- [ ] **Subprocessor notification**: Vendor must notify customer **30 days in advance**
  of engaging any new subprocessor or changing existing subprocessors.
  _[GDPR Art.28(2), ISO 27001 A.5.21]_

- [ ] **Subprocessor approval rights**: Customer retains the right to object to new
  subprocessors. If objection is raised and not resolved, customer may terminate
  without penalty.
  _[GDPR Art.28(2)]_

- [ ] **Subprocessor list**: Vendor must maintain and share a current list of all
  subprocessors, including their processing activities and data locations.
  _[GDPR Art.28(2), DORA Art.29]_

### 1.3 Security Assurance

- [ ] **Annual security assessment**: Vendor must provide, at minimum annually, one of:
  SOC 2 Type II report, ISO 27001 certificate, or equivalent third-party security
  assessment.
  _[DORA Art.28(6), ISO 27001 A.5.22]_

- [ ] **Right to audit**: Customer has the right to audit the vendor's security controls,
  either directly or through an independent third-party auditor, with **30 days
  advance notice**. Audits may be conducted annually or upon reasonable suspicion of
  non-compliance.
  _[DORA Art.28(6), ISO 27001 A.5.22]_

- [ ] **Vulnerability management**: Vendor must maintain a vulnerability management
  program with defined SLAs for remediation: Critical (24h), High (7 days),
  Medium (30 days), Low (90 days).
  _[ISO 27001 A.5.22]_

### 1.4 Access Control

- [ ] **Data encryption at rest**: All customer data must be encrypted at rest using
  AES-256 or equivalent. Encryption keys must be managed using a key management
  system with appropriate access controls.
  _[ISO 27001 A.5.20]_

- [ ] **Data encryption in transit**: All data in transit must be encrypted using
  TLS 1.2 or higher. Mutual TLS (mTLS) required for service-to-service
  communication where technically feasible.
  _[ISO 27001 A.5.20]_

- [ ] **Least privilege access**: Vendor must enforce least privilege access to customer
  data and systems. Administrative access must require multi-factor authentication
  and be logged.
  _[ISO 27001 A.5.20, DORA Art.28(5)]_

- [ ] **Access logging**: All access to customer data must be logged with sufficient
  detail for audit purposes. Logs must be retained for a minimum of 12 months.
  _[ISO 27001 A.5.22]_

---

## 2. Data Protection

### 2.1 Data Processing Agreement

- [ ] **DPA executed**: A Data Processing Agreement compliant with GDPR Art.28 must be
  executed before any personal data processing begins.
  _[GDPR Art.28, DORA Art.28(2)]_

- [ ] **Processing purpose limitation**: DPA must specify the subject matter, duration,
  nature, and purpose of processing, as well as the types of personal data and
  categories of data subjects.
  _[GDPR Art.28(3)]_

- [ ] **Processor obligations**: DPA must include vendor obligations regarding
  confidentiality, security measures, subprocessor management, data subject rights
  assistance, and deletion/return of data.
  _[GDPR Art.28(3)]_

### 2.2 Data Residency

- [ ] **Data residency requirements**: All customer data must be processed and stored
  within the **EU/EEA**. Any transfer outside the EU/EEA requires explicit customer
  approval and appropriate safeguards (SCCs, adequacy decisions).
  _[GDPR Art.44-49, DORA Art.28(4)]_

- [ ] **Data location transparency**: Vendor must disclose all data processing and
  storage locations, including those of subprocessors, and notify customer of any
  changes.
  _[DORA Art.28(4)]_

### 2.3 Data Lifecycle

- [ ] **Data deletion upon termination**: Upon contract termination or expiry, vendor
  must delete all customer data within **30 days** and provide written confirmation
  of deletion, unless retention is required by law.
  _[GDPR Art.28(3)(g), DORA Art.28(8)]_

- [ ] **Data portability**: Vendor must provide customer data in a standard,
  machine-readable format upon request and at contract termination.
  _[GDPR Art.20, DORA Art.28(8)]_

- [ ] **Data retention limits**: Vendor must not retain customer data beyond the
  agreed retention period. Automated deletion mechanisms must be in place.
  _[GDPR Art.5(1)(e)]_

---

## 3. Operational Controls

### 3.1 Service Level Agreement

- [ ] **Availability targets**: SLA must define minimum availability targets
  (e.g., 99.9% monthly uptime for production services).
  _[DORA Art.28(5), ISO 27001 A.5.22]_

- [ ] **Performance metrics**: SLA must define measurable performance metrics
  (response time, throughput) and monitoring mechanisms.
  _[ISO 27001 A.5.22]_

- [ ] **SLA breach remediation**: SLA must define remedies for breaches, including
  service credits, escalation procedures, and termination rights for persistent
  non-compliance.
  _[DORA Art.28(5)]_

### 3.2 Change Management

- [ ] **Change notification**: Vendor must notify customer **30 days in advance** of
  any material changes to the service, including infrastructure changes, feature
  deprecations, or security-relevant modifications.
  _[ISO 27001 A.5.22, DORA Art.28(5)]_

- [ ] **Breaking change policy**: Vendor must provide a minimum **90-day deprecation
  period** for breaking API or service changes, with migration guidance.
  _[ISO 27001 A.5.22]_

### 3.3 Business Continuity and Disaster Recovery

- [ ] **BC/DR provisions**: Contract must include vendor's business continuity and
  disaster recovery commitments, including RTO and RPO targets.
  _[DORA Art.28(5), ISO 27001 A.5.22]_

- [ ] **BC/DR testing**: Vendor must test BC/DR plans at least annually and share
  test results or summary upon request.
  _[DORA Art.28(5)]_

- [ ] **Geographic redundancy**: For Critical-rated vendors, service must be available
  from multiple geographic regions to mitigate regional outage risk.
  _[DORA Art.28(5)]_

### 3.4 Escalation and Communication

- [ ] **Escalation path**: Contract must define a clear escalation path for critical
  issues, including named contacts and maximum response times.
  _[ISO 27001 A.5.22]_

- [ ] **Regular service reviews**: For High/Critical vendors, quarterly service review
  meetings must be contractually defined.
  _[ISO 27001 A.5.22]_

---

## 4. Exit and Transition

### 4.1 Transition Assistance

- [ ] **Transition assistance period**: Vendor must provide a minimum **90-day
  transition assistance period** following contract termination or non-renewal,
  during which full service access and support are maintained.
  _[DORA Art.28(8)]_

- [ ] **Transition planning**: Vendor must cooperate with customer's transition plan,
  including knowledge transfer, data migration support, and parallel running
  periods.
  _[DORA Art.28(8)]_

### 4.2 Data Return and Deletion

- [ ] **Data return**: Vendor must return all customer data in a standard,
  machine-readable format within the transition assistance period.
  _[DORA Art.28(8), GDPR Art.28(3)(g)]_

- [ ] **Deletion confirmation**: Vendor must provide written confirmation of data
  deletion from all systems (including backups) within **30 days** of the
  transition period end.
  _[GDPR Art.28(3)(g)]_

### 4.3 Anti-Lock-In

- [ ] **No lock-in provisions**: Contract must not contain provisions that create
  unreasonable barriers to switching providers (excessive termination fees,
  proprietary data formats without export capability, non-compete clauses).
  _[DORA Art.28(8)]_

- [ ] **API and format standards**: Where applicable, vendor must use open standards
  and formats to facilitate interoperability and migration.
  _[DORA Art.28(8)]_

---

## Compliance Mapping

| Control Area | DORA | NIS2 | ISO 27001 | SOC 2 |
|-------------|------|------|-----------|-------|
| Incident notification | Art.28(7) | Art.21.2(d) | A.5.20 | CC7.4, CC7.5 |
| Subprocessor management | Art.29 | Art.21.2(d) | A.5.21 | CC9.2 |
| Security assurance/audit | Art.28(6) | Art.21.2(d) | A.5.22 | CC3.1, CC9.2 |
| Access control | Art.28(5) | Art.21.2(d) | A.5.20 | CC6.1, CC6.3 |
| Data protection/DPA | Art.28(2) | Art.21.2(d) | A.5.19 | CC2.3 |
| Data residency | Art.28(4) | -- | A.5.19 | CC2.3 |
| Data lifecycle | Art.28(8) | -- | A.5.19 | CC6.5 |
| SLA/availability | Art.28(5) | Art.21.2(d) | A.5.22 | CC9.2 |
| Change management | Art.28(5) | -- | A.5.22 | CC8.1 |
| BC/DR | Art.28(5) | Art.21.2(d) | A.5.22 | CC9.1 |
| Exit/transition | Art.28(8) | -- | A.5.23 | CC9.2 |
| Anti-lock-in | Art.28(8) | -- | A.5.23 | CC9.2 |

---

## Usage Instructions

1. For each new vendor rated **Medium** or above in the
   [vendor-risk-register.md](vendor-risk-register.md), complete this checklist against
   the vendor's contract, DPA, and service agreement.
2. Document any gaps as risk exceptions requiring approval per the
   [vendor-due-diligence-checklist.md](vendor-due-diligence-checklist.md) approval
   authority table.
3. Store completed checklists alongside vendor contracts in the secure document
   repository.
4. Review annually or upon contract renewal, whichever comes first.

---

## Review History

| Date | Reviewer | Changes |
|------|----------|---------|
| 2026-03-15 | Initial creation | Contract control requirements established |
