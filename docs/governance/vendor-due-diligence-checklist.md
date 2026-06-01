# Vendor Due Diligence Checklist

**Document Owner:** Security Lead
**Last Reviewed:** 2026-03-15
**Review Cadence:** Annually and upon process changes
**Compliance Scope:** DORA Art.28-30, NIS2 Art.21.2.d, ISO 27001 A.5.19-A.5.23, SOC 2 CC9

---

## Purpose

This checklist must be completed before onboarding any new third-party ICT service
provider or adopting any new open-source tool within the CyberForge DevSecOps Pipeline.
It ensures consistent evaluation of security, data handling, legal, and operational
risks in accordance with DORA, NIS2, ISO 27001, and SOC 2 requirements.

---

## Vendor Information

| Field | Value |
|-------|-------|
| Vendor Name | |
| Service/Product | |
| Proposed Use Case | |
| Requestor | |
| Date of Evaluation | |
| Evaluator(s) | |

---

## 1. Security Posture Assessment

### 1.1 Certifications and Compliance

- [ ] Vendor holds SOC 2 Type II certification (current, within last 12 months)
- [ ] Vendor holds ISO 27001 certification (current, within last 3 years)
- [ ] Vendor provides penetration test results or summary (within last 12 months)
- [ ] Vendor has a published security policy or security whitepaper
- [ ] Vendor participates in a bug bounty or responsible disclosure program

### 1.2 Security Practices

- [ ] Vendor implements encryption at rest (AES-256 or equivalent)
- [ ] Vendor implements encryption in transit (TLS 1.2+ minimum)
- [ ] Vendor enforces multi-factor authentication for administrative access
- [ ] Vendor follows secure software development lifecycle (SSDLC)
- [ ] Vendor performs regular vulnerability scanning and patching
- [ ] Vendor has a documented incident response plan

### 1.3 Incident History

- [ ] No major security breaches in the past 24 months
- [ ] If breaches occurred: root cause analysis and remediation documented
- [ ] Vendor provides incident notification within 24-72 hours (contractual)

**Notes:**
```
[Document findings here]
```

---

## 2. Data Handling Assessment

### 2.1 Data Classification

- [ ] Identified all data types the vendor will process, store, or transmit
- [ ] Classified data sensitivity level (Public / Internal / Confidential / Restricted)
- [ ] Documented data flow from pipeline to vendor and back
- [ ] Confirmed no unnecessary data collection or retention

### 2.2 Data Storage and Processing

- [ ] Data processing location(s) identified and documented
- [ ] Data residency requirements satisfied (EU/EEA for personal data)
- [ ] Data retention period defined and acceptable
- [ ] Data deletion/destruction procedures documented
- [ ] Backup and recovery procedures documented

### 2.3 Data Sharing

- [ ] Subprocessors identified and documented
- [ ] No unauthorized data sharing with third parties
- [ ] Data aggregation/anonymization practices documented (if applicable)

**Data Types Processed:**
```
[List specific data types here]
```

**Data Location(s):**
```
[List processing/storage locations here]
```

---

## 3. Legal and Contractual Assessment

### 3.1 Data Protection Agreement

- [ ] DPA available and reviewed by legal counsel
- [ ] DPA compliant with GDPR Art.28 requirements
- [ ] Standard Contractual Clauses (SCCs) in place for non-EU transfers (if applicable)
- [ ] Transfer Impact Assessment completed (if non-EU transfer)

### 3.2 GDPR Compliance

- [ ] Vendor has appointed a Data Protection Officer (if required)
- [ ] Vendor maintains a Record of Processing Activities
- [ ] Vendor supports data subject rights (access, deletion, portability)
- [ ] Vendor has a published privacy policy

### 3.3 Contractual Terms

- [ ] Contract reviewed by legal counsel
- [ ] Liability and indemnification terms acceptable
- [ ] Intellectual property rights clearly defined
- [ ] Governing law and jurisdiction acceptable
- [ ] Termination provisions reviewed (see Section 6)

**Notes:**
```
[Document legal findings here]
```

---

## 4. Operational Assessment

### 4.1 Service Level Agreement

- [ ] SLA defines availability targets (e.g., 99.9% uptime)
- [ ] SLA defines response times for incident severity levels
- [ ] SLA defines escalation procedures
- [ ] SLA penalties or credits for non-compliance documented
- [ ] Historical uptime data reviewed (if publicly available)

### 4.2 Support and Communication

- [ ] Support channels defined (email, chat, phone, portal)
- [ ] Support hours and response times documented
- [ ] Dedicated account manager or support contact assigned (if applicable)
- [ ] Change notification process defined (advance notice for material changes)

### 4.3 Business Continuity

- [ ] Vendor has a documented business continuity plan
- [ ] Vendor has a documented disaster recovery plan
- [ ] Recovery Time Objective (RTO) acceptable
- [ ] Recovery Point Objective (RPO) acceptable
- [ ] Vendor performs regular BC/DR testing

**Notes:**
```
[Document operational findings here]
```

---

## 5. Supply Chain Assessment

### 5.1 Subprocessors

- [ ] List of subprocessors obtained and reviewed
- [ ] Subprocessor notification process defined (advance notice of changes)
- [ ] Right to object to new subprocessors documented
- [ ] Subprocessor data processing locations identified

### 5.2 Open Source (for OSS tools only)

- [ ] License type identified and compatible with project requirements
- [ ] Project is actively maintained (commits within last 6 months)
- [ ] Project has a security policy (SECURITY.md or equivalent)
- [ ] Known vulnerabilities assessed (CVE database, GitHub Security Advisories)
- [ ] Community health assessed (contributors, issue response time, release cadence)
- [ ] No telemetry or phone-home behavior enabled by default (or can be disabled)

### 5.3 Dependency Chain

- [ ] Vendor's own dependency chain assessed for concentration risk
- [ ] No single points of failure in the vendor's infrastructure
- [ ] Vendor's key personnel/team risk assessed (for small vendors/OSS projects)

**Notes:**
```
[Document supply chain findings here]
```

---

## 6. Exit and Portability Assessment

### 6.1 Data Portability

- [ ] Data export formats documented (standard, machine-readable)
- [ ] Data export mechanism available (API, bulk export, manual request)
- [ ] Data migration timeline estimated
- [ ] Data deletion confirmation process documented

### 6.2 Service Transition

- [ ] Alternative vendors/tools identified
- [ ] Migration path assessed (effort, timeline, risks)
- [ ] Contract termination notice period documented
- [ ] Transition assistance provisions in contract (minimum 90 days)
- [ ] No vendor lock-in provisions (proprietary formats, exclusive APIs)

### 6.3 Exit Plan

- [ ] Exit plan drafted using [vendor-exit-plan-template.md](vendor-exit-plan-template.md)
- [ ] Exit plan reviewed and approved

**Notes:**
```
[Document exit/portability findings here]
```

---

## 7. Risk Classification

### 7.1 Risk Rating Matrix

Determine the overall risk rating based on data sensitivity and operational dependency:

| | Low Operational Dependency | Medium Operational Dependency | High Operational Dependency |
|---|---|---|---|
| **No External Data** | Low | Low | Medium |
| **Public Data Only** | Low | Medium | Medium |
| **Internal/Confidential Data** | Medium | Medium | High |
| **Restricted/Personal Data** | Medium | High | Critical |

### 7.2 Classification Result

| Factor | Assessment |
|--------|------------|
| Data Sensitivity | [ ] None / [ ] Public / [ ] Internal / [ ] Confidential / [ ] Restricted |
| Operational Dependency | [ ] Low / [ ] Medium / [ ] High |
| **Overall Risk Rating** | [ ] Low / [ ] Medium / [ ] High / [ ] Critical |
| **Criticality Level** | [ ] Low / [ ] Medium / [ ] High / [ ] Critical |

---

## 8. Approval

### 8.1 Approval Authority

| Risk Rating | Required Approvals |
|-------------|-------------------|
| **Low** | Security Lead |
| **Medium** | Security Lead + Engineering Lead |
| **High** | CTO + Security Lead |
| **Critical** | CTO + Security Lead + Legal Counsel |

### 8.2 Approval Record

| Role | Name | Decision | Date | Signature |
|------|------|----------|------|-----------|
| Security Lead | | [ ] Approve / [ ] Reject / [ ] Conditional | | |
| Engineering Lead | | [ ] Approve / [ ] Reject / [ ] Conditional | | |
| CTO | | [ ] Approve / [ ] Reject / [ ] Conditional | | |
| Legal Counsel | | [ ] Approve / [ ] Reject / [ ] Conditional | | |

### 8.3 Conditions (if conditional approval)

```
[Document any conditions for approval here]
```

---

## 9. Post-Onboarding Actions

Upon approval, complete the following:

- [ ] Add vendor to [vendor-risk-register.md](vendor-risk-register.md)
- [ ] Execute DPA (if personal data processed)
- [ ] Configure monitoring/alerting for the service
- [ ] Document exit plan using [vendor-exit-plan-template.md](vendor-exit-plan-template.md)
- [ ] Add vendor to [check-dpa.sh](../../scripts/check-dpa.sh) processor inventory
- [ ] Schedule first periodic review (quarterly for High/Critical, annually for Low/Medium)
- [ ] Update contract controls checklist per [ict-third-party-contract-controls.md](ict-third-party-contract-controls.md)

---

## Review History

| Date | Reviewer | Changes |
|------|----------|---------|
| 2026-03-15 | Initial creation | Checklist template established |
