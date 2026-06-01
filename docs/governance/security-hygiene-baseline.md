# Security Hygiene Baseline

| Field          | Value                                                  |
|----------------|--------------------------------------------------------|
| Document Owner | Security Lead                                          |
| Approved By    | CyberForge Management                                  |
| Version        | 1.0                                                    |
| Effective Date | 2026-03-15                                             |
| Review Cycle   | Annually, or after significant security incidents      |
| Compliance     | NIS2 Art.21.2.g, ISO 27001 Clause 7.3, DORA (general hygiene), SOC 2 CC1/CC2 |

---

## 1. Purpose

This document defines the baseline cyber hygiene practices that all CyberForge personnel must follow. NIS2 Art.21.2.g requires "basic cyber hygiene practices and cybersecurity training" as part of the cybersecurity risk-management measures. This baseline establishes the minimum acceptable security behaviors for anyone with access to CyberForge systems.

Adherence to this baseline is mandatory, not aspirational. Each item represents a concrete, verifiable security control that reduces the attack surface of CyberForge's operations and protects client assets processed through the pipeline.

---

## 2. Scope

This baseline applies to:

- All CyberForge personnel (employees, co-founders, contractors).
- All systems used to access, develop, or operate CyberForge services (workstations, mobile devices, cloud accounts).
- External parties with temporary access (auditors, consultants) for the duration of their engagement.

---

## 3. Authentication and Access

- [ ] MFA enabled on all GitHub accounts (enforced at org level).
- [ ] MFA enabled on all Azure accounts (enforced via Conditional Access).
- [ ] SSH keys: Ed25519 or RSA-4096 minimum, rotated annually.
- [ ] No shared accounts or credentials.
- [ ] Password manager used for all non-SSO credentials.
- [ ] OIDC federation for all CI/CD-to-cloud authentication (no static secrets).
- [ ] Principle of least privilege applied to all access grants.
- [ ] Unique, strong passwords for all accounts (minimum 16 characters for non-SSO accounts).
- [ ] No password reuse across services.

### Rationale

Credential compromise is the most common initial attack vector in software supply chain attacks. MFA, strong passwords, and the elimination of shared credentials substantially reduce this risk. OIDC federation eliminates the need for stored cloud credentials entirely, removing a major class of secret exposure vulnerabilities.

Reference: [IAM Governance Policy](iam-governance.md), Section 5 (Authentication Requirements).

---

## 4. Device Security (Developer Workstations)

- [ ] Full disk encryption enabled (LUKS/FileVault/BitLocker).
- [ ] OS and software kept up to date (security patches within 7 days of release).
- [ ] Antivirus/EDR installed and active (where applicable to OS).
- [ ] Screen lock enabled (5 minute timeout maximum).
- [ ] No sensitive data stored locally outside encrypted volumes.
- [ ] Git commit signing configured (GPG or SSH).
- [ ] Automatic OS updates enabled where supported.
- [ ] Browser extensions minimized to trusted, necessary extensions only.

### Rationale

Developer workstations have direct access to source code, credentials, and cloud management interfaces. A compromised workstation can lead to unauthorized code changes, secret exfiltration, or supply chain attacks. Full disk encryption protects data at rest if a device is lost or stolen. Timely patching closes known vulnerability windows. Commit signing ensures code provenance.

---

## 5. Network Security

- [ ] VPN or secure connection required for remote access to sensitive systems.
- [ ] Public Wi-Fi: VPN mandatory before accessing any CyberForge systems.
- [ ] Home network: router firmware updated, default passwords changed.
- [ ] No use of open/unencrypted Wi-Fi networks for work activities.
- [ ] DNS-over-HTTPS or DNS-over-TLS enabled where supported.

### Rationale

Network-level attacks (man-in-the-middle, DNS spoofing, traffic interception) can compromise authentication tokens, expose sensitive data in transit, and enable session hijacking. VPN usage on untrusted networks provides an encrypted tunnel that mitigates these risks.

---

## 6. Email and Communication

- [ ] Phishing awareness: verify sender before clicking links or downloading attachments.
- [ ] Do not send credentials, secrets, or sensitive data via email or chat.
- [ ] Report suspicious emails to Security Lead immediately.
- [ ] Verify out-of-band any requests for credential changes, access grants, or fund transfers.
- [ ] Do not use personal email accounts for CyberForge business communications.

### Rationale

Social engineering and phishing remain among the most effective attack vectors. Even technically sophisticated organizations are vulnerable to well-crafted phishing campaigns. Verification of unusual requests out-of-band (e.g., confirming a credential reset request via phone) prevents business email compromise attacks.

---

## 7. Code and Repository Security

- [ ] Never commit secrets, credentials, or API keys to repositories.
- [ ] Use `.gitignore` to exclude sensitive files (`.env`, `credentials.json`, private keys).
- [ ] Review and understand `.trivyignore` entries (VEX justification required for each entry).
- [ ] Use signed commits for all contributions.
- [ ] Review dependencies before adding (check maintenance status, known vulnerabilities, license compatibility).
- [ ] Do not disable or bypass pipeline security gates without documented risk acceptance.
- [ ] Verify GitHub Actions are pinned to full SHA before using them.
- [ ] Do not grant repository access beyond what is needed for the task.

### Rationale

The source code repository is the primary target for software supply chain attacks. Committed secrets can be harvested from git history even after deletion. Unsigned commits allow impersonation. Unvetted dependencies introduce transitive risk. These controls directly support the pipeline's security posture.

Reference: [Vulnerability Management Policy](vulnerability-management-policy.md), [Risk Acceptance Process](risk-acceptance-process.md).

---

## 8. Incident Reporting

- [ ] Report any suspected security incident immediately to Security Lead.
- [ ] Preserve evidence (do not delete logs, screenshots, or communications).
- [ ] Do not attempt to investigate or contain alone without notifying the team.
- [ ] If in doubt whether something is an incident, report it anyway.
- [ ] Follow the escalation procedures in the [Crisis Management Plan](crisis-management-plan.md) for events that meet crisis criteria.

### Rationale

Rapid reporting is essential for effective incident response. Delayed reporting increases the window of exposure and can cause CyberForge to miss regulatory notification deadlines (NIS2: 24 hours for early warning; DORA: 4 hours for initial notification). Evidence preservation prevents loss of forensic data needed for root cause analysis.

Reference: Incident Handling Runbooks (planned, Task 24, `docs/runbooks/`).

---

## 9. Data Handling

- [ ] Classify data before processing (Strictly Confidential, Confidential, Internal, Public).
- [ ] Do not store client data on personal devices.
- [ ] Use approved tools only for data processing.
- [ ] Dispose of sensitive data securely (secure delete, shred physical media).
- [ ] Do not transfer data to unapproved cloud services or personal accounts.
- [ ] When in doubt about classification, treat data as Confidential until confirmed otherwise.

### Rationale

Improper data handling can lead to unauthorized disclosure, regulatory violations (GDPR breach notification obligations), and loss of client trust. The data classification scheme defined in the [Asset Inventory](asset-inventory.md) provides the framework for consistent data handling decisions.

Reference: [Asset Inventory](asset-inventory.md), Section 2 (Data Classification Scheme).

---

## 10. Physical Security

- [ ] Do not leave devices unattended in public spaces.
- [ ] Lock workstation when stepping away (even in private offices).
- [ ] Secure physical access to any location where CyberForge work is performed.
- [ ] Do not allow unauthorized persons to observe screens displaying sensitive data.
- [ ] Report lost or stolen devices to Security Lead immediately.

### Rationale

Physical access to an unlocked workstation bypasses all logical access controls. Lost or stolen devices may contain cached credentials, active sessions, or locally stored sensitive data. Immediate reporting enables rapid credential rotation and session revocation.

---

## 11. Acknowledgement and Compliance

### 11.1 Acknowledgement Requirement

All CyberForge personnel must formally acknowledge this baseline:

- **New joiners:** Within the first week of onboarding, as part of the [JML Process](jml-process.md).
- **Existing personnel:** Annually, within 30 days of the review date.
- **After significant updates:** Within 30 days of any material revision to this baseline.

Acknowledgement confirms that the individual has read, understood, and commits to following the baseline requirements.

### 11.2 Acknowledgement Record

| Date | Name | Role | Version Acknowledged | Signature/Confirmation |
|------|------|------|----------------------|------------------------|
| | | | | |

### 11.3 Non-Compliance

Failure to follow the security hygiene baseline may result in:

1. Verbal reminder and additional training for first-time, low-risk violations.
2. Written warning and mandatory remedial training for repeated or higher-risk violations.
3. Access suspension pending review for violations that create immediate security risk.
4. Disciplinary action per employment/contractor agreements for willful or repeated non-compliance.

All non-compliance incidents are documented and reviewed as part of the annual security hygiene baseline review.

---

## 12. Verification Methods

The Security Lead verifies compliance with this baseline through:

| Verification Method                | Frequency       | Covers                                       |
|------------------------------------|-----------------|-----------------------------------------------|
| GitHub org MFA enforcement check   | Continuous      | Authentication and Access (MFA)               |
| Azure Conditional Access audit     | Quarterly       | Authentication and Access (MFA, SSO)          |
| SSH key audit                      | Annually        | Authentication and Access (key rotation)      |
| Access review                      | Quarterly/Semi-annually | Authentication and Access (least privilege) |
| Pipeline gate enforcement          | Continuous      | Code and Repository Security                  |
| Acknowledgement record review      | Annually        | Overall compliance                            |
| Spot checks (device encryption)    | Annually        | Device Security                               |

---

## 13. Compliance Mapping

| Requirement                        | Framework Reference       | How This Baseline Addresses It                         |
|------------------------------------|---------------------------|--------------------------------------------------------|
| Basic cyber hygiene practices      | NIS2 Art.21.2.g           | Comprehensive hygiene baseline with verification       |
| Cybersecurity training             | NIS2 Art.21.2.g           | Baseline acknowledgement includes awareness training   |
| Multi-factor authentication        | NIS2 Art.21.2.j           | MFA requirement for all accounts                       |
| Access control                     | NIS2 Art.21.2.i           | Least privilege, no shared credentials, access review  |
| Awareness                          | ISO 27001 Clause 7.3      | Mandatory acknowledgement and annual renewal           |
| Acceptable use                     | ISO 27001 A.5.10          | Data handling, device security, network security rules |
| Information security awareness     | SOC 2 CC1.4               | Security hygiene practices and acknowledgement         |
| Internal communications            | SOC 2 CC2.2               | Baseline communicates security expectations            |
| ICT risk management                | DORA Art.16               | Hygiene practices reduce operational ICT risk          |

---

## 14. Related Documents

- [IAM Governance Policy](iam-governance.md)
- [JML Process](jml-process.md)
- [Asset Inventory](asset-inventory.md)
- [Crisis Management Plan](crisis-management-plan.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Risk Acceptance Process](risk-acceptance-process.md)
- [NIS2 Management Training Records](nis2-management-training-records.md)
- [Security Training Program](security-training-program.md) (Task 29)
- Incident Handling Runbooks (planned, Task 24, `docs/runbooks/`)

---

## 15. Revision History

| Date       | Change             | Author                  |
|------------|--------------------|-------------------------|
| 2026-03-15 | Initial version    | CyberForge Engineering  |
