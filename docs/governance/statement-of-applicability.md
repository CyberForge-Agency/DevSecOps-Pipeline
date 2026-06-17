# Statement of Applicability

**Document Owner:** Security Lead
**Last Reviewed:** 2026-03-15
**Review Cadence:** Annually, or after significant changes to the ISMS scope or control environment
**Version:** 1.0
**ISO 27001 Reference:** Clause 6.1.3 d)

---

## 1. Purpose

This Statement of Applicability (SoA) documents the applicability decisions for all 93 controls in Annex A of ISO/IEC 27001:2022. For each control, it states whether the control is applicable, the justification for inclusion or exclusion, the current implementation status, and references to implementing documents or systems.

This document is a mandatory requirement for ISO 27001 certification and serves as the definitive link between the risk assessment, the risk treatment plan, and the implemented controls.

---

## 2. Scope

This SoA applies to the ISMS scope as defined in [isms-scope.md](isms-scope.md): the CyberForge DevSecOps Pipeline platform, supporting cloud infrastructure, and governance processes.

---

## 3. Status Definitions

| Status | Definition |
|---|---|
| **Implemented** | Control is fully operational with documented evidence |
| **Partially Implemented** | Control is in place but requires additional work to reach full effectiveness |
| **Planned** | Control is not yet implemented; scheduled for a future phase |
| **Not Applicable** | Control is excluded from scope with documented justification |

---

## 4. Annex A Controls

### A.5 Organizational Controls (A.5.1 -- A.5.37)

| Control | Name | Applicable? | Justification | Status | Reference |
|---|---|---|---|---|---|
| A.5.1 | Policies for information security | Yes | Required to establish management direction for information security | Implemented | `docs/governance/` (all governance policy documents) |
| A.5.2 | Information security roles and responsibilities | Yes | Required to assign and communicate security responsibilities | Implemented | `docs/governance/iam-governance.md`, ISMS scope Section 6 |
| A.5.3 | Segregation of duties | Yes | Required to reduce risk of unauthorized or unintentional modification | Partially Implemented | 2-reviewer PR requirement, CODEOWNERS, branch protection. Limited by 2-person startup size; compensating controls documented. |
| A.5.4 | Management responsibilities | Yes | Management must ensure personnel follow security policies | Implemented | `docs/governance/isms-scope.md` Section 6, management review process |
| A.5.5 | Contact with authorities | Yes | Required for regulatory incident reporting (NIS2, RODO) | Implemented | `docs/governance/crisis-management-plan.md` (CSIRT, UODO, KNF contact procedures) |
| A.5.6 | Contact with special interest groups | Yes | Stay informed about threats and best practices | Partially Implemented | Participation in OWASP, CNCF supply chain security WG. Formal register planned for Phase F. |
| A.5.7 | Threat intelligence | Yes | Required to maintain awareness of current threat landscape | Partially Implemented | GitHub Advisory Database, Trivy vulnerability feeds, NVD. Formal threat intelligence process planned. |
| A.5.8 | Information security in project management | Yes | Security must be integrated into project delivery | Implemented | Security gates integrated into every pipeline phase; `.github/workflows/security-gate.yml`, `.github/workflows/build-and-scan.yml` |
| A.5.9 | Inventory of information and other associated assets | Yes | Required to identify assets requiring protection | Implemented | `docs/governance/asset-inventory.md`, `docs/governance/service-inventory.md` |
| A.5.10 | Acceptable use of information and other associated assets | Yes | Required to define rules for use of assets | Implemented | `docs/governance/security-hygiene-baseline.md` |
| A.5.11 | Return of assets | Yes | Required when personnel leave the organization | Implemented | `docs/governance/jml-process.md` (Leaver process) |
| A.5.12 | Classification of information | Yes | Required to ensure information receives appropriate protection | Implemented | `docs/governance/isms-scope.md` Section 4.2 (asset classification), `docs/governance/asset-inventory.md` |
| A.5.13 | Labelling of information | Yes | Required to identify classified information | Partially Implemented | Document classification headers present; automated labelling planned for Phase F. |
| A.5.14 | Information transfer | Yes | Required to protect information shared externally | Partially Implemented | TLS enforced for all transfers; evidence packs use SHA256 integrity verification. Formal transfer policy planned. |
| A.5.15 | Access control | Yes | Required to control access to information and systems | Implemented | `docs/governance/iam-governance.md`, `docs/governance/access-review-procedure.md` |
| A.5.16 | Identity management | Yes | Required to manage the full lifecycle of identities | Implemented | `docs/governance/jml-process.md`, Azure AD/Entra ID, GitHub organization management |
| A.5.17 | Authentication information | Yes | Required to control allocation and management of authentication | Implemented | `docs/governance/iam-governance.md` (MFA, OIDC federation, no static credentials) |
| A.5.18 | Access rights | Yes | Required to provision, review, and revoke access rights | Implemented | `docs/governance/access-review-procedure.md`, `docs/governance/jml-process.md` |
| A.5.19 | Information security in supplier relationships | Yes | Required to manage ICT supply chain risk (DORA Art.28) | Implemented | `docs/governance/vendor-risk-register.md`, `docs/governance/vendor-due-diligence-checklist.md` |
| A.5.20 | Addressing information security within supplier agreements | Yes | Required to establish security obligations in contracts | Implemented | `docs/governance/ict-third-party-contract-controls.md` |
| A.5.21 | Managing information security in the ICT supply chain | Yes | Required to manage supply chain risks across the chain | Implemented | `docs/governance/vendor-risk-register.md`, SHA-pinned Actions, SBOM generation, Cosign signing |
| A.5.22 | Monitoring, review and change management of supplier services | Yes | Required to monitor supplier performance and changes | Partially Implemented | `docs/governance/vendor-risk-register.md` (quarterly review) is the active control; `renovate.json` config present; Renovate App activation pending |
| A.5.23 | Information security for use of cloud services | Yes | Core to CyberForge operations (Azure, GitHub) | Implemented | `docs/governance/vendor-risk-register.md`, Azure OIDC federation, `docs/governance/iam-governance.md` |
| A.5.24 | Information security incident management planning and preparation | Yes | Required to prepare for security incidents | Implemented | `docs/governance/crisis-management-plan.md`, `docs/governance/vulnerability-management-policy.md` |
| A.5.25 | Assessment and decision on information security events | Yes | Required to assess and classify security events | Implemented | `docs/governance/vulnerability-management-policy.md` (severity classification) |
| A.5.26 | Response to information security incidents | Yes | Required to respond to incidents | Implemented | `docs/governance/crisis-management-plan.md` |
| A.5.27 | Learning from information security incidents | Yes | Required to improve from incidents | Partially Implemented | Post-incident reviews defined in crisis management plan; formal lessons-learned database planned. |
| A.5.28 | Collection of evidence | Yes | Required for incident investigation and legal proceedings | Implemented | Evidence Pack workflow (`.github/workflows/evidence-pack.yml`), SHA256 manifests, Azure WORM storage |
| A.5.29 | Information security during disruption | Yes | Required to maintain security during disruptions | Implemented | `docs/governance/crisis-management-plan.md` |
| A.5.30 | ICT readiness for business continuity | Yes | Required to ensure ICT services can be restored | Partially Implemented | Infrastructure as code (Terraform) enables rapid re-provisioning. Formal BCP/DR plan planned for Phase F. |
| A.5.31 | Legal, statutory, regulatory and contractual requirements | Yes | Required to identify compliance obligations | Implemented | `docs/compliance/scope-and-limitations.md`, `docs/compliance/framework-boundaries.md` |
| A.5.32 | Intellectual property rights | Yes | Required to protect IP and comply with licensing | Partially Implemented | Open-source license compliance tracked via SBOM. Formal IP register planned. |
| A.5.33 | Protection of records | Yes | Required to protect records from loss or falsification | Implemented | Azure WORM immutability for evidence packs; governance docs in version-controlled repository |
| A.5.34 | Privacy and protection of personal information | Yes | Required for RODO/GDPR compliance | Partially Implemented | Privacy considerations in ISMS scope. Formal DPIA and privacy program planned for Phase F. |
| A.5.35 | Independent review of information security | Yes | Required to ensure ISMS effectiveness | Planned | Internal audit program to be executed per `docs/governance/internal-audit-program.md`. External certification audit planned. |
| A.5.36 | Compliance with policies, rules and standards for information security | Yes | Required to verify adherence to policies | Planned | Internal audit program will verify compliance. Automated policy checks via OPA (`policies/`). |
| A.5.37 | Documented operating procedures | Yes | Required to document procedures for information processing | Implemented | Pipeline workflows documented in `.github/workflows/`; governance procedures in `docs/governance/`; runbooks in `docs/` |

### A.6 People Controls (A.6.1 -- A.6.8)

| Control | Name | Applicable? | Justification | Status | Reference |
|---|---|---|---|---|---|
| A.6.1 | Screening | Yes | Required to verify personnel before granting access | Partially Implemented | Background verification for founders completed. Formal screening procedure for future hires planned. |
| A.6.2 | Terms and conditions of employment | Yes | Required to include security responsibilities in employment terms | Implemented | Security obligations defined in employment contracts; NDA requirements |
| A.6.3 | Information security awareness, education and training | Yes | Required to ensure personnel competence | Implemented | `docs/governance/security-training-program.md`, `docs/governance/nis2-management-training-records.md` |
| A.6.4 | Disciplinary process | Yes | Required to address security policy violations | Partially Implemented | Process defined at management level. Formal documented procedure planned as team grows. |
| A.6.5 | Responsibilities after termination or change of employment | Yes | Required to protect information after employment ends | Implemented | `docs/governance/jml-process.md` (Leaver process: access revocation, NDA continuation) |
| A.6.6 | Confidentiality or non-disclosure agreements | Yes | Required to protect confidential information | Implemented | NDA required for all personnel and contractors; defined in `docs/governance/jml-process.md` |
| A.6.7 | Remote working | Yes | Core operating model -- CyberForge is remote-first | Implemented | `docs/governance/security-hygiene-baseline.md` (device security, VPN, encrypted storage) |
| A.6.8 | Information security event reporting | Yes | Required to enable personnel to report security events | Implemented | Reporting procedures in `docs/governance/crisis-management-plan.md`; dedicated security channel |

### A.7 Physical Controls (A.7.1 -- A.7.14)

| Control | Name | Applicable? | Justification | Status | Reference |
|---|---|---|---|---|---|
| A.7.1 | Physical security perimeters | No | Remote-first company, cloud-hosted infrastructure. Physical security delegated to cloud provider (Microsoft Azure SOC 2 report). | Not Applicable | Azure SOC 2 Type II report |
| A.7.2 | Physical entry | No | Remote-first company, cloud-hosted infrastructure. Physical security delegated to cloud provider (Microsoft Azure SOC 2 report). | Not Applicable | Azure SOC 2 Type II report |
| A.7.3 | Securing offices, rooms and facilities | No | Remote-first company, cloud-hosted infrastructure. Physical security delegated to cloud provider (Microsoft Azure SOC 2 report). | Not Applicable | Azure SOC 2 Type II report |
| A.7.4 | Physical security monitoring | No | Remote-first company, cloud-hosted infrastructure. Physical security delegated to cloud provider (Microsoft Azure SOC 2 report). | Not Applicable | Azure SOC 2 Type II report |
| A.7.5 | Protecting against physical and environmental threats | No | Remote-first company, cloud-hosted infrastructure. Physical security delegated to cloud provider (Microsoft Azure SOC 2 report). | Not Applicable | Azure SOC 2 Type II report |
| A.7.6 | Working in secure areas | No | Remote-first company, cloud-hosted infrastructure. Physical security delegated to cloud provider (Microsoft Azure SOC 2 report). | Not Applicable | Azure SOC 2 Type II report |
| A.7.7 | Clear desk and clear screen | Yes | Applicable to remote worker home offices to prevent information exposure | Partially Implemented | `docs/governance/security-hygiene-baseline.md` (screen lock policy). Enforcement via endpoint management planned. |
| A.7.8 | Equipment siting and protection | No | Remote-first company, cloud-hosted infrastructure. Physical security delegated to cloud provider (Microsoft Azure SOC 2 report). | Not Applicable | Azure SOC 2 Type II report |
| A.7.9 | Security of assets off-premises | Yes | Developer workstations used outside traditional office environments | Implemented | `docs/governance/security-hygiene-baseline.md` (encrypted disks, device security requirements) |
| A.7.10 | Storage media | Yes | Developer workstations may contain sensitive data on local storage | Partially Implemented | Full-disk encryption required per security hygiene baseline. Formal media disposal procedure planned. |
| A.7.11 | Supporting utilities | No | Remote-first company, cloud-hosted infrastructure. Physical security delegated to cloud provider (Microsoft Azure SOC 2 report). | Not Applicable | Azure SOC 2 Type II report |
| A.7.12 | Cabling security | No | Remote-first company, cloud-hosted infrastructure. Physical security delegated to cloud provider (Microsoft Azure SOC 2 report). | Not Applicable | Azure SOC 2 Type II report |
| A.7.13 | Equipment maintenance | No | Remote-first company, cloud-hosted infrastructure. Physical security delegated to cloud provider (Microsoft Azure SOC 2 report). Developer workstations are personally managed. | Not Applicable | Azure SOC 2 Type II report |
| A.7.14 | Secure disposal or re-use of equipment | Yes | Developer workstations must be securely wiped before disposal or re-use | Planned | Formal secure disposal procedure to be documented. Currently covered by security hygiene baseline guidance. |

### A.8 Technological Controls (A.8.1 -- A.8.34)

| Control | Name | Applicable? | Justification | Status | Reference |
|---|---|---|---|---|---|
| A.8.1 | User endpoint devices | Yes | Developer workstations access pipeline systems | Implemented | `docs/governance/security-hygiene-baseline.md` (encryption, OS updates, antimalware) |
| A.8.2 | Privileged access rights | Yes | Required to control administrative access to pipeline and cloud resources | Implemented | `docs/governance/iam-governance.md`, `docs/governance/access-review-procedure.md` (quarterly privileged access review) |
| A.8.3 | Information access restriction | Yes | Required to enforce least privilege on information assets | Implemented | `docs/governance/iam-governance.md` (least privilege principle), CODEOWNERS, branch protection |
| A.8.4 | Access to source code | Yes | Source code is a critical asset requiring controlled access | Implemented | GitHub repository permissions, CODEOWNERS, branch protection (2-reviewer requirement, signed commits), `.github/workflows/security-gate.yml` |
| A.8.5 | Secure authentication | Yes | Required to prevent unauthorized access through strong authentication | Implemented | `docs/governance/iam-governance.md` (MFA mandatory, OIDC federation, no passwords for service accounts) |
| A.8.6 | Capacity management | Yes | Required to ensure adequate pipeline and infrastructure capacity | Partially Implemented | Azure autoscaling for Container Apps. Formal capacity planning process planned for Phase F. |
| A.8.7 | Protection against malware | Yes | Required to protect pipeline runners and workstations | Partially Implemented | GitHub-hosted runners are ephemeral (clean environment per run). Endpoint protection on developer workstations per security hygiene baseline. |
| A.8.8 | Management of technical vulnerabilities | Yes | Core pipeline function -- vulnerability detection and remediation | Implemented | `.github/workflows/build-and-scan.yml` (Trivy SCA, Trivy image, CodeQL SAST), `.github/workflows/dast.yml` (OWASP ZAP), `docs/governance/vulnerability-management-policy.md` |
| A.8.9 | Configuration management | Yes | Required to ensure secure configuration of pipeline and infrastructure | Implemented | `.github/workflows/security-gate.yml` (Checkov IaC scanning), Terraform version-controlled infrastructure (`infra/`), OPA policies (`policies/`) |
| A.8.10 | Information deletion | Yes | Required to ensure data is deleted when no longer needed | Partially Implemented | Azure Blob Storage lifecycle policies. Formal data retention and deletion procedure planned. |
| A.8.11 | Data masking | Yes | Required to protect sensitive data in non-production environments | Partially Implemented | No production personal data in pipeline demo app. Masking requirements defined for client engagements. |
| A.8.12 | Data leakage prevention | Yes | Required to prevent unauthorized data exfiltration | Implemented | TruffleHog secret scanning (`.github/workflows/security-gate.yml`), GitHub push protection, `.gitignore` enforcement |
| A.8.13 | Information backup | Yes | Required to protect against data loss | Implemented | Source code in GitHub (replicated); infrastructure as code in version control; evidence packs in Azure WORM storage |
| A.8.14 | Redundancy of information processing facilities | Yes | Required to maintain availability | Partially Implemented | Azure Container Apps multi-instance deployment. Formal availability and redundancy architecture planned. |
| A.8.15 | Logging | Yes | Required for security monitoring and incident investigation | Implemented | GitHub Actions workflow logs, GitHub audit log, Azure Activity Log, `.github/workflows/evidence-pack.yml` (evidence collection) |
| A.8.16 | Monitoring activities | Yes | Required to detect anomalous behavior and security events | Partially Implemented | GitHub audit log monitoring, Azure Monitor. Formal SIEM integration and alerting planned for Phase F. |
| A.8.17 | Clock synchronization | Yes | Required for accurate log correlation | Implemented | GitHub Actions and Azure services use NTP-synchronized system clocks. No custom time sources. |
| A.8.18 | Use of privileged utility programs | Yes | Required to restrict access to system-level utilities | Implemented | Pipeline runners are ephemeral (no persistent privileged utilities). Workstation admin access controlled per security hygiene baseline. |
| A.8.19 | Installation of software on operational systems | Yes | Required to control software installation on production systems | Implemented | Container-based deployments; no ad-hoc software installation. All software defined in Dockerfiles and Terraform. |
| A.8.20 | Networks security | Yes | Required to protect network communications | Implemented | Azure VNet isolation, NSG rules defined in Terraform (`infra/`), TLS enforced for all external communications |
| A.8.21 | Security of network services | Yes | Required to secure network services | Implemented | Azure-managed network services with TLS, OIDC federation, no public endpoints for internal services |
| A.8.22 | Segregation of networks | Yes | Required to separate network segments by trust level | Implemented | Azure VNet subnet segregation defined in Terraform (`infra/`), container isolation |
| A.8.23 | Web filtering | Yes | Applicable to pipeline runner egress | Partially Implemented | GitHub-hosted runners have unrestricted egress. Network egress restrictions for production workloads planned. |
| A.8.24 | Use of cryptography | Yes | Required to protect information confidentiality and integrity | Implemented | Cosign signing (`.github/workflows/sign-and-attest.yml`), SHA256 checksums, Azure Key Vault for key management, TLS everywhere |
| A.8.25 | Secure development life cycle | Yes | Core service offering -- secure SDLC enablement | Implemented | Full 6-phase pipeline: `.github/workflows/security-gate.yml`, `.github/workflows/build-and-scan.yml`, `.github/workflows/sign-and-attest.yml`, `.github/workflows/deploy.yml`, `.github/workflows/dast.yml`, `.github/workflows/evidence-pack.yml` |
| A.8.26 | Application security requirements | Yes | Required to define and implement security requirements | Implemented | Security gates enforce requirements per pipeline phase; OPA policies (`policies/`) enforce deployment criteria |
| A.8.27 | Secure system architecture and engineering principles | Yes | Required to design secure systems | Implemented | Zero-trust pipeline architecture, OIDC federation, immutable infrastructure, signed artifacts |
| A.8.28 | Secure coding | Yes | Required to prevent vulnerabilities in developed code | Implemented | CodeQL SAST scanning (`.github/workflows/build-and-scan.yml`), MegaLinter code quality checks, 2-reviewer PR requirement, `docs/governance/security-training-program.md` |
| A.8.29 | Security testing in development and acceptance | Yes | Required to verify security before deployment | Implemented | Multi-phase testing: SAST (CodeQL), SCA (Trivy), DAST (ZAP), IaC scanning (Checkov), secret scanning (TruffleHog) |
| A.8.30 | Outsourced development | Yes | Applicable when contractors contribute to pipeline development | Partially Implemented | CODEOWNERS, PR review requirements, signed commits enforced for all contributors. Formal outsourced development policy planned. |
| A.8.31 | Separation of development, test and production environments | Yes | Required to prevent unintended changes to production | Implemented | Separate pipeline stages; OPA deployment gate (`policies/deployment-gate.rego`); Cosign signature verification before production deploy |
| A.8.32 | Change management | Yes | Required to control changes to information processing facilities | Implemented | Git-based change management (PR workflow), branch protection (2 reviewers, signed commits), `.github/workflows/pipeline.yml` orchestration, `policies/deployment-gate.rego` |
| A.8.33 | Test information | Yes | Required to protect test data | Implemented | Demo application uses synthetic data only (`app/`). No production data in test environments. |
| A.8.34 | Protection of information systems during audit testing | Yes | Required to protect production during audits | Planned | Audit procedures to include safeguards. Defined in `docs/governance/internal-audit-program.md`. |

---

## 5. Summary Statistics

| Theme | Total Controls | Applicable | Not Applicable | Implemented | Partially Implemented | Planned |
|---|---|---|---|---|---|---|
| A.5 Organizational | 37 | 37 | 0 | 27 | 8 | 2 |
| A.6 People | 8 | 8 | 0 | 6 | 2 | 0 |
| A.7 Physical | 14 | 4 | 10 | 2 | 2 | 0 |
| A.8 Technological | 34 | 34 | 0 | 25 | 7 | 2 |
| **Total** | **93** | **83** | **10** | **60** | **19** | **4** |

---

## 6. Exclusion Justification Summary

All 10 excluded controls are physical controls (A.7.1 through A.7.6, A.7.8, A.7.11, A.7.12, A.7.13). The justification for all exclusions is identical:

> CyberForge operates as a remote-first company with no dedicated office or data center premises. All infrastructure is cloud-hosted on Microsoft Azure. Physical security of data center facilities is the responsibility of Microsoft under their ISO 27001 certification, SOC 2 Type II report, and the Azure Data Processing Agreement. CyberForge reviews Microsoft's SOC 2 report annually as part of the vendor risk management process documented in the [Vendor Risk Register](vendor-risk-register.md).

This exclusion is consistent with the ISMS scope statement (Section 4: Exclusions) in [isms-scope.md](isms-scope.md).

---

## 7. Compliance Mapping

| Requirement | Framework Reference |
|---|---|
| Statement of Applicability | ISO 27001 Clause 6.1.3 d) |
| Annex A control selection and justification | ISO 27001 Annex A |
| Risk treatment options | ISO 27001 Clause 6.1.3 |
| Security measures | NIS2 Art.21 |
| ICT security requirements | DORA Art.9 |

---

## 8. Related Documents

- [ISMS Scope](isms-scope.md)
- [Risk Register](risk-register.md)
- [Risk Treatment Plan](risk-treatment-plan.md)
- [Risk Assessment Methodology](risk-assessment-methodology.md)
- [IAM Governance Policy](iam-governance.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [Crisis Management Plan](crisis-management-plan.md)
- [Security Training Program](security-training-program.md)
- [Internal Audit Program](internal-audit-program.md)

---

## 9. Revision History

| Date | Change | Author |
|---|---|---|
| 2026-03-15 | Initial version -- all 93 Annex A controls assessed | CyberForge Security Lead |
