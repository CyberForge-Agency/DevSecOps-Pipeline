# ISMS Scope Statement

**Document Owner:** CyberForge Management
**Last Reviewed:** 2026-03-15
**Review Cadence:** Annually, or after significant changes to organizational context, services, or regulatory obligations
**Version:** 1.0
**ISO 27001 Reference:** Clauses 4.1, 4.2, 4.3

---

## 1. Purpose

This document defines the scope of the CyberForge Information Security Management System (ISMS) as required by ISO/IEC 27001:2022 Clause 4.3. It establishes the boundaries, context, interested parties, and applicability of the ISMS to the CyberForge DevSecOps Pipeline platform and associated services.

---

## 2. Organization

| Field | Value |
|---|---|
| Legal Entity | CyberForge Sp. z o.o. |
| Registered Office | Poland |
| Industry | Information Technology -- DevSecOps Services and CI/CD Hardening |
| Company Size | Startup (micro-enterprise, fewer than 10 employees) |
| Operating Model | Remote-first, cloud-native |
| Primary Markets | Polish financial, critical infrastructure, and technology sectors |

CyberForge is a technical boutique specializing in CI/CD pipeline hardening, DevSecOps consulting, and compliance-enabling software delivery automation. The company provides its DevSecOps Pipeline platform to clients subject to DORA, NIS2, ISO 27001, SOC 2, and RODO/GDPR requirements.

---

## 3. ISMS Scope

### 3.1 Scope Statement

The ISMS scope covers the design, development, operation, and maintenance of the **CyberForge DevSecOps Pipeline platform**, including:

- The CI/CD workflows and security gates that constitute the pipeline
- The cloud infrastructure supporting pipeline operations
- The evidence generation and archival subsystem
- The governance processes that support pipeline integrity and compliance
- The personnel involved in pipeline development and operations

### 3.2 In-Scope Assets and Services

| Category | In-Scope Components |
|---|---|
| **CI/CD Platform** | GitHub Actions reusable workflows (6 phases: Security Gate, Build and Scan, Sign and Attest, Deploy, DAST, Evidence Pack) |
| **Infrastructure as Code** | Terraform configurations for Azure resource provisioning (`infra/`) |
| **Policy Engine** | OPA/Rego compliance policies (`policies/`) |
| **Evidence Generation** | Evidence Pack scripts, SHA256 manifest generation, compliance matrix generation (`scripts/`) |
| **Cloud Infrastructure** | Azure Container Registry (ACR), Azure Container Apps, Azure Key Vault, Azure Blob Storage (evidence archival with WORM policy) |
| **Identity and Access** | Azure AD/Entra ID (for OIDC federation), GitHub organization and repository access controls |
| **Source Code Repositories** | CyberForge Pipeline repository and associated configuration repositories |
| **Developer Workstations** | Workstations used for pipeline development (remote-first, personally managed devices) |
| **Governance Documentation** | Policies, procedures, risk registers, and compliance documentation maintained in `docs/governance/` |

### 3.3 Interfaces

The ISMS scope includes the following interfaces with external systems and parties:

| Interface | Description | Direction |
|---|---|---|
| Client Repositories | When the pipeline is deployed for client engagements, client source code repositories interface with the pipeline workflows | Inbound |
| Azure AD/Entra ID | Identity federation for OIDC authentication between GitHub Actions and Azure services | Bidirectional |
| Third-Party Tools | Open-source tools (Trivy, Checkov, Syft, TruffleHog, MegaLinter, CodeQL, OWASP ZAP, Cosign) running within pipeline runners | Inbound (vulnerability databases, signatures) |
| Sigstore/Rekor | Public transparency log for keyless signing operations | Outbound (signatures and identity tokens) |
| Renovate (GitHub App) | Automated dependency update management | Bidirectional (within GitHub) |

For the complete third-party inventory, see [Vendor Risk Register](vendor-risk-register.md).

---

## 4. Exclusions

The following are explicitly excluded from the ISMS scope. Each exclusion is justified below:

| Exclusion | Justification |
|---|---|
| Client application source code | CyberForge provides the pipeline platform; client code transits through the pipeline but is not owned, managed, or governed by CyberForge (beyond the demo application in `app/`). Client code security is the client's responsibility. |
| Client infrastructure | Client Azure subscriptions, on-premises infrastructure, and non-pipeline systems are outside CyberForge's operational control. |
| Physical premises | CyberForge operates as a remote-first company with no dedicated office space. Cloud infrastructure is hosted in Azure data centers (Poland Central region). Physical security of Azure data centers is managed by Microsoft under their own ISO 27001 certification and DPA. |
| Non-pipeline business systems | General business operations (accounting, CRM, marketing) not directly related to pipeline development and operation are excluded from this initial ISMS scope. |

These exclusions do not diminish CyberForge's obligation to protect information assets. Excluded areas may be brought into scope as the organization grows or as regulatory requirements demand.

---

## 5. Context of the Organization (Clause 4.1)

### 5.1 External Issues

| Issue | Relevance |
|---|---|
| EU regulatory pressure (DORA, NIS2) | CyberForge's clients in financial and critical infrastructure sectors face mandatory compliance deadlines. The pipeline must demonstrably support these requirements. |
| Supply chain threat landscape | Increasing sophistication of software supply chain attacks (dependency confusion, compromised Actions, malicious packages) directly threatens the pipeline's integrity. |
| Market competition | Other DevSecOps consultancies and platform vendors compete in the Polish and EU markets. Demonstrable ISO 27001 certification and compliance tooling provide competitive differentiation. |
| Cloud provider dependency | Concentration risk on Microsoft (Azure and GitHub). Service disruptions, pricing changes, or policy changes by Microsoft could impact pipeline operations. |
| Open-source ecosystem stability | The pipeline relies on open-source tools maintained by third parties. Project abandonment, license changes, or security vulnerabilities in these tools represent ongoing risk. |

### 5.2 Internal Issues

| Issue | Relevance |
|---|---|
| Small team size | As a micro-enterprise, CyberForge has limited personnel for separation of duties, on-call coverage, and knowledge redundancy. Key-person risk is elevated. |
| Skill availability | Specialized DevSecOps, compliance, and cloud security skills are in high demand and limited supply in the Polish market. |
| Rapid growth trajectory | Scaling from a startup to a mature service provider requires governance processes that can grow with the organization without creating excessive overhead. |
| Resource constraints | Limited budget and headcount for dedicated GRC, internal audit, and compliance staffing. Processes must be efficient and proportionate. |
| Technical debt | As the pipeline evolves, accumulated technical debt and configuration drift could introduce security gaps if not managed. |

---

## 6. Interested Parties (Clause 4.2)

| Interested Party | Needs and Expectations | Relevance to ISMS |
|---|---|---|
| CyberForge founders and engineers | Secure, reliable pipeline operations; clear governance processes; manageable compliance overhead | Primary operators and risk owners |
| Clients | Demonstrable security and compliance controls; trustworthy evidence generation; contractual security assurances | Rely on pipeline for their own compliance obligations |
| Auditors (internal and external) | Clear scope documentation; traceable controls; complete evidence packs; access to governance records | Evaluate ISMS effectiveness and Annex A control implementation |
| KNF (Komisja Nadzoru Finansowego) | DORA compliance evidence from CyberForge's financial sector clients | Supervisory authority for DORA-regulated clients |
| CSIRT (national CSIRT for NIS2) | NIS2 incident reporting and security measure evidence | National authority for NIS2 obligations |
| UODO (Urzad Ochrony Danych Osobowych) | RODO/GDPR compliance for personal data processed by the pipeline | Data protection supervisory authority |
| Investors (current and potential) | Sound governance, risk management, and compliance posture; protection of intellectual property | Due diligence and ongoing governance oversight |
| Cloud service providers (Microsoft) | Adherence to terms of service, acceptable use policies, and shared responsibility model | Infrastructure and platform dependency |
| Open-source communities | Responsible use of open-source software; vulnerability disclosure and contribution | Tool dependency and reputation |

---

## 7. ISMS Objectives

The CyberForge ISMS pursues the following information security objectives:

| Objective | Measurable Target | Review Frequency |
|---|---|---|
| Protect pipeline integrity | Zero unauthorized deployments to production per quarter | Quarterly |
| Maintain secret hygiene | Zero secrets committed to source code (TruffleHog pass rate: 100%) | Per pipeline run |
| Ensure evidence trustworthiness | 100% of evidence packs include valid SHA256 manifest and WORM archival confirmation | Per release |
| Manage vulnerabilities within SLA | 95% or higher SLA compliance rate for vulnerability remediation | Monthly |
| Maintain access control discipline | 100% of access reviews completed on schedule | Quarterly (privileged) / Semi-annually (standard) |
| Ensure supply chain transparency | SBOM generated for every container image build | Per pipeline run |
| Achieve and maintain ISO 27001 certification | Successful certification audit | Annual surveillance audit |

---

## 8. ISMS Documentation Structure

The ISMS is documented through the following interconnected records:

| Document | Purpose | Location |
|---|---|---|
| ISMS Scope (this document) | Define ISMS boundaries and context | `docs/governance/isms-scope.md` |
| Risk Assessment Methodology | Define how risks are identified, assessed, and treated | `docs/governance/risk-assessment-methodology.md` |
| Risk Register | Inventory of identified risks with scores and treatment | `docs/governance/risk-register.md` |
| Risk Treatment Plan | Detailed treatment for High/Critical risks | `docs/governance/risk-treatment-plan.md` |
| Statement of Applicability | All 93 Annex A controls with applicability decisions | `docs/governance/statement-of-applicability.md` |
| Internal Audit Program | Audit planning, execution, and findings tracking | `docs/governance/internal-audit-program.md` |
| Management Review Template | Structured template for ISO 27001 management reviews | `docs/governance/management-review-template.md` |
| Corrective Actions Log | Nonconformity and CAPA tracking | `docs/governance/corrective-actions-log.md` |
| Security Training Program | Personnel competence and awareness | `docs/governance/security-training-program.md` |

Supporting governance documents:

| Document | Location |
|---|---|
| IAM Governance Policy | `docs/governance/iam-governance.md` |
| Access Review Procedure | `docs/governance/access-review-procedure.md` |
| JML Process | `docs/governance/jml-process.md` |
| Vulnerability Management Policy | `docs/governance/vulnerability-management-policy.md` |
| Risk Acceptance Process | `docs/governance/risk-acceptance-process.md` |
| Vendor Risk Register | `docs/governance/vendor-risk-register.md` |
| Compliance Scope and Limitations | `docs/compliance/scope-and-limitations.md` |
| Framework Boundaries | `docs/compliance/framework-boundaries.md` |

---

## 9. Applicability of This Scope to Client Engagements

This ISMS scope document serves a dual purpose:

1. **Internal governance:** Defines the ISMS for CyberForge's own pipeline operations.
2. **Client template:** Provides a starting point that CyberForge adapts for client engagements, adjusting scope boundaries, interested parties, and context to reflect the client's organizational environment.

When adapting for client use, the following sections require client-specific customization:

- Section 2 (Organization): Client legal entity, industry, size, and market
- Section 3.2 (In-Scope Assets): Client-specific infrastructure and repositories
- Section 4 (Exclusions): Adjusted based on client scope decisions
- Section 5 (Context): Client-specific internal and external issues
- Section 6 (Interested Parties): Client's regulators, customers, and stakeholders

---

## 10. Scope Review and Maintenance

This scope statement is reviewed:

- **Annually** as part of the management review cycle.
- **After significant changes** to organizational structure, services offered, regulatory landscape, or technology stack.
- **After major incidents** that reveal scope gaps or boundary issues.

Changes to the ISMS scope require approval from CyberForge Management and must be communicated to all interested parties.

---

## 11. Compliance Mapping

| Requirement | Framework Reference |
|---|---|
| Understanding the organization and its context | ISO 27001 Clause 4.1 |
| Understanding the needs and expectations of interested parties | ISO 27001 Clause 4.2 |
| Determining the scope of the ISMS | ISO 27001 Clause 4.3 |
| Information security management system | ISO 27001 Clause 4.4 |
| Risk analysis and information system security policies | NIS2 Art.21.2.a |
| Management body oversight and training | NIS2 Art.20 |
| ICT risk management framework | DORA Art.5, Art.16 |

---

## 12. Related Documents

- [Risk Assessment Methodology](risk-assessment-methodology.md)
- [Statement of Applicability](statement-of-applicability.md)
- [Compliance Scope and Limitations](../compliance/scope-and-limitations.md)
- [Framework Boundaries](../compliance/framework-boundaries.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [IAM Governance Policy](iam-governance.md)

---

## 13. Revision History

| Date | Change | Author |
|---|---|---|
| 2026-03-15 | Initial version | CyberForge Management |
