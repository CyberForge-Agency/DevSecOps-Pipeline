# Risk Assessment Methodology

**Document Owner:** Security Lead
**Last Reviewed:** 2026-03-15
**Review Cadence:** Annually, or after a major incident or significant change to the ISMS scope
**Version:** 1.0
**ISO 27001 Reference:** Clauses 6.1.1, 6.1.2, 8.2

---

## 1. Purpose

This document defines the risk assessment methodology used within the CyberForge ISMS. It establishes a consistent, repeatable process for identifying, analyzing, evaluating, and treating information security risks to the DevSecOps Pipeline platform and associated services.

---

## 2. Scope

This methodology applies to all information assets within the ISMS scope as defined in [isms-scope.md](isms-scope.md). It covers risks to the confidentiality, integrity, and availability of information processed, stored, or transmitted by the CyberForge DevSecOps Pipeline.

---

## 3. Approach

CyberForge uses a **qualitative, asset-based risk assessment** approach. The process follows this sequence:

1. **Identify assets** within the ISMS scope.
2. **Identify threats** to each asset.
3. **Identify vulnerabilities** that threats could exploit.
4. **Assess likelihood** of threat materialization.
5. **Assess impact** if the threat materializes.
6. **Calculate risk level** as Likelihood x Impact.
7. **Evaluate risk** against the risk appetite to determine treatment.
8. **Select treatment** and document in the risk register and treatment plan.

---

## 4. Asset Identification

### 4.1 Asset Categories

Assets are classified into four categories:

| Category | Description | Examples |
|---|---|---|
| **Information Assets** | Data and information created, processed, stored, or transmitted by the pipeline | Source code, secrets and credentials, evidence packs, client data (in transit through pipeline), SBOM artifacts, configuration files, governance documentation |
| **Technology Assets** | Hardware, software, cloud services, and tools used to deliver pipeline services | GitHub (Actions, repositories, Advanced Security), Azure (ACR, Container Apps, Key Vault, Blob Storage), Terraform, open-source scanning tools (Trivy, Checkov, TruffleHog, Syft, CodeQL, ZAP, Cosign, MegaLinter) |
| **People** | Individuals who interact with or are responsible for pipeline operations | CyberForge founders, engineers, contractors, external auditors |
| **Processes** | Operational and governance procedures that support pipeline delivery | Pipeline operations (CI/CD execution), evidence generation and archival, vulnerability management, access review, incident response, change management |

### 4.2 Asset Register

Each identified asset is recorded with:

- Asset name and description
- Asset owner (person accountable for the asset's security)
- Asset category (Information, Technology, People, Process)
- Classification (Confidential, Internal, Public)
- Criticality (Critical, High, Medium, Low)

The asset register is maintained as part of the risk assessment process and reviewed at each risk assessment cycle.

---

## 5. Threat Taxonomy

The following threat taxonomy is used to ensure consistent threat identification across risk assessments. Threats are specific to the CI/CD pipeline context:

| Threat ID | Threat | Description | Typical Target Assets |
|---|---|---|---|
| T-01 | Supply chain compromise | A dependency, GitHub Action, or container base image is compromised by an attacker, introducing malicious code into the pipeline | Technology assets, information assets |
| T-02 | Secret exposure | API keys, tokens, credentials, or other secrets are inadvertently committed to source code or exposed in logs | Information assets |
| T-03 | Unauthorized deployment | An actor bypasses pipeline gates and deploys unverified or malicious code to production | Technology assets, processes |
| T-04 | Evidence tampering | Evidence pack artifacts are modified, deleted, or fabricated to misrepresent compliance status | Information assets |
| T-05 | Insider threat | A trusted insider (employee, contractor) abuses their access to deploy malicious code, exfiltrate data, or sabotage operations | People, information assets, processes |
| T-06 | Dependency vulnerability | A known CVE in a direct or transitive dependency is exploited before it is detected and remediated | Technology assets |
| T-07 | Cloud misconfiguration | Azure resources are misconfigured (overly permissive RBAC, public storage, missing encryption) creating security exposure | Technology assets |
| T-08 | Identity compromise | An attacker gains access to a legitimate user or service account through credential theft, session hijacking, or OIDC federation abuse | People, technology assets |
| T-09 | Key person loss | A critical team member with concentrated knowledge departs, creating operational gaps | People, processes |
| T-10 | Third-party discontinuation | A key open-source tool or cloud service is discontinued, abandoned, or materially changed, disrupting pipeline operations | Technology assets |
| T-11 | Data exfiltration | Sensitive information (source code, client data, secrets) is extracted from pipeline systems by an external or internal actor | Information assets |
| T-12 | Denial of service | Pipeline infrastructure or dependencies are rendered unavailable through targeted attack or resource exhaustion | Technology assets, processes |

This taxonomy is not exhaustive. Additional threats may be identified during each risk assessment cycle and added to the taxonomy.

---

## 6. Likelihood Scale

| Score | Level | Definition | Indicative Frequency |
|---|---|---|---|
| 1 | Rare | The threat is unlikely to occur under normal circumstances. No known incidents in the industry for comparable organizations. | Less than once per 5 years |
| 2 | Unlikely | The threat could occur but is not expected. Isolated incidents known in the industry. | Once per 2-5 years |
| 3 | Possible | The threat has a reasonable chance of occurring. Regular incidents reported in the industry for comparable organizations. | Once per 1-2 years |
| 4 | Likely | The threat is expected to occur. Frequent incidents in the industry, or conditions that make occurrence probable. | Multiple times per year |
| 5 | Almost Certain | The threat is expected to occur frequently or is already occurring. Active exploitation observed or conditions make occurrence near-inevitable. | Monthly or more frequently |

When assessing likelihood, consider:

- Historical data (has this occurred before, internally or in comparable organizations?)
- Current threat intelligence (is this threat actively being exploited?)
- Effectiveness of existing controls (do current controls reduce likelihood?)
- Environmental factors (does the operating context increase or decrease likelihood?)

---

## 7. Impact Scale

| Score | Level | Definition | Business Impact Description |
|---|---|---|---|
| 1 | Negligible | Minimal impact on operations, no data loss, no regulatory consequence, no client impact | Minor inconvenience; resolved within normal operations |
| 2 | Minor | Limited operational disruption, potential minor data exposure, no regulatory reporting required, minimal client impact | Short-term workaround available; resolved within days |
| 3 | Moderate | Significant operational disruption, potential data breach affecting limited records, potential regulatory inquiry, some client impact | Requires dedicated response effort; resolved within weeks; potential reputational damage |
| 4 | Major | Severe operational disruption, confirmed data breach, regulatory notification required, significant client impact, financial loss | Extended recovery; regulatory investigation possible; material reputational damage; loss of client confidence |
| 5 | Catastrophic | Complete loss of service, large-scale data breach, mandatory regulatory penalties, loss of key clients, existential threat to the organization | Threatens business continuity; regulatory enforcement actions; potential litigation; severe financial loss |

When assessing impact, consider effects across all three dimensions:

- **Confidentiality impact:** Unauthorized disclosure of information
- **Integrity impact:** Unauthorized modification or destruction of information
- **Availability impact:** Disruption to access or use of information and services

The highest impact across the three dimensions is used as the overall impact score.

---

## 8. Risk Matrix

The risk score is calculated as **Likelihood x Impact**. The resulting score maps to a risk level:

```
                    IMPACT
                 1    2    3    4    5
              +----+----+----+----+----+
          5   |  5 | 10 | 15 | 20 | 25 |
              +----+----+----+----+----+
          4   |  4 |  8 | 12 | 16 | 20 |
L             +----+----+----+----+----+
I         3   |  3 |  6 |  9 | 12 | 15 |
K             +----+----+----+----+----+
E         2   |  2 |  4 |  6 |  8 | 10 |
L             +----+----+----+----+----+
I         1   |  1 |  2 |  3 |  4 |  5 |
H             +----+----+----+----+----+
O
O
D
```

### Risk Level Classification

| Risk Score | Risk Level | Color Code |
|---|---|---|
| 1 - 4 | **Low** | Green |
| 5 - 9 | **Medium** | Yellow |
| 10 - 15 | **High** | Orange |
| 16 - 25 | **Critical** | Red |

---

## 9. Risk Appetite Statement

CyberForge Management establishes the following risk appetite:

| Risk Level | Treatment Requirement |
|---|---|
| **Low** (1-4) | Accepted. Monitored during regular risk reviews. No mandatory treatment required, but opportunities for improvement should be considered. |
| **Medium** (5-9) | Treatment required. Risk must be reduced to Low through controls, or formally accepted with documented justification per [risk-acceptance-process.md](risk-acceptance-process.md). Review at least annually. |
| **High** (10-15) | Treatment mandatory. Risk must be actively mitigated, transferred, or avoided. A risk treatment plan with specific controls, timelines, and owners is required. Review at least semi-annually. |
| **Critical** (16-25) | Immediate action required. Risk must be treated as a priority. Escalation to CyberForge Management within 24 hours of identification. Treatment plan implementation must begin immediately. |

CyberForge does not accept High or Critical residual risks without exceptional, documented justification approved by CyberForge Management.

---

## 10. Risk Treatment Options

For risks that exceed the risk appetite, one or more of the following treatment options must be selected:

| Treatment | Description | When to Use |
|---|---|---|
| **Avoid** | Eliminate the risk by removing the threat source or discontinuing the activity that creates the risk | When the risk-generating activity is not essential or an alternative approach exists |
| **Mitigate** | Reduce the likelihood or impact through implementing controls | When the activity is necessary and controls can bring the risk within appetite |
| **Transfer** | Shift the risk to a third party through insurance, contractual terms, or outsourcing | When the risk cannot be fully mitigated internally and a third party can absorb it |
| **Accept** | Formally acknowledge and accept the residual risk | Only when the risk is within appetite (Low) or when a documented exception is approved per [risk-acceptance-process.md](risk-acceptance-process.md) |

Each treatment decision must be documented in the [Risk Register](risk-register.md) and, for High/Critical risks, in the [Risk Treatment Plan](risk-treatment-plan.md).

---

## 11. Risk Assessment Process

### 11.1 Full Risk Assessment

A full risk assessment is performed:

- **Annually** as part of the ISMS review cycle.
- **After major incidents** that reveal previously unidentified risks or indicate that existing controls are insufficient.
- **After significant changes** to the ISMS scope, technology stack, organizational structure, or regulatory environment.

### 11.2 Process Steps

| Step | Activity | Responsible | Output |
|---|---|---|---|
| 1 | Review and update the asset register | Asset owners | Updated asset inventory |
| 2 | Identify threats to each asset using the threat taxonomy | Security Lead with asset owners | Threat-asset mapping |
| 3 | Identify existing controls for each threat-asset pair | Security Lead | Current control inventory |
| 4 | Assess likelihood considering existing controls | Risk assessment participants | Likelihood scores |
| 5 | Assess impact considering worst-case scenario | Risk assessment participants | Impact scores |
| 6 | Calculate risk scores and assign risk levels | Security Lead | Risk scores and levels |
| 7 | Compare risk levels against risk appetite | Security Lead | Treatment decisions |
| 8 | Select treatment options for risks above appetite | Risk owners with Security Lead | Treatment selections |
| 9 | Document results in the Risk Register | Security Lead | Updated [Risk Register](risk-register.md) |
| 10 | Develop/update treatment plans for High/Critical risks | Risk owners | Updated [Risk Treatment Plan](risk-treatment-plan.md) |
| 11 | Present results to management for review and approval | Security Lead | Management sign-off |

### 11.3 Participants

Risk assessments are conducted collaboratively by:

- **Security Lead** (facilitator and coordinator)
- **CyberForge Management** (risk appetite authority and final approver)
- **Asset owners** (subject matter experts for their respective assets)

For a startup of CyberForge's size, the founders typically fulfill all three roles. Separation is maintained by ensuring the person approving risk treatment decisions is not the same person who assessed the risk where practical.

### 11.4 Incremental Risk Assessment

Between full assessment cycles, incremental risk assessments are triggered by:

- New vulnerability findings that fall outside existing risk register entries.
- Changes to the threat landscape (e.g., new supply chain attack vector).
- Introduction of new technology, tools, or cloud services.
- Significant changes to organizational structure or personnel.

Incremental assessments follow the same methodology but are scoped to the specific change or trigger.

---

## 12. Residual Risk

After treatment controls are implemented, the risk is re-assessed to determine the **residual risk level**:

- If the residual risk is within appetite (Low), the treatment is considered effective.
- If the residual risk remains above appetite, additional controls must be considered, or a formal risk acceptance must be processed per [risk-acceptance-process.md](risk-acceptance-process.md).

Residual risk scores are recorded in the Risk Register alongside the inherent (pre-treatment) scores.

---

## 13. Risk Assessment Records

Each risk assessment cycle produces the following records:

| Record | Description | Retention |
|---|---|---|
| Risk Register (updated) | All identified risks with scores, levels, and treatment decisions | Maintained continuously; historical versions retained for 5 years |
| Risk Treatment Plan (updated) | Detailed treatment plans for High/Critical risks | Maintained continuously; historical versions retained for 5 years |
| Risk Assessment Report | Summary of assessment scope, participants, key findings, and changes from previous assessment | Retained for 5 years |
| Management approval record | Evidence that management reviewed and approved the risk assessment results | Retained for 5 years |

---

## 14. Compliance Mapping

| Requirement | Framework Reference |
|---|---|
| Information security risk assessment | ISO 27001 Clause 6.1.2 |
| Information security risk treatment | ISO 27001 Clause 6.1.3 |
| Operational planning and control (risk) | ISO 27001 Clause 8.2 |
| Risk analysis and information system security policies | NIS2 Art.21.2.a |
| ICT risk management framework | DORA Art.5, Art.16 |
| Risk assessment | SOC 2 CC3.1, CC3.2 |

---

## 15. Related Documents

- [ISMS Scope](isms-scope.md)
- [Risk Register](risk-register.md)
- [Risk Treatment Plan](risk-treatment-plan.md)
- [Risk Acceptance Process](risk-acceptance-process.md)
- [Statement of Applicability](statement-of-applicability.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Vendor Risk Register](vendor-risk-register.md)

---

## 16. Revision History

| Date | Change | Author |
|---|---|---|
| 2026-03-15 | Initial version | CyberForge Security Lead |
