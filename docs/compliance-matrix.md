# Compliance Matrix (Design Intent) - CyberForge DevSecOps Pipeline

This document is the human-readable, detailed compliance mapping for the CyberForge DevSecOps Pipeline design.

It explains:

- what requirement areas each framework expects
- how the pipeline design intends to address them
- what evidence the pipeline is designed to generate
- what still requires non-pipeline controls (Phase F / organizational controls)

This document is intentionally more detailed than the generated `evidence/compliance-matrix.json` artifact produced by the Phase 6 workflow.

## 1. Scope and Interpretation

### 1.1 What this document is

- A design-intent mapping for the CyberForge DevSecOps pipeline (see `../README.md`)
- A control/evidence crosswalk for a compliance-enabling CI/CD subsystem
- A requirements explanation for engineers, founders, and compliance stakeholders

### 1.2 What this document is not

- Not legal advice
- Not an auditor opinion
- Not a claim of full DORA, NIS2, ISO 27001, SOC 2, or GDPR compliance by itself
- Not a substitute for framework-specific policies, governance, incident response, BC/DR, IAM governance, or audit programs

### 1.3 Coverage model used in this matrix

This matrix uses requirement areas relevant to the repository design. For legal and audit frameworks, not every article/control is directly implementable inside a CI/CD pipeline. To avoid overclaiming, each row explicitly states whether coverage is:

- `Direct (Pipeline)` - The pipeline design directly implements a technical control
- `Partial (Pipeline + Org)` - The pipeline contributes technical controls/evidence, but organizational controls are also required
- `Phase F / Org Required` - The requirement is primarily outside the pipeline and must be addressed in governance/runbooks/processes
- `Out of Scope (for this subsystem)` - Important requirement, but not a CI/CD pipeline responsibility

### 1.4 Design basis (target-state intent)

The mapping below reflects the target design intent of the CyberForge pipeline architecture:

- Phase 1: Security Gate (`security-gate.yml`)
- Phase 2: Build & Scan (`build-and-scan.yml`)
- Phase 3: Sign & Attest (`sign-and-attest.yml`)
- Phase 4: Deploy (`deploy.yml`)
- Phase 5: DAST (`dast.yml`)
- Phase 6: Evidence Pack (`evidence-pack.yml`)
- Supporting controls:
  - Terraform (`infra/`)
  - OPA policies (`policies/`)
  - Governance config (`.github/CODEOWNERS`, `.github/branch-protection.json`, `renovate.json`)
  - Evidence scripts (`scripts/*.sh`)
- Missing broader compliance areas tracked as Phase F workstreams in the implementation plan

## 2. Control and Evidence Building Blocks (Design Intent)

Before framework-by-framework mapping, this section defines the design building blocks referenced throughout the matrix.

### 2.1 Core pipeline controls (technical)

- Secret scanning (TruffleHog)
- IaC scanning (Checkov)
- Code linting (MegaLinter / ESLint and related linters)
- Commit signature / authorship verification (design intent: signed commit enforcement and verification)
- PII scanning (design intent includes regex + Presidio; implementation may vary)
- SCA / dependency vulnerability scanning (Trivy)
- SAST (CodeQL)
- Unit tests + coverage gate (Jest)
- Docker image build and image scanning (Trivy image mode)
- SBOM generation (Syft, CycloneDX)
- Image signing and attestations (Cosign)
- Build provenance attestation (SLSA provenance)
- Pre-deploy signature verification
- Terraform-based infrastructure change control
- DAST (OWASP ZAP)
- Evidence packaging, checksum manifest, and archive workflow

### 2.2 Core evidence artifacts (planned/generated)

The design expects the Evidence Pack to contain (at minimum):

- `security-report.json`
- `sbom.cyclonedx.json`
- `provenance.intoto.jsonl`
- `cosign-verification.log`
- `pipeline-run.json`
- `dependency-review.json`
- `zap-report.json`
- `dpa-compliance-check.json`
- `data-flow-diagram.json`
- `compliance-matrix.json`
- `manifest.sha256`
- Evidence Pack `README.md`

### 2.3 Non-pipeline controls explicitly required (Phase F)

The design and patched implementation plan already acknowledge these as necessary additions:

- True Azure Blob immutability/WORM operationalization and lock procedures
- SIEM integration and alerting
- DORA/NIS2 incident handling and reporting runbooks
- Backup/restore evidence and BC/DR drills
- IAM governance, access reviews, MFA/SSO enforcement evidence
- Supplier / ICT third-party risk process and contract controls
- ISO 27001 ISMS documentation (Clauses 4-10, SoA, audits, management review)
- SOC 2 system description, control ownership, evidence calendar
- NIS2 operational readiness (assets, training, crisis management)
- Extended audit dry run

## 3. DORA (EU 2022/2554) - Design Intent Mapping

### 3.1 DORA scope note

DORA is an operational resilience framework for financial entities and critical ICT third-party providers. A CI/CD pipeline can support DORA, but it cannot by itself satisfy governance, incident reporting, resilience testing program, or third-party risk lifecycle obligations.

### 3.2 DORA matrix (design intent)

| DORA Area / Article | Plain-language requirement (summary) | Design intent (how this project addresses it) | Planned controls / files | Planned evidence | Coverage type | What else must be added |
|---|---|---|---|---|---|---|
| Art. 5 (management body) | Leadership accountability and oversight for ICT risk | Pipeline provides technical evidence that management can review, but does not create governance itself | `pipeline-run.json`, governance docs | Evidence Pack metadata, governance records (outside pipeline) | Phase F / Org Required | Management oversight procedures, approval records, training, board reporting cadence |
| ICT risk mgmt framework (DORA ICT risk chapters incl. Art.16 intent) | Identify, protect, detect, respond, recover for ICT risk | Pipeline acts as a preventive and detective control layer in software delivery | Phases 1-6 workflows, OPA policies, Terraform IaC | `security-report.json`, `pipeline-run.json`, `compliance-matrix.json` | Partial (Pipeline + Org) | Enterprise risk register, treatment plans, asset inventory, recovery procedures |
| Art.16.1.a (risk mgmt support) | ICT risk controls should be implemented and evidenced | Enforce pre-merge and pre-deploy gates to reduce risky changes entering production | Phase 1 (TruffleHog, Checkov, lint), Phase 2 (SCA/SAST/tests), Phase 4 verify-before-deploy | `security-report.json`, `dependency-review.json`, `pipeline-run.json` | Direct (Pipeline) | Formal risk methodology and ownership outside CI/CD |
| Art.16.1.c (updated systems/tools) | Maintain secure and updated systems/components | Use SCA, image scanning, dependency updates, and scanning gates | `build-and-scan.yml`, `renovate.json`, `.trivyignore` with justification handling | `dependency-review.json`, image scan output, Renovate history | Partial (Pipeline + Org) | Vulnerability remediation SLA process, patch governance, exceptions process |
| Art.16.1.d (detection/monitoring support) | Detect anomalies/incidents and maintain monitoring capability | Pipeline emits run metadata and gate outcomes; Phase F adds SIEM integration | Phase 6 `pipeline-run.json`; planned SIEM workstream | `pipeline-run.json`, SIEM logs (Phase F) | Partial (Pipeline + Org) | SIEM ingestion, alert routing, on-call playbooks, thresholds |
| Protection of ICT systems/data (DORA protection measures) | Prevent tampering and insecure deployments | Sign images, verify signatures before deploy, use OIDC (no static cloud secrets) | `sign-and-attest.yml`, `deploy.yml`, Azure OIDC login | `cosign-verification.log`, provenance, `pipeline-run.json` | Direct (Pipeline) | Platform hardening outside pipeline (network, host, runtime policies) |
| Response and recovery support | Restore operations after incidents; resilience | Pipeline can produce evidence and deployment artifacts but is not a BC/DR program | Phase 6 evidence pack; Terraform for reproducible infra definitions | Evidence Pack + Terraform code | Phase F / Org Required | Backup/restore procedures, BC/DR plans, RTO/RPO, drills, recovery evidence |
| Art.17 (ICT-related incident management process) | Formal incident handling lifecycle | DAST can raise technical findings; pipeline can create incident tickets; governance runbooks must define full process | `dast.yml` issue creation, Phase F runbooks | `zap-report.json`, issue references, incident runbooks | Partial (Pipeline + Org) | Classification, escalation, roles, post-incident review process |
| Art.19 (major ICT incident reporting) | Report major incidents to regulators within required timelines | Pipeline can preserve evidence; reporting workflow itself is organizational and legal | Phase 6 evidence pack; Phase F reporting templates/runbooks | Evidence Pack + reporting records (outside pipeline) | Phase F / Org Required | Regulatory notification procedures, legal review, authority-specific templates |
| Art.24 (digital operational resilience testing) | Resilience testing program | Pipeline includes application DAST and smoke tests; broader resilience testing must be added | `dast.yml`, `deploy.yml` smoke test, Phase F testing program docs | `zap-report.json`, smoke test logs, test program docs | Partial (Pipeline + Org) | Scenario testing, recovery testing, advanced resilience testing governance |
| Arts.28-30 (ICT third-party risk + contracts) | Manage third-party ICT risk and contractual controls | Pipeline provides supply-chain evidence (SBOM, provenance, signed artifacts) and DPA checks; full supplier lifecycle/contracts are outside pipeline | `build-and-scan.yml`, `sign-and-attest.yml`, `scripts/check-dpa.sh`, Phase F supplier risk docs | `sbom.cyclonedx.json`, `provenance.intoto.jsonl`, `dpa-compliance-check.json` | Partial (Pipeline + Org) | Supplier register, due diligence, contract clauses, exit plans, periodic reviews |
| Immutable evidence retention (DORA-aligned audit defensibility) | Preserve tamper-evident evidence over long retention | Design targets Evidence Pack archive in Blob with immutability/WORM and retention checks | `evidence-pack.yml`, Terraform storage module, `policies/retention-policy.rego` | Evidence Pack ZIP, `manifest.sha256`, retention check outputs | Partial (Pipeline + Org) | Operational WORM lock procedures, legal hold governance, retention legal validation |

### 3.3 DORA design intent summary

- Strong coverage for software delivery preventive/detective controls and supply-chain integrity
- Partial coverage for detection/monitoring and incident management support
- Major DORA obligations still require governance, legal, and operational resilience processes (Phase F)

## 4. NIS2 (EU 2022/2555) - Design Intent Mapping

### 4.1 NIS2 scope note

NIS2 requires risk-management measures, management oversight, incident reporting, continuity, supply-chain controls, and cyber hygiene across the organization. The pipeline is one technical subsystem supporting selected measures.

### 4.2 NIS2 matrix (design intent)

| NIS2 Article / Area | Plain-language requirement (summary) | Design intent (how this project addresses it) | Planned controls / files | Planned evidence | Coverage type | What else must be added |
|---|---|---|---|---|---|---|
| Art.20 (management bodies) | Management approval/oversight and training accountability | Pipeline generates technical evidence but does not establish management governance | Phase 6 outputs + Phase F governance docs | `pipeline-run.json`, review records (outside pipeline) | Phase F / Org Required | Management training, oversight process, policy approvals |
| Art.21 risk management measures (overall) | Implement proportionate technical, operational, and organizational measures | Pipeline contributes technical controls for SSDLC and supply-chain integrity | Phases 1-6, Terraform, OPA policies | Evidence Pack + repo configs | Partial (Pipeline + Org) | Organization-wide policy/risk program and operational controls |
| Art.21.2(a) risk analysis and system security policies | Risk analysis and security policy basis | Design plan documents controls; pipeline enforces technical gates | governance docs, OPA policies, workflows | `pipeline-run.json`, policy outputs | Partial (Pipeline + Org) | Formal risk analysis process, approved policies, risk treatment tracking |
| Art.21.2(b) incident handling | Incident prevention/detection/response procedures | DAST produces findings and can create issues; evidence pack preserves logs | `dast.yml`, `evidence-pack.yml` | `zap-report.json`, issue references, `pipeline-run.json` | Partial (Pipeline + Org) | IR runbooks, severity model, escalation/on-call, postmortems |
| Art.21.2(c) business continuity, backup, DR, crisis management | Continuity and recovery capability | Terraform supports reproducibility; pipeline alone does not provide BC/DR | `infra/` (IaC), Phase F BC/DR docs/tasks | Terraform code, backup/restore evidence (Phase F) | Phase F / Org Required | Backups, DR architecture, recovery tests, crisis management procedures |
| Art.21.2(d) supply chain security | Manage third-party and supply-chain cyber risks | SBOM, SCA, signed attestations, provenance support software supply-chain controls | `build-and-scan.yml`, `sign-and-attest.yml`, `renovate.json` | `dependency-review.json`, `sbom.cyclonedx.json`, `provenance.intoto.jsonl` | Direct (Pipeline) for software supply chain / Partial overall | Supplier governance process, contractual controls, periodic assessments |
| Art.21.2(e) secure development and vulnerability handling/disclosure | Secure acquisition, development, maintenance, and vuln handling | CI/CD gates, tests, scans, DAST, deployment verification implement SSDLC controls | Phases 1-5, OPA deployment gate policy | `security-report.json`, coverage, `zap-report.json`, `cosign-verification.log` | Partial (Pipeline + Org) | Vulnerability disclosure policy/process, remediation SLA governance |
| Art.21.2(f) effectiveness assessment | Assess effectiveness of risk-management measures | Pipeline produces repeatable evidence and pass/fail gate outcomes | Phase 6 evidence pack, `pipeline-run.json`, `compliance-matrix.json` | Evidence Pack artifacts and trendable history | Partial (Pipeline + Org) | KPI/KRI program, management review, audit and control testing cadence |
| Art.21.2(g) basic cyber hygiene and training | Hygiene practices and training | Renovate supports patch hygiene; pipeline cannot deliver workforce training | `renovate.json`, scan workflows | Dependency scan evidence + update history | Partial (Pipeline + Org) | Security awareness program, admin hygiene standards, device/network controls |
| Art.21.2(h) cryptography and encryption | Appropriate use of cryptography | Design uses OIDC, keyless signing, signature verification, and secure artifact attestations | `sign-and-attest.yml`, `deploy.yml`, Azure OIDC login | `cosign-verification.log`, provenance, `pipeline-run.json` | Direct (Pipeline) | Organization-wide crypto/key mgmt standards outside CI/CD |
| Art.21.2(i) HR security, access control, asset management | Personnel/access/asset governance | Repo governance supports code change access control; broader HR/IAM/asset controls are outside pipeline | `.github/CODEOWNERS`, `.github/branch-protection.json`, Phase F IAM docs | Repo config exports, `pipeline-run.json` | Partial (Pipeline + Org) | Joiner/mover/leaver, access reviews, CMDB/asset inventory, HR controls |
| Art.21.2(j) MFA and secure communications (where appropriate) | MFA/secure admin and communications | OIDC reduces static credentials; GitHub/Azure MFA/SSO evidence must be operationally documented | `deploy.yml`, `SETUP.md`, Phase F IAM workstreams | OIDC logs + org settings evidence (Phase F) | Partial (Pipeline + Org) | Enforced MFA/SSO policies and periodic validation evidence |
| Art.23 incident reporting obligations | Timely notifications and final reports | Pipeline preserves technical evidence for reporting; reporting process is external to CI/CD | Phase 6 evidence pack, Phase F reporting runbooks | Evidence Pack + regulator notification records | Phase F / Org Required | Reporting playbooks, legal approvals, timeline tracking, authority-specific forms |

### 4.3 NIS2 design intent summary

- Good design support for SSDLC, software supply-chain integrity, and cryptographic integrity
- Partial support for incident handling and effectiveness assessment through evidence generation
- Major organizational duties (management oversight, BC/DR, reporting, training) remain Phase F / organizational scope

## 5. ISO/IEC 27001:2022 - Design Intent Mapping

### 5.1 ISO 27001 scope note

ISO 27001 certification is based on an ISMS (management system), not a CI/CD pipeline alone.

This matrix therefore separates:

- ISMS clauses (organizational requirements, mostly Phase F)
- Annex A technical/operational controls that the pipeline design directly supports

### 5.2 ISO 27001 Clauses 4-10 (ISMS) - design intent support

| Clause | Requirement area (summary) | Design intent support from this project | Planned evidence / artifacts | Coverage type | What else must be added |
|---|---|---|---|---|---|
| Clause 4 | Context of the organization | Design docs can help define system scope and interfaces for the CI/CD subsystem | `README.md`, design/implementation docs, architecture docs | Partial (Pipeline + Org) | Formal ISMS scope, interested parties, boundaries, issues register |
| Clause 5 | Leadership | Pipeline does not establish leadership commitment | Governance records only (outside pipeline) | Phase F / Org Required | ISMS policy approval, role assignment, leadership accountability evidence |
| Clause 6 | Planning (risk/opportunities) | OPA policies and gates support risk treatment implementation, but not risk methodology | OPA policies, evidence pack trend data | Partial (Pipeline + Org) | Risk assessment method, risk register, treatment plan, SoA linkage |
| Clause 7 | Support (resources, competence, awareness, communication, documented info) | Repository provides documented procedures and technical artifacts | `docs/*`, evidence pack, runbooks (Phase F) | Partial (Pipeline + Org) | Training records, communication processes, document control procedure |
| Clause 8 | Operation | Pipeline is a direct operational control mechanism for software delivery changes | Workflow runs, artifacts, deployment logs | Direct (Pipeline) for CI/CD operation / Partial overall | Broader operational procedures beyond CI/CD |
| Clause 9 | Performance evaluation | Evidence pack and verification logs support measurement and audit preparation | `pipeline-run.json`, `compliance-matrix.json`, local verification docs | Partial (Pipeline + Org) | Internal audits, management review, KPI/KRI dashboards |
| Clause 10 | Improvement | Pipeline defects and findings can feed improvements, but process ownership is external | Issues, PR history, remediation commits | Partial (Pipeline + Org) | CAPA process, continual improvement governance, tracked actions |

### 5.3 ISO 27001 Annex A controls (selected, pipeline-relevant) - design intent mapping

| Annex A control (2022) | Requirement area (summary) | Design intent (how this project addresses it) | Planned controls / files | Planned evidence | Coverage type | What else must be added |
|---|---|---|---|---|---|---|
| A.5.x (policy, roles, supplier governance families) | Governance and organizational controls | Design acknowledges these but does not claim pipeline-only coverage | Phase F governance/compliance docs | Policies, approvals, reviews (outside pipeline) | Phase F / Org Required | Policy framework, role assignment, supplier governance process |
| A.8.4 Access to source code | Controlled access and change traceability | Branch protection, CODEOWNERS, signed commits, PR review workflow | `.github/CODEOWNERS`, `.github/branch-protection.json`, Phase 1 checks | `pipeline-run.json`, repo settings exports | Partial (Pipeline + Org) | Access review process, org IAM governance, joiner/mover/leaver |
| A.8.8 Management of technical vulnerabilities | Identify and manage vulnerabilities | SCA, image scan, SAST, DAST gates in CI/CD | `build-and-scan.yml`, `dast.yml`, `.trivyignore` | `dependency-review.json`, `security-report.json`, `zap-report.json` | Partial (Pipeline + Org) | Remediation SLAs, exception approvals, vuln disclosure and tracking process |
| A.8.9 Configuration management | Control and version infrastructure/app configuration | Terraform IaC + Checkov + Git-tracked config changes | `infra/`, `security-gate.yml`, `deploy.yml` | Terraform plan/apply logs, Checkov results | Direct (Pipeline) for CI/CD-managed infra / Partial overall | CMDB/baselines for non-CI/CD systems |
| A.8.15 Logging | Event logging | Pipeline run metadata and audit artifacts provide CI/CD traceability; SIEM planned | Phase 6 evidence generation, Phase F SIEM | `pipeline-run.json`, workflow logs, SIEM logs (Phase F) | Partial (Pipeline + Org) | Central logging standards, retention/monitoring for all systems |
| A.8.16 Monitoring activities | Monitoring and analysis | Pipeline gate outcomes and planned SIEM integration support monitoring | Workflow statuses, alerts, Phase F SIEM | `pipeline-run.json`, alert records | Partial (Pipeline + Org) | Central monitoring coverage, on-call procedures, tuning |
| A.8.25 Secure development life cycle | Controlled secure development practices | Enforced CI gates, tests, scans, review process, evidence generation | Phases 1-6, repo governance, OPA policies | `security-report.json`, coverage, `pipeline-run.json` | Direct (Pipeline) for CI/CD SDLC controls | Organization-wide SDL policy, secure design reviews |
| A.8.28 Secure coding | Secure coding practices and verification | SAST, linting, DAST, PII scanning, code review support | `security-gate.yml`, `build-and-scan.yml`, `dast.yml` | `security-report.json`, `zap-report.json` | Partial (Pipeline + Org) | Developer training, coding standards, manual review guidance |
| A.8.30 Outsourced development (where applicable) | Control outsourced development risk | Supply-chain evidence supports software component traceability; not full vendor governance | SBOM, provenance, signatures | `sbom.cyclonedx.json`, `provenance.intoto.jsonl` | Partial (Pipeline + Org) | Outsourced dev controls, contract clauses, supplier assessments |
| A.8.32 Change management | Controlled changes and approvals | PR-based workflow, required checks, deployment verification, evidence pack | `pipeline.yml`, repo governance, `deploy.yml` | `pipeline-run.json`, cosign verify logs | Direct (Pipeline) for code/infrastructure changes through pipeline | Emergency change process, CAB/approval policy (if required by org) |

### 5.4 ISO 27001 design intent summary

- The design strongly supports Annex A technical controls relevant to SDLC, configuration, change management, and vulnerability management
- ISO 27001 certification readiness still depends on the ISMS management system (Clauses 4-10), which is Phase F / organizational work

## 6. SOC 2 (Trust Services Criteria) - Design Intent Mapping

### 6.1 SOC 2 scope note

SOC 2 is an attestation over a defined system and controls, typically over time (Type II). The pipeline can provide important technical controls and evidence, but does not replace entity-level controls, control ownership, or auditor evaluation.

### 6.2 SOC 2 matrix (design intent)

| SOC 2 TSC Area / Criterion | Plain-language requirement (summary) | Design intent (how this project addresses it) | Planned controls / files | Planned evidence | Coverage type | What else must be added |
|---|---|---|---|---|---|---|
| CC1 Control Environment | Governance, ethics, organizational structure | Pipeline does not create entity-level governance | Phase F SOC2/ISMS docs | Policies, org charts, approvals | Phase F / Org Required | Control environment documentation and ownership |
| CC2 Communication and Information | Communicate responsibilities and policies | Repo docs and runbooks support technical communication, not full org communication processes | `README.md`, `SETUP.md`, `docs/*`, Phase F runbooks | Documented procedures and revision history | Partial (Pipeline + Org) | Formal policy communication, acknowledgement, training |
| CC3 Risk Assessment | Identify/analyze risks to system objectives | Technical gates reflect risk treatment intent, but not full enterprise risk assessment | OPA policies, workflow gates, design docs | `pipeline-run.json`, policy docs, exceptions (Phase F) | Partial (Pipeline + Org) | Risk assessment methodology, risk register, periodic reassessment |
| CC4 Monitoring Activities | Monitor controls and remediate deficiencies | Pipeline generates repeatable evidence and pass/fail outcomes; SIEM integration planned | Phase 6 Evidence Pack, Phase F SIEM | `pipeline-run.json`, `compliance-matrix.json`, alert logs | Partial (Pipeline + Org) | Formal control monitoring program, remediation tracking |
| CC5 Control Activities | Control design and operation procedures | CI/CD gates, OPA policies, Terraform change control provide strong technical control activities | Phases 1-6, `policies/`, `infra/` | Workflow artifacts + policy results | Direct (Pipeline) for CI/CD controls / Partial overall | Broader business process control activities |
| CC6 Logical and Physical Access Controls | Restrict logical access and protect assets | Repo governance, signed commits, OIDC reduce CI/CD access risk; physical controls are cloud/provider scope | `.github/CODEOWNERS`, branch protection config, `deploy.yml`, `sign-and-attest.yml` | `pipeline-run.json`, repo config export, cosign logs | Partial (Pipeline + Org) | IAM governance, access reviews, MFA evidence, vendor physical security reliance documentation |
| CC7 System Operations | Detect/respond to operational issues and ensure secure operations | Signature verification, scan gates, DAST, evidence packaging support system operation monitoring | Phases 2-6, planned SIEM | `cosign-verification.log`, `security-report.json`, `zap-report.json`, `pipeline-run.json` | Partial (Pipeline + Org) | On-call, incident ops, monitoring coverage, runbooks |
| CC8 Change Management | Authorize, test, approve, and track changes | PR-based flow, required checks, tests, signed artifacts, deploy verification, traceability | `pipeline.yml`, repo governance, build/test/deploy workflows | `pipeline-run.json`, test reports, signatures | Direct (Pipeline) for delivery changes | Emergency changes and segregation/approval procedures outside CI/CD |
| CC9 Risk Mitigation (vendor/supply chain/etc.) | Mitigate risks from vendors and dependencies | SBOM, provenance, SCA support software dependency risk; supplier governance remains external | `build-and-scan.yml`, `sign-and-attest.yml`, `scripts/check-dpa.sh` | `sbom.cyclonedx.json`, `provenance.intoto.jsonl`, `dpa-compliance-check.json` | Partial (Pipeline + Org) | Vendor management program, due diligence, contract reviews |
| PI1 Processing Integrity | Complete, valid, accurate, timely processing | Tests, coverage, smoke test, DAST, signed deployments improve processing integrity of software changes | `build-and-scan.yml`, `deploy.yml`, `dast.yml` | Coverage artifacts, smoke test logs, `zap-report.json`, `pipeline-run.json` | Direct (Pipeline) for release pipeline integrity / Partial system-wide | Business process validation, data quality controls in application scope |

### 6.3 SOC 2 design intent summary

- Strong design support for CC5, CC8, and PI1 in the software delivery pipeline
- Partial support for CC6/CC7/CC9 through technical controls and evidence
- SOC 2 readiness still requires system description, control ownership, period-based evidence collection, and auditor attestation

## 7. RODO/GDPR (EU 2016/679) - Supporting Controls / Evidence Mapping (Design Intent)

### 7.1 GDPR scope note

This pipeline is not a GDPR program by itself. It provides supporting controls and evidence related to:

- data minimization in artifacts/logs
- retention and deletion policy checks (for evidence storage)
- privacy by design support in engineering workflow
- processor/DPA tracking for pipeline tooling
- records/evidence of processing related to CI/CD operations

It does not replace full GDPR governance (legal basis, DPIA program, data subject rights process, breach notification program, transfer assessments, etc.).

### 7.2 GDPR/RODO matrix (design intent)

| GDPR Article / Principle | Plain-language requirement (summary) | Design intent (how this project addresses it) | Planned controls / files | Planned evidence | Coverage type | What else must be added |
|---|---|---|---|---|---|---|
| Art.5(1)(c) Data minimization | Keep personal data limited to what is necessary | Evidence workflow sanitizes logs and reduces unnecessary PII in archived artifacts | `scripts/sanitize-logs.sh`, `evidence-pack.yml` | Sanitized logs, `dpa-compliance-check.json` | Partial (Pipeline + Org) | Data classification policy, retention/access procedures beyond CI/CD |
| Art.5(1)(e) Storage limitation | Retain data only as long as necessary | Retention metadata checks and storage lifecycle/WORM design for audit evidence | `policies/retention-policy.rego`, storage Terraform module, `evidence-pack.yml` | Retention check outputs, storage config, `dpa-compliance-check.json` | Partial (Pipeline + Org) | Legal retention schedule validation, destruction procedures, exceptions governance |
| Art.25 Data protection by design/default | Build privacy considerations into systems/processes | PII scanning and data-flow mapping support engineering privacy-by-design evidence | Phase 1 PII scanner, `scripts/generate-data-flow.sh`, docs | `data-flow-diagram.json`, PII scan outputs | Partial (Pipeline + Org) | DPIA methodology, privacy requirements process, product design reviews |
| Art.28 Processor obligations | Ensure processor agreements and controls | DPA check script tracks status of key pipeline processors and services | `scripts/check-dpa.sh`, Phase 6 evidence generation | `dpa-compliance-check.json` | Partial (Pipeline + Org) | Formal processor inventory, DPA repository, contract/legal review process |
| Art.30 Records of processing activities (supporting evidence) | Maintain records of processing | Pipeline metadata provides CI/CD processing traceability and audit trail support | `scripts/generate-pipeline-run.sh`, `evidence-pack.yml` | `pipeline-run.json` | Partial (Pipeline + Org) | Formal RoPA covering all business processing, not just CI/CD |
| Art.32 Security of processing | Appropriate technical/organizational security measures | CI/CD security gates, signing, OIDC, scanning, and evidence improve engineering control posture | Phases 1-6, Terraform, repo governance | `security-report.json`, `cosign-verification.log`, `pipeline-run.json` | Partial (Pipeline + Org) | Broader technical and organizational security measures across all systems |
| Art.33/34 Personal data breach notification | Notify authority/data subjects where required | Pipeline can preserve technical evidence for incidents; notification process is organizational/legal | Evidence Pack + Phase F incident/reporting runbooks | Evidence Pack + incident records | Phase F / Org Required | Breach assessment workflow, legal decisioning, notification templates |

### 7.3 GDPR/RODO design intent summary

- The design provides useful privacy-supporting engineering evidence
- GDPR compliance remains mostly organizational and legal, with pipeline controls as supporting technical proof points

## 8. Cross-Framework Evidence-to-Requirement Mapping (Design Intent)

This section explains what each major planned evidence artifact is intended to prove across frameworks.

| Planned evidence artifact | What it demonstrates (design intent) | Typical framework use |
|---|---|---|
| `security-report.json` | Consolidated security findings from SAST/SCA/DAST and related scans | DORA risk controls, NIS2 SSDLC, ISO secure coding/vuln mgmt, SOC 2 system ops |
| `dependency-review.json` | Dependency/SCA scan outcomes and vulnerability posture | DORA updated systems, NIS2 supply chain, ISO vuln mgmt |
| `sbom.cyclonedx.json` | Component inventory for built artifact | DORA third-party risk support, NIS2 supply chain, SOC 2 vendor/software transparency |
| `provenance.intoto.jsonl` | Build provenance and traceability of artifact generation | DORA supply-chain risk support, NIS2 supply chain, SOC 2 change integrity |
| `cosign-verification.log` | Cryptographic verification of artifact signature | NIS2 cryptography, SOC 2 system operations, DORA tamper resistance support |
| `pipeline-run.json` | End-to-end run metadata, gates, actor, trigger, tool versions | DORA monitoring/risk evidence, NIS2 effectiveness evidence, ISO change/operation traceability, SOC 2 CC8 |
| `zap-report.json` | Runtime web application security test results | NIS2 SSDLC/incident handling support, ISO secure coding, SOC 2 operations |
| `dpa-compliance-check.json` | Pipeline tool processor/DPA status snapshot | GDPR Art.28 support, GDPR accountability support |
| `data-flow-diagram.json` | CI/CD data flow and PII transit mapping | GDPR Art.25/30 support, privacy design evidence |
| `compliance-matrix.json` | Machine-generated requirement/evidence presence map | Internal audit prep, evidence completeness review |
| `manifest.sha256` | Tamper-evident file manifest for Evidence Pack contents | SOC 2 operations/integrity support, DORA audit defensibility support |
| Evidence Pack ZIP + archive metadata | Immutable packaged evidence set for a release/deploy event | Audit support across frameworks (not a compliance substitute) |

## 9. What the Pipeline Design Does Well vs What It Does Not Solve

### 9.1 Strong design coverage (technical CI/CD control layer)

- Secure SDLC enforcement (pre-merge and pre-deploy gates)
- Software supply-chain integrity (SBOM + signing + provenance)
- Change traceability and artifact-level verification
- Automated audit evidence collection and packaging
- Cloud auth hardening via OIDC (no static secrets in deploy workflows)

### 9.2 Important gaps that are intentionally not solved by pipeline alone

- Management governance and accountability
- Legal/regulatory incident reporting workflows
- Full BC/DR program and resilience drills
- Organization-wide IAM governance and access recertification
- Supplier risk lifecycle and contract controls
- Full ISO 27001 ISMS (Clauses 4-10 + SoA + audits + reviews)
- SOC 2 system description, control ownership, and period-based operating effectiveness evidence
- Full GDPR program (DPIAs, legal basis, DSR handling, transfer assessments)

## 10. Required Additions (Phase F and Beyond) to Support Real-World Compliance Readiness

This section summarizes what must be added beyond the pipeline design for credible DORA/NIS2/ISO/SOC2 readiness claims.

### 10.1 Platform and operational additions

- SIEM ingestion for GitHub/Azure logs with alerting rules and escalation paths
- True Azure Blob immutability (WORM) operationalization, lock strategy, and legal hold process
- Backup/restore procedures and evidence-producing test drills
- Access-control evidence exports (MFA/SSO/org settings/branch protection snapshots)
- Exception and risk-acceptance workflow with approvers and expirations

### 10.2 Governance and GRC additions

- DORA/NIS2 incident management and regulator reporting runbooks
- Supplier / ICT third-party risk process and contract clause standards
- ISO 27001 ISMS core document set:
  - ISMS scope
  - risk methodology
  - risk register
  - treatment plan
  - Statement of Applicability
  - internal audit program
  - management review process
  - corrective action process
- SOC 2 readiness set:
  - system description
  - control matrix with owners
  - evidence calendar
  - period-based evidence collection process

### 10.3 Validation and assurance additions

- Legal/compliance validation of DORA/NIS2 interpretation in target jurisdiction
- External audit/certification/attestation (ISO 27001 certification body, SOC 2 CPA firm)
- Periodic control effectiveness reviews and dry-run audits

## 11. Recommended Claim Language (to Avoid Overclaiming)

Use language like:

- "Compliance-enabling DevSecOps pipeline with evidence generation for DORA/NIS2/ISO 27001/SOC 2 readiness"
- "Implements a secure CI/CD and software supply-chain control layer with audit evidence packaging"
- "Supports selected technical control requirements and audit evidence collection"

Avoid language like:

- "This pipeline alone makes you DORA compliant"
- "ISO 27001 certified by pipeline setup"
- "SOC 2 compliant without auditor review"

## 12. Relationship to Other Project Documents

- `../README.md` — pipeline overview, phases, and scope boundaries
- `../SETUP.md` — rollout and configuration
- `governance/` — ISMS, SOC 2, risk, IAM, and supplier-risk control documentation
- `compliance/framework-boundaries.md` — per-framework coverage boundaries

## 13. Maintenance Guidance

Update this document when any of the following changes occur:

- new framework mappings are added or removed
- evidence artifact names change
- workflow phase behavior changes (for example DAST gating policy)
- new Phase F workstreams are added
- compliance scope/claim language changes in the design documents

When updating, keep the distinction between:

- `design intent` (target-state controls)
- `implementation status` (what is currently built and verified)
