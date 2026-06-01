# Vendor Exit Plan Template

**Document Owner:** Security Lead / Engineering Lead
**Last Reviewed:** 2026-03-15
**Review Cadence:** Annually and upon vendor risk rating change
**Compliance Scope:** DORA Art.28(8), ISO 27001 A.5.23, SOC 2 CC9.2

---

## Purpose

This template provides a structured framework for planning and executing the exit from
a third-party ICT service provider. An exit plan must be developed for every vendor
rated **Medium** or above in the
[vendor-risk-register.md](vendor-risk-register.md). Exit plans for **Critical** vendors
must be tested at least annually.

---

## Instructions

1. Copy this template for each vendor requiring an exit plan.
2. Complete all sections with vendor-specific details.
3. Review and approve according to the approval authority table in the
   [vendor-due-diligence-checklist.md](vendor-due-diligence-checklist.md).
4. Test the exit plan annually for Critical vendors, biennially for High vendors.
5. Update upon any material change to the vendor relationship or alternative landscape.

---

# Exit Plan: [Vendor Name]

## 1. Vendor and Service Overview

| Field | Value |
|-------|-------|
| **Vendor Name** | |
| **Services Provided** | |
| **Contract Start Date** | |
| **Contract End Date / Renewal Date** | |
| **Contract Termination Notice Period** | |
| **Risk Rating** | |
| **Criticality Level** | |
| **Vendor Risk Register Reference** | |
| **Primary Contact (Vendor)** | |
| **Primary Contact (Internal)** | |

---

## 2. Trigger Conditions

Define the conditions under which this exit plan would be activated:

| Trigger | Description | Severity |
|---------|-------------|----------|
| **Contract expiry** | Contract reaches end date without renewal | Planned |
| **Cost escalation** | Pricing increase exceeds budget threshold (define %) | Planned |
| **Security incident** | Vendor experiences a material security breach affecting our data | Urgent |
| **Compliance failure** | Vendor fails to maintain required certifications or DPA terms | High |
| **Service degradation** | Vendor consistently fails SLA targets (define threshold) | High |
| **Business change** | Strategic decision to change technology stack or vendor | Planned |
| **Vendor insolvency** | Vendor ceases operations or enters administration | Urgent |
| **Regulatory requirement** | Regulatory action requires vendor change | High |

---

## 3. Alternative Vendors / Tools

| Alternative | Type | Evaluation Status | Migration Effort | Key Trade-offs |
|------------|------|-------------------|-----------------|----------------|
| | | [ ] Evaluated / [ ] Shortlisted / [ ] Not yet assessed | Low / Medium / High | |
| | | [ ] Evaluated / [ ] Shortlisted / [ ] Not yet assessed | Low / Medium / High | |
| | | [ ] Evaluated / [ ] Shortlisted / [ ] Not yet assessed | Low / Medium / High | |

---

## 4. Data Migration Plan

### 4.1 Data Inventory

| Data Type | Volume (Est.) | Format | Export Method | Sensitivity |
|-----------|--------------|--------|---------------|-------------|
| | | | | |
| | | | | |

### 4.2 Migration Steps

1. [ ] Export all data from current vendor in agreed format
2. [ ] Validate exported data completeness and integrity
3. [ ] Transform data to target vendor format (if required)
4. [ ] Import data into target vendor/system
5. [ ] Validate imported data completeness and integrity
6. [ ] Confirm data deletion from source vendor (written confirmation)

### 4.3 Data Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Data loss during migration | | | |
| Data format incompatibility | | | |
| Extended migration timeline | | | |

---

## 5. Service Continuity Plan

Describe how pipeline operations will be maintained during the transition:

| Phase | Duration | Operations Impact | Mitigation |
|-------|----------|-------------------|------------|
| **Pre-transition** | | | |
| **Parallel running** | | | |
| **Cutover** | | | |
| **Post-cutover validation** | | | |

---

## 6. Timeline

| Phase | Activity | Start | End | Duration | Owner |
|-------|----------|-------|-----|----------|-------|
| **Phase 0: Preparation** | | | | | |
| | Activate exit plan and notify stakeholders | | | | |
| | Finalize alternative vendor selection | | | | |
| | Negotiate alternative vendor contract | | | | |
| **Phase 1: Setup** | | | | | |
| | Provision alternative environment | | | | |
| | Configure alternative service | | | | |
| | Integration testing | | | | |
| **Phase 2: Migration** | | | | | |
| | Data export from current vendor | | | | |
| | Data import to alternative vendor | | | | |
| | Data validation | | | | |
| **Phase 3: Parallel Running** | | | | | |
| | Run both systems in parallel | | | | |
| | Validate parity of results | | | | |
| | User acceptance testing | | | | |
| **Phase 4: Cutover** | | | | | |
| | Switch production traffic to alternative | | | | |
| | Monitor for issues | | | | |
| | Rollback window (define duration) | | | | |
| **Phase 5: Decommission** | | | | | |
| | Confirm data deletion from current vendor | | | | |
| | Terminate current vendor contract | | | | |
| | Update vendor risk register | | | | |
| | Archive exit plan documentation | | | | |

---

## 7. Responsible Parties

| Role | Name | Responsibilities |
|------|------|-----------------|
| **Exit Plan Owner** | | Overall coordination, stakeholder communication |
| **Technical Lead** | | Migration execution, integration, testing |
| **Security Lead** | | Security validation, DPA management, data deletion confirmation |
| **Legal Counsel** | | Contract review, termination, new vendor agreement |
| **Operations** | | Service continuity, monitoring, incident response during transition |

---

## 8. Risks and Mitigations

| # | Risk | Likelihood | Impact | Mitigation | Residual Risk |
|---|------|-----------|--------|------------|---------------|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |

---

## 9. Communication Plan

| Audience | Channel | Timing | Content | Owner |
|----------|---------|--------|---------|-------|
| **Executive leadership** | | Exit plan activation, major milestones | | |
| **Development team** | | Detailed transition plan, action items | | |
| **Security team** | | Security implications, validation requirements | | |
| **Affected clients** | | Service impact (if any), timeline | | |
| **Current vendor** | | Termination notice, transition requirements | | |
| **Alternative vendor** | | Onboarding requirements, timeline | | |

---

## 10. Approval

| Role | Name | Decision | Date |
|------|------|----------|------|
| Exit Plan Owner | | [ ] Approved | |
| Security Lead | | [ ] Approved | |
| CTO | | [ ] Approved | |

---

## 11. Test History

| Date | Test Type | Result | Issues Found | Remediation |
|------|-----------|--------|-------------|-------------|
| | Tabletop exercise | | | |
| | Partial migration test | | | |
| | Full dry run | | | |

---
---

# EXAMPLE: GitHub Actions to GitLab CI Migration

> **NOTE:** This is a pre-filled example for illustrative purposes only. All dates,
> names, and details are fictional and must be replaced with actual values when
> creating a real exit plan.

## 1. Vendor and Service Overview

| Field | Value |
|-------|-------|
| **Vendor Name** | GitHub (Microsoft) |
| **Services Provided** | GitHub Actions (CI/CD), GitHub Advanced Security (CodeQL, secret scanning), Repository hosting |
| **Contract Start Date** | 2025-01-01 |
| **Contract End Date / Renewal Date** | 2026-12-31 |
| **Contract Termination Notice Period** | 90 days |
| **Risk Rating** | Medium |
| **Criticality Level** | Critical |
| **Vendor Risk Register Reference** | EP-001 in vendor-risk-register.md |
| **Primary Contact (Vendor)** | GitHub Enterprise Support |
| **Primary Contact (Internal)** | [Engineering Lead] |

## 2. Trigger Conditions

| Trigger | Description | Severity |
|---------|-------------|----------|
| **Cost escalation** | GitHub Enterprise pricing increase > 25% YoY | Planned |
| **Security incident** | Breach affecting source code or build secrets | Urgent |
| **Service degradation** | GitHub Actions availability < 99.5% for 3 consecutive months | High |
| **Regulatory requirement** | Regulatory mandate requiring self-hosted CI/CD | High |

## 3. Alternative Vendors / Tools

| Alternative | Type | Evaluation Status | Migration Effort | Key Trade-offs |
|------------|------|-------------------|-----------------|----------------|
| GitLab CI (self-managed) | Self-hosted | [x] Evaluated | High | Full control, higher ops burden |
| GitLab CI (SaaS) | Cloud | [x] Evaluated | Medium | Similar model, EU hosting available |
| Forgejo + Woodpecker CI | Self-hosted OSS | [x] Shortlisted | High | Full OSS, smaller community |

## 4. Data Migration Plan

### 4.1 Data Inventory

| Data Type | Volume (Est.) | Format | Export Method | Sensitivity |
|-----------|--------------|--------|---------------|-------------|
| Git repositories | ~5 GB | Git | `git clone --mirror` | Confidential |
| GitHub Actions workflows | ~200 files | YAML | Repository export | Internal |
| GitHub Actions secrets | ~30 secrets | N/A | Manual re-creation in target | Restricted |
| Issues and PRs | ~500 items | JSON | GitHub API / `gh` CLI export | Internal |
| Packages (container images) | ~20 GB | OCI | `docker pull` + `docker push` | Internal |

### 4.2 Migration Steps

1. [x] Map GitHub Actions workflow syntax to GitLab CI YAML syntax
2. [ ] Export all repositories using `git clone --mirror`
3. [ ] Export issues, PRs, and metadata using GitHub API
4. [ ] Import repositories into GitLab
5. [ ] Import issues/PRs using GitLab import API
6. [ ] Recreate CI/CD secrets in GitLab CI variables
7. [ ] Convert workflow files from GitHub Actions to `.gitlab-ci.yml`
8. [ ] Migrate container images from GHCR to GitLab Container Registry
9. [ ] Configure GitLab runners (self-hosted or SaaS)
10. [ ] Validate all pipelines execute successfully
11. [ ] Confirm data deletion from GitHub (after retention period)

## 5. Service Continuity Plan

| Phase | Duration | Operations Impact | Mitigation |
|-------|----------|-------------------|------------|
| **Pre-transition** | 4 weeks | None | Preparation only |
| **Parallel running** | 4 weeks | Dual maintenance burden | Both systems active; GitHub primary |
| **Cutover** | 1 week | Reduced deployment frequency | Pre-approved deployment freeze window |
| **Post-cutover validation** | 2 weeks | Monitoring overhead | Rollback to GitHub if critical issues |

## 6. Timeline (Example)

| Phase | Activity | Duration | Owner |
|-------|----------|----------|-------|
| **Phase 0** | Activate plan, notify stakeholders, finalize GitLab contract | 2 weeks | Exit Plan Owner |
| **Phase 1** | Provision GitLab, configure runners, convert 1 pilot pipeline | 3 weeks | Technical Lead |
| **Phase 2** | Migrate repositories, convert remaining pipelines, migrate images | 4 weeks | Technical Lead |
| **Phase 3** | Parallel running, validate parity | 4 weeks | Operations |
| **Phase 4** | Cutover, monitor, rollback window | 2 weeks | Technical Lead |
| **Phase 5** | Decommission GitHub, confirm deletion, update registers | 2 weeks | Security Lead |
| **Total** | | **17 weeks** | |

## 8. Risks and Mitigations

| # | Risk | Likelihood | Impact | Mitigation | Residual Risk |
|---|------|-----------|--------|------------|---------------|
| 1 | Workflow conversion errors | Medium | High | Automated conversion tools + manual review + parallel running | Low |
| 2 | Lost CI/CD secrets during migration | Low | Critical | Secrets inventory pre-migration; verify all secrets in target before cutover | Low |
| 3 | Team productivity loss during transition | Medium | Medium | Training sessions; migration documentation; extended parallel running | Low |
| 4 | GitHub Advanced Security features not replicated | Medium | High | Evaluate GitLab SAST/DAST or standalone tools (Semgrep, Trivy) as replacements | Medium |

---

## Review History

| Date | Reviewer | Changes |
|------|----------|---------|
| 2026-03-15 | Initial creation | Template and example exit plan established |
