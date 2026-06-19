# Vendor Exit Plans (Critical / High Vendors)

**Document Owner:** Engineering Lead / Security Lead
**Last Reviewed:** 2026-06-16
**Review Cadence:** Annually and upon vendor risk-rating change; Critical-vendor plans tested at least annually
**Compliance Scope:** DORA Art.28(8), Art.30(2)-(3); ISO 27001 A.5.23; SOC 2 CC9.2
**Template:** [vendor-exit-plan-template.md](vendor-exit-plan-template.md)
**Register:** [vendor-risk-register.md](vendor-risk-register.md) -> Exit Plan References

---

## Scope and Status

This document holds the **completed, operable** exit plans for the Critical/High
vendors in the [vendor-risk-register.md](vendor-risk-register.md) that processed only a
"template available" / "planned" placeholder before. Each plan below is filled against
the [vendor-exit-plan-template.md](vendor-exit-plan-template.md) structure and is the
authoritative source for the register's `Documented` status.

| Ref | Vendor | Criticality | Plan Status | Tabletop Tested |
|-----|--------|-------------|-------------|-----------------|
| EP-001 | GitHub (Microsoft) | Critical | Documented | 2026-06-15 (tabletop) |
| EP-002 | Microsoft Azure | Critical | Documented | 2026-06-15 (tabletop) |

**Honesty boundary (blueprint/04 §9):** these plans are *documented* and *tabletop-tested*.
No production exit has been *executed*; the `check-thirdparty-clauses` validator asserts
the plan is documented/tested in the register, never that an exit was actually run. A full
production dry-run is scheduled (see each plan's Test History) and requires human sign-off
to mark `Tested` against a real migration.

---
---

# EP-001 — Exit Plan: GitHub (Microsoft) -> GitLab / Gitea

## 1. Vendor and Service Overview

| Field | Value |
|-------|-------|
| **Vendor Name** | GitHub (Microsoft) |
| **Services Provided** | Repository hosting, GitHub Actions (CI/CD), GitHub Advanced Security (CodeQL, secret scanning), GHCR (container packages), Renovate (GitHub App) |
| **Contract Start Date** | 2025-01-01 |
| **Contract End Date / Renewal Date** | 2026-12-31 (annual enterprise agreement) |
| **Contract Termination Notice Period** | 90 days |
| **Risk Rating** | Medium |
| **Criticality Level** | Critical (outage blocks all CI/CD) |
| **Vendor Risk Register Reference** | Row 1 / EP-001 in vendor-risk-register.md |
| **Primary Contact (Vendor)** | GitHub Enterprise Support |
| **Primary Contact (Internal)** | Engineering Lead (Szymon Mytych) |

## 2. Trigger Conditions

| Trigger | Description | Severity |
|---------|-------------|----------|
| **Cost escalation** | GitHub Enterprise pricing increase > 25% YoY | Planned |
| **Security incident** | Breach affecting source code or Actions build secrets | Urgent |
| **Service degradation** | GitHub Actions availability < 99.5% for 3 consecutive months | High |
| **Regulatory requirement** | Mandate requiring EU-sovereign or self-hosted CI/CD | High |
| **Vendor insolvency** | Discontinuation of Actions/Advanced Security tier | Urgent |

## 3. Alternative Vendors / Tools (assessed)

| Alternative | Type | Evaluation Status | Migration Effort | Key Trade-offs |
|------------|------|-------------------|-----------------|----------------|
| **GitLab CI (SaaS, EU region)** | Cloud | [x] Evaluated — **primary target** | Medium | Closest model to Actions; native EU hosting; built-in SAST/DAST/secret-detection replaces GH Advanced Security; built-in container registry replaces GHCR |
| GitLab CE (self-managed) | Self-hosted | [x] Evaluated — fallback | High | Full data sovereignty; higher ops burden (runners, upgrades, backups) |
| **Gitea / Forgejo + Woodpecker CI** | Self-hosted OSS | [x] Shortlisted — sovereignty fallback | High | Fully OSS, lightweight, no licence cost; smaller ecosystem; CI conversion heaviest here |

Primary target = **GitLab CI (SaaS)**; sovereignty fallback = **Gitea/Forgejo + Woodpecker**.

## 4. Data Migration Plan

### 4.1 Data Inventory

| Data Type | Volume (Est.) | Format | Export Method | Sensitivity |
|-----------|--------------|--------|---------------|-------------|
| Git repositories | ~5 GB | Git | `git clone --mirror` | Confidential |
| Actions workflows | ~15 YAML files | YAML | In-repo (migrated with repo) | Internal |
| Actions/Dependabot secrets | ~30 secrets | N/A | Re-created from secret manager / Key Vault, never exported in clear | Restricted |
| Issues, PRs, releases | ~500 items | JSON | `gh api` / GitLab import API | Internal |
| Container packages (GHCR) | ~20 GB | OCI | `skopeo sync` / `crane copy` registry-to-registry | Internal |
| Branch protection / org settings | config | manual | Re-create as code in target | Internal |

### 4.2 Migration Steps

1. [x] Map each GitHub Actions workflow construct to the target syntax (Actions `jobs/steps` -> GitLab `stages/jobs`, or -> Woodpecker `pipeline`). Conversion crib sheet maintained in the runbook.
2. [ ] Mirror every repository: `git clone --mirror`, then `git push --mirror` to target.
3. [ ] Import issues/PRs/releases via GitLab's GitHub importer (or `gh api` -> Gitea migrate API).
4. [ ] Re-create CI/CD secrets in target as masked CI variables, sourcing values from the secret manager — secrets are NEVER round-tripped in plaintext.
5. [ ] Convert workflows to `.gitlab-ci.yml` (or `.woodpecker.yml`); keep one pilot pipeline first.
6. [ ] Copy container images registry-to-registry with `skopeo sync` (no local pull); re-sign in the new registry per the existing cosign keyless flow (or self-managed key if Sigstore also exited — see EP-003).
7. [ ] Replace GitHub Advanced Security with target-native equivalents already present in this pipeline as OSS: Semgrep/CodeQL-OSS for SAST, TruffleHog/Gitleaks for secrets, Trivy for SCA — no new vendor needed.
8. [ ] Repoint Renovate (self-hosted Renovate runner) or switch to GitLab's native dependency updates.
9. [ ] Validate all pipelines green on the target; run the evidence-pack + sign-and-attest jobs end-to-end.
10. [ ] Cutover; keep GitHub read-only for the rollback window.
11. [ ] After retention window, confirm deletion from GitHub (written confirmation).

### 4.3 Data Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Workflow conversion errors | Medium | High | Pilot pipeline + parallel running + conversion crib sheet |
| Lost CI/CD secrets | Low | Critical | Secrets sourced from Key Vault/secret manager, not GitHub; verified in target before cutover |
| Container provenance break | Medium | High | Re-sign images in target registry; verify cosign attestation chain before cutover |

## 5. Service Continuity Plan

| Phase | Duration | Operations Impact | Mitigation |
|-------|----------|-------------------|------------|
| **Pre-transition** | 4 weeks | None | Prep only; GitHub remains primary |
| **Parallel running** | 4 weeks | Dual maintenance | Both CI systems active; GitHub authoritative |
| **Cutover** | 1 week | Deployment freeze | Pre-approved freeze window |
| **Post-cutover validation** | 2 weeks | Monitoring overhead | Rollback to GitHub if a critical gate fails |

## 6. Timeline

| Phase | Activity | Duration | Owner |
|-------|----------|----------|-------|
| Phase 0 | Activate plan, notify stakeholders, finalize target contract | 2 weeks | Exit Plan Owner |
| Phase 1 | Provision target, configure runners, convert 1 pilot pipeline | 3 weeks | Technical Lead |
| Phase 2 | Mirror repos, convert remaining pipelines, sync images | 4 weeks | Technical Lead |
| Phase 3 | Parallel running, validate parity (incl. evidence pack) | 4 weeks | Operations |
| Phase 4 | Cutover, monitor, rollback window | 2 weeks | Technical Lead |
| Phase 5 | Decommission GitHub, confirm deletion, update register | 2 weeks | Security Lead |
| **Total** | | **17 weeks** | |

## 7. Responsible Parties

| Role | Name | Responsibilities |
|------|------|-----------------|
| Exit Plan Owner | Engineering Lead | Coordination, stakeholder comms |
| Technical Lead | Engineering Lead | Migration, pipeline conversion, image re-signing |
| Security Lead | Security Lead | Secret re-creation, provenance, deletion confirmation |
| Legal Counsel | (external counsel) | Contract termination, target agreement |

## 8. Risks and Mitigations

| # | Risk | Likelihood | Impact | Mitigation | Residual |
|---|------|-----------|--------|------------|----------|
| 1 | Conversion errors | Medium | High | Pilot + parallel + crib sheet | Low |
| 2 | Secret loss | Low | Critical | Source from secret manager; verify pre-cutover | Low |
| 3 | Productivity dip | Medium | Medium | Training, docs, extended parallel | Low |
| 4 | GH Advanced Security not replicated | Low | Medium | Pipeline already runs OSS SAST/secret/SCA equivalents | Low |

## 9. Communication Plan

| Audience | Timing | Content |
|----------|--------|---------|
| Leadership | Activation + milestones | Status, budget, risk |
| Dev team | Detailed plan | Action items, training |
| Current vendor (GitHub) | 90-day notice | Termination, data return |
| Target vendor | Onboarding | Provisioning, timeline |

## 10. Approval

| Role | Decision | Date |
|------|----------|------|
| Exit Plan Owner | [ ] Approved (pending human sign-off) | |
| Security Lead | [ ] Approved (pending human sign-off) | |
| CTO | [ ] Approved (pending human sign-off) | |

> Plan content is complete and operable; production execution and the `Tested`
> (real-migration) flag require the human countersignatures above.

## 11. Test History

| Date | Test Type | Result | Issues Found | Remediation |
|------|-----------|--------|-------------|-------------|
| 2026-06-15 | Tabletop exercise | Pass | Confirmed OSS SAST/secret/SCA already cover GH Advanced Security; image re-signing step added | Crib sheet + step 6/7 added above |
| (scheduled) | Partial migration (1 repo + 1 pipeline to GitLab SaaS) | — | — | Requires human sign-off + sandbox |

---
---

# EP-002 — Exit Plan: Microsoft Azure -> Alternative Cloud

## 1. Vendor and Service Overview

| Field | Value |
|-------|-------|
| **Vendor Name** | Microsoft Azure |
| **Services Provided** | Azure Container Registry (ACR), Container Apps, Key Vault, Blob Storage (evidence-pack WORM archive) |
| **Contract Start Date** | 2025-01-01 |
| **Contract End Date / Renewal Date** | 2026-12-31 (annual enterprise agreement) |
| **Contract Termination Notice Period** | 90 days |
| **Risk Rating** | Medium |
| **Criticality Level** | Critical (hosts runtime + evidence store) |
| **Vendor Risk Register Reference** | Row 2 / EP-002 in vendor-risk-register.md |
| **Primary Contact (Vendor)** | Microsoft Enterprise Support |
| **Primary Contact (Internal)** | Engineering Lead (Szymon Mytych) |

## 2. Trigger Conditions

| Trigger | Description | Severity |
|---------|-------------|----------|
| **Cost escalation** | Azure pricing/consumption increase > 25% YoY | Planned |
| **Security incident** | Breach affecting evidence store, images, or Key Vault | Urgent |
| **Compliance failure** | Loss of EU data residency (Poland Central) or DPA terms | High |
| **Service degradation** | Container Apps / Blob availability below SLA for 3 consecutive months | High |
| **Regulatory requirement** | Mandate to change cloud provider / sovereignty rule | High |
| **Vendor insolvency / withdrawal** | Service withdrawal from EU region | Urgent |

## 3. Alternative Vendors / Tools (assessed)

| Alternative | Type | Evaluation Status | Migration Effort | Key Trade-offs |
|------------|------|-------------------|-----------------|----------------|
| **AWS (ECR + ECS Fargate / App Runner + Secrets Manager + S3 Object Lock)** | Cloud | [x] Evaluated — **primary target** | Medium | Direct service-for-service map; S3 Object Lock = WORM parity for evidence packs; eu-central-1 / eu-west-1 EU residency |
| GCP (Artifact Registry + Cloud Run + Secret Manager + GCS bucket-lock) | Cloud | [x] Evaluated — fallback | Medium | Cloud Run ~= Container Apps; GCS retention lock = WORM parity; europe-west EU residency |
| Self-hosted (Harbor registry + K8s + HashiCorp Vault + MinIO with object-lock) | Self-hosted OSS | [x] Shortlisted — sovereignty fallback | High | Full sovereignty, no cloud lock-in; highest ops burden |

Primary target = **AWS**; sovereignty fallback = **self-hosted (Harbor + Vault + MinIO)**.
All infrastructure is already declared in Terraform, so the cloud is swappable by writing
an equivalent provider module rather than re-architecting.

## 4. Data Migration Plan

### 4.1 Data Inventory

| Data Type | Volume (Est.) | Format | Export Method | Sensitivity |
|-----------|--------------|--------|---------------|-------------|
| Container images (ACR) | ~20 GB | OCI | `skopeo sync` / `crane copy` registry-to-registry (no local pull) | Internal |
| Application config / Container Apps spec | small | YAML/IaC | Re-declare in target IaC (Terraform) | Internal |
| Key Vault secrets/keys | ~30 items | N/A | Re-create in target secret manager from source of truth; values never exported in clear; rotate on arrival | Restricted |
| Blob evidence packs (WORM, 5-yr) | growing, ~50 GB | tar/JSON | `azcopy`/`rclone` -> target object store **with object-lock enabled before copy** | Confidential (immutable) |
| Application/build logs | 90-day | JSON | Forward to target log store; legacy retained to end of window | Internal |

### 4.2 Migration Steps

1. [ ] Stand up the target provider module in Terraform (registry, runtime, secret store, object store) — parameterized so the cloud is a provider swap, not a rewrite.
2. [ ] Enable **WORM/object-lock on the target evidence bucket BEFORE any copy** (S3 Object Lock / GCS retention lock / MinIO object-lock) to preserve the 5-year immutability guarantee.
3. [ ] Copy container images registry-to-registry with `skopeo sync` (server-side, no local pull); re-sign in the target registry via the existing cosign keyless flow.
4. [ ] Re-create Key Vault secrets/keys in the target secret manager from the secret source of truth (dual-write for one rotation cycle); **rotate all credentials on arrival**; never round-trip secrets in plaintext.
5. [ ] Copy evidence packs with `azcopy`/`rclone`, verifying object count + checksum + retention-lock metadata against the source manifest.
6. [ ] Deploy the application to the target runtime (ECS Fargate / Cloud Run); wire secrets via the target's workload identity (IRSA / Workload Identity).
7. [ ] Re-point CI/CD (deploy.yml) provider auth + resource names to the target; run a full pipeline including evidence-pack write and restore-test on the target store.
8. [ ] Parallel-run: keep Azure authoritative; validate parity of runtime + evidence integrity.
9. [ ] Cutover production traffic; keep Azure read-only for the rollback window.
10. [ ] After the rollback window AND after the 5-year WORM obligation is satisfied or the immutable archive is fully re-anchored on the target, confirm deletion from Azure (written confirmation). Do NOT delete evidence still under its retention obligation.

### 4.3 Data Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Evidence immutability break | Low | Critical | Enable object-lock on target BEFORE copy; checksum + retention-metadata verification; do not delete source until obligation re-anchored |
| Secret exposure during migration | Low | Critical | No plaintext export; rotate on arrival; dual-write one cycle |
| Image provenance break | Medium | High | Re-sign + verify cosign attestation chain on target before cutover |
| Data residency regression | Low | High | Pin target to EU region; verify before copy |

## 5. Service Continuity Plan

| Phase | Duration | Operations Impact | Mitigation |
|-------|----------|-------------------|------------|
| **Pre-transition** | 4 weeks | None | Build target IaC module; Azure primary |
| **Parallel running** | 4 weeks | Dual cost | Both clouds active; Azure authoritative |
| **Cutover** | 1 week | Deployment freeze | Pre-approved freeze window |
| **Post-cutover validation** | 3 weeks | Monitoring overhead | Rollback to Azure if a critical gate / evidence check fails |

## 6. Timeline

| Phase | Activity | Duration | Owner |
|-------|----------|----------|-------|
| Phase 0 | Activate plan, notify stakeholders, finalize target contract + region | 2 weeks | Exit Plan Owner |
| Phase 1 | Build target Terraform module; enable object-lock; provision runtime/secret store | 4 weeks | Technical Lead |
| Phase 2 | Sync images, migrate secrets (rotate), copy + verify evidence packs | 4 weeks | Technical Lead |
| Phase 3 | Parallel running, validate runtime parity + evidence integrity + restore test | 4 weeks | Operations |
| Phase 4 | Cutover, monitor, rollback window | 2 weeks | Technical Lead |
| Phase 5 | Decommission Azure (respecting WORM obligation), confirm deletion, update register | 2 weeks | Security Lead |
| **Total** | | **18 weeks** | |

## 7. Responsible Parties

| Role | Name | Responsibilities |
|------|------|-----------------|
| Exit Plan Owner | Engineering Lead | Coordination, stakeholder comms |
| Technical Lead | Engineering Lead | Target IaC, image/secret/evidence migration |
| Security Lead | Security Lead | Secret rotation, evidence immutability, residency, deletion confirmation |
| Legal Counsel | (external counsel) | Contract termination, target agreement, DPA |

## 8. Risks and Mitigations

| # | Risk | Likelihood | Impact | Mitigation | Residual |
|---|------|-----------|--------|------------|----------|
| 1 | Evidence immutability/retention break | Low | Critical | Object-lock before copy; verify; retain source under obligation | Low |
| 2 | Secret exposure | Low | Critical | No plaintext export; rotate on arrival | Low |
| 3 | Image provenance break | Medium | High | Re-sign + verify on target before cutover | Low |
| 4 | Cost during parallel run | Medium | Medium | Time-box parallel window; reserved capacity | Medium |

## 9. Communication Plan

| Audience | Timing | Content |
|----------|--------|---------|
| Leadership | Activation + milestones | Status, budget, residency, risk |
| Dev/Ops team | Detailed plan | Action items, target IaC |
| Current vendor (Azure) | 90-day notice | Termination, data return, deletion timing vs WORM |
| Target vendor | Onboarding | Provisioning, EU region, timeline |

## 10. Approval

| Role | Decision | Date |
|------|----------|------|
| Exit Plan Owner | [ ] Approved (pending human sign-off) | |
| Security Lead | [ ] Approved (pending human sign-off) | |
| CTO | [ ] Approved (pending human sign-off) | |

> Plan content is complete and operable; production execution, the `Tested`
> (real-migration) flag, and any deletion of immutable evidence require the human
> countersignatures above and confirmation that retention obligations are satisfied.

## 11. Test History

| Date | Test Type | Result | Issues Found | Remediation |
|------|-----------|--------|-------------|-------------|
| 2026-06-15 | Tabletop exercise | Pass | Identified WORM/object-lock ordering risk (must enable before copy) and need to retain source evidence until obligation re-anchored | Steps 2 + 10 and Risk #1 added above |
| (scheduled) | Partial dry-run (image sync + evidence-pack copy to AWS sandbox, object-lock verified) | — | — | Requires human sign-off + non-prod target account (NEEDS-AZURE/cloud) |

---

## Review History

| Date | Reviewer | Changes |
|------|----------|---------|
| 2026-06-16 | Engineering Lead | Completed EP-001 (GitHub -> GitLab/Gitea) and EP-002 (Azure -> alt-cloud) exit plans from template; tabletop-tested 2026-06-15; register status updated to Documented |
