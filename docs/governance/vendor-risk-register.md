# Vendor Risk Register

**Document Owner:** Security Lead
**Last Reviewed:** 2026-06-16 (reviewed 2026-06-16; Szymon to countersign)
**Review Cadence:** Quarterly (minimum) and upon any vendor change
**Compliance Scope:** DORA Art.28-30, NIS2 Art.21.2.d, ISO 27001 A.5.19-A.5.23, SOC 2 CC9

---

## Purpose

This register catalogues all third-party ICT service providers and open-source tools
used within the CyberForge DevSecOps Pipeline. It provides a single source of truth for
vendor risk assessment, DPA status tracking, and supply chain oversight as required by
DORA, NIS2, ISO 27001, and SOC 2.

---

## Risk Rating Criteria

| Rating | Definition |
|--------|------------|
| **Critical** | Core pipeline dependency processing sensitive data in external environment; no drop-in replacement; outage halts all deployments |
| **High** | Significant operational dependency or external data processing; replacement requires substantial effort |
| **Medium** | Cloud service with active DPA; replacement available but requires migration planning |
| **Low** | Open-source tool running locally on pipeline runner; no data leaves the build environment; easily replaceable |

---

## Criticality Classification

| Level | Definition |
|-------|------------|
| **Critical** | Pipeline cannot function without this service; outage blocks all CI/CD operations |
| **High** | Pipeline degraded without this service; core security or deployment capability impaired |
| **Medium** | Pipeline can operate with reduced capability; alternative workarounds exist |
| **Low** | Convenience tool; pipeline operates normally without it |

---

## Vendor Inventory

| # | Vendor | Service | Data Types Processed | Data Location | DPA Status | DPA URL / Reference | Risk Rating | Criticality | Contract Renewal | Exit Plan Ref |
|---|--------|---------|---------------------|---------------|------------|---------------------|-------------|-------------|-----------------|---------------|
| 1 | GitHub (Microsoft) | GitHub Actions, GitHub Advanced Security, CodeQL | Source code, build logs, developer metadata, PR/issue data | EU (GitHub data residency) | ACTIVE | [GitHub DPA](https://github.com/customer-terms/github-data-protection-agreement) | Medium | Critical | Annual (enterprise agreement) | [EP-001](#exit-plan-references) |
| 2 | Microsoft Azure | ACR, Container Apps, Key Vault, Blob Storage | Container images, application logs, evidence packs, secrets (encrypted) | Poland Central (EU) | ACTIVE | [Microsoft DPA](https://www.microsoft.com/licensing/docs/view/Microsoft-Products-and-Services-Data-Protection-Addendum-DPA) | Medium | Critical | Annual (enterprise agreement) | [EP-002](#exit-plan-references) |
| 3 | Sigstore (Linux Foundation) | Fulcio, Rekor transparency log | OIDC identity tokens, cryptographic signatures | Global (US-hosted infrastructure) | NOT_REQUIRED | N/A - Public transparency log; no personal data beyond GitHub OIDC identity | Low | High | N/A (open infrastructure) | [EP-003](#exit-plan-references) |
| 4 | OWASP Foundation | OWASP ZAP | No data sent externally (self-hosted on runner) | N/A (local execution) | NOT_REQUIRED | N/A - Self-hosted, no external data transmission | Low | Medium | N/A (open source) | [EP-004](#exit-plan-references) |
| 5 | Aqua Security | Trivy (OSS) | Vulnerability database downloads (inbound only); scan results remain local | N/A (client-side only) | NOT_REQUIRED | N/A - No data sent externally; vulnerability DB fetched read-only | Low | Medium | N/A (open source) | [EP-005](#exit-plan-references) |
| 6 | Bridgecrew (Palo Alto Networks) | Checkov (OSS) | IaC scan results (local only) | N/A (client-side only) | NOT_REQUIRED | N/A - All processing local; no telemetry enabled | Low | Medium | N/A (open source) | [EP-006](#exit-plan-references) |
| 7 | Anchore | Syft (OSS) | SBOM generation output (local only) | N/A (client-side only) | NOT_REQUIRED | N/A - All processing local; SBOM stored in pipeline artifacts | Low | Medium | N/A (open source) | [EP-007](#exit-plan-references) |
| 8 | OxSecurity | MegaLinter (OSS) | Linting results (local only) | N/A (client-side only) | NOT_REQUIRED | N/A - All processing local; no external reporting enabled | Low | Low | N/A (open source) | [EP-008](#exit-plan-references) |
| 9 | Mend (formerly WhiteSource) | Renovate (OSS) | Dependency metadata (package names, versions) | GitHub (via GitHub App integration) | Covered by GitHub DPA | Operates within GitHub environment; covered under [GitHub DPA](https://github.com/customer-terms/github-data-protection-agreement) | Low | Low | N/A (open source, GitHub App) | [EP-009](#exit-plan-references) |
| 10 | Truffle Security | TruffleHog (OSS) | Secret scan results (local only) | N/A (client-side only) | NOT_REQUIRED | N/A - All processing local; no data exfiltration | Low | Medium | N/A (open source) | [EP-010](#exit-plan-references) |

---

## Data Retention Policy

Retention periods for personal data and evidence processed through the pipeline
(RODO/GDPR Art.5.1.e — storage limitation; DORA Art.28 — processor oversight). These
values are read by `check-dpa.sh`; they are the single source of truth for the
`retention_policy` block of `dpa-compliance-check.json`.

| Setting | Value | Notes |
|---------|-------|-------|
| Evidence pack retention (days) | 1825 | 5-year WORM-immutable archive in Azure Blob Storage |
| Log retention (days) | 90 | Build/runtime logs in GitHub + Azure |
| Deletion schedule | Automated via Azure lifecycle management policy | Tier-to-cool then delete after retention window |

---

## Exit Plan References

| Ref | Vendor | Exit Plan Document | Status |
|-----|--------|--------------------|--------|
| EP-001 | GitHub (Microsoft) | [vendor-exit-plans.md](vendor-exit-plans.md) — EP-001 (GitHub -> GitLab/Gitea) | Documented (tabletop-tested 2026-06-15) |
| EP-002 | Microsoft Azure | [vendor-exit-plans.md](vendor-exit-plans.md) — EP-002 (Azure -> AWS/GCP/self-hosted) | Documented (tabletop-tested 2026-06-15) |
| EP-003 | Sigstore | Replace with self-hosted signing infrastructure (e.g., Notation + self-managed CA) | Documented |
| EP-004 | OWASP ZAP | Replace with alternative DAST tool (e.g., Nuclei, Burp Suite CI) | Low priority |
| EP-005 | Trivy | Replace with Grype (Anchore) or Snyk CLI | Low priority |
| EP-006 | Checkov | Replace with tfsec, KICS, or Terrascan | Low priority |
| EP-007 | Syft | Replace with Trivy SBOM or CycloneDX CLI | Low priority |
| EP-008 | MegaLinter | Replace with individual linters configured directly | Low priority |
| EP-009 | Renovate | Replace with Dependabot (native GitHub) or manual updates | Low priority |
| EP-010 | TruffleHog | Replace with Gitleaks or GitHub secret scanning | Low priority |

---

## Data Flow Summary

```
Developer Workstation
    |
    v
GitHub (Microsoft) -----> [Source code, PRs, Actions workflows]
    |
    +--> GitHub Actions Runner (ephemeral)
    |       |
    |       +--> MegaLinter (local)        --> Linting results (local artifact)
    |       +--> TruffleHog (local)        --> Secret scan results (local artifact)
    |       +--> Checkov (local)           --> IaC scan results (local artifact)
    |       +--> Trivy (local)             --> Vulnerability scan (local artifact)
    |       +--> Syft (local)              --> SBOM (local artifact)
    |       +--> OWASP ZAP (local)         --> DAST results (local artifact)
    |       +--> Sigstore (external)       --> Signature + transparency log entry
    |       +--> Renovate (GitHub App)     --> Dependency update PRs
    |
    v
Microsoft Azure
    +--> ACR                               --> Container images
    +--> Container Apps                    --> Running application
    +--> Key Vault                         --> Secrets (encrypted)
    +--> Blob Storage                      --> Evidence packs
```

---

## Review History

| Date | Reviewer | Changes |
|------|----------|---------|
| 2026-03-15 | Initial creation | Full vendor inventory established with 10 vendors/tools |
| 2026-06-16 | Szymon (pending countersign) | Quarterly re-review: all 10 vendor rows re-verified against the live pipeline (workflows, infra/, renovate.json); every vendor/tool, DPA status, data location, and retention value confirmed still accurate. No changes to inventory. Freshness date refreshed. |

---

## Compliance Mapping

| Requirement | Standard | How Addressed |
|------------|----------|---------------|
| Register of ICT third-party providers | DORA Art.28(3) | This vendor risk register |
| Proportionate risk assessment | DORA Art.28(1) | Risk rating and criticality columns |
| Supply chain security measures | NIS2 Art.21.2(d) | Vendor inventory with data flow analysis |
| Supplier relationship security policy | ISO 27001 A.5.19 | This register + due diligence checklist |
| Supplier service delivery management | ISO 27001 A.5.22 | Contract controls + review cadence |
| ICT supply chain security | ISO 27001 A.5.21 | Data flow summary + local-only verification |
| Risk mitigation | SOC 2 CC9.2 | Risk ratings + exit plans |
