# CyberForge Pipeline — Operationalization Task List (PROMPT v5)

> **Purpose:** the execution-ready backlog that takes the CyberForge DevSecOps pipeline from "demo-grade with checkable overclaims" to **fully working and fully operational** — every gate fail-closed, every compliance row content-evaluated, the integrity chain end-to-end, governance plumbing real, and a verifiable sample Evidence Pack generatable.
> **Honesty is the spec:** every task moves a claim toward being TRUE, never toward better marketing of an untrue claim. Each existing overclaim is its own task.

**Ground truth** (read before executing any task): [blueprint/00-SUMMARY.md](../../blueprint/00-SUMMARY.md) · [evidence-pack-specification.md](../../evidence-pack-specification.md) · [CyberForge-Evidence-Pack-struktura.md](../../CyberForge-Evidence-Pack-struktura.md)

**Scope:** 119 tasks, T-01..T-125 (gaps in numbering are intentional — stream ID ranges). Milestones: **M0** Fix-the-lies & critical bugs · **M1** Real gates & matrix · **M2** Compliance-as-code & integrity · **M3** Governance plumbing & self-tests · **M4** Sample Evidence Pack & docs. Counts: M0=25, M1=17, M2=39, M3=25, M4=13. Priorities: P0=43, P1=58, P2=18.

---

## 1. Executive map

### Maturity (current → target)

| Dimension | Current | Target | Note |
|---|---|---|---|
| SAST gate (CodeQL) | L2 | L4 | Advisory-only: `upload:false` (build-and-scan.yml:201), `continue-on-error` (:206), no threshold gate. T-01. |
| Container/dependency scan (Trivy) | L4 | L4 | Genuinely blocking (fs+image `--exit-code 1` under pipefail). Harden: surface CVE count + justified `.trivyignore`. T-02. |
| IaC scan (Checkov) | L3 | L4 | Blocks via pipefail but 19 checks skipped with no justification/expiry. T-04/T-76. |
| DAST (ZAP) | L4 | L4 | Hard-fails on riskcode≥3 but parses only site[0]; target_url interpolated into JS. T-07. |
| Secrets (TruffleHog) | L4 | L4 | Blocks via `--only-verified` + proper PR diff. PII companion is fail-open on scanner error. T-06. |
| Lint (MegaLinter) | L1 | L3 | Never gates — summary-only (security-gate.yml:220). Gate or relabel. T-05. |
| Coverage gate | L4 | L4 | Hard-fails <80%. Harden: expose `coverage_pct` output; remove stale junit. T-63/T-84. |
| Deploy admission (cosign verify) | L3 | L4 | Blocking but identity regexp prefix-matches whole repo — any workflow's signature passes. T-08/T-69. |
| Policy-as-code (OPA) | L1 | L4 | 3 policies tested (10 cases) but wired into **0** workflows. T-09/T-60/T-61/T-62/T-64/T-80. |
| Compliance matrix (content) | L1 | L4 | 100% file-presence; 0/21 rows read content; `{}` PASSes DORA 16.1.a. T-12..T-17. |
| Compliance-as-code validators A.1–A.10 | L1 | L3 | Absent (only retention.rego logic exists, unwired). T-20..T-29. |
| Evidence-completeness gating | L1 | L4 | Warn-only — FAIL/MISSING packs seal to 5-yr WORM. T-11/T-42/T-61. |
| Organizational-control validation | L1 | L5 | File-presence only; no RoI/DPA/RoPA/restore content checks. T-20..T-30. |
| Compliance gate (signed verdict) | L1 | L4 | No aggregating signed PASS/FAIL gate. T-19/T-30/T-73. |
| Evidence-reader honesty (static emitters) | L1 | L4 | check-dpa.sh + generate-data-flow.sh are heredocs. T-21/T-31. |
| Tool-version provenance | L2 | L4 | 8 versions hardcoded in generate-pipeline-run.sh. T-18/T-32/T-72. |
| Crypto posture (A.9) | L2 | L4 | TLS1_2 set but never asserted vs threshold. T-28. |
| Restore test (A.10) | L1 | L4 | bcdr-plan "Not yet conducted" — a genuine FAIL to surface. T-29. |
| Merkle-root signing | L1 | L4 | `merkle-root.cosign.bundle` NEVER produced (ordering bug). T-40/T-41. |
| SBOM + provenance signing / Rekor | L2 | L4 | Fallback provenance corruptible; wrong builder.id; Rekor not independently verified. T-49/T-50/T-51. |
| SLSA level honesty | L2 | L4 | Doc layer honest (L2) but workflow says L3 — mixed. T-44/T-45/T-95/T-98. |
| WORM immutability (locked) | L2 | L4 | Policy created UNLOCKED while report says "immutable". T-46/T-47/T-104. |
| Qualified timestamping (eIDAS QTS) | L1 | L3 | Only freetsa.org (non-qualified). T-53/T-54/T-110. |
| Reproducibility | L1 | L3 | No reproducibility statement / rebuild procedure. T-55. |
| Supply-chain self-defence (Scorecard + pinning) | L3 | L5 | 64/64 SHA-pinned but no Scorecard, no pin-audit guard. T-70/T-71/T-72. |
| Source-control governance | L2 | L4 | branch-protection.json exists but team missing, Renovate uninstalled, 0 PRs. T-65/T-66/T-67/T-68. |
| Pipeline self-test (opa test / unit) | L1 | L4 | opa test runs in 0 workflows; no bats/pytest. T-64/T-80/T-81/T-82/T-83. |
| E2E proof on push AND PR | L1 | L3 | PR path skips sign/deploy/dast; nested repo has 1 commit. T-85/T-86/T-124. |
| Sample/demo Evidence Pack | L1 | L3 | No sample pack exists. T-90/T-91/T-92/T-93/T-94. |
| Snapshot scan-results credibility | L2 | L4 | score:-1 sentinel leaks to JSON; Snapshot unversioned. T-87/T-88. |
| Claims vs behavior | L2 | L4 | SLSA L3, SIEM rows, README crypto ahead of fixes. T-95..T-101. |
| Crosswalk + gap register | L1 | L3 | Presence-only, single-framework; no gap register. T-102/T-103. |
| IaC WORM/network hardening | L2 | L4 | Unlocked WORM; lifecycle delete footgun; all endpoints public. T-104/T-105/T-106. |
| Poland specifics | L1 | L3 | No residency/language/retention-minima/QTS content. T-107..T-110. |
| Demo app robustness | L2 | L4 | Unbounded store; no body/rate limit; parallel-unsafe tests. T-111..T-114. |
| Threat model / VEX / CSPM / runtime (Part C) | L1 | L3+ | No threat-model, VEX, CSPM, or runtime-hardening artifact. T-115..T-118. |
| Scope determination / risk-acceptance / SoA | L1 | L3 | Scope prose-only; exception register unread; SoA unscored. T-119..T-122. |

### Overall spec satisfaction

Synthesized from per-area %: Gates & Matrix **28%** · Compliance-as-code + gate **8%** · Integrity chain **38%** · OPA + Governance + Supply-chain **35%** · Self-test + demo pack **22%** · Claims/IaC/Poland/App **32%**. **Unweighted overall ≈ 27% of `evidence-pack-specification.md` satisfied.** The lowest area (compliance-as-code, 8%) is the single biggest differentiator gap and the largest milestone (M2, 39 tasks).

### Top 5 blockers to operational

1. **Compliance matrix is 100% file-presence (K1)** — a `{}` security-report.json PASSes DORA 16.1.a; the single fact a technical buyer finds fastest. Unblocked by **T-12** (then T-13..T-17).
2. **CodeQL advisory-only while docs claim fail-closed SAST (K7)** — a 60-second falsifiable overclaim. **T-01** is the credibility unlock.
3. **3 OPA policies tested but wired into 0 workflows (K4)** — spec calls audit-only policies an auditor-rejection trigger. **T-60/T-61/T-62**, blocked on **T-63** (real workflow outputs) so inputs aren't hardcoded.
4. **Merkle-root cosign bundle NEVER produced (§6.2-A HIGH)** — the pack's single headline cryptographic claim is absent from every sealed pack. **T-40** (centerpiece), guarded by **T-41**.
5. **Evidence-completeness warn-only (§6.4-C)** — FAIL/MISSING packs seal to 5-year WORM. **T-11/T-42/T-61**.

### Shortest path to a demonstrable sample Evidence Pack

The sample pack's integrity proof only verifies after the fix-the-lies M0 items land. Minimum ordered chain (IDs in order):

**T-40** (Merkle-cosign fix) → **T-44** (SLSA L3→L2 relabel) → **T-87** (Snapshot score:-1 fix) → **T-88** (version Snapshot) → **T-12 → T-13** (content matrix so the control-matrix component is real) → **T-85** (define PR-mode E2E) → **T-86** (prove a green run) → **T-90** (sanitized demo repo + run) → **T-91** (assemble 8 components, `verify-evidence-pack.sh` exits 0) → **T-93** (sanitize/redact) → **T-94** (one-command reproducer).

The formal longest dependency chain to the pack (T-91) is `T-88 → T-81 → T-83 → T-86 → T-90 → T-91` (6 hops); the **fastest credible** path treats the full bats/pytest coverage (T-81/T-82/T-83) as parallelizable and gates T-90 on a green PR run via the lighter T-85 PR-mode.

---

## 2. Coverage / gap table

| Requirement | Current state | Gap | Task IDs |
|---|---|---|---|
| SAST gate must block on critical findings | CodeQL advisory: upload:false (:201), continue-on-error (:206), no threshold | Findings never fail build; 'fail-closed SAST' overclaim (K7) | T-01 |
| Policy gate must enforce, not audit-only | 3 OPA policies tested, invoked by 0 workflows (K4) | deployment-gate/retention/evidence-completeness rego never executed | T-09,T-10,T-11 |
| Compliance matrix must evaluate CONTENT | generate-compliance-matrix.sh:7-19 file-presence only; 0/21 read content | {} and 500-CRITICAL both PASS (K1) | T-12,T-13,T-14,T-15,T-16,T-17 |
| Evidence-completeness must block incomplete packs | evidence-pack.yml:210-234 warn-only | FAIL/MISSING controls still seal to 5-year WORM | T-11 |
| Deploy admission must verify tight signer identity | deploy.yml:62 broad regexp github.com/${repo}/ | Any workflow's signature passes (K7 HIGH) | T-08 |
| IaC gate skips must be justified + expiring | 19 Checkov skips (security-gate.yml:108), no justification | Silent broad skip indistinguishable from policy decision | T-04 |
| Lint gate must block or be honestly relabeled | MegaLinter summary-only (:220), no exit 1 | Lint failures never gate; implied as a gate | T-05 |
| Scanners must fail-closed on internal error | PII grep `|| false` treats grep exit>=2 as no-match | Scanner malfunction reads as clean pass (§6.6-B) | T-06 |
| DAST gate must count all sites + injection-safe | dast.yml parses only site[0]; target_url into JS | Multi-site under-count; expression-injection surface | T-07 |
| SBOM + provenance rows must verify schema + attestation | dependency-review.json = cp; no verify-attestation in matrix | Supply-chain rows are renamed files, never checked | T-15 |
| Workflow outputs must carry gate values for OPA/matrix | build-and-scan.yml:405-407 exposes only image_uri/digest | No critical_cves/coverage_pct; OPA would hardcode fake inputs | T-03,T-63 |
| Tool versions measured not hardcoded | cosign/syft/opa/codeql versions not recorded | Matrix cannot cite versions that ran | T-18,T-32,T-72 |
| Compliance gate aggregates A.1-A.10 into signed PASS/FAIL | No compliance-validate job; validators do not exist | No aggregated, blocking, signed compliance verdict | T-19,T-30,T-73 |
| Trivy SCA 'updated systems' row asserts real config not cp | dependency-review.json is a cp; row file-presence | Row doesn't assert severity gate + 0 unjustified suppressions | T-14,T-02 |
| A.1 validate-roi: schema+LEI of Register of Information | No RoI YAML/schema/validator; vendor-risk-register is Markdown, no LEI | Author RoI YAML + roi.schema.json + validate-roi | T-20,T-36 |
| A.2 check-dpa: presence+freshness of DPAs | check-dpa.sh static heredoc; never reads register | Rewrite to parse vendor register + assert 92-day freshness | T-21 |
| A.3 validate-ropa: RoPA + DPIA schema | No RoPA/DPIA doc exists anywhere | Author RoPA YAML + ropa.schema.json + validate-ropa | T-22 |
| A.4 check-incident-register: statutory-clock schema | Runbook has clock; nothing validates a register schema | Define incident-register schema + validator | T-23 |
| A.5 assert-retention: threshold vs IaC | retention.rego written but unwired; nothing reads tfplan | tfplan extractor + opa eval + signed retention-policy.json | T-24,T-48,T-62 |
| A.6 check-governance: board approval + training freshness | Docs exist; no validator checks presence/freshness | Parse dates, assert within-cadence freshness | T-25 |
| A.7 check-thirdparty-clauses: tested exit plans | Checklist + register exist; several exit plans 'Planned' | Cross-ref Criticality vs Exit-Plan status, FAIL on template-only | T-26 |
| A.8 check-access-reviews: Next-Due freshness | Schedule has Next Due dates (some PAST); nothing parses | Parse Next Due, FAIL past-due (a real FAIL today) | T-27 |
| A.9 assert-crypto: TLS min-version vs IaC | TLS1_2 set; no check asserts the minimum | Read plan, assert >=TLS1_2 + at-rest + key-mgmt | T-28 |
| A.10 check-restore-test: successful restore in window | bcdr-plan 'Not yet conducted' — genuine FAIL | Define restore-test log + validator; FAIL until conducted | T-29 |
| Compliance gate: signed aggregate, fail on stale evidence | No aggregator; nearest is warn-only file-presence | aggregate-compliance-gate.py + cosign sign-blob + blocking | T-30 |
| Replace generate-data-flow.sh static heredoc | Static heredoc; pii_present hardcoded | Move to data-flow.yaml; schema-validated reader | T-31 |
| Merkle root MUST be cryptographically signed | merkle-root.cosign.bundle NEVER created (ordering bug) | Write merkle-root.txt before Step 3; CI precondition | T-40,T-41 |
| Evidence-completeness MUST be BLOCKING (presence+non-empty) | evidence-pack.yml:213-234 warn-only; downloads continue-on-error | Fail non-PR on missing/empty required artifact | T-42,T-43 |
| SLSA level claim MUST equal reality | evidence-pack.yml:200 says L3; audit doc says L2 | Relabel everything to L2; scope what L3 needs | T-44,T-45,T-95,T-98 |
| WORM/retention MUST be enforced (locked) + claims match | Policy UNLOCKED; report asserts 'immutable WORM' | locked=true behind var; soften wording until locked | T-46,T-47,T-48,T-104,T-105 |
| SBOM+provenance signed, valid JSONL, correct builder.id, Rekor | Fallback folds stderr; wrong builder.id; Rekor unverified | Drop 2>&1; fix builder.id/buildType; add Rekor verify | T-49,T-50,T-51 |
| Qualified eIDAS QTS path | Only freetsa.org non-qualified TSA | Pluggable TSA + documented Polish/EU QTS path + CA chain | T-53,T-54,T-110 |
| Reproducibility statement | No statement; no rebuild-and-match procedure | Reproducibility artifact + rebuild procedure | T-55 |
| 3 OPA policies wired into NAMED blocking steps | Invoked by 0 workflows | Named blocking opa eval steps with REAL inputs | T-60,T-61,T-62,T-63 |
| opa test green in CI on push AND PR | 10/10 pass locally but no workflow runs opa test | policy-test job (opa test + opa fmt) on PR+push | T-64,T-80 |
| CODEOWNERS resolves | Team does not exist; all 5 rules error (K6) | Create team or repoint to real handles; verify via gh api | T-65 |
| Renovate installed + activated | Config valid but App never installed; 0 bot PRs (K9) | Install Renovate; confirm onboarding/Dashboard PR | T-66 |
| Branch protection enforced + verified | JSON + apply script exist; live config unverified | Run apply + verify live config via gh api | T-67 |
| PR-path controls TESTED via crafted blocked PR | 0 PRs ever; commit-signing PR-only, never ran (K9) | 3 crafted PRs each demonstrably blocked | T-68,T-124 |
| OpenSSF Scorecard (Pinned-Deps + Dangerous-Workflow PASS) | No scorecard workflow exists | scorecard-action workflow + assert both checks PASS | T-70 |
| Digest-pin every action + tool; keep 100% | 64/64 pinned but no CI guard prevents regression | pin-audit CI step fails on any non-SHA; tool inventory | T-71,T-72 |
| deploy.yml must not silently fall back to local TF state | deploy.yml:97-98 backend=false warn-only fallback | Fail hard non-PR when backend vars unset | T-74 |
| evidence-pdf-test standing id-token job removed | push trigger remains despite 'remove before merge' | Make dispatch-only; delete stale branch | T-59,T-75 |
| Unit tests for validators/scripts with coverage | 0 bats, no pytest for Pipeline scripts | bats + pytest suites with coverage floor | T-81,T-82,T-83 |
| Stale junit removed; counts reflect reality | app/junit.xml committed with tests=0 (K8) | Delete stale junit; assert tests>0 | T-84,T-114 |
| Green E2E on BOTH push AND PR | PR skips sign/deploy/dast; nested repo 1 commit | PR-mode E2E + prove two green runs | T-85,T-86 |
| Generate sanitized sample Evidence Pack (8 components) | No sample pack exists (MISSING/high-priority) | Demo repo + run + assemble 8 components | T-90,T-91,T-92,T-93,T-94 |
| Sample-pack integrity proof actually verifies | Merkle cosign never produced; SLSA L3 mislabel | Gate on Merkle fix + relabel; verify exits 0 | T-91,T-40,T-44 |
| Fix Snapshot score:-1 leaking + regression test | engine.py:82 score=-1 leaks to JSON | Optional[int]=None; emit null; regression test | T-87 |
| Snapshot scanner under version control | git-ignored (.gitignore:34); duplicate dir | Un-ignore/init Snapshot; delete duplicate Codex | T-88 |
| Sample pack proves enforcement (gate blocks bad PR) | No recorded 'gate blocks bad PR' artifact | Capture deterministic failing run | T-89 |
| Founder-independent reproducible demo | No demo script/walkthrough; single-human dependency | make demo-pack + 1-page walkthrough | T-94 |
| Every checkable overclaim removed | SLSA L3; SIEM/Sentinel rows; K8s/ARC claim | Correct to L2 / remove / re-scope Phase F | T-95,T-96,T-97,T-98,T-99 |
| README/SETUP claims match behavior (RFC-3161/Merkle) | README asserts signed RFC-3161 + cosign Merkle root | Condition wording until integrity fix lands | T-100,T-101 |
| Auto-generated multi-framework crosswalk + gap register | Crosswalk presence-only single-framework; no gap register | Content-derived crosswalk + gap register | T-102,T-103 |
| IaC true immutability + storage hardening | WORM unlocked; lifecycle footgun; endpoints public | Lockable WORM; fix lifecycle; network-hardened variant | T-104,T-105,T-106 |
| Poland-specifics baked into the pack | No residency/language/retention/QTS content | Poland appendix + retention table + QTS + residency | T-107,T-108,T-109,T-110 |
| Demo/pack-credible app | Unbounded Map; no body/rate limit; stale junit | Bounded store + limits + isolated tests + remove junit | T-111,T-112,T-113,T-114 |
| Threat model (Part C.1) | No file, no task previously | Versioned signed STRIDE threat-model + validator | T-115 |
| VEX (Part C.11) | Glossary-only; §8 anti-pattern 'no VEX' | Per-release OpenVEX bound to SBOM + signed | T-116 |
| CSPM/cloud posture (Part C.14) | 'design-stage' prose only | CIS-mapped scan OR honest relabel | T-117 |
| Runtime hardening (Part C.15) | No coverage | Least-privilege runtime posture statement | T-118 |
| Source-control export as evidence (Part C.2) | export script exists but UNWIRED | Wire export + drift validator + 'live' provenance | T-119 |
| Scope/applicability determination (Part B / 0.4) | Prose-only; §8 anti-pattern #10 | Machine-validated signed applicability.yaml | T-120 |
| Risk-acceptance validation + residual-risk (J.2/D.4) | Register exists but unread; §8 anti-pattern #5 | Validate approver+expiry; emit residual-risk | T-121 |
| SoA + SAMM maturity (D.3/§9) | SoA file exists but unscored; guards L5 claim | Score §9 dimensions from real evidence | T-122 |
| RFC-3161 verify-side ordering parity (§6.4 gap 2) | No self-test for .tsr ordering parity | Self-test asserting Merkle .tsr verifiable | T-123 |
| PR-path latent-bug audit (§6.4 gap 1) | PR-conditional branches run 0 times | Enumerate + exercise + fix PR-only branches | T-124 |
| SARIF 2.1.0 conformance (§4) | No SARIF schema validation | Assert version==2.1.0 + schema per stage | T-125 |

---

## 4. Task list (grouped by milestone, P0 → P1 → P2)

## M0 — Fix-the-lies & critical bugs  (25 tasks)

#### T-01 — Make CodeQL a blocking SAST gate on high-severity findings (or honestly relabel advisory)
- **Area:** Gates | **Priority:** P0 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** Docs/READMEs imply a fail-closed SAST gate, but CodeQL is advisory-only and findings never fail the build. This is a 60-second falsifiable overclaim a technical buyer will find (K7; blueprint/04 §8; blueprint/06 §6.3.0). Spec §4 lists 'criticals waved through silently' as an auditor rejection trigger (evidence-pack-specification.md:189).
- **Current state:** VERIFIED advisory: `analyze` runs `upload: false` (build-and-scan.yml:201); the separate SARIF upload is `continue-on-error: true` (build-and-scan.yml:206); NO exit-code/security-severity threshold exists anywhere in the codeql job (lines 166-295) — the summary step only counts findings.
- **Definition of Done:** A step after `analyze` parses `codeql-results/javascript.sarif`, counts results with `level == "error"` OR `security-severity >= 7.0`, and `exit 1` when count > 0; a justified, expiring suppression file (mirroring the .trivyignore policy) is honored. (Fallback branch if Szymon rejects blocking: relabel every CodeQL mention in README/SETUP/matrix/compliance-matrix.sh to 'SAST evidence (advisory)' and tier it EVIDENCE-ONLY.)
- **Implementation notes:** In `Pipeline/.github/workflows/build-and-scan.yml`, add after the analyze step:\n```python\nimport json,sys\nsarif=json.load(open('codeql-results/javascript.sarif'))\nsupp={l.strip() for l in open('app/.codeqlignore')} if __import__('os').path.exists('app/.codeqlignore') else set()\nerrs=[r for run in sarif['runs'] for r in run.get('results',[]) if (r.get('level')=='error' or float(r.get('properties',{}).get('security-severity',0))>=7.0) and r.get('ruleId') not in supp]\nif errs: print(f'::error::CodeQL {len(errs)} high-severity findings'); sys.exit(1)\n```\nKeep `upload-sarif` for code-scanning UI but the gate must not depend on it. Spec: blueprint/04 §8 Option A; spec §4 SAST row.
- **Acceptance criteria:**
  - A deliberately-introduced injection (e.g. `eval(req.query.x)`) in app/src makes the codeql job exit non-zero.
  - `app/.codeqlignore` entries require an inline justification + expiry; expired entries are ignored (still gate).
  - README/SETUP no longer claim a SAST gate without it actually blocking.
- **Verification:** `act -j codeql` (or push a branch with a seeded high-severity finding) and confirm the job concludes failure; `grep -rn 'upload: false' Pipeline/.github/workflows/build-and-scan.yml` and confirm a threshold step follows.
- **Dependencies:** none
- **Maps to:** blueprint/04 §8; blueprint/06 §6.3.0 K7; spec §4 SAST; spec Part C.4

#### T-08 — Tighten cosign verify identity at the deploy admission gate to the release workflow ref
- **Area:** Gates | **Priority:** P0 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** The deploy admission gate verifies a signature but with a broad identity regexp that prefix-matches ANY workflow in the repo, so a signature minted by an unrelated workflow would pass admission — a real audit HIGH (K7; blueprint/04 §3.4; blueprint/06 §6.2 deploy.yml).
- **Current state:** VERIFIED `cosign verify --certificate-identity-regexp="https://github.com/${{ github.repository }}/" --certificate-oidc-issuer="https://token.actions.githubusercontent.com"` against `image_uri@image_digest` (deploy.yml:61-64). The trailing `/` after repo matches every workflow path. The companion verify in sign-and-attest.yml shares the loose pattern.
- **Definition of Done:** The regexp is tightened to the signing workflow ref, e.g. `https://github.com/${REPO}/.github/workflows/sign-and-attest.yml@refs/heads/main` (and tags as appropriate); verification still runs under `set -o pipefail` against the DIGEST (not the tag); a signature from any other workflow fails admission.
- **Implementation notes:** Update `Pipeline/.github/workflows/deploy.yml:62` and the matching line in `sign-and-attest.yml` to the precise identity. Confirm the actual `certificate-identity` cosign emits for the signer by inspecting an existing signature (cosign verify ... --output json). Keep it parameterizable for tag releases. Spec: blueprint/04 §3.4; blueprint/06 §6.2 (deploy); spec §4 Provenance/signing.
- **Acceptance criteria:**
  - cosign verify still passes for a legitimately sign-and-attest-signed image.
  - A signature whose certificate identity is a different workflow path fails admission.
- **Verification:** `cosign verify --certificate-identity-regexp '.../sign-and-attest.yml@refs/heads/main' --certificate-oidc-issuer https://token.actions.githubusercontent.com <image>@<digest>` exits 0 for the real image; document the negative test.
- **Dependencies:** none
- **Maps to:** blueprint/04 §3.4; blueprint/06 §6.2 + K7; spec §4 signing; spec Part C.12

#### T-21 — A.2 check-dpa — replace static heredoc with vendor-register reader + freshness (RODO Art.28)
- **Area:** compliance-as-code | **Priority:** P0 | **Milestone:** M0 | **Effort:** M | **Owner:** Szymon
- **Context:** check-dpa.sh is the canonical 'fix-the-lies' item: it prints a hardcoded heredoc with `"dpa_status":"ACTIVE"` per vendor (check-dpa.sh:5-91) yet a real, maintained vendor register exists (vendor-risk-register.md:44-54). A technical buyer who opens this script loses trust in 60 seconds (blueprint/04:16,49). struktura §6 A.2 = presence+freshness → dpa-coverage.json (RODO Art.28 [HARD]).
- **Current state:** VERIFIED check-dpa.sh:5-91 is a static heredoc; references vendor-risk-register.md at :9 but never reads it. The register carries `Last Reviewed: 2026-03-15` (:4) and `Review Cadence: Quarterly` (:5).
- **Definition of Done:** check-dpa.sh (or check-dpa.py) parses the `## Vendor Inventory` GFM table into per-vendor DPA records (values from the file, not hardcoded) AND asserts register freshness: FAIL if `today - Last Reviewed > 92 days`. Emits `dpa-coverage.json` via T-33 envelope: per-vendor statuses EVIDENCE-ONLY (contract facts not pipeline-verifiable), freshness BLOCKING.
- **Implementation notes:** Use T-33 `gfm_table('docs/governance/vendor-risk-register.md','Vendor Inventory')`; parse `Last Reviewed:` via regex; `status = 'PASS' if days_since(last_reviewed) <= 92 else 'FAIL'`. Keep the same output filename `dpa-compliance-check.json` so the evidence-pack.yml:175 call site is unchanged. Honest framing: pipeline verifies the register is OPERATED (freshness), not that a DPA is legally valid (blueprint/04:253).
- **Acceptance criteria:**
  - Output JSON values for ≥1 vendor differ when the register row is edited (proves it reads the file)
  - A register with `Last Reviewed` >92 days old yields FAIL with the day count in `detail`
  - No hardcoded vendor list remains in the script
- **Verification:** `bash scripts/check-dpa.sh > /tmp/dpa.json && jq '.processors|length, .status' /tmp/dpa.json`
- **Dependencies:** T-33
- **Maps to:** struktura §6 A.2; blueprint/04 §5.1; bug G3 (hardcoded heredoc); GTM-RESET quick-fix #4

#### T-40 — Fix the Merkle-root cosign-signing ordering bug (write merkle-root.txt before Step 3)
- **Area:** Integrity chain | **Priority:** P0 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** The pack's single headline cryptographic claim — keyless identity attribution over the artifact-committing Merkle root — is absent from EVERY sealed pack. `seal-evidence.sh` signs `evidence/merkle-root.txt` in Step 3a but that file is created for the first time in Step 4, so the `-f` guard short-circuits and the signature is never produced. This is blueprint §6.2-A [HIGH], called 'the single most dangerous bug for sales credibility because the pack is sold as the proof'.
- **Current state:** VERIFIED. `seal-evidence.sh:308-309` guards `if [ -f "${EVIDENCE_DIR}/merkle-root.txt" ] && cosign_sign_retry …`; `merkle-root.txt` is written for the first time at `seal-evidence.sh:383-384` (Step 4, RFC-3161). At Step 3 the test is false, the else branch (`:312-316`) sets `merkle_status=failed`/`COSIGN_OK=0`, and `merkle-root.cosign.bundle` is never created; soft-degrade (`:333-344`) exits 0. The header comment (`:267`) wrongly claims the file was 'written once above'.
- **Definition of Done:** `merkle-root.cosign.bundle` is produced on every successful seal; `manifest.signatures.cosign.merkle_status == signed`; the duplicate write is removed; comment corrected.
- **Implementation notes:** In `Pipeline/scripts/seal-evidence.sh`, immediately after line 229 (`MERKLE_ROOT="$(get_field merkle_root || true)"`) add: `if [ -n "${MERKLE_ROOT}" ]; then printf '%s\n' "${MERKLE_ROOT}" > "${EVIDENCE_DIR}/merkle-root.txt"; fi`. Delete the duplicate write at `:383-384` but keep the `rfc3161_stamp "merkle-root" "${MR_FILE}"` call, repointing `MR_FILE="${EVIDENCE_DIR}/merkle-root.txt"` to the now-existing file. Fix the stale comment at `:263-269` to state the file is written before Step 3. Spec §7.1, Part I.2; blueprint §6.2-A exact-fix.
- **Acceptance criteria:**
  - After a local seal run, `evidence/merkle-root.cosign.bundle` exists and is non-empty.
  - `python3 scripts/_manifest_sig_helper.py evidence/manifest.json get signatures.cosign.merkle_status` prints `signed`.
  - RFC-3161 merkle-root.tsr still produced (no regression in Step 4).
- **Verification:** `EVIDENCE_ALLOW_DEGRADE= bash Pipeline/scripts/seal-evidence.sh evidence evidence/evidence-report.pdf evidence/manifest.json && test -s evidence/merkle-root.cosign.bundle && echo MERKLE_SIGNED_OK`
- **Dependencies:** none
- **Maps to:** blueprint §6.2-A (HIGH); spec §7.1, Part I.2; bug §6.2-A / K-headline

#### T-41 — Add CI hard precondition that merkle-root.cosign.bundle exists after sealing (anti-regression)
- **Area:** Integrity chain | **Priority:** P0 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** §6.2-A could recur silently because cosign failure soft-degrades (exits 0). The blueprint's exact-fix explicitly requires 'a hard precondition in CI (non-degrade mode) that merkle-root.cosign.bundle exists after Step 3, so this regression cannot recur silently'. Without it the centerpiece claim can break again undetected.
- **Current state:** VERIFIED. No check asserts the Merkle bundle exists. `seal-evidence.sh:333-344` records `cosign_status=failed-soft` and exits 0 even when both cosign signs fail. `verify-evidence-pack.sh:195-221` does not emit any line for a missing Merkle bundle when the PDF bundle exists (`COSIGN_CHECKED=1`).
- **Definition of Done:** In non-degrade mode, a missing/empty `merkle-root.cosign.bundle` after sealing FAILS the job; verify runbook emits an explicit PASS/FAIL line for the Merkle bundle.
- **Implementation notes:** In `Pipeline/scripts/seal-evidence.sh` after Step 3, add a non-degrade guard: `if ! is_degrade && [ ! -s "${MERKLE_BUNDLE}" ]; then die "merkle-root.cosign.bundle missing — Merkle signing failed (fail-closed)"; fi`. In `Pipeline/scripts/verify-evidence-pack.sh`, in the cosign block (~`:195-206`), emit `fail` when `merkle-root.txt` exists but `merkle-root.cosign.bundle` is absent (instead of silently skipping). Add a step in `Pipeline/.github/workflows/evidence-pack.yml` after 'Build audit-grade PDF evidence' asserting `test -s evidence/merkle-root.cosign.bundle` for non-PR.
- **Acceptance criteria:**
  - With `EVIDENCE_ALLOW_DEGRADE` unset and cosign forced to fail, `seal-evidence.sh` exits non-zero.
  - `verify-evidence-pack.sh` prints a `FAIL` line when the Merkle bundle is missing but merkle-root.txt is present.
- **Verification:** `PATH=/nonexistent EVIDENCE_ALLOW_DEGRADE= bash Pipeline/scripts/seal-evidence.sh evidence evidence/evidence-report.pdf evidence/manifest.json; test $? -ne 0 && echo FAILS_CLOSED_OK` (cosign unavailable → must fail in CI mode)
- **Dependencies:** T-40
- **Maps to:** blueprint §6.2-A exact-fix (anti-regression); spec §12 self-tests

#### T-44 — Correct SLSA L3 overclaim to L2 everywhere (README, workflow, HTML report)
- **Area:** Integrity chain | **Priority:** P0 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** Honesty is the spec: the architecture is ~SLSA Build L2 (provenance generation is best-effort, not demonstrably isolated from the build job) but auditor-facing strings claim L3. The audit document already states L2 honestly; the README and workflow README block contradict it. Every overclaim inside a 'honest evidence' deliverable is a credibility risk (blueprint K5, COMPANY-AUDIT §3.3).
- **Current state:** VERIFIED. `evidence-pack.yml:200` labels `cosign-verification.log` as 'NIS2 Art.21.2.h, SLSA L3'. `generate-html-report.sh:273` says 'DORA Art.28, SLSA L2+'. `build-audit-document.py:57-59` correctly says 'SLSA Build L2 achieved — L3 is NOT claimed'. The doc layer is honest; the README/workflow/HTML layer is not, so the claim is inconsistent.
- **Definition of Done:** No string in the repo claims SLSA L3 as achieved; all integrity claims read 'SLSA Build L2' consistently; the honest L2 wording matches build-audit-document.py:57-59.
- **Implementation notes:** Edit `evidence-pack.yml:200` 'SLSA L3' → 'SLSA Build L2'. Edit `generate-html-report.sh:273` 'SLSA L2+' → 'SLSA Build L2' (drop the '+', which reads as 'L2 or better'). Grep the whole tree: `grep -rniE 'slsa.?l3|slsa level 3|slsa-3' Pipeline/`. Update `Pipeline/README.md` integrity section (`:41-42`) if it implies L3. Spec §9 anti-pattern, §8 SLSA L0/L1 contrast.
- **Acceptance criteria:**
  - `grep -rniE 'slsa.?l3|slsa level 3' Pipeline/` returns 0 matches that claim L3 as achieved.
  - README, evidence-pack.yml, generate-html-report.sh, and build-audit-document.py all state 'SLSA Build L2' consistently.
- **Verification:** `grep -rniE 'slsa.?l3|slsa level 3|slsa-3|slsa l2\+' Pipeline/ --include='*.md' --include='*.yml' --include='*.sh' --include='*.py' | grep -vi 'L3 is NOT claimed\|L3 target\|L3 would require'; echo "remaining=$?"`
- **Dependencies:** none
- **Maps to:** blueprint K5, COMPANY-AUDIT §3.3; spec §8/§9

#### T-65 — Make CODEOWNERS resolve (create @CyberForge-Agency/security-team or repoint)
- **Area:** Governance | **Priority:** P0 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** CODEOWNERS is the first governance control a technical buyer checks and it is currently a prop — the referenced team does not exist, so GitHub errors on all 5 rules and no code-owner review is ever actually required (VERIFIED COMPANY-AUDIT:70 'all 5 rules error'; bug K6). This is a fix-the-lies M0 item: branch-protection.json sets `require_code_owner_reviews: true` against a non-resolving owner.
- **Current state:** VERIFIED Pipeline/.github/CODEOWNERS has 5 rules pointing at `@CyberForge-Agency/security-team`; the nested authoritative repo (Pipeline/.git, commit d53cb2e) uses `@cyberforge/security-team` (old casing); the outer working tree has an uncommitted edit changing casing only — neither has been proven to resolve.
- **Definition of Done:** Either the GitHub team `CyberForge-Agency/security-team` exists with >=1 member and write access to the repo, OR CODEOWNERS is repointed to real `@`-user handles; in both cases `gh api repos/<owner>/<repo>/codeowners/errors` returns zero errors.
- **Implementation notes:** Preferred: `gh api -X POST orgs/CyberForge-Agency/teams -f name='security-team'` then add Szymon + grant repo access; alternative for a single-founder repo: replace team refs with `@szymon-handle`. Reconcile the nested-repo vs outer-tree drift so the committed CODEOWNERS matches reality. Commit only when asked.
- **Acceptance criteria:**
  - `gh api repos/<owner>/<repo>/codeowners/errors` returns `{"errors": []}`
  - Opening a PR touching /policies/ requests the resolved owner for review
- **Verification:** `gh api repos/<owner>/<repo>/codeowners/errors --jq '.errors | length'` returns 0
- **Dependencies:** none
- **Maps to:** spec §4 Source control (review records); bug K6; COMPANY-AUDIT §3.3

#### T-69 — Tighten cosign certificate-identity-regexp to the release workflow ref
- **Area:** Supply-chain | **Priority:** P0 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** The deploy admission gate and evidence re-verify accept any signature whose identity starts with `https://github.com/<repo>/`, so a signature produced by ANY workflow on ANY branch in the repo (e.g. a malicious added workflow) passes the gate (VERIFIED bug K7; COMPANY-AUDIT:73 'trusts any workflow on any branch'; blueprint 04 §3.4). This is a fix-the-lies M0 item — the gate claims to prove provenance from the release pipeline.
- **Current state:** VERIFIED broad regexp `https://github.com/${{ github.repository }}/` at deploy.yml:62, sign-and-attest.yml:131, and the summary string sign-and-attest.yml:178.
- **Definition of Done:** All 3 sites pin the identity to the signing workflow ref, e.g. `https://github.com/<repo>/.github/workflows/sign-and-attest.yml@refs/heads/main`, so a non-release workflow's signature cannot verify.
- **Implementation notes:** Replace the regexp with an anchored pattern `--certificate-identity-regexp="^https://github.com/${{ github.repository }}/\.github/workflows/sign-and-attest\.yml@refs/heads/main$"` at deploy.yml:62 and sign-and-attest.yml:131; update the summary at :178 to the same string. Verify against the image DIGEST not the tag (blueprint 04 §3.4). Coordinate with the integrity stream so the merkle/SBOM attestation verify uses the same identity.
- **Acceptance criteria:**
  - No workflow contains the bare `https://github.com/<repo>/` identity regexp
  - A test signature from a different workflow path fails `cosign verify`
  - The release pipeline's own signature still verifies green
- **Verification:** `grep -rn 'certificate-identity-regexp' Pipeline/.github/workflows/` shows only the anchored sign-and-attest.yml ref; a dispatch run's deploy gate still passes for the genuine signature
- **Dependencies:** none
- **Maps to:** blueprint 04 §3.4; spec §8 anti-pattern (provenance); bug K7

#### T-84 — Delete stale app/junit.xml and assert tests>0 in the coverage summary
- **Area:** Pipeline self-test | **Priority:** P0 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** The unit-test Job Summary parses JUnit by globbing `app/test-results/*.xml` PLUS the stale committed `app/junit.xml`, which contains `tests="0" failures="0"` (cat app/junit.xml). On any run where jest-junit's real output is absent or out of order, the summary can report 0 tests as a pass — a checkable overclaim that contradicts the 'battle-tested' story (COMPANY-AUDIT §3.4, deep-dive K8). This is a fix-the-lies item.
- **Current state:** VERIFIED: build-and-scan.yml:359 globs `app/junit.xml`; that file is committed with tests="0" (cat Pipeline/app/junit.xml -> testsuites tests="0").
- **Definition of Done:** The committed stale `app/junit.xml` is removed; the glob no longer includes it; the summary step fails the job if the parsed total test count is 0.
- **Implementation notes:** `git rm Pipeline/app/junit.xml`; add `app/junit.xml` to `app/.gitignore`. Edit build-and-scan.yml:359 to glob only `app/test-results/*.xml`. In the summary Python (build-and-scan.yml:340-393) after parsing, add `if test_count == 0: print('::error::No JUnit test results parsed'); raise SystemExit(1)`. Jest already emits jest-junit to `JEST_JUNIT_OUTPUT_DIR=./test-results` (build-and-scan.yml:320).
- **Acceptance criteria:**
  - `app/junit.xml` no longer tracked (`git ls-files | grep junit` -> empty).
  - Glob at build-and-scan.yml references only `test-results/*.xml`.
  - Summary step exits non-zero when test_count==0.
- **Verification:** `cd Pipeline/app && npm run test:ci && ls test-results/*.xml && grep -c 'tests="[1-9]' test-results/*.xml` (>=1)
- **Dependencies:** none
- **Maps to:** COMPANY-AUDIT §3.4; blueprint 06 K8; GTM-RESET §4

#### T-87 — Fix Snapshot score:-1 sentinel leaking into JSON + add a json_report regression test
- **Area:** Demo deliverable | **Priority:** P0 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** The sample Evidence Pack's scan-results component (and every Readiness Check deliverable) is rendered from the Snapshot scanner, whose JSON emits raw `"score": -1` for unassessed categories — a checkable trust-leak a buyer who opens the JSON reads as a bug (deep-dive §6.6-D, COMPANY-AUDIT §3.6). The MD/HTML templates already guard on `assessed`, but `json_report.py` dumps the model verbatim. This is a fix-the-lies prerequisite for a credible sample pack.
- **Current state:** VERIFIED: Snapshot/src/snapshot/scoring/engine.py:82 sets `score = -1`; models/score.py:13 types `score: int` (no Optional); json_report.py:20 does `model_dump` verbatim; raw -1 present in canonical results JSON (deep-dive §6.6-D, lines 19/40).
- **Definition of Done:** `CategoryScore.score` is `Optional[int]=None`; engine sets `None` for unassessed; JSON emits `null`; a regression test asserts no negative score for any unassessed category; stale `-1/100` artifacts regenerated.
- **Implementation notes:** models/score.py:13 -> `score: Optional[int] = None`. engine.py:82 -> `score = None`. Templates unchanged (key off `assessed`). New test in Snapshot/tests/unit/test_report_generation.py: build a ScanResult with one unassessed category, run JsonReportGenerator, load JSON, assert every category_scores[*].score is None or >=0 (never <0). Apply identically in whichever dir survives T-88. Spec struktura scan-results (X.1/C).
- **Acceptance criteria:**
  - `grep -R '"score": -1' <generated json>` -> 0 hits after a fresh scan.
  - New regression test fails on the old code, passes on the new.
  - Overall weighted score unchanged (still excludes unassessed; engine.py:131-136).
- **Verification:** `cd Snapshot && pytest tests/unit/test_report_generation.py -k negative -q` (PASS) and re-scan produces JSON with `null` not `-1`
- **Dependencies:** none
- **Maps to:** blueprint 06 §6.6-D; blueprint 01 §1.6 A2; spec struktura §X.1

#### T-95 - Remove SLSA L3 overclaim (evidence-pack.yml:200)
- Area: CLAIMS/DOCS | P0 | M0 | S | Szymon
- Context: The pack README written into every Evidence Pack labels cosign-verification.log as SLSA L3; arch is Build L2 not L3. A checkable lie in a doc sold as honest evidence. Source COMPANY-AUDIT 3.3; blueprint/06 K5; GTM-RESET 4.
- Current state: VERIFIED evidence-pack.yml:200 tags the cosign row SLSA L3 (uncommitted +160-line edit did not touch it). build-audit-document.py:58,1602 already enforce an L3-NOT-claimed banner.
- DoD: No SLSA L3 string in any pack artifact; cosign row reads SLSA Build L2.
- Notes: Edit :200 to SLSA Build L2; optionally fix provenance row :198.
- Acceptance: grep SLSA L3 in Pipeline/.github, README, SETUP returns zero.
- Verification: grep -rn SLSA L3 across those paths returns no matches.
- Deps: none
- Maps to: blueprint/06 K5; spec 8 #9; COMPANY-AUDIT 3.3; GTM-RESET 4

#### T-96 - Remove SIEM/Sentinel evidence rows (compliance.md:11,38)
- Area: CLAIMS/DOCS | P0 | M0 | S | Szymon
- Context: A client matrix asserts SIEM/Azure Sentinel logs as delivered evidence, none deployed. Pipeline compliance-matrix.md correctly marks SIEM as Phase F. Source COMPANY-AUDIT 3.4; GTM-RESET 4.
- Current state: VERIFIED compliance.md:11 cites Azure Sentinel + SIEM alert logs and :38 cites SIEM logs. No Sentinel/SIEM resource in Pipeline/infra/.
- DoD: Both rows drop the SIEM/Sentinel claim or re-scope to Planned Phase F.
- Notes: Edit :11 to pipeline-run.json + SIEM planned Phase F; :38 to cosign-verification.log + SIEM planned Phase F.
- Acceptance: No row presents SIEM/Sentinel logs as current; any ref is planned/Phase F.
- Verification: grep sentinel/siem in compliance.md, every match labelled planned or phase f.
- Deps: none
- Maps to: COMPANY-AUDIT 3.4; GTM-RESET 4; spec 8 #1

#### T-100 - Condition README RFC-3161/Merkle-cosign wording
- Area: CLAIMS/DOCS | P0 | M0 | S | Szymon
- Context: README claims a signed RFC-3161-timestamped pack with cosign sign-blob Merkle root. Integrity stream proves the Merkle root is NEVER cosign-signed (merkle-root.cosign.bundle never created; merkle-root.txt written after the cosign step) and RFC-3161 is best-effort, no qualified eIDAS QTS. Source blueprint/06 6.2-A; spec 7.2-7.3.
- Current state: VERIFIED README.md:32-33 and :45-46 assert signed RFC-3161 + cosign sign-blob Merkle root. blueprint/06 6.2-A confirms the bundle is never produced.
- DoD: README true at all times: until T-101 it says Merkle root computed, signing best-effort, no unconditional signed claim; distinguishes RFC-3161 from qualified eIDAS QTS.
- Notes: Soften :32-33 to best-effort wording with QTS-upgrade note (T-110). Restore firm wording once T-101 confirms the bundle.
- Acceptance: No README sentence claims the Merkle root is signed unless the pipeline produces the bundle.
- Verification: grep merkle/rfc-3161/sign-blob in README shows only conditioned wording.
- Deps: T-101
- Maps to: blueprint/06 6.2-A; spec 7.2-7.3; GTM-RESET 4

#### T-06 — Fail-close the PII scanner on grep errors (distinguish exit 1 from exit >=2)
- **Area:** Gates | **Priority:** P1 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** The PII gate uses `grep ... || false`, which treats a real grep error (exit >=2, e.g. bad path) identically to 'no match' (exit 1) — a scanner malfunction reads as a clean pass, the textbook fail-open antipattern (blueprint/06 §6.6-B).
- **Current state:** VERIFIED PESEL/phone checks use `if grep ... || false; then FOUND=1` (security-gate.yml:316,322); the email pipe ends `|| false` under `set -o pipefail` (security-gate.yml:328-330) masking internal errors. grep exit 2 is swallowed.
- **Definition of Done:** Each grep captures `rc=$?` and: rc==0 -> match handling; rc==1 -> no-match (continue); rc>=2 -> `echo '::error::PII grep failed'; exit 1`. The gate fails closed on scanner error.
- **Implementation notes:** In `Pipeline/.github/workflows/security-gate.yml` rewrite the PESEL/phone/email blocks:\n```bash\nset +e; grep -rnE "$PAT" app/src/ app/tests/; rc=$?; set -e\nif [ "$rc" -eq 0 ]; then FOUND=1; elif [ "$rc" -ge 2 ]; then echo '::error::PII grep failed'; exit 1; fi\n```\nKeep email advisory (warning) but still fail on rc>=2. Spec: blueprint/06 §6.6-B; spec §4 secrets/pre-commit stage.
- **Acceptance criteria:**
  - Pointing a grep at a nonexistent dir (rc=2) fails the job, not passes it.
  - A real PESEL in app/src still fails (rc=0 path).
  - No PII present still passes (rc=1 path).
- **Verification:** Temporarily set a bad path and confirm `::error::PII grep failed` + non-zero exit; restore and confirm pass.
- **Dependencies:** none
- **Maps to:** blueprint/06 §6.6-B; spec §4 pre-commit/secrets stage

#### T-31 — Replace generate-data-flow.sh static heredoc with a maintained data-flow YAML reader
- **Area:** compliance-as-code | **Priority:** P1 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** generate-data-flow.sh is the second static-emitter (alongside check-dpa.sh) flagged in blueprint/04:47-49. It prints a fixed JSON data-flow with hardcoded `pii_present` booleans, so the RODO Art.25/30 'data flow' evidence is a script literal, not a maintained record. struktura §6 requires real readers, not static heredocs (FULLY-OPERATIONAL item 7).
- **Current state:** VERIFIED generate-data-flow.sh:4-55 is a static heredoc; consumed at evidence-pack.yml:178-179 into data-flow-diagram.json.
- **Definition of Done:** Content moves to `docs/governance/data-flow.yaml`; generate-data-flow.sh (or .py) reads + schema-validates it (every stage has `pii_present`; if true, a non-empty `pii_justification`); output filename `data-flow-diagram.json` unchanged so the call site is untouched. Tier EVIDENCE-ONLY + BLOCKING-on-schema (blueprint/04 §5.2).
- **Implementation notes:** Reuse T-33 helpers; jsonschema or an inline assertion loop. Keep the existing stages/values so behavior is preserved but now data-driven.
- **Acceptance criteria:**
  - Editing a stage's pii_present in the YAML changes the JSON output (proves it reads the file)
  - A stage with pii_present:true and empty justification makes the script exit non-zero
  - No hardcoded stage list remains in the script
- **Verification:** `bash scripts/generate-data-flow.sh > /tmp/df.json && jq '.stages|length' /tmp/df.json`
- **Dependencies:** T-33
- **Maps to:** struktura §6 (real readers); blueprint/04 §5.2; FULLY-OPERATIONAL item 7

#### T-47 — Soften 'immutable WORM' report wording to match unlocked state until locked
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** Until WORM is locked (T-46), the HTML report's 'immutable WORM archive … Tampering is detectable' is an overclaim — the policy is editable. build-audit-document.py already reads worm_state from the manifest honestly; generate-html-report.sh hardcodes the absolute claim. The wording must match reality (claim==reality) until the lock is applied. Blueprint §6.5-B.
- **Current state:** VERIFIED. `generate-html-report.sh:851` hardcodes 'This pack is part of an immutable WORM archive (Azure Blob, 1825-day retention). SHA256-manifested. Tampering is detectable.' `build-audit-document.py:60-62` honestly says 'Immutability is DESIGNED, not yet locked … read from the manifest worm_state field, never hardcoded.'
- **Definition of Done:** generate-html-report.sh wording reads 'WORM-designed (unlocked)' OR is driven by the manifest worm_state, matching build-audit-document.py's honesty banner.
- **Implementation notes:** Edit `generate-html-report.sh:851` to either (a) read `worm_state` from manifest.json and render 'immutable WORM (LOCKED)' only when locked, else 'WORM-designed (unlocked) — retention enforced by Azure policy', or (b) hardcode the honest 'WORM-designed (unlocked)' until T-46 lands. Prefer (a) so it auto-upgrades after T-46. Blueprint §6.5-B exact-fix.
- **Acceptance criteria:**
  - With an unlocked policy, the report does NOT assert 'immutable WORM … Tampering is detectable' unconditionally.
  - The wording matches build-audit-document.py:60-62.
- **Verification:** `grep -n 'immutable WORM' Pipeline/scripts/generate-html-report.sh | grep -v 'unlocked\|worm_state\|LOCKED'; echo "unconditional_claims=$?"`
- **Dependencies:** none
- **Maps to:** blueprint §6.5-B; spec §9 anti-pattern

#### T-49 — Stop fallback provenance corruption (drop 2>&1) and validate in-toto JSONL
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** The manual SLSA provenance fallback folds stderr INTO the attestation file, so any warning or error text can land verbatim in `provenance.intoto.jsonl`, silently producing a malformed attestation the pack then labels DORA Art.28 / NIS2 Art.21.2.d. Blueprint §6.4-B [MED].
- **Current state:** VERIFIED. `sign-and-attest.yml:97`: `bash scripts/generate-provenance.sh 2>&1 | tee /tmp/provenance-generation-output.txt > provenance-out/provenance.intoto.jsonl`. The `2>&1` merges stderr into stdout before the redirect.
- **Definition of Done:** Only stdout (the JSON) reaches the attestation file; stderr goes to a separate log; the file is validated as line-delimited JSON before upload.
- **Implementation notes:** Edit `sign-and-attest.yml:97` to: `bash scripts/generate-provenance.sh > provenance-out/provenance.intoto.jsonl 2>/tmp/provenance-generation-output.txt`. Add a validation step: `python3 -c 'import json;[json.loads(l) for l in open("provenance-out/provenance.intoto.jsonl") if l.strip()]'`. Blueprint §6.4-B exact-fix.
- **Acceptance criteria:**
  - `provenance.intoto.jsonl` contains only valid JSON line(s) even when the script emits warnings.
  - A JSONL-validity step fails the build if the attestation is malformed.
- **Verification:** `cd Pipeline && IMAGE_URI=demo.azurecr.io/app:v1 IMAGE_DIGEST=sha256:abc bash scripts/generate-provenance.sh > /tmp/p.jsonl 2>/dev/null && python3 -c 'import json;[json.loads(l) for l in open("/tmp/p.jsonl") if l.strip()]' && echo PROVENANCE_JSONL_OK`
- **Dependencies:** none
- **Maps to:** blueprint §6.4-B; spec C.12, §8 (provenance unsigned/malformed anti-pattern)

#### T-59 — Remove the rogue evidence-pdf-test push trigger (standing OIDC signing job)
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** A test workflow retains a `push` trigger its own comment says to delete before merge, making it a standing `id-token: write` job that performs keyless cosign sign-blob against freetsa.org + Sigstore on every push to that branch, and fabricates a synthetic cosign-verification.log with a `Certificate subject: …/sign-and-attest.yml@refs/heads/main` line that could be mistaken for genuine evidence. Blueprint §6.3-G.
- **Current state:** VERIFIED. `Pipeline/.github/workflows/evidence-pdf-test.yml:21-27` comment says 'TEMPORARY: Remove this push trigger before merging' but `push: branches: [feat/evidence-pdf]` is still present; `permissions: id-token: write` (`:31`). Blueprint confirms branch `feat/evidence-pdf` exists locally and on old-origin.
- **Definition of Done:** The unintended push trigger is removed (workflow runs only on workflow_dispatch / explicit invocation); no synthetic verification log can be mistaken for a real signed pack.
- **Implementation notes:** Edit `evidence-pdf-test.yml:21-27` to remove the `push:` trigger, leaving `workflow_dispatch:` only (or gate behind a manual input). Ensure the synthetic cosign-verification.log it generates is clearly labelled as a test fixture (e.g. prefix `TEST-FIXTURE`). Optionally delete the `feat/evidence-pdf` branch. Blueprint §6.3-G exact-fix.
- **Acceptance criteria:**
  - `evidence-pdf-test.yml` has no `push:` trigger.
  - The workflow only runs on manual dispatch.
- **Verification:** `grep -A3 '^on:' Pipeline/.github/workflows/evidence-pdf-test.yml | grep -q 'push' && echo STILL_HAS_PUSH || echo PUSH_TRIGGER_REMOVED_OK`
- **Dependencies:** none
- **Maps to:** blueprint §6.3-G; spec §8 (synthetic-evidence anti-pattern)

#### T-75 — Make evidence-pdf-test.yml dispatch-only (remove standing id-token signing job)
- **Area:** Governance | **Priority:** P1 | **Milestone:** M0 | **Effort:** S | **Owner:** Szymon
- **Context:** evidence-pdf-test.yml keeps a `push` trigger on feat/evidence-pdf that its own comment says to remove before merge, leaving a standing `id-token: write` job that keyless-signs synthetic 'evidence' on every push to that branch — and fabricates a `Certificate subject: .../sign-and-attest.yml@refs/heads/main` line that could be mistaken for real evidence (VERIFIED bug §6.3-G; evidence-pdf-test.yml:25-27, :31). This is a governance/supply-chain hygiene defect (an unintended OIDC signing workload).
- **Current state:** VERIFIED evidence-pdf-test.yml:25-27 `push: branches: [feat/evidence-pdf]` despite the 'remove before merge' comment at :21-24; the branch exists.
- **Definition of Done:** The harness is `workflow_dispatch`-only (the push block removed) OR removed from the default branch entirely; the stale feat/evidence-pdf branch is deleted.
- **Implementation notes:** Delete lines 25-27. If keeping the harness, ensure its synthetic cosign-verification.log is clearly labeled SYNTHETIC so it cannot be confused with a real pack. Delete the branch locally and on the remote.
- **Acceptance criteria:**
  - evidence-pdf-test.yml has no `push:` trigger (dispatch-only) or is deleted
  - The feat/evidence-pdf branch no longer exists on the remote
- **Verification:** `grep -n 'push:' Pipeline/.github/workflows/evidence-pdf-test.yml` returns nothing; `git -C Pipeline branch -a | grep evidence-pdf` returns nothing
- **Dependencies:** none
- **Maps to:** bug §6.3-G; spec §4 (signed-history integrity)

#### T-97 - Correct SIEM/Sentinel overclaims in cicd.md (28, 236)
- Area: CLAIMS/DOCS | P1 | M0 | S | Szymon
- Context: The Polish CI/CD write-up presents log centralisation into Microsoft Sentinel + SIEM alerting as template; SOC2 CC7.1 row cites SIEM alerts - none implemented. Source GTM-RESET 4; COMPANY-AUDIT 3.4.
- Current state: VERIFIED cicd.md:28 (forwarding to a SIEM e.g. Microsoft Sentinel) and :236 (SIEM alerts). No SIEM/Sentinel in Pipeline/infra/.
- DoD: Every SIEM/Sentinel mention re-scoped to future/Phase-F or removed.
- Notes: Reword :28 optional Phase-F; :236 drop or label planned. Keep GitHub Audit Log (real).
- Acceptance: SIEM/Sentinel mentions only future/optional or external citations.
- Verification: grep sentinel/siem in cicd.md, matches only phase f/optional/planned/external.
- Deps: none
- Maps to: GTM-RESET 4; COMPANY-AUDIT 3.4; spec 8 #1

#### T-98 - Fix SLSA Level 3 section title cicd.md:100 to L2
- Area: CLAIMS/DOCS | P1 | M0 | S | Szymon
- Context: The supply-chain section is titled Supply Chain Security - SLSA Level 3. The pipeline reaches Build L2. Source COMPANY-AUDIT 3.3; blueprint/06 K5.
- Current state: VERIFIED cicd.md:100 heading 3.3 titled Supply Chain Security - SLSA Level 3.
- DoD: Title reads SLSA Build L2 or drops the number; aspirational L3 marked target-state.
- Notes: Change heading to SLSA Build L2; prefix L3 features with target.
- Acceptance: cicd.md:100 no longer asserts SLSA Level 3 as current state.
- Verification: grep slsa level 3/slsa l3 in cicd.md, any match target-state labelled.
- Deps: none
- Maps to: COMPANY-AUDIT 3.3; blueprint/06 K5; spec 9

#### T-111 - Bound the demo API store via an injectable capacity-limited store
- Area: APP | P1 | M0 | M | Szymon
- Context: The demo API is public, unauthenticated, backed by an unbounded process-global Map - floodable to OOM mid-demo; also forces parallel-unsafe tests. An injection seam fixes both. Source COMPANY-AUDIT 3.4 K8; blueprint/06 6.7-A + remediation 10.
- Current state: VERIFIED items.ts:10 a module-level Map singleton, no cap; POST :17-32 no size limit; no injection seam.
- DoD: items.ts exposes createItemsRouter(store) with a capacity-limited store (max N, reject/evict beyond cap); the app wires a bounded instance; no module-level singleton as sole store.
- Notes: Per remediation 10 refactor to createItemsRouter(store); BoundedMap max about 1000, return 429/409 or evict-oldest. app.ts injects it.
- Acceptance: Posting beyond cap does not grow memory unbounded; router accepts an injected store.
- Verification: npm test passes; a new test posting beyond cap asserts count never exceeds cap.
- Deps: none
- Maps to: COMPANY-AUDIT 3.4 K8; blueprint/06 6.7-A + remediation 10; spec 8

#### T-114 - Remove the stale committed junit.xml (tests=0)
- Area: APP | P1 | M0 | S | Szymon
- Context: A stale junit.xml reporting tests=0 is committed; if it reaches the evidence glob it falsely advertises zero tests ran, contradicting the 80 percent coverage gate. Source COMPANY-AUDIT 3.4 K8; blueprint/06 K8 + 6.2.
- Current state: VERIFIED Pipeline/app/junit.xml is committed; blueprint/06 line 138 + K8 confirm tests=0.
- DoD: The stale junit.xml removed + gitignored; no evidence glob picks up a committed stale report.
- Notes: git rm Pipeline/app/junit.xml; add junit.xml to Pipeline/app/.gitignore; confirm the workflow generates junit fresh + the glob references the generated path.
- Acceptance: No committed junit.xml with tests=0; junit.xml gitignored; CI produces a fresh report.
- Verification: Pipeline/app/junit.xml absent + junit.xml in .gitignore; npm test regenerates a non-zero report.
- Deps: none
- Maps to: COMPANY-AUDIT 3.4 K8; blueprint/06 K8 / 6.2; spec 8 #1

#### T-99 - Remove K8s/Azure-Pipelines runner claim cicd.md:90
- Area: CLAIMS/DOCS | P2 | M0 | S | Szymon
- Context: The doc asserts ARC for GitHub or Azure Pipelines Agent on Kubernetes (KEDA) as template. The pipeline runs GitHub-hosted runners only; deploy target is Azure Container Apps not K8s. Source GTM-RESET 4; my-area mandate.
- Current state: VERIFIED cicd.md:90 lists ARC for GitHub or Azure Pipelines Agent on Kubernetes (KEDA scalers). No ARC/KEDA manifests exist.
- DoD: Line describes only GitHub-hosted runners or marks ARC/KEDA/Azure-Pipelines as future.
- Notes: Reword to current GitHub-hosted runners; optional ARC/KEDA not deployed in base template.
- Acceptance: No sentence implies current K8s/ARC/KEDA/Azure Pipelines.
- Verification: grep kubernetes/ARC/KEDA/azure pipelines in cicd.md, matches only optional/not-deployed/future.
- Deps: none
- Maps to: GTM-RESET 4; spec 8; my-area mandate

#### T-112 - Add body-size limit + rate limiting to the demo API
- Area: APP | P2 | M0 | S | Szymon
- Context: Even with a bounded store (T-111), the public demo accepts unlimited JSON body size + request rate. A body cap + rate limit makes it survive a hostile prospect live. Source COMPANY-AUDIT 3.4; spec 8; security checklist.
- Current state: VERIFIED app.ts:45 express.json() no limit; no rate-limit middleware (no express-rate-limit import in app/src).
- DoD: express.json with a small limit (about 16kb); a rate-limit middleware on the mutating routes; clean 413/429.
- Notes: express.json limit 16kb; express-rate-limit or a tiny limiter on /api/items. Keep /health + /api/build-info light. Existing name validation items.ts:18-22 stays.
- Acceptance: Oversized body 413; excessive requests 429; /health responsive.
- Verification: npm test passes including new 413 + 429 tests.
- Deps: T-111
- Maps to: COMPANY-AUDIT 3.4; spec 8; security checklist

## M1 — Real gates & matrix  (17 tasks)

#### T-03 — Expose critical_cves and coverage_pct as build-and-scan workflow outputs
- **Area:** Gates | **Priority:** P0 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** OPA deployment-gate wiring (T-09) and the content matrix (T-13) need REAL gate values; without measured outputs they would hardcode `true`/`0`, re-creating the file-presence lie. blueprint/04 §4.1 calls this 'the load-bearing detail'.
- **Current state:** VERIFIED build-and-scan.yml job `docker-build` exposes only `image_uri` and `image_digest` outputs (build-and-scan.yml:405-407). The values exist in artifacts (trivy-*-results.json severity_breakdown; coverage/coverage-summary.json) but are never surfaced as outputs. unit-tests is a separate job and currently emits no outputs.
- **Definition of Done:** The workflow emits `critical_cves`, `high_cves` (from the image scan results) and `coverage_pct` (min of lines/branches/functions/statements) as `workflow_call` outputs, populated from real parsed JSON, consumable by downstream jobs in pipeline.yml.
- **Implementation notes:** In `Pipeline/.github/workflows/build-and-scan.yml`: add `id:` to the Trivy image step's metadata parse, write `echo "critical_cves=$N" >> "$GITHUB_OUTPUT"`; add a step in `unit-tests` writing `coverage_pct` to `$GITHUB_OUTPUT`; promote both job `outputs:` and add to the top-level `outputs:` block (lines 16-22). Update pipeline.yml so deploy/evidence-pack `needs` can read `needs.build-and-scan.outputs.critical_cves`. Spec: blueprint/04 §4.1.
- **Acceptance criteria:**
  - `needs.build-and-scan.outputs.critical_cves` resolves to an integer in a downstream job.
  - `coverage_pct` matches the value used by the existing 80% gate (build-and-scan.yml:323-334).
- **Verification:** Trigger pipeline; in deploy job log echo the three outputs and confirm non-empty integers; `grep -n 'critical_cves\|coverage_pct' Pipeline/.github/workflows/build-and-scan.yml`.
- **Dependencies:** none
- **Maps to:** blueprint/04 §4.1; spec Part C.13 (admission inputs)

#### T-12 — Replace check_file orchestrator with per-row content validators emitting status/measured/threshold/tier
- **Area:** Compliance-matrix | **Priority:** P0 | **Milestone:** M1 | **Effort:** M | **Owner:** Szymon
- **Context:** The entire compliance evaluation is file-presence; a `{}` or 500-CRITICAL security-report.json both yield PASS — the single fact a technical buyer finds in ~60 seconds, falsifying every 'we check DORA/NIS2' claim (K1; blueprint/04 §1.1; GTM-RESET §4). This task builds the orchestrator + envelope that T-13..T-17 plug validators into.
- **Current state:** VERIFIED generate-compliance-matrix.sh:7-9 `check_file` returns PASS iff `[ -f ]`; check_all (:11-19) loops `[ ! -f ]`; all 21 rows (lines 25-55) call one of them; neither opens a file. 0/21 rows read content.
- **Definition of Done:** generate-compliance-matrix.sh remains the orchestrator but each row calls a small single-purpose validator (python) returning the envelope `{status: PASS|FAIL|INDETERMINATE, tier: BLOCKING|EVIDENCE-ONLY|OUT-OF-PIPELINE, measured, threshold, detail, tool_version}`; the matrix JSON carries the measured value. An empty `{}` artifact yields INDETERMINATE, never silent PASS. A `validators/` dir + a dispatch table replace check_file/check_all.
- **Implementation notes:** Create `Pipeline/scripts/validators/` (one module per row group) and a `run_validator()` shell function that invokes `python3 validators/<id>.py evidence/` and embeds its JSON. Keep the 5-framework structure but add `tier` + `measured` to each row. Three-tier labeling per blueprint/04 §2. Spec: blueprint/04 §2-3; spec Parts D.1/D.2; struktura.md:203 (check types).
- **Acceptance criteria:**
  - Every one of the 21 rows includes `tier` and `measured` fields.
  - An empty security-report.json produces INDETERMINATE for its rows, not PASS.
  - The orchestrator exits non-zero if any BLOCKING row is FAIL.
- **Verification:** `bash Pipeline/scripts/generate-compliance-matrix.sh fixtures/empty-evidence/ | jq '.frameworks.DORA[0].status'` returns INDETERMINATE; with good fixtures returns PASS with a measured value.
- **Dependencies:** none
- **Maps to:** blueprint/04 §2-3; blueprint/06 K1; spec Parts D.1/D.2; struktura.md:203

#### T-13 — Content validator: DORA Art.16.1.a + DAST rows (parse JSON, assert 0 CRITICAL / 0 HIGH-CRITICAL)
- **Area:** Compliance-matrix | **Priority:** P0 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** The two highest-visibility rows must read content: DORA Art.16.1.a (ICT risk mgmt) should parse the consolidated scan report and assert 0 CRITICAL; NIS2 21.2.b / ISO A.8.28 (DAST) should parse zap-report.json and assert 0 HIGH/CRITICAL. These are the recorded-number twins of gates that already block (blueprint/04 §3.1, §3.5).
- **Current state:** VERIFIED both rows are file-presence: DORA Art.16.1.a -> `check_file security-report.json` (generate-compliance-matrix.sh:26); NIS2 Art.21.2.b -> `check_file zap-report.json` (generate-compliance-matrix.sh:32). Neither parses CVE/alert counts.
- **Definition of Done:** `validators/dora_16_1_a.py` parses evidence/security-report.json (and embedded Trivy results), counts CRITICAL/HIGH, returns PASS iff CRITICAL==0 and >=1 Result parsed (empty -> INDETERMINATE), tier BLOCKING, measured={critical,high}. `validators/dast_findings.py` counts zap alerts riskcode>=3, PASS iff 0, tier BLOCKING. Both exit non-zero on FAIL so the orchestrator can block.
- **Implementation notes:** Use the sketch in blueprint/04 §3.1 for DORA and the same riskcode>=3 parse the incident-issue uses (dast.yml:147) for DAST; record tool_version from trivy-*-summary.json. Wire into the T-12 dispatch table for both rows (DORA Art.16.1.a, ISO A.8.28, SOC2 PI1.1 share security-report.json; NIS2 Art.21.2.b uses zap). Spec: blueprint/04 §3.1, §3.5; spec Part C.4/C.8.
- **Acceptance criteria:**
  - A security-report.json with 1 CRITICAL makes the DORA row FAIL.
  - An empty `{}` makes it INDETERMINATE.
  - A zap-report with a riskcode-3 alert makes the DAST row FAIL.
- **Verification:** `python3 Pipeline/scripts/validators/dora_16_1_a.py fixtures/crit-evidence/; echo $?` returns 1 and prints status FAIL with measured.critical>=1.
- **Dependencies:** T-12
- **Maps to:** blueprint/04 §3.1 + §3.5; spec Part C.4/C.8; spec D.1

#### T-33 — Shared compliance-validator envelope + libcompliance helper
- **Area:** compliance-as-code | **Priority:** P0 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** Every A.1-A.10 validator must emit a uniform, honest result so the gate (T-30) can aggregate them and the matrix can carry the measured value, not just PASS/MISSING. blueprint/04:85-91 specifies the envelope `{status,tier,measured,threshold,detail,tool_version}`. The design rule (blueprint/04:69) is that a check may emit PASS ONLY if it parsed a value and that value met a stated threshold; everything else is MISSING/INDETERMINATE/EVIDENCE-ONLY, never silent PASS. This task builds the shared helper so all ten validators are consistent and testable.
- **Current state:** VERIFIED no shared envelope exists; generate-compliance-matrix.sh:7-9 emits bare PASS/MISSING from `[ -f file ]` with no measured value or tier.
- **Definition of Done:** `scripts/validators/libcompliance.py` (or .sh) exposes `emit(status, tier, measured, threshold, detail, tool_version)` returning the JSON envelope and setting exit code (0 PASS/EVIDENCE-ONLY, 1 FAIL, 2 INDETERMINATE); a freshness helper `days_since(date_str)` and `gfm_table(md_path, heading)`; unit tests prove envelope shape + freshness math.
- **Implementation notes:** Python (every workflow already calls python3). `scripts/validators/libcompliance.py`: `def emit(status,tier,measured=None,threshold=None,detail="",tool_version=None): print(json.dumps({...})); sys.exit({'PASS':0,'EVIDENCE-ONLY':0,'FAIL':1,'INDETERMINATE':2}[status])`. `gfm_table()` parses a `| a | b |` Markdown table under a `## heading` into list[dict]. Tier enum: BLOCKING|EVIDENCE-ONLY. Maps to struktura §6 check types (presence/schema/freshness/threshold/crypto).
- **Acceptance criteria:**
  - `python3 -c "import scripts.validators.libcompliance as l; print(l.emit('PASS','BLOCKING',1,0,'ok'))"` prints valid JSON and exits 0
  - A FAIL status causes exit 1; INDETERMINATE exits 2
  - `gfm_table()` correctly parses vendor-risk-register.md `## Vendor Inventory` into 10 dicts
- **Verification:** `python3 -m pytest scripts/validators/test_libcompliance.py -q`
- **Dependencies:** none
- **Maps to:** blueprint/04 §2-§3 (envelope); struktura §6 check types

#### T-42 — Make evidence-completeness BLOCKING on required artifacts (presence + non-empty)
- **Area:** Integrity chain | **Priority:** P0 | **Milestone:** M1 | **Effort:** M | **Owner:** Szymon
- **Context:** A green, sealed, 5-year-WORM-archived pack does not imply scanners ran — completeness is warn-only and required inputs download with continue-on-error. Blueprint §6.4-C: 'a pack can be cryptographically sealed and stored for 5 years while internally documenting unsatisfied controls — the seal certifies an incomplete pack.' GTM-RESET §4 fix #2 names 'make evidence-completeness blocking' as a Grade-A item.
- **Current state:** VERIFIED. `evidence-pack.yml:213-234` ('Validate evidence completeness') only prints `::warning::` and never exits non-zero (comment `:210-212` makes this explicit). Inputs download with `continue-on-error: true` (`:53,60,67,74,81,88,95,102`).
- **Definition of Done:** Non-PR runs FAIL when any REQUIRED artifact is absent OR zero-bytes; optional artifacts remain warn-only; failure is honest (lists exactly which artifact failed).
- **Implementation notes:** Replace the warn-only python block at `evidence-pack.yml:213-234` with a check that, for non-PR (`github.event_name != 'pull_request'`), exits 1 if any of `security-report.json`, `sbom.cyclonedx.json`, `provenance.intoto.jsonl`, `cosign-verification.log` is missing or `os.path.getsize(path)==0`. Keep `compliance-matrix` PASS/MISSING warnings for non-required items. Place BEFORE 'Build audit-grade PDF evidence' so an incomplete pack is never sealed. Spec Part J, §8 anti-pattern (presence-not-content).
- **Acceptance criteria:**
  - Removing/zeroing `evidence/sbom.cyclonedx.json` causes the completeness step to exit 1 on a non-PR run.
  - PR runs still pass (degradable) with a warning.
  - Required-artifact list is configurable in one place.
- **Verification:** `cd Pipeline && python3 -c "import os,sys; req=['security-report.json','sbom.cyclonedx.json','provenance.intoto.jsonl','cosign-verification.log']; bad=[f for f in req if not (os.path.isfile('evidence/'+f) and os.path.getsize('evidence/'+f))]; sys.exit(1 if bad else 0)"; echo "exit=$?"`
- **Dependencies:** none
- **Maps to:** blueprint §6.4-C (LOW→raised to P0 per GTM); spec Part J, §8; GTM-RESET §4 fix #2

#### T-63 — Emit critical_cves + coverage_pct as build-and-scan job outputs
- **Area:** OPA | **Priority:** P0 | **Milestone:** M1 | **Effort:** M | **Owner:** Szymon
- **Context:** The deployment-gate OPA wiring (T-60) is only honest if it reads MEASURED values; otherwise inputs get hardcoded `true`/`0`, re-creating the file-presence fake. blueprint 04 §4.1 calls this 'the load-bearing detail'. VERIFIED build-and-scan.yml exposes only image_uri+image_digest, so the real CVE/coverage numbers never leave the job.
- **Current state:** VERIFIED build-and-scan.yml:17-22 (workflow_call outputs) and :405-407 (docker-build job outputs) expose only image_uri + image_digest; coverage is computed at build-and-scan.yml:327 and Trivy summary carries severity counts (blueprint 04 §3.1) but neither is an output.
- **Definition of Done:** build-and-scan.yml exposes `critical_cves` and `coverage_pct` as `workflow_call` outputs sourced from the Trivy image summary JSON and the coverage-summary JSON; pipeline.yml passes them into deploy via `needs.build-and-scan.outputs.*`.
- **Implementation notes:** Add a step `id: metrics` in the relevant jobs that `jq` the critical count from trivy-image-summary and parses the coverage %, writing to `$GITHUB_OUTPUT`; promote to job outputs then to the two `outputs:` blocks (:17, :405). Then deploy.yml (T-60) and pipeline.yml consume them. Avoid `|| 0` defaults that mask a missing measurement — emit an explicit `INDETERMINATE` sentinel the OPA input treats as fail.
- **Acceptance criteria:**
  - `build-and-scan.yml` `workflow_call.outputs` includes critical_cves and coverage_pct
  - The values are derived from artifact JSON, not hardcoded
  - pipeline.yml forwards both to deploy.yml inputs/needs
- **Verification:** A dispatch run shows `needs.build-and-scan.outputs.critical_cves` and `coverage_pct` populated with the same numbers as the uploaded summaries
- **Dependencies:** none
- **Maps to:** blueprint 04 §4.1 (load-bearing detail); spec §4; bug K4

#### T-02 — Harden Trivy fs+image gates: assert exit-code behavior + require justified .trivyignore entries
- **Area:** Gates | **Priority:** P1 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** Trivy fs+image are the strongest existing gates and must STAY blocking; a silently-added suppression must not weaken them. The .trivyignore format already documents a VEX-justification convention but does not enforce it (app/.trivyignore:1-9). Keeping suppressions justified+expiring is the honesty boundary (blueprint/04 §3.2).
- **Current state:** VERIFIED blocking: `trivy fs app/ ... --exit-code 1 --severity CRITICAL,HIGH --ignorefile app/.trivyignore` under `set -o pipefail` (build-and-scan.yml:59-66); image scan identical (build-and-scan.yml:528-535). app/.trivyignore currently has 0 active suppressions (lines 9-17). No CI check enforces the justification convention.
- **Definition of Done:** A pre-scan lint step fails the job if any non-comment, non-blank line in app/.trivyignore lacks a preceding `# VEX:` justification line and an expiry date; expired suppressions cause a fail. The two scan steps' `--exit-code 1` and `set -o pipefail` are covered by a unit test (T-fixture or `bash -n` + an asserted-fail fixture image).
- **Implementation notes:** Add a `Validate .trivyignore policy` step in build-and-scan.yml before the fs scan:\n```bash\npython3 scripts/lint-trivyignore.py app/.trivyignore  # exits 1 on unjustified/expired entry\n```\nThe linter: for each CVE line, require the immediately-preceding non-blank line match `^# VEX: (not_affected|false_positive|will_not_fix) - .+ expires=\\d{4}-\\d{2}-\\d{2}`; fail if `expires` < today. Spec: blueprint/04 §3.2; spec §4 SCA/Container rows.
- **Acceptance criteria:**
  - Adding `CVE-2099-0001` with no VEX line fails the job.
  - An entry with `expires=2020-01-01` fails the job.
  - With 0 suppressions (current), the step passes.
- **Verification:** `python3 scripts/lint-trivyignore.py app/.trivyignore` exits 0 now; add a temp unjustified line and confirm exit 1.
- **Dependencies:** none
- **Maps to:** blueprint/04 §3.2; spec §4 SCA + Container rows; spec Part C.5/C.7/C.11(VEX)

#### T-04 — Justify or remove the 19 Checkov skips; document each with a control reference
- **Area:** Gates | **Priority:** P1 | **Milestone:** M1 | **Effort:** M | **Owner:** Szymon
- **Context:** The IaC gate blocks but skips 19 checks with no justification, indistinguishable from quietly making the gate green. Spec §4 IaC row: 'Misconfigurations blocked (gate); mapped to CIS; drift checked' (struktura.md:160). An auditor opening the skip list expects a rationale per skip.
- **Current state:** VERIFIED `CHECKOV_SKIP_CHECKS="CKV_AZURE_163,...,CKV_AZURE_206"` — 19 IDs (security-gate.yml:108), echoed into the proof log (security-gate.yml:126) with no per-skip justification or expiry. Gate itself blocks via `set -o pipefail` (security-gate.yml:107).
- **Definition of Done:** A `infra/.checkov-skips.yaml` (or .checkov.yaml `skip-check` with comments) lists each skipped check with: check-id, reason, compensating-control reference, owner, expiry. The workflow reads skips from that file (not an inline string); CI fails if any skip lacks all five fields or is expired. Checks with no real justification are UN-skipped (gate becomes stricter).
- **Implementation notes:** Move the inline list to `Pipeline/infra/.checkov.yaml` with a YAML-comment block per skip OR a sibling `infra/checkov-skip-justifications.yaml` validated by a small python step before `checkov`. Re-run checkov without the skip to see what each blocks, then justify or fix the underlying Terraform. Spec: struktura.md:160; spec §4 IaC row; spec Part C.6.
- **Acceptance criteria:**
  - The 19 skips each have a documented reason + expiry; the count of unjustified skips is 0.
  - Removing a skip's justification fails the IaC job.
  - At least the skips with no real compensating control are removed (gate stricter than before).
- **Verification:** `checkov -d Pipeline/infra/ --config-file Pipeline/infra/.checkov.yaml` runs; `python3 scripts/validate-checkov-skips.py` exits 0; confirm justification file has 19 entries with expiry dates.
- **Dependencies:** none
- **Maps to:** blueprint/06 §6.2 (security-gate); spec §4 IaC row; spec Part C.6

#### T-05 — Make MegaLinter gate on lint errors (or relabel advisory)
- **Area:** Gates | **Priority:** P1 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** The lint/SAST-adjacent job writes a summary but never fails the gate, so a lint failure passes silently — a claim/behavior drift (blueprint/06 §6.2 security-gate). Either enforce it or stop presenting it as a gate.
- **Current state:** VERIFIED the MegaLinter job's only outcome handling is `if [ "${{ steps.megalinter.outcome }}" = "success" ]` in the Job Summary (security-gate.yml:220) — it writes a checkmark/x but there is no `exit 1`; no `continue-on-error`, no `DISABLE_ERRORS`. A non-success outcome does not fail the job because the summary step swallows it.
- **Definition of Done:** Either (A) add a step that fails the job when `steps.megalinter.outcome != 'success'` for the error-class linters (JS/TS ES, Dockerfile Hadolint), keeping markdown/yaml/json advisory via per-linter config; OR (B) relabel the job 'Code Linting (advisory)' and remove any doc/matrix implication that it gates. Default to (A).
- **Implementation notes:** In `Pipeline/.github/workflows/security-gate.yml` linting job, set MegaLinter `DISABLE_ERRORS_LINTERS: MARKDOWN_MARKDOWNLINT,YAML_YAMLLINT,JSON_JSONLINT` and add `- name: Fail on lint errors\n  if: steps.megalinter.outcome != 'success'\n  run: exit 1`. Note checkout at security-gate.yml:192 lacks `persist-credentials:false` — add it for consistency. Spec: spec §4 SAST/lint expectations.
- **Acceptance criteria:**
  - An ESLint error in app/src fails the linting job.
  - A markdownlint warning does NOT fail the job (advisory tier).
  - No doc claims lint gates unless it does.
- **Verification:** Introduce a deliberate ESLint violation and confirm the job fails; introduce a markdown style nit and confirm it does not.
- **Dependencies:** none
- **Maps to:** blueprint/06 §6.2 (security-gate BADLY); spec §4 SAST row

#### T-07 — DAST gate: count all ZAP sites + pass target_url via env (no JS interpolation)
- **Area:** Gates | **Priority:** P1 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** The DAST gate hard-fails correctly on HIGH/CRITICAL but parses only the first ZAP site, so a second site's HIGH findings are ignored (blueprint/06 §6.2 dast.yml); and target_url is interpolated into a github-script JS template literal — the canonical expression-injection antipattern (blueprint/06 §6.6-C).
- **Current state:** VERIFIED the severity counter uses `report.get('site', [{}])[0].get('alerts', [])` (dast.yml:65) and the summary likewise (dast.yml:96) — only site[0]. The incident-issue body interpolates `${{ inputs.target_url }}` directly into the JS body (dast.yml:160). Gate exits 1 on count!=0 (dast.yml:131-135).
- **Definition of Done:** The HIGH/CRITICAL counter iterates ALL `report['site']` entries (sum riskcode>=3 across sites); the github-script step receives `TARGET_URL` via `env:` and reads `process.env.TARGET_URL` instead of `${{ }}` interpolation. Gate still exits 1 on any HIGH/CRITICAL.
- **Implementation notes:** In `Pipeline/.github/workflows/dast.yml`: change both parse blocks to `for site in report.get('site',[]): alerts += site.get('alerts',[])`; add `env:\n  TARGET_URL: ${{ inputs.target_url }}` to the incident-issue step and use `process.env.TARGET_URL`. Spec: blueprint/06 §6.2, §6.6-C; spec §4 DAST row.
- **Acceptance criteria:**
  - A synthetic two-site ZAP report with a HIGH in site[1] fails the gate.
  - No `${{ inputs.target_url }}` remains inside any JS string body in dast.yml.
- **Verification:** Feed a crafted multi-site zap-report.json to the python step locally and confirm count>0; `grep -n 'inputs.target_url' Pipeline/.github/workflows/dast.yml` shows it only under `env:`.
- **Dependencies:** none
- **Maps to:** blueprint/06 §6.2 + §6.6-C; spec §4 DAST row; spec Part C.8

#### T-32 — Measure tool versions into tool-versions.json instead of hardcoding in generate-pipeline-run.sh
- **Area:** compliance-as-code | **Priority:** P1 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** FULLY-OPERATIONAL item 7 + struktura X.3 require tool versions to be MEASURED, not hardcoded, so the evidence reflects what actually ran. generate-pipeline-run.sh:38-48 hardcodes 8 versions (`"trivy":"v0.58+"`,`"cosign":"v2.4+"`,...). blueprint/04 §7 notes the Trivy summary already measures its own version (build-and-scan.yml:74); the rest are guesses.
- **Current state:** VERIFIED generate-pipeline-run.sh:38-48 contains a hardcoded `"tools":{...}` block with `+`-suffixed version strings; no tool-versions.json is produced.
- **Definition of Done:** A step writes `evidence/tool-versions.json` by invoking each tool's version command (`trivy --version`, `cosign version`, `syft version`, `opa version`, `checkov --version`, `trufflehog --version`, `terraform version`); generate-pipeline-run.sh no longer hardcodes versions (reads from tool-versions.json or omits the block); the matrix/gate reference the measured versions in `detail`.
- **Implementation notes:** Small shell loop capturing `cmd --version 2>/dev/null | head -1` per tool into a JSON map; tolerate a missing tool (record 'not-present'). Surface trivy's already-measured version from trivy-sca-summary.json. Tier EVIDENCE-ONLY.
- **Acceptance criteria:**
  - tool-versions.json contains measured versions for every installed tool
  - generate-pipeline-run.sh output no longer contains hardcoded `vX.Y+` literals
  - A tool absent from PATH is recorded as 'not-present', not a fabricated version
- **Verification:** `bash scripts/generate-tool-versions.sh > /tmp/tv.json && jq 'to_entries|length' /tmp/tv.json && ! grep -qE '"v[0-9].*\+"' scripts/generate-pipeline-run.sh`
- **Dependencies:** none
- **Maps to:** struktura X.3; blueprint/04 §7; FULLY-OPERATIONAL item 7 (versions measured not hardcoded)

#### T-43 — Capture parse_errors in security-report consolidation and fail on zero parsed reports
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** The consolidation that builds `security-report.json` swallows every parse error with a bare `except: pass`, so a corrupt or empty scanner output silently produces an empty consolidated report that the presence-only matrix then cannot flag. Blueprint §6.3-C. Combined with §6.4-C this is why 'a green pack does not imply the scanners ran'.
- **Current state:** VERIFIED. `evidence-pack.yml:107-117` ('Generate consolidated security report') uses `try: … except: pass` inside the glob loop; no error list is recorded; `security-report.json` is written even if zero reports parsed.
- **Definition of Done:** Parse failures are recorded into a `parse_errors` list in `security-report.json`; non-PR runs fail if zero reports parsed OR any parse_errors for a required scanner.
- **Implementation notes:** In `evidence-pack.yml:107-117` replace `except: pass` with `except Exception as e: parse_errors.append({'file': f, 'error': str(e)})` and write `{'consolidated_at':…, 'reports':reports, 'parse_errors':parse_errors}`. Add a non-PR assertion (can be merged into T-42's completeness step) failing on `len(reports)==0` or non-empty `parse_errors`. Blueprint §6.3-C exact-fix.
- **Acceptance criteria:**
  - `security-report.json` contains a `parse_errors` array.
  - A corrupt input JSON yields a `parse_errors` entry and (non-PR) fails the build.
- **Verification:** `cd Pipeline && python3 -c "import json; d=json.load(open('evidence/security-report.json')); assert 'parse_errors' in d; print('parse_errors_present', len(d['reports']))"`
- **Dependencies:** T-42
- **Maps to:** blueprint §6.3-C; spec §8 anti-pattern

#### T-50 — Fix fallback provenance builder.id and buildType to be SLSA-verifiable
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** The fallback provenance hardcodes a non-resolvable buildType and uses the workflow DISPLAY NAME as builder.id, so a verifier pinning builder identity cannot match it — the fallback provenance fails the very supply-chain verification the pack advertises. Blueprint §6.4-D [MED].
- **Current state:** VERIFIED. `generate-provenance.sh:46` sets `buildType: https://github.com/CyberForge/pipeline@v1` (non-resolvable placeholder org, real owner is CyberForge-Agency). `:77` sets `builder.id` using `${GITHUB_WORKFLOW}` (the display name 'Phase 3: Sign & Attest'), not the ref-pinned `${GITHUB_WORKFLOW_REF}` (which IS already used correctly at `:51`).
- **Definition of Done:** builder.id is the ref-pinned `${GITHUB_WORKFLOW_REF}` URI; buildType is a resolvable/standard URI; a verifier can pin builder identity.
- **Implementation notes:** In `Pipeline/scripts/generate-provenance.sh`: change `:77` `builder.id` to `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/.github/workflows/${GITHUB_WORKFLOW_REF}` (use the env var already documented at `:14`); change `:46` `buildType` to a resolvable owned URI or the SLSA generic `https://slsa.dev/container-based-build/v0.1`. Blueprint §6.4-D exact-fix.
- **Acceptance criteria:**
  - `builder.id` contains the ref (`@refs/...` or `@<sha>`), not a display name with spaces.
  - `buildType` resolves or is a recognized SLSA buildType URI.
- **Verification:** `cd Pipeline && GITHUB_WORKFLOW_REF='owner/repo/.github/workflows/sign-and-attest.yml@refs/heads/main' GITHUB_REPOSITORY=owner/repo IMAGE_URI=d/app:v1 IMAGE_DIGEST=sha256:abc bash scripts/generate-provenance.sh | python3 -c 'import json,sys; d=json.load(sys.stdin); bid=d["predicate"]["runDetails"]["builder"]["id"]; assert "@" in bid and " " not in bid, bid; print("BUILDER_ID_OK", bid)'`
- **Dependencies:** T-49
- **Maps to:** blueprint §6.4-D; spec C.12, §3 Build provenance row

#### T-56 — Assert at least one RFC-3161 timestamp was produced in non-degrade CI
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** RFC-3161 stamping soft-degrades even in CI (by design for TSA flakiness), but combined with §6.2-A the worry is that a structural failure masquerades as infra flakiness forever. After T-40 fixes Merkle signing, CI should assert that at least one trusted-time anchor (a .tsr) was actually produced for non-PR runs, so a permanently-broken TSA path is caught.
- **Current state:** VERIFIED. `seal-evidence.sh:390-395` records `rfc3161 status=unavailable` and warns but never fails, even in CI. No CI step asserts a .tsr exists. `verify-evidence-pack.sh:269-271` SKIPs when no .tsr present.
- **Definition of Done:** Non-PR CI fails if zero `.tsr` tokens were produced (TSA path totally broken), while transient single-artifact TSA misses remain soft.
- **Implementation notes:** Add a non-PR assertion in `evidence-pack.yml` after sealing: `count=$(ls evidence/*.tsr 2>/dev/null | wc -l); if [ "$count" -eq 0 ]; then echo '::error::no RFC-3161 timestamp produced'; exit 1; fi`. Keep per-artifact softness inside seal-evidence.sh. This is the honest middle ground recommended by blueprint §6.2 (structural-vs-flaky distinction) and gap #2.
- **Acceptance criteria:**
  - With a reachable TSA, the assertion passes (≥1 .tsr).
  - With TSA fully unreachable on a non-PR run, the job fails.
- **Verification:** `cd Pipeline && ls evidence/*.tsr >/dev/null 2>&1 && echo TSR_PRESENT_OK || echo TSR_MISSING`
- **Dependencies:** T-40
- **Maps to:** blueprint §6.2 / §6.4 gap #2; spec §7.3, Part I.2

#### T-74 — Fail hard on missing Terraform backend (no silent local-state apply)
- **Area:** Governance | **Priority:** P1 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** deploy.yml silently falls back to `terraform init -backend=false` (ephemeral local state) when backend vars are unset, so a misconfigured production apply orphans real Azure resources, loses the state lock, AND would let the retention OPA gate (T-62) evaluate a plan against throwaway state (VERIFIED deploy.yml:97-98; blueprint 06 deploy.yml note). This undermines the integrity of the deploy-time policy gate.
- **Current state:** VERIFIED deploy.yml:96-99 `else echo ::warning:: ... terraform init -backend=false fi` — warn-only local-state fallback for an apply.
- **Definition of Done:** On non-PR runs, deploy.yml exits non-zero when any of TFSTATE_RESOURCE_GROUP/STORAGE_ACCOUNT/CONTAINER/KEY is unset, instead of falling back to local state; PR/plan-only runs may keep a backend=false dry-run.
- **Implementation notes:** Replace the warn-only else with `if [ "${{ github.event_name }}" != 'pull_request' ]; then echo '::error::Terraform backend not configured; refusing real apply'; exit 1; fi` before any `-backend=false`. Ensures T-62's retention OPA gate runs against the authoritative remote state.
- **Acceptance criteria:**
  - A non-PR run with unset backend vars exits non-zero before plan/apply
  - A PR dry-run still works without remote backend
- **Verification:** A dispatch run on main with backend vars cleared fails at init with the explicit error; with vars set it initializes the azurerm backend
- **Dependencies:** none
- **Maps to:** blueprint 06 §6.2 deploy.yml; spec §7 (reproducibility/state integrity)

#### T-76 — Justify (or remove) the 19 Checkov skips and gate on unjustified skips
- **Area:** Governance | **Priority:** P2 | **Milestone:** M1 | **Effort:** M | **Owner:** Szymon
- **Context:** The IaC security gate suppresses 19 Checkov checks via a single CHECKOV_SKIP_CHECKS string with no per-check rationale (VERIFIED COMPANY-AUDIT:73 '19 Checkov skips with no per-check justification'; security-gate.yml Run Checkov step). spec §5 / §8 treat unbounded, unjustified exceptions as a rejection trigger; an auditor opening the gate sees 19 silenced controls.
- **Current state:** VERIFIED security-gate.yml 'Run Checkov' lists CHECKOV_SKIP_CHECKS with 19 IDs (CKV_AZURE_163, _237, ...); the uncommitted edit added `set -o pipefail` but not justifications.
- **Definition of Done:** Each skipped check has a documented justification + expiry (in a `infra/.checkov.yaml` or a committed `checkov-skips.md` mapping ID->reason->expiry), and a CI step fails if a skip lacks a justification or is expired.
- **Implementation notes:** Move skips into `infra/.checkov.yaml` `skip-check:` with comments, or a YAML mapping the gate reads; add a validator that asserts every ID in the active skip set has a non-empty justification and a future expiry (mirroring the .trivyignore policy from blueprint 04 §3.2). Re-evaluate whether some skips can simply be fixed in Terraform instead.
- **Acceptance criteria:**
  - Every active Checkov skip has a justification + expiry recorded
  - A skip with no justification or a past expiry fails CI
- **Verification:** A validator run over the skip list exits 0 today and exits non-zero after deleting one justification or back-dating one expiry
- **Dependencies:** none
- **Maps to:** spec §5 (exceptions log) / §8 (unbounded exceptions); COMPANY-AUDIT §3.3

#### T-125 — Assert SARIF 2.1.0 schema conformance for each scanner stage output (spec §4)
- **Area:** Gates/Evidence | **Priority:** P2 | **Milestone:** M1 | **Effort:** S | **Owner:** Szymon
- **Context:** The master spec mandates SARIF 2.1.0 as the required format for the secrets/SAST/SCA/IaC/container/DAST stages ('Format: SARIF 2.1.0', evidence-pack-specification.md:136-141,190-194 + struktura §4:157-162). An auditor's tooling ingests SARIF; a non-conformant or non-SARIF output fails machine ingestion. VERIFIED the matrix labels these rows but the pipeline consolidates raw JSON (security-report.json) without asserting any scanner emits schema-valid SARIF 2.1.0 — so the spec's named format requirement is unchecked.
- **Current state:** VERIFIED no SARIF schema validation exists — the consolidation in evidence-pack.yml globs `evidence/**/*.sarif` and `evidence/*.json` and json.loads them (deep-dive §6.3-C) but never validates `$schema`/`version == '2.1.0'`; grep for `sarif` schema-validation in scripts returns no validator.
- **Definition of Done:** A validator asserts each scanner SARIF artifact has `version == '2.1.0'` and the SARIF `$schema`, validates against the SARIF 2.1.0 JSON schema, and FAILs (non-PR) if a stage that should emit SARIF emitted non-conformant or non-SARIF output; the measured format is surfaced into the matrix detail.
- **Implementation notes:** Add `scripts/validators/sarif_conformance.py` taking the SARIF paths (CodeQL javascript.sarif, any tool emitting SARIF) and validating against a bundled SARIF 2.1.0 schema with `jsonschema`. For tools that emit native JSON not SARIF (Trivy default), either convert to SARIF (`trivy ... --format sarif`) or document the format honestly in the matrix detail rather than mislabeling it SARIF. Wire into the compliance-validate job. Maps to spec §4 format column + §3 C rows.
- **Acceptance criteria:**
  - Each declared-SARIF artifact validates against the SARIF 2.1.0 schema or the validator FAILs.
  - The matrix detail records the actual format/version measured per stage.
  - No stage is labeled 'SARIF 2.1.0' in the matrix unless its output validates.
- **Verification:** `python3 Pipeline/scripts/validators/sarif_conformance.py evidence/codeql-results/javascript.sarif`
- **Dependencies:** T-12
- **Maps to:** spec §4 format requirement; evidence-pack-specification.md:136-141,190-194; struktura §4:157-162

## M2 — Compliance-as-code & integrity  (39 tasks)

#### T-09 — Wire deployment-gate.rego as a blocking step in deploy.yml with real inputs
- **Area:** Compliance-gate | **Priority:** P0 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** The deployment-gate policy is written and unit-tested (denies on unsigned image, missing SBOM, critical_cves>0, coverage<80) but executed by no workflow; spec §4 calls audit-only policies an auditor rejection (spec:196; K4). Inputs must be REAL (from T-03), else this re-creates the file-presence lie.
- **Current state:** VERIFIED `grep -rn 'opa\|conftest\|rego' Pipeline/.github/workflows/` returns empty; policies/deployment-gate.rego + _test.rego (4 cases) exist (policies dir). deploy.yml has no OPA step (deploy.yml:55-72 jumps signature->Terraform).
- **Definition of Done:** After the (tightened, T-08) cosign verify and BEFORE Setup Terraform, deploy.yml runs `opa eval` against deployment-gate.rego with an input JSON built from `needs.build-and-scan.outputs.critical_cves`/`coverage_pct` (T-03) and real signed/sbom booleans; a non-empty `deny` set fails the deploy (`exit 1`). setup-opa is SHA-pinned per repo policy.
- **Implementation notes:** In `Pipeline/.github/workflows/deploy.yml` insert after deploy.yml:66:\n```yaml\n- name: Setup OPA\n  uses: open-policy-agent/setup-opa@<pin-SHA> # vN\n- name: OPA deployment gate (blocking)\n  run: |\n    set -o pipefail\n    cat > /tmp/in.json <<JSON\n    {"image_signed":true,"sbom_attached":true,"critical_cves":${{ needs.build-and-scan.outputs.critical_cves }},"tests_passed":true,"coverage_pct":${{ needs.build-and-scan.outputs.coverage_pct }}}\n    JSON\n    DENY=$(opa eval -d policies/deployment-gate.rego -i /tmp/in.json 'data.compliance.deployment.deny' --format raw)\n    [ "$(echo "$DENY" | jq 'length')" -eq 0 ] || { echo "::error::$DENY"; exit 1; }\n```\nPipeline.yml must pass build-and-scan outputs into deploy `with:`/`needs`. Spec: blueprint/04 §4.1.
- **Acceptance criteria:**
  - With critical_cves>0 injected, the OPA step fails the deploy.
  - With clean inputs, deploy proceeds.
  - The input JSON values are sourced from real outputs, not literals.
- **Verification:** `opa eval -d Pipeline/policies/deployment-gate.rego -i fixtures/deny-input.json 'data.compliance.deployment.deny'` returns a non-empty set; `opa test Pipeline/policies/` passes.
- **Dependencies:** T-03
- **Maps to:** blueprint/04 §4.1; blueprint/06 K4; spec §4 Policy gate; spec Part C.13

#### T-11 — Replace warn-only evidence-completeness with blocking evidence-completeness.rego (non-PR)
- **Area:** Compliance-gate | **Priority:** P0 | **Milestone:** M2 | **Effort:** S | **Owner:** Szymon
- **Context:** A pack with FAIL/MISSING controls still seals and archives to 5-year WORM because the completeness check is warn-only by design — the seal certifies an incomplete pack (§6.4-C; blueprint/04 §4.3). This is GTM-RESET quick-fix #2: 'incomplete packs cannot seal.'
- **Current state:** VERIFIED the 'Validate evidence completeness' step only emits `::warning::` and never exits non-zero (evidence-pack.yml:213-234); the comment states 'does NOT block archival' (evidence-pack.yml:210-212). evidence-completeness.rego (denies on 11 missing files) + 3 tests exist but are unwired (K4).
- **Definition of Done:** The warn-only block is replaced by an OPA step that builds an input file list from `evidence/`, evaluates `data.compliance.evidence.deny`, and on non-PR runs `exit 1` when deny is non-empty; PR runs degrade to warning (consistent with the existing degrade-on-PR pattern). Required artifacts must be present AND non-empty AND content-valid (depends on the matrix validators landing first, T-12).
- **Implementation notes:** Replace evidence-pack.yml:213-234 with the Setup-OPA + `opa eval` block from blueprint/04 §4.3; gate `if: github.event_name != 'pull_request'`. Required set: security-report.json, sbom.cyclonedx.json, provenance.intoto.jsonl, cosign-verification.log, compliance-matrix.json — each present + non-empty. setup-opa SHA-pinned. Spec: blueprint/04 §4.3; spec §5 (completeness); spec Part I.
- **Acceptance criteria:**
  - On a non-PR run with a deleted sbom.cyclonedx.json, the evidence-pack job fails before seal.
  - On a PR run the same condition warns but does not block.
  - A complete pack seals as today.
- **Verification:** `opa test Pipeline/policies/` passes; simulate a missing required artifact on a non-PR dispatch and confirm the job fails before the seal step.
- **Dependencies:** T-12
- **Maps to:** blueprint/04 §4.3; blueprint/06 §6.4-C + K4; spec §5; spec Part I

#### T-20 — A.1 validate-roi — Register of Information schema + LEI validation (DORA Art.28(3))
- **Area:** compliance-as-code | **Priority:** P0 | **Milestone:** M2 | **Effort:** L | **Owner:** Szymon
- **Context:** DORA Art.28(3) [HARD] requires a machine-readable Register of Information with an LEI for every ICT third party; KNF demands form SPR-PF-18 (blueprint/02:12). struktura §6 A.1 specifies `validate-roi` = schema+threshold → `roi-validation.json`. This is the single strongest differentiator and the seed of the Tier-2 Operated-Register product (blueprint/04 §6.3). A bank's vendor questionnaire asks exactly for this.
- **Current state:** VERIFIED no RoI YAML, no schema, no validator (grep validate-roi/jsonschema = 0 hits). Source data exists only as Markdown in vendor-risk-register.md:44-54 with no LEI column.
- **Definition of Done:** `docs/governance/register-of-information.yaml` (seeded from vendor-risk-register) + `schemas/roi.schema.json` exist; `scripts/validators/validate-roi.py` validates the YAML against the schema, asserts an LEI (ISO 17442 format) per party and a non-empty `exit_plan_ref`+`substitutability` for every Critical/High vendor; emits `roi-validation.json` via the T-33 envelope (tier BLOCKING on schema+completeness, EVIDENCE-ONLY on advisory fields).
- **Implementation notes:** `python3 -c "import yaml,json,jsonschema; jsonschema.validate(yaml.safe_load(open('docs/governance/register-of-information.yaml')), json.load(open('schemas/roi.schema.json')))"`. Map columns→EBA RT.01/RT.05 fields (entity, function, ICT service, criticality, data location, substitutability, exit plan, LEI). LEI assertion: 20-char `^[A-Z0-9]{18}[0-9]{2}$`; if CyberForge has no issued LEI, downgrade that row to EVIDENCE-ONLY (open question). Add `pyyaml jsonschema` to requirements. Wire as a step in evidence-pack.yml before the matrix; sign the output (T-30/seal pattern).
- **Acceptance criteria:**
  - `validate-roi.py` exits 0 on the seeded register and emits schema-valid `roi-validation.json` with a `measured` LEI count
  - Removing a Critical vendor's `exit_plan_ref` makes it exit 1 with a specific error
  - An invalid LEI format is reported in `detail`
- **Verification:** `python3 scripts/validators/validate-roi.py docs/governance/register-of-information.yaml schemas/roi.schema.json && jq .status roi-validation.json`
- **Dependencies:** T-33, T-36
- **Maps to:** struktura §6 A.1; spec F.1/§3 RoI row; blueprint/04 §6.3; bug: file-presence matrix (G1)

#### T-24 — A.5 assert-retention — threshold vs Terraform plan, wire retention-policy.rego (DORA Art.12)
- **Area:** compliance-as-code | **Priority:** P0 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** DORA's 5-year (1825-day) evidence retention is a number in a regulation checked against live infrastructure — a genuinely regulation-unique check (blueprint/04 §6.1). The retention-policy.rego (1825-day constant + WORM + deletion-schedule) is written and unit-tested but invoked by zero workflows (blueprint/04:44-45). struktura §6 A.5 = threshold vs IaC → retention-policy.json. This connects the dormant policy to actual infra state and catches any future regression below 1825 days.
- **Current state:** VERIFIED Terraform sets immutability_period_days=1825 + retention_days=1825 (infra/modules/storage/variables.tf:16-26, main.tf:42); retention-policy.rego:5 has the constant but no workflow runs `opa eval` (grep opa/conftest in workflows = 0).
- **Definition of Done:** `scripts/tfplan-to-retention-input.py` extracts immutability_period_in_days + lifecycle delete + worm flag from `terraform show -json tfplan`; an `opa eval -d policies/retention-policy.rego` step in deploy.yml gates (exit non-zero on deny); the validator emits `retention-policy.json` via T-33 envelope (BLOCKING). (If OPA-wiring is owned by the gates stream, this task still owns the extractor + signed A.5 artifact.)
- **Implementation notes:** Walk `plan['planned_values']['root_module']['child_modules'][*]['resources']` for `azurerm_storage_container_immutability_policy`. Emit `{retention_days, worm_enabled, deletion_schedule}`. `DENY=$(opa eval -d ../policies/retention-policy.rego -i /tmp/ret-input.json 'data.compliance.retention.deny' --format raw); [ "$(echo "$DENY"|jq length)" -eq 0 ]`. Pin setup-opa by SHA.
- **Acceptance criteria:**
  - Extractor produces `retention_days: 1825, worm_enabled: true` from the real plan
  - Lowering immutability to 365 in a test plan makes the opa step exit non-zero
  - `retention-policy.json` PASS reflects the measured 1825
- **Verification:** `terraform -chdir=infra show -json tfplan > /tmp/p.json && python3 scripts/tfplan-to-retention-input.py /tmp/p.json | opa eval -d policies/retention-policy.rego -I 'data.compliance.retention.deny'`
- **Dependencies:** T-33
- **Maps to:** struktura §6 A.5; blueprint/04 §6.1 + §4.2; COMPANY-AUDIT §3.5 (dormant 1825 policy)

#### T-25 — A.6 check-governance — board-approval + management-training freshness (DORA Art.5/NIS2 20)
- **Area:** compliance-as-code | **Priority:** P0 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** DORA Art.5 + NIS2 Art.20 [HARD] are 'the part auditors check first, and entities most often miss' (spec Part A header) — board approval of security measures and management cybersecurity training. struktura §6 A.6 = presence+freshness → governance-evidence.json. Missing board sign-off is a named rejection trigger (struktura §12).
- **Current state:** VERIFIED management-review-template.md (Last Reviewed 2026-03-15, semi-annual cadence) and nis2-management-training-records.md (Effective 2026-03-15, annual cycle, Art.20 text quoted) exist; no validator checks their presence/freshness.
- **Definition of Done:** `check-governance.py` asserts both documents exist, parses their dates, and FAILs if either is outside its stated cadence (management-review >183 days, training >365 days); emits `governance-evidence.json` via T-33 (BLOCKING on freshness; per-attendee data EVIDENCE-ONLY since training is a human event — struktura §14 / blueprint/04 §9).
- **Implementation notes:** Regex the `Last Reviewed:`/`Effective Date:` and `Review Cadence/Cycle` lines; use T-33 `days_since`. Honest framing: the pipeline validates the LOG's freshness, not that training actually happened (blueprint/04 §9 row 1). Wire into evidence-pack.yml before the gate.
- **Acceptance criteria:**
  - PASS on current docs (both within cadence)
  - Backdating training record's Effective Date >365 days makes it FAIL with the article cited
  - Deleting either document yields a presence FAIL, not a silent pass
- **Verification:** `python3 scripts/validators/check-governance.py docs/governance/ && jq .status governance-evidence.json`
- **Dependencies:** T-33
- **Maps to:** struktura §6 A.6; spec Part A rows; struktura §12 (no board signature)

#### T-27 — A.8 check-access-reviews — Next-Due freshness gate (NIS2 21(2)(i)/ISO 8.2)
- **Area:** compliance-as-code | **Priority:** P0 | **Milestone:** M2 | **Effort:** S | **Owner:** Szymon
- **Context:** struktura §6 A.8 = freshness — access-review records present and in-cycle, privileged accounts re-certified → access-review.json. access-review-schedule.md already carries machine-parseable per-row `Next Due` dates and SOC2 criteria — an ideal honest freshness check (the pipeline validates cadence, not the review's content — blueprint/04 §9).
- **Current state:** VERIFIED access-review-schedule.md:32-? has a `Next Due` column (e.g. Privileged GitHub Org Owners due 2026-06-15, which is PAST relative to today 2026-06-16 — a real FAIL the validator must surface, not hide).
- **Definition of Done:** `check-access-reviews.py` parses every `Next Due` date in the schedule table, FAILs any row whose due date is in the past, records the worst-case days-overdue in `measured`; emits `access-review.json` via T-33 (BLOCKING).
- **Implementation notes:** T-33 `gfm_table('docs/governance/access-review-schedule.md','Review Schedule')`; `overdue = [r for r in rows if date.fromisoformat(r['Next Due']) < date.today()]`; `status = 'FAIL' if overdue else 'PASS'`. This validator demonstrably FAILs on the current repo (good demo of a real, not cosmetic, check).
- **Acceptance criteria:**
  - On current data with a past Next Due, exits 1 listing the overdue review type(s)
  - Updating all Next Due dates to the future flips it to PASS
  - `access-review.json.measured` reports max days overdue
- **Verification:** `python3 scripts/validators/check-access-reviews.py docs/governance/access-review-schedule.md; echo "exit=$?"; jq .status access-review.json`
- **Dependencies:** T-33
- **Maps to:** struktura §6 A.8; spec Part A/D; blueprint/04 §9 (cadence not content)

#### T-30 — Compliance gate — aggregate A.1-A.10 into one SIGNED PASS/FAIL report, fail-closed on stale evidence
- **Area:** compliance-as-code | **Priority:** P0 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** struktura §6 'bramka zgodności' (compliance gate) requires the A.1-A.10 verdicts to be aggregated into ONE signed PASS/FAIL state-of-compliance report, where a missing or stale organizational evidence item yields FAIL with a concrete remediation pointer. This is FULLY-OPERATIONAL item 3 (validators emit signed PASS/FAIL into a compliance gate) and item 6 (evidence-completeness blocking) for the organizational layer. Today the nearest construct is warn-only (evidence-pack.yml:210-234, 'does NOT block archival').
- **Current state:** VERIFIED no aggregator exists (grep compliance-gate/aggregat = 0 functional hits); completeness step at evidence-pack.yml:213-234 only emits `::warning::` from the file-presence matrix; only seal-evidence.sh signs blobs (cosign sign-blob), so A.* outputs are unsigned today.
- **Definition of Done:** `scripts/aggregate-compliance-gate.py` reads the 10 `*-validation.json`/`*.json` verdicts, computes overall status (FAIL if any BLOCKING verdict is FAIL or any required verdict file is missing/stale), writes `compliance-gate.json` (overall + per-control rows + remediation hints), cosign-signs it (reusing the seal-evidence sign-blob pattern), and exits non-zero on FAIL; a blocking job in evidence-pack.yml replaces the warn-only block (blocks on non-PR, warns on PR per the existing degrade-on-PR pattern at evidence-pack.yml:322).
- **Implementation notes:** Iterate a fixed list of expected verdict filenames; a missing file = FAIL (closes the warn-only hole). Sign with `cosign sign-blob --yes --bundle compliance-gate.cosign.bundle compliance-gate.json` (same retry helper style as seal-evidence.sh:285-309). Add `compliance-gate.json` to evidence-completeness.rego required_files so the OPA completeness check also enforces its presence.
- **Acceptance criteria:**
  - With all 10 verdicts PASS, gate exits 0 and emits a signed compliance-gate.json (cosign bundle present + non-empty)
  - Deleting any one verdict file makes the gate exit 1 ('missing org evidence: <name>')
  - Any BLOCKING FAIL (e.g. overdue access review from T-27) makes the gate exit 1 on a non-PR run
  - The evidence-pack.yml step blocks (non-zero) on push, warns on pull_request
- **Verification:** `python3 scripts/aggregate-compliance-gate.py evidence/ && cosign verify-blob --bundle evidence/compliance-gate.cosign.bundle evidence/compliance-gate.json`
- **Dependencies:** T-20, T-21, T-22, T-23, T-24, T-25, T-26, T-27, T-28, T-29
- **Maps to:** struktura §6 (compliance gate); FULLY-OPERATIONAL items 3 + 6; blueprint/04 §4.3; GTM-RESET quick-fix #2

#### T-60 — Wire deployment-gate.rego as a NAMED blocking step in deploy.yml
- **Area:** OPA | **Priority:** P0 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** The 3 OPA policies are written + unit-tested (10/10 pass) but invoked by zero workflows (VERIFIED: `grep -rniE 'opa|conftest|rego' Pipeline/.github/workflows/` returns only izpack false-positives). spec §4 requires the policy gate to 'Block non-compliant deploys', not sit in audit-only. This makes deployment-gate.rego a real admission control before infra mutation. blueprint 04 §4.1.
- **Current state:** VERIFIED policies/deployment-gate.rego:5-31 (allow + deny on unsigned/no-SBOM/critical_cves>0/coverage<80); 0 workflow references; deploy.yml has cosign-verify gate at deploy.yml:55-66 but no OPA step.
- **Definition of Done:** A named step `OPA deployment gate (blocking)` runs in deploy.yml after signature verify and BEFORE `Setup Terraform`/plan, evaluates `data.compliance.deployment.deny`, and `exit 1` when the deny set is non-empty.
- **Implementation notes:** In deploy.yml, add `Setup OPA` via `open-policy-agent/setup-opa@<SHA>` then a step that writes `/tmp/deploy-input.json` from REAL inputs `critical_cves: ${{ needs.build-and-scan.outputs.critical_cves }}`, `coverage_pct: ${{ needs.build-and-scan.outputs.coverage_pct }}`, `image_signed`/`sbom_attached` derived from the cosign-verify + attest step outcomes (not literal true). `DENY=$(opa eval -d policies/deployment-gate.rego -i /tmp/deploy-input.json 'data.compliance.deployment.deny' --format raw); [ "$(echo "$DENY" | jq 'length')" -eq 0 ] || { echo "::error::$DENY"; exit 1; }`. NEVER hardcode true/0 (that re-creates the file-presence fake). blueprint 04 §4.1; struktura §6 compliance gate.
- **Acceptance criteria:**
  - deploy.yml contains a step named `OPA deployment gate (blocking)` that calls `opa eval` on deployment-gate.rego
  - With a synthetic input of critical_cves=2 the step exits non-zero; with the clean input it passes
  - No input field is a hardcoded literal that should be measured (critical_cves, coverage_pct come from needs outputs)
- **Verification:** `act -W .github/workflows/deploy.yml` (or a dispatch run) shows the step; locally: `opa eval -d Pipeline/policies/deployment-gate.rego -i /tmp/bad.json 'data.compliance.deployment.deny' --format raw | jq 'length'` returns >0 for critical_cves=2
- **Dependencies:** T-63
- **Maps to:** blueprint 04 §4.1; spec §4 Policy gate; bug K4

#### T-61 — Replace warn-only completeness with blocking evidence-completeness.rego OPA step
- **Area:** OPA | **Priority:** P0 | **Milestone:** M2 | **Effort:** S | **Owner:** Szymon
- **Context:** Evidence-completeness validation is warn-only by design — a pack with every required artifact MISSING still seals to 5-year WORM (VERIFIED evidence-pack.yml:210-234, comment 'does NOT block archival'; bug §6.4-C). spec §8 lists 'policies in audit-only forever' as a rejection trigger. The policy already exists; this is pure wiring. GTM-RESET §4 quick-fix #2.
- **Current state:** VERIFIED evidence-pack.yml:213-234 emits only `::warning::`; policies/evidence-completeness.rego:5-28 denies on any of 11 missing required files with 3 passing tests.
- **Definition of Done:** The warn-only block is replaced by a `Setup OPA` + `OPA evidence completeness (blocking on non-PR)` step that fails the job (non-PR) when `data.compliance.evidence.deny` is non-empty, and warns on PR.
- **Implementation notes:** `FILES=$(cd evidence && find . -maxdepth 2 -type f -printf '\"%f\",' | sed 's/,$//'); echo "{\"files\":[${FILES}]}" > /tmp/ev-input.json; DENY=$(opa eval -d policies/evidence-completeness.rego -i /tmp/ev-input.json 'data.compliance.evidence.deny' --format raw); if [ "${{ github.event_name }}" != "pull_request" ] && [ "$(echo "$DENY" | jq 'length')" -gt 0 ]; then echo "::error::Evidence pack incomplete: $DENY"; exit 1; fi`. Must run AFTER the §3/§4 validators that produce dependency-review.json etc. (the content-matrix stream). blueprint 04 §4.3.
- **Acceptance criteria:**
  - evidence-pack.yml no longer contains the `does NOT block archival` warn-only block
  - A non-PR run missing sbom.cyclonedx.json exits non-zero before the WORM upload step
  - A PR run with the same gap warns (exit 0), preserving the degrade-on-PR pattern
- **Verification:** `opa eval -d Pipeline/policies/evidence-completeness.rego -i /tmp/partial.json 'data.compliance.evidence.deny' --format raw | jq 'length'` >0 for a partial file set; dispatch run on main shows the job fail when an artifact is absent
- **Dependencies:** none
- **Maps to:** blueprint 04 §4.3; spec §8 anti-pattern #4; bug §6.4-C / K1

#### T-104 - Make storage WORM lockable (var.lock_worm) + align wording
- Area: IaC | P0 | M2 | M | Szymon
- Context: The WORM immutability policy is created UNLOCKED; period can be shortened/deleted by Storage Account Contributor; not true WORM until locked true. Docs assert immutable WORM + 5-year WORM. Source blueprint/06 6.5-B + remediation 4; COMPANY-AUDIT 3.5; GTM-RESET 5.
- Current state: VERIFIED storage/main.tf:32-37 sets immutability_period_in_days + protected_append_writes_all_enabled true but NO locked true and no lock step; variables.tf has no lock_worm.
- DoD: var.lock_worm (false non-prod, true prod) drives locked true; until locked all wording reads WORM-designed unlocked.
- Notes: Add variable lock_worm bool default false; add locked var.lock_worm (azurerm v4; irreversible, blocks destroy - document). Thread through infra/main.tf. Report reads worm_state (build-audit-document.py:26).
- Acceptance: plan with lock_worm true shows locked true; with false every immutability claim reads WORM-designed unlocked.
- Verification: terraform validate + plan with lock_worm true shows locked true.
- Deps: none
- Maps to: blueprint/06 6.5-B + remediation 4; spec 7.5; COMPANY-AUDIT 3.5; GTM-RESET 5

#### T-10 — Wire retention-policy.rego in deploy.yml against the Terraform plan
- **Area:** Compliance-gate | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** retention-policy.rego encodes the only DORA-specific number (1825-day retention) plus worm_enabled/deletion_schedule, but no workflow runs it, so the 5-year retention claim is unenforced (K4; blueprint/04 §4.2/§6.1). Connecting it to live tfplan turns a dormant constant into an enforced gate and catches future regressions below 1825 days.
- **Current state:** VERIFIED policies/retention-policy.rego:5 `minimum_retention_days := 1825` with 3 unit tests; invoked nowhere. deploy.yml produces `tfplan` (deploy.yml:111-113) but never inspects it for retention.
- **Definition of Done:** A new step after Terraform Plan runs `terraform show -json tfplan`, extracts the storage immutability period + lifecycle delete days via a helper script into OPA input, evaluates `data.compliance.retention.deny`, and fails the deploy on any deny. Today's 1825/1825 values pass truthfully.
- **Implementation notes:** Add `scripts/tfplan-to-retention-input.py` walking `planned_values...child_modules` for `azurerm_storage_container_immutability_policy.immutability_period_in_days` and the lifecycle delete; emit `{retention_days, worm_enabled, deletion_schedule}`. Add the OPA step in `Pipeline/.github/workflows/deploy.yml` (working-directory infra/) per blueprint/04 §4.2. Spec: blueprint/04 §6.1; spec Part I.3 (retention/immutability).
- **Acceptance criteria:**
  - A tfplan with retention_days<1825 fails the deploy.
  - The current infra (1825) passes.
  - worm_enabled false triggers deny.
- **Verification:** `python3 scripts/tfplan-to-retention-input.py fixtures/tfplan.json | opa eval -d Pipeline/policies/retention-policy.rego -i /dev/stdin 'data.compliance.retention.deny'` returns empty for compliant, non-empty for a shortened-retention fixture.
- **Dependencies:** T-09
- **Maps to:** blueprint/04 §4.2 + §6.1; spec Part I.3; spec §4 Policy gate

#### T-14 — Content validator: DORA Art.16.1.c (real SCA gate config + 0 unjustified suppressions, not a cp)
- **Area:** Compliance-matrix | **Priority:** P1 | **Milestone:** M2 | **Effort:** S | **Owner:** Szymon
- **Context:** This row is currently fed by `dependency-review.json`, which is literally `cp trivy-sca-results.json` and then labeled DORA Art.16.1.c (K3; blueprint/04 §1.5/§3.2). The honest evidence is 'SCA ran with a blocking severity gate AND the suppression policy is empty/justified.'
- **Current state:** VERIFIED evidence-pack.yml:123 `cp evidence/trivy-sca-results.json evidence/dependency-review.json`; matrix row DORA Art.16.1.c -> `check_file dependency-review.json` (generate-compliance-matrix.sh:27).
- **Definition of Done:** `validators/dora_16_1_c.py` asserts: (a) trivy-sca-summary.json.severity_filter contains CRITICAL and HIGH; (b) app/.trivyignore has 0 unjustified/expired suppressions (shared logic with T-02); (c) dependency-review.json is structurally a Trivy report (has Results), not an arbitrary copy. PASS iff all true; tier BLOCKING. Stop labeling a bare cp as a review.
- **Implementation notes:** Reuse the .trivyignore linter from T-02. Per blueprint/04 §3.2 sketch. Either keep producing dependency-review.json but validate its shape, or replace the cp with a genuine dependency-review artifact. Wire into T-12 dispatch. Spec: blueprint/04 §3.2; spec Part C.5.
- **Acceptance criteria:**
  - Removing CRITICAL from severity_filter fails the row.
  - An unjustified .trivyignore line fails the row.
  - A dependency-review.json without `Results` fails the row.
- **Verification:** `python3 Pipeline/scripts/validators/dora_16_1_c.py fixtures/good-evidence/; echo $?` returns 0; tamper a fixture and confirm exit 1.
- **Dependencies:** T-12
- **Maps to:** blueprint/04 §3.2; blueprint/06 K3; spec Part C.5

#### T-15 — Content validator: NIS2 Art.21.2.d supply-chain (CycloneDX schema valid + cosign verify-attestation binds to digest)
- **Area:** Compliance-matrix | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** The supply-chain rows are file-presence over sbom.cyclonedx.json + provenance.intoto.jsonl; an auditor needs proof the SBOM is schema-valid AND is the one attested to the deployed digest (blueprint/04 §3.3; spec §4 SBOM 'unlinked to running artifact' = rejection).
- **Current state:** VERIFIED NIS2 Art.21.2.d -> `check_all sbom.cyclonedx.json provenance.intoto.jsonl` (generate-compliance-matrix.sh:33) — presence only; no schema validation, no verify-attestation anywhere in the matrix path.
- **Definition of Done:** `validators/nis2_21_2_d.py` (a) validates sbom.cyclonedx.json against the CycloneDX JSON schema (bomFormat==CycloneDX, specVersion present, components>0); (b) re-runs `cosign verify-attestation --type cyclonedx` with the tightened identity (T-08) against image_uri@image_digest and asserts exit 0. PASS iff schema-valid AND >=1 component AND attestation verifies; tier BLOCKING.
- **Implementation notes:** Add `cyclonedx-cli` (or bundled jsonschema) for schema check; reuse the verify pattern from sign-and-attest.yml:125-134. Best wired as a step in sign-and-attest.yml (where the attestation is created at :63-70) feeding a JSON the matrix reads, per blueprint/04 §3.3. Spec: blueprint/04 §3.3; spec Part C.10/C.12/F.4.
- **Acceptance criteria:**
  - A malformed SBOM (missing specVersion) fails the row.
  - An SBOM not attested to the digest fails verify-attestation.
  - A valid attested SBOM passes.
- **Verification:** `cyclonedx validate --input-file evidence/sbom.cyclonedx.json --fail-on-errors` exits 0; `cosign verify-attestation --type cyclonedx --certificate-identity-regexp '...sign-and-attest.yml@refs/heads/main' ... <image>@<digest>` exits 0.
- **Dependencies:** T-12
- **Maps to:** blueprint/04 §3.3; spec §4 SBOM/Provenance; spec Part C.10/C.12/F.4

#### T-16 — Content validator: NIS2 Art.21.2.h cryptography (re-run cosign verify on deployed digest)
- **Area:** Compliance-matrix | **Priority:** P1 | **Milestone:** M2 | **Effort:** S | **Owner:** Szymon
- **Context:** The cryptography row trusts the mere presence of cosign-verification.log; an auditor needs the matrix to RE-EXECUTE cosign verify on the deployed digest with the tightened identity and record the Rekor index + cert identity (blueprint/04 §3.4).
- **Current state:** VERIFIED NIS2 Art.21.2.h -> `check_file cosign-verification.log` (generate-compliance-matrix.sh:35); the log is not re-verified, and the existing verify identity is broad (deploy.yml:62, addressed by T-08).
- **Definition of Done:** `validators/nis2_21_2_h.py` re-runs `cosign verify` against image_uri@image_digest with the tightened identity (T-08) and asserts exit 0; parses the log/output to record Rekor log index + certificate identity into the row `detail`. PASS iff verify exits 0 against the digest (not the tag); tier BLOCKING.
- **Implementation notes:** Shell out to cosign verify with `--certificate-identity-regexp '.../sign-and-attest.yml@refs/heads/main'`; capture `--output json` for the Rekor index. Wire into T-12 dispatch; also strengthens SOC2 CC7.1 which shares cosign-verification.log (generate-compliance-matrix.sh:45). Spec: blueprint/04 §3.4; spec Part C.12/H.4.
- **Acceptance criteria:**
  - Verifying against the tag instead of the digest is rejected (must use digest).
  - A tampered/absent signature makes the row FAIL.
  - The row detail includes a Rekor log index.
- **Verification:** `python3 Pipeline/scripts/validators/nis2_21_2_h.py evidence/; echo $?` returns 0 for a real signed image and 1 for an unsigned one; detail shows a numeric Rekor index.
- **Dependencies:** T-08, T-12
- **Maps to:** blueprint/04 §3.4; spec Part C.12/H.4

#### T-17 — Content validators: ISO/SOC2/RODO rows assert pipeline-run.json gate_results + register freshness
- **Area:** Compliance-matrix | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** The remaining ~11 ISO/SOC2/RODO rows are all `check_file pipeline-run.json` or DPA/data-flow file-presence; they must assert content: that every relevant gate result == success and the run SHA matches the deployed provenance, plus RODO rows tie to register freshness rather than a static heredoc (blueprint/04 §3.6).
- **Current state:** VERIFIED ISO A.8.4/A.8.9/A.8.25, SOC2 CC6.1/CC8.1, RODO Art.30 all -> `check_file pipeline-run.json` (generate-compliance-matrix.sh:38-40,44,46,54); RODO Art.5.1.c/Art.5.1.e/Art.28 -> `check_file dpa-compliance-check.json` (generate-compliance-matrix.sh:50-51,53), which is produced by a static heredoc (check-dpa.sh, K2). gate_results JSON is passed in (pipeline.yml:106-107) but never asserted in the matrix.
- **Definition of Done:** `validators/gate_results.py` asserts pipeline-run.json contains gate_results where every required gate == 'success' (FAIL otherwise; INDETERMINATE if absent), tier BLOCKING for the gate-result rows. RODO descriptive rows are tier EVIDENCE-ONLY and fed by register freshness (cross-ref the check-dpa register-read task in the compliance-as-code stream). All ~11 rows carry measured values.
- **Implementation notes:** Parse the gate_results JSON consolidated into pipeline-run.json (built from pipeline.yml:106-107). Mark a gate failure as a FAIL row. For RODO Art.28/Art.5, depend on a real register read (out of this stream's scope; reference it). Wire into T-12 dispatch. Spec: blueprint/04 §3.6; spec Parts D.1/D.2/H.
- **Acceptance criteria:**
  - A gate_results with security_gate=failure makes the SOC2 CC6.1 row FAIL.
  - Absent gate_results -> INDETERMINATE, not PASS.
  - Each of the 11 rows includes a measured value + tier.
- **Verification:** `python3 Pipeline/scripts/validators/gate_results.py fixtures/failed-gate/; echo $?` returns 1 with the failing gate named in detail.
- **Dependencies:** T-12
- **Maps to:** blueprint/04 §3.6; spec Parts D.1/D.2/H

#### T-22 — A.3 validate-ropa — RoPA/DPIA presence + Art.30 schema completeness (RODO Art.30/35)
- **Area:** compliance-as-code | **Priority:** P1 | **Milestone:** M2 | **Effort:** L | **Owner:** Szymon
- **Context:** RODO Art.30 [HARD] requires a standalone, complete Records-of-Processing-Activities document per processing activity; Art.35 requires a DPIA for high-risk processing. struktura §6 A.3 = presence+schema → ropa-completeness.json. A bank/UODO auditor asks for the RoPA as a discrete artifact; scattered references are a rejection trigger (struktura §12).
- **Current state:** VERIFIED no RoPA or DPIA document exists in Pipeline/ (find -iname ropa/dpia = none). generate-data-flow.sh claims 'Demo app does not process personal data' — that determination itself must be evidenced, not implied.
- **Definition of Done:** `docs/governance/ropa.yaml` (seed) + `schemas/ropa.schema.json` exist (Art.30(1) fields: controller, purposes, categories of data/subjects, recipients, third-country transfers, retention, security measures); `validate-ropa.py` asserts presence + per-activity completeness + a recorded DPIA determination (done|not-required-with-reason); emits `ropa-completeness.json` via T-33 envelope (BLOCKING on presence+schema).
- **Implementation notes:** jsonschema validation as in T-20. DPIA logic: if any activity has `high_risk: true` then a `dpia_ref` must be non-empty, else a documented `dpia_not_required_reason`. Wire into evidence-pack.yml before the matrix; sign output (T-30).
- **Acceptance criteria:**
  - `validate-ropa.py` exits 0 on the seeded RoPA and emits schema-valid `ropa-completeness.json`
  - An activity missing `retention` or `lawful_basis` makes it exit 1
  - A high_risk activity with no dpia_ref and no not-required-reason makes it exit 1
- **Verification:** `python3 scripts/validators/validate-ropa.py docs/governance/ropa.yaml schemas/ropa.schema.json && jq .status ropa-completeness.json`
- **Dependencies:** T-33
- **Maps to:** struktura §6 A.3; spec H.1/H.2; struktura §12 (RoPA/DPIA scattered)

#### T-23 — A.4 check-incident-register — schema + statutory-clock fields (DORA Art.17/NIS2 23/RODO 33)
- **Area:** compliance-as-code | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** struktura §6 A.4 requires that each incident-register entry carries a classification and the reporting-clock fields (4h/24h/72h) and that the procedure maps statutory thresholds → incident-readiness.json. The runbook already encodes the correct DORA Art.19 three-phase clock (incident-response.md:16-34) and the DAST workflow auto-creates incident issues with an SLA block (dast.yml:137-165) — but nothing validates a register's schema.
- **Current state:** VERIFIED incident-response.md:16-34 has the clock + classification (:42-52); dast.yml:137-165 embeds Triage-4h/Fix-48h/Deploy-72h; no schema validator exists.
- **Definition of Done:** `docs/governance/incident-register.yaml` (seed) + `schemas/incident-register.schema.json` (fields: id, detection_ts, classification_ts, severity, major_bool, clock {initial_4h, early_warning_24h, intermediate_72h, final_1mo}); `check-incident-register.py` asserts schema + every entry has classification + clock fields present/fillable; emits `incident-readiness.json` via T-33 (BLOCKING on schema, EVIDENCE-ONLY on count).
- **Implementation notes:** Optionally cross-check that open GitHub issues labelled `security-incident` (created by dast.yml) have a matching register entry (EVIDENCE-ONLY). Threshold mapping table comes from incident-response.md §3. Note the actual filing to KNF/CSIRT is a human act (struktura §14 / blueprint/04 §9) — validator checks readiness, not that a report was sent.
- **Acceptance criteria:**
  - `check-incident-register.py` exits 0 on the seeded register with all clock fields present
  - An entry missing `classification_ts` or a clock field makes it exit 1
  - `incident-readiness.json` records the entry count in `measured`
- **Verification:** `python3 scripts/validators/check-incident-register.py docs/governance/incident-register.yaml && jq .status incident-readiness.json`
- **Dependencies:** T-33
- **Maps to:** struktura §6 A.4; spec G.3/G.4; blueprint/04 §6.2 (SLA timer is sibling)

#### T-26 — A.7 check-thirdparty-clauses — Art.30 clause checklist + tested exit plans (DORA 28-30)
- **Area:** compliance-as-code | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** DORA Art.28-30 require, per critical vendor, the mandatory contractual clauses (audit rights, sub-outsourcing, exit) plus a documented and tested exit strategy (Art.28(8)). struktura §6 A.7 = presence → tpp-clauses.json. blueprint/02:43 confirms the clause checklist (ict-third-party-contract-controls.md) and exit-plan template are 'genuinely strong governance templates' — exactly what a bank asks the vendor to produce.
- **Current state:** VERIFIED ict-third-party-contract-controls.md (full Art.28-30 checklist) + vendor-exit-plan-template.md exist; vendor-risk-register Exit Plan Ref column (:62-71) shows several as 'Planned'/'Template available' (not operated/tested) — a real partial-FAIL to surface honestly.
- **Definition of Done:** `check-thirdparty-clauses.py` joins vendor-risk-register Criticality (col) with the Exit Plan Reference status table; FAIL if any Critical/High vendor's exit plan status is template-only/Planned (not Documented/Tested); asserts ict-third-party-contract-controls.md is present and within cadence; emits `tpp-clauses.json` via T-33 (BLOCKING on Critical-vendor exit-plan completeness, EVIDENCE-ONLY otherwise).
- **Implementation notes:** Reuse T-33 `gfm_table` on both the Vendor Inventory and Exit Plan References tables; map Criticality∈{Critical,High} → requires status∈{Documented,Tested}. Honest: validator checks the exit plan is DOCUMENTED+TESTED-flag, not that an exit was actually executed (blueprint/04 §9).
- **Acceptance criteria:**
  - On current data, Azure (EP-002 'Planned', Criticality Critical) makes it FAIL with the vendor named
  - Marking EP-002 'Tested' flips that vendor to PASS
  - `tpp-clauses.json` lists each Critical/High vendor with its exit-plan status
- **Verification:** `python3 scripts/validators/check-thirdparty-clauses.py docs/governance/ && jq '.status, .measured' tpp-clauses.json`
- **Dependencies:** T-33
- **Maps to:** struktura §6 A.7; spec F.2; blueprint/02 §3 Art.30 map

#### T-28 — A.9 assert-crypto — TLS min-version + at-rest/key-mgmt assertion vs IaC (NIS2 21(2)(h)/RODO 32)
- **Area:** compliance-as-code | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** struktura §6 A.9 = crypto+threshold — TLS enforced (min version/ciphers), at-rest encryption on, key-management proof → crypto-posture.json. This is a headline DORA Art.30(2)#3 fit (blueprint/02:84). The infra already enforces TLS1_2 and provisions Key Vault, but no check asserts the value meets a stated minimum, so a regression to TLS1_0 would pass silently.
- **Current state:** VERIFIED infra/modules/storage/main.tf:7 `min_tls_version = "TLS1_2"`; infra/main.tf:27 Key Vault module; no check reads or asserts these.
- **Definition of Done:** `assert-crypto.py` reads the Terraform plan/state (or HCL) for `min_tls_version`, at-rest encryption flag, and Key Vault presence; asserts min_tls_version >= TLS1_2 and at-rest enabled and a key-management resource present; emits `crypto-posture.json` via T-33 (BLOCKING on TLS threshold).
- **Implementation notes:** Prefer `terraform show -json` (consistent with T-24) over HCL parsing. Compare TLS as an ordered enum {TLS1_0<TLS1_1<TLS1_2<TLS1_3}. Record the measured version + key-vault name in `detail`. Wire alongside T-24 in deploy.yml (both consume the plan).
- **Acceptance criteria:**
  - PASS on current plan (TLS1_2, Key Vault present)
  - A plan with TLS1_0 makes it exit 1 naming the resource
  - `crypto-posture.json.measured` shows the actual TLS version
- **Verification:** `terraform -chdir=infra show -json tfplan > /tmp/p.json && python3 scripts/validators/assert-crypto.py /tmp/p.json && jq '.status,.measured' crypto-posture.json`
- **Dependencies:** T-33
- **Maps to:** struktura §6 A.9; spec H.4; blueprint/02 Art.30(2)#3

#### T-29 — A.10 check-restore-test — successful-restore proof + freshness (DORA Art.11-12)
- **Area:** compliance-as-code | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** struktura §6 A.10 + §12 require proof of a SUCCESSFUL restore test (not merely a backup) within the window, with RTO/RPO met → restore-test.json. 'Backups without a restore test' is a named auditor rejection trigger (struktura §12). bcdr-plan.md §6 has the schedule + RTO/RPO targets but the test status is honestly 'Not yet conducted' — the validator must FAIL on this, not mask it.
- **Current state:** VERIFIED bcdr-plan.md §6.1 test table shows `Last Tested: Not yet conducted` for the Terraform-state restore drill; RTO/RPO targets at §4. No validator.
- **Definition of Done:** `docs/runbooks/restore-test-log.yaml` (seed schema: test_date, scenario, rto_target, rto_actual, rpo_actual, outcome) + `check-restore-test.py` asserts ≥1 SUCCESSFUL restore within the cadence window and that rto_actual<=rto_target; emits `restore-test.json` via T-33 (BLOCKING). While 'Not yet conducted', it honestly FAILs.
- **Implementation notes:** Parse the YAML log; `passing = [t for t in tests if t['outcome']=='success' and days_since(t['test_date'])<=365 and t['rto_actual']<=t['rto_target']]`; FAIL if none. Do NOT auto-PASS from the schedule table alone — only a logged successful test counts. This is the honest opposite of file-presence.
- **Acceptance criteria:**
  - With no successful restore logged, exits 1 ('no successful restore test in window')
  - Adding a successful, in-window, RTO-met entry flips it to PASS
  - `restore-test.json` records last_successful_test_date in `measured`
- **Verification:** `python3 scripts/validators/check-restore-test.py docs/runbooks/restore-test-log.yaml; echo exit=$?; jq .status restore-test.json`
- **Dependencies:** T-33
- **Maps to:** struktura §6 A.10; spec E.3; struktura §12 (backup without restore)

#### T-36 — Author EBA Register-of-Information field mapping (roi.schema.json source-of-truth)
- **Area:** compliance-as-code | **Priority:** P1 | **Milestone:** M2 | **Effort:** S | **Owner:** external
- **Context:** validate-roi (T-20) validates against schemas/roi.schema.json, but that schema is only credible if its field list matches the current EBA ITS 2024/2956 / KNF SPR-PF-18 template (RT.01/RT.05). blueprint/04 A16 flags this as the one item needing external regulatory confirmation. HONESTY: building a schema from a guessed field list would be a new overclaim; this task pins it to the real template.
- **Current state:** VERIFIED no roi.schema.json exists; the only RoI source is the Markdown vendor-risk-register.md (no LEI, no EBA field mapping).
- **Definition of Done:** A confirmed field-mapping document (`schemas/roi-fields.md`) listing each EBA RT.01/RT.05 mandatory field, its meaning, and the source register column, signed off by a compliance advisor or cross-checked against the published ITS template; roi.schema.json (T-20) is generated from it.
- **Implementation notes:** Source: EUR-Lex ITS (EU) 2024/2956 templates + KNF SPR-PF-18. Capture which fields are mandatory vs conditional and which require LEI/EUID. This is research/regulatory, not code.
- **Acceptance criteria:**
  - Every mandatory RT.01/RT.05 field appears in roi-fields.md with its register-column mapping
  - LEI and substitutability/exit-plan fields are explicitly marked mandatory for critical providers
  - roi.schema.json's `required` array derives 1:1 from this document
- **Verification:** `test -f schemas/roi-fields.md && jq -e '.required|length>0' schemas/roi.schema.json`
- **Dependencies:** none
- **Maps to:** struktura §6 A.1; blueprint/04 A16; spec §16 (ITS 2024/2956)

#### T-46 — Add locked=true WORM immutability behind var.lock_worm (Terraform)
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M2 | **Effort:** S | **Owner:** Szymon
- **Context:** The pack and audit document assert an 'immutable WORM archive … Tampering is detectable', but the Terraform ships the immutability policy UNLOCKED — the retention period can be shortened or the policy deleted by a Storage Account Contributor, so it is not true WORM. Blueprint §6.5-B; GTM-RESET §5 lists 'WORM policy moved to Locked' as a Grade-A item.
- **Current state:** VERIFIED. `infra/modules/storage/main.tf:32-37` sets `immutability_period_in_days` and `protected_append_writes_all_enabled = true` but has NO `locked = true` and no separate lock step. `generate-html-report.sh:851` asserts 'immutable WORM archive'.
- **Definition of Done:** A `var.lock_worm` (default false) gates `locked = true` on the immutability policy; production sets it true; documented that locking is irreversible and blocks container destroy.
- **Implementation notes:** In `infra/modules/storage/main.tf:32-37` add `locked = var.lock_worm` (azurerm v4 supports `locked` on `azurerm_storage_container_immutability_policy`). Add `variable "lock_worm" { type = bool; default = false }` to `infra/modules/storage/variables.tf`. Pass through from `infra/main.tf:36-44` (true for prod, false otherwise). Blueprint §6.5-B exact-fix.
- **Acceptance criteria:**
  - `terraform validate` passes with the new variable.
  - `terraform plan` with `lock_worm=true` shows `locked = true` on the immutability policy.
  - Default (false) keeps non-prod destroyable.
- **Verification:** `cd Pipeline/infra && terraform validate && terraform plan -var='lock_worm=true' 2>/dev/null | grep -q 'locked .* true' && echo WORM_LOCK_OK`
- **Dependencies:** none
- **Maps to:** blueprint §6.5-B; spec Part I.3; GTM-RESET §5; struktura A.5

#### T-48 — Build A.5 assert-retention validator (retention/immutability vs Terraform) into compliance gate
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** struktura §6 A.5 ('Asercja polityki retencji i niezmienialności vs IaC/Terraform', table row `assert-retention`, threshold check vs IaC, DORA Art.12 / NIS2 21(2)(c) / ISO 8.16) requires a validator that reads the actual Terraform immutability + retention config and asserts ≥5y AND locked, emitting `retention-policy.json` with a signed PASS/FAIL into the compliance gate. Currently retention is only an abstract OPA rule with no Terraform input.
- **Current state:** VERIFIED. `policies/retention-policy.rego:5-26` checks `input.retention_days >= 1825`, `worm_enabled == true`, `deletion_schedule != ""`, but nothing feeds it the real Terraform values — `retention-policy_test.rego` only uses hand-written input. No `assert-retention` script reads `infra/modules/storage/*.tf`.
- **Definition of Done:** A validator parses the Terraform storage config (immutability_period_days, locked, retention_days, versioning) and produces `retention-policy.json` with PASS/FAIL, fed into the OPA retention policy and the compliance gate.
- **Implementation notes:** Create `Pipeline/scripts/assert-retention.py` (or .sh) that reads `infra/modules/storage/main.tf` + `variables.tf` (or `terraform show -json` plan output) and emits `{retention_days, worm_enabled, worm_locked, deletion_schedule}` as `retention-policy.json`; pipe into `opa eval -d policies/retention-policy.rego`. Extend retention-policy.rego to also require `worm_locked == true` for production (gated). Wire as compliance-as-code A.5 into the (cross-stream) compliance gate. struktura A.5, table row assert-retention.
- **Acceptance criteria:**
  - `retention-policy.json` is generated from real Terraform values.
  - `opa eval` against it returns deny=[] when retention≥1825 and (prod) locked=true.
  - A retention_days<1825 in Terraform produces a FAIL.
- **Verification:** `cd Pipeline && python3 scripts/assert-retention.py infra/modules/storage > /tmp/retention-policy.json && opa eval -d policies/retention-policy.rego -i /tmp/retention-policy.json 'data.compliance.retention.compliant' | grep -q true && echo A5_RETENTION_OK`
- **Dependencies:** T-46
- **Maps to:** struktura §6 A.5, table assert-retention; spec Part I.3; blueprint §6.5-B

#### T-51 — Add Rekor inclusion verification for SBOM attestation + Merkle bundle to verify runbook
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** Spec §7.2 / Part I.2 and struktura I.2 require Rekor transparency-log proofs ('who signed what, when' survives key disposal) for SBOM, provenance and the signed Merkle root. The pipeline signs keylessly (which logs to Rekor) but the verify runbook never independently confirms Rekor inclusion, so the 'Rekor-verifiable' claim is unproven in the deliverable.
- **Current state:** VERIFIED. `verify-evidence-pack.sh:176-224` runs `cosign verify-blob --bundle` (which checks the bundle's embedded Rekor entry) but emits no explicit Rekor-inclusion line; image-level `cosign verify` in `sign-and-attest.yml:125-134` does not assert Rekor inclusion separately. The README claims 'Cosign → Fulcio/Rekor' (`:41-42`) without a verification step proving it.
- **Definition of Done:** verify-evidence-pack.sh asserts Rekor inclusion for the Merkle bundle, pdf bundle, and the image SBOM attestation, emitting explicit PASS/FAIL lines.
- **Implementation notes:** In `Pipeline/scripts/verify-evidence-pack.sh`, after the cosign verify-blob block, add `cosign verify-blob --bundle … --rekor-url https://rekor.sigstore.dev` (or parse the bundle's `rekorBundle`/`tlogEntries` and confirm a logIndex/integratedTime). For the SBOM attestation add a `cosign verify-attestation --type cyclonedx` step in the workflow. Emit a `pass`/`fail` line per artifact. Spec §7.2, Part I.2; struktura I.2.
- **Acceptance criteria:**
  - The runbook prints an explicit 'Rekor inclusion verified' PASS for the Merkle bundle.
  - A tampered bundle (no Rekor entry) produces a FAIL.
- **Verification:** `cd Pipeline && COSIGN_IDENTITY=$COSIGN_IDENTITY COSIGN_ISSUER=https://token.actions.githubusercontent.com bash scripts/verify-evidence-pack.sh evidence | grep -i rekor`
- **Dependencies:** T-40
- **Maps to:** spec §7.2, Part I.2; struktura I.2; blueprint integrity-chain class

#### T-62 — Wire retention-policy.rego against the live Terraform plan in deploy.yml
- **Area:** OPA | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** retention-policy.rego holds the only DORA-specific number (1825 days) but no workflow executes it, so a regression shortening retention would ship undetected (VERIFIED policies/retention-policy.rego:5; COMPANY-AUDIT note that the 1825 constant 'lived in a policy no workflow executed'). blueprint 04 §4.2/§6.1 connects it to live infra state. This is a genuine regulation-unique check (DORA Art.12 / RODO Art.5.1.e).
- **Current state:** VERIFIED retention-policy.rego:5-26 (>=1825 days, worm_enabled, non-empty deletion_schedule) + 3 passing tests; Terraform sets immutability_period_days=1825 & retention_days=1825 (infra/modules/storage/variables.tf:16-26) but deploy.yml never feeds them to OPA.
- **Definition of Done:** A named step `OPA retention policy (blocking)` in deploy.yml runs `terraform show -json tfplan`, extracts immutability/retention via a new `scripts/tfplan-to-retention-input.py`, evaluates `data.compliance.retention.deny`, and exits 1 on any deny.
- **Implementation notes:** New `scripts/tfplan-to-retention-input.py` walks `planned_values` for `azurerm_storage_container_immutability_policy.immutability_period_in_days` and the lifecycle delete, emits `{retention_days, worm_enabled, deletion_schedule}`. Step: `terraform show -json tfplan > /tmp/tfplan.json; python3 ../scripts/tfplan-to-retention-input.py /tmp/tfplan.json > /tmp/ret-input.json; DENY=$(opa eval -d ../policies/retention-policy.rego -i /tmp/ret-input.json 'data.compliance.retention.deny' --format raw); [ "$(echo "$DENY" | jq 'length')" -eq 0 ] || { echo "::error::$DENY"; exit 1; }`. Depends on T-74 so the plan reflects the REAL remote backend, not ephemeral local state. blueprint 04 §4.2 + §6.1.
- **Acceptance criteria:**
  - deploy.yml contains a step named `OPA retention policy (blocking)` after Terraform plan
  - A plan with immutability_period_in_days=365 makes the step exit non-zero
  - The current 1825/1825 plan passes truthfully
- **Verification:** `python3 scripts/tfplan-to-retention-input.py fixtures/tfplan-short.json | opa eval -d policies/retention-policy.rego -i /dev/stdin 'data.compliance.retention.deny' --format raw | jq 'length'` >0
- **Dependencies:** T-74
- **Maps to:** blueprint 04 §4.2, §6.1; spec §4 Policy gate / §7 immutability; struktura A.5

#### T-73 — Aggregate OPA results into a signed compliance-gate report in evidence
- **Area:** OPA | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** struktura §6 specifies a compliance gate that aggregates check results into ONE signed PASS/FAIL state report embedded in the pack. The 3 OPA evaluations (T-60..T-62) currently would just gate inline; their verdicts must also be captured as signed evidence so an auditor can read 'which policy passed/failed, when, over what input'. spec §4 'Admission audit report'.
- **Current state:** INFERENCE: with T-60..T-62 the OPA deny outputs gate the pipeline but are not written to a durable, signed artifact; no policy-results JSON exists today (VERIFIED 0 OPA refs in workflows).
- **Definition of Done:** Each `opa eval` writes its full result (`{policy, input, allow/deny, evaluated_at}`) to `evidence/policy-results/<policy>.json`; a consolidator emits `evidence/compliance-gate.json` with overall PASS/FAIL; the file(s) are sealed/signed via the existing flow.
- **Implementation notes:** Replace `--format raw` deny-only evals with `opa eval ... 'data.compliance.<pkg>' --format json > evidence/policy-results/<pkg>.json`; a small consolidator computes overall status and writes compliance-gate.json. Add compliance-gate.json to the evidence-completeness required set (coordinate with T-61). Sealed by seal-evidence so it carries the manifest digest + timestamp.
- **Acceptance criteria:**
  - evidence/policy-results/ contains one JSON per wired policy with the actual input + verdict
  - evidence/compliance-gate.json carries an overall PASS/FAIL and is covered by the manifest
  - A denied policy makes compliance-gate.json overall=FAIL
- **Verification:** `jq '.overall' evidence/compliance-gate.json` returns PASS on a clean run; `grep compliance-gate.json evidence/manifest.sha256` matches
- **Dependencies:** T-60, T-61, T-62
- **Maps to:** struktura §6 compliance gate; spec §4 admission audit report

#### T-101 - Gate firm README crypto wording on the Merkle-cosign fix
- Area: CLAIMS/DOCS | P1 | M2 | S | Szymon
- Context: README crypto claims (T-100) can only be firm once the Merkle root is cosign-signed every run. The fix lives in the integrity stream (write merkle-root.txt before the cosign step; CI precondition that the bundle exists). Source blueprint/06 6.2-A + remediation 1.
- Current state: VERIFIED the Merkle cosign bundle is never created (blueprint/06 6.2-A lines 195+). Fix owned by the integrity stream; this gates the README revert.
- DoD: After the integrity fix is verified (bundle present, a Merkle pass line), restore firm README wording with the QTS-upgrade note.
- Notes: README revert only; reference the integrity stream 6.2-A task. Confirm via evidence-pdf-test.yml the bundle appears.
- Acceptance: Firm wording restored ONLY after the bundle provably exists; QTS note (T-110) remains.
- Verification: integrity run produces merkle-root.cosign.bundle and a Merkle pass line; README shows restored wording.
- Deps: none
- Maps to: blueprint/06 6.2-A + remediation 1; spec 7.2

#### T-102 - Auto-generate a multi-framework crosswalk from real evidence
- Area: CLAIMS/DOCS | P1 | M2 | M | Szymon
- Context: Spec 5.2 and struktura D.2 require a crosswalk where one evidence item maps to many clauses (DORA, NIS2-KSC, GDPR, CRA, ISO27001, NIST CSF 2.0, SSDF), generated from the actual evidence set. The current generator is presence-only and single-framework. Source spec 5.2; struktura 8/D.2.
- Current state: VERIFIED no crosswalk emitter maps one artifact to many clauses from real state; compliance-matrix.md 8 is static; compliance-matrix.json is presence-only (6.1.3).
- DoD: scripts/generate-crosswalk reads evidence + each artifact PASS/present and emits crosswalk.json + a framework-column table from one mapping; only present+PASS satisfied.
- Notes: scripts/crosswalk-mapping.yaml keyed by artifact per spec 5.2 rows; join with presence+PASS; wire into evidence-pack.yml.
- Acceptance: crosswalk.json has at least 1 row spanning at least 3 frameworks, satisfied only when present AND PASS; one mapping file; no clause for a missing artifact.
- Verification: full-pack fixture first row lists at least 3 frameworks; a missing-SBOM fixture marks that row unsatisfied.
- Deps: none
- Maps to: spec 5.2; struktura D.2/8; spec 9 L3

#### T-105 - Fix lifecycle-delete WORM footgun
- Area: IaC | P1 | M2 | S | Szymon
- Context: The lifecycle policy deletes evidence at the SAME age as the WORM period, driven by a second var both defaulting 1825; no guard, so immutability_period_days 0 would delete the only WORM-less copy. Source blueprint/06 6.5-A + remediation 9.
- Current state: VERIFIED storage/main.tf:40-59 sets delete_after_days from var.retention_days default 1825; WORM uses var.immutability_period_days default 1825 with a count guard. No precondition ties them.
- DoD: One source of truth; lifecycle delete removed (preferred) OR strictly greater than immutability_period_days with a precondition forbidding 0 when delete present; tiering preserved.
- Notes: Per remediation 9 drop delete_after_days keeping tier_to_cool; if needed use immutability_period_days+30 + a precondition. One variable.
- Acceptance: One retention var governs both; plan with immutability_period_days 0 + delete present fails the precondition.
- Verification: terraform validate + plan with immutability_period_days 0 errors on the precondition or shows no delete.
- Deps: T-104
- Maps to: blueprint/06 6.5-A + remediation 9; spec 7.5

#### T-115 — Generate a versioned, signed threat-model artifact (STRIDE) and validate it in the pack (spec Part C.1)
- **Area:** Compliance/Evidence | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** The Evidence Pack master spec lists a threat model as a required Part C row (evidence-pack-specification.md:135 + struktura:155: 'NIS2 21(2)(e); DORA RTS 2024/1774; ISO 8.25; SSDF PW.1 — exists per critical feature; risks traced to controls'). It is also a §4 pipeline stage ('Plan / threat-model · must emit threat model · rejected when one stale doc for the whole app'). VERIFIED there is no threat-model artifact in the repo, so the pack cannot answer the first DevSecOps stage. Every other Part C row has a task; this one had none.
- **Current state:** VERIFIED no threat-model file exists — `git -C Pipeline ls-tree -r --name-only HEAD | grep -iE 'threat|stride|linddun'` returns nothing; build-audit-document.py has no threat-model section.
- **Definition of Done:** A maintained `docs/governance/threat-model.yaml` (per critical feature: asset, STRIDE category, threat, mitigating control-ref) exists; a validator `scripts/validators/threat_model.py` asserts every entry has a non-empty `control_ref` and the file's `last_reviewed` is within a stated window; the threat model is rendered into the audit PDF and included in the manifest + Merkle root so it is signed at production.
- **Implementation notes:** Author `Pipeline/docs/governance/threat-model.yaml` keyed by feature (e.g. items API, build-info endpoint). Add `scripts/validators/threat_model.py` emitting the shared `{status,tier,measured,threshold,detail}` envelope (tier EVIDENCE-ONLY for content, BLOCKING-on-schema). Wire its output into `generate-compliance-matrix.sh` as the NIS2 21(2)(e)/ISO 8.25 secure-design row and into `evidence-pack.yml` before the manifest step so the file is hashed into the Merkle root. Maps to spec §3 C row 'Threat model' and §4 stage 'Plan / threat-model'.
- **Acceptance criteria:**
  - `threat-model.yaml` exists with >=1 entry per critical feature and every entry has a control_ref.
  - `threat_model.py` exits non-zero on a missing control_ref or schema violation.
  - The threat model appears in `manifest.json` artifact list and is committed-to by the Merkle root.
- **Verification:** `python3 Pipeline/scripts/validators/threat_model.py Pipeline/docs/governance/threat-model.yaml && grep -q threat-model Pipeline/scripts/generate-compliance-matrix.sh`
- **Dependencies:** T-12, T-33
- **Maps to:** spec Part C.1; evidence-pack-specification.md:135 §4 stage 'Plan/threat-model'; struktura:155

#### T-116 — Generate a per-release VEX (OpenVEX) bound to the SBOM and signed (spec Part C.11)
- **Area:** Supply-chain/Integrity | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** The master spec lists VEX as a required Part C.11 artifact ('Exploitability triage · CycloneDX/CSAF 2.0/OpenVEX · CRA vuln-handling · not_affected claims justified (CISA categories) · sign; per-release', evidence-pack-specification.md:145 + struktura:166). Spec §8 anti-pattern: 'no VEX, so every CVE looks unhandled' is a documented rejection trigger and §9 maturity puts VEX triage at L5. VERIFIED the pipeline generates NO VEX: 'VEX' appears only as a glossary term (build-audit-document.py:1502) and a remediation note (generate-html-report.sh:1002). Without a VEX, every triaged/non-exploitable CVE reads as an open finding to an auditor.
- **Current state:** VERIFIED no VEX document is produced — grep for `vex|openvex|csaf` across scripts/ and workflows finds only the glossary string and the HTML remediation note; no `*.vex.json` artifact and no creator.
- **Definition of Done:** The pipeline emits `evidence/vex.openvex.json` per release listing each triaged CVE with a CISA-category justification (component_not_present / vulnerable_code_not_in_execute_path / etc.); the VEX references the SBOM and the image digest; it is signed (cosign sign-blob) and included in the manifest/Merkle root; a validator asserts every `not_affected`/`fixed` statement carries a non-empty justification.
- **Implementation notes:** Add `scripts/generate-vex.py` reading `evidence/trivy-image-results.json` + `evidence/trivy-sca-results.json` + the SBOM digest, emitting an OpenVEX 0.2 doc (`@context`, `author`, `statements[]` with `vulnerability`, `products` (= image digest), `status`, `justification`). Source justifications from a maintained `docs/governance/vex-justifications.yaml` (never auto-invent). Sign the output in `evidence-pack.yml` alongside the other blobs. Add `scripts/validators/vex.py` (BLOCKING: any status not in {affected} requires a justification). Maps to spec §3 C.11 + §8 anti-pattern 'no VEX'.
- **Acceptance criteria:**
  - `evidence/vex.openvex.json` is generated and references the deployed image digest.
  - Every non-`affected` statement has a CISA-category justification or the validator fails.
  - The VEX is present in `manifest.json` and committed-to by the Merkle root.
- **Verification:** `python3 Pipeline/scripts/generate-vex.py && python3 Pipeline/scripts/validators/vex.py evidence/vex.openvex.json`
- **Dependencies:** T-15, T-49
- **Maps to:** spec Part C.11; evidence-pack-specification.md:145 §8 anti-pattern 'no VEX'; struktura:166

#### T-117 — Add a CSPM / cloud-posture scan (CIS-mapped) emitting a signed evidence artifact (spec Part C.14)
- **Area:** Cloud/Posture | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** The master spec requires a Cloud posture (CSPM) Part C.14 row ('Cloud configured to benchmark · Prowler/Custodian · NIS2 21(2)(i); DORA 9; CIS/ISO 8.9 · CIS Foundations mapped; criticals remediated; drift alerted', evidence-pack-specification.md:149 + struktura:170). Spec §4 rejects 'point-in-time screenshot from audit week'. VERIFIED the only cloud-posture content is 'design-stage' / 'pending' prose in build-audit-document.py:1351,1423,1427 — no CSPM scan runs and no artifact is produced, so the pack overclaims a posture it cannot show.
- **Current state:** VERIFIED no CSPM scan exists — grep for `cspm|prowler|cis.?benchmark|cloud.?posture|drift` over scripts/ and workflows finds only build-audit-document.py 'design-stage' text; no posture artifact and no creator.
- **Definition of Done:** A scan step (e.g. Prowler for Azure, SHA-pinned per the repo's 100% pin policy) runs against the deployed subscription/resource-group via the existing OIDC identity, emits `evidence/cloud-posture.json` mapped to CIS Azure Foundations, is signed and added to the manifest/Merkle root, and a validator records the CRITICAL-misconfig count (BLOCKING on CRITICAL for production runs, EVIDENCE-ONLY otherwise). Until the scan is wired, the audit-document CSPM wording is relabeled 'design-stage (no live scan)' so the doc never overclaims.
- **Implementation notes:** Add a `cloud-posture` job to `deploy.yml` (post-apply) or a scheduled `cloud-posture.yml` using OIDC (no static secrets, consistent with deploy.yml). Run Prowler scoped to the resource group; convert its output to a consolidated `cloud-posture.json` with `{cis_control, status, severity}` rows. Add `scripts/validators/cloud_posture.py` (envelope per T-33). If a live scan is not feasible immediately, the SAME task must relabel build-audit-document.py:1351/1423/1427 to remove the implied live posture (honesty constraint). Maps to spec §3 C.14 + §4 stage 'Runtime/cloud posture'.
- **Acceptance criteria:**
  - `evidence/cloud-posture.json` is produced from a real scan OR the audit-document CSPM rows are relabeled 'design-stage'.
  - CIS-mapped rows present; CRITICAL count surfaced into the matrix detail.
  - Artifact signed and in the Merkle root when a live scan runs.
- **Verification:** `python3 Pipeline/scripts/validators/cloud_posture.py evidence/cloud-posture.json` (or, if relabel path, `! grep -niE 'live drift|design-stage pending' Pipeline/scripts/build-audit-document.py` shows wording corrected)
- **Dependencies:** T-74
- **Maps to:** spec Part C.14; evidence-pack-specification.md:149 §4 'Runtime/cloud posture'; struktura:170

#### T-120 — Produce a machine-validated, signed scope & applicability determination (spec Part B / Part 0.4)
- **Area:** Compliance/Evidence | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** The master spec dedicates Part B to Scope & applicability (B.1 entity classification DORA/NIS2/CRA; B.2 system+data inventory, data-flow & residency map; B.3 regulatory applicability matrix with rationale; evidence-pack-specification.md:61-64 + struktura Part 0.4 'Oświadczenie o stosowalności'). Spec §8 anti-pattern #10 'Scope hand-waving — no documented rationale for why DORA/NIS2/CRA do or don't apply' is an explicit rejection trigger. VERIFIED the pack only has narrative 'In scope' prose (build-audit-document.py:853); T-31 rewrites the data-flow heredoc but produces no applicability determination. No task makes the scope determination a structured, signed artifact.
- **Current state:** VERIFIED scope is narrative-only — build-audit-document.py:853 renders an 'In scope' section from prose; no `applicability.yaml`/`scope-determination.json` artifact exists; grep for `applicab|entity.?class|in.?scope` shows only NA-normalization helpers and the one prose heading.
- **Definition of Done:** A maintained `docs/governance/applicability.yaml` records, per regime (DORA/NIS2-KSC/CRA/RODO), `applies: true|false` with a `rationale` and a clause basis; a validator emits `evidence/scope-determination.json` (FAIL if any regime lacks a rationale), it is rendered into the pack's Part B, signed, and committed-to by the Merkle root.
- **Implementation notes:** Author `Pipeline/docs/governance/applicability.yaml` with the regimes and rationales from spec §6 (DORA->KNF, NIS2->KSC Dz.U.2026 poz.252, CRA, RODO). Add `scripts/validators/applicability.py` (BLOCKING: every regime needs `applies` + non-empty `rationale`). Wire into `evidence-pack.yml` before the matrix step; render into build-audit-document.py Part B replacing the prose heading. Reuse the data-flow YAML from T-31 for the B.2 residency map. Maps to spec Part B + §8 anti-pattern #10 + struktura Part 0.4.
- **Acceptance criteria:**
  - `applicability.yaml` covers DORA, NIS2-KSC, CRA, RODO each with applies+rationale.
  - `applicability.py` FAILs if any regime is missing a rationale.
  - `scope-determination.json` is signed and in the manifest/Merkle root.
- **Verification:** `python3 Pipeline/scripts/validators/applicability.py Pipeline/docs/governance/applicability.yaml`
- **Dependencies:** T-31, T-33
- **Maps to:** spec Part B; evidence-pack-specification.md:61-64 §8 anti-pattern #10; struktura Part 0.4

#### T-121 — Validate the risk-acceptance / exceptions log for named approver + expiry and emit a residual-risk statement (spec Part J.2 / D.4)
- **Area:** Compliance/Evidence | **Priority:** P1 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** The master spec requires Part J.2 (Risk-acceptance / exceptions log 'with named approver, justification, and expiry date — Unbounded accepted risks are a rejection trigger', evidence-pack-specification.md:219 + struktura:229) and Part D.4 (Residual-risk statement signed by the accountable officer, tied to board risk tolerance DORA 5(2), evidence-pack-specification.md:220). Spec §8 anti-pattern #5 'Unbounded risk acceptances — no approver, no expiry' is a documented rejection trigger and is in the coverage checklist with NO task. VERIFIED `docs/compliance/exception-register.md` and `docs/governance/risk-acceptance-process.md` exist in HEAD, but no validator checks them and no residual-risk artifact is generated.
- **Current state:** VERIFIED the exception register exists (git ls-tree HEAD shows docs/compliance/exception-register.md + .github/ISSUE_TEMPLATE/risk-acceptance.yml + docs/governance/risk-acceptance-process.md) but is never read by a pipeline check; no residual-risk statement artifact exists.
- **Definition of Done:** A validator parses the exception register and FAILs on any acceptance lacking a named approver, justification, or future expiry (or already expired); a `residual-risk.json` is emitted summarizing open accepted risks + residual posture; both are signed and in the Merkle root; the validator feeds the matrix risk-acceptance row.
- **Implementation notes:** Add `scripts/validators/risk_acceptance.py` parsing the GFM table in `docs/compliance/exception-register.md` (columns: id, control, approver, justification, accepted_date, expiry). BLOCKING: any row with empty approver/justification/expiry OR `expiry < today` -> FAIL. Emit `evidence/residual-risk.json` aggregating still-open acceptances. Wire into the compliance gate (T-30) and render Part J.2 + D.4 in build-audit-document.py. Maps to spec Part J.2/D.4 + §8 anti-pattern #5.
- **Acceptance criteria:**
  - `risk_acceptance.py` FAILs on any acceptance missing approver/justification/expiry or already expired.
  - `residual-risk.json` lists open accepted risks and is signed + in the manifest.
  - The risk-acceptance row appears in the compliance matrix output.
- **Verification:** `python3 Pipeline/scripts/validators/risk_acceptance.py Pipeline/docs/compliance/exception-register.md`
- **Dependencies:** T-30, T-33
- **Maps to:** spec Part J.2 + D.4; evidence-pack-specification.md:219-220 §8 anti-pattern #5; struktura:229

#### T-45 — Scope what SLSA Build L3 would require (roadmap document, not a claim)
- **Area:** Integrity chain | **Priority:** P2 | **Milestone:** M2 | **Effort:** S | **Owner:** Szymon
- **Context:** The spec target (struktura A/§5, evidence-pack-specification §3 row 'Build provenance') sets 'SLSA Build L2+ (L3 target)'. To move the claim toward true (not toward marketing), L3 needs an explicit, scoped gap analysis so the roadmap is honest and the difference between current L2 and target L3 is documented for buyers and auditors.
- **Current state:** VERIFIED. No document defines the L3 gap. `build-audit-document.py:58` only says L3 is not claimed because 'provenance generation is best-effort and not demonstrably isolated from the build job' — the kernel of the gap, but not a full scoping.
- **Definition of Done:** A concise L3-gap section exists (in docs or Part I appendix) listing each SLSA L3 requirement the pipeline does NOT yet meet and the concrete change to meet it.
- **Implementation notes:** Document the L3 deltas: (1) provenance generated by a hosted/isolated build platform the tenant cannot influence (GitHub-hosted reusable workflow with provenance from `actions/attest-build-provenance` as primary, not fallback); (2) non-falsifiable provenance (signing keys not accessible to build steps); (3) builder identity ref-pinned (ties to T-50). Map to slsa.dev v1.0 Build L3 track. Keep it a roadmap, not a claim. Spec §3 'Build provenance' row, struktura row C.12.
- **Acceptance criteria:**
  - A document enumerates each L3 requirement and the gap vs current state with file references.
  - It explicitly states the pipeline is L2 today.
- **Verification:** `test -f Pipeline/docs/slsa-l3-gap.md && grep -qi 'isolated\|non-falsifiable\|builder.id' Pipeline/docs/slsa-l3-gap.md && echo L3_SCOPE_OK`
- **Dependencies:** T-44
- **Maps to:** spec §3 Build provenance, struktura C.12; blueprint K5

#### T-52 — Remove lifecycle-delete retention footgun and add single-source-of-truth guard
- **Area:** Integrity chain | **Priority:** P2 | **Milestone:** M2 | **Effort:** S | **Owner:** Szymon
- **Context:** The lifecycle policy schedules evidence-blob DELETION at the same age as the WORM immutability period, driven by a second independent variable with no guard tying it to the WORM count — if `immutability_period_days` is ever set to 0, the lifecycle rule would delete the only copy at day 1825 with no WORM protecting it. Blueprint §6.5-A (config-hardening footgun).
- **Current state:** VERIFIED. `infra/modules/storage/main.tf:40-59` sets `delete_after_days_since_modification_greater_than = var.retention_days` (default 1825) on prefix `evidence-packs/`; the WORM policy (`:32-37`) uses `var.immutability_period_days` (default 1825) gated by `count = var.immutability_period_days > 0 ? 1 : 0`. Two independent 1825 vars, no precondition linking them.
- **Definition of Done:** Either the lifecycle delete action is removed (WORM + legal hold govern deletion) or it fires strictly after the immutability period; a precondition forbids `immutability_period_days == 0` when the delete action is present; both retention numbers derive from one variable.
- **Implementation notes:** In `infra/modules/storage/main.tf:40-59`, remove `delete_after_days_since_modification_greater_than` (keep `tier_to_cool`/archive) OR set it to `var.immutability_period_days + 30`. Add a `lifecycle { precondition { condition = var.immutability_period_days > 0 … } }` or a `check` block. Collapse `retention_days`/`immutability_period_days` to one source. Blueprint §6.5-A exact-fix.
- **Acceptance criteria:**
  - `terraform validate` passes.
  - With `immutability_period_days=0` and a delete action present, plan fails the precondition.
  - No unconditional delete at the same day as the WORM period.
- **Verification:** `cd Pipeline/infra && terraform validate && terraform plan -var='immutability_period_days=0' 2>&1 | grep -qi 'precondition\|error' && echo RETENTION_GUARD_OK`
- **Dependencies:** T-46
- **Maps to:** blueprint §6.5-A; spec Part I.3; struktura A.5

#### T-53 — Make TSA pluggable and document path to a qualified eIDAS QTS (KIR Szafir / Certum)
- **Area:** Integrity chain | **Priority:** P2 | **Milestone:** M2 | **Effort:** M | **Owner:** Szymon
- **Context:** Legally-facing artifacts (board approvals, incident reports, attestations) require a QUALIFIED electronic timestamp from an eIDAS qualified trust service provider for admissible non-repudiation (spec §7.3, §6.5; struktura §11). The pipeline currently only uses freetsa.org — a free, non-qualified TSA. The path to a Polish/EU QTS (KIR Szafir, Asseco Certum, EuroCert, CenCert) must be a configurable, documented option, not a hardcoded free TSA.
- **Current state:** VERIFIED. `seal-evidence.sh:39` hardcodes `TSA_URL="${TSA_URL:-https://freetsa.org/tsr}"` (overridable but defaulting to a non-qualified TSA). evidence-pack.yml:327 sets the same freetsa URL. No qualified-QTS provider config, no per-artifact distinction between informational vs legally-facing timestamps.
- **Definition of Done:** TSA endpoint + CA chain + (optional) auth are fully parameterized; a documented procedure exists to point at a qualified Polish/EU QTS; the manifest records whether the timestamp was qualified or not (honest label).
- **Implementation notes:** Keep `TSA_URL` overridable; add `TSA_CA_FILE`, `TSA_AUTH` (basic/token) and `TSA_QUALIFIED` (bool) env vars consumed by `rfc3161_stamp` in `seal-evidence.sh:361-399`; record `qualified=true|false` into `signatures.rfc3161`. Document in Part I.1 a tested config for KIR Szafir / Certum QTS endpoints (most are authenticated, paid). Do NOT claim QTS until actually wired to a qualified provider. Spec §7.3, §6.5; struktura §11.
- **Acceptance criteria:**
  - `seal-evidence.sh` accepts a custom TSA URL + CA chain + auth and records `qualified` honestly in the manifest.
  - A doc lists at least one qualified Polish/EU QTS provider with endpoint/auth requirements.
  - With freetsa, the manifest records `qualified=false`.
- **Verification:** `cd Pipeline && TSA_URL=https://freetsa.org/tsr EVIDENCE_ALLOW_DEGRADE=1 bash scripts/seal-evidence.sh evidence evidence/evidence-report.pdf evidence/manifest.json; python3 scripts/_manifest_sig_helper.py evidence/manifest.json get signatures.rfc3161 | grep -qi 'qualified' && echo QTS_LABEL_OK`
- **Dependencies:** none
- **Maps to:** spec §7.3, §6.5 (eIDAS QTS, KIR Szafir/Certum); struktura §11; Part I.1

#### T-54 — Ship TSA CA chain so openssl ts -verify fully validates RFC-3161 tokens
- **Area:** Integrity chain | **Priority:** P2 | **Milestone:** M2 | **Effort:** S | **Owner:** Szymon
- **Context:** The verify runbook can only PARSE the RFC-3161 token, not fully verify it, because no TSA CA chain is shipped with the pack — so the timestamp's cryptographic validity is never independently confirmed by an auditor running the runbook. spec Part I.2 requires verifiable tamper-evidence proofs.
- **Current state:** VERIFIED. `verify-evidence-pack.sh:251-266`: when `tsa-ca.pem` is absent it falls back to `openssl ts -reply -in … -text` (parse-only) and emits SKIP, never PASS. The seal step does not fetch/ship the TSA CA chain.
- **Definition of Done:** The seal step fetches and includes the TSA CA chain (`tsa-ca.pem`) in the pack so the verify runbook performs full `openssl ts -verify -CAfile`.
- **Implementation notes:** In `seal-evidence.sh` Step 4, after a successful stamp, download the TSA's CA chain (provider-specific; for freetsa: `https://freetsa.org/files/cacert.pem` + `tsa.crt`) to `${EVIDENCE_DIR}/tsa-ca.pem`. Ensure it is included in the pack but excluded from the Merkle set if needed (it is added after manifest regen, which already re-hashes). Then `verify-evidence-pack.sh:252-258` upgrades the SKIP to a PASS/FAIL. Spec Part I.2.
- **Acceptance criteria:**
  - A sealed pack contains `tsa-ca.pem`.
  - `verify-evidence-pack.sh` prints PASS for `openssl ts -verify` (not SKIP) when a .tsr + CA are present.
- **Verification:** `cd Pipeline && bash scripts/verify-evidence-pack.sh evidence | grep -E 'openssl ts -verify' | grep -qi 'PASS' && echo TSA_VERIFY_OK`
- **Dependencies:** T-53
- **Maps to:** spec Part I.2; blueprint §6.4 gap #2 (RFC-3161 verify symmetry)

#### T-103 - Emit a gap register tied to the crosswalk
- Area: CLAIMS/DOCS | P2 | M2 | S | Szymon
- Context: Spec 5.3 requires a gap register (control to gap to severity to root cause); spec 8 #5 rejects unbounded risk acceptances. T-102 produces per-clause satisfied/unsatisfied. Source spec 5.3-5.4.
- Current state: VERIFIED no gap register artifact; compliance-matrix.md lists prose only.
- DoD: generate-crosswalk also emits gap-register.json with every unsatisfied clause + severity + root_cause; rendered into the pack.
- Notes: Gaps from unsatisfied rows; HARD clauses high else medium; root_cause from presence/PASS. Phase-F controls labelled not flagged.
- Acceptance: One row per unsatisfied clause; no satisfied clause is a gap.
- Verification: partial fixture length greater than 0; complete fixture length 0.
- Deps: T-102
- Maps to: spec 5.3-5.4; spec 8 #5

## M3 — Governance plumbing & self-tests  (25 tasks)

#### T-19 — Aggregate matrix + A.1-A.10 validators into one signed compliance-gate verdict (blocking)
- **Area:** Compliance-gate | **Priority:** P0 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** The spec requires A.1-A.10 organizational-control validators plus the matrix to aggregate into ONE signed compliance-status report that emits PASS/FAIL into a blocking compliance gate (struktura.md:201-218; spec C.13 admission control). Today there is no aggregated, blocking, signed compliance verdict — the matrix output is unsigned and non-blocking.
- **Current state:** VERIFIED no compliance-validate job exists; generate-compliance-matrix.sh output is consumed only by the warn-only completeness step (evidence-pack.yml:219) and OSCAL render (evidence-pack.yml:349); it is never signed as a standalone verdict nor used to fail the pipeline.
- **Definition of Done:** A `compliance-validate` job (in evidence-pack.yml or a new reusable workflow before it) runs all content validators (T-13..T-17) + any available A.1-A.10 validators, aggregates them into `compliance-status.json` with an overall PASS/FAIL + per-check list, fails the pipeline (non-PR) on any BLOCKING FAIL, and the report is cosign sign-blob'd into evidence (signing handled with/by the integrity-chain stream). Mirrors verify-evidence-pack.sh's accumulate-fail-count + exit-nonzero pattern (blueprint/04 §1.6).
- **Implementation notes:** New `scripts/aggregate-compliance.py` reading each validator's envelope; emit overall_status + counts; exit 1 on any BLOCKING FAIL (non-PR). Sign compliance-status.json via cosign sign-blob (coordinate with the seal-evidence/sign-and-attest owner). Wire as a `needs` of evidence-pack so an incomplete/failing compliance state blocks seal. Spec: struktura.md:201-218; spec Part C.13/D.
- **Acceptance criteria:**
  - One BLOCKING validator FAIL makes the compliance-validate job exit non-zero on non-PR.
  - compliance-status.json carries overall_status + per-check status/measured/tier.
  - A cosign signature/bundle exists over compliance-status.json.
- **Verification:** `python3 Pipeline/scripts/aggregate-compliance.py evidence/ ; echo $?` returns 1 when a BLOCKING row is FAIL; `cosign verify-blob --bundle compliance-status.cosign.bundle compliance-status.json` exits 0.
- **Dependencies:** T-12, T-13, T-14, T-15, T-16, T-17
- **Maps to:** struktura.md:201-218 (A.1-A.10 + compliance gate); spec Part C.13/D; blueprint/04 §1.6 (validator pattern)

#### T-64 — Add opa test + opa fmt CI job (policy self-test on push AND PR)
- **Area:** OPA | **Priority:** P0 | **Milestone:** M3 | **Effort:** S | **Owner:** Szymon
- **Context:** The master prompt requires pipeline self-tests including `opa test` green on push AND PR. VERIFIED 10/10 OPA tests pass locally (`opa test policies/ -v`) but no workflow runs them, so a policy edit that breaks a rule ships green. This is the cheapest self-defense for the policy layer that everything else (T-60..T-62) depends on.
- **Current state:** VERIFIED no workflow references `opa test`/`opa fmt` (grep over .github/workflows/ = 0); policies/*_test.rego carry 10 tests.
- **Definition of Done:** A workflow (new `policy-test.yml` reusable, called by pipeline.yml, or a job in security-gate.yml) installs OPA (SHA-pinned), runs `opa test policies/ -v` and `opa fmt --list policies/` (fail on unformatted), gating both `push` and `pull_request`.
- **Implementation notes:** `- uses: open-policy-agent/setup-opa@<SHA>` then `run: opa test policies/ -v` and `run: test -z "$(opa fmt -l policies/)" || { echo '::error::rego not formatted'; opa fmt -l policies/; exit 1; }`. Wire as a required status check in branch-protection.json (T-67). Keep permissions minimal (`contents: read`).
- **Acceptance criteria:**
  - A workflow runs `opa test policies/` on both push and PR events
  - Breaking a rule (e.g. flipping `>=` to `>`) turns the check red
  - Unformatted rego fails the job
- **Verification:** Open a PR that breaks deployment-gate.rego and confirm the `opa test` check is red; `gh run list --workflow policy-test.yml` shows runs on push+PR
- **Dependencies:** none
- **Maps to:** master prompt item 12 (pipeline self-tests); spec §4 Policy gate

#### T-67 — Apply + verify branch protection matches branch-protection.json
- **Area:** Governance | **Priority:** P0 | **Milestone:** M3 | **Effort:** S | **Owner:** Szymon
- **Context:** branch-protection.json documents 2 reviews + code-owner reviews + required_signatures + linear history + enforce_admins + 8 status-check contexts, and apply-branch-protection.sh translates it to the GitHub API, but the live config has never been independently verified (admin-only API, COMPANY-AUDIT:45) and is a core SLSA Source / SOC2 CC6.1 control. spec §4 requires '2-party review, no direct prod push' to be PROVABLE.
- **Current state:** VERIFIED Pipeline/.github/branch-protection.json:1-29 (2 reviews, dismiss_stale, code-owner, 8 contexts, required_signatures, linear history, enforce_admins, no force-push/deletions) + apply-branch-protection.sh:31-64 applies core + required_signatures endpoint.
- **Definition of Done:** apply-branch-protection.sh has been run against main, and a verification step confirms the LIVE protection (`gh api .../branches/main/protection`) equals the JSON for: required_approving_review_count=2, require_code_owner_reviews, required_signatures, required_linear_history, enforce_admins, and the status-check contexts (incl. the new `opa test` check from T-64).
- **Implementation notes:** Add the T-64 `opa test`, T-70 Scorecard, and T-76 contexts to `required_status_checks.contexts`. After apply, diff live vs spec: `gh api repos/<r>/branches/main/protection --jq '{rev:.required_pull_request_reviews.required_approving_review_count, sig:.required_signatures.enabled, lin:.required_linear_history.enabled}'`. Update CODEOWNERS first (T-65) so code-owner reviews resolve.
- **Acceptance criteria:**
  - Live protection shows required_approving_review_count=2, required_signatures.enabled=true, required_linear_history.enabled=true, enforce_admins.enabled=true
  - The required status-check contexts include the OPA test and Scorecard checks
- **Verification:** `bash scripts/apply-branch-protection.sh && gh api repos/<owner>/<repo>/branches/main/protection --jq '.required_signatures.enabled, .required_linear_history.enabled, .required_pull_request_reviews.required_approving_review_count'` prints `true true 2`
- **Dependencies:** T-64, T-65
- **Maps to:** spec §4 Source control; SOC2 CC6.1 / NIS2 21.2.e; bug K9

#### T-68 — Test PR-path controls via a crafted PR that MUST be blocked
- **Area:** Governance | **Priority:** P0 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** The entire PR-side enforcement layer (commit-signature check, TruffleHog PR diff, required review, code-owner review) has NEVER executed because 0 PRs have ever been opened (VERIFIED COMPANY-AUDIT:73; bug K9). spec §4 'no unreviewed merges' and §8 anti-pattern 'guardrails that warn but never block' mean an untested PR gate is an unproven claim. The commit-signing job is explicitly PR-only (`if: inputs.is_pull_request == 'true'`, security-gate.yml:228-232), so it is dead code until exercised.
- **Current state:** VERIFIED security-gate.yml:228-232 commit-signing job is PR-gated and never ran; TruffleHog PR-diff at security-gate.yml:48-49 uses base/head only on PRs; 0 PRs exist.
- **Definition of Done:** At least 3 crafted PRs each demonstrably blocked: (a) a PR with an UNSIGNED commit fails the commit-signing check; (b) a PR introducing a planted fake secret fails TruffleHog; (c) a PR to a /policies/ or /infra/ path is blocked pending code-owner review. Each failing check is captured (run URL/screenshot) as governance evidence.
- **Implementation notes:** Use disposable branches. For (a) push a commit with signing disabled; for (b) add e.g. an AWS-shaped test key the verified-secrets detector flags (then delete the branch, no real secret); for (c) edit policies/deployment-gate.rego in a PR and confirm review-required. Record results into evidence/governance/pr-control-tests.md for the Evidence Pack (M4).
- **Acceptance criteria:**
  - The unsigned-commit PR shows the commit-signing check failed (red)
  - The planted-secret PR shows TruffleHog failed (red) and the PR is not mergeable
  - The /policies/ PR shows 'Review required from code owners' and is blocked
- **Verification:** `gh pr checks <pr-number>` for each crafted PR lists the relevant check as `fail`; `gh pr view <pr> --json mergeable` shows not mergeable
- **Dependencies:** T-67
- **Maps to:** spec §4 Source control / §8 anti-pattern #4; bug K9

#### T-71 — Add CI pin-audit that fails on any non-SHA, non-local action
- **Area:** Supply-chain | **Priority:** P0 | **Milestone:** M3 | **Effort:** S | **Owner:** Szymon
- **Context:** The repo is at 64/64 SHA-pinned (VERIFIED `grep -rEoh 'uses: [^ ]+@[0-9a-f]{40}'`=64, non-SHA non-local=0), but nothing PREVENTS a future PR from adding a tag-pinned action — exactly the supply-chain exposure spec §8 flags ('unpinned CI actions'). A guard converts a one-time-good state into an enforced invariant.
- **Current state:** VERIFIED 64 SHA-pinned, 0 tag-pinned, 6 local `uses: ./` (correctly unpinned); no CI check enforces this.
- **Definition of Done:** A CI step (in the policy-test or security-gate workflow) scans `.github/workflows/*.yml`, counts `uses:` lines that are neither 40-hex-SHA-pinned nor local `./`, prints `pinned=N tag/branch=M`, and `exit 1` when M>0.
- **Implementation notes:** `BAD=$(grep -rEn 'uses: ' .github/workflows/ | grep -vE '@[0-9a-f]{40}' | grep -v 'uses: \./'); if [ -n "$BAD" ]; then echo "::error::unpinned actions:"; echo "$BAD"; exit 1; fi`. Emit the pinned count to the step summary so the inventory is recorded. This is the gate that backs the Scorecard Pinned-Dependencies claim (T-70).
- **Acceptance criteria:**
  - The check passes today (0 unpinned)
  - Adding `actions/checkout@v4` to a workflow makes the check fail
  - 6 local reusable `uses: ./` are not flagged
- **Verification:** `grep -rEn 'uses: ' Pipeline/.github/workflows/ | grep -vE '@[0-9a-f]{40}' | grep -v 'uses: \./'` returns empty; the CI step is red after planting a tag-pinned action
- **Dependencies:** none
- **Maps to:** spec §4 / §8 (unpinned CI actions); struktura C.16; blueprint 06 §6.0 (64/64 pinned)

#### T-80 — Add a CI job that runs `opa test policies/` and fails on any failing test
- **Area:** Pipeline self-test | **Priority:** P0 | **Milestone:** M3 | **Effort:** S | **Owner:** Szymon
- **Context:** The 3 OPA policies (deployment-gate, evidence-completeness, retention-policy) ship with `*_test.rego` pairs but are executed in ZERO workflows — `opa test` / `conftest` appears nowhere in `Pipeline/.github` or `Pipeline/scripts` (grep -> 0 hits). Authored-but-never-run tests are a self-test gap and a known overclaim (COMPANY-AUDIT §3.4, deep-dive K4). 'Fully operational' requires `opa test policies/` green and run in CI.
- **Current state:** VERIFIED: grep `opa test|opa eval|conftest` over Pipeline/.github/workflows + Pipeline/scripts -> 0 hits; 6 rego files present (Pipeline/policies/, 3 policy + 3 _test).
- **Definition of Done:** A reusable workflow `policy-test.yml` installs a pinned OPA, runs `opa test policies/ -v`, and exits non-zero if any test fails or any policy file fails to parse.
- **Implementation notes:** New `Pipeline/.github/workflows/policy-test.yml` (workflow_call). Steps: checkout (persist-credentials:false); install OPA by digest-pinned download (record `opa version`); `opa test policies/ -v --explain fails`. Optionally `opa test policies/ --coverage --threshold 80` to enforce rego coverage. Wire into orchestrator in T-86. Spec: struktura §6 compliance gate; spec §C.13 policy-as-code.
- **Acceptance criteria:**
  - `policy-test.yml` exists and calls `opa test policies/ -v`.
  - Job fails (non-zero) when a `_test.rego` assertion fails (prove by temporarily breaking one).
  - OPA version is captured into the job log (measured, not hardcoded).
- **Verification:** `cd Pipeline && opa test policies/ -v` (exit 0; lists PASS for all tests in deployment-gate_test/evidence-completeness_test/retention-policy_test)
- **Dependencies:** none
- **Maps to:** blueprint 04 OPA wiring; blueprint 06 K4; spec §C.13; struktura §6 compliance gate

#### T-81 — Add a bats unit-test suite for evidence shell scripts with a coverage floor
- **Area:** Pipeline self-test | **Priority:** P0 | **Milestone:** M3 | **Effort:** L | **Owner:** Szymon
- **Context:** The integrity chain rests on shell scripts (`seal-evidence.sh`, `verify-evidence-pack.sh`, `generate-compliance-matrix.sh`, `sanitize-logs.sh`) that have ZERO automated tests — `find . -name '*.bats'` returns nothing. These scripts have known logic bugs (Merkle-cosign ordering §6.2-A; presence-only matrix K1) that tests would have caught. 'Fully operational' requires pipeline self-tests including unit tests for the new validators/scripts.
- **Current state:** VERIFIED: 0 bats files exist (find *.bats -> 0); the 17 scripts in Pipeline/scripts/ are untested.
- **Definition of Done:** A `Pipeline/scripts/tests/*.bats` suite covers the verify/seal/matrix scripts with fixtures, runs in CI, and measures coverage (kcov or bashcov) with a documented floor.
- **Implementation notes:** New `Pipeline/scripts/tests/` with bats-core (pinned). Test `verify-evidence-pack.sh` against a fixture evidence dir (good pack -> exit 0 with PASS lines; tampered file -> FAIL; missing bundle -> SKIP). Test `seal-evidence.sh` Step-3 precondition: after seal, `merkle-root.cosign.bundle` MUST exist (catches §6.2-A regression). Test `generate-compliance-matrix.sh` emits content-based PASS/FAIL (post-fix). Run via `bats scripts/tests/`; coverage via `kcov --include-path=scripts coverage scripts/tests/...`. Spec §I integrity; struktura §6.
- **Acceptance criteria:**
  - `bats scripts/tests/` runs >= 12 assertions and passes locally and in CI.
  - A test asserts `merkle-root.cosign.bundle` is produced by seal (would fail today; passes after §6.2-A fix).
  - Coverage floor documented (e.g. >=70% of script lines via kcov) and enforced in CI.
- **Verification:** `cd Pipeline && bats scripts/tests/` (all assertions PASS)
- **Dependencies:** T-88
- **Maps to:** blueprint 06 §6.2-A, K1; spec §I; struktura §6

#### T-82 — Add a pytest suite for the Python evidence generators/validators
- **Area:** Pipeline self-test | **Priority:** P0 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** The pack's machine-readable artifacts are produced by Python (`generate-evidence-manifest.py`, `generate-oscal.py`, `build-audit-document.py`, and the new A.1–A.10 validators / content-readers replacing the static heredoc emitters). None has a unit test in the Pipeline repo (only the demo app has jest, and Snapshot has its own pytest). The new readers must be tested to prove they evaluate CONTENT not presence (GTM-RESET §4).
- **Current state:** VERIFIED: no pytest config or `test_*.py` exists under Pipeline/ (tests live only in app/ jest and Snapshot/); the Python generators in Pipeline/scripts/ are untested.
- **Definition of Done:** `Pipeline/scripts/tests/test_*.py` covers manifest generation (Merkle root determinism), OSCAL MISSING->FAIL mapping, and each new content-validator with PASS and FAIL fixtures; runs in CI with >=80% coverage of the new modules.
- **Implementation notes:** Add `pytest`+`pytest-cov` (pinned) and a `pyproject.toml`/`pytest.ini` under Pipeline/scripts. Tests: `generate-evidence-manifest.py` — same inputs -> identical merkle_root; reordered files -> identical root (RFC-6962). `generate-oscal.py:97-106` — MISSING control -> finding state `not-satisfied`. For each new A.x validator: a malformed/stale fixture -> FAIL, a conformant fixture -> PASS. Run `pytest scripts/tests --cov=scripts --cov-fail-under=80`. Spec struktura §6 A.1–A.10; spec §C.
- **Acceptance criteria:**
  - `pytest scripts/tests --cov=scripts` passes with coverage >=80% on the new validator/reader modules.
  - At least one PASS and one FAIL fixture per new content-validator.
  - Manifest Merkle-root determinism test present and green.
- **Verification:** `cd Pipeline && pytest scripts/tests --cov=scripts --cov-report=term-missing` (exit 0, coverage >=80%)
- **Dependencies:** none
- **Maps to:** struktura §6 A.1–A.10; spec §C; GTM-RESET §4

#### T-85 — Define a PR-appropriate E2E path in the orchestrator (no real deploy, full gates)
- **Area:** Pipeline self-test | **Priority:** P0 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** 'Fully operational' requires a green E2E on BOTH push AND PR. Today the PR path is structurally incomplete: sign-and-attest, deploy and dast are hard-skipped on PRs (pipeline.yml:62,74,87 `if: github.event_name != 'pull_request'`), so a PR never exercises the integrity/evidence half of the chain. The PR path must run everything that does NOT require pushing an image or mutating Azure — including a dry-seal evidence-pack — so a PR proves the pack assembles and verifies.
- **Current state:** VERIFIED: pipeline.yml:62,74,87 gate sign/deploy/dast off on PR; evidence-pack runs `if: always()` (pipeline.yml:98) but with N/A image inputs and warn-only completeness, so PR never proves a verifiable pack.
- **Definition of Done:** On a PR, the pipeline runs security-gate + build+scan (push_image:false) + self-test/opa + a dry-run evidence-pack that seals and self-verifies locally (degraded/non-WORM), and the whole run is green without deploying.
- **Implementation notes:** Keep deploy/dast push-only. Add a PR-mode to evidence-pack.yml: when `is_pull_request`, run seal in `EVIDENCE_ALLOW_DEGRADE`/local mode and then `verify-evidence-pack.sh` (exit 0 on degraded pack per its own policy, script header lines 14-18) so the PR proves assembly+verification without QTS/WORM. Pass build-and-scan outputs (image built but not pushed) for SBOM/provenance-over-fs. Ensure sign-and-attest has a PR-safe sign-blob-only variant OR is correctly skipped while the pack still self-verifies.
- **Acceptance criteria:**
  - On a PR, build+scan+gates+self-test+evidence-pack(dry) all succeed; deploy/dast skipped by design.
  - The PR run produces an evidence dir on which `verify-evidence-pack.sh` exits 0.
  - No image is pushed and no Azure resource is mutated on the PR path.
- **Verification:** open a PR; `gh run watch` the pipeline -> conclusion success with deploy/dast 'skipped' and evidence-pack 'success'
- **Dependencies:** none
- **Maps to:** blueprint 06 PR-path untested; spec §4 stages

#### T-86 — Prove a green END-TO-END run on both push AND PR with captured run links
- **Area:** Pipeline self-test | **Priority:** P0 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** The PR-side controls and the full pipeline have never actually executed: the public repo shows 1 squashed commit / 4 runs and the Pipeline nested repo has exactly 1 commit (`git -C Pipeline log` -> d53cb2e), so 'gates fail closed on PR' and 'E2E green' are unproven claims (COMPANY-AUDIT §3.3/§3.6, K9). This task is the evidence that the self-test + PR-path work (T-80,T-83,T-84,T-85) actually produces two green runs.
- **Current state:** VERIFIED: `git -C Pipeline log --oneline` -> single commit d53cb2e; no PR has ever run (blueprint 01 §1.2; K9 0 PRs).
- **Definition of Done:** Two captured runs exist — one push-to-main and one PR — both green, with opa/self-test/junit-real present, and the run URLs recorded in the repo (README badges + a docs/evidence note).
- **Implementation notes:** Commit the pending pipefail/gate fixes first (blueprint 01 B2). Open a real PR that touches app code so build+scan+jest run; confirm self-test (T-83) + opa (T-80) phases run on PR. Then merge to main and confirm the push run reaches deploy/dast/evidence-pack green. Record both `gh run view --json` URLs. Add status badges to Pipeline/README.md. This is the proof object referenced by the sample-pack (T-90).
- **Acceptance criteria:**
  - One PR run: conclusion success, self-test+opa+real-junit visible, deploy skipped.
  - One push run: conclusion success through evidence-pack.
  - Both run URLs recorded in-repo; README badges added.
- **Verification:** `cd Pipeline && gh run list --limit 5 --json conclusion,event,url | jq '.[] | select(.conclusion=="success") | {event,url}'` shows both a 'push' and a 'pull_request' success
- **Dependencies:** T-80, T-83, T-84, T-85
- **Maps to:** COMPANY-AUDIT §3.3/§3.6; blueprint 06 K9; spec §4

#### T-88 — Put the Snapshot scanner under version control and delete the duplicate Snapshot-Codex
- **Area:** Demo deliverable | **Priority:** P0 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** The Snapshot scanner feeds the sample pack's scan-results and crosswalk components, yet it is git-ignored (`.gitignore:34 /Snapshot/*`; `git check-ignore Snapshot` -> exit 1) — 140MB+ of the entry-product IP plus its 134-test suite live on one disk only (blueprint 01 §1.5). A pack component cannot be cited as reproducible if its generator is unversioned, and the duplicate `Snapshot-Codex/` makes 'which folder is canonical?' ambiguous mid-delivery.
- **Current state:** VERIFIED: .gitignore lines 33-35 exclude /Pipeline/*, /Snapshot/*, /Snapshot-Codex/*; `git check-ignore Snapshot Snapshot-Codex` exit 1 (both ignored); 134 `def test_` functions in Snapshot/tests/unit; both dirs near-identical (blueprint 01 §1.5).
- **Definition of Done:** Snapshot is tracked in a (nested or dedicated) git repo with its tests, the duplicate dir is deleted, and CI can run `pytest` against it.
- **Implementation notes:** Decide canonical dir — blueprint 01 §1.5 says Snapshot/ has the fuller analyzer set (models/+report/). Either `git init Snapshot` as its own repo or remove the `/Snapshot/*` ignore in the outer repo and commit. Delete the non-canonical dir (the Codex copy with the stray CLAUDE.md + extra results/). Keep an `.gitignore` inside Snapshot for venv/__pycache__/results. After T-87, the surviving dir carries the fixed engine. This unblocks T-81 (script tests that may shell out to snapshot) and T-90 (pack reproducibility).
- **Acceptance criteria:**
  - `git -C Snapshot ls-files | grep -c 'src/snapshot'` > 0 (source tracked).
  - Only one Snapshot dir remains; the duplicate is deleted.
  - `pytest` runs against the tracked tree (134+ tests collected).
- **Verification:** `cd Snapshot && git ls-files | wc -l` (>0) and `pytest --collect-only -q | tail -1` (>=134 tests)
- **Dependencies:** none
- **Maps to:** blueprint 01 §1.5 B1; COMPANY-AUDIT §3.6

#### T-34 — Validator unit-test harness + opa test integration
- **Area:** compliance-as-code | **Priority:** P1 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** FULLY-OPERATIONAL item 12 requires pipeline self-tests (unit tests + opa test). The 3 OPA policies already have 10 passing rego tests, but the new A.1-A.10 Python validators will have none. Each validator must be tested with a known-good fixture (PASS) and a known-bad fixture (FAIL) so the gate's verdicts are trustworthy. This is the testing layer that makes the compliance-as-code claim defensible to a technical buyer.
- **Current state:** VERIFIED rego tests exist (policies/*_test.rego, 10 cases) but run in no workflow; no Python validator tests exist (validators don't exist yet).
- **Definition of Done:** `scripts/validators/tests/` has one pytest module per validator with a PASS fixture and a FAIL fixture; a CI step runs `pytest` + `opa test policies/` and fails the build on any failure.
- **Implementation notes:** Add a `compliance-tests` job (or step in security-gate.yml) running `python3 -m pytest scripts/validators/tests -q` and `opa test policies/ -v`. Fixtures live under `scripts/validators/tests/fixtures/` (e.g. a vendor-risk-register with a stale Last Reviewed date → FAIL). Pin `open-policy-agent/setup-opa` by SHA (repo's 100% pin policy).
- **Acceptance criteria:**
  - `pytest` covers all 10 validators with ≥2 cases each (PASS+FAIL)
  - `opa test policies/` passes its 10 cases in CI
  - A deliberately broken validator fixture turns the CI job red
- **Verification:** `python3 -m pytest scripts/validators/tests -q && opa test policies/ -v`
- **Dependencies:** T-33
- **Maps to:** FULLY-OPERATIONAL item 12; blueprint/04 §11

#### T-57 — Add verify-side ordering-parity test for the §6.2-A class (sealing artifact symmetry)
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** Blueprint §6.4 flags as an uninvestigated gap '(2) whether verify-evidence-pack.sh has the symmetric ordering assumptions for RFC-3161 tokens that §6.2-A exposed for cosign'. The verify runbook silently emitted NO line for the missing Merkle bundle (because the PDF bundle set COSIGN_CHECKED=1) — a class of 'silent absence' bugs. A regression test must catch any sealing artifact that is silently never verified.
- **Current state:** VERIFIED. `verify-evidence-pack.sh:195-221`: when only one of the two cosign bundles exists, `COSIGN_CHECKED=1` suppresses the literal SKIP, and the missing bundle yields no line at all. Same risk exists for the three RFC-3161 labels (`:241-268`).
- **Definition of Done:** A test asserts that, given a manifest claiming a Merkle root and a present PDF, the verify runbook emits an explicit PASS or FAIL (never silent absence) for BOTH the Merkle bundle and the pdf bundle, and for each expected .tsr label.
- **Implementation notes:** Add a test (bash + a fixture evidence dir, or a python harness) that runs `verify-evidence-pack.sh` against (a) a complete pack and (b) a pack with the Merkle bundle deleted, asserting case (b) prints a FAIL line mentioning merkle. Tie to T-41's explicit-fail change. Add to the pipeline self-test suite (cross-stream §12). Blueprint §6.4 gap #2.
- **Acceptance criteria:**
  - Deleting merkle-root.cosign.bundle yields an explicit FAIL line from the runbook (not silence).
  - Each expected .tsr label yields PASS/SKIP/FAIL, never absence.
- **Verification:** `cd Pipeline && rm -f evidence/merkle-root.cosign.bundle && bash scripts/verify-evidence-pack.sh evidence 2>&1 | grep -qi 'merkle' && echo VERIFY_PARITY_OK`
- **Dependencies:** T-40, T-41
- **Maps to:** blueprint §6.4 gap #2; spec §12 self-tests, Part I.2

#### T-58 — Add sealing-artifact completeness self-test (all 8 integrity outputs land)
- **Area:** Integrity chain | **Priority:** P1 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** Spec §4/§12 and §1.0 sample Evidence Pack require the integrity chain to deterministically emit its full artifact set: manifest.json (Merkle root), merkle-root.txt, merkle-root.cosign.bundle, pdf-sha256.cosign.bundle, *.tsr, verapdf-report.json, oscal-assessment-results.json, sbom + provenance. Without a single self-test asserting all of these exist + are non-empty, regressions like §6.2-A slip through.
- **Current state:** VERIFIED. No single check asserts the full sealing-artifact set. `evidence-pack.yml:390-403` uploads with `if-no-files-found: warn` (does not fail on missing). The generator self-test (`generate-evidence-manifest.py --selftest`) only covers Merkle math, not the emitted pack.
- **Definition of Done:** A self-test (script + workflow step) asserts every required sealing artifact exists and is non-empty after a full seal run; non-PR CI fails if any is missing.
- **Implementation notes:** Add `Pipeline/scripts/check-sealing-completeness.sh <evidence_dir>` enumerating: `manifest.json`, `merkle-root.txt`, `merkle-root.cosign.bundle`, `pdf-sha256.cosign.bundle`, `verapdf-report.json`, `oscal-assessment-results.json`, `sbom.cyclonedx.json`, `provenance.intoto.jsonl`, and ≥1 `*.tsr`; fail if any missing/zero-byte (non-degrade). Call it in `evidence-pack.yml` after sealing and change the upload `if-no-files-found` to `error`. Spec §4, §12, §1.0 sample pack (8 components).
- **Acceptance criteria:**
  - All listed artifacts present + non-empty after a full seal → script exits 0.
  - Any missing artifact → exit 1 (non-degrade).
- **Verification:** `cd Pipeline && bash scripts/check-sealing-completeness.sh evidence && echo SEALING_COMPLETE_OK`
- **Dependencies:** T-40, T-49, T-50
- **Maps to:** spec §4, §12, §1.0 sample pack; blueprint §6.2-A anti-regression

#### T-66 — Install + activate Renovate (verify the bot runs)
- **Area:** Governance | **Priority:** P1 | **Milestone:** M3 | **Effort:** S | **Owner:** Szymon
- **Context:** renovate.json is well-formed and even extends `helpers:pinGitHubActionDigests`, but the Renovate GitHub App was never installed, so 0 bot PRs have ever opened and the digest-pinning automation that keeps the 64/64 pin status fresh does not actually run (VERIFIED COMPANY-AUDIT:73, GTM-RESET:106; bug K9). A config without a running bot is claim/emit drift.
- **Current state:** VERIFIED Pipeline/renovate.json:1-25 valid (config:recommended + pinGitHubActionDigests + :pinDependencies, github-actions pinDigests:true); 0 Renovate runs (no Dependency Dashboard issue, no bot PRs).
- **Definition of Done:** The Renovate GitHub App (or self-hosted Renovate action) is installed on the repo, has completed onboarding, and has produced at least the Dependency Dashboard issue / an onboarding PR.
- **Implementation notes:** Install via github.com/apps/renovate scoped to the repo, OR add a `renovate.yml` workflow running `renovatebot/github-action@<SHA>` on a schedule with a RENOVATE_TOKEN. Confirm `vulnerabilityAlerts.enabled` resolves (requires Dependabot alerts on). Self-hosted option keeps it inside the same SHA-pinned supply chain.
- **Acceptance criteria:**
  - A Renovate onboarding PR or Dependency Dashboard issue exists in the repo
  - At least one Renovate run is visible (App activity log or workflow run)
- **Verification:** `gh pr list --author 'app/renovate'` (or `gh issue list --search 'Dependency Dashboard'`) returns >=1 item
- **Dependencies:** none
- **Maps to:** spec §4 supply-chain self-defence; bug K9; GTM-RESET §4

#### T-70 — Add OpenSSF Scorecard with Pinned-Dependencies + Dangerous-Workflow PASS
- **Area:** Supply-chain | **Priority:** P1 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** spec §4 names OpenSSF Scorecard's Pinned-Dependencies + Dangerous-Workflow checks as the supply-chain self-defence differentiator (also struktura C.16, L5 maturity), citing the March-2026 trivy-action compromise. VERIFIED no Scorecard workflow exists, so the pipeline cannot prove its own scanners are not an attack surface.
- **Current state:** VERIFIED `ls Pipeline/.github/workflows/ | grep -i scorecard` = none; 64/64 actions SHA-pinned (raw material for a Pinned-Dependencies PASS exists but is unproven).
- **Definition of Done:** A `scorecard.yml` workflow (SHA-pinned `ossf/scorecard-action`) runs on schedule + push to main, uploads SARIF to code-scanning, and a step asserts the Pinned-Dependencies and Dangerous-Workflow checks both score PASS (>=8 / not failing).
- **Implementation notes:** `uses: ossf/scorecard-action@<SHA>` with `results_format: sarif`, `publish_results: true`; then parse the SARIF/JSON and `exit 1` if `Pinned-Dependencies` or `Dangerous-Workflow` score < threshold. Needs `id-token: write` + `security-events: write`. Add the Scorecard check to branch-protection contexts (T-67). Pin the new action itself (T-71 guard must accept it).
- **Acceptance criteria:**
  - scorecard.yml exists, SHA-pinned, runs on schedule+push
  - The run reports Pinned-Dependencies and Dangerous-Workflow as passing
  - A regression (a tag-pinned action) drops Pinned-Dependencies and the assert step fails
- **Verification:** `gh run list --workflow scorecard.yml` shows green runs; the Scorecard SARIF in code-scanning shows Pinned-Dependencies + Dangerous-Workflow PASS
- **Dependencies:** T-71
- **Maps to:** spec §4 supply-chain self-defence + L5 maturity; struktura C.16

#### T-83 — Wire bats + pytest self-tests into a CI quality job that runs on push AND PR
- **Area:** Pipeline self-test | **Priority:** P1 | **Milestone:** M3 | **Effort:** S | **Owner:** Szymon
- **Context:** Adding bats (T-81) and pytest (T-82) suites is only half the requirement — they must execute as gating CI steps on every push AND every PR so the pipeline self-tests for real. Today the only test gate is the app jest job (build-and-scan.yml:321); script/validator tests would not run.
- **Current state:** VERIFIED: only `npm run test:ci` runs in CI (grep jest/npm test across Pipeline/.github/workflows -> only build-and-scan.yml:321); no bash/python self-test job exists.
- **Definition of Done:** A reusable `self-test.yml` runs the bats + pytest suites, captures tool versions, and is invoked by the orchestrator on both `push` and `pull_request`.
- **Implementation notes:** New `Pipeline/.github/workflows/self-test.yml` (workflow_call) with two jobs: shell-tests (install bats+kcov pinned, `bats scripts/tests/`) and python-tests (`pytest scripts/tests --cov-fail-under=80`). Add a `needs`/`uses` entry in pipeline.yml so it runs unconditionally (no `if: != pull_request`). Combine with the OPA job (T-80) under one 'self-test' phase. Measure (`bats --version`, `pytest --version`, `opa version`) into logs.
- **Acceptance criteria:**
  - self-test.yml runs on a PR and on a push (no event-conditional skip).
  - A failing bats or pytest assertion fails the overall pipeline run.
  - Tool versions appear in the job log.
- **Verification:** `cd Pipeline && gh run list --workflow=pipeline.yml --limit 2` shows the self-test phase present on both a push run and a PR run
- **Dependencies:** T-81, T-82
- **Maps to:** blueprint 06 self-test gap; spec §C.13

#### T-119 — Wire export-github-security-config.sh into the pipeline and capture source-control controls as signed evidence (spec Part C.2)
- **Area:** Governance/Evidence | **Priority:** P1 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** The master spec requires a Source-control & change-management Part C.2 row ('Branch protection, signed commits, review records · 2-party review · no direct prod push', evidence-pack-specification.md:188 + struktura:156: 'Podpisany JSON · brak force-push; podpisane commity'). VERIFIED `scripts/export-github-security-config.sh` exists (10KB) but is NOT wired into any workflow (grep over .github/workflows/ returns nothing), so the live branch-protection/commit-signing config is never captured into the pack — the audit-document asserts the 2-approval gate as a 'static intent file; live drift reconciliation pending' (build-audit-document.py:1351). The control claim is therefore unbacked by live evidence.
- **Current state:** VERIFIED export-github-security-config.sh is not invoked anywhere — `grep -rn export-github-security-config .github/workflows/` returns nothing; build-audit-document.py:1351 labels the 2-approval gate provenance 'static'.
- **Definition of Done:** A pipeline step runs `export-github-security-config.sh` (read-only GitHub API via the run token), writes `evidence/source-control-config.json` (branch-protection rules, required reviews, signed-commit enforcement, CODEOWNERS resolution), a validator asserts it MATCHES `branch-protection.json` (drift = FAIL), the artifact is signed and in the Merkle root, and the audit-document C.2 row provenance changes from 'static' to 'live'.
- **Implementation notes:** Add an `export-source-control-config` step to `evidence-pack.yml` (or a small dedicated job) invoking the existing script; add `scripts/validators/source_control.py` comparing the exported live config to `branch-protection.json` (BLOCKING on drift for non-PR). Update build-audit-document.py:1351 provenance_badge from 'static' to 'live' once wired. This depends on branch protection actually being applied (T-67). Maps to spec §3 C.2 + §4 stage 'Source control'.
- **Acceptance criteria:**
  - `evidence/source-control-config.json` is produced by a pipeline run from the live API.
  - `source_control.py` FAILs if live config drifts from branch-protection.json.
  - audit-document C.2 row no longer carries the 'static intent file' provenance.
- **Verification:** `grep -rn export-github-security-config Pipeline/.github/workflows/ && python3 Pipeline/scripts/validators/source_control.py evidence/source-control-config.json Pipeline/branch-protection.json`
- **Dependencies:** T-67
- **Maps to:** spec Part C.2; evidence-pack-specification.md:188 §4 'Source control'; struktura:156

#### T-123 — Add verify-side RFC-3161 token ordering-parity self-test (deep-dive §6.4 gap 2)
- **Area:** Integrity/Self-test | **Priority:** P1 | **Milestone:** M3 | **Effort:** S | **Owner:** Szymon
- **Context:** The pipeline deep dive explicitly flags as an un-investigated gap: 'whether verify-evidence-pack.sh has the symmetric ordering assumptions for RFC-3161 tokens that §6.2-A exposed for cosign' (blueprint/06-pipeline-deep-dive.md:345 obvious-gap 2). The §6.2-A Merkle cosign bug (T-40) was an ordering defect where a signed artifact was produced after the step that consumed it. T-57 covers ordering-parity for the §6.2-A cosign class only; the RFC-3161 .tsr token path is a DISTINCT symmetry that has never been verified. VERIFIED verify-evidence-pack.sh checks `.tsr` tokens (verify-evidence-pack.sh:10,12 'openssl ts -verify if a .tsr token is present') and the Merkle root is timestamped at seal-evidence.sh:382-385 — the same region as the §6.2-A ordering bug.
- **Current state:** VERIFIED the .tsr verify path exists (verify-evidence-pack.sh:12) and the RFC-3161 stamp over merkle-root is written at seal-evidence.sh:382-385; no self-test asserts the .tsr token is actually produced AND verifiable for the Merkle root after the T-40 fix re-orders the file write.
- **Definition of Done:** A self-test (run in non-degrade CI) asserts that after sealing a synthetic pack, a Merkle-root `.tsr` token exists, `openssl ts -verify` validates it against the (T-54) CA chain, and verify-evidence-pack.sh emits a PASS line for it (not a silent skip), proving the RFC-3161 path has no residual §6.2-A-style ordering defect.
- **Implementation notes:** Extend the evidence-pdf-test harness (or a bats test) to run seal-evidence.sh then assert `evidence/merkle-root.tsr` (or the actual token name) exists and is non-empty, run `openssl ts -verify -in merkle-root.tsr -data merkle-root.txt -CAfile <chain>` exit 0, and grep verify-evidence-pack.sh output for a 'RFC-3161 ... PASS' line for the Merkle root. Must run AFTER T-40 re-orders the merkle-root.txt write. Maps to deep-dive §6.4 obvious-gap 2; spec §7.3-7.4 integrity.
- **Acceptance criteria:**
  - A Merkle-root RFC-3161 token is produced by a non-degrade seal run.
  - `openssl ts -verify` validates it and verify-evidence-pack.sh prints a PASS (not skip) for it.
  - The test fails if the token is absent (anti-regression for the §6.2-A class on the RFC-3161 path).
- **Verification:** `cd Pipeline && bash scripts/seal-evidence.sh <fixture> && openssl ts -verify -in evidence/merkle-root.tsr -data evidence/merkle-root.txt -CAfile evidence/tsa-chain.pem && bash scripts/verify-evidence-pack.sh evidence | grep -i 'rfc-3161.*pass'`
- **Dependencies:** T-40, T-57
- **Maps to:** deep-dive §6.4 obvious-gap 2 (06-pipeline-deep-dive.md:345); spec §7.3-7.4; bug §6.2-A class

#### T-124 — Audit and fix the PR-side conditional path for latent logic bugs before declaring E2E parity (deep-dive §6.4 gap 1)
- **Area:** Self-test/CI | **Priority:** P1 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** The pipeline deep dive flags as an un-investigated gap: 'whether the PR-side path — never run, 0 PRs (K9) — hides further logic bugs that only surface on PR triggers' (blueprint/06-pipeline-deep-dive.md:345 obvious-gap 1). The workflows are riddled with `if: github.event_name == 'pull_request'` degrade branches (e.g. evidence-pack.yml degrade-on-PR at :322, completeness warn-on-PR, commit-signing PR-only). T-85 DEFINES a PR E2E path and T-86 RUNS it green, but neither AUDITS the existing PR-conditional branches for bugs that only execute on PR. A bug that only fires on PR would be masked by simply 'getting a green PR run' if the green path doesn't exercise the conditional.
- **Current state:** VERIFIED multiple PR-conditional branches exist and have run 0 times (K9, COMPANY-AUDIT §3.3: 0 PRs); e.g. seal-evidence degrade-on-PR (evidence-pack.yml ~:322), completeness warn-only-on-PR, security-gate commit-signing gated to PRs only — none exercised end-to-end.
- **Definition of Done:** Every `github.event_name == 'pull_request'` (and `!= 'pull_request'`) conditional across the 8 workflows is enumerated, each branch's behavior is documented (degrade vs block vs skip), the crafted-PR test (T-68) is extended to exercise each PR-only branch, and any latent bug found (mis-negated condition, skipped gate, fall-through) is fixed with a regression assertion.
- **Implementation notes:** Grep `grep -rn "event_name" Pipeline/.github/workflows/` to enumerate all branches; build a small matrix (workflow:line -> PR behavior -> push behavior). Add PR-path assertions to the T-68 crafted-PR test so each PR-only branch is hit at least once. Fix any branch where the PR path silently skips a control it should still run, or where a `!=` was meant to be `==`. Maps to deep-dive §6.4 obvious-gap 1; FULLY-OPERATIONAL item 12 (green E2E on PR AND push).
- **Acceptance criteria:**
  - A documented enumeration of all PR-conditional branches with their push-vs-PR behavior exists.
  - The crafted-PR test exercises each PR-only branch at least once.
  - Any latent PR-path bug is fixed and covered by a regression assertion.
- **Verification:** `grep -rn "event_name" Pipeline/.github/workflows/ | wc -l` (enumeration baseline) and a green crafted-PR run whose logs show each PR-only branch executed
- **Dependencies:** T-85, T-86
- **Maps to:** deep-dive §6.4 obvious-gap 1 (06-pipeline-deep-dive.md:345); FULLY-OPERATIONAL item 12; bug K9

#### T-18 — Capture measured tool versions into evidence and surface them in matrix detail
- **Area:** Compliance-matrix | **Priority:** P2 | **Milestone:** M3 | **Effort:** S | **Owner:** Szymon
- **Context:** The matrix/OSCAL output should reflect the versions that ACTUALLY ran, not hardcoded/omitted ones; spec Appendix X.3 wants a tool inventory pinned by digest (blueprint/04 §7; spec §4 supply-chain self-defence; spec X.3).
- **Current state:** VERIFIED only Trivy captures its version via `subprocess.run(['trivy','--version'])` (build-and-scan.yml:74,543); CodeQL/cosign/syft/opa versions are pinned by action SHA but never recorded into evidence, and the matrix rows carry no tool_version.
- **Definition of Done:** A step writes `evidence/tool-versions.json` capturing measured versions of trivy, cosign, syft, opa, checkov, codeql (and their action SHAs); the matrix validators populate each row's `tool_version` from it. No version is hardcoded in the matrix output.
- **Implementation notes:** Add a `Capture tool versions` step (e.g. in evidence-pack.yml or each scan job) running `cosign version`, `syft version`, `opa version`, `trivy --version`, `checkov --version`; write JSON; T-12 validators read it into the envelope `tool_version`. Spec: blueprint/04 §7; spec X.3.
- **Acceptance criteria:**
  - evidence/tool-versions.json lists >=5 tools with measured (not placeholder) versions.
  - At least one matrix row's tool_version is populated from that file.
- **Verification:** `jq 'keys' evidence/tool-versions.json` lists the tools; `bash Pipeline/scripts/generate-compliance-matrix.sh evidence/ | jq '.frameworks.DORA[0].tool_version'` is non-empty.
- **Dependencies:** T-12
- **Maps to:** blueprint/04 §7; spec §4 supply-chain self-defence; spec X.3

#### T-106 - Add a network-hardened Terraform variant for regulated clients
- Area: IaC | P2 | M3 | M | Szymon
- Context: All Azure data-plane endpoints are public - fine for demo, not for the DORA/NIS2 client variant where the KNF cloud communique expects data-localisation + supervisory access (spec 6.2). Source COMPANY-AUDIT 3.4; spec 6.2.
- Current state: VERIFIED storage/main.tf has NO network_rules/public_network_access/private-endpoint config; infra/main.tf passes no hardening. Storage, ACR, Key Vault, Container Apps all public.
- DoD: var.network_hardened default false gates (on evidence storage) public_network_access_enabled false + network_rules default_action Deny + optional private endpoint; documented in SETUP.md; demo default unchanged.
- Notes: Add variable network_hardened bool default false; conditional public_network_access_enabled + dynamic network_rules. CI runner needs a private path or trusted-services exception. Evidence storage first.
- Acceptance: plan with network_hardened true shows public_network_access_enabled false + Deny default action; SETUP.md documents the variant.
- Verification: terraform validate + plan with network_hardened true shows public_network_access_enabled false.
- Deps: none
- Maps to: COMPANY-AUDIT 3.4; spec 6.2; spec 9 L5

#### T-113 - Isolate item-store tests per suite
- Area: APP | P2 | M3 | S | Szymon
- Context: The items test resets state by GET-then-delete-all in beforeEach because the store is a process-global; passes only because Jest is serial within a file. T-111's injection seam lets each suite build its own store. Source blueprint/06 6.7-A.
- Current state: VERIFIED items.test.ts:5-10 beforeEach deletes all items to reset the shared singleton; build-info.test.ts + health.test.ts share it.
- DoD: Each suite builds an app/router with a fresh injected store; the beforeEach reset removed; no cross-test shared mutable state.
- Notes: createItemsRouter(new BoundedMap()) per suite or a makeApp factory; delete the beforeEach loop. Coverage at least 80 percent.
- Acceptance: No test relies on a shared global store; npm test passes, coverage at least 80 percent.
- Verification: npm test with coverage at least 80 percent; the items test has no beforeEach reset.
- Deps: T-111
- Maps to: blueprint/06 6.7-A; common/testing.md

#### T-118 — Emit a runtime-hardening posture statement (Pod Security / container least-privilege) (spec Part C.15)
- **Area:** Cloud/Posture | **Priority:** P2 | **Milestone:** M3 | **Effort:** S | **Owner:** Szymon
- **Context:** The master spec requires a Runtime hardening Part C.15 row ('Least-privilege runtime · K8s Pod Security Admission · restricted (or justified baseline) enforced', evidence-pack-specification.md:150 + struktura:171). The deployed app is an Azure Container App (not k8s), so the honest artifact is a least-privilege container/runtime posture statement (non-root user, read-only FS, dropped caps, ingress restrictions), not a fabricated PSS profile. VERIFIED no runtime-hardening artifact exists and no task covers this Part C row.
- **Current state:** VERIFIED no runtime-hardening evidence — grep for `pod.?security|psa|restricted|runtime.?harden|kubernetes` over scripts finds only the document-classification string; the Dockerfile and Terraform set runtime properties but they are not asserted into evidence.
- **Definition of Done:** A validator reads the Dockerfile + Terraform container config and emits `evidence/runtime-hardening.json` asserting non-root user, read-only rootfs where feasible, no privileged mode, and least-privilege ingress; the artifact is signed and in the manifest; the audit-document Part C.15 wording reflects the real Azure-Container-Apps posture (not a k8s PSS claim).
- **Implementation notes:** Add `scripts/validators/runtime_hardening.py` parsing `app/Dockerfile` (assert `USER` non-root present) and `infra/` container resource (assert no admin/privileged ingress). Emit the envelope per T-33, tier EVIDENCE-ONLY with a BLOCKING sub-check on 'runs as non-root'. Render the result into build-audit-document.py as the C.15 row with honest Azure-Container-Apps wording. Maps to spec §3 C.15.
- **Acceptance criteria:**
  - `evidence/runtime-hardening.json` asserts non-root execution and is FAIL if the Dockerfile lacks a non-root USER.
  - Audit-document C.15 row describes the actual runtime (no fabricated k8s PSS 'restricted' claim).
  - Artifact signed and in the Merkle root.
- **Verification:** `python3 Pipeline/scripts/validators/runtime_hardening.py Pipeline/app/Dockerfile`
- **Dependencies:** T-117
- **Maps to:** spec Part C.15; evidence-pack-specification.md:150; struktura:171

#### T-122 — Render Statement of Applicability + SAMM maturity scores into the pack (spec Part D.3 / §9)
- **Area:** Compliance/Evidence | **Priority:** P2 | **Milestone:** M3 | **Effort:** M | **Owner:** Szymon
- **Context:** The master spec requires Part D.3 'Statement of Applicability (ISO 27001) + maturity scores (SAMM)' (evidence-pack-specification.md:80 + struktura:88) and §9 grades the pack against an L1->L5 maturity benchmark (evidence-pack-specification.md:291-302). VERIFIED `docs/governance/statement-of-applicability.md` exists in HEAD but no task validates it or renders a maturity score into the pack; T-102 generates the crosswalk but not the SoA/maturity layer. Without a defensible maturity score the L5 maturity claim in struktura:317 is an overclaim.
- **Current state:** VERIFIED SoA file exists (git ls-tree HEAD: docs/governance/statement-of-applicability.md) but is not parsed by any validator; no maturity-score artifact is produced; struktura:317 claims L5 delivery with no computed evidence.
- **Definition of Done:** A validator parses the SoA (each ISO 27001 Annex-A control: applicable?, implemented?, justification) and emits `evidence/soa-maturity.json` with a per-dimension maturity score against the §9 L1-L5 table computed from real evidence state; the SoA + scores render into the pack Part D.3; the headline maturity claim is set to the COMPUTED level (no hardcoded L5).
- **Implementation notes:** Add `scripts/validators/soa_maturity.py` parsing `docs/governance/statement-of-applicability.md` and scoring the §9 dimensions (Evidence production, Build integrity, Scanning, Compliance mapping, Integrity) from actual evidence presence/signing state. Emit a per-dimension level; the overall claim must equal the lowest dimension or a justified weighted score, never a hardcoded 'L5'. Render into build-audit-document.py Part D.3 and align struktura:317 wording to the computed level. Maps to spec Part D.3 + §9.
- **Acceptance criteria:**
  - `soa-maturity.json` scores each §9 dimension from real evidence state.
  - The pack's headline maturity level equals the computed value, not a hardcoded L5.
  - SoA controls render into Part D.3 with applicable/implemented/justification columns.
- **Verification:** `python3 Pipeline/scripts/validators/soa_maturity.py Pipeline/docs/governance/statement-of-applicability.md`
- **Dependencies:** T-102, T-33
- **Maps to:** spec Part D.3 + §9 maturity benchmark; evidence-pack-specification.md:80,291-302; struktura:88,317

## M4 — Sample Evidence Pack & docs  (13 tasks)

#### T-90 — Stand up a sanitized public demo repo and run the pipeline end-to-end on it
- **Area:** Sample Evidence Pack | **Priority:** P0 | **Milestone:** M4 | **Effort:** M | **Owner:** Szymon
- **Context:** The headline near-term partner deliverable is a credible sample/demo Evidence Pack, which requires a neutral demo repo to generate it from (blueprint 01 §1.6 says replace the own-repo target; B6 = friendly-repo dry-run -> canonical neutral sample). A sanitized, public demo repo running the real pipeline is the substrate for all 8 components and removes internal target names from the artifacts.
- **Current state:** VERIFIED: no demo/sample pack or neutral target exists (find *sample*evidence* -> 0); current sample reports target Cyberforge-Pipeline-Priv / hacknarok (blueprint 01 §1.6), not sanitized neutral.
- **Definition of Done:** A public demo repo (neutral name, no client/internal identifiers) contains the demo app + the pipeline, and a real green pipeline run (push) has executed against it producing live artifacts.
- **Implementation notes:** Create `cyberforge-demo` (or similar neutral) public repo; copy Pipeline/app + the workflows (post-fixes from M0–M3). Configure required secrets/OIDC for a throwaway ACR/Azure or run the PR-mode (T-85) if cloud is unavailable. Trigger one push run (T-86 patterns). Sanitize: no real client names, no `firma/myapp` placeholders (blueprint 01 §1.3), neutral org. The run's evidence dir + Snapshot scan of this repo (T-88) feed T-91/T-92.
- **Acceptance criteria:**
  - Public demo repo exists with neutral naming and no internal/client identifiers.
  - At least one green pipeline run executed against it (URL captured).
  - A Snapshot scan of the demo repo produces sanitized JSON (no -1 after T-87).
- **Verification:** `gh repo view <demo-repo> --json visibility,name` (public) and `gh run list -R <demo-repo> --json conclusion | jq '.[0].conclusion'` (success)
- **Dependencies:** T-86, T-88
- **Maps to:** blueprint 01 §1.6/B6; GTM-RESET §5

#### T-91 — Generate the sample Evidence Pack with all 8 components and a verifying integrity proof
- **Area:** Sample Evidence Pack | **Priority:** P0 | **Milestone:** M4 | **Effort:** L | **Owner:** Szymon
- **Context:** This is the SHORTEST-PATH partner deliverable: a sanitized, credible downloadable sample Evidence Pack containing the 8 minimum components — (1) PDF board report, (2) artifact manifest, (3) scan results, (4) SBOM, (5) control matrix, (6) regulatory crosswalk, (7) gap/remediation register, (8) integrity proof (blueprint 01 §2.3, GTM-RESET §5 'high priority', B5). It must be sanitized and the integrity proof must ACTUALLY verify — which is blocked until the Merkle-root cosign bug (§6.2-A) is fixed and SLSA is relabeled L2.
- **Current state:** VERIFIED: no sample pack exists (find -> 0). Integrity proof would not verify today: Merkle-root cosign never produced (seal-evidence.sh:308 vs :383-384, §6.2-A HIGH); SLSA L3 mislabel at evidence-pack.yml:200.
- **Definition of Done:** A sanitized `sample-evidence-pack/` (and ZIP) containing all 8 components is generated from the demo run; `verify-evidence-pack.sh sample-evidence-pack/` exits 0 with explicit PASS lines for sha256 + Merkle + cosign + timestamp; the README labels SLSA L2 (or whatever is actually achieved).
- **Implementation notes:** Map components to spec parts: (1) board PDF -> Part 0.2 PDF/A-3b exec summary (render-evidence-pdf.py); (2) manifest -> Part 0.1 manifest.json+manifest.sha256; (3) scan results -> §X.1/Part C SARIF + Snapshot JSON (sanitized, post-T-87); (4) SBOM -> C.10 sbom.cyclonedx.json; (5) control matrix -> D.1 compliance-matrix.json (content-based); (6) crosswalk -> D.2; (7) gap/remediation register -> Part J; (8) integrity proof -> Part I (manifest signature + merkle-root.cosign.bundle + RFC-3161 .tsr + Rekor URL). Generate via the demo run (T-90) or a scripted `seal-evidence.sh` over the demo evidence dir. Sanitize all names. DEPENDS on the integrity fixes from the integrity stream (Merkle-cosign, SLSA relabel) — declare that dependency explicitly.
- **Acceptance criteria:**
  - All 8 named components present and non-empty in the pack.
  - `verify-evidence-pack.sh` exits 0 with PASS (not SKIP) for sha256, Merkle, cosign over the Merkle root, and timestamp.
  - No SLSA L3 string and no internal/client identifiers anywhere in the pack (`grep -riE 'SLSA L3|Pipeline-Priv|firma/myapp' sample-evidence-pack/` -> 0).
- **Verification:** `cd Pipeline && bash scripts/verify-evidence-pack.sh ../sample-evidence-pack && echo OK` (exit 0, OK, all PASS lines)
- **Dependencies:** T-90, T-87
- **Maps to:** blueprint 01 §2.3/B5; GTM-RESET §5; spec Parts 0/A/C/D/I/J; struktura 8 components; blueprint 06 §6.2-A

#### T-93 — Sanitize-and-redact pass over the sample pack (no secrets, no fake findings, honest labels)
- **Area:** Sample Evidence Pack | **Priority:** P0 | **Milestone:** M4 | **Effort:** S | **Owner:** Szymon
- **Context:** A sample pack handed to a partner/prospect must be sanitized AND credible — the demo history shows the failure mode: a fake `ghp_xK9mL2...` token presented as a real finding and a placeholder `firma/myapp` cosign command (blueprint 01 §1.3). The pack must contain real-but-neutral data, no live secrets, no fabricated evidence (spec §8 #1 'suspiciously uniform dates / assembled for audit'), and honest maturity/SLSA labels.
- **Current state:** VERIFIED: the existing demo surface contains fabricated findings + placeholders (blueprint 01 §1.3, demo (2).html:531/1101); SLSA L3 overclaim in evidence README (evidence-pack.yml:200); no sanitized pack exists.
- **Definition of Done:** The sample pack passes a redaction checklist: no real secrets/tokens, no fabricated findings, neutral target names, dates reflect the actual demo run, and every maturity/SLSA claim matches reality (L2 unless L3 achieved).
- **Implementation notes:** Run a secret scan over the pack (trufflehog/gitleaks) -> 0 verified secrets. Grep for fabricated artifacts (`ghp_`, `firma/myapp`, `[wstaw NIP]`, `Pipeline-Priv`) -> 0. Verify the integrity timestamps are genuinely from the demo run (not back-dated). Confirm the board PDF + README state SLSA L2 (post-relabel) and label the demo RFC-3161 as non-qualified if freetsa is used (spec §7 honesty). Document the redaction checklist in the pack's cover note.
- **Acceptance criteria:**
  - Secret scan over the pack -> 0 verified secrets.
  - `grep -riE 'ghp_|firma/myapp|wstaw NIP|Pipeline-Priv|SLSA L3' sample-evidence-pack/` -> 0.
  - Maturity/SLSA labels match the achieved level; demo QTS honestly labeled.
- **Verification:** `trufflehog filesystem sample-evidence-pack --only-verified | tail` (no verified secrets) and the grep above returns 0
- **Dependencies:** T-91
- **Maps to:** blueprint 01 §1.3; spec §7/§8; COMPANY-AUDIT honesty constraints; GTM-RESET §5

#### T-35 — Sample Evidence Pack — compliance-as-code section with signed A.1-A.10 verdicts + gate report
- **Area:** compliance-as-code | **Priority:** P1 | **Milestone:** M4 | **Effort:** M | **Owner:** Szymon
- **Context:** The sample/demo Evidence Pack (FULLY-OPERATIONAL item 11; blueprint/01:185 'Sanitized sample Evidence Pack ZIP — MISSING, high priority') must include the compliance-as-code layer (struktura Part A) so a buyer sees the signed PASS/FAIL org-control verdicts, not just DevSecOps SARIF. This is the proof that the differentiator is real and demoable.
- **Current state:** VERIFIED no sample pack contains A.1-A.10 verdicts (the validators + gate do not yet exist); blueprint/01:185 lists the sample ZIP as missing.
- **Definition of Done:** A demo evidence-pack run produces the 10 signed `*-validation.json`/`*.json` verdicts + the signed `compliance-gate.json` inside the sanitized sample Evidence Pack ZIP, with a 1-page 'what an auditor sees' walkthrough of Part A; the demo deliberately includes one BLOCKING FAIL (e.g. the past-due access review from T-27 or 'restore not yet conducted' from T-29) to show the gate fails honestly and points to remediation.
- **Implementation notes:** Drive evidence-pack.yml (or a local harness) against the seeded registers; ensure cosign bundles verify; sanitize any PII. Reference struktura Part A and the golden-thread (struktura §1) in the walkthrough so each verdict maps control→evidence→clause.
- **Acceptance criteria:**
  - Sample ZIP contains 10 signed verdict JSONs + signed compliance-gate.json, all cosign-verifiable
  - The walkthrough shows at least one honest FAIL with a remediation pointer
  - Each verdict carries the struktura §6 clause mapping (e.g. A.1→DORA Art.28(3))
- **Verification:** `unzip -l sample-evidence-pack.zip | grep -E 'roi-validation|compliance-gate.json' && cosign verify-blob --bundle compliance-gate.cosign.bundle compliance-gate.json`
- **Dependencies:** T-30
- **Maps to:** struktura Part A/§1; blueprint/01 sample pack; FULLY-OPERATIONAL item 11

#### T-89 — Capture a deterministic 'gate blocks a bad PR' enforcement proof for the demo
- **Area:** Demo deliverable | **Priority:** P1 | **Milestone:** M4 | **Effort:** S | **Owner:** Szymon
- **Context:** The single most-rejected anti-pattern is 'policies in audit-only mode forever — guardrails that warn but never block; show enforcement (blocked deploys)' (spec §8 #4). The acceptance criterion for Remediation Sprint is literally 'gates demonstrably fail-closed (show a deliberately-failing test blocking merge)' (blueprint 01 §2.2), and no such recorded artifact exists. The sample pack and demo need one reproducible, screenshot-able failing run.
- **Current state:** INFERENCE: no 'gate blocks bad PR' artifact exists (blueprint 01 §2.2 demo assets MISSING; no PR has ever run, K9). VERIFIED the gates that should block: coverage<80 (build-and-scan.yml:324-336), Trivy --exit-code 1, opa deny (post-T-80).
- **Definition of Done:** A documented, repeatable procedure produces a PR that is BLOCKED by a real gate (failing test / sub-80 coverage / critical CVE fixture / opa deny), with the red run captured (URL + log excerpt) for inclusion in the sample pack.
- **Implementation notes:** Add a `demo/bad-pr-fixture` branch script that introduces one deterministic failure (e.g. a unit test asserting false, or a Dockerfile with a known-critical base) and opens a PR; capture `gh run view` red conclusion + the specific gate's error line. Keep it OUT of main. Pair with a green control PR so the contrast is visible. This becomes pack component evidence under §8/enforcement.
- **Acceptance criteria:**
  - A PR exists whose pipeline conclusion is failure, attributable to one named gate.
  - The red run URL + the gate's `::error::` line are captured.
  - The procedure is re-runnable (documented one-liner).
- **Verification:** `cd Pipeline && gh run list --event pull_request --json conclusion,url | jq '.[] | select(.conclusion=="failure")'` returns the captured run
- **Dependencies:** T-85, T-86
- **Maps to:** spec §8 anti-pattern #4; blueprint 01 §2.2

#### T-92 — Add an automated structural assertion that the sample pack has all 8 components
- **Area:** Sample Evidence Pack | **Priority:** P1 | **Milestone:** M4 | **Effort:** S | **Owner:** Szymon
- **Context:** The sample pack must be regenerable without silently losing a component. The evidence-completeness OPA policy (Pipeline/policies/evidence-completeness.rego) already encodes a required-file set, but it does not map to the 8 partner-facing components, and there is no test that the SAMPLE pack specifically contains all 8. A blocking structural check makes the deliverable durable and ties into completeness-blocking (deep-dive §6.4-C).
- **Current state:** VERIFIED: evidence-completeness.rego lists 11 required files but is wired into 0 workflows (K4); no assertion maps to the 8 partner components; no sample-pack test exists.
- **Definition of Done:** A test (bats or pytest, reusing T-81/T-82 infra) asserts the sample pack contains each of the 8 components by content type, and runs in CI as part of the demo-pack generation.
- **Implementation notes:** Add `scripts/tests/test_sample_pack.py` (or .bats): assert presence+non-empty of board PDF (PDF magic bytes), manifest.json (valid JSON with merkle_root), scan-results (SARIF or snapshot JSON), sbom.cyclonedx.json (CycloneDX bomFormat field), compliance-matrix.json (rows with content verdicts), crosswalk file, gap/remediation register (Part J), integrity proof bundle(s). Optionally feed the file list into `opa eval -d policies/evidence-completeness.rego` to reuse the policy. Fail if any of the 8 is missing/empty.
- **Acceptance criteria:**
  - Test enumerates exactly the 8 components and fails if any is absent/empty.
  - Test is part of the self-test CI (T-83) or the demo-pack make target (T-94).
  - Removing any one component from the fixture makes the test fail.
- **Verification:** `cd Pipeline && pytest scripts/tests/test_sample_pack.py -q` (PASS with the real sample pack; FAIL when a component is removed)
- **Dependencies:** T-91
- **Maps to:** struktura 8 components; spec §I; blueprint 06 K4/§6.4-C

#### T-94 — Add a one-command reproducer + walkthrough so the sample pack is founder-independent
- **Area:** Sample Evidence Pack | **Priority:** P1 | **Milestone:** M4 | **Effort:** S | **Owner:** Szymon
- **Context:** Szymon is by-design never client-facing, so any demo asset that only Szymon can regenerate is a scaling bottleneck (blueprint 01 §1.9/§4, COMPANY-AUDIT §3.6). A `make demo-pack` one-command reproducer plus a short 'what an auditor sees' walkthrough lets Michal regenerate and present the sample pack without Szymon, and proves the pack is pipeline-generated (spec §8 #1 credibility).
- **Current state:** VERIFIED: no demo script/video/walkthrough exists (blueprint 01 §1.9); pack generation is currently a manual, single-human sequence.
- **Definition of Done:** `make demo-pack` (or a single script) regenerates the sanitized 8-component pack and runs `verify-evidence-pack.sh` to exit 0; a 1-page walkthrough maps each component to the auditor question it answers.
- **Implementation notes:** Add a `Makefile`/`scripts/make-demo-pack.sh` target chaining: Snapshot scan of demo repo -> assemble evidence dir -> `seal-evidence.sh` (degraded/local OK) -> `verify-evidence-pack.sh` -> zip. Write `sample-evidence-pack/README.md` (the 1-page 'what an auditor sees' walkthrough, blueprint 01 §2.3) mapping the 8 components to spec Parts (auditor enters via D, drills to A/C, verifies in I — struktura §44). Reference the T-86 run links as the live counterpart. Keep it idempotent and offline-capable (degrade mode) so Michal can run it without cloud creds.
- **Acceptance criteria:**
  - `make demo-pack` regenerates the pack and exits 0 (verify passes).
  - A 1-page walkthrough maps all 8 components to their auditor questions/spec Parts.
  - The reproducer runs with no Szymon-only knowledge (documented prereqs only).
- **Verification:** `cd Pipeline && make demo-pack && bash scripts/verify-evidence-pack.sh ../sample-evidence-pack` (exit 0)
- **Dependencies:** T-91, T-92
- **Maps to:** blueprint 01 §1.9/§2.3/§4; COMPANY-AUDIT §3.6; struktura §44

#### T-107 - Add a Poland-specifics appendix to the Evidence Pack
- Area: POLAND | P1 | M4 | M | Szymon
- Context: Spec 6 requires Poland-specific content the pack lacks: regime (DORA to KNF / NIS2 to KSC), KNF expectations (Rekomendacja D, cloud communique), UODO/RODO duties, language/residency/retention minima, eIDAS QTS providers. Source spec 6.1-6.5; struktura 6.
- Current state: VERIFIED no Poland appendix in Pipeline/ (grep Rekomendacja D/KNF/UODO/wykaz/KSC returns nothing); content lives only in spec/struktura.
- DoD: docs/poland-appendix.md (emitted into the pack) covers 6.1-6.5, each with the spec pin-cite placeholders + confirm-before-signoff markers preserved.
- Notes: Port spec 6.1-6.5; reference Dz.U. 2025 poz. 1069 (DORA op act), Dz.U. 2026 poz. 252 (KSC), KNF Rekomendacja D + komunikat chmurowy (23 Jan 2020), UODO 72h clock, eIDAS 2.0 (2024/1183). Keep confirm markers.
- Acceptance: Appendix covers all five 6.x subsections; pin-cite markers retained.
- Verification: grep rekomendacja d/komunikat chmurowy/dz.u. 2026 poz. 252/uodo/wykaz in the appendix, at least 5 matches.
- Deps: none
- Maps to: spec 6.1-6.5; struktura 6

#### T-110 - Document the qualified eIDAS QTS provider path
- Area: POLAND | P1 | M4 | S | Szymon
- Context: Spec 6.5 + 7.3 require qualified electronic timestamps (QTS) from a Polish/EU qualified trust service provider for legal admissibility. The pipeline uses best-effort RFC-3161, not a qualified eIDAS QTS. Source spec 6.5, 7.3; my-area mandate.
- Current state: VERIFIED README:33,46 claim RFC-3161 timestamps with no qualified-QTS distinction; no doc names a provider. Spec 6.5 names KIR Szafir, Asseco/Certum, EuroCert, CenCert under eIDAS 910/2014 + 2024/1183.
- DoD: The pack documents RFC-3161 (non-qualified) as default + qualified eIDAS QTS from a named provider as the upgrade; states which step (seal-evidence.sh RFC-3161 call) the QTS would replace, with the confirm caveat.
- Notes: Add a Qualified timestamps eIDAS QTS subsection listing KIR Szafir / Certum / EuroCert / CenCert + eIDAS basis; cross-link to the RFC-3161 step. Documented upgrade only; coordinates with T-100/T-101.
- Acceptance: Pack distinguishes RFC-3161 from qualified eIDAS QTS + names at least 2 providers; integration point identified.
- Verification: grep szafir/certum/eurocert/cencert/eidas/qts in the appendix, at least 3 matches; a sentence states RFC-3161 is non-qualified by default.
- Deps: T-107
- Maps to: spec 6.5, 7.3; spec 9 L5; my-area mandate

#### T-55 — Add reproducibility statement + rebuild-and-compare procedure (spec Part I.4)
- **Area:** Integrity chain | **Priority:** P2 | **Milestone:** M4 | **Effort:** M | **Owner:** Szymon
- **Context:** Spec Part I.4 / §7.6 and struktura §11.7 require a reproducibility statement — 'each release pins commit + build inputs (SLSA provenance) so a third party can rebuild and match the digest — the strongest possible proof this is really what runs in prod'. No such statement or procedure exists today, so the strongest integrity claim is unsupported.
- **Current state:** VERIFIED. No reproducibility artifact in the pack; provenance pins `gitCommit` (`generate-provenance.sh:71`) but no documented rebuild-and-match procedure. build-audit-document.py:62 covers tamper-evidence but not byte-reproducibility.
- **Definition of Done:** A reproducibility statement artifact + a documented (and ideally CI-exercised) procedure to rebuild the image from the pinned commit/inputs and compare the resulting digest.
- **Implementation notes:** Add a `reproducibility-statement.json` to the pack recording: pinned commit, base image digest, builder, toolchain digests (spec X.3), and a 'rebuild command' a third party can run. Optionally add a CI job (or doc-only first) that rebuilds and compares the digest, recording match/mismatch honestly. State limits honestly (true byte-reproducibility may not hold without a reproducible base image). Spec Part I.4, §7.6, X.3.
- **Acceptance criteria:**
  - The pack contains a reproducibility statement listing pinned inputs and a rebuild procedure.
  - It honestly states whether digest-match has been demonstrated or is design-only.
- **Verification:** `cd Pipeline && test -f evidence/reproducibility-statement.json && python3 -c 'import json;d=json.load(open("evidence/reproducibility-statement.json"));assert "git_commit" in d and "rebuild_procedure" in d;print("REPRO_OK")'`
- **Dependencies:** T-50
- **Maps to:** spec Part I.4, §7.6, X.3; struktura §11.7

#### T-72 — Generate a signed pinned-toolchain + tool-version inventory into evidence
- **Area:** Supply-chain | **Priority:** P2 | **Milestone:** M4 | **Effort:** S | **Owner:** Szymon
- **Context:** spec §4 requires 'a pinned tool inventory (Appendix X.3)' as the supply-chain self-defence evidence, and blueprint 04 §7 wants tool versions MEASURED not hardcoded. VERIFIED actions are SHA-pinned but no artifact enumerates which action SHAs + tool versions (cosign, syft, opa, trivy) actually ran, so the Evidence Pack cannot prove the toolchain.
- **Current state:** VERIFIED no `tool-versions.json` / pinned-inventory artifact in scripts or workflows; Trivy version is captured inline (build-and-scan.yml:74) but not surfaced as evidence.
- **Definition of Done:** A step writes `evidence/toolchain-inventory.json` containing (a) every `uses: <action>@<sha>` extracted from the workflows and (b) measured versions of cosign/syft/opa/trivy from `--version`; the file is included in the manifest and sealed.
- **Implementation notes:** `grep -rEoh 'uses: [^ ]+@[0-9a-f]{40}' .github/workflows/ | sort -u` for actions; `cosign version`, `syft version`, `opa version`, `trivy --version` for tools; emit JSON. Add to the evidence-completeness required set only as EVIDENCE-ONLY. Sealed by the existing seal-evidence flow so it inherits the manifest + timestamp.
- **Acceptance criteria:**
  - evidence/toolchain-inventory.json lists all action SHAs + the 4 tool versions actually run
  - The file appears in manifest.sha256 and is covered by the Merkle root
- **Verification:** `jq '.actions | length, .tools' evidence/toolchain-inventory.json` shows the action list + tool versions; `grep toolchain-inventory.json evidence/manifest.sha256` matches
- **Dependencies:** T-71
- **Maps to:** spec §4 (pinned tool inventory); blueprint 04 §7; struktura C.16

#### T-108 - Bake Polish statutory retention minima into the pack
- Area: POLAND | P2 | M4 | S | Szymon
- Context: Spec 6.4 requires statutory retention minima in Part I: AML 5y, accounting/tax 5y (Ordynacja podatkowa), DORA/NIS2 5y plus, financial longer. The WORM/lifecycle uses one hardcoded 1825, no per-class retention or Polish basis. Source spec 6.4; struktura 6.
- Current state: VERIFIED infra/main.tf:38 retention_days 1825 with a verify comment; storage/variables.tf defaults 1825; no per-class table or Polish basis.
- DoD: A retention table lists each data class with its Polish statutory minimum + citation; 1825 justified against the longest class with the confirm marker.
- Notes: Table AML 5y; accounting/tax 5y (Ordynacja podatkowa); DORA/NIS2 5y plus; financial longer - each with confirm. Reference from the retention_days comment.
- Acceptance: Pack documents per-class retention minima with Polish citations; 1825 justified.
- Verification: grep ordynacja podatkowa/AML/5y/1825 in the appendix, at least 3 matches.
- Deps: T-107
- Maps to: spec 6.4; spec 7.5

#### T-109 - Add data-residency assertion + Polish management layer
- Area: POLAND | P2 | M4 | M | Szymon
- Context: Spec 6.4: evidence for KNF/UODO/a Polish auditor is expected in Polish (or certified translation), and residency/lawful-transfer documented. The pack is English-only and asserts no concrete data location despite the Terraform example polandcentral. Source spec 6.4; SETUP.md:130.
- Current state: VERIFIED pack/report scripts emit English only; location flows from the RG (example polandcentral) but no artifact asserts region/lawful-transfer.
- DoD: A residency artifact records the deployed region + lawful-transfer basis; the management summary is available in Polish (translated or bilingual).
- Notes: Emit residency.json (azure_region, data_location, transfer_basis). Produce audit-summary.pl.md, or mark bilingual with the translate-per-engagement caveat (spec 6.4).
- Acceptance: A residency artifact records the real region + transfer basis; Polish summary present or requirement documented with the caveat.
- Verification: residency.json has azure_region + transfer_basis on a fixture; audit-summary.pl.md exists or appendix states polish translation per engagement.
- Deps: T-107
- Maps to: spec 6.4

---

## 5. Dependency graph / critical path

**Roots (48 tasks, no dependencies)** can start immediately — most of M0 and the foundational outputs (T-03, T-12, T-33, T-40, T-42, T-44, T-63, T-65, T-71) are here.

**Top unblockers (highest fan-out — fix these to free the most work):**

- **T-33** (shared validator envelope) → unblocks **16**: T-20..T-29 (all A.1–A.10), T-31, T-34, T-115, T-120, T-121, T-122. *The keystone of the entire compliance-as-code milestone.*
- **T-12** (content-matrix orchestrator) → unblocks **10**: T-11, T-13..T-19, T-115, T-125. *The keystone of the matrix + completeness layer.*
- **T-40** (Merkle-cosign fix) → unblocks **6**: T-41, T-51, T-56, T-57, T-58, T-123. *The keystone of the integrity chain + its self-tests.*
- **T-49** (provenance JSONL fix) → 3 (T-50, T-58, T-116); **T-85** (PR-mode) → 3 (T-86, T-89, T-124); **T-86** (green run) → 3 (T-89, T-90, T-124); **T-91** (sample pack) → 3 (T-92, T-93, T-94); **T-107** (Poland appendix) → 3 (T-108, T-109, T-110).

**Critical path to the sample Evidence Pack (T-91):**
`T-88 → T-81 → T-83 → T-86 → T-90 → T-91` (longest chain, 6 hops). To T-94 (founder-independent reproducer): 8 hops via `… → T-91 → T-92 → T-94`.

**Critical path to the signed compliance gate (T-30):** `T-33 → T-{20..29} → T-30` (3 hops; the breadth, not depth, is the cost — 10 parallel A.x validators all gate T-30).

**Three independent critical chains** (can run in parallel by different owners):
1. **Compliance:** T-33 → A.1–A.10 → T-30 → T-35 (and T-12 → T-13..T-17 → T-19).
2. **Integrity:** T-40 → T-41/T-56/T-57/T-58 + T-49 → T-50 → T-58; T-46 → T-48/T-52.
3. **Self-test/demo:** T-88 → T-81 → T-83 → T-86 → T-90 → T-91 → T-92/T-93/T-94.

---

## 6. "Fully operational" master checklist (12 objective items)

| # | Objective | Satisfying task IDs |
|---|---|---|
| 1 | Every gate fail-closed (SAST/CodeQL, Trivy fs+image, secrets, Checkov IaC, DAST, coverage, cosign-verify admission) | T-01, T-02, T-04, T-05, T-06, T-07, T-08, T-63, T-69, T-84 |
| 2 | Compliance matrix evaluates CONTENT not file-presence | T-12, T-13, T-14, T-15, T-16, T-17, T-18, T-125 |
| 3 | Compliance-as-code validators A.1–A.10 exist + run + emit signed PASS/FAIL into a compliance gate | T-20, T-21, T-22, T-23, T-24, T-25, T-26, T-27, T-28, T-29, T-30, T-33, T-34, T-19 |
| 4 | Integrity chain end-to-end (SBOM+provenance signed, Merkle root cosign-signed, RFC-3161 + path to eIDAS QTS, Rekor-verifiable, WORM, reproducible) | T-40, T-41, T-46, T-49, T-50, T-51, T-53, T-54, T-55, T-56, T-104 |
| 5 | 3 OPA policies wired into workflow steps + enforce | T-09, T-10, T-11, T-60, T-61, T-62, T-64, T-73, T-80 |
| 6 | Evidence-completeness blocking | T-11, T-42, T-43, T-58, T-61 |
| 7 | Static-emitter scripts replaced by real readers; tool versions measured not hardcoded | T-18, T-21, T-31, T-32, T-72 |
| 8 | Claims == reality (SLSA L2 unless L3 achieved; no SIEM rows w/o evidence; README==behavior) | T-44, T-45, T-47, T-95, T-96, T-97, T-98, T-99, T-100, T-101, T-122 |
| 9 | Governance plumbing real (CODEOWNERS resolves, Renovate runs, branch protection enforced, PR-path controls tested) | T-59, T-65, T-66, T-67, T-68, T-74, T-75, T-76, T-119, T-124 |
| 10 | Supply-chain self-defence (digest-pinned toolchain + Scorecard) | T-70, T-71, T-72 |
| 11 | A sample/demo Evidence Pack (8 components) generatable | T-35, T-89, T-90, T-91, T-92, T-93, T-94, T-102, T-103, T-115, T-116, T-117, T-118, T-120, T-121 |
| 12 | Pipeline self-tests (unit tests, opa test, green E2E on push AND PR) | T-34, T-57, T-64, T-80, T-81, T-82, T-83, T-84, T-85, T-86, T-123, T-124 |

---

## 7. Recommended execution sequence

Optimized for (a) the fastest credible sample Evidence Pack and (b) removing every checkable overclaim first.

**Wave 1 — Fix-the-lies (M0, do first; all roots, fully parallel).** Every checkable overclaim a buyer can falsify in minutes:
T-95, T-96, T-97, T-98, T-99 (claims) · T-44 (SLSA relabel) · T-01 (CodeQL gate) · T-08, T-69 (cosign identity) · T-40 → T-41 (Merkle-cosign + guard) · T-47 (WORM wording) · T-49 (provenance JSONL) · T-59, T-75 (rogue push trigger) · T-65 (CODEOWNERS) · T-84, T-114 (stale junit) · T-87 (Snapshot -1) · T-06 (PII fail-close) · T-21, T-31 (static emitters) · T-100/T-101 (README, gate-paired) · T-111 (bounded store).

**Wave 2 — Foundational outputs (M1, unblock the most).** T-33 (envelope → 16), T-12 (matrix → 10), T-63/T-03 (real outputs), T-32 (tool versions), T-42/T-43 (completeness blocking), T-50 (builder.id), T-56 (tsr assert), T-13 (DORA/DAST content), T-02/T-125 (Trivy/SARIF), T-04/T-05/T-07 (gates), T-74 (TF backend), T-76 (Checkov), T-112 (limits).

**Wave 3 — Compliance-as-code + integrity (M2).** A.1–A.10 (T-20..T-29) in parallel off T-33 → T-30; T-14..T-17 → T-19; OPA wiring T-60/T-61/T-62 → T-73; integrity T-46→T-48/T-52, T-51, T-53/T-54, T-45; Part C artifacts T-115/T-116/T-117/T-120/T-121; crosswalk T-102→T-103; IaC T-104→T-105; T-09/T-10/T-11.

**Wave 4 — Governance plumbing + self-tests (M3).** T-64/T-80 (opa test), T-88 → T-81/T-82 → T-83 (unit suites), T-67 (branch protection, needs T-64/T-65) → T-68/T-119/T-124, T-66 (Renovate), T-70/T-71/T-72 (Scorecard + pin-audit), T-85 → T-86 (green E2E), T-18/T-34/T-57/T-58/T-123, T-106/T-113/T-118/T-122.

**Wave 5 — Sample pack + docs (M4).** T-90 → T-91 → T-92/T-93 → T-94 (the deliverable), T-35 (compliance-as-code pack section), T-89 (enforcement proof), T-55, T-72, T-107 → T-108/T-109/T-110 (Poland).

---

## 8. Open questions & decisions

1. CodeQL Option A (block on level==error / security-severity>=7.0) vs honest relabel to advisory — confirm Szymon accepts false-positive risk + expiring suppression list. Tasks default to Option A with relabel fallback (T-01).
2. MegaLinter: gate JS/TS/Dockerfile-Hadolint as errors vs relabel advisory — confirm acceptable strictness (T-05).
3. Checkov 19-skip list: does each skip map to a real compensating control? Some may need to be UN-skipped (gate stricter) (T-04/T-76).
4. compliance-validate job placement: inside evidence-pack.yml or a new reusable workflow before it? (T-19/T-30).
5. Signing the aggregated compliance verdict: cosign sign-blob over compliance-status.json inside seal-evidence.sh? Cross-stream with integrity owner (T-19/T-30).
6. EBA Register-of-Information field list (RT.01/RT.05) must be confirmed against current ITS 2024/2956 by a compliance advisor (T-36, external).
7. Is a real LEI available for CyberForge? Without it, validate-roi can only check format, not registration — label EVIDENCE-ONLY until issued (T-20).
8. Signing identity for A.* artifacts: reuse keyless cosign sign-blob or a dedicated key? Affects independent verification of each verdict (T-30).
9. Should the compliance gate block on PR runs or only non-PR (mirroring degrade-on-PR)? Recommend block on non-PR, warn on PR (T-30).
10. RoPA/DPIA (A.3): does the demo app process any personal data? If not, DPIA may be 'not required' but must be evidenced as a documented determination, not silence (T-22/T-31).
11. Should WORM locking (T-46) apply to live prod storage now (irreversible, blocks destroy) or stage behind a prod-only flag? One-way door.
12. Which qualified eIDAS QTS provider — KIR Szafir vs Asseco Certum? Endpoint + auth scheme determines seal-evidence.sh integration shape and cost (T-53/T-110).
13. Is true byte-for-byte reproducibility (T-55) in scope, or is a documented design-level statement sufficient for the current sales stage?
14. Add SBOM/provenance Rekor verification to the deploy admission gate (cosign verify-attestation) as well, or only to the offline runbook? (T-51).
15. Authoritative repo: nested Pipeline/.git (1 commit d53cb2e) or outer CyberForge tracking Pipeline/ files? Outer tree has uncommitted CODEOWNERS/workflow edits. Settle the deploy/sync target before applying governance changes (T-65..T-69).
16. What is the actual GitHub owner/org and repo name on the remote? Needed for branch-protection, CODEOWNERS team, Renovate, Scorecard publish_results, codeowners/errors API (T-65..T-71).
17. Does the org plan permit creating teams (T-65) and is the Renovate App installable (org vs personal)? If personal, T-66 must use the self-hosted action.
18. Pin cosign identity to @refs/heads/main only, or also tags/release refs? Releases from tags would be rejected by a main-only regexp (T-69).
19. conftest not installed locally (only opa) — confirm wiring standard is `opa eval` (blueprint 04 §4) not conftest, for consistent setup action + CI image.
20. Demo-repo identity: fresh public org/repo or existing Cyberforge-Pipeline-Priv sanitized? blueprint 01 §1.6 says use a neutral target (T-90).
21. Qualified eIDAS QTS for the sample, or ship freetsa.org labeled 'non-qualified (demo)' to stay honest? Affects T-91/T-93 integrity-proof wording.
22. Shell-script coverage via bats: is kcov/bashcov acceptable in CI, or target count-of-functions-covered instead of % line coverage? Affects T-81/T-83 DoD.
23. Keep Snapshot-Codex or Snapshot/ as canonical (Snapshot/ has the fuller analyzer set incl. models/+report/)? T-88 must delete exactly one.
24. Monitoring error-spike alert can-never-fire (monitoring/main.tf:80-96: counts result rows vs threshold>10, time_aggregation_method Count) — VERIFIED real bug. If no other stream ID range covers it, it needs a dedicated task (COMPANY-AUDIT 3.4). Confirm ownership.
25. Translate Poland management layer to Polish now (T-109) or defer to per-engagement certified translation (spec 6.4 caveat)?
26. Network-hardened variant (T-106): should the CI runner reach private endpoints (self-hosted runner / trusted-services exception), or is the hardened variant deploy-only?
27. Pipeline/docs/cost-management.md:84 lists Azure Sentinel as a production upgrade (correctly future-framed). Leave as-is or add an explicit not-implemented-in-base note?
