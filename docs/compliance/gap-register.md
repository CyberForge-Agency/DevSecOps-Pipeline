# Compliance Gap Register — CyberForge DevSecOps Pipeline

**Document Owner:** CTO (Evidence & Compliance domain — see [control-owners.md](../governance/control-owners.md))
**Last Reviewed:** 2026-06-16
**Review Cadence:** Per Evidence Pack production run + monthly during open-gap remediation
**Version:** 1.0
**Status of this document:** Living register — partially TARGET-STATE (auto-derivation from the crosswalk is not yet wired; see §4)

## 1. Purpose

This register records every **open compliance gap** in the CyberForge DevSecOps
Pipeline: each control that is *not yet satisfied*, mapped to the gap, a severity,
a root cause, a single accountable owner, and a target remediation date. It exists
to satisfy the master spec requirement (spec §5.3) for a **gap register
(control → gap → severity → root cause)** that complements the crosswalk
(T-102) and to make remediation **bounded and accountable** — spec §8 anti-pattern
#5 rejects unbounded risk acceptances and "guardrails that warn but never block".

Standard gap-register practice — severity classified by *risk impact* (not effort),
a single accountable owner per control, realistic timelines, and leadership
sign-off — is followed here (see Sources). Risk **acceptances** (with named
approver + expiry) live in the separate
[exception-register.md](./exception-register.md); this file tracks gaps that are
**being remediated**, not accepted.

### 1.1 What this register is NOT

- Not a risk-acceptance log — accepted risks with approver+expiry go to
  [exception-register.md](./exception-register.md).
- Not legal advice or an auditor opinion.
- Not a substitute for the framework-specific
  [statement-of-applicability.md](../governance/statement-of-applicability.md) or
  [framework-boundaries.md](./framework-boundaries.md).

## 2. Severity, root-cause, and status conventions

These conventions are derived from the compliance-as-code (CAC) validator library
this register aggregates ([libcompliance.py](../../scripts/validators/libcompliance.py:30-41)).

### 2.1 Severity

Severity reflects **risk impact**, anchored to the validator **tier** that produced
the finding:

| Severity | Meaning | Anchor |
|----------|---------|--------|
| **HIGH** | A `BLOCKING`-tier validator FAILs, or a HARD regulatory clause is unsatisfied. A FAIL here exits non-zero and would stop merge/deploy/seal when the validator is wired into a gate. | `tier: BLOCKING` + `status: FAIL` |
| **MEDIUM** | An `EVIDENCE-ONLY` validator records a failing/INDETERMINATE measurement, or a soft clause is unsatisfied, or a deferred-wiring gap means a BLOCKING check is authored-but-not-enforced. | `tier: EVIDENCE-ONLY`, or wiring deferred |
| **LOW** | A roadmap/maturity delta (e.g. SLSA L2→L3) that is honestly disclosed and not currently claimed. | maturity/roadmap |

A clause that is **Phase-F / Outside-Pipeline-Scope**
([framework-boundaries.md](./framework-boundaries.md) category 3) is **labelled, not
flagged as a gap** (per T-103 Notes): it appears in §5.3 for transparency but
carries no severity/target date because it is an organizational, not a pipeline,
control.

### 2.2 Root cause

Per T-103 Notes, root cause is derived from the **presence/PASS** state of the
underlying evidence:

- `evidence-stale` — artifact present but outside its freshness window.
- `evidence-absent` — required artifact/entry does not exist (e.g. empty log).
- `wiring-deferred` — validator exists and PASS/FAILs locally but is not yet
  invoked by a pipeline gate, so a FAIL does not block.
- `maturity-delta` — control is at a lower assurance level than the target; the
  delta is disclosed, not overclaimed.
- `external-truth` — pipeline records the content but cannot prove the world-fact
  (EVIDENCE-ONLY); a gap only if the *recorded value* itself fails.

### 2.3 Status

| Status | Meaning |
|--------|---------|
| **OPEN** | Gap is real today and under remediation. |
| **TARGET-STATE** | The remediating capability is planned/in-flight (a sibling operationalization task) but not yet shipped. |
| **CLOSED** | Re-validated PASS; retained for audit trail with the closing run. |

## 3. How this register is populated

Each row is grounded in a **real, reproducible measurement** captured on
2026-06-16 by running the CAC validators against the committed evidence. The exact
command and observed `status`/`detail` are recorded in the **Evidence** column so an
auditor can reproduce it. No row is speculative: a control is a gap only because a
validator legitimately reports it as such today.

## 4. Crosswalk linkage (TARGET-STATE)

The master spec (§5.3-5.4, T-103 DoD) requires that `generate-crosswalk` *also*
emit a machine-readable `gap-register.json` with **one row per unsatisfied clause**
(severity from HARD/soft, root_cause from presence/PASS), rendered into the Evidence
Pack. That is **not yet wired**:

- `scripts/generate-crosswalk*` and `scripts/crosswalk-mapping.yaml` **do not exist
  yet** (T-102, a parallel task) — VERIFIED: `ls scripts/generate-crosswalk*` → no
  matches (2026-06-16).
- Therefore the **machine-derived** gap register (`gap-register.json` keyed off
  per-clause satisfied/unsatisfied from the crosswalk) is **TARGET-STATE**.
- This Markdown register is the **hand-curated interim** source of truth and the
  acceptance fixture for the future emitter: every `OPEN` HIGH/MEDIUM row below
  must reappear as an unsatisfied-clause row in `gap-register.json` once T-102/T-103
  generation lands; no `PASS` (satisfied) clause may appear as a gap.

**Follow-up (post-M0 wiring):** when T-102's `generate-crosswalk` exists, extend it
to emit `gap-register.json` from the unsatisfied rows + the severity/root-cause
taxonomy in §2, and render both into the pack (build-audit-document.py + manifest /
Merkle root). Acceptance per T-103: partial fixture length > 0; complete fixture
length 0.

## 5. The register

### 5.1 Open gaps (pipeline-addressable)

> Owners are role names from [control-owners.md](../governance/control-owners.md)
> §3 (CyberForge is a two-founder startup; one person may hold multiple roles).

| # | Control / Clause | Gap | Severity | Root cause | Owner | Target date | Status | Evidence (reproduce) |
|---|------------------|-----|----------|------------|-------|-------------|--------|----------------------|
| G-01 | A.10 Restore test — DORA Art.11-12 / NIS2 21(2)(c) / ISO 27001 A.8.13 | No successful, in-window restore drill has been conducted; `restore-test-log.yaml` is `tests: []`. "Backups without a restore test" is an explicit auditor rejection trigger. | **HIGH** | `evidence-absent` | DevOps Lead (backup: CTO) | 2026-07-15 (run + log one Terraform-state restore drill, RTO ≤ 60min, RPO 0) | OPEN | `python3 scripts/validators/check-restore-test.py` → `FAIL: no restore drill logged (bcdr-plan.md S.6.1: 'Not yet conducted')` |
| G-02 | Vendor / DPA register freshness — DORA Art.28-30 (third-party register) / ISO 27001 A.5.19 | `vendor-risk-register.md` last reviewed 2026-03-15 = 93 days old; freshness limit 92 days → register is stale by 1 day. | **HIGH** | `evidence-stale` | CTO (backup: Security Lead) | 2026-06-23 (re-review vendor/DPA register; reset `Last Reviewed`) | OPEN | `bash scripts/check-dpa.sh` → `FAIL … measured 93, threshold 92 … 93 days ago; limit 92 days` |
| G-03 | A.8 Access reviews — SOC 2 CC6.1-CC6.3 / ISO 27001 A.5.18 / NIS2 21(2)(i) | 4 of 7 access reviews are overdue by 1 day (Privileged GitHub Org Owners, Privileged Azure roles, Service principals, Branch protection; all due 2026-06-15). | **HIGH** | `evidence-stale` | Security Lead (backup: CTO) | 2026-06-22 (conduct the 4 overdue reviews; record next-due) | OPEN | `python3 scripts/validators/check-access-reviews.py` → `FAIL: 4 access review(s) overdue (worst: … by 1d)` |
| G-04 | DORA Art.28(8) / ICT-third-party exit plans — register-of-information exit strategy | 2 of 3 Critical/High vendors lack a Documented/Tested exit plan: GitHub (EP-001 "Template available"), Microsoft Azure (EP-002 "Planned"). | **HIGH** | `evidence-absent` (plans not documented/tested) | CTO (backup: Security Lead) | 2026-08-31 (author + tabletop-test EP-001/EP-002) | OPEN | `python3 scripts/validators/check-thirdparty-clauses.py` → `FAIL … 2 of 3 Critical/High vendor(s) lack a Documented/Tested exit plan` |
| G-05 | CAC validator suite not wired into the gate — spec §8 "guardrails that warn but never block" | Only `check-dpa.sh` is invoked by `evidence-pack.yml` (line 175). The BLOCKING validators check-restore-test, validate-ropa, check-governance, check-access-reviews, check-incident-register, check-thirdparty-clauses, validate-roi, assert-crypto are authored but **not enforced** — their FAILs (G-01..G-04) do not block seal/deploy today. | **MEDIUM** | `wiring-deferred` | CTO (Evidence & Compliance) | 2026-07-31 (aggregate into a blocking compliance-gate — see T-19) | OPEN | `grep -nE 'validators/\|check-restore\|validate-ropa\|check-access' .github/workflows/evidence-pack.yml` → only `check-dpa.sh` (line 175) |
| G-06 | NIS2 Art.20(2) — management cybersecurity training records | `training_attendees_recorded = 0`: the training log has no populated attendee rows (EVIDENCE-ONLY: pipeline records the log, not that training occurred). | **MEDIUM** | `evidence-absent` | CTO (management body) | 2026-07-31 (record ≥1 completed management-training attendee) | OPEN | `python3 scripts/validators/check-governance.py` → `training_attendees_recorded … FAIL … 0 populated training-attendee row(s)` |
| G-07 | DORA Art.28(3) — maintaining-entity LEI | CyberForge has no issued ISO 17442 LEI; register-of-information records the maintaining-entity LEI as PENDING/placeholder. EVIDENCE-ONLY (GLEIF lookup is outside the pipeline). | **MEDIUM** | `external-truth` | CTO | 2026-09-30 (obtain a GLEIF-issued LEI for CyberForge) | OPEN | `python3 scripts/validators/validate-roi.py` → `maintaining-entity LEI PENDING … EVIDENCE-ONLY gap, not blocking` |
| G-08 | CODEOWNERS / code-owner review — spec §4 source control, SOC 2 CC6.1, bug K6 | All 5 CODEOWNERS rules point at `@CyberForge-Agency/security-team`, a team that is not proven to resolve; `branch-protection.json` sets `require_code_owner_reviews: true` against a possibly non-resolving owner, so code-owner review may never actually be required. | **HIGH** | `evidence-absent` (owner does not resolve) | Security Lead (backup: CTO) | 2026-06-20 (M0 — create the team or repoint to real handles; `gh api …/codeowners/errors` returns 0) | OPEN | `cat .github/CODEOWNERS` (5 rules → `@CyberForge-Agency/security-team`); verify via `gh api repos/<o>/<r>/codeowners/errors --jq '.errors\|length'` == 0. Remediation tracked by T-65 (M0). |

### 5.2 Roadmap / maturity deltas (disclosed, not claimed)

| # | Control / Clause | Gap | Severity | Root cause | Owner | Target date | Status | Evidence |
|---|------------------|-----|----------|------------|-------|-------------|--------|----------|
| G-09 | SLSA Build provenance — spec §3 "Build provenance" / struktura C.12 | Pipeline is **SLSA Build L2**, not L3. L3 deltas (provenance from a hosted/isolated builder the tenant cannot influence; non-falsifiable provenance with signing keys inaccessible to build steps; ref-pinned builder identity) are not met. Honestly disclosed; L3 is **not** claimed. | **LOW** | `maturity-delta` | DevOps Lead (backup: CTO) | 2026-Q4 (scope L3 gap doc — T-45 — then implement) | OPEN | `grep -n 'SLSA Build L2' scripts/build-audit-document.py` (lines 9,26,58,1602: "L3 is NOT claimed — provenance best-effort, not isolated"). `docs/slsa-l3-gap.md` does not exist yet (T-45). |
| G-10 | eIDAS qualified timestamp (QTS) — spec §7.3 / struktura §11 | RFC-3161 timestamps default to freetsa.org, a **non-qualified** TSA; legally-facing artifacts that need a qualified eIDAS timestamp (KIR Szafir / Certum) are not yet qualified. Manifest must record `qualified=false` honestly. | **LOW** | `maturity-delta` | CTO (Evidence & Compliance) | 2026-Q4 (make TSA pluggable + document QTS path — T-53) | OPEN | `seal-evidence.sh` defaults `TSA_URL=https://freetsa.org/tsr`; manifest `signatures.rfc3161.qualified` should read `false`. |

### 5.3 Phase-F / outside-pipeline-scope clauses (labelled, NOT flagged)

Per [framework-boundaries.md](./framework-boundaries.md) category 3 (Outside
Pipeline Scope) and T-103 Notes, these are organizational/legal controls a CI/CD
subsystem cannot satisfy. They are listed for transparency and carry **no severity
or target date** — they are *not* pipeline gaps.

| Control / Clause | Note |
|------------------|------|
| NIS2 Art.20(1) management-body approval; board risk-tolerance sign-off (DORA Art.5(2)) | Organizational — recorded in governance docs; the pipeline records the approval block, it does not perform board governance. (`check-governance.py` already PASSes the recorded sign-off block.) |
| Physical security, HR vetting, legal contract negotiation (ISO 27001 A.6, A.7) | Outside CI/CD scope — covered by the ISMS, not the pipeline. |
| Actual occurrence of management cybersecurity training (vs the log of it) | EVIDENCE-ONLY by nature; the pipeline can only check the record exists (see G-06 for the record gap). |

## 6. Summary

- **Open HIGH gaps:** 5 (G-01 restore test, G-02 vendor/DPA stale, G-03 access reviews overdue, G-04 vendor exit plans, G-08 CODEOWNERS). All are BLOCKING-tier validator FAILs grounded in reproducible commands.
- **Open MEDIUM gaps:** 3 (G-05 validator-wiring deferred, G-06 training attendees, G-07 LEI pending).
- **Open LOW (roadmap) deltas:** 2 (G-09 SLSA L2→L3, G-10 non-qualified TSA).
- **PASS today (no gap):** validate-ropa (RoPA complete), check-incident-register (2 incidents, all clock fields), check-governance freshness + board sign-off, validate-roi schema/LEI-format.
- **Machine emitter:** `gap-register.json` derivation from the crosswalk is **TARGET-STATE** (T-102/T-103 wiring; §4).

## 7. Related documents

- [exception-register.md](./exception-register.md) — accepted risks (approver + expiry)
- [framework-boundaries.md](./framework-boundaries.md) — scope categories (incl. Phase-F)
- [compliance-matrix.md](../compliance-matrix.md) — design-intent control mapping
- [control-owners.md](../governance/control-owners.md) — owner role definitions
- [statement-of-applicability.md](../governance/statement-of-applicability.md) — ISO 27001 SoA
- `scripts/validators/` — the CAC validators this register aggregates

## 8. Sources

Gap-register / remediation structure (severity by risk impact, single accountable
owner, leadership sign-off):

- [ISO 27001 Gap Analysis: Steps, Checklist & Templates (Sprinto, 2026)](https://sprinto.com/blog/iso-27001-gap-analysis/)
- [How to conduct an ISO 27001 gap analysis (Scrut)](https://www.scrut.io/hub/iso-27001/iso-27001-gap-analysis)
- [ISO 27001 Gap Analysis: Complete Practical Guide 2026 (ComplyJet)](https://www.complyjet.com/blog/iso-27001-gap-analysis)
- [How DORA fits with ISO 27001, NIS2 and the GDPR (GRC Solutions)](https://grcsolutions.io/how-dora-fits-with-iso-27001-nis2-and-the-gdpr/)
- [DORA vs NIS2: differences, overlaps, compliance impact (Invicti)](https://www.invicti.com/blog/web-security/dora-vs-nis2-differences-overlaps-compliance-impact)
