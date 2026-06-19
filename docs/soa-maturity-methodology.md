# Part D.3 — Statement of Applicability + Maturity Scoring (methodology)

> **What this document is.** The human-readable companion to Evidence Pack **Part D.3**
> ("Statement of Applicability (ISO 27001) + maturity scores (SAMM)",
> [evidence-pack-specification.md §Part D](../../evidence-pack-specification.md)). It
> explains how the pack's headline maturity level is **computed from real evidence
> state** rather than asserted, and how the ISO 27001 Statement of Applicability is
> parsed into the pack. The machine-readable artifact is
> [`evidence/soa-maturity.json`](#5-the-soa-maturityjson-artifact), produced by
> [`scripts/validators/soa_maturity.py`](../scripts/validators/soa_maturity.py).
>
> This document is design intent + methodology; the **numbers** in any given pack come
> from the validator run against that pack's evidence directory, never from prose here.

Task: **T-122** (OPERATIONALIZATION-TASKLIST.md). Maps to spec **Part D.3** and the
**§9 L1->L5 maturity benchmark** (evidence-pack-specification.md:80, 289-302) and
corrects the hardcoded-L5 overclaim at struktura §13
(CyberForge-Evidence-Pack-struktura.md:315-322).

---

## 1. Why a computed score (the overclaim it removes)

The pack structure (struktura §13) previously printed a fixed headline:

> "Pakiet jest dostarczany na poziomie **L5 (state-of-the-art)**" — *the pack is
> delivered at level L5*.

A self-declared L5 with no computed evidence is exactly the rejection trigger the spec
warns about (spec §8 #1 "evidence assembled for the audit, not produced by the
pipeline"; #9 "provenance unsigned... can't prove"). **T-122 replaces the hardcoded
headline with a level computed from the artifacts that actually exist in the pack**, so
the maturity claim is falsifiable by re-running the validator.

**Rule:** the headline maturity level equals the **lowest** of the five scored
dimensions (a chain is only as strong as its weakest link). It is never a literal `L5`.

---

## 2. The Statement of Applicability that is parsed

Source document:
[`docs/governance/statement-of-applicability.md`](governance/statement-of-applicability.md)
(ISO/IEC 27001:2022 Clause 6.1.3 d).

The validator parses **every Annex A control row** — `Control | Name | Applicable? |
Justification | Status | Reference` — across the four ISO/IEC 27001:2022 themes and
recomputes coverage **directly from the rows**, deliberately ignoring the document's own
"Summary Statistics" table (so a stale hand-edited summary cannot inflate the score).

| Theme | ISO 27001:2022 control count |
|---|---|
| A.5 Organizational | 37 |
| A.6 People | 8 |
| A.7 Physical | 14 |
| A.8 Technological | 34 |
| **Total** | **93** |

(Annex A = 93 controls in four themes — ISO/IEC 27001:2022; corroborated against the
public reference list, see Sources.) The validator asserts the parsed row count equals
93 (`structurally_complete`) so a truncated SoA is flagged rather than silently scored.

> **Honest gap surfaced.** The SoA's hand-written "Summary Statistics" table claims
> 61 implemented / 18 partially-implemented. Recomputed from the actual rows the figures
> are **58 implemented / 21 partially-implemented / 4 planned / 10 not-applicable**
> (83 applicable of 93). The validator emits the recomputed figures; the static summary
> table in the SoA should be corrected to match (a one-line documentation fix, tracked
> as follow-up — see §6).

---

## 3. The five maturity dimensions (§9)

Five §9 dimensions are scored (the subset the pack's pipeline can measure objectively;
the remaining §9 rows — Resilience, Third-party, Incident readiness — are governed by
the dedicated A.x validators and the DORA/NIS2 registers, not by this scorer). The
L1/L3/L5 anchors are taken **verbatim** from the spec §9 table.

| Dimension | L1 (passing) | L3 (strong) | L5 (state of the art) | Honest ceiling in this pack |
|---|---|---|---|---|
| Evidence production | Manual, screenshots | Pipeline emits artifacts | Every artifact auto-signed + QTS + Rekor at production | **L4** — timestamp is non-qualified (freetsa); L5 needs **QTS** |
| Build integrity | Build runs | SBOM per release | SLSA Build L3, non-falsifiable provenance, reproducible | **L4** — provenance is **SLSA Build L2** (evidence-pack.yml:200), not L3 |
| Scanning | SAST runs sometimes | SAST/DAST/SCA/IaC/container all gate | + VEX triage, OpenSSF Scorecard, digest-pinned toolchain | **L3** until VEX + Scorecard + digest-pinned toolchain artifacts are in the pack |
| Compliance mapping | Spreadsheet of controls | Crosswalk to 2-3 frameworks | One evidence -> all frameworks, auto-generated, gap-tracked live | **L4** — L5 needs the auto-generated one-evidence->all-frameworks crosswalk (T-102) |
| Integrity | Files in a folder | Signed + retained | Qualified timestamps, transparency log, immutable WORM, reproducible | **L4** — RFC-3161 timestamp is **non-qualified** (freetsa, evidence-pack.yml:327); L5 needs QTS |

The "SAMM" lineage: OWASP SAMM is a maturity model scoring security practices by level;
the spec §9 table is the pack's own L1->L5 adaptation of that idea, and is the
authoritative scale used here (see Sources).

---

## 4. How each dimension is scored (from real evidence state)

The scorer probes the evidence directory for **presence + non-emptiness** of the
canonical artifacts the evidence-pack workflow writes (artifact names verified read-only
against `.github/workflows/evidence-pack.yml`). It NEVER inspects content to claim a
control passed — that is the job of the per-article A.1-A.10 validators. Presence/signing
state alone drives the level, so the score cannot be faked by a well-worded document.

| Dimension | L3 awarded when... | L4 awarded when... | L5 (not reachable in this pack) |
|---|---|---|---|
| Evidence production | `manifest.json` **or** the board report present | manifest **and** report present | + qualified timestamp (QTS) + Rekor |
| Build integrity | `sbom.cyclonedx.json` present | SBOM **and** `provenance.intoto.json` present | SLSA Build L3 + reproducible |
| Scanning | scan output **and** SCA output present | (n/a) | + VEX + Scorecard + digest-pinned toolchain |
| Compliance mapping | `compliance-matrix.json` present | matrix **and** OSCAL **and** SoA complete (93) | auto-generated live-gap-tracked crosswalk |
| Integrity | a cosign signature present | `merkle-root.cosign.bundle` **and** an `*.tsr` present | QTS + transparency log + immutable WORM |

**Empty / missing evidence does not silently pass.** A dimension stays at the level it
can actually prove, with the missing artifact named in its `detail` string. When the SoA
itself is missing or unparseable the overall verdict is `INDETERMINATE` (a measured
nothing), never a score.

---

## 5. The `soa-maturity.json` artifact

The validator emits a [T-33 envelope](../scripts/validators/libcompliance.py)
(`status / tier / measured / threshold / detail / tool_version / validator /
checked_at`) at the **EVIDENCE-ONLY** tier — a maturity *score* is a measured fact for
the pack, not a build-breaking gate (the per-article validators own the blocking gate),
so it never breaks the build regardless of the computed level.

Shape (abridged):

```json
{
  "status": "PASS | FAIL | INDETERMINATE",
  "tier": "EVIDENCE-ONLY",
  "measured": {
    "overall_level": "L3",
    "dimension_levels": {
      "evidence_production": "L4", "build_integrity": "L4",
      "scanning": "L3", "compliance_mapping": "L4", "integrity": "L4"
    }
  },
  "overall_level": "L3",
  "weakest_dimensions": ["scanning"],
  "soa": {
    "total_controls_parsed": 93, "structurally_complete": true,
    "by_theme": {"A.5": 37, "A.6": 8, "A.7": 14, "A.8": 34},
    "applicable": 83, "implemented": 58, "partially_implemented": 21,
    "planned": 4, "not_applicable": 10,
    "implementation_rate_applicable": 0.8253
  },
  "dimensions": { "...": "per-dimension level + §9 anchors + the probed evidence flags" }
}
```

`overall_level` is the **minimum** of `dimension_levels` — the single field that
replaces the hardcoded `L5` in the pack headline.

**Run it:**

```bash
python3 scripts/validators/soa_maturity.py \
    docs/governance/statement-of-applicability.md \
    --evidence-dir evidence \
    --out evidence/soa-maturity.json
jq .measured.overall_level evidence/soa-maturity.json
```

---

## 6. Wiring into the pack (deferred — post-M0)

These steps touch shared / protected files and are intentionally NOT done in this task:

- **Render Part D.3 into the board document.** `scripts/build-audit-document.py` should
  read `evidence/soa-maturity.json`, render the SoA coverage table (applicable /
  implemented / justification columns) and the five dimension levels, and set the
  document's headline maturity to `overall_level` (never a literal `L5`). The renderer
  is a shared artifact also touched by the crosswalk/matrix tasks, so the edit is
  sequenced after the M0 workflow freeze.
- **Run the validator in the evidence-pack workflow** (`.github/workflows/evidence-pack.yml`)
  so `soa-maturity.json` is produced and sealed with the rest of the evidence. Workflow
  wiring is a deliberate post-M0 task.
- **Correct struktura §13** wording from the hardcoded "L5 (state-of-the-art) — nasz
  poziom" to "computed per pack (see `evidence/soa-maturity.json`)".
- **Fix the SoA Summary Statistics table** (58/21 vs the stale 61/18 — see §2).

---

## 7. Compliance mapping

| Requirement | Reference |
|---|---|
| Statement of Applicability | ISO/IEC 27001:2022 Clause 6.1.3 d), Annex A (93 controls) |
| Maturity scoring (Part D.3) | evidence-pack-specification.md:80; struktura §13 |
| L1->L5 benchmark dimensions | evidence-pack-specification.md:289-302 (§9) |
| Honest, non-overclaimed maturity | spec §8 #1, #9; blueprint/04 §2 (no silent PASS) |
| SAMM lineage | OWASP SAMM v2 (maturity-by-practice model) |

---

## 8. Sources

- ISO/IEC 27001:2022 Annex A — 93 controls in 4 themes (Organizational 37 / People 8 /
  Physical 14 / Technological 34); SoA required by Clause 6.1.3 d).
  <https://hightable.io/iso-27001-annex-a-controls-reference-guide/>
- OWASP SAMM v2 — Software Assurance Maturity Model (maturity levels per security
  practice / business function). <https://owaspsamm.org/model/>
- Evidence Pack master spec §9 maturity benchmark (L1->L5) —
  [evidence-pack-specification.md](../../evidence-pack-specification.md) lines 289-302.
