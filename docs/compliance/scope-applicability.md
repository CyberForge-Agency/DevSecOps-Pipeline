# Scope & Applicability Determination

**Document owner:** CyberForge Management (accountable: Managing Director)
**Maps to:** Evidence Pack spec Part B (B.1 entity classification · B.2 system & data inventory + residency map · B.3 regulatory applicability matrix with rationale) — `evidence-pack-specification.md:61-64`; Poland regulatory regime determination spec §6.1 — `evidence-pack-specification.md:228`; struktura Part 0.4 *Oświadczenie o stosowalności*.
**Addresses rejection trigger:** spec §8 anti-pattern #10 — *"Scope hand-waving — no documented rationale for why DORA/NIS2/CRA do or don't apply"* (`evidence-pack-specification.md:282`).
**Status:** Human-readable source-of-truth determination. The machine-validated, signed encoding (`docs/governance/applicability.yaml` + `scripts/validators/applicability.py` → `evidence/scope-determination.json`) is delivered separately under **T-120**; this document is the rationale that artifact must agree with. See [Boundary with T-120](#7-boundary-with-the-machine-validated-artifact-t-120).
**Review cadence:** Annually, and on any material change to entity size, services, markets, or the regulatory texts cited (these are the triggers that flip a verdict below).
**As-of date:** 2026-06-16.

> **Honesty note.** Verdicts here are a *self-classification* by CyberForge based on the regulatory texts cited and the entity facts in [§1](#1-b1--entity-classification). Self-classification is what the regimes require entities to perform (e.g. KSC self-identification by 2026-10-03), but it is **not** a legal opinion and does not bind a supervisory authority. Items marked **EVIDENCE-ONLY** depend on facts (entity size, whether a product is placed on the market) that the pipeline cannot verify and that a human must keep current. ⚠️ markers flag pin-cites the master spec itself flagged as "lock before sign-off" (`evidence-pack-specification.md:226`).

---

## 1. B.1 — Entity classification

### 1.1 The entity

| Field | Value | Source |
|---|---|---|
| Legal entity | CyberForge Sp. z o.o. | `docs/governance/isms-scope.md:22` |
| Registered office | Poland | `docs/governance/isms-scope.md:23` |
| Industry | Information technology — DevSecOps services, CI/CD hardening, compliance-enabling delivery automation | `docs/governance/isms-scope.md:24,28` |
| Size class | **Micro-enterprise** (fewer than 10 employees; assumed turnover/balance-sheet ≤ €2M) | `docs/governance/isms-scope.md:24,105` |
| Operating model | Remote-first, cloud-native; infrastructure in Azure **Poland Central** | `docs/governance/isms-scope.md:25`; `docs/governance/data-flow.yaml:60,73` |
| Primary markets | Polish financial, critical-infrastructure, and technology sectors | `docs/governance/isms-scope.md:26` |
| Role in clients' value chain | **ICT third-party service provider** — supplies a CI/CD / software-supply-chain control subsystem to client financial entities; client code & infrastructure are explicitly **out of CyberForge's operational control** | `docs/compliance/scope-and-limitations.md:99-102`; `docs/governance/isms-scope.md:80-81` |

### 1.2 Headline classification (the three questions the spec asks)

| Question (spec B.1) | Verdict | One-line basis (full rationale in [§3](#3-b3--regulatory-applicability-matrix-with-rationale)) |
|---|---|---|
| **DORA in-scope (as a financial entity)?** | **No** — not a financial entity | CyberForge is an *ICT third-party service provider*, not one of DORA Art. 2(1) financial-entity types. Flow-down obligations apply via its clients' contracts; direct DORA financial-entity obligations do not. |
| **DORA — designated *critical* ICT third-party provider (CTPP)?** | **No** | CTPP designation (DORA Art. 31) targets systemically important, low-substitutability providers; a micro-enterprise is not a designation candidate. The first ESA CTPP list (18 Nov 2025, 19 providers) confirms the scale of designated entities. |
| **NIS2 *podmiot kluczowy / ważny*?** | **No (today)** — sector met, **size threshold not met** | Activity falls in NIS2 Annex I *ICT service management (B2B)* as an MSP/MSSP **(sector criterion satisfied)**, but the KSC size criterion (medium = *ważny*, large = *kluczowy*) is **not** met by a micro-enterprise, and no size-independent category (DNS/TLD/trust service/public-comms) applies. **Watch item — flips on growth.** |
| **CRA manufacturer?** | **No (today)** | CyberForge does not place a *product with digital elements* on the EU market under its own name/trademark; it delivers a service and an internal demo app. **Watch item — flips if the pipeline is productised/distributed.** |
| **RODO / GDPR controller-processor?** | **Yes** | Personal data (commit author identity, pipeline-log identity) is processed; CyberForge is at minimum a controller for that processing. |

The net effect: **today, CyberForge's *direct* statutory obligations come from RODO**, plus **contractual flow-down** of DORA ICT-third-party requirements from its financial clients, plus **KNF supervisory expectations** that its financial clients impose on their providers. NIS2/KSC and CRA are **monitored, not-yet-applicable** regimes with explicit trigger conditions documented below. This is the deliberate "collapse the pack to exactly the applicable parts" outcome the spec calls for (`evidence-pack-specification.md:339`).

---

## 2. B.2 — System & data inventory; data-flow & residency map

This section is a *summary index* into the maintained machine-readable records; it does not duplicate them (single source of truth lives in the YAML/MD files cited).

### 2.1 In-scope system boundary

| Layer | In-scope components | Source of truth |
|---|---|---|
| CI/CD platform | GitHub Actions reusable workflows (Security Gate, Build & Scan, Sign & Attest, Deploy, DAST, Evidence Pack) | `docs/governance/isms-scope.md:48` |
| IaC | Terraform for Azure provisioning (`infra/`) | `docs/governance/isms-scope.md:49` |
| Policy engine | OPA/Rego compliance policies (`policies/`) | `docs/governance/isms-scope.md:50` |
| Evidence subsystem | Evidence-Pack scripts, SHA-256 manifest, compliance matrix (`scripts/`) | `docs/governance/isms-scope.md:51` |
| Cloud infrastructure | Azure ACR, Container Apps, Key Vault, Blob Storage (WORM) | `docs/governance/isms-scope.md:52` |
| Full asset inventory | — | `docs/governance/asset-inventory.md` |

Exclusions (carve-outs) — client application code, client infrastructure, physical premises, non-pipeline business systems — are enumerated and justified in `docs/governance/isms-scope.md:78-85` and `docs/compliance/scope-and-limitations.md:68-123`. The audit-document renders the SOC2-style system boundary/CUEC view in `scripts/build-audit-document.py` (`render_scope`, `:849+`).

### 2.2 Data inventory & PII

| Data class | Where | PII? | Lawful-basis / minimisation note | Source |
|---|---|---|---|---|
| Commit author identity (name, email) | GitHub repository (source) | Yes | Git metadata required for the audit trail (ISO 27001 A.8.4) | `docs/governance/data-flow.yaml:34-40` |
| Pipeline build/scan data | GitHub Actions ephemeral runners | No | — | `docs/governance/data-flow.yaml:45-55` |
| Demo application data | Azure Container Apps (Poland Central) | No | Demo app does not process personal data | `docs/governance/data-flow.yaml:66-70` |
| Pipeline-log identity in sealed evidence | Azure Blob WORM (Poland Central) | Yes | Sanitised to minimum; 5-year (DORA) retention; access limited to compliance + auditor roles | `docs/governance/data-flow.yaml:72-78` |
| Full processing record (RoPA) | — | — | Records of Processing Activities | `docs/governance/ropa.yaml` |

### 2.3 Residency map (DORA/NIS2 data-localisation & KNF cloud-communiqué relevance)

All persistent data planes are pinned to **Azure Poland Central**: ACR (`data-flow.yaml:60`), Container Apps (`data-flow.yaml:67`), and the WORM evidence archive (`data-flow.yaml:73`). EU-region residency directly supports the KNF *komunikat chmurowy* (23 Jan 2020) **data-localisation & supervisory-access** expectation (`evidence-pack-specification.md:237`) and the spec §6.4 residency requirement (`evidence-pack-specification.md:246`). Transparency-log egress (Sigstore/Rekor) carries signatures and OIDC identity tokens only — no payload data (`docs/governance/isms-scope.md:67`). ⚠️ Confirm any post-2020 KNF cloud-communiqué update before sign-off.

---

## 3. B.3 — Regulatory applicability matrix with rationale

Legend — **Verdict:** `DIRECT` (statutory obligation falls on CyberForge itself) · `FLOW-DOWN` (obligation reaches CyberForge contractually via client financial entities, not directly by statute) · `MONITOR` (sector applies but a threshold/trigger is not met — re-evaluate on the stated trigger) · `OUT` (does not apply). Every regime has a non-empty rationale **and** a documented trigger that would change the verdict — this is the content T-120's validator makes BLOCKING.

### 3.1 DORA — Reg. (EU) 2022/2554 + Polish operational act Dz.U. 2025 poz. 1069 (in force 7 Aug 2025)

- **As a financial entity — Verdict: `OUT`.** DORA's direct addressees are the financial-entity types in Art. 2(1) (banks, investment firms, insurers, crypto-asset service providers, etc.). CyberForge is an IT services boutique, none of those types (`docs/governance/isms-scope.md:28`). The micro-enterprise *simplified* ICT-risk framework (DORA Arts 15–16) is a relief **for in-scope financial entities that are micro**, not a route into scope — so it does not pull CyberForge in.
- **As an ICT third-party service provider — Verdict: `FLOW-DOWN` (active).** DORA Arts 28–30 place ICT-third-party-risk obligations on the *financial entity*; those obligations reach CyberForge through client contracts (audit & access rights, security requirements, exit assistance, sub-outsourcing transparency, Register-of-Information data). CyberForge maintains the supporting evidence its financial clients need: the Register of Information (`docs/governance/register-of-information.yaml`, DORA Art. 28(3) / ITS 2024/2956), third-party contract controls (`docs/governance/ict-third-party-contract-controls.md`), vendor due-diligence & exit plans. **EVIDENCE-ONLY caveat:** CyberForge has **not yet been issued an LEI**; the Register-of-Information maintaining-entity LEI is a documented PENDING placeholder (`docs/governance/register-of-information.yaml:38-40`).
- **As a *critical* ICT third-party provider (CTPP, DORA Art. 31) — Verdict: `OUT`.** CTPP designation rests on systemic importance, the criticality of functions supported across financial entities, and low substitutability — assessed by the ESAs (first list of 19 providers published 18 Nov 2025 under Art. 31(9)). A micro-enterprise is not a designation candidate.
- **Competent authority:** KNF (`evidence-pack-specification.md:230`). Polish reporting rail (for in-scope entities): KNF *System Sprawozdawczości DORA* (crp.knf.gov.pl); **LEI mandatory** for financial entities.
- **Trigger to re-evaluate:** CyberForge acquires a regulated financial-entity status (e.g. becomes a crypto-asset or payment service provider) ⇒ DORA `DIRECT`. CyberForge is ever ESA-designated as critical ⇒ CTPP oversight applies. New client contract ⇒ re-confirm flow-down clause coverage. ⚠️ Lock the DORA Art. 2(1) entity-type pin-cite at sign-off.

### 3.2 NIS2 — Dir. (EU) 2022/2555 + Polish KSC amendment Dz.U. 2026 poz. 252 (in force 3 Apr 2026)

- **Verdict: `MONITOR` (sector criterion met; size criterion not met).**
- **Sector:** CyberForge's managed-pipeline / DevSecOps activity falls within NIS2 **Annex I — ICT service management (B2B)**, as a **managed service provider (MSP)** and, given it provides cybersecurity risk-management assistance, arguably a **managed security service provider (MSSP)**. So the *sector* limb of the Polish two-limb test is satisfied.
- **Size:** The Polish KSC test (transposing NIS2) requires **both** limbs together — sector **and** size: *podmiot kluczowy* = large enterprise (≥250 staff or >€50M turnover), *podmiot ważny* = medium enterprise (≥50 staff or >€10M turnover/balance sheet). The NIS2 **size-cap rule** excludes micro/small enterprises except for size-independent categories. CyberForge is a **micro-enterprise** below the *ważny* threshold and is **not** in a size-independent category (DNS, TLD registry, trust service provider, or public electronic-communications provider — none apply, `docs/governance/isms-scope.md:67`). **⇒ Not a podmiot kluczowy or ważny today.**
- **Anti-pattern #11 guard (`evidence-pack-specification.md:283`):** even for in-scope entities, KSC transition windows are open — self-identification/registration in the *wykaz* by **2026-10-03**, full technical compliance by **2027-04-03**, penalties enforceable from ~Apr 2028. A determination must not assert non-compliance against an obligation whose window has not closed.
- **Competent authority / reporting:** national CSIRT (NASK default; sectoral CSIRT under KNF for finance once live); registration via System S46 / wykaz-ksc.gov.pl (`evidence-pack-specification.md:231`).
- **Trigger to re-evaluate (high-likelihood, given the stated growth trajectory `isms-scope.md:107`):** CyberForge reaches **medium-enterprise size** (≥50 staff **or** >€10M turnover/balance) ⇒ becomes a **podmiot ważny** (an MSSP at large scale could be *kluczowy*); then self-identify and register in the *wykaz* by the applicable deadline. Re-check at every annual review and on any headcount/turnover step-change.

### 3.3 CRA — Reg. (EU) 2024/2847 (in force 10 Dec 2024; reporting obligations 11 Sep 2026; full application 11 Dec 2027)

- **Verdict: `MONITOR` (not a manufacturer today).**
- **Rationale:** CRA's primary obligations bind the **manufacturer** — Art. 3(13): a person who develops/manufactures a *product with digital elements* (PDwDE), or has it made, **and markets it under its own name or trademark**, whether for payment, monetisation, or free of charge. CyberForge currently **delivers a service** (pipeline operation / DevSecOps consulting) and maintains an internal **demo application** (`app/`) that is **not placed on the EU market** as a commercial product under CyberForge's name. *"Placing on the market"* = the first making available on the Union market — which has not occurred for any CyberForge PDwDE. ⇒ not a CRA manufacturer.
- **Note on SaaS / remote data-processing solutions:** the CRA can reach remote data-processing solutions integral to a PDwDE; the CyberForge service is delivered into clients' own environments rather than offered as a marketed remote-processing product, which keeps it outside the manufacturer obligation today. ⚠️ confirm against final CRA scoping guidance.
- **Trigger to re-evaluate (the blueprint's Tier-2 "Operated Register" / productisation path makes this live):** CyberForge **productises and distributes** the pipeline (or any PDwDE) under its own name/trademark on the EU market ⇒ becomes a **manufacturer** and the CRA Annex I essential requirements, vulnerability-handling, and SBOM obligations apply (relevant CRA-aligned evidence — SBOM/VEX — is already produced by the pipeline, see `evidence-pack-specification.md:144-145`).

### 3.4 RODO / GDPR — Reg. (EU) 2016/679 + Polish Ustawa o ochronie danych osobowych (10 May 2018)

- **Verdict: `DIRECT` (applies).**
- **Rationale:** CyberForge processes personal data — developer identity in commit metadata and in sealed pipeline logs ([§2.2](#22-data-inventory--pii); `docs/governance/data-flow.yaml:34-40,72-78`). As the entity determining the purposes/means of that processing it is a **controller** for it (and a **processor** to the extent it handles any client personal data transiting the pipeline; the demo app processes none, `data-flow.yaml:70`).
- **Obligations engaged:** RoPA (Art. 30 — `docs/governance/ropa.yaml`), security of processing (Art. 32), DPIA where required (Art. 35), breach notification **72h to UODO** (Art. 33) and to data subjects where required (Art. 34), data-protection-by-design (Art. 25 — the data-flow record itself).
- **Supervisory authority:** UODO (`evidence-pack-specification.md:239-241`).
- **Trigger to re-evaluate:** any new processing of special-category data, large-scale monitoring, or international transfer ⇒ re-run the Art. 35 DPIA-necessity test and transfer assessment.

### 3.5 KNF supervisory expectations [de-facto via flow-down]

Not a separate "applies/doesn't" regime, but the lens Polish auditors use for any provider to supervised entities (`evidence-pack-specification.md:234-237`):

- **Rekomendacja D** (IT/ICT-environment security management) — the auditor's mental model even for non-banks; CyberForge evidences IT governance, secure development, IT operations, ICT-environment security, and **cooperation with external providers**. ⚠️ confirm latest revision.
- **KNF *komunikat chmurowy* (23 Jan 2020)** — information classification, KNF notification, contractual requirements, **data-localisation & supervisory access** (met by Poland-Central residency, [§2.3](#23-residency-map-doranis2-data-localisation--knf-cloud-communiqué-relevance)), encryption & key management (Azure Key Vault), and a documented **exit plan** (`docs/governance/vendor-exit-plan-template.md`). ⚠️ confirm any post-2020 update.

### 3.6 Summary applicability matrix

| Framework | Direct addressee? | Verdict | Authority | Trigger that flips the verdict |
|---|---|---|---|---|
| DORA — financial entity | No | `OUT` | KNF | Becomes a regulated financial entity |
| DORA — ICT third-party (Arts 28–30) | Via client contracts | `FLOW-DOWN` | KNF (via clients) | New/changed client contract; obtains LEI |
| DORA — critical ICT third-party (Art. 31) | No | `OUT` | ESAs | ESA designation as critical |
| NIS2 / KSC (Dz.U. 2026 poz. 252) | Sector yes, size no | `MONITOR` | NASK CSIRT / KNF sectoral | Reaches medium-enterprise size |
| CRA (Reg. 2024/2847) | No | `MONITOR` | Market-surveillance authority | Places a PDwDE on the EU market under own name |
| RODO / GDPR | Yes | `DIRECT` | UODO | New special-category / large-scale / transfer processing |
| KNF Rekomendacja D + komunikat chmurowy | De-facto via flow-down | `FLOW-DOWN` | KNF (via clients) | — |

---

## 4. How this answers anti-pattern #10

Spec §8 #10 rejects scope determinations that hand-wave applicability. This document provides, for **every** regime the spec names (DORA, NIS2-KSC, CRA, RODO) plus the KNF supervisory layer: (a) an explicit **applies / does-not-apply / flow-down / monitor** verdict, (b) a **clause-grounded rationale** citing the governing text, (c) the **entity facts** the verdict rests on (cited to repo records), and (d) a **documented trigger** that would change the verdict. The default posture is conservative — sector-in / size-out regimes are kept on a **`MONITOR`** footing rather than dismissed — so growth does not silently create undocumented non-compliance.

## 5. Open determinations to lock before external sign-off

1. **Confirm DORA financial-entity status of the operating entity** (the spec's #1 open decision, `evidence-pack-specification.md:339`) — the determination above assumes CyberForge is *not itself* a financial entity. ⚠️
2. **Obtain CyberForge's own LEI** — required for any DORA financial-entity rail and for the Register-of-Information maintaining-entity field (currently PENDING, `register-of-information.yaml:38-40`).
3. **Lock the Poland §6 pin-cites** the spec flagged as interrupted research (`evidence-pack-specification.md:226,341`): KNF Rekomendacja D revision, KNF cloud-communiqué post-2020 updates, the exact KSC kluczowy/ważny size thresholds against the final Dz.U. 2026 poz. 252 text.
4. **Re-test NIS2/KSC size on every headcount/turnover change** — this is the most likely verdict to flip given the documented growth trajectory.
5. **Re-test CRA on any productisation/distribution decision** (the Tier-2 Operated-Register product path).

## 6. Related documents

- `docs/compliance/scope-and-limitations.md` — pipeline *coverage* scope (what the pipeline does/doesn't control), the complementary view to this entity-level *applicability* determination.
- `docs/compliance/framework-boundaries.md` — three-tier per-control classification per framework.
- `docs/governance/isms-scope.md` — ISO 27001 ISMS scope, organisational context, interested parties.
- `docs/governance/register-of-information.yaml` — DORA Art. 28(3) Register of Information (third-party flow-down evidence).
- `docs/governance/data-flow.yaml` / `docs/governance/ropa.yaml` — data inventory, residency, RoPA (B.2 source of truth).

## 7. Boundary with the machine-validated artifact (T-120)

This document is the **human-readable determination**. The machine-validated, signed counterpart is a separate task (**T-120**) and lives in a different path so the two never collide:

| Concern | This doc (T-119 cluster) | T-120 |
|---|---|---|
| Path | `docs/compliance/scope-applicability.md` | `docs/governance/applicability.yaml` + `scripts/validators/applicability.py` |
| Form | Narrative determination + rationale matrix | Structured per-regime `applies` + `rationale` records, BLOCKING-validated |
| Output | Source-of-truth for reviewers/auditors | `evidence/scope-determination.json`, signed, in the Merkle root |
| Rendered into pack | — | Audit-document Part B (replaces the prose heading) |

**T-120's `applicability.yaml` must agree, regime-for-regime, with [§3](#3-b3--regulatory-applicability-matrix-with-rationale) of this document.** Keeping the verdicts/rationales here lets T-120's validator assert *presence + non-empty rationale per regime* against an authored basis rather than an invented one.

---

## 8. Revision history

| Date | Change | Author |
|---|---|---|
| 2026-06-16 | Initial determination (B.1/B.2/B.3) grounded in isms-scope, data-flow, register-of-information; regulatory facts web-verified | CyberForge Engineering |
