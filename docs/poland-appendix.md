# Poland-specifics appendix (Evidence Pack Part 6)

> **Status: target-state / human-confirm document.** This appendix ports
> `evidence-pack-specification.md` §6.1–6.5 into the pack and grounds it in
> CyberForge's *actual* pipeline configuration. Several items below are
> **legal/regulatory determinations** the pipeline cannot make on its own — they
> are marked `⚠️ confirm` and **must be locked by legal/compliance before the
> binder is signed**. The pipeline can prove *configuration meets a stated
> threshold*; it cannot prove a *legal minimum is the right one*. Where a control
> is designed but not yet implemented it is labelled **TARGET-STATE**.

- **Spec source:** `evidence-pack-specification.md` §6 (Poland-specific auditor
  requirements), §7.3 (qualified timestamps).
- **Struktura source:** `CyberForge-Evidence-Pack-struktura.md` §6 (Reżim /
  Retencja / Kwalifikowane usługi zaufania) and §A row "Polityka retencji / WORM".
- **Emission target:** this file is emitted into the Evidence Pack alongside the
  other Part-6 / Part-I artifacts. Cross-linked companions in this repo:
  `docs/governance/evidence-retention-policy.md` (the A.5 `assert-retention`
  threshold doc) and `docs/governance/ropa.yaml` (RoPA for §6.3).

---

## 6.1 Which Polish regime applies — determine and document first

> **DETERMINATION REQUIRED — ⚠️ confirm before sign-off.** Which limb below
> applies is an entity-classification decision for legal/compliance, not a
> pipeline output. Document the rationale and the boundary in the pack.

- **DORA-covered financial entity?** → **KNF** is competent authority. Polish
  operational act: **Dz.U. 2025 poz. 1069** (in force **7 Aug 2025**). DORA is
  *lex specialis* — such entities are **carved out of much of the KSC Act**.
  Report via **KNF System Sprawozdawczości DORA** (`crp.knf.gov.pl`); **LEI
  mandatory**. ⚠️ confirm entity is in DORA scope (Art. 2) and the reporting
  channel is live for the entity type.
- **NIS2 entity?** → Polish **KSC amendment, Dz.U. 2026 poz. 252, in force
  3 April 2026.** Classify **podmiot kluczowy vs ważny**; **register in the
  *wykaz* by ~3 Oct 2026** (System S46 / `wykaz-ksc.gov.pl`); full technical
  compliance ~3 Apr 2027; penalties enforceable ~Apr 2028. Report incidents to
  the competent **CSIRT** (NASK default; GOV/MON for state/defence; sectoral
  CSIRT under KNF for finance once live). ⚠️ confirm classification
  (kluczowy/ważny) and the applicable transition deadlines for the entity.
- **Both can apply to one group** — apply the higher obligation and **document
  the boundary** explicitly (do not let one regime's carve-out hide the other's
  duties). ⚠️ confirm boundary memo authored.

**Pipeline-verifiable vs evidence-only:** none of §6.1 is pipeline-verifiable —
it is a scoping/legal determination. The pack records it as **EVIDENCE-ONLY**
human attestation. Do not assert a regime as "achieved"; assert it as
"determined and documented by [named approver], dated".

---

## 6.2 KNF supervisory expectations [BP, de facto mandatory for supervised entities]

> **TARGET-STATE for non-bank entities; ⚠️ confirm latest revisions.**

- **Rekomendacja D** (IT & ICT-environment security management in banks) — the
  benchmark Polish auditors reach for, covering: IT governance, system
  development & maintenance, IT operations, ICT-environment security, and
  **outsourcing/cooperation with external providers**. Evidence each area even if
  you are not a bank — it is the auditor's mental model. ⚠️ confirm latest
  revision of Rekomendacja D before mapping controls to it.
  - *Where the pipeline already produces aligned evidence (non-binding mapping,
    ⚠️ confirm):* system development & maintenance → the SDLC gates
    (`.github/workflows/build-and-scan.yml`, `security-gate.yml`); IT operations
    & ICT-environment security → `docs/governance/security-hygiene-baseline.md`,
    `docs/governance/iam-governance.md`; outsourcing → `register-of-information.yaml`,
    `vendor-due-diligence-checklist.md`, `ict-third-party-contract-controls.md`.
- **KNF cloud-computing communiqué (komunikat chmurowy, 23 Jan 2020)** — for
  processing supervised information in the cloud: **information classification**,
  risk assessment, **notification to KNF**, contractual requirements, **data
  localisation & supervisory access**, encryption & **key management**, and a
  documented **exit plan**. ⚠️ confirm any post-2020 update before relying on it.
  - *Evidence expected:* classification register, KNF notification record, cloud
    contract clauses, key-custody design, exit plan.
  - *Repo grounding:* data localisation → see §6.4 residency below and
    `SETUP.md` (example region `polandcentral`); key management → Azure Key Vault
    module `infra/modules/keyvault/main.tf`; exit plan →
    `docs/governance/vendor-exit-plan-template.md`. The **KNF notification record**
    is a manual filing — **TARGET-STATE**, ⚠️ confirm filed.

---

## 6.3 UODO / RODO

- **RoPA** (Art. 30), **DPIA** (Art. 35), **breach notification 72h to UODO**
  (Art. 33) and to data subjects (Art. 34); Polish **Ustawa o ochronie danych
  osobowych (10 May 2018)** as national overlay.
- **Evidence expected:** RoPA, DPIAs, breach-procedure with the **72h clock**,
  lawful-basis register, data-subject-rights workflow.
- **Repo grounding:** RoPA → `docs/governance/ropa.yaml`; breach/incident with
  the 72h clock → `docs/runbooks/incident-response.md` and
  `docs/governance/incident-register.yaml`. ⚠️ confirm the DPIA exists for the
  specific processing and that the 72h clock procedure has been exercised
  (tabletop) — **the existence of a procedure is not proof it was met**.

---

## 6.4 Language, residency, retention

### Language

- Evidence presented to **KNF / UODO / a Polish auditor** is expected **in Polish**
  (or with certified translation). Build the pack bilingual or translate the
  management-facing layers.
- **Repo grounding:** the struktura (`CyberForge-Evidence-Pack-struktura.md`) is
  authored in Polish and serves as the PL-language structural layer; the
  English spec is the working source. The *generated* artifacts (manifest, PDF
  report) are currently English. **TARGET-STATE:** a Polish management summary
  (or certified translation of the management-facing layers) per engagement.
  ⚠️ confirm translation scope per engagement (whole pack vs management layer).

### Residency / sovereignty

- Document **data location** and the **lawful-transfer mechanism**; cloud
  localisation expectations flow from the KNF communiqué (§6.2) and sector rules.
- **Repo grounding:** the Terraform resource group region is the residency
  control point; the worked example is **`polandcentral`** (`SETUP.md`). The pack
  should carry a residency assertion recording the *deployed* region and the
  transfer basis (intra-EU; SCCs/adequacy only if any sub-processor is outside
  the EU/EEA). **TARGET-STATE:** an explicit `residency` artifact asserting the
  real region + transfer basis (tracked separately under the residency task).
  ⚠️ confirm the actually-deployed region and whether any sub-processor egresses
  the EU/EEA.

### Retention — statutory minima to bake into Part I

> The pipeline can prove **configured retention ≥ a stated threshold** against the
> Terraform plan (A.5 `assert-retention`, BLOCKING). It **cannot** prove that the
> stated threshold is the *legally correct* minimum — that is a per-data-class
> legal determination. ⚠️ confirm exact periods per data class with legal/compliance.

| Data class | Statutory minimum | Polish legal basis | Status |
|---|---|---|---|
| AML / CFT records (CDD, transaction records) | **5 years** (extendable on KGIIF request) | **art. 49 ustawy o przeciwdziałaniu praniu pieniędzy oraz finansowaniu terroryzmu** (Dz.U. 2018 poz. 723 ze zm.) | confirmed via source; ⚠️ confirm extension triggers |
| Tax books & related documents | **until przedawnienie** = **5 years** from end of the year the tax payment fell due (longer where a loss is carried) | **art. 86 § 1 Ordynacji podatkowej** (przedawnienie: **art. 70 § 1 Ordynacji podatkowej**) | confirmed via source; ⚠️ confirm loss-year extension applies |
| Accounting books (`księgi rachunkowe`) | **5 years** from start of the year after the financial year | **art. 74 ust. 2 pkt 1 ustawy o rachunkowości** | confirmed via source |
| Approved annual financial statements | **trwałe przechowywanie** (permanent) | **art. 74 ust. 1 ustawy o rachunkowości** | confirmed via source |
| DORA ICT-risk / security records | **typically 5y+** (audit-defensibility window across the ICT-risk chapter) | **DORA (EU 2022/2554)** Art. 11–12 + RTS; PL op. act Dz.U. 2025 poz. 1069 | ⚠️ confirm exact period per record type |
| NIS2 / KSC security records | **typically 5y+** | KSC (Dz.U. 2026 poz. 252) | ⚠️ confirm exact period |
| Payroll / social-insurance (ZUS) | **10 years** (50 years for pre-2019 employment) | ustawa o emeryturach i rentach z FUS / Kodeks pracy | ⚠️ confirm; out of pipeline scope but note in Part I if applicable |

**Justification of the 1825-day (5-year) WORM floor.** The pipeline's configured
retention is **1825 days** (`infra/main.tf:42`,
`policies/retention-policy.rego` `minimum_retention_days := 1825`, enforced
BLOCKING by `scripts/tfplan-to-retention-input.py`). 1825 days = 5 years covers
the **AML 5y**, **tax 5y**, and **accounting-books 5y** classes above, and is the
**minimum** for the DORA/NIS2 "5y+" classes. It does **NOT** by itself satisfy:
(a) **financial statements** (permanent — handled outside the evidence-WORM store
as a separate accounting obligation), or (b) **payroll/ZUS** (10–50y). ⚠️ confirm
the evidence store's scope excludes those long-retention classes, or extend the
WORM period for the affected artifacts. See
`docs/governance/evidence-retention-policy.md` for the threshold-provenance note
and the BLOCKING-vs-EVIDENCE-ONLY scope split.

---

## 6.5 Qualified trust services (eIDAS) — Polish providers

> **TARGET-STATE.** The pipeline today timestamps with a **best-effort,
> non-qualified RFC-3161** TSA — `seal-evidence.sh` Step 4 (lines 382–419) posts
> the Merkle root, manifest, and PDF to `TSA_URL` (default
> **`https://freetsa.org/tsr`**, `seal-evidence.sh:39`), and TSA unreachability is
> a **soft** condition (recorded `rfc3161_unavailable`, not a hard fail —
> `seal-evidence.sh:413–414`). README claims (`README.md:33,46`) describe these as
> "RFC-3161 timestamps" with **no qualified-QTS distinction**. A qualified eIDAS
> QTS is **not yet wired** and is documented here as the upgrade path.

**Why it matters.** A **qualified electronic timestamp (QTS)** from a qualified
trust service provider carries the eIDAS **legal presumption** of accuracy of the
date/time and integrity of the data, and the **reversed burden of proof**
(eIDAS Art. 41). A plain RFC-3161 stamp from a non-qualified TSA (e.g. FreeTSA)
is technically valid but **does not** carry that presumption — it is **not**
legally equivalent for KNF/UODO/court admissibility of legally-facing artifacts
(board approvals, incident reports, attestations).

**Polish qualified trust service providers offering qualified timestamps (QTS):**

| Provider | Entity | Qualified timestamp (QTS) | Notes |
|---|---|---|---|
| **KIR (Szafir / mSzafir)** | Krajowa Izba Rozliczeniowa S.A. | Yes (qualified timestamping centre) | Bank-clearing-house operator; widely used for QTS |
| **Certum** | Asseco Data Systems S.A. | Yes (`Certum QTST` / `Certum QTSA` TSAs) | Largest PL/EU certificate authority |
| **EuroCert** | EuroCert Sp. z o.o. | Yes (qualified electronic timestamp) | |
| **CenCert** | Enigma SOI Sp. z o.o. (Centrum Certyfikacji) | Yes (qualified trust services) | |

- **Legal basis:** **eIDAS — Reg. (EU) 910/2014**, now **eIDAS 2.0 — Reg. (EU)
  2024/1183**; qualified-timestamp legal effect at **Art. 41**.
- **Authoritative provider list:** the Polish register is maintained by **NCCert
  (Narodowe Centrum Certyfikacji)** under the Minister of Digitisation and feeds
  the **EU Trusted List (EUTL)**, which is **updated monthly**. Always verify a
  provider's *current* qualified status for the *timestamping* service in the EUTL
  at issuance. ⚠️ confirm provider + QTS status against the live trusted list
  before procurement.
  - EU Trusted List browser: `https://eidas.ec.europa.eu/efda/tl-browser/`
  - NCCert: `https://www.nccert.pl/`

### Integration point (the RFC-3161 → QTS upgrade)

- **What it replaces:** the RFC-3161 call in **`scripts/seal-evidence.sh`
  Step 4** (the `rfc3161_stamp` function and the `TSA_URL` default). Pointing
  `TSA_URL` at a **qualified** TSA endpoint from one of the providers above, and
  treating the stamp as **MANDATORY (hard fail on absence)** for legally-facing
  artifacts, upgrades the pack from non-qualified to qualified time-anchoring.
- **Honest current state:** RFC-3161 (non-qualified, best-effort, soft-fail) is
  the **default and only** timestamping today. Qualified eIDAS QTS is
  **TARGET-STATE / DOCUMENTED-UPGRADE-ONLY**; this is the named-provider path,
  not an achieved capability. ⚠️ confirm a QTSP contract and a qualified TSA
  endpoint before claiming QTS in any buyer-facing material.

---

## Confirm-before-signoff checklist (carry into the binder)

- [ ] §6.1 Regime determined (DORA/NIS2/both) + boundary memo — named approver, dated. ⚠️
- [ ] §6.2 Rekomendacja D latest revision confirmed; KNF cloud-communiqué notification filed. ⚠️
- [ ] §6.3 RoPA current; DPIA present for the processing; 72h breach clock tabletop-exercised. ⚠️
- [ ] §6.4 Per-data-class retention minima confirmed with legal; permanent/long classes handled outside the 1825-day WORM floor. ⚠️
- [ ] §6.4 Deployed region + lawful-transfer basis asserted (residency artifact); Polish management summary scoped per engagement. ⚠️
- [ ] §6.5 Qualified QTSP selected + qualified TSA endpoint wired into `seal-evidence.sh` Step 4; current EUTL status verified. ⚠️

---

*Sources (verified June 2026):*
*AML 5y — art. 49 ustawy o przeciwdziałaniu praniu pieniędzy (e.g. iAML / EY summaries of the act).*
*Tax 5y — art. 86 + art. 70 Ordynacji podatkowej (lexlege.pl, sip.lex.pl Dz.U. 2026.622 t.j.).*
*Accounting 5y / statements permanent — art. 74 ustawy o rachunkowości (arslege.pl, lexlege.pl).*
*QTSPs — NCCert register feeding the EU Trusted List (nccert.pl; digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists; eidas.ec.europa.eu); provider QTS confirmations: KIR/elektronicznypodpis.pl, Certum repository, EuroCert (eurocert.pl), CenCert.*
*Lock all ⚠️ items against primary law and the live EUTL before sign-off.*
