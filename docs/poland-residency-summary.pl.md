# Residency assertion + Polish management summary (Evidence Pack Part 6 / §6.4)

> **Status: wired-emission / human-confirm document.** This file delivers
> two of the §6.4 obligations from [`poland-appendix.md`](poland-appendix.md):
> (1) a **data-residency + lawful-transfer assertion** grounded in the *actual*
> Terraform configuration and emitted as a `residency.json` artifact by the
> evidence-pack workflow (`.github/workflows/evidence-pack.yml`,
> "Generate crosswalk, gap register, residency assertion (T-102/T-103/T-109)"
> step — fail-closed on non-PR, warn-only on PR); and
> (2) a **Polish-language executive summary** (warstwa zarządcza) of the Evidence
> Pack for KNF / UODO / a Polish auditor. The pipeline can assert *configuration*
> (region, retention) deterministically; it **cannot** make the legal
> determinations — those are marked `⚠️ confirm` and must be locked by
> legal/compliance before the binder is signed.

- **Builds on:** `poland-appendix.md` §6.4 (Language, residency, retention).
- **Spec source:** `evidence-pack-specification.md` §6.4.
- **Grounding facts (verified against the repo):**
  - Azure region default `polandcentral` — `infra/variables.tf:13-17`,
    `infra/main.tf:13-16` (resource group `cyberforge-<env>-rg` in that region),
    `SETUP.md:130,135`.
  - All Azure data-plane stages (ACR, Container Apps, Evidence WORM store) are in
    **Poland Central** — `docs/governance/data-flow.yaml:59-78`.
  - Configured WORM retention **1825 days (5 years)** — `infra/main.tf:42`,
    `policies/retention-policy.rego` (`minimum_retention_days := 1825`),
    BLOCKING via `scripts/tfplan-to-retention-input.py`.
  - Azure Poland Central is physically in **Warsaw, Poland**, data at rest in
    Poland (Microsoft Azure geography) — confirmed June 2026 (see Sources).

---

## 1. Residency assertion (the `residency.json` artifact)

### 1.1 What it asserts

The pack carries an explicit **residency assertion** recording the *deployed*
Azure region and the **lawful-transfer basis** for personal data. The region is
not hard-coded into the assertion as a literal — it is the **single residency
control point** `var.location` in Terraform (`infra/variables.tf:13-17`). The
worked/default value is `polandcentral`; the assertion records whatever region
was actually applied so the artifact reflects the *real* deployment, not the
example.

### 1.2 Lawful-transfer analysis (RODO/GDPR Chapter V)

| Stage | Location | At-rest region | Egress EU/EEA? |
|---|---|---|---|
| Azure Container Registry | `polandcentral` | Poland (EU) | No |
| Azure Container Apps | `polandcentral` | Poland (EU) | No |
| Azure Key Vault | `polandcentral` | Poland (EU) | No |
| Evidence WORM (Blob, immutable) | `polandcentral` | Poland (EU) | No |
| Build & Scan / Security Gate | GitHub Actions runner (ephemeral) | runner region | ⚠️ see below |

- **Azure data plane → intra-EU.** All four Azure stages run in **Poland
  Central** (Warsaw), with data at rest in Poland. A Poland-to-Poland flow is an
  **intra-EU transfer**: **no Chapter V transfer mechanism (SCCs / adequacy
  decision) is required** for the Azure data plane. The lawful-transfer basis is
  therefore **"intra-EU / EEA — no third-country transfer"**.
- **The one egress to confirm.** The `Build & Scan` and `Security Gate` stages
  execute on **GitHub Actions runners** (ephemeral; `data-flow.yaml:45-57`).
  GitHub-hosted runners may execute outside the EU/EEA, and Git commit metadata
  contains PII (developer names/emails — `data-flow.yaml:34-44`). This is the
  **only** stage that can egress the EU/EEA. ⚠️ **confirm** per engagement
  whether runners are EU-pinned (self-hosted / larger runners in an EU region) or
  whether a Chapter V mechanism (GitHub DPA SCCs) covers the processing. If a
  sub-processor outside the EU/EEA is introduced, the `transfer_basis` field
  below MUST change from `intra-EU` to `SCCs` / `adequacy` and the mechanism
  recorded.

### 1.3 Emitted artifact shape — `residency.json`

> **Wiring note.** The schema and the worked fixture below are defined here; the
> emit-into-pack wiring (writing `residency.json` from the applied Terraform
> region into the Evidence Pack) is now implemented in the evidence-pack workflow
> (`.github/workflows/evidence-pack.yml` — the T-102/T-103/T-109 step), which
> reads the **applied** region from `terraform output` when available and falls
> back to the `infra/variables.tf` default, recording which source was used
> (`azure_region_source`). The values below are the *default* (`polandcentral`)
> deployment fixture; the emitter substitutes the **applied** region at run time.

```json
{
  "schema": "cyberforge.residency/v1",
  "azure_region": "polandcentral",
  "azure_region_geography": "Poland (Warsaw)",
  "data_location": "EU/EEA — Poland",
  "transfer_basis": "intra-EU",
  "transfer_mechanism": null,
  "subprocessors_outside_eea": false,
  "data_plane_stages": [
    "azure-container-registry",
    "azure-container-apps",
    "azure-key-vault",
    "evidence-worm-blob"
  ],
  "egress_to_confirm": [
    {
      "stage": "github-actions-runner",
      "reason": "build/scan + security-gate execute on GitHub-hosted runners; commit metadata contains PII",
      "status": "confirm-per-engagement"
    }
  ],
  "retention_days": 1825,
  "source_of_truth": {
    "region": "infra/variables.tf:var.location",
    "applied_region": "terraform output / azurerm_resource_group.this.location"
  },
  "confirm_before_signoff": [
    "applied region matches azure_region",
    "no sub-processor egresses EU/EEA (or transfer_mechanism recorded)",
    "GitHub Actions runner residency confirmed or SCCs-covered"
  ]
}
```

Field contract (what a validator/auditor checks):

| Field | Meaning | Pipeline-verifiable? |
|---|---|---|
| `azure_region` | applied Azure region (residency control point) | **Yes** — from `terraform output` / RG location |
| `data_location` | human-readable at-rest jurisdiction | derived from region |
| `transfer_basis` | `intra-EU` \| `SCCs` \| `adequacy` | **EVIDENCE-ONLY** — legal determination |
| `transfer_mechanism` | the specific instrument when not intra-EU | **EVIDENCE-ONLY** |
| `subprocessors_outside_eea` | any sub-processor egressing EU/EEA | **EVIDENCE-ONLY** — ⚠️ confirm |
| `retention_days` | configured WORM retention | **Yes** — from the plan (A.5) |

**Honesty note.** That `azure_region` equals the applied region is
pipeline-verifiable (compare the assertion to `terraform output`). That the
`transfer_basis` is the *legally correct* one — and that **no** sub-processor
egresses the EU/EEA — is a legal/architectural determination the pipeline cannot
make; it is **EVIDENCE-ONLY** and carried as a `⚠️ confirm` item.

---

## 2. Polish-language scope decision (warstwa zarządcza)

Per `poland-appendix.md` §6.4 (Language) and `evidence-pack-specification.md`
§6.4, evidence presented to **KNF / UODO / a Polish auditor** is expected **in
Polish** (or with certified translation). This document satisfies the **management
layer** (warstwa zarządcza) in Polish below (§3). The **machine layer** (manifest,
SBOM, attestations, validator outputs) remains in international standard formats
(English / JSON), which is accepted practice.

> **⚠️ confirm — translation scope per engagement.** Whether the *whole* pack or
> only the management-facing layer requires Polish (and whether a **certified
> translation** by a sworn translator — *tłumacz przysięgły* — is required for
> court/regulator admissibility) is a per-engagement determination. This summary
> is an **operational** Polish translation, **not** a certified one. For
> legally-facing submissions, ⚠️ confirm whether certified translation is needed
> and commission it per engagement (the spec §6.4 caveat).

---

## 3. Podsumowanie zarządcze (Executive Summary — wersja polska)

> **Status: tłumaczenie operacyjne, nie uwierzytelnione.** Warstwa zarządcza
> Pakietu Dowodowego (Evidence Pack) CyberForge w języku polskim, dla KNF / UODO
> / audytora polskiego. Warstwa maszynowa (manifest, SBOM, atestacje, wyniki
> walidatorów) pozostaje w formatach międzynarodowych (angielski / JSON).
> Pozycje oznaczone `⚠️ potwierdzić` to **determinacje prawne** — muszą zostać
> zatwierdzone przez dział prawny / compliance przed podpisaniem segregatora.

### 3.1 Czym jest ten pakiet

Pakiet Dowodowy CyberForge to **kryptograficznie zabezpieczony zbiór dowodów**
zgodności, generowany automatycznie przez pipeline DevSecOps. Każdy artefakt jest
**podpisany w momencie wytworzenia** (DSSE / Sigstore keyless), zapisany w
**rejestrze transparentności (Rekor)**, objęty **korzeniem Merkle (RFC-6962)** i
przechowywany w **niezmienialnym magazynie WORM**. Hasło przewodnie: *„Nie ufaj —
zweryfikuj."*

### 3.2 Rezydencja danych i legalny transfer

- **Lokalizacja danych:** wszystkie warstwy danych Azure (rejestr kontenerów,
  aplikacja kontenerowa, Key Vault, magazyn dowodów WORM) działają w regionie
  **Azure Poland Central (Warszawa)** — dane spoczynkowe **w Polsce (UE)**.
  Punktem kontrolnym rezydencji jest zmienna Terraform `var.location`
  (`infra/variables.tf`); wartość domyślna/wzorcowa to `polandcentral`. Artefakt
  `residency.json` zapisuje **faktycznie wdrożony** region.
- **Podstawa legalnego transferu:** przepływ Polska→Polska to **transfer
  wewnątrzunijny** — **nie wymaga** mechanizmu z Rozdziału V RODO (SCC / decyzja o
  adekwatności). Podstawa: **„wewnątrz UE/EOG — brak transferu do państwa
  trzeciego"**.
- **Jedyny punkt do potwierdzenia:** etapy `Build & Scan` oraz `Security Gate`
  wykonują się na **runnerach GitHub Actions** (efemeryczne); metadane commitów
  zawierają dane osobowe (imiona/adresy deweloperów). To jedyne miejsce możliwego
  wyjścia poza UE/EOG. ⚠️ **potwierdzić** per zlecenie: czy runnery są przypięte
  do regionu UE, albo czy przetwarzanie pokrywają SCC z umowy DPA GitHub.
- **Podstawy prawne:** DORA Art. 28–30 (ICT third-party / lokalizacja); RODO
  Rozdz. V (transfery); komunikat chmurowy KNF (lokalizacja danych i dostęp
  nadzorczy — `poland-appendix.md` §6.2).

### 3.3 Retencja

- Skonfigurowana retencja: **1825 dni (5 lat)**, WORM (niezmienialność), z
  harmonogramem usuwania — egzekwowane **blokująco** przez walidator A.5
  (`tfplan-to-retention-input.py` + `policies/retention-policy.rego`).
- Pokrywa minima ustawowe **AML 5 lat**, **podatkowe 5 lat**, **księgi
  rachunkowe 5 lat** oraz minimum dla rekordów bezpieczeństwa **DORA/NIS2 (5l+)**.
- **Nie pokrywa** samodzielnie: **sprawozdań finansowych** (przechowywanie
  trwałe) ani **płac/ZUS** (10–50 lat) — obsługiwane poza magazynem WORM dowodów.
  ⚠️ **potwierdzić** zakres i okresy per klasa danych z działem prawnym
  (`poland-appendix.md` §6.4, tabela retencji).

### 3.4 Reżim nadzorczy (do ustalenia)

- **Podmiot DORA →** organ właściwy **KNF**; raportowanie przez System
  Sprawozdawczości DORA; **LEI obowiązkowe** (akt operacyjny Dz.U. 2025 poz.
  1069, obowiązuje od 7 sierpnia 2025).
- **Podmiot NIS2 →** nowelizacja KSC (Dz.U. 2026 poz. 252, obowiązuje od 3
  kwietnia 2026); klasyfikacja **podmiot kluczowy / ważny**; wpis do *wykazu*
  (System S46); raport do właściwego **CSIRT** (NASK / GOV / MON).
- ⚠️ **potwierdzić** klasyfikację podmiotu i granicę między reżimami (gdy oba mają
  zastosowanie — stosuje się obowiązek wyższy). To **determinacja prawna**, nie
  wynik pipeline'u (`poland-appendix.md` §6.1).

### 3.5 Kwalifikowane usługi zaufania (eIDAS) — stan obecny

- Obecnie pakiet znakuje czasem przez **niekwalifikowany RFC-3161** (FreeTSA,
  best-effort, soft-fail) — `scripts/seal-evidence.sh`. **Kwalifikowany znacznik
  czasu (QTS)** od polskiego QTSP (**KIR Szafir, Asseco Certum, EuroCert,
  CenCert**) jest **stanem docelowym** (TARGET-STATE) i ścieżką uaktualnienia.
- Znaczenie: kwalifikowany QTS niesie **domniemanie eIDAS** co do dokładności
  daty/czasu i integralności danych oraz **odwraca ciężar dowodu** (eIDAS Art.
  41) — czego stempel niekwalifikowany **nie** zapewnia. ⚠️ **potwierdzić** umowę
  z QTSP przed deklarowaniem QTS w materiałach dla klienta
  (`poland-appendix.md` §6.5).

### 3.6 Co pipeline udowadnia, a czego nie

| Warstwa | Status | Uwaga |
|---|---|---|
| Region wdrożenia = zadeklarowany | **Weryfikowalne** | porównanie `residency.json` z `terraform output` |
| Retencja ≥ 1825 dni + WORM | **Blokujące** | walidator A.5 z planu Terraform |
| Podstawa transferu jest prawnie właściwa | **EVIDENCE-ONLY** | determinacja prawna — ⚠️ potwierdzić |
| Brak sub-procesora poza UE/EOG | **EVIDENCE-ONLY** | ⚠️ potwierdzić (runnery GitHub) |
| Reżim (DORA/NIS2) i klasyfikacja | **EVIDENCE-ONLY** | ⚠️ potwierdzić (atestacja imienna, datowana) |
| Kwalifikowany QTS (eIDAS) | **TARGET-STATE** | dziś tylko RFC-3161 niekwalifikowany |

---

## 4. Confirm-before-signoff (carry into the binder)

- [ ] `residency.json` emitted with the **applied** region (not the example) — ⚠️
- [ ] Lawful-transfer basis recorded; **no** sub-processor egresses EU/EEA, or the
      Chapter V mechanism (SCCs/adequacy) is recorded — ⚠️
- [ ] GitHub Actions runner residency confirmed (EU-pinned) or SCCs-covered — ⚠️
- [ ] Translation scope decided per engagement; certified translation
      (*tłumacz przysięgły*) commissioned if required for legally-facing submission — ⚠️
- [ ] This summary's `⚠️ potwierdzić` items locked against primary law by
      legal/compliance, named approver, dated — ⚠️

---

*Sources (verified June 2026):*
*Azure Poland Central — Warsaw, Poland; data at rest in Poland (Microsoft Azure geography): https://azure.microsoft.com/en-us/explore/global-infrastructure/geographies ; https://news.microsoft.com/europe/2023/04/26/microsoft-launches-its-first-datacenter-region-in-poland-bringing-new-opportunities-to-develop-the-digital-economy/*
*eIDAS Reg. (EU) 910/2014 Art. 41 — legal effect of electronic time stamps; qualified timestamp presumption of accuracy/integrity + cross-border recognition: https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32014R0910*
*Region/retention/transfer determinations are repo-grounded (infra/variables.tf, infra/main.tf, data-flow.yaml, retention-policy.rego); legal minima per poland-appendix.md §6. Lock all `⚠️ confirm` / `⚠️ potwierdzić` items before sign-off.*
