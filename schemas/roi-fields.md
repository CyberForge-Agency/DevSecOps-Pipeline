# RoI Field Mapping — EBA Register of Information ↔ `roi.schema.json`

Source-of-truth field-mapping doc behind [`schemas/roi.schema.json`](roi.schema.json)
and its populated instance
[`docs/governance/register-of-information.yaml`](../docs/governance/register-of-information.yaml).

**Regulatory basis:** DORA Art.28(3) (the requirement to maintain a Register of
Information on all contractual arrangements for the use of ICT services provided
by ICT third-party service providers) and **Commission Implementing Regulation
(EU) 2024/2956** — the ITS on the register of information, which defines the
relational `B_xx.yy` templates. KNF form **SPR-PF-18** maps onto the same dataset.

> **Honesty note — scope (read this first).** The CyberForge schema is a
> **deliberate subset** of the full EBA ITS relational model. It captures the
> fields needed to make a defensible, machine-validatable register for a small
> entity with a handful of ICT providers — not the complete 15-template ITS
> filing. The mapping below states, for every `roi.schema.json` property, which
> EBA template it corresponds to **and** flags where the schema is narrower than
> the ITS. Templates that the schema does **not** model are listed in
> [Out-of-scope EBA templates](#out-of-scope-eba-templates) rather than silently
> implied. The `B_xx.yy` template attributions are carried verbatim from the
> `Field-to-EBA-template mapping` comment block in
> `register-of-information.yaml` (lines 17–29); where that block is silent the
> attribution is marked *(schema-local; no ITS template number asserted)* rather
> than invented.

## How the columns relate

- **`roi.schema.json` property** — JSON-pointer-style path into the schema
  (`maintaining_entity.lei`, `ict_third_party[].function`, …). Every property the
  schema defines appears exactly once below.
- **`register-of-information.yaml` key** — the same dotted key as it appears in the
  populated instance.
- **EBA ITS template** — the `B_xx.yy` template / field the property corresponds
  to under Commission Implementing Regulation (EU) 2024/2956.
- **DORA Art.28(3) basis** — why the regulation requires (or the schema records)
  the field.
- **Validator tier** — how `scripts/validators/validate-roi.py` treats the field:
  **BLOCKING** (deterministically checkable, a FAIL exits non-zero),
  **EVIDENCE-ONLY** (recorded as a measured count, never blocks), or
  **structural** (carried in the record / enforced only by JSON-Schema shape).

## Register-level / provenance fields

| `roi.schema.json` property | `register-of-information.yaml` key | EBA ITS template | DORA Art.28(3) basis | Validator tier |
| --- | --- | --- | --- | --- |
| `schema_version` | `schema_version` | *(schema-local; no ITS template number asserted)* | Versioning of the register's own data model so changes are auditable. | structural (pattern `^[0-9]+\.[0-9]+$`) |
| `regulation` | `regulation` | *(provenance block; informational — not an ITS template)* | Records the legal basis of the mapping (framework / article / ITS / KNF form). | structural (`additionalProperties: true`) |
| `regulation.framework` | `regulation.framework` | *(informational)* | Names the governing framework (`DORA`). | structural |
| `regulation.article` | `regulation.article` | *(informational)* | Pins the DORA article (`Art.28(3)`) that mandates the register. | structural |
| `regulation.its` | `regulation.its` | *(informational)* | Pins the ITS (`Commission Implementing Regulation (EU) 2024/2956`). | structural |
| `regulation.knf_form` | `regulation.knf_form` | *(informational; national mapping)* | Cross-references the KNF national supervisory form (`SPR-PF-18`) that consumes the same dataset. | structural |

## Maintaining entity — EBA template **B_01.01**

The financial entity maintaining the register.

| `roi.schema.json` property | `register-of-information.yaml` key | EBA ITS template | DORA Art.28(3) basis | Validator tier |
| --- | --- | --- | --- | --- |
| `maintaining_entity` | `maintaining_entity` | B_01.01 (entity maintaining the register) | Identifies the financial entity that owns the register. | structural (object; required) |
| `maintaining_entity.name` | `maintaining_entity.name` | B_01.01 (entity name) | Names the maintaining financial entity. | structural (required, `minLength: 1`) |
| `maintaining_entity.lei` | `maintaining_entity.lei` | B_01.01 (financial entity LEI) | Identifies the maintaining entity by ISO 17442 LEI; the unique-identifier anchor of the whole relational register. | EVIDENCE-ONLY (CyberForge has no issued LEI — documented `PENDING-NOT-YET-ISSUED` placeholder surfaced as a gap, never blocked) |
| `maintaining_entity.country` | `maintaining_entity.country` | B_01.01 (country of the entity) | Jurisdiction of the maintaining entity (`PL`). | structural |
| `maintaining_entity.competent_authority` | `maintaining_entity.competent_authority` | B_01.01 (competent authority) | Names the supervising competent authority (`KNF`) the register is filed with. | structural |
| `maintaining_entity.last_updated` | `maintaining_entity.last_updated` | *(maintenance metadata; supports the ITS at-least-annual maintenance expectation)* | Freshness anchor: date the register was last maintained. | BLOCKING (must be within `review_cadence_days` of today) |
| `maintaining_entity.review_cadence_days` | `maintaining_entity.review_cadence_days` | *(maintenance metadata)* | Maximum age before the register is stale; the ITS expects at least annual maintenance (`365`). | BLOCKING (threshold for the freshness check) |

## ICT third-party providers — EBA templates **B_01.02 / B_02.02 / B_05.01 / B_05.02 / B_06.01**

`ict_third_party[]` — one array entry per ICT third-party service provider. The
schema collapses several ITS templates that are, in the full ITS, separate
relational tables (provider register B_05.01, sub-outsourcing chain B_05.02,
function register B_06.01, ICT-service taxonomy B_02.02) into a single denormalised
row per provider. The per-property template attribution below reflects which ITS
table the field originates from.

| `roi.schema.json` property | `register-of-information.yaml` key | EBA ITS template | DORA Art.28(3) basis | Validator tier |
| --- | --- | --- | --- | --- |
| `ict_third_party` | `ict_third_party` | B_01.02 / B_05.01 / B_05.02 (provider records) | The core list of contractual arrangements with ICT third-party providers — the subject of Art.28(3). | structural (array, `minItems: 1`, required) |
| `ict_third_party[].id` | `ict_third_party[].id` | *(schema-local internal key; pattern `^TPP-[0-9]{3,}$`)* | Stable internal identifier linking a provider to its exit plan and other artifacts. | structural (pattern-enforced) |
| `ict_third_party[].provider` | `ict_third_party[].provider` | B_01.02 / B_05.01 (ICT third-party provider name) | Identifies the ICT third-party service provider by name. | structural (required, `minLength: 1`) |
| `ict_third_party[].lei` | `ict_third_party[].lei` | B_01.02 / B_05.01 (ICT provider LEI) | ISO 17442 LEI of the provider where it is a legal entity holding one; `null` when `NOT_LEI_ELIGIBLE`. | BLOCKING **format** (ISO 17442) for non-exempt providers; **registration truth** is EVIDENCE-ONLY (GLEIF lookup outside the pipeline) |
| `ict_third_party[].lei_status` | `ict_third_party[].lei_status` | *(LEI-eligibility classifier supporting B_01.02 LEI)* | Declares whether the provider LEI is `ISSUED` / `PLACEHOLDER` / `PENDING` / `NOT_LEI_ELIGIBLE`; drives which providers are in the LEI-format BLOCKING set vs. excluded honestly. | BLOCKING (enum; gates LEI-format applicability) |
| `ict_third_party[].function` | `ict_third_party[].function` | B_06.01 (function identifier / supported function) | The financial-entity function supported by the ICT service — Art.28(3) requires the register to link arrangements to functions. | structural (required, `minLength: 1`) |
| `ict_third_party[].ict_service` | `ict_third_party[].ict_service` | B_02.02 / B_05.01 (ICT service — taxonomy) | The type of ICT service provided, per the ITS service taxonomy. | structural (required, `minLength: 1`) |
| `ict_third_party[].data_types` | `ict_third_party[].data_types` | B_05.01 (data processed / sensitivity) | Categories of data handled under the arrangement; supports risk and data-protection assessment. | structural (optional) |
| `ict_third_party[].data_location` | `ict_third_party[].data_location` | B_05.01 (storage / processing location) | Location of data storage / processing — required for the Art.28(3) location-of-data record. | structural (required, `minLength: 1`) |
| `ict_third_party[].criticality` | `ict_third_party[].criticality` | B_05.01 (Critical/Important Function flag) | Marks whether the arrangement supports a critical or important function (CIF); drives the heightened Art.28 controls. | BLOCKING (enum `Critical/High/Medium/Low`; gates the completeness check below) |
| `ict_third_party[].substitutability` | `ict_third_party[].substitutability` | B_05.01 (substitutability of the provider) | Art.28 substitutability assessment — how readily the provider could be replaced. | BLOCKING (must be non-empty for `Critical`/`High`) |
| `ict_third_party[].exit_plan_ref` | `ict_third_party[].exit_plan_ref` | B_05.01 (exit plan availability / reference) | Art.28 exit-strategy requirement — reference to the documented exit plan. | BLOCKING (must be non-empty for `Critical`/`High`) |
| `ict_third_party[].sub_outsourcing` | `ict_third_party[].sub_outsourcing` | B_05.02 (sub-outsourcing / supply-chain flag) | Whether the provider further sub-outsources — the ITS sub-outsourcing chain. | structural (boolean, optional) |
| `ict_third_party[].notice_period_days` | `ict_third_party[].notice_period_days` | B_05.01 (termination notice period) | Contractual termination notice period — an Art.28(7) contractual-term datum. | structural (integer ≥ 0, optional) |
| `ict_third_party[].last_audit_date` | `ict_third_party[].last_audit_date` | B_05.01 (date of last audit) | Date the provider was last audited — supports ongoing monitoring under Art.28. | structural (date pattern, optional) |
| `ict_third_party[].dpa_status` | `ict_third_party[].dpa_status` | *(schema-local; data-protection-agreement status — not a distinct ITS field)* | Records whether a Data Processing Agreement is in place / required / covered upstream; cross-links to the RoPA/DPA evidence. | structural (optional) |

## Coverage statement

Every property defined in `roi.schema.json` (29 paths: 6 register-level/provenance,
7 maintaining-entity, 16 ICT-third-party including the array root) appears exactly
once in the tables above. This is the invariant the verification step checks: the
doc is the field-by-field source of truth for the schema, with no property left
unmapped and no field invented that the schema does not define.

## Out-of-scope EBA templates

The full EBA ITS relational model (Commission Implementing Regulation (EU)
2024/2956) defines templates this schema does **not** currently model. Listing them
honestly so the gap is explicit rather than implied:

| EBA ITS template | Purpose | Status in this schema |
| --- | --- | --- |
| B_01.03 | Identification of the entities signing the contractual arrangements (where different from the maintaining entity, e.g. group / branch hierarchy) | **Not modelled** — single maintaining entity assumed |
| B_02.01 | Contractual arrangement — general information (per-contract reference number, start/end dates, governing law) | **Partially / not modelled** — the schema records `notice_period_days` per provider but not full per-contract rows; no contract-reference table |
| B_02.03 | Intra-group arrangements | **Not modelled** — no group structure |
| B_03.01–B_03.03 | Entities making use of the ICT services (consuming functions, branch-level use) | **Not modelled** — collapsed into the single `function` field per provider |
| B_04.01 | Entities providing ICT services as part of a contractual arrangement (provider hierarchy beyond direct provider) | **Not modelled** — only the direct provider is recorded |
| B_05.02 | Full sub-outsourcing chain (rank, sub-provider identity, sub-provider LEI) | **Reduced** — represented only by the `sub_outsourcing` boolean flag; the chain itself is not enumerated |
| B_07.01 | Assessment of the ICT third-party providers' contractual arrangements (risk assessment detail) | **Reduced** — represented by `criticality` + `substitutability` + `exit_plan_ref`; not the full assessment dataset |

If CyberForge grows beyond a small provider count or files the complete ITS return,
these templates would need first-class schema support; until then the schema's
narrower scope is recorded here deliberately and is reflected in the validator,
which only blocks on the fields it can deterministically and honestly check.
