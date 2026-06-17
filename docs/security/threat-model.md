# Threat Model — CyberForge DevSecOps Pipeline & Demo App

> **Spec mapping:** Evidence Pack master spec Part C.1 "Threat model & secure-design records"
> (`evidence-pack-specification.md:67`, `:135`) and §4 pipeline stage "Plan / threat-model"
> (`evidence-pack-specification.md:187`).
> **Reg. clauses:** NIS2 21(2)(e) (secure development life cycle); DORA RTS (EU) 2024/1774
> (ICT security policies / secure SDLC); ISO/IEC 27001:2022 A.8.25 (secure development life
> cycle); NIST SSDF PW.1 (design software to meet security requirements & mitigate risks).
> **PASS criteria (spec):** "Exists per critical feature; updated on arch change; risks
> traced to controls." A *single stale doc for the whole app* is an explicit rejection
> trigger (`evidence-pack-specification.md:187`).

| Field | Value |
|---|---|
| `model_version` | `1.0.0` |
| `last_reviewed` | `2026-06-16` |
| `review_window_days` | `180` (re-review on architecture change or at least every 6 months) |
| `methodology` | STRIDE-per-element (per critical feature / data-flow element) |
| `scope` | Demo app (`Pipeline/app/src`) + CI/CD supply chain (`Pipeline/.github/workflows`) + Azure runtime + evidence integrity chain |
| `out_of_scope` | The cloud provider's own control plane (Azure platform security), GitHub's own platform security, physical security of GitHub/Azure data centres |

## How to read this document

This model is **STRIDE-per-element**: the system is first decomposed into critical
features / data-flow elements with explicit trust boundaries (per the dataflow-diagram
+ trust-boundary method — see [Sources](#sources)), then each element is examined for
the six STRIDE categories: **S**poofing, **T**ampering, **R**epudiation, **I**nformation
disclosure, **D**enial of service, **E**levation of privilege.

Every identified threat is **traced to a mitigating control already in this repo** (with a
`path:line` citation to the workflow / gate / code that implements it) **or flagged as a
GAP** with the task that would close it. This satisfies the spec's "risks traced to
controls" PASS criterion and keeps the model honest: GAP rows are *target-state*, never
claimed as achieved.

**Honesty caveat (EVIDENCE-ONLY):** the SCHEMA of this model (every threat has either a
`control_ref` or an explicit `gap_ref`) is machine-checkable. That each control *actually
and fully* mitigates the threat in production is a human-reviewed assertion, not something
the pipeline proves.

---

## 1. System decomposition & trust boundaries

The data-flow elements below are the single source of truth in
`Pipeline/docs/governance/data-flow.yaml` (RODO Art.30 record). Trust boundaries (TB) are
drawn where data changes trust level.

```
 [Internet / anonymous client]
        |   TB-1  (public ingress — untrusted -> app)
        v
 +------------------------------+
 |  Demo App (Azure Container   |   features: F1 items API, F2 build-info,
 |  Apps, Poland Central)       |             F3 health, F4 static showcase
 +------------------------------+
        ^   TB-2  (registry pull — ACR -> Container Apps)
        |
 +------------------------------+
 |  Azure Container Registry    |
 +------------------------------+
        ^   TB-3  (push from CI — ephemeral runner -> Azure, via OIDC)
        |
 +------------------------------+        TB-4 (developer -> source repo)
 |  CI/CD supply chain          | <----- [Developer / PR author]
 |  GitHub Actions (ephemeral)  |
 |  P1 source -> P2 sec-gate -> |
 |  P3 build/scan -> P4 sign/   |
 |  attest -> P5 deploy ->      |
 |  P6 evidence-pack/seal       |
 +------------------------------+
        |   TB-5  (evidence -> WORM archive + transparency log)
        v
 +------------------------------+
 |  Evidence Pack Archive       |
 |  (Azure Blob WORM + Rekor)   |
 +------------------------------+
```

| Boundary | Crosses from -> to | Why it is a boundary |
|---|---|---|
| TB-1 | anonymous Internet -> demo app | Untrusted external input reaches the app process |
| TB-2 | ACR -> Container Apps runtime | Artifact moves from registry into the running trust zone (admission point) |
| TB-3 | ephemeral CI runner -> Azure (ACR/Container Apps/Terraform) | Build identity gains write access to cloud resources |
| TB-4 | developer -> source repository | Human-authored change enters the trusted build input |
| TB-5 | pipeline -> immutable evidence store / public transparency log | Evidence crosses from mutable CI into a non-repudiation/WORM zone |

---

## 2. Critical features / flows under analysis

### Demo application (`Pipeline/app/src`)
- **F1 — Items API** (`app/src/routes/items.ts`): in-memory CRUD over `/api/items` (GET list, POST create, GET/:id, DELETE/:id).
- **F2 — Build-info endpoint** (`app/src/app.ts:88-139`): returns deployment metadata (image digest, repo, run URLs, cosign/Rekor verify commands).
- **F3 — Health endpoint** (`app/src/app.ts:71-77`): liveness probe consumed by the deploy smoke test.
- **F4 — Static showcase page** (`app/src/public/index.html`, served at `app/src/app.ts:48`).

### Pipeline / supply chain (`Pipeline/.github/workflows`)
- **P1 — Source control** (`security-gate.yml`, `build-and-scan.yml` triggers; branch protection via `scripts/apply-branch-protection.sh`).
- **P2 — Security gate** (`security-gate.yml`): secret detection (TruffleHog), IaC scan (Checkov).
- **P3 — Build & scan** (`build-and-scan.yml`): Trivy SCA, CodeQL SAST, image scan + SBOM, unit tests/coverage.
- **P4 — Sign & attest** (`sign-and-attest.yml`): cosign keyless sign, SBOM attestation, SLSA/in-toto provenance.
- **P5 — Deploy** (`deploy.yml`): OIDC login, cosign-verify admission gate, Terraform apply, image deploy, smoke test.
- **P6 — Evidence pack / seal** (`evidence-pack.yml`, `scripts/seal-evidence.sh`): manifest, Merkle root, RFC-3161 timestamp, WORM archive.

---

## 3. STRIDE analysis — Demo application

> Each row: **STRIDE category · threat · mitigating control (`path:line`) OR `[GAP]`**.

### F1 — Items API (`app/src/routes/items.ts`)

| STRIDE | Threat | Mitigation / Status |
|---|---|---|
| **S** Spoofing | Anonymous caller acts as a legitimate user (no authentication on `/api/items`). | **`[GAP]` G-01.** The demo API is intentionally unauthenticated. Items are non-persistent (`items` is an in-process `Map`, `items.ts:10`) and carry no PII (`data-flow.yaml:66-70`). *Target-state:* add authn/authz before any real-data use. Tracked as a documented demo limitation, not an achieved control. |
| **T** Tampering | Malicious payload alters server state or injects via `name`. | Input validated at the boundary: `name` required + type-checked (`items.ts:18-22`); IDs are server-generated `crypto.randomUUID()` (`items.ts:25`), not client-supplied, so a client cannot overwrite an arbitrary record. JSON body size/shape constrained by `express.json()` (`app.ts:45`). |
| **R** Repudiation | A mutating call (POST/DELETE) cannot later be attributed. | App-level: requests are stateless and ephemeral. Pipeline-level non-repudiation of the *deployed code* is covered by signed provenance (`sign-and-attest.yml:45-56`) + Rekor. **`[GAP]` G-02:** no per-request audit log in the demo app (acceptable for an in-memory demo with no PII; *target-state* for a production service). |
| **I** Information disclosure | Listing/reading items leaks data. | No PII or secrets are stored (`data-flow.yaml:66-70`); items hold only a client-supplied `name` + generated id/timestamp (`items.ts:4-8`). Response bodies contain no server internals. |
| **D** Denial of service | Unbounded item creation exhausts memory; large request bodies. | Partial: `express.json()` enforces a default body-size limit (`app.ts:45`). Platform autoscaling/replica limits at Container Apps level (`deploy.yml` env wiring). **`[GAP]` G-03:** no application-level rate limiting or `items` map cap; *target-state* — add rate limiting (security rule: rate-limit all endpoints). |
| **E** Elevation of privilege | Caller escalates to admin/host. | API exposes no admin surface; runs as non-root uid 65532 in a hardened Chainguard image (`app/Dockerfile:48`, `:59`); CSP via Helmet restricts script/style origins (`app.ts:32-44`). |

### F2 — Build-info endpoint (`app/src/app.ts:88-139`)

| STRIDE | Threat | Mitigation / Status |
|---|---|---|
| **S** Spoofing | A forged deployment claims another repo's identity. | Values are baked from the real build (`build-info.json` at Docker build, `Dockerfile:23`) and runtime env set by `deploy.yml:165-170`; the cosign verify command it prints binds to `--certificate-identity-regexp` for the repo (`app.ts:110`), so a verifier can independently detect a spoofed image (`deploy.yml:61-65`). |
| **T** Tampering | Metadata altered to hide provenance. | The endpoint is read-only; the underlying image is signed (`sign-and-attest.yml:45-56`) and admission-gated at deploy (`deploy.yml:55-65`), so a tampered image cannot reach the runtime that serves this endpoint. |
| **R** Repudiation | "We can't prove which build is running." | This endpoint *is* the repudiation control: it surfaces image digest, run URL and a paste-ready Rekor search URL (`app.ts:101-106`) tying the running artifact to the public transparency log. |
| **I** Information disclosure | Endpoint leaks sensitive internals. | Only non-secret build metadata is exposed (digest, repo, run id, public verify commands); no tokens/keys. OIDC issuer + cert pattern are *public verification* data, not secrets (`app.ts:98-99`). Reviewed: no env secret is echoed. |
| **D** Denial of service | Endpoint abused for load. | `readBuildInfo()` reads a tiny file once at startup (`app.ts:51-69`); the handler does only string formatting (no I/O per request). Same platform-level scaling caveat as F1 (G-03). |
| **E** Elevation of privilege | n/a — read-only, no privileged action. | No state change, no shell-out, no file write. Runs non-root (`Dockerfile:59`). |

### F3 — Health endpoint (`app/src/app.ts:71-77`)

| STRIDE | Threat | Mitigation / Status |
|---|---|---|
| **I** Information disclosure | Health probe leaks version/internal state. | Returns only `status`, ISO timestamp and a package version string (`app.ts:72-76`) — no internal topology, stack traces or secrets. |
| **D** Denial of service | Probe endpoint hammered. | Constant-time JSON response, no I/O. Used as the deploy smoke test (`deploy.yml:194`), so its availability is itself monitored. Platform scaling caveat (G-03). |
| **S/T/R/E** | Low relevance (read-only liveness probe). | No auth context, no state, no privileged path. |

### F4 — Static showcase page (`app/src/public/index.html`, served `app/src/app.ts:48`)

| STRIDE | Threat | Mitigation / Status |
|---|---|---|
| **T** Tampering | Injected/defaced static content. | Content is baked into the image at build (`Dockerfile:8` copies `src/public`) and served from an admission-gated signed image (`deploy.yml:55-65`); the runtime filesystem is the immutable container image. |
| **I** Information disclosure / **XSS** | Inline scripts or third-party content execute in the user's browser. | Helmet Content-Security-Policy restricts `defaultSrc`/`scriptSrc`/`styleSrc`/`fontSrc`/`imgSrc` to `'self'` + named origins (`app.ts:34-41`). **`[GAP]` G-04:** CSP allows `'unsafe-inline'` for scripts/styles (`app.ts:37`,`:39`) — *target-state:* move to nonce/hash-based CSP to remove `'unsafe-inline'`. |
| **S/R/D/E** | Static asset serving; low relevance. | No auth, no state mutation, non-root runtime (`Dockerfile:59`). |

---

## 4. STRIDE analysis — Pipeline / supply chain

The supply chain is itself a critical "feature" of an Evidence-Pack product: a compromise
here forges *every* downstream compliance claim. STRIDE is applied per pipeline phase /
trust boundary.

### P1 / TB-4 — Source control (developer -> repo)

| STRIDE | Threat | Mitigation / Status |
|---|---|---|
| **S** Spoofing | Attacker pushes as a trusted committer. | Branch protection enforced via `scripts/apply-branch-protection.sh` (required reviews / no direct prod push — SLSA Source intent, spec §4 `:188`). |
| **T** Tampering | Malicious code merged or history rewritten (force-push). | Required pull-request review + branch protection (`apply-branch-protection.sh`); SAST (CodeQL `build-and-scan.yml:166-208`) and secret scan (`security-gate.yml:33-87`) run on the change before it can be built. |
| **R** Repudiation | Author of a change denied. | Git commit metadata retained as audit trail (`data-flow.yaml:34-40`). **`[GAP]` G-05:** signed-commit enforcement (SLSA Source L4) is *target-state*, not enforced today. |
| **I/D/E** | Token leak, CI starvation, runner-priv escalation. | Secret detection blocks credentials at source (`security-gate.yml:44-46`); see TB-3 for CI identity scoping. |

### P2 — Security gate (`security-gate.yml`)

| STRIDE | Threat | Mitigation / Status |
|---|---|---|
| **I** Information disclosure | Secret committed into code/history reaches the image. | TruffleHog secret detection runs as Phase 1 gate (`security-gate.yml:44-46`), output captured as evidence (`:52-64`). |
| **T** Tampering | Insecure IaC ships a misconfigured cloud. | Checkov IaC scan with `set -o pipefail` so a policy failure is **not** masked by `tee` (`security-gate.yml:104-116`) — fails the gate on misconfig; SARIF uploaded (`:134-138`). |
| **R** Repudiation | "Scan didn't really run." | Per-run logs + SARIF uploaded as artifacts (`security-gate.yml:82-87`,`:134-138`); rolled into the signed evidence pack (P6). |

### P3 — Build & scan (`build-and-scan.yml`)

| STRIDE | Threat | Mitigation / Status |
|---|---|---|
| **T** Tampering | Vulnerable dependency / code-level vuln enters the artifact. | Trivy SCA filesystem scan (`build-and-scan.yml:53-66`) + CodeQL SAST (`:166-208`) run per build; SARIF uploaded to Code Scanning (`:203-208`). |
| **I** Information disclosure | Unknown components hide CVEs. | SBOM (CycloneDX) generated and later signed/attested (P4); SCA + SBOM is the spec's transparency control (`evidence-pack-specification.md:138`). |
| **R** Repudiation | Scan results disputed. | Tool version + scan metadata recorded into summaries (`build-and-scan.yml:74-106`); artifacts uploaded (`:110-116`). |
| **D** Denial of service | Poisoned dependency in build. | Trivy SCA flags known-vulnerable deps before build promotion (`build-and-scan.yml:53-66`); `npm ci --ignore-scripts` blocks install-time script execution (`Dockerfile:5`,`:38`). |

### P4 / TB-3 — Sign & attest (`sign-and-attest.yml`)

| STRIDE | Threat | Mitigation / Status |
|---|---|---|
| **S** Spoofing | Attacker signs an image as our pipeline. | Cosign **keyless OIDC** signing (`sign-and-attest.yml:45-56`) binds the signature to the workflow's GitHub OIDC identity via Fulcio — no long-lived key to steal. |
| **T** Tampering | Artifact swapped after build. | SLSA/in-toto provenance binds artifact-by-digest to builder+inputs (`sign-and-attest.yml:79-101`); fallback provenance is JSONL-validated so a corrupt attestation is never published (`:102-107`). SBOM attached as a signed attestation (`:64-70`). |
| **R** Repudiation | "We never signed/built this." | Signing event is recorded in the **Rekor** public transparency log (Sigstore keyless flow, `sign-and-attest.yml:45-56`); the demo app surfaces the Rekor search URL (`app.ts:106`). |
| **I** Information disclosure | Signing key exfiltration. | No persistent signing key exists (keyless), so there is no key material to disclose (`sign-and-attest.yml:33`,`:45-48`). |
| **E** Elevation of privilege | Over-broad CI token. | Workflow permissions scoped (`sign-and-attest.yml:17-19` `attestations: write`); OIDC short-lived tokens, no static cloud secrets (consistent with `deploy.yml:42-43`). |

### P5 / TB-2 — Deploy (`deploy.yml`)

| STRIDE | Threat | Mitigation / Status |
|---|---|---|
| **S** Spoofing | Unsigned / foreign image deployed. | **Admission gate:** `cosign verify` with `--certificate-identity-regexp` + `--certificate-oidc-issuer` *before* deploy, with `set -o pipefail` so a failed verify cannot be masked by `tee` (`deploy.yml:55-65`). |
| **T** Tampering | Tampered image or infra drift applied. | Image is digest-pinned and verified (`deploy.yml:55-65`); infra applied only via Terraform in-pipeline (`:118-125`), not manual `kubectl`/portal edits (spec §4 reject `:199`). |
| **R** Repudiation | "Who deployed what?" | Run summary records environment, image, OIDC auth (`deploy.yml:216-241`); deploy is part of the sealed evidence pack (P6). |
| **I** Information disclosure | Static cloud credentials leak. | **Zero static secrets** — Azure login is OIDC federation (`deploy.yml:42-43`,`:79` `ARM_USE_OIDC`). |
| **E** Elevation of privilege | Pipeline gains excessive cloud rights. | OIDC-scoped identity per environment (`deploy.yml:33` `environment`); RBAC exportable for review (`scripts/export-azure-rbac.sh`). **`[GAP]` G-06:** runtime admission policy-as-code (OPA/Kyverno `verifyImages`) is spec C.13 *target-state* — current admission is the CI-side cosign-verify gate, not an in-cluster controller. |

### P6 / TB-5 — Evidence pack & seal (`evidence-pack.yml`, `scripts/seal-evidence.sh`)

| STRIDE | Threat | Mitigation / Status |
|---|---|---|
| **T** Tampering | Evidence altered after the fact. | Per-file manifest + **Merkle root** over the pack, then **RFC-3161 timestamp** and WORM archive (`scripts/seal-evidence.sh`); this threat model file is hashed into that Merkle root once T-115 wiring lands (see §6). |
| **R** Repudiation | "Evidence was back-dated / fabricated." | RFC-3161 timestamp + (target) qualified eIDAS QTS provides non-repudiation; **`[GAP]` G-07:** default TSA is freetsa (non-qualified) — qualified QTS is *target-state* (T-53, manifest must label `qualified=false` honestly). |
| **I** Information disclosure | Pipeline logs leak PII/secrets into evidence. | Log sanitisation step (`scripts/sanitize-logs.sh`); evidence archive PII minimised + access-restricted (`data-flow.yaml:72-78`). |
| **D** Denial of service | Evidence destroyed to break audit. | WORM immutability + retention (5y DORA) on the archive (`data-flow.yaml:78`); **`[GAP]` G-08:** lifecycle-delete vs WORM footgun is *target-state* fix (T-52). |
| **S/E** | Forged/over-privileged seal identity. | Seal runs under the same OIDC-scoped CI identity (no static secret); transparency log makes a forged seal externally detectable. |

---

## 5. Gap register (target-state — NOT achieved)

These are honestly-labelled gaps surfaced by the STRIDE pass. They are *target-state*; none
is claimed as an implemented control. They feed the spec Part J.1 gap register.

| Gap | Element | Threat (STRIDE) | Target-state action | Tracking |
|---|---|---|---|---|
| G-01 | F1 Items API | S — unauthenticated API | Add authn/authz before any real-data use | Demo limitation (no PII today) |
| G-02 | F1 Items API | R — no per-request audit log | Structured request audit log for mutating calls | Production-readiness |
| G-03 | F1/F2/F3 | D — no app-level rate limiting / map cap | Rate-limit endpoints; bound the in-memory store | Production-readiness |
| G-04 | F4 showcase | I/XSS — CSP allows `'unsafe-inline'` | Nonce/hash-based CSP, drop `'unsafe-inline'` | Hardening (`app.ts:37`,`:39`) |
| G-05 | P1 source | R — signed commits not enforced | Enforce commit signing (SLSA Source L4) | Spec §4 `:188` |
| G-06 | P5 deploy | E — no in-cluster admission controller | OPA/Kyverno `verifyImages` policy gate | Spec C.13; runtime task |
| G-07 | P6 seal | R — non-qualified timestamp | Wire qualified eIDAS QTS; label honestly | T-53 |
| G-08 | P6 seal | D — lifecycle-delete vs WORM footgun | Tie delete action after immutability period | T-52 |

---

## 6. Integration status (target-state vs achieved)

| Item | Status |
|---|---|
| Threat-model artifact exists, per critical feature, risks traced to controls | **ACHIEVED** (this file). |
| Versioned + `last_reviewed` within a stated window | **ACHIEVED** (`model_version 1.0.0`, `last_reviewed 2026-06-16`, `review_window_days 180`). |
| Machine validator (`scripts/validators/threat_model.py`) asserting every entry has a non-empty control/gap ref | **TARGET-STATE** — validator is owned by the T-115 validator/matrix-wiring work (existing-script domain); not created here to respect strict file disjointness. |
| Hashed into manifest + Merkle root (signed at production) | **TARGET-STATE** — requires adding this path to the seal set in `evidence-pack.yml` (existing-workflow domain); not edited here. Once wired, this file is committed-to by the Merkle root. |
| Rendered into the audit PDF (Part C.1) | **TARGET-STATE** — `scripts/build-audit-document.py` Part C.1 section (existing-script domain). |

> Per strict task disjointness, this task creates **only** the threat-model artifact. The
> validator, the `generate-compliance-matrix.sh` row, and the `evidence-pack.yml` seal-set
> wiring are existing-file edits handled by the sibling T-115 implementation work and are
> recorded above as target-state so this document never overclaims.

---

## Sources

Methodology and regulatory grounding (web-verified 2026-06):

- STRIDE model overview — Wikipedia: https://en.wikipedia.org/wiki/STRIDE_model
- A Guide to the STRIDE Threat Model — SecureFlag (STRIDE-per-element, trust boundaries): https://blog.secureflag.com/2026/06/05/guide-to-stride-threat-model/
- Threat Modelling — OWASP Security Culture: https://owasp.org/www-project-security-culture/v10/6-Threat_Modelling/
- Threat Modeling Process — OWASP Foundation: https://owasp.org/www-community/Threat_Modeling_Process
- Mastering Application Security Requirements for ISO 27001, DORA, and NIS2 — Clarysec (NIS2 21(2)(e) / ISO 8.25 secure SDLC mapping): https://blog.clarysec.com/posts/mastering-application-security-requirements-for-compliance/
- NIS2 Implementing Act (EU) 2024/2690 ↔ ISO 27001 mapping — OpenKRITIS: https://www.openkritis.de/massnahmen/implementing-acts-it-nis2-mapping.html
