# CyberForge — Sample Evidence Pack (DEMO)

> **DEMO sample — degrade mode; live keyless signature, Azure WORM archival, and
> A.10 restore-test pending the production CI run on the CyberForge Azure
> subscription.**

This is a **sanitized, partner-showable structural sample** of the CyberForge
Evidence Pack. It was assembled **offline** (no cloud, no Azure, no image push,
no deploy) to demonstrate the *shape and contents* of a real pack and to let a
prospect run the integrity runbook themselves. It is **not** a compliance
attestation for any production system.

## How to verify this pack yourself

```bash
cd Pipeline
# Re-run the reproducer; it verifies as its last step and exits 0:
bash sample-evidence-pack/make-sample-pack.sh
```

Expected (this offline demo): `RESULT: OK` with `5 PASS / 4 SKIP / 0 FAIL` —
sha256 manifest, RFC-6962 Merkle root, and **both RFC-3161 timestamps verify
cryptographically against the freetsa CA**. cosign keyless verification and PDF/A
(veraPDF/pdfsig) **SKIP** because this box has no sigstore OIDC and no WeasyPrint.

> **Why verify is run with cosign hidden.** This is a degrade-mode pack: the
> Merkle-root cosign bundle is **PENDING the live CI run** and does not exist yet.
> `verify-evidence-pack.sh` has an anti-regression rule (§6.2-A): if cosign is on
> PATH but the bundle is absent while `merkle-root.txt` exists, it **FAILs on
> purpose** — that is the exact silent-omission bug it guards against. So for this
> offline pack the runbook is invoked under the documented *offline-no-sigstore*
> model (cosign not visible), where the missing bundle is a clean **SKIP**. Once
> the production CI run produces `merkle-root.cosign.bundle` + Rekor proof, the
> pack verifies with real cosign on PATH and the SKIP becomes a PASS. Running
> `bash scripts/verify-evidence-pack.sh sample-evidence-pack/evidence` with cosign
> installed will (correctly) report the §6.2-A FAIL until then.

## The 8 components (spec / struktura mapping)

An auditor enters at **D** (the matrix/crosswalk — "do you cover my framework?"),
drills into **A/C** (the org verdicts and the scan evidence behind a row), and
verifies trust in **I** (the integrity proof). The pack is built so that path
works:

| # | Component | File(s) in `evidence/` | Spec part | Status in this demo |
|---|-----------|------------------------|-----------|---------------------|
| 1 | **Board report (PDF)** | `audit-document.html`, `evidence-report.html` (+ `evidence-report.pdf.MISSING`) | Part 0.2 | **HTML present; PDF/A PENDING** (WeasyPrint absent offline → honest `.MISSING` marker; CI renders the PDF/A-3b) |
| 2 | **Artifact manifest** | `manifest.json`, `manifest.sha256`, `merkle-root.txt` | Part 0.1 | **Present** (RFC-6962 Merkle root `2ca49f9c…`, rendered from `merkle-root.txt` by the reproducer — cannot drift) |
| 3 | **Scan results** | `trivy-sca-results.json`, `trivy-results.sarif` | §X.1 / Part C | **Present** (real Trivy scan of the demo app) |
| 4 | **SBOM** | `sbom.cyclonedx.json` | Part C.10 | **Present** (real CycloneDX, 70 components) |
| 5 | **Control matrix** | `compliance-matrix.json` | Part D.1 | **Present** (content-validated DORA/NIS2/GDPR/CRA/ISO/SOC2) |
| 6 | **Regulatory crosswalk** | `crosswalk.json` | Part D.2 | **Present** (one evidence → many clauses, derived from the matrix + A.1–A.10) |
| 7 | **Gap / remediation register** | `gap-register.md`, `gap-register.json` | Part J | **Present** (control → gap → severity → root cause) |
| 8 | **Integrity proof** | `merkle-root.txt`+`.tsr`, `manifest.tsr`, `tsa-ca.pem`, `manifest.signatures{}` | Part I | **Partial — RFC-3161 PRESENT & VERIFYING; cosign keyless PENDING** |

Supporting org-control evidence (Part A, the differentiator — signed PASS/FAIL
organizational verdicts): `compliance-status.json` (the A.1–A.10 aggregate gate,
the **compliance gate** itself — T-35) plus the per-control inputs
`access-review.json`, `dpa-compliance-check.json`, `governance-evidence.json`,
`incident-readiness.json`, `restore-test.json`, `roi-validation.json`,
`ropa-completeness.json`, `tpp-clauses.json`.

Additional spec-part artifacts bound into the pack (Merkle-covered) by the
reproducer so the audit can drill all the way down:

| Artifact in `evidence/` | Spec part | Source validator |
|-------------------------|-----------|------------------|
| `threat-model-validation.json` (+ `threat-model.yaml`) | Part C / STRIDE | `validators/threat_model.py` (T-115) |
| `runtime-hardening.json` | Part C runtime posture | `validators/runtime_hardening.py` (T-118) |
| `scope-determination.json` | Part B / 0.4 applicability | `validators/applicability.py` |
| `residual-risk.json` | Part J residual risk | `validators/risk_acceptance.py` (T-121) |
| `soa-maturity.json` | Part D.3 / §9 maturity | `validators/soa_maturity.py` |
| `vex.openvex.json` | Part C.11 (VEX) | `generate-vex.py` (T-116) |

These carry the live validator verdicts of THIS run (never recomputed, never a
fabricated PASS). The OpenVEX is **bound to a digest derived deterministically
from this pack's real SBOM** under a clear demo URI (`cyberforge-demo/app:offline-demo`)
— there is no released image offline, so it is a reproducible demo binding, not a
production release attestation.

## Honest verdict (this is the point — the gate fails honestly)

This pack contains **real, un-doctored** verdicts. The chain *assembled and
self-verified*; that is separate from whether the sample evidence is *compliant*:

- **Organizational gate (A.1–A.10):** `compliance-status.json` → **overall FAIL,
  1 BLOCKING failure**. The blocking control is **A.10 — restore / BCDR test:
  "no restore drill logged"**. This is **deliberate and honest**: the A.10
  restore-test requires the live Azure environment and is **PENDING** (held).
  We do **not** fake a PASS. A real pack from the production run will carry the
  conducted-drill evidence.
- **Content matrix:** `compliance-matrix.json` → **16 BLOCKING rows**, almost all
  **INDETERMINATE** because the **live-CI / cloud-only artifacts are absent
  offline** (`security-report.json`, `trivy-sca-summary.json`, `pipeline-run.json`,
  `provenance.intoto.jsonl`, `zap-report.json`, CodeQL SARIF, image scan, OSCAL).
  Those are produced by the production CI run on the CyberForge Azure
  subscription — **PENDING** for this demo. The SBOM row *does* resolve (real
  CycloneDX detected). An INDETERMINATE row is the validator correctly refusing
  to PASS a control it could not measure — never a silent green.

## What is PENDING the production CI run (do not read these as done)

1. **cosign keyless signature** over the Merkle root (Fulcio identity + Rekor
   transparency log). Offline there is no OIDC token, so the seal honestly
   records `signatures.cosign.status = unavailable` and the verify runbook emits a
   clean **SKIP** (not a fabricated PASS). The live CI run produces
   `merkle-root.cosign.bundle` + a Rekor inclusion proof.
2. **Azure WORM (immutable) archival.** This demo performs **no** cloud upload.
   `manifest.worm_state = pending`. The live run writes the pack to an
   immutability-locked container.
3. **A.10 restore-test.** Held on Azure; shown here as an honest **BLOCKING
   FAIL**, not a PASS.
4. **PDF/A-3b board report.** Rendered by WeasyPrint in CI; offline it degrades to
   an `evidence-report.pdf.MISSING` marker. The HTML audit document is the
   showable stand-in.

## Trust labels (honest, non-overclaiming)

- **RFC-3161 timestamps are NON-QUALIFIED** (freetsa.org, free). `qualified=false`
  is recorded in the manifest. Production can switch to a qualified eIDAS QTS
  (KIR Szafir / Asseco Certum / EuroCert / CenCert) by config — no code change.
- **SLSA Build L2** (not L3). L3 is explicitly **not** claimed (see
  `gap-register.md` G-09).
- The PDF report is the *evidentiary* object; the HTML is illustrative.

## Sanitization

No live secrets, no fabricated findings, no internal/client identifiers. Local
absolute filesystem paths were redacted to a neutral `/cyberforge-demo` root in
the Trivy SARIF and `incident-readiness.json`. A redaction grep over the pack for
leaked GitHub PATs, the known demo placeholder tokens, the internal repo name,
and any SLSA-Level-3 overclaim returns **0 matches**.

## Reproduce

One command regenerates this entire pack offline and re-verifies it:

```bash
bash sample-evidence-pack/make-sample-pack.sh   # exits 0; prints the verify runbook
```

It mirrors `scripts/run-local-e2e.sh` (the offline chain) with two deliberate
differences so the integrity proof is richer: **curl is kept visible** so the seal
produces real freetsa RFC-3161 timestamps, and the **freetsa CA chain is bundled**
(`tsa-ca.pem`) so `openssl ts -verify` is a full cryptographic PASS rather than a
parse-only SKIP. cosign stays hidden to model offline-no-sigstore honestly. The
crosswalk + gap-register derivation lives in `derive-crosswalk-and-gaps.py` (pure
stdlib). Before the final manifest the reproducer also binds the spec-part
artifacts above (threat model, runtime hardening, applicability, residual risk,
SoA maturity, OpenVEX) into `evidence/` so they are Merkle-covered, then renders
the README's Merkle-root reference from `merkle-root.txt` so it can never drift.
Prereqs: `bash`, `python3`, `openssl`, `curl`, `trivy` (warmed DB cache).

A coherent **re-seal** of the committed sample (recomputing the Merkle root over
the newly-bound artifacts and re-timestamping) requires the production CI run
(network freetsa TSA + the in-flight pipeline scripts) — see the repo task notes;
the committed pack here verifies as-is (`5 PASS / 4 SKIP / 0 FAIL`).
