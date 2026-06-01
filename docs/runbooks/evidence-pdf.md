# Runbook — Audit-Grade Evidence PDF Generator

> How CyberForge turns a raw evidence directory into a single, self-contained,
> cryptographically anchored audit document — and how anyone can verify it.
>
> **Authoritative artifact:** the sealed `evidence-report.pdf` (PDF/A-3b) together with
> its embedded `manifest.json`, Merkle root, and signature bundle. The marketing
> showcase (`app/src/public/index.html`) is **illustrative only**.

---

## 1. Trust model (honest by construction)

These principles are non-negotiable and are enforced in the generators, not just
documented here. Every claim in the report is either **measured** (computed from
evidence files) or explicitly flagged **asserted/static**.

| Principle | What it means in practice |
|-----------|---------------------------|
| **SLSA Build L2, not L3** | We claim hosted, signed-build-platform provenance (L2). L3 (hermetic, isolated builder) is **not** claimed without proof. |
| **Immutability is DESIGNED, not LOCKED** | The report prints the **measured** `worm_state` from `manifest.json` (e.g. `pending`, `locked`, `unavailable`). It never asserts "WORM immutable" unconditionally. |
| **Report is evidentiary; the website is illustrative** | The PDF is the artifact of record. The webpage carries a disclaimer to that effect. |
| **Tamper-evidence requires an anchor** | The manifest + Merkle root make tampering *detectable* only **once anchored** via RFC 3161 timestamp and/or Rekor transparency log. Before anchoring it is "integrity-checkable", not "tamper-evident". |
| **Verify the digest externally** | A container's self-reported digest is not proof. The verify runbook resolves the digest from the registry and compares. |
| **No hardcoded numbers/timestamps/state** | Compliance counts, hashes, timestamps, and WORM state are computed from evidence or carried via env — never baked into a template. |
| **Graceful degradation with provenance** | Any missing external tool is recorded as a provenance flag. **CI fails closed** unless `EVIDENCE_ALLOW_DEGRADE=1`; locally the full chain runs degraded with only stdlib tooling. |

### Subservice organizations (carve-out) & CUECs

The pipeline depends on subservice organizations **outside its control boundary** —
**GitHub** (build platform, OIDC issuer, artifact/release storage), **Microsoft Azure**
(Blob storage + immutability/retention enforcement), and **Sigstore** (Fulcio CA, Rekor
log). Their controls are assumed under a carve-out model and are **not** re-tested here.

Effectiveness also depends on **Complementary User Entity Controls** the adopter must
operate: branch protection + signed commits + 2-reviewer approval; pinned OIDC trust
policy and pinned Fulcio/issuer identity at verification time; a configured **and locked**
Azure immutability policy on the evidence container; protected/rotated registry & storage
access; and **independent** digest/signature verification rather than trusting self-reports.

---

## 2. Pipeline stages

The generator chain runs in this fixed order. Each stage consumes the previous stage's
output.

```
generate-evidence-manifest.py   # hash every artifact, build RFC-6962 Merkle root
        │
generate-oscal.py               # emit NIST OSCAL assessment-results from the matrix
        │
build-audit-document.py         # assemble the full forensic HTML audit document
        │
render-evidence-pdf.py          # WeasyPrint -> PDF/A-3b with embedded raw evidence
        │
seal-evidence.sh                # normalize, verapdf gate, cosign, RFC3161, PAdES
        │
verify-evidence-pack.sh         # independent re-verification (the verify runbook)
```

### 2.1 `generate-evidence-manifest.py`
Pure-stdlib Python 3. Hashes every file in the evidence directory (excluding
`manifest.json` itself), classifies each as **live** (scanner outputs, SBOMs) or
**static/asserted** (DPA check, data-flow diagram, cost tables, README) by a documented
filename heuristic, and computes an **RFC-6962 domain-separated** Merkle root:

- leaf = `SHA256(0x00 || data)`
- node = `SHA256(0x01 || left || right)`
- artifacts sorted by path; empty tree = `SHA256(b"")`

Writes `manifest.json` (schema `cyberforge-evidence-manifest/v1`) and a legacy
`manifest.sha256` (sorted `sha256␠␠path`). Timestamps come from `GENERATED_AT`
(falling back to a fixed placeholder) so output is **deterministic and testable**.

```bash
python3 scripts/generate-evidence-manifest.py "$EVIDENCE_DIR" \
  --out manifest.json --legacy-out manifest.sha256
python3 scripts/generate-evidence-manifest.py --selftest   # known-vector Merkle check
```

### 2.2 `generate-oscal.py`
Deterministic transform of `compliance-matrix.json` into a minimal-valid NIST **OSCAL
1.1.2** Assessment Results document: one observation per control (id, description,
PASS/FAIL/NA, linked evidence artifact + its SHA-256 from the manifest).

### 2.3 `build-audit-document.py`
Assembles the **full forensic audit document** as a single self-contained HTML file in
the exact section order from the design spec (cover → document control → TOC → statement
of authority → assurance summary → scope/boundaries/subservice + CUEC → management
attestation → IPE/population → control-to-evidence matrix (incl. UKSC Art.8, CRA Art.13,
and an SSDF PO/PS/PW/RV sub-matrix) → provenance + SBOM attestation → per-control evidence
detail (inlines the data-driven `evidence-report.html` body) → vulnerability management →
change & approval records → exceptions/deviation register → emergency/break-glass →
DORA + security-KPI trends → retention metadata (prints `worm_state`) → glossary →
tamper-evidence appendix (hash table + Merkle root + signature refs) → self-seal page →
claims register).

Every figure is pulled from `manifest.json` / `compliance-matrix.json` and each evidence
row carries a **live/measured vs static/asserted** badge from the manifest provenance.
Missing optional inputs degrade a section to "Not available this run" rather than failing.

### 2.4 `render-evidence-pdf.py`
The only generator with a third-party dependency (**WeasyPrint**). Renders the audit
HTML to **PDF/A-3b** and embeds the raw evidence files (`manifest.json`, OSCAL, SBOM,
SARIFs, provenance, verify runbook) as attachments with `AFRelationship` Source/Data.
Document XMP created/modified come from `GENERATED_AT`.

If WeasyPrint is unavailable: with `EVIDENCE_ALLOW_DEGRADE=1` it warns, writes a
`*.pdf.MISSING` marker, and exits 0; otherwise it exits non-zero.

### 2.5 `seal-evidence.sh`
Each step tolerates a missing tool (outcome recorded into `manifest.json` `signatures{}`
via a Python helper — **JSON is never edited with `sed`**). In CI **without**
`EVIDENCE_ALLOW_DEGRADE=1`, a missing render / verapdf / cosign is a **hard fail**.

1. `qpdf --linearize --deterministic-id` (normalize) if present.
2. `verapdf --flavour 3b --format json` PDF/A gate (fail-closed in CI) → `verapdf-report.json`.
3. `cosign sign-blob --yes --bundle` (keyless) over `manifest.json` and the PDF's SHA-256 → `*.bundle`.
4. `openssl ts` query/reply over the Merkle root, manifest, and PDF via `TSA_URL` (default `https://freetsa.org/tsr`) → `*.tsr`; TSA unreachable records an `rfc3161 unavailable` soft flag.
5. `pyhanko sign addsig` PAdES (B-LTA target, honest fallback label) if present.
6. Update `manifest.json` `signatures{cosign, rfc3161, pades, verapdf}` + tooling versions.

---

## 3. Verify runbook — `verify-evidence-pack.sh`

Anyone can independently re-verify a pack. Each check prints **PASS / SKIP / FAIL**;
the script exits 0 only if there is **no FAIL** (SKIP is allowed for an absent tool, so
a locally-sealed degraded pack still passes on the hash + Merkle checks).

```bash
scripts/verify-evidence-pack.sh "$EVIDENCE_DIR"
```

Checks performed:

1. **SHA-256** — `sha256sum -c` the legacy `manifest.sha256`.
2. **Merkle root** — recompute the RFC-6962 root and compare to `manifest.merkle_root`.
3. **Cosign** — `cosign verify-blob` with a **pinned** identity (`COSIGN_IDENTITY` / `COSIGN_ISSUER`) if cosign + bundle present.
4. **RFC 3161** — `openssl ts -verify` if a `.tsr` is present.
5. **PDF/A** — `verapdf` if present.
6. **Signature coverage** — `pdfsig` whole-document-coverage check if pdfsig + PDF present.

### Verify the image digest externally (do not trust self-reports)

```bash
# 1. What the running container claims:
curl -s https://<host>/api/build-info | jq -r .imageDigest
# 2. Resolve the digest independently from the registry and compare:
crane digest ghcr.io/<org>/app:latest          # or: cosign triangulate ...
# 3. Verify SLSA Build L2 provenance with a pinned identity:
cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp 'https://github.com/.+/.github/workflows/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/<org>/app@sha256:<digest>
```

---

## 4. Local dry run (degraded)

Locally only `python3`, `openssl`, `qpdf`, `jq`, `sha256sum`, and `zip` are assumed
present (WeasyPrint / verapdf / cosign / gs / pyhanko are absent). Run the chain with
degradation allowed:

```bash
export EVIDENCE_ALLOW_DEGRADE=1
export REPORT_ID=local-dryrun GIT_SHA=$(git rev-parse HEAD) \
       IMAGE_DIGEST=sha256:0000 GENERATED_AT=1970-01-01T00:00:00Z \
       PERIOD_START=2026-01-01 PERIOD_END=2026-03-31
EVID=/tmp/evidence
python3 scripts/generate-evidence-manifest.py "$EVID" --out manifest.json --legacy-out manifest.sha256
python3 scripts/generate-oscal.py "$EVID" docs/compliance-matrix.json
python3 scripts/build-audit-document.py --evidence-dir "$EVID" \
  --manifest manifest.json --report-html evidence-report.html --out audit-document.html
python3 scripts/render-evidence-pdf.py --html audit-document.html \
  --evidence-dir "$EVID" --out evidence-report.pdf      # writes .pdf.MISSING if WeasyPrint absent
bash scripts/seal-evidence.sh "$EVID" evidence-report.pdf manifest.json
bash scripts/verify-evidence-pack.sh "$EVID"            # PASS on sha256 + Merkle, SKIP elsewhere
```

A degraded pack is honest about what is missing: missing tools surface as provenance
flags in `manifest.json` and as SKIP lines in the verify output — never as silent success.

## 5. CI behaviour (fail-closed)

In `.github/workflows/evidence-pack.yml` the "Build audit-grade PDF" block runs the same
chain **without** `EVIDENCE_ALLOW_DEGRADE` on non-PR runs, so any missing
render / verapdf / cosign step is a hard failure. It exports
`REPORT_ID` / `GIT_SHA` / `IMAGE_DIGEST` / `GENERATED_AT` / `PERIOD_*`, uploads
`evidence-report.pdf` + the signature bundle as artifacts, and falls back to a
`gh release` upload. PDF/A conformance and signature verification gate the release.

## 6. Honesty checklist before publishing a pack

- [ ] `worm_state` in `manifest.json` reflects the **actual** retention-lock state.
- [ ] No compliance count, hash, timestamp, or WORM claim is hardcoded.
- [ ] SLSA level claimed is **L2** (no L3 without hermetic-builder proof).
- [ ] Every evidence row is badged **live/measured** or **static/asserted**.
- [ ] "Tamper-evident" is qualified with "once anchored" until RFC3161/Rekor succeeds.
- [ ] `verify-evidence-pack.sh` exits 0 (no FAIL).

## See also

- `docs/compliance-matrix.md` — control-to-evidence mapping (incl. UKSC Art.8, CRA Art.13)
- `docs/governance/soc2-control-matrix.md` — SOC 2 TSC mapping and control-testing notes
- `.github/workflows/evidence-pack.yml` — the CI evidence pipeline
- `app/src/public/index.html` — illustrative showcase (carries the disclaimer banner)
