# CyberForge DevSecOps Pipeline

A secure, compliance-enabling **GitHub Actions CI/CD pipeline** for a
containerized Node.js application on Microsoft Azure, with automated,
cryptographically sealed **audit evidence generation** on every release.

It is built as a reference implementation of secure software delivery and
software-supply-chain controls aligned to:

- **DORA** (EU 2022/2554)
- **NIS2** (EU 2022/2555)
- **ISO/IEC 27001:2022**
- **SOC 2**
- **GDPR / RODO** (supporting controls and evidence)

## Pipeline phases

The pipeline runs as six modular, reusable workflows, gated end to end:

1. **Security Gate** — secret scanning (TruffleHog), IaC scanning (Checkov),
   linting (MegaLinter), PII scanning, and PR commit-signature verification.
2. **Build & Scan** — dependency scanning (Trivy SCA), SAST (CodeQL),
   unit tests with an 80% coverage gate, container build, image scanning, and
   CycloneDX SBOM generation.
3. **Sign & Attest** — keyless image signing (Cosign / Sigstore), SBOM
   attestation, and SLSA build provenance.
4. **Deploy** — Azure OIDC authentication (no static cloud secrets), a blocking
   `cosign verify` admission gate, Terraform plan/apply, and a smoke test.
5. **DAST** — OWASP ZAP scan against the deployed app, with incident creation
   on high-severity findings.
6. **Evidence Pack** — collects all phase artifacts, sanitizes logs, computes an
   RFC-6962 Merkle root over every artifact, keyless Cosign `sign-blob`s the
   root (fail-closed in CI) and RFC-3161-timestamps it (a standard TSA, not a
   qualified eIDAS QTS — see upgrade path below), and produces a **PDF/A-3 audit
   report** archived to immutable storage.

## Security & supply-chain posture

- **Zero static cloud secrets** — Azure access via OIDC federation only.
- **All third-party Actions pinned** to full commit SHAs.
- **Enforced, fail-closed gates** — CVE (CRITICAL/HIGH), coverage, secret, and
  signature checks block the build; they do not merely warn.
- **Keyless signing + provenance** — Cosign → Fulcio/Rekor, CycloneDX SBOM
  attestation, SLSA provenance; the signature is re-verified before deploy.
- **Hardened runtime** — minimal, non-root container image, scanned to
  0 HIGH/CRITICAL.
- **Tamper-evident evidence** — per-artifact SHA-256 + RFC-6962 Merkle root, a
  keyless Cosign `sign-blob` over the root, and RFC-3161 timestamps. The Merkle
  root is signed on every production run: a missing or empty
  `merkle-root.cosign.bundle` is a hard CI failure, so the pack cannot be sealed
  without it. The RFC-3161 stamp uses a standard public TSA (freetsa.org),
  **not** a qualified eIDAS Qualified Timestamp Service (QTS); a pluggable QTS
  upgrade path (KIR Szafir / Certum / EuroCert / CenCert) is documented
  separately. On local/degrade runs the Cosign and TSA steps soft-degrade on
  signing-infra/TSA flakiness; PDF/A-3 archival anchors the pack regardless.

## Repository layout

| Path | Contents |
|---|---|
| `app/` | Node.js + TypeScript + Express demo application and `Dockerfile` |
| `.github/workflows/` | The six reusable pipeline workflows + orchestrator |
| `infra/` | Terraform for Azure (ACR, Container Apps, Key Vault, WORM storage, monitoring) |
| `policies/` | OPA/Rego compliance policies |
| `scripts/` | Evidence-pack generation, manifest/Merkle, OSCAL, and PDF tooling |
| `docs/` | Compliance matrix, governance/ISMS documentation, and runbooks |

## Documentation

- [`SETUP.md`](SETUP.md) — GitHub + Azure setup and rollout checklist
- [`docs/README.md`](docs/README.md) — full documentation index
- [`docs/compliance-matrix.md`](docs/compliance-matrix.md) — framework → control → evidence mapping
- [`docs/governance/`](docs/governance) — ISMS, SOC 2, risk, IAM, and supplier-risk documentation
- [`docs/runbooks/`](docs/runbooks) — incident response, BC/DR, WORM, and evidence-PDF runbooks

## Scope and boundaries

This pipeline provides **technical** secure-SDLC and supply-chain controls and
generates audit evidence for them. It is a strong foundation for DORA / NIS2 /
ISO 27001 / SOC 2 readiness — but a full compliance program also requires
organizational controls outside CI/CD: governance and risk management, incident
reporting procedures, BC/DR drills, IAM governance, supplier-risk management,
internal audit, and management review. ISO 27001 and SOC 2 additionally require
external certification/attestation; this repository prepares evidence and
controls but does not self-certify. See
[`docs/compliance/scope-and-limitations.md`](docs/compliance/scope-and-limitations.md)
for the detailed scope statement.
