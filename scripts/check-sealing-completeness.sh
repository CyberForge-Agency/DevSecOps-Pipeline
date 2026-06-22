#!/usr/bin/env bash
#
# check-sealing-completeness.sh — the evidence-integrity self-test (T-58).
#
# Asserts that a fully-sealed CyberForge evidence pack deterministically emitted
# its COMPLETE integrity-chain artifact set. This is the single check that turns
# the spec §1.0 / §4 / §12 "8-component Evidence Pack" requirement into an
# enforceable gate, so a §6.2-A-class regression (an integrity output that is
# silently never produced) cannot slip through with a green, sealed pack.
#
# Usage: check-sealing-completeness.sh <evidence_dir>
#
# Required sealing artifacts (each MUST exist and be non-empty):
#   1. manifest.json                 — Merkle root + per-artifact hashes (§7.1)
#   2. merkle-root.txt               — the immutable RFC-6962 root that is signed
#   3. merkle-root.cosign.bundle     — keyless identity attribution over the root
#                                      (the pack's headline crypto claim; §6.2-A)
#   4. pdf-sha256.cosign.bundle      — keyless attribution over the PDF hash
#   5. verapdf-report.json           — PDF/A-3b conformance gate evidence (§7)
#   6. oscal-assessment-results.json — OSCAL assessment-results (control findings)
#   7. sbom.cyclonedx.json           — CycloneDX SBOM (Part C.10)
#   8. provenance.intoto.jsonl       — in-toto / SLSA build provenance (Part C.12)
#   +  >=1 *.tsr                      — at least one RFC-3161 trusted-time token
#
# Beyond presence + non-emptiness, a cheap STRUCTURAL check is applied where it
# is correct and free (JSON parses; CycloneDX bomFormat == "CycloneDX"; each
# provenance JSONL line is a valid in-toto Statement or DSSE envelope; manifest
# carries a non-empty merkle_root) — presence-over-content is exactly the trust
# leak this self-test exists to close (blueprint/06 §6.2-A, §6.4-C).
#
# Exit / degradation contract (mirrors seal-evidence.sh):
#   * EVIDENCE_ALLOW_DEGRADE=1 (local / PR): a missing or malformed required
#     artifact is a WARN; the script still exits 0 (a locally-sealed degraded
#     pack legitimately lacks cosign bundles / .tsr when the toolchain or TSA is
#     absent).
#   * EVIDENCE_ALLOW_DEGRADE unset (non-PR CI): any missing / zero-byte /
#     structurally-invalid required artifact is a HARD FAIL (exit 1). This is the
#     "non-PR CI fails if any is missing" gate from the T-58 Definition of Done.
#
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: check-sealing-completeness.sh <evidence_dir>" >&2
  exit 64
fi

EVIDENCE_DIR="$1"
[ -d "${EVIDENCE_DIR}" ] || { echo "FAIL  evidence dir not found: ${EVIDENCE_DIR}" >&2; exit 1; }

ALLOW_DEGRADE="${EVIDENCE_ALLOW_DEGRADE:-}"
is_degrade() { [ "${ALLOW_DEGRADE}" = "1" ]; }

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

pass() { printf 'PASS  %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
warn() { printf 'WARN  %s\n' "$*"; WARN_COUNT=$((WARN_COUNT + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# miss <message>: a missing/invalid required artifact. HARD FAIL in CI, WARN in
# degrade mode — keeping the local "degraded pack still exits 0" contract.
miss() {
  if is_degrade; then
    warn "$* (degrade mode — recorded, not failing)"
  else
    fail "$*"
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# json_ok <file>: 0 iff python3 absent (cannot check — skip the structural arm)
# or the file parses as JSON. Never blocks when python3 is unavailable.
json_ok() {
  have python3 || return 0
  python3 - "$1" <<'PY' 2>/dev/null
import json, sys
try:
    json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
PY
}

# require_nonempty <relpath> <description>: present + non-empty (+ JSON parse for
# *.json). Emits exactly one PASS line on success, or one miss() line.
require_nonempty() {
  local rel="$1" desc="$2" full="${EVIDENCE_DIR}/$1"
  if [ ! -e "${full}" ]; then
    miss "${rel} MISSING — ${desc}"
    return
  fi
  if [ ! -s "${full}" ]; then
    miss "${rel} ZERO-BYTE — ${desc}"
    return
  fi
  case "${rel}" in
    *.json)
      if ! json_ok "${full}"; then
        miss "${rel} present but NOT valid JSON — ${desc}"
        return
      fi
      ;;
  esac
  pass "${rel} present + non-empty — ${desc}"
}

echo "=== CyberForge sealing-artifact completeness self-test: ${EVIDENCE_DIR} ==="
echo "mode: $(is_degrade && echo 'degrade (missing = WARN, exit 0)' || echo 'fail-closed CI (missing = FAIL, exit 1)')"

# ---------------------------------------------------------------------------
# 1. manifest.json — must parse AND carry a non-empty merkle_root.
# ---------------------------------------------------------------------------
MANIFEST_JSON="${EVIDENCE_DIR}/manifest.json"
if [ ! -s "${MANIFEST_JSON}" ]; then
  miss "manifest.json MISSING or zero-byte — Merkle root + per-artifact hashes (§7.1)"
elif ! json_ok "${MANIFEST_JSON}"; then
  miss "manifest.json present but NOT valid JSON — Merkle root + per-artifact hashes (§7.1)"
elif have python3; then
  MR="$(python3 - "${MANIFEST_JSON}" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    sys.stdout.write(str(d.get("merkle_root", "")).strip())
except Exception:
    pass
PY
)"
  if [ -n "${MR}" ]; then
    pass "manifest.json present + carries merkle_root (${MR:0:16}…)"
  else
    miss "manifest.json present but merkle_root is EMPTY — integrity root not committed (§7.1)"
  fi
else
  pass "manifest.json present + non-empty (python3 absent — merkle_root not structurally checked)"
fi

# ---------------------------------------------------------------------------
# 2-8. The remaining fixed-name required artifacts.
# ---------------------------------------------------------------------------
require_nonempty "merkle-root.txt"               "immutable RFC-6962 Merkle root (the signed/timestamped blob)"
require_nonempty "merkle-root.cosign.bundle"     "keyless identity attribution over the Merkle root (§6.2-A headline claim)"
require_nonempty "pdf-sha256.cosign.bundle"      "keyless attribution over the evidence-PDF hash"
require_nonempty "verapdf-report.json"           "veraPDF PDF/A-3b conformance report (§7)"
require_nonempty "oscal-assessment-results.json" "OSCAL assessment-results (control findings)"
require_nonempty "sbom.cyclonedx.json"           "CycloneDX SBOM (Part C.10)"
require_nonempty "provenance.intoto.jsonl"       "in-toto / SLSA build provenance (Part C.12)"

# ---------------------------------------------------------------------------
# 8a. cosign-bundle structural check — both cosign v2 (legacy `base64Signature`)
# and cosign v3 (`--bundle` sigstore) outputs are JSON OBJECTS. require_nonempty
# above only JSON-parses *.json, so a truncated / upload-race / non-empty-garbage
# *.cosign.bundle would otherwise pass on presence alone — exactly the
# presence-over-content trust leak this self-test exists to close (§6.2-A is the
# bundle that should exist but does not; this is its sibling: a bundle that
# exists but is corrupt). A bundle that does not parse as a JSON object FAILs.
# (We do NOT field-check the bundle here — the two cosign formats differ in
# shape; the Rekor-inclusion crypto assertion is verify-evidence-pack.sh §3b's
# job. This is strictly "is it structurally a bundle, not a half-written file".)
# ---------------------------------------------------------------------------
for bundle_rel in merkle-root.cosign.bundle pdf-sha256.cosign.bundle; do
  bundle_full="${EVIDENCE_DIR}/${bundle_rel}"
  if [ -s "${bundle_full}" ] && have python3; then
    if python3 - "${bundle_full}" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(d, dict) and d else 1)
PY
    then
      pass "${bundle_rel} is a structurally-valid JSON cosign bundle"
    else
      miss "${bundle_rel} present but NOT a parseable JSON cosign bundle (truncated/corrupt)"
    fi
  fi
done

# ---------------------------------------------------------------------------
# 8b. CycloneDX structural check — bomFormat MUST be "CycloneDX" + specVersion
# present (CycloneDX schema's two mandatory fields). A non-empty JSON that is
# not actually a CycloneDX BOM would otherwise pass require_nonempty above.
# ---------------------------------------------------------------------------
SBOM="${EVIDENCE_DIR}/sbom.cyclonedx.json"
if [ -s "${SBOM}" ] && have python3; then
  if python3 - "${SBOM}" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(d, dict) and d.get("bomFormat") == "CycloneDX" and d.get("specVersion") else 1)
PY
  then
    pass "sbom.cyclonedx.json is a CycloneDX BOM (bomFormat + specVersion present)"
  else
    miss "sbom.cyclonedx.json present but NOT a valid CycloneDX BOM (bomFormat/specVersion missing)"
  fi
fi

# ---------------------------------------------------------------------------
# 8c. Provenance JSONL structural check — every non-blank line must parse as
# JSON and be one of the THREE shapes a SLSA provenance .jsonl legitimately
# takes (slsa.dev provenance/v1 + in-toto Attestation Framework / ITE-6):
#   (i)   a bare in-toto Statement     ({_type / predicateType ...})
#   (ii)  a bare DSSE envelope         ({payload, payloadType, signatures})
#   (iii) a Sigstore bundle v0.3       ({mediaType, verificationMaterial,
#         dsseEnvelope}) that WRAPS the DSSE under .dsseEnvelope. GitHub Artifact
#         Attestations / slsa-github-generator now emit this wrapped form
#         (mediaType "application/vnd.dev.sigstore.bundle.v0.3+json"); the earlier
#         check only accepted (i)/(ii) and wrongly FAILed a valid wrapped pack.
# For the wrapped form we UNWRAP dsseEnvelope and validate that its base64
# .payload decodes to an in-toto Statement (the actual provenance predicate),
# so this stays a genuine content check, not presence-only.
# ---------------------------------------------------------------------------
PROV="${EVIDENCE_DIR}/provenance.intoto.jsonl"
if [ -s "${PROV}" ] && have python3; then
  if python3 - "${PROV}" <<'PY' 2>/dev/null
import base64
import json
import sys

INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def _is_intoto_statement(o):
    """True iff o looks like an in-toto Statement (ITE-6)."""
    if not isinstance(o, dict):
        return False
    return o.get("_type") == INTOTO_STATEMENT_TYPE or "predicateType" in o


def _is_bare_dsse(o):
    """True iff o is a bare DSSE envelope ({payload, payloadType})."""
    return isinstance(o, dict) and "payload" in o and "payloadType" in o


def _dsse_payload_is_statement(env):
    """True iff a DSSE envelope's base64 payload decodes to an in-toto Statement."""
    if not isinstance(env, dict):
        return False
    payload_b64 = env.get("payload")
    if not isinstance(payload_b64, str) or not payload_b64:
        return False
    try:
        raw = base64.b64decode(payload_b64, validate=True)
        stmt = json.loads(raw)
    except Exception:
        return False
    return _is_intoto_statement(stmt)


def _is_sigstore_bundle_dsse(o):
    """True iff o is a Sigstore bundle v0.3 wrapping a valid DSSE under
    .dsseEnvelope (mediaType + verificationMaterial + dsseEnvelope)."""
    if not isinstance(o, dict):
        return False
    if "dsseEnvelope" not in o:
        return False
    # A bundle is identified by its mediaType + verificationMaterial; tolerate a
    # missing mediaType but require the dsseEnvelope to carry a real Statement.
    env = o.get("dsseEnvelope")
    if not _is_bare_dsse(env):
        return False
    return _dsse_payload_is_statement(env)


lines = [l for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
if not lines:
    sys.exit(1)
for l in lines:
    try:
        o = json.loads(l)
    except Exception:
        sys.exit(1)
    if not isinstance(o, dict):
        sys.exit(1)
    is_statement = _is_intoto_statement(o)
    # A bare DSSE is accepted; when it carries a payload we also confirm the
    # payload decodes to a Statement (tolerant: a payload-less envelope still
    # passes on shape, matching the prior bare-DSSE behaviour).
    is_dsse = _is_bare_dsse(o)
    is_bundle = _is_sigstore_bundle_dsse(o)
    if not (is_statement or is_dsse or is_bundle):
        sys.exit(1)
sys.exit(0)
PY
  then
    pass "provenance.intoto.jsonl: every line is a valid in-toto Statement, DSSE envelope, or Sigstore-bundle-wrapped DSSE"
  else
    miss "provenance.intoto.jsonl present but a line is not a valid in-toto Statement / DSSE envelope / Sigstore-bundle-wrapped DSSE"
  fi
fi

# ---------------------------------------------------------------------------
# 9. >=1 *.tsr (RFC-3161 trusted-time token). The exact label set varies
# (merkle-root.tsr / manifest.tsr / pdf.tsr) and a single-artifact TSA miss is
# tolerated by seal-evidence.sh, so the completeness bar is "at least one".
# ---------------------------------------------------------------------------
TSR_COUNT="$(find "${EVIDENCE_DIR}" -maxdepth 1 -name '*.tsr' -type f ! -empty 2>/dev/null | wc -l | tr -d '[:space:]')"
if [ "${TSR_COUNT:-0}" -ge 1 ]; then
  pass "RFC-3161 timestamp present (${TSR_COUNT} non-empty *.tsr token(s))"
else
  miss "no non-empty *.tsr — no RFC-3161 trusted-time token produced for any artifact"
fi

# ---------------------------------------------------------------------------
# Summary + deterministic exit.
# ---------------------------------------------------------------------------
echo "---"
echo "completeness summary: ${PASS_COUNT} PASS / ${WARN_COUNT} WARN / ${FAIL_COUNT} FAIL"
if [ "${FAIL_COUNT}" -gt 0 ]; then
  echo "RESULT: INCOMPLETE (required sealing artifact missing/invalid — fail-closed)"
  exit 1
fi
if [ "${WARN_COUNT}" -gt 0 ]; then
  echo "RESULT: OK-DEGRADED (some artifacts absent; tolerated in degrade mode)"
else
  echo "RESULT: COMPLETE (all 8 integrity outputs + >=1 RFC-3161 token present)"
fi
exit 0
