#!/usr/bin/env bash
#
# verify-evidence-pack.sh — the shipped + CI-run verification runbook for a
# sealed CyberForge evidence pack.
#
# Usage: verify-evidence-pack.sh <evidence_dir>
#
# Checks (each prints exactly one PASS / SKIP / FAIL line):
#   1. sha256sum -c the legacy manifest.sha256
#   2. recompute the RFC-6962 Merkle root and compare to manifest.merkle_root
#   3. cosign verify-blob (identity-pinned) if cosign + a .bundle are present
#   4. openssl ts -verify if a .tsr token is present
#   5. verapdf --flavour 3b if verapdf + the PDF are present
#   6. pdfsig whole-document-coverage if pdfsig + the PDF are present
#
# Exit policy: exit 0 only if NO check FAILs. SKIP (absent tool / absent input)
# is allowed and does not fail the run. A locally-sealed (degraded) pack — where
# only sha256 + Merkle can be checked — therefore exits 0.
#
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: verify-evidence-pack.sh <evidence_dir>" >&2
  exit 64
fi

EVIDENCE_DIR="$1"
[ -d "${EVIDENCE_DIR}" ] || { echo "FAIL  evidence dir not found: ${EVIDENCE_DIR}" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
MANIFEST_PY="${SCRIPT_DIR}/generate-evidence-manifest.py"
MANIFEST_JSON="${EVIDENCE_DIR}/manifest.json"
LEGACY_MANIFEST="${EVIDENCE_DIR}/manifest.sha256"

COSIGN_IDENTITY="${COSIGN_IDENTITY:-}"
COSIGN_ISSUER="${COSIGN_ISSUER:-}"

FAIL_COUNT=0
PASS_COUNT=0
SKIP_COUNT=0

pass() { printf 'PASS  %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
skip() { printf 'SKIP  %s\n' "$*"; SKIP_COUNT=$((SKIP_COUNT + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

have() { command -v "$1" >/dev/null 2>&1; }

echo "=== CyberForge evidence-pack verification: ${EVIDENCE_DIR} ==="

# ---------------------------------------------------------------------------
# 1. Legacy SHA-256 manifest
# ---------------------------------------------------------------------------
if [ -f "${LEGACY_MANIFEST}" ] && have sha256sum; then
  # manifest.sha256 lines are "<hash>  <relpath>"; verify from inside the dir.
  if ( cd "${EVIDENCE_DIR}" && sha256sum -c --quiet "$(basename "${LEGACY_MANIFEST}")" \
        >/dev/null 2>&1 ); then
    pass "sha256sum -c manifest.sha256 (all listed files match)"
  else
    # Re-run verbose to know whether it's a real mismatch vs missing files.
    if ( cd "${EVIDENCE_DIR}" && sha256sum -c "$(basename "${LEGACY_MANIFEST}")" \
          2>&1 | grep -q 'FAILED' ); then
      fail "sha256sum -c manifest.sha256 — one or more files FAILED checksum"
    else
      # Non-zero but no explicit FAILED line usually means a listed file is
      # absent (e.g. the manifest predates added files). Treat as FAIL only if
      # checksums mismatched; otherwise warn-pass is unsafe -> mark FAIL.
      fail "sha256sum -c manifest.sha256 — verification returned errors"
    fi
  fi
elif [ ! -f "${LEGACY_MANIFEST}" ]; then
  skip "sha256sum manifest check (manifest.sha256 absent)"
else
  skip "sha256sum manifest check (sha256sum absent)"
fi

# ---------------------------------------------------------------------------
# 2. Merkle root recomputation vs manifest.merkle_root
# ---------------------------------------------------------------------------
merkle_from_manifest() {
  python3 - "$MANIFEST_JSON" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    sys.stdout.write(str(d.get("merkle_root", "")))
except Exception:
    sys.stdout.write("")
PY
}

# Pure-stdlib RFC-6962 recomputation, used as the standalone fallback so verify
# works even if generate-evidence-manifest.py is unavailable. Excludes
# manifest.json itself (matching the generator's documented behavior).
merkle_recompute() {
  python3 - "$EVIDENCE_DIR" <<'PY' 2>/dev/null
import hashlib, os, sys
root_dir = sys.argv[1]
EXCLUDE = {"manifest.json"}
paths = []
for dirpath, _dirs, files in os.walk(root_dir):
    for f in files:
        full = os.path.join(dirpath, f)
        rel = os.path.relpath(full, root_dir)
        if rel in EXCLUDE:
            continue
        paths.append((rel, full))
paths.sort(key=lambda t: t[0])

def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()

def node_hash(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()

if not paths:
    sys.stdout.write(hashlib.sha256(b"").hexdigest())
    sys.exit(0)

level = []
for _rel, full in paths:
    with open(full, "rb") as fh:
        level.append(leaf_hash(fh.read()))

while len(level) > 1:
    nxt = []
    for i in range(0, len(level), 2):
        if i + 1 < len(level):
            nxt.append(node_hash(level[i], level[i + 1]))
        else:
            nxt.append(level[i])  # odd node promoted (RFC-6962)
    level = nxt
sys.stdout.write(level[0].hex())
PY
}

if [ -f "${MANIFEST_JSON}" ] && have python3; then
  EXPECTED="$(merkle_from_manifest)"
  if [ -z "${EXPECTED}" ]; then
    skip "Merkle root check (manifest.json has no merkle_root)"
  else
    RECOMPUTED=""
    USED_GENERATOR=0
    # Prefer the generator's --verify mode. It re-hashes every RECORDED artifact
    # (tamper check) and, on success, prints ONLY the bare recomputed root on
    # stdout (human status goes to stderr) and exits 0. We gate on its exit code
    # and capture that bare root.
    if [ -f "${MANIFEST_PY}" ]; then
      if RECOMPUTED="$(python3 "${MANIFEST_PY}" "${EVIDENCE_DIR}" --verify 2>/dev/null)"; then
        RECOMPUTED="$(printf '%s' "${RECOMPUTED}" | tr -d '[:space:]')"
        USED_GENERATOR=1
      else
        # Non-zero exit = integrity failure (missing/altered artifact or root mismatch).
        RECOMPUTED=""
      fi
    fi
    # Fallback to the in-script recomputation only if the generator was unusable.
    if [ "${USED_GENERATOR}" -eq 0 ] && [ -z "${RECOMPUTED}" ]; then
      RECOMPUTED="$(merkle_recompute | tr -d '[:space:]')"
    fi
    if [ -n "${RECOMPUTED}" ] && [ "${RECOMPUTED}" = "${EXPECTED}" ]; then
      if [ "${USED_GENERATOR}" -eq 1 ]; then
        pass "Merkle root matches manifest (RFC6962, via generate-evidence-manifest.py)"
      else
        pass "Merkle root matches manifest (RFC6962, recomputed in-runbook)"
      fi
    else
      fail "Merkle root MISMATCH (manifest=${EXPECTED:0:16}… recomputed=${RECOMPUTED:0:16}…)"
    fi
  fi
else
  skip "Merkle root check (manifest.json or python3 absent)"
fi

# ---------------------------------------------------------------------------
# 3. cosign verify-blob (identity-pinned)
# ---------------------------------------------------------------------------
verify_cosign_bundle() {
  # $1 = bundle, $2 = signed-data-file
  local bundle="$1" data="$2"
  local args=(verify-blob --bundle "${bundle}")
  if [ -n "${COSIGN_IDENTITY}" ]; then
    args+=(--certificate-identity "${COSIGN_IDENTITY}")
  fi
  if [ -n "${COSIGN_ISSUER}" ]; then
    args+=(--certificate-oidc-issuer "${COSIGN_ISSUER}")
  fi
  args+=("${data}")
  COSIGN_EXPERIMENTAL=1 cosign "${args[@]}" >/dev/null 2>&1
}

COSIGN_CHECKED=0
if have cosign; then
  # We sign the STABLE merkle-root.txt (not manifest.json, which receives a
  # signatures{} record after signing). The Merkle root commits to every
  # artifact, and the runbook independently recomputes + compares it above.
  MERKLE_BUNDLE="${EVIDENCE_DIR}/merkle-root.cosign.bundle"
  MERKLE_FILE="${EVIDENCE_DIR}/merkle-root.txt"
  if [ -f "${MERKLE_BUNDLE}" ] && [ -f "${MERKLE_FILE}" ]; then
    COSIGN_CHECKED=1
    if [ -z "${COSIGN_IDENTITY}" ] || [ -z "${COSIGN_ISSUER}" ]; then
      skip "cosign verify-blob merkle-root (identity/issuer not pinned — set COSIGN_IDENTITY & COSIGN_ISSUER)"
    elif verify_cosign_bundle "${MERKLE_BUNDLE}" "${MERKLE_FILE}"; then
      pass "cosign verify-blob merkle-root.txt (identity-pinned)"
    else
      fail "cosign verify-blob merkle-root.txt failed"
    fi
  fi
  PDF_BUNDLE="${EVIDENCE_DIR}/pdf-sha256.cosign.bundle"
  PDF_HASH_FILE="${EVIDENCE_DIR}/pdf.sha256"
  if [ -f "${PDF_BUNDLE}" ] && [ -f "${PDF_HASH_FILE}" ]; then
    COSIGN_CHECKED=1
    if [ -z "${COSIGN_IDENTITY}" ] || [ -z "${COSIGN_ISSUER}" ]; then
      skip "cosign verify-blob pdf-sha256 (identity/issuer not pinned)"
    elif verify_cosign_bundle "${PDF_BUNDLE}" "${PDF_HASH_FILE}"; then
      pass "cosign verify-blob pdf.sha256 (identity-pinned)"
    else
      fail "cosign verify-blob pdf.sha256 failed"
    fi
  fi
  if [ "${COSIGN_CHECKED}" -eq 0 ]; then
    skip "cosign verify-blob (no *.cosign.bundle present — pack signed in degrade mode)"
  fi
else
  skip "cosign verify-blob (cosign absent)"
fi

# ---------------------------------------------------------------------------
# 4. RFC-3161 token verification (openssl ts -verify)
# ---------------------------------------------------------------------------
TSR_FOUND=0
if have openssl; then
  # Map label -> data file used at stamping time.
  declare -A TSR_DATA=(
    ["merkle-root"]="${EVIDENCE_DIR}/merkle-root.txt"
    ["manifest"]="${MANIFEST_JSON}"
    ["pdf"]=""  # resolved below
  )
  # Resolve the pdf data file (any *.pdf in evidence dir).
  PDF_FILE="$(find "${EVIDENCE_DIR}" -maxdepth 1 -name '*.pdf' 2>/dev/null | head -n 1 || true)"
  TSR_DATA["pdf"]="${PDF_FILE}"

  for label in merkle-root manifest pdf; do
    tsr="${EVIDENCE_DIR}/${label}.tsr"
    data="${TSR_DATA[$label]}"
    if [ -f "${tsr}" ]; then
      TSR_FOUND=1
      if [ -z "${data}" ] || [ ! -f "${data}" ]; then
        skip "openssl ts -verify ${label} (.tsr present but data file missing)"
        continue
      fi
      # Need the TSA CA chain to fully verify; without it we can at least parse.
      CAFILE="${EVIDENCE_DIR}/tsa-ca.pem"
      if [ -f "${CAFILE}" ]; then
        if openssl ts -verify -data "${data}" -in "${tsr}" -CAfile "${CAFILE}" \
              >/dev/null 2>&1; then
          pass "openssl ts -verify ${label} (token valid against TSA CA)"
        else
          fail "openssl ts -verify ${label} failed against TSA CA"
        fi
      else
        # Parse-only sanity check (no CA chain shipped).
        if openssl ts -reply -in "${tsr}" -text >/dev/null 2>&1; then
          skip "openssl ts -verify ${label} (token parses; tsa-ca.pem absent for full verify)"
        else
          fail "RFC-3161 token ${label} is malformed"
        fi
      fi
    fi
  done
  if [ "${TSR_FOUND}" -eq 0 ]; then
    skip "RFC-3161 timestamp verify (no *.tsr present — TSA unavailable at seal time)"
  fi
else
  skip "RFC-3161 timestamp verify (openssl absent)"
fi

# ---------------------------------------------------------------------------
# 5 + 6. PDF/A validation + signature coverage (need the PDF)
# ---------------------------------------------------------------------------
PDF_FILE="${PDF_FILE:-$(find "${EVIDENCE_DIR}" -maxdepth 1 -name '*.pdf' 2>/dev/null | head -n 1 || true)}"

if [ -n "${PDF_FILE}" ] && [ -f "${PDF_FILE}" ]; then
  # 5. veraPDF
  if have verapdf; then
    if verapdf --flavour 3b --format text "${PDF_FILE}" >/dev/null 2>&1; then
      pass "verapdf --flavour 3b ($(basename "${PDF_FILE}") is PDF/A-3b conformant)"
    else
      fail "verapdf --flavour 3b — $(basename "${PDF_FILE}") NOT PDF/A-3b conformant"
    fi
  else
    skip "verapdf PDF/A validation (verapdf absent)"
  fi

  # 6. pdfsig whole-document coverage
  if have pdfsig; then
    PDFSIG_OUT="$(pdfsig "${PDF_FILE}" 2>&1 || true)"
    if printf '%s' "${PDFSIG_OUT}" | grep -qi 'does not contain any signatures\|No signatures'; then
      skip "pdfsig coverage (PDF carries no PAdES signature — external cosign+RFC3161 is authoritative)"
    elif printf '%s' "${PDFSIG_OUT}" | grep -qi 'total document is signed\|covers the whole'; then
      pass "pdfsig — signature covers the whole document"
    elif printf '%s' "${PDFSIG_OUT}" | grep -qi 'Signature'; then
      # Signature present but coverage line not the expected phrase.
      if printf '%s' "${PDFSIG_OUT}" | grep -qi 'not been modified\|valid'; then
        pass "pdfsig — signature present and validates"
      else
        fail "pdfsig — signature present but does NOT cover the whole document"
      fi
    else
      skip "pdfsig coverage (no signature information available)"
    fi
  else
    skip "pdfsig coverage (pdfsig absent)"
  fi
else
  skip "verapdf PDF/A validation (no PDF in pack — render degraded)"
  skip "pdfsig coverage (no PDF in pack — render degraded)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "---"
echo "verify summary: ${PASS_COUNT} PASS / ${SKIP_COUNT} SKIP / ${FAIL_COUNT} FAIL"
if [ "${FAIL_COUNT}" -gt 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: OK (no FAILs; SKIP allowed for absent tools)"
exit 0
