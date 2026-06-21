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
#   3b. Rekor transparency-log INCLUSION proof per cosign bundle (spec §7.2/I.2)
#   4. openssl ts -verify if a .tsr token is present
#   5. verapdf --flavour 3b if verapdf + the PDF are present
#   6. pdfsig whole-document-coverage if pdfsig + the PDF are present
#   7. sealing-artifact completeness self-test (all 8 integrity outputs +
#      >=1 RFC-3161 token landed) via check-sealing-completeness.sh (spec §12).
#
# Exit policy: exit 0 only if NO check FAILs. SKIP (absent tool / absent input)
# is allowed and does not fail the run. A locally-sealed (degraded) pack — where
# only sha256 + Merkle can be checked — therefore exits 0. The §7 completeness
# self-test honours the same EVIDENCE_ALLOW_DEGRADE contract: in degrade mode a
# missing sealing artifact is reported but does not fail; in fail-closed CI mode
# a missing required artifact FAILs the runbook (matching seal-evidence.sh).
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
COMPLETENESS_SH="${SCRIPT_DIR}/check-sealing-completeness.sh"
MANIFEST_JSON="${EVIDENCE_DIR}/manifest.json"
LEGACY_MANIFEST="${EVIDENCE_DIR}/manifest.sha256"

COSIGN_IDENTITY="${COSIGN_IDENTITY:-}"
COSIGN_ISSUER="${COSIGN_ISSUER:-}"
# A10-1: a pack sealed in DECLARED degrade mode (EVIDENCE_ALLOW_DEGRADE=1, e.g. the
# committed offline sample pack built without keyless cosign) legitimately has no
# cosign bundle. In that explicit mode the §6.2-A "bundle missing" condition is a
# SKIP, not a FAIL. STRICT release verification (the default — env UNSET) keeps the
# §6.2-A anti-regression FAIL so a real release pack that lost its headline bundle
# is still rejected.
ALLOW_DEGRADE="${EVIDENCE_ALLOW_DEGRADE:-}"

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
  elif [ -f "${MERKLE_FILE}" ]; then
    # A Merkle root exists to sign but its cosign bundle is absent: the pack's
    # headline cryptographic claim is missing. In STRICT mode this is the §6.2-A
    # regression surface — fail explicitly rather than silently skip. In DECLARED
    # degrade mode (EVIDENCE_ALLOW_DEGRADE=1) the absence is expected (offline
    # sample pack with no keyless cosign) and is a SKIP.
    COSIGN_CHECKED=1
    if [ "${ALLOW_DEGRADE}" = "1" ]; then
      skip "cosign verify-blob merkle-root — bundle absent; DECLARED degrade pack (EVIDENCE_ALLOW_DEGRADE=1). Strict release verify (unset env) treats this as §6.2-A FAIL."
    else
      fail "cosign verify-blob merkle-root — merkle-root.cosign.bundle missing while merkle-root.txt present (§6.2-A)"
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
# 3b. Rekor transparency-log INCLUSION verification (spec §7.2 #2 / Part I.2).
#
# The §3 cosign verify-blob above does cryptographically check the embedded
# Rekor SET as part of its default tlog verification — but it emits no explicit
# Rekor line, so the "Rekor-verifiable" / "signatures recorded in an append-only
# log" claim is never *proven in the deliverable*. Worse, CVE-2022-36056
# (GHSA-8gw7-4j42-w388) showed a crafted bundle could pass verify-blob while its
# rekorBundle did not actually reference the signature. So we assert Rekor
# inclusion in TWO independent ways and emit one PASS/FAIL line per bundle:
#
#   (a) STRUCTURAL — parse the bundle JSON and confirm it carries a real Rekor
#       transparency-log entry (a logIndex AND integratedTime). Handles BOTH the
#       legacy cosign-v2 `rekorBundle.Payload{logIndex,integratedTime,logID}`
#       shape AND the cosign-v3 sigstore-bundle `verificationMaterial.
#       tlogEntries[]{logIndex,integratedTime,inclusionPromise|inclusionProof}`
#       shape (the two formats seal-evidence.sh's Step-3 comment calls out).
#       A bundle with NO tlog entry (e.g. tampered, or signed with
#       --no-tlog-upload) FAILS here — that is the tampered-bundle acceptance
#       case.
#   (b) CRYPTOGRAPHIC — when identity+issuer are pinned, re-run cosign
#       verify-blob with tlog verification explicitly REQUIRED
#       (--insecure-ignore-tlog=false). This validates the Rekor SET/inclusion
#       against the log's public key (offline via the stapled proof, or against
#       --rekor-url when reachable). If cosign supports an --offline flag we add
#       it so the assertion does not silently fall back to a network query.
#
# We FAIL the Rekor line only when a bundle exists but cannot be shown to be in
# Rekor; absence of any bundle (degrade-mode pack) is a SKIP, matching §3.
# ---------------------------------------------------------------------------

# rekor_entry_present <bundle.json> : exit 0 iff the bundle carries a Rekor tlog
# entry with both a logIndex and an integratedTime (>0). Prints "<logIndex>" on
# success for the human-readable line. Pure stdlib; tolerant of both formats.
rekor_entry_present() {
  python3 - "$1" <<'PY' 2>/dev/null
import json, sys
try:
    b = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(2)

def _int(v):
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return None

# (1) legacy cosign-v2 bundle: top-level rekorBundle.Payload{logIndex,integratedTime}
rb = b.get("rekorBundle") if isinstance(b, dict) else None
if isinstance(rb, dict):
    p = rb.get("Payload", rb.get("payload", {}))
    if isinstance(p, dict):
        li, it = _int(p.get("logIndex")), _int(p.get("integratedTime"))
        if li is not None and li >= 0 and it is not None and it > 0:
            sys.stdout.write(str(li)); sys.exit(0)

# (2) new sigstore bundle: verificationMaterial.tlogEntries[]{logIndex,integratedTime}
vm = b.get("verificationMaterial") if isinstance(b, dict) else None
if isinstance(vm, dict):
    for e in (vm.get("tlogEntries") or []):
        if not isinstance(e, dict):
            continue
        li, it = _int(e.get("logIndex")), _int(e.get("integratedTime"))
        has_proof = bool(e.get("inclusionProof") or e.get("inclusionPromise"))
        if li is not None and li >= 0 and it is not None and it > 0 and has_proof:
            sys.stdout.write(str(li)); sys.exit(0)

sys.exit(1)
PY
}

# cosign_rekor_verify <bundle> <data> : cryptographic tlog-required re-verify.
# Returns 0 on success. tlog verification is cosign's default, but we make it
# explicit and refuse the network fallback so a missing Rekor entry cannot be
# masked by an online query that silently succeeds.
COSIGN_HAS_OFFLINE=0
if have cosign && cosign verify-blob --help 2>&1 | grep -q -- '--offline'; then
  COSIGN_HAS_OFFLINE=1
fi
cosign_rekor_verify() {
  local bundle="$1" data="$2"
  local args=(verify-blob --bundle "${bundle}" --insecure-ignore-tlog=false)
  [ "${COSIGN_HAS_OFFLINE}" -eq 1 ] && args+=(--offline=true)
  [ -n "${COSIGN_IDENTITY}" ] && args+=(--certificate-identity "${COSIGN_IDENTITY}")
  [ -n "${COSIGN_ISSUER}" ]   && args+=(--certificate-oidc-issuer "${COSIGN_ISSUER}")
  args+=("${data}")
  COSIGN_EXPERIMENTAL=1 cosign "${args[@]}" >/dev/null 2>&1
}

# rekor_check <label> <bundle> <data> : emit one PASS/FAIL line per bundle.
rekor_check() {
  local label="$1" bundle="$2" data="$3"
  [ -f "${bundle}" ] || return 0   # absent bundle handled by §3 skip logic
  REKOR_ANY=1
  if ! have python3; then
    skip "Rekor inclusion ${label} (python3 absent — cannot parse bundle)"
    return 0
  fi
  local logidx
  if ! logidx="$(rekor_entry_present "${bundle}")"; then
    fail "Rekor inclusion ${label} — bundle carries NO transparency-log entry (not Rekor-logged / tampered)"
    return 0
  fi
  # Structural proof present. Add the cryptographic re-verify when we can pin
  # identity AND have the signed data file (offline stapled-proof validation).
  if have cosign && [ -f "${data}" ] && [ -n "${COSIGN_IDENTITY}" ] && [ -n "${COSIGN_ISSUER}" ]; then
    if cosign_rekor_verify "${bundle}" "${data}"; then
      pass "Rekor inclusion ${label} verified (logIndex=${logidx}; SET/inclusion-proof cryptographically validated)"
    else
      fail "Rekor inclusion ${label} — bundle has a tlog entry (logIndex=${logidx}) but cosign tlog verification FAILED"
    fi
  else
    # No identity pinning or cosign absent: the structural inclusion proof still
    # demonstrates the signature was logged to Rekor; flag the weaker assurance.
    pass "Rekor inclusion ${label} present (logIndex=${logidx}; structural — pin COSIGN_IDENTITY/ISSUER + cosign for crypto re-verify)"
  fi
}

REKOR_ANY=0
if have python3 || have cosign; then
  rekor_check "merkle-root" "${EVIDENCE_DIR}/merkle-root.cosign.bundle" "${EVIDENCE_DIR}/merkle-root.txt"
  rekor_check "pdf-sha256"  "${EVIDENCE_DIR}/pdf-sha256.cosign.bundle"  "${EVIDENCE_DIR}/pdf.sha256"
  if [ "${REKOR_ANY}" -eq 0 ]; then
    skip "Rekor inclusion verify (no *.cosign.bundle present — pack signed in degrade mode)"
  fi
else
  skip "Rekor inclusion verify (python3 and cosign both absent)"
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
        # Parse-only sanity check (no CA chain shipped). Beyond "does it DER-
        # decode", confirm the TSA GRANTED the token — a rejection or a non-token
        # body that somehow landed as .tsr must FAIL, not pass as "parses".
        # (Mirrors seal-evidence.sh's tsr_is_valid_token granted-status gate.)
        if openssl ts -reply -in "${tsr}" -text 2>/dev/null | grep -qi 'Status: *Granted'; then
          skip "openssl ts -verify ${label} (token parses + granted; tsa-ca.pem absent for full verify)"
        else
          fail "RFC-3161 token ${label} is malformed or not granted"
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
# 7. Sealing-artifact completeness self-test (spec §12; T-58).
#
# The §1-6 checks each verify ONE integrity property of whatever artifacts
# happen to be present — they say nothing about whether the FULL integrity-chain
# artifact set was actually emitted. §6.2-A was exactly a "silently absent
# artifact" bug. So we delegate to check-sealing-completeness.sh, which asserts
# all 8 sealing outputs (+ >=1 RFC-3161 .tsr) exist, are non-empty, and parse.
# It honours EVIDENCE_ALLOW_DEGRADE itself (degrade -> exit 0 with WARNs;
# fail-closed CI -> exit 1 on any missing required artifact), so we simply
# surface its result as one PASS/SKIP/FAIL line, preserving this runbook's
# "degraded local pack still exits 0" contract.
# ---------------------------------------------------------------------------
if [ -x "${COMPLETENESS_SH}" ] || [ -f "${COMPLETENESS_SH}" ]; then
  if bash "${COMPLETENESS_SH}" "${EVIDENCE_DIR}" >/dev/null 2>&1; then
    pass "sealing-artifact completeness (all required integrity outputs present, or degrade-tolerated)"
  else
    fail "sealing-artifact completeness — a required integrity output is missing/invalid (run check-sealing-completeness.sh for detail)"
  fi
else
  skip "sealing-artifact completeness self-test (check-sealing-completeness.sh not found alongside this runbook)"
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
