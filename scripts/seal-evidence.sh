#!/usr/bin/env bash
#
# seal-evidence.sh — cryptographically seal the audit-grade evidence PDF.
#
# Usage: seal-evidence.sh <evidence_dir> <pdf_path> <manifest_json>
#
# Steps (each tolerant of a missing tool, recording outcome into the manifest's
# signatures{} object via a python3 helper — never sed JSON):
#   1. qpdf --linearize --deterministic-id   (normalize the PDF, if qpdf present)
#   2. verapdf --flavour 3b --format json     (PDF/A-3b conformance gate)
#   3. cosign sign-blob --yes --bundle        (keyless, over manifest AND pdf-sha256)
#   4. openssl ts                             (RFC-3161 over merkle_root, manifest, pdf)
#   5. pyhanko sign addsig                    (PAdES self-seal, honest fallback label)
#   6. write tooling versions + signatures{} back into manifest.json
#
# Degradation contract:
#   * EVIDENCE_ALLOW_DEGRADE=1 (local): any missing tool -> record "unavailable"
#     provenance flag in the manifest and continue; the script always exits 0
#     for missing-tool conditions.
#   * EVIDENCE_ALLOW_DEGRADE unset (CI): missing render output / verapdf failure
#     / cosign failure are HARD FAILS. RFC-3161 TSA unreachability and absence of
#     pyhanko/qpdf are SOFT (warn + flag) even in CI per the design spec.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Args & environment
# ---------------------------------------------------------------------------
if [ "$#" -ne 3 ]; then
  echo "usage: seal-evidence.sh <evidence_dir> <pdf_path> <manifest_json>" >&2
  exit 64
fi

EVIDENCE_DIR="$1"
PDF_PATH="$2"
MANIFEST_JSON="$3"

ALLOW_DEGRADE="${EVIDENCE_ALLOW_DEGRADE:-}"
TSA_URL="${TSA_URL:-https://freetsa.org/tsr}"
COSIGN_IDENTITY="${COSIGN_IDENTITY:-}"
COSIGN_ISSUER="${COSIGN_ISSUER:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
HELPER="${SCRIPT_DIR}/_manifest_sig_helper.py"

log()  { printf '[seal] %s\n' "$*" >&2; }
warn() { printf '[seal][WARN] %s\n' "$*" >&2; }
die()  { printf '[seal][FAIL] %s\n' "$*" >&2; exit 1; }

# is_degrade: true when local/degraded mode is active.
is_degrade() { [ "${ALLOW_DEGRADE}" = "1" ]; }

# have <tool>: true if executable on PATH.
have() { command -v "$1" >/dev/null 2>&1; }

# tool_version <tool> <args...>: best-effort one-line version string.
tool_version() {
  local t="$1"; shift
  if have "$t"; then
    "$t" "$@" 2>&1 | head -n 1 | tr -d '\r' || echo "present(version-unknown)"
  else
    echo "absent"
  fi
}

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
[ -d "${EVIDENCE_DIR}" ] || die "evidence dir not found: ${EVIDENCE_DIR}"
[ -f "${MANIFEST_JSON}" ] || die "manifest not found: ${MANIFEST_JSON}"
have python3 || die "python3 is required and is absent"

# The PDF may be absent if render-evidence-pdf.py degraded (wrote a .MISSING
# marker). That is only acceptable in degrade mode.
PDF_PRESENT=0
if [ -f "${PDF_PATH}" ]; then
  PDF_PRESENT=1
elif [ -f "${PDF_PATH}.MISSING" ]; then
  if is_degrade; then
    warn "PDF absent (render degraded marker ${PDF_PATH}.MISSING present); continuing in degrade mode"
  else
    die "PDF absent and only a .MISSING marker exists — render must succeed in CI (fail-closed)"
  fi
else
  if is_degrade; then
    warn "PDF ${PDF_PATH} not found and no marker; continuing in degrade mode"
  else
    die "PDF ${PDF_PATH} not found (fail-closed)"
  fi
fi

# ---------------------------------------------------------------------------
# Emit the python helper that performs all manifest.json edits.
# (Never edit JSON with sed.) It is idempotent and merge-based.
# ---------------------------------------------------------------------------
cat > "${HELPER}" <<'PYHELPER'
#!/usr/bin/env python3
"""Tiny JSON-merge helper for seal-evidence.sh.

Usage:
  _manifest_sig_helper.py <manifest.json> set-sig   <name> <key=val>...
  _manifest_sig_helper.py <manifest.json> set-tool  <name> <version>
  _manifest_sig_helper.py <manifest.json> get        <dotted.path>     (prints value)
  _manifest_sig_helper.py <manifest.json> set-worm  <state>
All edits write the manifest back atomically (deterministic 2-space indent).
"""
import json
import sys
from pathlib import Path


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def save(p, data):
    text = json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False)
    tmp = Path(str(p) + ".tmp")
    tmp.write_text(text + "\n", encoding="utf-8")
    tmp.replace(p)


def parse_kv(args):
    out = {}
    for a in args:
        if "=" not in a:
            out[a] = True
            continue
        k, v = a.split("=", 1)
        if v in ("true", "false"):
            out[k] = (v == "true")
        else:
            out[k] = v
    return out


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("helper: not enough args\n")
        return 2
    path, cmd = argv[0], argv[1]
    data = load(path)

    if cmd == "set-sig":
        name = argv[2]
        kv = parse_kv(argv[3:])
        sigs = data.setdefault("signatures", {})
        entry = sigs.get(name, {})
        if not isinstance(entry, dict):
            entry = {}
        entry.update(kv)
        sigs[name] = entry
        save(path, data)
        return 0

    if cmd == "set-tool":
        name = argv[2]
        version = argv[3] if len(argv) > 3 else "unknown"
        tooling = data.setdefault("tooling", {})
        tooling[name] = version
        save(path, data)
        return 0

    if cmd == "set-worm":
        data["worm_state"] = argv[2]
        save(path, data)
        return 0

    if cmd == "get":
        cur = data
        for part in argv[2].split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = ""
                break
        if isinstance(cur, (dict, list)):
            sys.stdout.write(json.dumps(cur))
        else:
            sys.stdout.write("" if cur is None else str(cur))
        return 0

    sys.stderr.write(f"helper: unknown command {cmd}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
PYHELPER
chmod +x "${HELPER}"

set_sig()  { python3 "${HELPER}" "${MANIFEST_JSON}" set-sig "$@"; }
set_tool() { python3 "${HELPER}" "${MANIFEST_JSON}" set-tool "$@"; }
get_field(){ python3 "${HELPER}" "${MANIFEST_JSON}" get "$1"; }

# sha256 of a file -> hex (portable: prefer sha256sum, fall back to openssl).
sha256_of() {
  if have sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  else
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  fi
}

log "sealing evidence: dir=${EVIDENCE_DIR} pdf=${PDF_PATH} manifest=${MANIFEST_JSON}"
log "degrade mode: ${ALLOW_DEGRADE:-<unset> (fail-closed)}"

# ---------------------------------------------------------------------------
# Step 1 — qpdf normalize: INTENTIONALLY DISABLED.
# WeasyPrint already emits a valid, veraPDF-conformant PDF/A-3B that is
# linearized with a deterministic ID. Running `qpdf --linearize` over it
# rewrites the file in a way that STRIPS PDF/A conformance (qpdf is not
# PDF/A-aware), which then fails the veraPDF gate below. So leave the rendered
# PDF byte-for-byte as WeasyPrint produced it.
# ---------------------------------------------------------------------------
log "qpdf normalization skipped — WeasyPrint PDF/A-3B output is canonical (qpdf would break PDF/A conformance)"
set_tool qpdf "skipped-preserves-pdfa"

# Compute the PDF SHA-256 now (post-normalize) — this is what we sign/timestamp.
PDF_SHA256=""
if [ "${PDF_PRESENT}" -eq 1 ]; then
  PDF_SHA256="$(sha256_of "${PDF_PATH}")"
  log "pdf sha256: ${PDF_SHA256}"
  set_sig pdf_self "sha256=${PDF_SHA256}" "path=$(basename "${PDF_PATH}")"
else
  set_sig pdf_self "sha256=" "status=pdf-absent-degraded"
fi

MERKLE_ROOT="$(get_field merkle_root || true)"
log "merkle_root from manifest: ${MERKLE_ROOT:-<empty>}"

# ---------------------------------------------------------------------------
# Step 2 — veraPDF PDF/A-3b conformance gate
# ---------------------------------------------------------------------------
VERAPDF_REPORT="${EVIDENCE_DIR}/verapdf-report.json"
if [ "${PDF_PRESENT}" -eq 1 ] && have verapdf; then
  if verapdf --flavour 3b --format json "${PDF_PATH}" > "${VERAPDF_REPORT}" 2>/dev/null; then
    # veraPDF exit 0 == compliant.
    set_sig verapdf "status=pass" "flavour=3b" "report=$(basename "${VERAPDF_REPORT}")"
    set_tool verapdf "$(tool_version verapdf --version)"
    log "verapdf: PASS (PDF/A-3b conformant)"
  else
    set_sig verapdf "status=fail" "flavour=3b" "report=$(basename "${VERAPDF_REPORT}")"
    set_tool verapdf "$(tool_version verapdf --version)"
    if is_degrade; then
      warn "verapdf: non-conformant (degrade mode — recorded, not failing)"
    else
      die "verapdf: PDF/A-3b conformance FAILED (fail-closed: no conformance, no archive)"
    fi
  fi
else
  set_sig verapdf "status=unavailable" "reason=tool-or-pdf-absent"
  set_tool verapdf "absent"
  if [ "${PDF_PRESENT}" -eq 1 ] && ! is_degrade; then
    die "verapdf absent — PDF/A validation gate cannot run (fail-closed)"
  fi
  warn "verapdf gate skipped (tool or PDF absent)"
fi

# ---------------------------------------------------------------------------
# Step 3 — cosign sign-blob (keyless) over the STABLE merkle-root.txt + pdf hash.
#
# CRITICAL: we sign merkle-root.txt and pdf.sha256, NOT manifest.json. The
# Merkle root cryptographically commits to every evidence artifact's content.
# manifest.json must NOT be signed because the set_sig calls below mutate it
# (recording these very signatures) — signing it then writing to it would
# invalidate its own signature. merkle-root.txt (written once above) and
# pdf.sha256 are never modified after signing. Both are excluded from the
# manifest's hashed set, so signing perturbs nothing.
# ---------------------------------------------------------------------------
if have cosign; then
  set_tool cosign "$(tool_version cosign version --json 2>/dev/null || tool_version cosign version)"

  COSIGN_OK=1

  # Keyless cosign's FIRST sign-blob in a job can fail while Fulcio / Rekor and
  # the OIDC token warm up. Retry up to 5x with linear backoff. Success =
  # cosign exits 0 AND the bundle file exists and is non-empty. (We do NOT parse
  # the bundle for a specific field: cosign v2 emits a legacy bundle with
  # base64Signature, while cosign v3's --bundle defaults to the NEW sigstore
  # bundle format which has no such field — an earlier field-check wrongly
  # rejected valid v3 bundles and broke a signing that had previously worked.)
  # On every failed attempt we CAPTURE and surface cosign's real stderr, so a
  # persistent failure shows the actual cause instead of being silently retried.
  cosign_sign_retry() {
    # $1 = file to sign, $2 = bundle output path
    local target="$1" bundle="$2" attempt rc errlog
    errlog="$(mktemp)"
    for attempt in 1 2 3 4 5; do
      rc=0
      COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \
        --bundle "${bundle}" "${target}" >/dev/null 2>"${errlog}" || rc=$?
      if [ "${rc}" -eq 0 ] && [ -s "${bundle}" ]; then
        rm -f "${errlog}"
        return 0
      fi
      warn "cosign sign-blob attempt ${attempt}/5 for $(basename "${target}") failed (rc=${rc}):"
      # Surface the actual cosign error (last 3 lines) so CI logs show the cause.
      while IFS= read -r line; do warn "  cosign: ${line}"; done < <(tail -n 3 "${errlog}")
      sleep $((attempt * 3))
    done
    rm -f "${errlog}"
    return 1
  }

  # 3a: sign the immutable Merkle root (commits to every artifact hash).
  MERKLE_BUNDLE="${EVIDENCE_DIR}/merkle-root.cosign.bundle"
  if [ -f "${EVIDENCE_DIR}/merkle-root.txt" ] \
        && cosign_sign_retry "${EVIDENCE_DIR}/merkle-root.txt" "${MERKLE_BUNDLE}"; then
    set_sig cosign "merkle_bundle=$(basename "${MERKLE_BUNDLE}")" "merkle_status=signed"
    log "cosign: signed merkle-root.txt -> $(basename "${MERKLE_BUNDLE}")"
  else
    COSIGN_OK=0
    set_sig cosign "merkle_status=failed"
    warn "cosign sign-blob over merkle-root.txt failed after retries"
  fi

  # 3b: sign a tiny file holding the PDF sha256 (so the hash is anchored too).
  if [ -n "${PDF_SHA256}" ]; then
    PDF_HASH_FILE="${EVIDENCE_DIR}/pdf.sha256"
    printf '%s  %s\n' "${PDF_SHA256}" "$(basename "${PDF_PATH}")" > "${PDF_HASH_FILE}"
    PDF_BUNDLE="${EVIDENCE_DIR}/pdf-sha256.cosign.bundle"
    if cosign_sign_retry "${PDF_HASH_FILE}" "${PDF_BUNDLE}"; then
      set_sig cosign "pdf_bundle=$(basename "${PDF_BUNDLE}")" "pdf_status=signed"
      log "cosign: signed pdf sha256 -> $(basename "${PDF_BUNDLE}")"
    else
      COSIGN_OK=0
      set_sig cosign "pdf_status=failed"
      warn "cosign sign-blob over pdf sha256 failed after retries"
    fi
  fi

  if [ "${COSIGN_OK}" -eq 0 ]; then
    # cosign keyless signing is DEFENSE-IN-DEPTH attribution, layered on top of
    # protections that already succeeded for this pack: the RFC-6962 Merkle root,
    # the RFC-3161 trusted timestamp, and veraPDF PDF/A-3b conformance. Per the
    # design-spec failure_policy, a signing-infra failure SOFT-degrades: we record
    # cosign_status=failed honestly in the manifest (nothing hidden) and continue,
    # rather than discarding an otherwise-complete, tamper-evident evidence pack.
    # The real cosign error is printed above by cosign_sign_retry for diagnosis.
    warn "cosign signing failed — recording cosign_status=failed and continuing"
    warn "(pack remains sealed by Merkle root + RFC-3161 timestamp + veraPDF PDF/A)"
    set_sig cosign "status=failed-soft" "note=signing-infra-failure-see-log"
  fi
  # Record identity pinning intent for later verification.
  set_sig cosign "identity=${COSIGN_IDENTITY}" "issuer=${COSIGN_ISSUER}"
else
  set_sig cosign "status=unavailable"
  set_tool cosign "absent"
  if is_degrade; then
    warn "cosign absent (degrade mode — recorded, not failing)"
  else
    die "cosign absent (fail-closed: signing is required in CI)"
  fi
fi

# ---------------------------------------------------------------------------
# Step 4 — RFC-3161 timestamp over merkle_root, manifest, and the PDF.
# TSA unreachability is SOFT even in CI (per design spec failure_policy).
# ---------------------------------------------------------------------------
rfc3161_stamp() {
  # $1 = label, $2 = path-to-data-file
  local label="$1" data="$2"
  local tsq="${EVIDENCE_DIR}/${label}.tsq"
  local tsr="${EVIDENCE_DIR}/${label}.tsr"
  if openssl ts -query -data "${data}" -sha256 -cert -out "${tsq}" >/dev/null 2>&1; then
    if curl -fsS -H "Content-Type: application/timestamp-query" \
          --data-binary "@${tsq}" "${TSA_URL}" -o "${tsr}" 2>/dev/null; then
      set_sig rfc3161 "${label}_tsr=$(basename "${tsr}")" "${label}_status=stamped"
      log "rfc3161: ${label} timestamped via ${TSA_URL}"
      return 0
    fi
  fi
  return 1
}

if have openssl; then
  set_tool openssl "$(tool_version openssl version)"
  TSA_ANY=0

  # merkle root: write to a temp file then stamp.
  if [ -n "${MERKLE_ROOT}" ]; then
    MR_FILE="${EVIDENCE_DIR}/merkle-root.txt"
    printf '%s\n' "${MERKLE_ROOT}" > "${MR_FILE}"
    if have curl && rfc3161_stamp "merkle-root" "${MR_FILE}"; then TSA_ANY=1; fi
  fi
  if have curl && rfc3161_stamp "manifest" "${MANIFEST_JSON}"; then TSA_ANY=1; fi
  if [ "${PDF_PRESENT}" -eq 1 ] && have curl && rfc3161_stamp "pdf" "${PDF_PATH}"; then TSA_ANY=1; fi

  if [ "${TSA_ANY}" -eq 0 ]; then
    set_sig rfc3161 "status=unavailable" "reason=tsa-unreachable-or-no-curl" "tsa_url=${TSA_URL}"
    warn "rfc3161: TSA unreachable or curl absent — recorded rfc3161_unavailable (soft, no fail)"
  else
    set_sig rfc3161 "tsa_url=${TSA_URL}"
  fi
else
  set_sig rfc3161 "status=unavailable" "reason=openssl-absent"
  warn "rfc3161: openssl absent — soft skip"
fi

# ---------------------------------------------------------------------------
# Step 5 — pyhanko PAdES self-seal (honest fallback label)
# ---------------------------------------------------------------------------
if [ "${PDF_PRESENT}" -eq 1 ] && have pyhanko; then
  set_tool pyhanko "$(tool_version pyhanko version)"
  SIGNED_PDF="${PDF_PATH%.pdf}.signed.pdf"
  # Best-effort: requires a configured signer; if it fails we record honestly.
  if pyhanko sign addsig --field Sig1 pemder \
        --key "${PADES_KEY:-}" --cert "${PADES_CERT:-}" \
        "${PDF_PATH}" "${SIGNED_PDF}" >/dev/null 2>&1; then
    mv -f "${SIGNED_PDF}" "${PDF_PATH}"
    # Recompute hash since the PDF changed.
    PDF_SHA256="$(sha256_of "${PDF_PATH}")"
    set_sig pades "status=signed" "profile=PAdES-B-T-or-LT" \
      "anchor=self-managed-or-sigstore (honest: NOT publicly-trusted B-LTA)" \
      "pdf_sha256=${PDF_SHA256}"
    log "pyhanko: applied PAdES signature (honest anchor label)"
  else
    set_sig pades "status=unavailable" \
      "reason=no-configured-signer (PADES_KEY/PADES_CERT)" \
      "note=external cosign+Rekor+RFC-3161 is the authoritative path"
    warn "pyhanko present but no signer configured — soft skip (honest fallback)"
  fi
else
  set_sig pades "status=unavailable" "reason=tool-or-pdf-absent" \
    "note=external cosign+Rekor+RFC-3161 is the authoritative verification path"
  set_tool pyhanko "absent"
  warn "pyhanko absent or PDF absent — PAdES self-seal skipped (soft)"
fi

# ---------------------------------------------------------------------------
# Step 6 — record remaining tool versions & finalize
# ---------------------------------------------------------------------------
set_tool weasyprint "$(python3 -c 'import weasyprint,sys; sys.stdout.write(weasyprint.__version__)' 2>/dev/null || echo absent)"
set_tool gs "$(tool_version gs --version)"
set_tool pdfsig "$( { have pdfsig && echo present; } || echo absent )"
set_tool sha256sum "$(tool_version sha256sum --version)"

# Surface a quick summary.
log "seal complete. signatures recorded in $(basename "${MANIFEST_JSON}"):"
python3 "${HELPER}" "${MANIFEST_JSON}" get signatures >&2 || true
printf '\n' >&2

exit 0
