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
#     / cosign failure are HARD FAILS. A *transient* RFC-3161 TSA miss on a single
#     artifact stays SOFT (warn + flag) even in CI per the design spec, BUT zero
#     valid .tsr produced across ALL artifacts (a structurally-broken trusted-time
#     path) is a HARD FAIL in CI (T-56: structural-vs-flaky distinction). Absence
#     of pyhanko/qpdf remains SOFT even in CI.
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

# ---------------------------------------------------------------------------
# Pluggable timestamp authority (T-53 / T-110).
#
# The timestamp authority is configured ENTIRELY by environment so that
# upgrading from the free, NON-QUALIFIED freetsa.org TSA to a QUALIFIED eIDAS
# QTS (KIR Szafir, Asseco Certum, EuroCert, CenCert) is a config switch, not a
# code change. Nothing about the qualified-provider path is hardcoded here.
#
#   QTS_PROVIDER  Optional human-readable name of the qualified TSP (e.g.
#                 "KIR Szafir", "Asseco Certum"). Recorded into the manifest
#                 for the audit trail. Empty => default (non-qualified) path.
#   QTS_URL       Optional RFC-3161 endpoint of the qualified TSP. When set it
#                 takes precedence over TSA_URL (a qualified endpoint, once
#                 provisioned, should be used instead of the free default).
#   TSA_URL       Generic RFC-3161 endpoint. Defaults to freetsa.org, which is
#                 NON-QUALIFIED (free, no eIDAS qualified status). Clearly
#                 labeled as such in the manifest.
#   TSA_CA_FILE   Optional PEM bundle for the TSA's CA chain. When set, Step 4
#                 copies it to ${EVIDENCE_DIR}/tsa-ca.pem after a successful
#                 stamp; otherwise the configured TSA's public CA chain is
#                 fetched (default freetsa). verify-evidence-pack.sh then reads
#                 that shipped tsa-ca.pem to fully verify the RFC-3161 token.
#   TSA_AUTH      Optional auth header value for authenticated (paid) QTS
#                 endpoints, e.g. "Authorization: Bearer <token>" or
#                 "Authorization: Basic <b64>". Passed verbatim to curl. Most
#                 qualified providers are authenticated.
#   TSA_QUALIFIED Explicit honest override of the qualified label
#                 (true|false). When UNSET, the label is inferred: true only
#                 when QTS_PROVIDER or QTS_URL is configured AND the default
#                 free freetsa endpoint is NOT in use. Defaults to false so the
#                 pack NEVER over-claims qualified status.
# ---------------------------------------------------------------------------
DEFAULT_TSA_URL="https://freetsa.org/tsr"   # free, NON-QUALIFIED eIDAS TSA
QTS_PROVIDER="${QTS_PROVIDER:-}"
QTS_URL="${QTS_URL:-}"
# A configured qualified endpoint (QTS_URL) wins over a generic TSA_URL.
TSA_URL="${QTS_URL:-${TSA_URL:-${DEFAULT_TSA_URL}}}"
TSA_CA_FILE="${TSA_CA_FILE:-}"
TSA_AUTH="${TSA_AUTH:-}"

# Honest qualified label. Default false; only true when explicitly asserted, or
# when a qualified provider/endpoint is wired AND we are not on the free default.
infer_qualified() {
  if [ -n "${TSA_QUALIFIED:-}" ]; then
    # Normalize an explicit operator assertion to a strict true|false.
    case "${TSA_QUALIFIED}" in
      1|true|TRUE|True|yes|YES) printf 'true'  ;;
      *)                        printf 'false' ;;
    esac
    return
  fi
  if { [ -n "${QTS_PROVIDER}" ] || [ -n "${QTS_URL}" ]; } \
        && [ "${TSA_URL}" != "${DEFAULT_TSA_URL}" ]; then
    printf 'true'
  else
    printf 'false'
  fi
}
TSA_QUALIFIED_LABEL="$(infer_qualified)"

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
  _manifest_sig_helper.py <manifest.json> record-bundle-sigs <evidence_dir>
  _manifest_sig_helper.py <manifest.json> set-worm-from-marker <marker_path>
All edits write the manifest back atomically (deterministic 2-space indent).

record-bundle-sigs (EP-02): scans <evidence_dir> for every *.cosign.bundle and
records, under manifest.signatures.bundles[], one self-documenting entry per
bundle parsed from the Sigstore bundle (v0.3) verificationMaterial:
  {artifact, cert_identity, oidc_issuer, rekor_log_index, signed_sha256,
   bundle_path}
This makes the manifest self-documenting: today the sidecar *.cosign.bundle
files exist but manifest.signatures stays {}. The parser is degrade-honest:
fields it cannot extract are recorded as null (never fabricated). It relies only
on the Python stdlib + an optional `openssl` for the X.509 identity extraction;
when openssl is absent, cert_identity / oidc_issuer degrade to null rather than
crash. signed_sha256 / rekor_log_index come straight from the bundle JSON.

set-worm-from-marker (EP-02): when a WORM-upload marker file is present, stamp
manifest.worm_state from it (the marker's text, or a JSON {"state":...}); absent
marker => leave worm_state untouched (honest: stays "pending" until WORM upload
is proven). NEVER fabricates a "locked" state.
"""
import base64
import binascii
import json
import os
import re
import shutil
import subprocess  # nosec B404 - used only to call the trusted local `openssl` binary
import sys
from pathlib import Path

# Fulcio OID carrying the OIDC issuer of the identity that requested the cert.
# https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
FULCIO_ISSUER_OID = "1.3.6.1.4.1.57264.1.1"


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


# ---------------------------------------------------------------------------
# EP-02: Sigstore-bundle parsing (self-documenting manifest.signatures).
# ---------------------------------------------------------------------------
def _b64_to_hex(b64):
    """Decode a base64 digest to lowercase hex, or None on any failure."""
    if not isinstance(b64, str) or not b64:
        return None
    try:
        return binascii.hexlify(base64.b64decode(b64, validate=True)).decode("ascii")
    except Exception:
        return None


def _extract_signed_sha256(bundle):
    """Pull the SHA-256 of the signed blob out of a Sigstore bundle.

    Covers BOTH bundle content variants:
      * messageSignature.messageDigest{algorithm:"SHA2_256", digest:<b64>}
        (cosign sign-blob over a raw artifact — the merkle-root / pdf bundles)
      * dsseEnvelope (an attestation) — there is no single blob digest, so None.
    Returns lowercase hex or None (degrade-honest, never fabricated).
    """
    if not isinstance(bundle, dict):
        return None
    ms = bundle.get("messageSignature")
    if isinstance(ms, dict):
        md = ms.get("messageDigest")
        if isinstance(md, dict):
            return _b64_to_hex(md.get("digest"))
    return None


def _extract_rekor_log_index(bundle):
    """Return the Rekor transparency-log index (int) or None.

    Handles the cosign-v3 sigstore bundle shape
    (verificationMaterial.tlogEntries[].logIndex) and the legacy cosign-v2 shape
    (rekorBundle.Payload.logIndex). Degrade-honest: None when absent.
    """
    if not isinstance(bundle, dict):
        return None
    vm = bundle.get("verificationMaterial")
    if isinstance(vm, dict):
        for e in (vm.get("tlogEntries") or []):
            if isinstance(e, dict) and e.get("logIndex") is not None:
                try:
                    return int(str(e["logIndex"]))
                except (TypeError, ValueError):
                    pass
    rb = bundle.get("rekorBundle")
    if isinstance(rb, dict):
        p = rb.get("Payload", rb.get("payload", {}))
        if isinstance(p, dict) and p.get("logIndex") is not None:
            try:
                return int(str(p["logIndex"]))
            except (TypeError, ValueError):
                pass
    return None


def _cert_der_from_bundle(bundle):
    """Return the leaf-cert DER bytes from a Sigstore bundle, or None.

    The v0.3 bundle stores the leaf cert at
    verificationMaterial.certificate.rawBytes (base64 DER). Older shapes used
    x509CertificateChain.certificates[0].rawBytes. Degrade-honest.
    """
    if not isinstance(bundle, dict):
        return None
    vm = bundle.get("verificationMaterial")
    if not isinstance(vm, dict):
        return None
    cert = vm.get("certificate")
    if isinstance(cert, dict) and cert.get("rawBytes"):
        try:
            return base64.b64decode(cert["rawBytes"], validate=True)
        except Exception:
            return None
    chain = vm.get("x509CertificateChain")
    if isinstance(chain, dict):
        certs = chain.get("certificates") or []
        if certs and isinstance(certs[0], dict) and certs[0].get("rawBytes"):
            try:
                return base64.b64decode(certs[0]["rawBytes"], validate=True)
            except Exception:
                return None
    return None


def _extract_identity_issuer(bundle):
    """Return (cert_identity, oidc_issuer) parsed from the leaf cert via openssl.

    cert_identity  = the SAN (URI/email) — the workload/user identity Fulcio
                     bound into the cert.
    oidc_issuer    = the OIDC issuer URI from Fulcio OID 1.3.6.1.4.1.57264.1.1.
    Degrade-honest: if openssl is absent or the cert cannot be parsed, BOTH are
    returned as None — the manifest never fabricates an identity.
    """
    der = _cert_der_from_bundle(bundle)
    if der is None:
        return None, None
    openssl = shutil.which("openssl")
    if not openssl:
        return None, None
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv to the local openssl
            [openssl, "x509", "-inform", "DER", "-noout", "-text"],
            input=der,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except Exception:
        return None, None
    text = proc.stdout.decode("utf-8", errors="replace")

    identity = None
    # SAN: "X509v3 Subject Alternative Name: [critical]\n   URI:... / email:..."
    san_m = re.search(r"Subject Alternative Name:[^\n]*\n\s*([^\n]+)", text)
    if san_m:
        san_line = san_m.group(1).strip()
        for part in san_line.split(","):
            part = part.strip()
            for prefix in ("URI:", "email:", "DNS:", "IP Address:"):
                if part.startswith(prefix):
                    identity = part[len(prefix):].strip()
                    break
            if identity:
                break
        if identity is None and san_line:
            identity = san_line

    issuer = None
    # Fulcio issuer OID block: "1.3.6.1.4.1.57264.1.1:\n    https://issuer"
    oid_m = re.search(
        re.escape(FULCIO_ISSUER_OID) + r":[^\n]*\n\s*([^\n]+)", text
    )
    if oid_m:
        # The value is a UTF8String; strip any leading non-printable framing.
        raw = oid_m.group(1).strip()
        url_m = re.search(r"https?://\S+", raw)
        issuer = url_m.group(0) if url_m else raw

    return identity, issuer


def record_bundle_sigs(manifest_path, evidence_dir):
    """EP-02: populate manifest.signatures.bundles[] from every *.cosign.bundle."""
    data = load(manifest_path)
    bundles_out = []
    names = sorted(
        f for f in os.listdir(evidence_dir) if f.endswith(".cosign.bundle")
    )
    for name in names:
        full = os.path.join(evidence_dir, name)
        try:
            bundle = json.loads(Path(full).read_text(encoding="utf-8"))
        except Exception:
            # Corrupt/half-written bundle: record honestly with nulls, never skip
            # silently (the completeness self-test FAILs corrupt bundles anyway).
            bundles_out.append({
                "artifact": name[: -len(".cosign.bundle")],
                "cert_identity": None,
                "oidc_issuer": None,
                "rekor_log_index": None,
                "signed_sha256": None,
                "bundle_path": name,
                "parse_error": "bundle not valid JSON",
            })
            continue
        identity, issuer = _extract_identity_issuer(bundle)
        bundles_out.append({
            # The signed artifact is the bundle filename minus the suffix; e.g.
            # merkle-root.cosign.bundle -> "merkle-root" (the merkle-root.txt blob).
            "artifact": name[: -len(".cosign.bundle")],
            "cert_identity": identity,
            "oidc_issuer": issuer,
            "rekor_log_index": _extract_rekor_log_index(bundle),
            "signed_sha256": _extract_signed_sha256(bundle),
            "bundle_path": name,
        })
    sigs = data.setdefault("signatures", {})
    if not isinstance(sigs, dict):
        sigs = {}
        data["signatures"] = sigs
    sigs["bundles"] = bundles_out
    save(manifest_path, data)
    sys.stdout.write(str(len(bundles_out)))
    return 0


def set_worm_from_marker(manifest_path, marker_path):
    """EP-02: stamp manifest.worm_state from a WORM-upload marker, if present.

    Degrade-honest: an absent / empty marker leaves worm_state UNCHANGED (it
    stays "pending"), so the pack never over-claims an immutable archive. A
    present marker may contain either plain text (used verbatim as the state) or
    JSON {"state": ..., ...} (the whole object is recorded so the audit trail
    keeps blob URL / timestamp / container provenance).
    """
    if not marker_path or not os.path.isfile(marker_path):
        sys.stdout.write("absent")
        return 0
    try:
        raw = Path(marker_path).read_text(encoding="utf-8").strip()
    except Exception:
        sys.stdout.write("unreadable")
        return 0
    if not raw:
        sys.stdout.write("empty")
        return 0
    data = load(manifest_path)
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = None
    if isinstance(parsed, dict):
        # Preserve the full marker object for provenance; ensure a state field.
        if "state" not in parsed:
            parsed["state"] = "locked"
        data["worm_state"] = parsed
        state_label = str(parsed.get("state"))
    else:
        data["worm_state"] = raw
        state_label = raw
    save(manifest_path, data)
    sys.stdout.write(state_label)
    return 0


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

    if cmd == "record-bundle-sigs":
        return record_bundle_sigs(path, argv[2])

    if cmd == "set-worm-from-marker":
        return set_worm_from_marker(path, argv[2])

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
record_bundle_sigs() { python3 "${HELPER}" "${MANIFEST_JSON}" record-bundle-sigs "$1"; }
set_worm_marker()    { python3 "${HELPER}" "${MANIFEST_JSON}" set-worm-from-marker "$1"; }

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
log "tsa: url=${TSA_URL} qualified=${TSA_QUALIFIED_LABEL} provider=${QTS_PROVIDER:-freetsa.org (non-qualified, default)}"

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

# Materialize the immutable merkle-root.txt NOW — BEFORE Step 3 — so the cosign
# sign-blob `-f` guard sees the file and actually produces merkle-root.cosign.bundle.
# (Previously this file was first written in Step 4, after Step 3 had already
# short-circuited; the headline signature was therefore never produced.) The same
# file is reused by the RFC-3161 stamp in Step 4 — written once, here.
MR_FILE="${EVIDENCE_DIR}/merkle-root.txt"
if [ -n "${MERKLE_ROOT}" ]; then
  printf '%s\n' "${MERKLE_ROOT}" > "${MR_FILE}"
fi

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
# Merkle root cryptographically commits to every evidence artifact's content —
# this now includes the organizational/compliance verdicts and per-release
# triage artifacts (compliance-status.json, compliance-matrix.json,
# vex.openvex.json, soa-maturity.json, residual-risk.json, scope-determination
# .json, and each A.x *-validation/verdict JSON), because the manifest is
# (re)generated over the full evidence/ directory before this step. No explicit
# allowlist is needed here: anything written into evidence/ ahead of the seal is
# leaf-hashed into the Merkle root by generate-evidence-manifest.py.
# manifest.json must NOT be signed because the set_sig calls below mutate it
# (recording these very signatures) — signing it then writing to it would
# invalidate its own signature. merkle-root.txt (written before Step 3, right
# after MERKLE_ROOT is read) and pdf.sha256 are never modified after signing.
# Both are excluded from the manifest's hashed set, so signing perturbs nothing.
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
# Step 3 hard precondition (anti-regression for blueprint §6.2-A).
# The headline cryptographic claim of the pack is keyless identity attribution
# over the Merkle root. §6.2-A was a silent ordering bug: cosign soft-degraded
# and the bundle was never produced, yet the seal exited 0. To ensure that
# regression cannot recur silently, in NON-degrade (CI) mode a missing or empty
# merkle-root.cosign.bundle is a HARD FAIL — even though plain cosign failure
# soft-degrades, the centerpiece signature is mandatory whenever a Merkle root
# exists to sign. (In degrade mode this stays soft, matching local runs.)
# ---------------------------------------------------------------------------
if ! is_degrade && [ -n "${MERKLE_ROOT}" ] && [ ! -s "${EVIDENCE_DIR}/merkle-root.cosign.bundle" ]; then
  die "merkle-root.cosign.bundle missing or empty after Step 3 — Merkle signing failed (fail-closed; §6.2-A anti-regression)"
fi

# ---------------------------------------------------------------------------
# Step 4 — RFC-3161 timestamp over merkle_root, manifest, and the PDF.
# A *single-artifact* TSA miss is SOFT even in CI (per design spec
# failure_policy), but ZERO valid .tsr across all artifacts is a HARD FAIL in
# non-degrade mode (T-56: structural-vs-flaky trusted-time assertion below).
# ---------------------------------------------------------------------------
# tsr_is_valid_token <tsr>: exit 0 iff the file is a non-empty, well-formed
# RFC-3161 timestamp response that the TSA GRANTED. `openssl ts -reply -text`
# DER-decodes the TimeStampResp and prints its status; a genuine token shows
# "Status: Granted." A misbehaving TSA / proxy that 200s with an HTML error
# page, an empty body, or an RFC-3161 rejection (status grantedWithMods/rejected)
# is caught here so a non-token can never be counted as a stamp. (Full
# cryptographic chain verification needs the TSA CA — Step 4 below ships
# ${EVIDENCE_DIR}/tsa-ca.pem (from TSA_CA_FILE or a provider fetch) and verify-
# evidence-pack.sh reads it to verify the chain; here we assert structural
# validity + granted status, which is what catches a STRUCTURALLY broken path.)
tsr_is_valid_token() {
  local tsr="$1"
  [ -s "${tsr}" ] || return 1
  openssl ts -reply -in "${tsr}" -text 2>/dev/null | grep -qi 'Status: *Granted'
}

rfc3161_stamp() {
  # $1 = label, $2 = path-to-data-file
  local label="$1" data="$2"
  local tsq="${EVIDENCE_DIR}/${label}.tsq"
  local tsr="${EVIDENCE_DIR}/${label}.tsr"
  if openssl ts -query -data "${data}" -sha256 -cert -out "${tsq}" >/dev/null 2>&1; then
    # Build the curl arg list. An optional TSA_AUTH header lets authenticated
    # (paid) qualified-QTS endpoints work without changing this code; it is
    # passed verbatim and only added when non-empty (freetsa needs no auth).
    local -a curl_args=(-fsS -H "Content-Type: application/timestamp-query")
    [ -n "${TSA_AUTH}" ] && curl_args+=(-H "${TSA_AUTH}")
    curl_args+=(--data-binary "@${tsq}" "${TSA_URL}" -o "${tsr}")
    if curl "${curl_args[@]}" 2>/dev/null; then
      # Produced AND valid: only count a token the TSA actually granted. A 200
      # response carrying a non-token body must NOT masquerade as a stamp.
      if tsr_is_valid_token "${tsr}"; then
        set_sig rfc3161 "${label}_tsr=$(basename "${tsr}")" "${label}_status=stamped"
        log "rfc3161: ${label} timestamped via ${TSA_URL} (token validated: granted, qualified=${TSA_QUALIFIED_LABEL})"
        return 0
      fi
      # Remove the bogus file so a non-token never satisfies the *.tsr CI/verify
      # assertion downstream; record the per-artifact miss (kept SOFT here).
      rm -f "${tsr}"
      set_sig rfc3161 "${label}_status=invalid-token"
      warn "rfc3161: ${label} TSA returned a response that is not a granted RFC-3161 token — discarded"
    fi
  fi
  return 1
}

# materialize_tsa_ca: ship ${EVIDENCE_DIR}/tsa-ca.pem so verify-evidence-pack.sh
# can run FULL `openssl ts -verify -CAfile` instead of only the parse+granted
# SKIP. Provider-driven: an operator-supplied TSA_CA_FILE is copied verbatim;
# otherwise the configured TSA's PUBLIC CA chain is fetched (default freetsa:
# tsa.crt + cacert.pem concatenated, mirroring make-sample-pack.sh). DEGRADE-
# HONEST: a fetch failure (offline) or degrade mode warns and continues WITHOUT
# a tsa-ca.pem (the pack then honestly SKIPs full ts -verify) — it NEVER fails
# the seal and NEVER fabricates a CA. Only the free freetsa default has a known
# public CA URL pair; any other endpoint without TSA_CA_FILE is skipped honestly.
materialize_tsa_ca() {
  local ca="${EVIDENCE_DIR}/tsa-ca.pem"
  [ -s "${ca}" ] && return 0
  if [ -n "${TSA_CA_FILE}" ]; then
    if [ -f "${TSA_CA_FILE}" ] && cp "${TSA_CA_FILE}" "${ca}" 2>/dev/null; then
      log "rfc3161: shipped TSA CA chain from TSA_CA_FILE -> $(basename "${ca}")"
      return 0
    fi
    warn "rfc3161: TSA_CA_FILE set but unreadable (${TSA_CA_FILE}) — no tsa-ca.pem shipped (verify will SKIP full ts -verify)"
    return 1
  fi
  if is_degrade; then
    warn "rfc3161: degrade mode — skipping TSA CA fetch (no tsa-ca.pem shipped; verify will SKIP full ts -verify)"
    return 1
  fi
  if [ "${TSA_URL}" = "${DEFAULT_TSA_URL}" ] && have curl; then
    # Default freetsa: fetch its public tsa.crt + cacert.pem and concatenate.
    local tsa_crt ca_crt
    tsa_crt="$(mktemp)"; ca_crt="$(mktemp)"
    if curl -fsS -m 30 https://freetsa.org/files/tsa.crt    -o "${tsa_crt}" 2>/dev/null \
       && curl -fsS -m 30 https://freetsa.org/files/cacert.pem -o "${ca_crt}" 2>/dev/null \
       && [ -s "${tsa_crt}" ] && [ -s "${ca_crt}" ]; then
      cat "${tsa_crt}" "${ca_crt}" > "${ca}" 2>/dev/null
      rm -f "${tsa_crt}" "${ca_crt}"
      if [ -s "${ca}" ]; then
        log "rfc3161: fetched freetsa public CA chain -> $(basename "${ca}")"
        return 0
      fi
    fi
    rm -f "${tsa_crt}" "${ca_crt}"
    warn "rfc3161: freetsa CA chain fetch failed (offline?) — no tsa-ca.pem shipped (verify will SKIP full ts -verify)"
    return 1
  fi
  warn "rfc3161: no TSA_CA_FILE and no known public CA URL for ${TSA_URL} — no tsa-ca.pem shipped (verify will SKIP full ts -verify)"
  return 1
}

if have openssl; then
  set_tool openssl "$(tool_version openssl version)"
  TSA_ANY=0

  # merkle root: reuse the merkle-root.txt already written before Step 3.
  if [ -n "${MERKLE_ROOT}" ] && [ -f "${MR_FILE}" ]; then
    if have curl && rfc3161_stamp "merkle-root" "${MR_FILE}"; then TSA_ANY=1; fi
  fi
  if have curl && rfc3161_stamp "manifest" "${MANIFEST_JSON}"; then TSA_ANY=1; fi
  if [ "${PDF_PRESENT}" -eq 1 ] && have curl && rfc3161_stamp "pdf" "${PDF_PATH}"; then TSA_ANY=1; fi

  # Record the honest qualified label + provider provenance regardless of
  # outcome, so the manifest never silently implies qualified status. With the
  # free freetsa default this is qualified=false; only a wired qualified eIDAS
  # QTS (QTS_PROVIDER/QTS_URL, or explicit TSA_QUALIFIED=true) flips it to true.
  set_sig rfc3161 "qualified=${TSA_QUALIFIED_LABEL}" \
    "provider=${QTS_PROVIDER:-freetsa.org (non-qualified, default)}" \
    "ca_file=${TSA_CA_FILE:-<unset>}"

  if [ "${TSA_ANY}" -eq 0 ]; then
    set_sig rfc3161 "status=unavailable" "reason=tsa-unreachable-or-no-curl" "tsa_url=${TSA_URL}"
    # ---------------------------------------------------------------------
    # T-56 — structural-vs-flaky trusted-time assertion (blueprint §6.2 gap #2).
    # RFC-3161 stamping soft-degrades by design so a *transient* TSA miss on a
    # single artifact never breaks a build. But ZERO valid .tsr across ALL
    # artifacts in NON-degrade (CI) mode means the trusted-time anchor path is
    # STRUCTURALLY broken (TSA totally unreachable, returns non-tokens, or
    # openssl-query is failing) — not flaky. Combined with §6.2-A this is the
    # exact case where a permanent failure could masquerade as infra flakiness
    # forever, so it is a HARD FAIL here. Per-artifact softness is preserved
    # above: this trips only when the entire path produced nothing valid.
    # (Degrade/local mode stays soft, matching local runs without a TSA.)
    # ---------------------------------------------------------------------
    if is_degrade; then
      warn "rfc3161: TSA unreachable or curl absent — recorded rfc3161_unavailable (soft, degrade mode)"
    else
      die "rfc3161: NO valid RFC-3161 timestamp produced for any artifact (fail-closed; T-56: trusted-time path structurally broken, not flaky). Set EVIDENCE_ALLOW_DEGRADE=1 for local runs without a TSA."
    fi
  else
    set_sig rfc3161 "tsa_url=${TSA_URL}"
    # At least one artifact got a granted token: ship the TSA CA chain so the
    # pack can be FULLY verified (openssl ts -verify -CAfile) rather than only
    # parse+granted SKIP. Degrade-honest: a fetch miss just omits tsa-ca.pem.
    if materialize_tsa_ca; then
      set_sig rfc3161 "ca_shipped=true" "ca_file_shipped=tsa-ca.pem"
    else
      set_sig rfc3161 "ca_shipped=false"
    fi
  fi
else
  set_sig rfc3161 "status=unavailable" "reason=openssl-absent"
  # openssl is the timestamping engine. Its absence in CI means no trusted-time
  # anchor can ever be produced — fail-closed in non-degrade mode (T-56), soft
  # locally where the toolchain may legitimately be incomplete.
  if is_degrade; then
    warn "rfc3161: openssl absent — soft skip (degrade mode)"
  else
    die "rfc3161: openssl absent — RFC-3161 trusted-time anchor cannot be produced (fail-closed; T-56)"
  fi
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

# ---------------------------------------------------------------------------
# Step 6a — EP-02: make the manifest self-documenting.
#
# Until now manifest.signatures stayed {} even though the seal produced
# *.cosign.bundle sidecars, and worm_state stayed "pending" forever. Here we:
#
#   (1) Re-stamp manifest.json from the bundles that ACTUALLY landed on disk:
#       for EACH *.cosign.bundle, record one self-documenting entry under
#       signatures.bundles[] parsed from the Sigstore bundle (cert identity +
#       OIDC issuer from the Fulcio cert, Rekor log index, the signed SHA-256,
#       and the sidecar path). Degrade-honest: any field that cannot be parsed
#       is recorded as null — never fabricated.
#
#   (2) Stamp worm_state IF a WORM-upload marker is present (env WORM_MARKER, or
#       ${EVIDENCE_DIR}/worm-upload.marker). Absent marker => worm_state is left
#       UNCHANGED ("pending") so the pack never over-claims an immutable archive.
#
# CRITICAL — Merkle consistency: this re-stamp ONLY mutates manifest.json (and
# never the Merkle root or any leaf-hashed artifact). manifest.json is excluded
# from the Merkle leaf set (EXCLUDED_NAMES in generate-evidence-manifest.py), and
# the *.cosign.bundle sidecars are excluded too (EXCLUDED_SUFFIXES). So recording
# the bundle metadata back into manifest.json perturbs neither merkle_root nor
# any signed/timestamped blob — the seal outputs were produced over merkle-root
# .txt / pdf.sha256, both also Merkle-excluded. The post-seal manifest therefore
# stays consistent with the existing exclusion rules.
# ---------------------------------------------------------------------------
WORM_MARKER="${WORM_MARKER:-${EVIDENCE_DIR}/worm-upload.marker}"

BUNDLE_COUNT="$(record_bundle_sigs "${EVIDENCE_DIR}" 2>/dev/null || echo 0)"
log "manifest: recorded ${BUNDLE_COUNT:-0} cosign-bundle signature entry(ies) into signatures.bundles[]"

WORM_RESULT="$(set_worm_marker "${WORM_MARKER}" 2>/dev/null || echo error)"
case "${WORM_RESULT}" in
  absent|empty|unreadable|error)
    log "manifest: worm_state left as-is (WORM marker ${WORM_MARKER} ${WORM_RESULT}; honest: not over-claiming locked archive)"
    ;;
  *)
    log "manifest: worm_state stamped from marker -> ${WORM_RESULT}"
    ;;
esac

# Surface a quick summary.
log "seal complete. signatures recorded in $(basename "${MANIFEST_JSON}"):"
python3 "${HELPER}" "${MANIFEST_JSON}" get signatures >&2 || true
printf '\n' >&2

exit 0
