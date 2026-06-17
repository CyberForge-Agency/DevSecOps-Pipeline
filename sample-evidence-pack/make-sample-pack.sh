#!/usr/bin/env bash
#
# make-sample-pack.sh — one-command, founder-independent reproducer for the
# CyberForge sample Evidence Pack (OFFLINE / degrade variant).
#
# It regenerates Pipeline/sample-evidence-pack/evidence/ from the repo's real
# scripts and the seeded governance/evidence inputs, with NO Azure, NO cloud
# upload, NO image push, NO deploy. It produces:
#   - real Trivy SBOM + SCA + SARIF of the demo app (offline DB cache)
#   - A.1-A.10 organizational gate          (aggregate-compliance.py)
#   - content-validated control matrix      (generate-compliance-matrix.sh)
#   - derived multi-framework crosswalk     (crosswalk.json)
#   - machine + narrative gap register      (gap-register.json + gap-register.md)
#   - HTML board/audit reports              (generate-html-report.sh + build-audit-document.py)
#   - RFC-6962 Merkle manifest              (generate-evidence-manifest.py)
#   - degrade seal w/ REAL freetsa RFC-3161 (seal-evidence.sh, EVIDENCE_ALLOW_DEGRADE=1)
#   - full integrity verification           (verify-evidence-pack.sh -> exit 0)
#
# PENDING the live CI run (NOT produced here, NOT faked):
#   - cosign keyless signature + Rekor inclusion (no OIDC offline -> "unavailable")
#   - Azure WORM archival (no cloud upload)
#   - PDF/A-3b render (WeasyPrint absent -> .MISSING marker)
#   - A.10 restore-test (held on Azure -> honest BLOCKING FAIL)
#
# Prereqs (documented, no Szymon-only knowledge): bash, python3, openssl, curl,
# trivy (with a warmed ~/.cache/trivy/db). cosign/weasyprint optional.
#
# Usage:  bash sample-evidence-pack/make-sample-pack.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PACK_DIR="${SCRIPT_DIR}"
PIPELINE_DIR="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
EVID="${PACK_DIR}/evidence"
S="${PIPELINE_DIR}/scripts"
TSA_URL="https://freetsa.org/tsr"

say() { printf '>>> %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

cd "${PIPELINE_DIR}" || { echo "cannot cd ${PIPELINE_DIR}"; exit 1; }

say "fresh evidence dir"
rm -rf "${EVID}"; mkdir -p "${EVID}"

say "seed organizational evidence (clean JSON inputs)"
cp "${PIPELINE_DIR}/evidence/"*.json "${EVID}/" 2>/dev/null || true

say "real Trivy SBOM + SCA + SARIF of the demo app (offline)"
if have trivy; then
  trivy fs --skip-db-update --offline-scan --skip-version-check --format cyclonedx     --output "${EVID}/sbom.cyclonedx.json"      app/ 2>/dev/null || true
  trivy fs --skip-db-update --offline-scan --skip-version-check --scanners vuln --format json  --output "${EVID}/trivy-sca-results.json" app/ 2>/dev/null || true
  trivy fs --skip-db-update --offline-scan --skip-version-check --scanners vuln --format sarif --output "${EVID}/trivy-results.sarif"   app/ 2>/dev/null || true
else
  echo "WARN: trivy absent — SBOM/scan components will be missing"
fi

say "A.1-A.10 organizational gate (honest verdict; FAIL is OK for the demo)"
python3 "${S}/aggregate-compliance.py" "${EVID}" >/dev/null 2>&1 || true

say "content-validated control matrix"
bash "${S}/generate-compliance-matrix.sh" "${EVID}" > "${EVID}/compliance-matrix.json" 2>/dev/null || true

say "narrative gap register (Part J)"
cp "${PIPELINE_DIR}/docs/compliance/gap-register.md" "${EVID}/gap-register.md"

say "derive crosswalk.json + gap-register.json from live verdicts"
python3 "${PACK_DIR}/derive-crosswalk-and-gaps.py" "${EVID}"

say "bind spec-part artifacts into the pack so they are Merkle-covered (T-35/T-115/T-116/T-118)"
V="${S}/validators"
# T-115 — validated STRIDE threat model (honest validator verdict, NOT recomputed)
python3 "${V}/threat_model.py" "${PIPELINE_DIR}/docs/security/threat-model.yaml" \
  --out "${EVID}/threat-model-validation.json" >/dev/null 2>&1 \
  || echo "WARN: threat_model validator unavailable — threat-model-validation.json missing"
cp "${PIPELINE_DIR}/docs/security/threat-model.yaml" "${EVID}/threat-model.yaml" 2>/dev/null || true
# T-118 — Azure Container Apps runtime-hardening posture
python3 "${V}/runtime_hardening.py" --dockerfile "${PIPELINE_DIR}/app/Dockerfile" \
  --tf "${PIPELINE_DIR}/infra/modules/container-apps/main.tf" \
  --out "${EVID}/runtime-hardening.json" >/dev/null 2>&1 \
  || echo "WARN: runtime_hardening validator unavailable — runtime-hardening.json missing"
# Part B / 0.4 — scope & applicability determination
python3 "${V}/applicability.py" "${PIPELINE_DIR}/docs/governance/applicability.yaml" \
  "${PIPELINE_DIR}/schemas/applicability.schema.json" \
  --out "${EVID}/scope-determination.json" >/dev/null 2>&1 \
  || echo "WARN: applicability validator unavailable — scope-determination.json missing"
# Part J — residual-risk / risk-acceptance (T-121)
python3 "${V}/risk_acceptance.py" "${PIPELINE_DIR}/docs/compliance/exception-register.md" \
  --out "${EVID}/residual-risk.json" >/dev/null 2>&1 \
  || echo "WARN: risk_acceptance validator unavailable — residual-risk.json missing"
# Part D.3 / §9 — SoA maturity (computed, not the struktura §13 L5 overclaim)
python3 "${V}/soa_maturity.py" "${PIPELINE_DIR}/docs/governance/statement-of-applicability.md" \
  --evidence-dir "${EVID}" --out "${EVID}/soa-maturity.json" >/dev/null 2>&1 \
  || echo "WARN: soa_maturity validator unavailable — soa-maturity.json missing"
# T-116 — signed OpenVEX. Offline there is NO released image, so we bind the VEX
# to a digest derived deterministically from THIS pack's real SBOM, with a clear
# demo URI (NOT a registry push). Honest: reproducible, not a fabricated release.
if [ -s "${EVID}/sbom.cyclonedx.json" ]; then
  VEX_DIGEST="sha256:$(python3 - "${EVID}/sbom.cyclonedx.json" <<'PY'
import hashlib,sys
print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())
PY
)"
  IMAGE_URI="${IMAGE_URI:-cyberforge-demo/app:offline-demo}" \
  python3 "${S}/generate-vex.py" \
    --sca-results "${EVID}/trivy-sca-results.json" \
    --sbom "${EVID}/sbom.cyclonedx.json" \
    --justifications "${PIPELINE_DIR}/docs/governance/vex-justifications.yaml" \
    --image-digest "${VEX_DIGEST}" \
    --out "${EVID}/vex.openvex.json" >/dev/null 2>&1 \
    || echo "WARN: generate-vex unavailable — vex.openvex.json missing"
else
  echo "WARN: no SBOM — VEX is image/SBOM-bound, skipping vex.openvex.json (honest)"
fi
# T-35 — copy the signed A.1-A.10 verdicts + compliance gate alongside (already in
# ${EVID} from the seed + aggregate step: compliance-status.json is the gate).

say "interim manifest, then HTML reports"
GENERATED_AT="${GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" REPORT_ID="${REPORT_ID:-cyberforge-demo-$(date -u +%Y%m%d)}" \
  python3 "${S}/generate-evidence-manifest.py" "${EVID}" --out "${EVID}/manifest.json" --legacy-out "${EVID}/manifest.sha256" >/dev/null 2>&1
bash "${S}/generate-html-report.sh" "${EVID}" "${EVID}/evidence-report.html" >/dev/null 2>&1 || true
python3 "${S}/build-audit-document.py" --evidence-dir "${EVID}" --manifest "${EVID}/manifest.json" \
  --report-html "${EVID}/evidence-report.html" --compliance-matrix "${EVID}/compliance-matrix.json" \
  --governance-dir "${PIPELINE_DIR}/docs/governance" \
  --exception-register "${PIPELINE_DIR}/docs/compliance/exception-register.md" \
  --control-owners "${PIPELINE_DIR}/docs/governance/control-owners.md" \
  --out "${EVID}/audit-document.html" >/dev/null 2>&1 || true

say "PDF render (degrades to .MISSING offline)"
EVIDENCE_ALLOW_DEGRADE=1 GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  python3 "${S}/render-evidence-pdf.py" --html "${EVID}/audit-document.html" \
  --evidence-dir "${EVID}" --out "${EVID}/evidence-report.pdf" >/dev/null 2>&1 || true

say "redact any local absolute paths -> neutral /cyberforge-demo root"
python3 - "${EVID}" <<'PY'
import os, sys
evid = sys.argv[1]
home = os.path.expanduser("~")
repls = [(f"file://{home}", "file:///cyberforge-demo"), (home, "/cyberforge-demo")]
# also strip the repo prefix if it differs from $HOME
for root,_d,files in os.walk(evid):
    for fn in files:
        if fn.endswith((".tsr",".tsq")): continue
        p=os.path.join(root,fn)
        try: t=open(p,encoding="utf-8").read()
        except Exception: continue
        n=t
        for a,b in repls: n=n.replace(a,b)
        if n!=t: open(p,"w",encoding="utf-8").write(n)
PY

say "final manifest (pass-1)"
GENERATED_AT="${GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" REPORT_ID="${REPORT_ID:-cyberforge-demo-$(date -u +%Y%m%d)}" \
  python3 "${S}/generate-evidence-manifest.py" "${EVID}" --out "${EVID}/manifest.json" --legacy-out "${EVID}/manifest.sha256" >/dev/null 2>&1

say "build offline-no-sigstore PATH (hide cosign; KEEP curl for real freetsa)"
NOSIG="$(mktemp -d)"
for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -x "$f" ] || continue
    b="${f##*/}"; [ "$b" = "cosign" ] && continue
    [ -e "${NOSIG}/${b}" ] || ln -s "$f" "${NOSIG}/${b}" 2>/dev/null || true
  done
done
for t in python3 openssl curl; do p="$(command -v $t)"; [ -n "$p" ] && { [ -e "${NOSIG}/$t" ] || ln -s "$p" "${NOSIG}/$t"; }; done

say "seal (EVIDENCE_ALLOW_DEGRADE=1) — real freetsa RFC-3161, cosign unavailable"
timeout 180 env PATH="${NOSIG}" EVIDENCE_ALLOW_DEGRADE=1 \
  bash "${S}/seal-evidence.sh" "${EVID}" "${EVID}/evidence-report.pdf" "${EVID}/manifest.json" >/dev/null 2>&1

say "bundle freetsa CA chain so RFC-3161 verifies fully (public certs)"
if [ ! -s "${EVID}/tsa-ca.pem" ] && have curl; then
  curl -fsS -m 30 https://freetsa.org/files/tsa.crt    -o /tmp/ft-tsa.crt 2>/dev/null
  curl -fsS -m 30 https://freetsa.org/files/cacert.pem -o /tmp/ft-ca.pem  2>/dev/null
  cat /tmp/ft-tsa.crt /tmp/ft-ca.pem > "${EVID}/tsa-ca.pem" 2>/dev/null || true
fi

say "re-timestamp manifest.tsr over the FINAL frozen manifest (last write)"
rm -f "${EVID}/manifest.tsr" "${EVID}/manifest.tsq"
openssl ts -query -data "${EVID}/manifest.json" -sha256 -cert -out "${EVID}/manifest.tsq" >/dev/null 2>&1
have curl && curl -fsS -m 30 -H "Content-Type: application/timestamp-query" \
  --data-binary "@${EVID}/manifest.tsq" "${TSA_URL}" -o "${EVID}/manifest.tsr" 2>/dev/null

say "rebuild legacy manifest.sha256 (without wiping manifest.json signatures)"
python3 - "${EVID}" <<'PY'
import os, hashlib, sys
evid=sys.argv[1]
EXCL={"manifest.json","manifest.sha256","file-list.txt","merkle-root.txt","pdf.sha256","verapdf-report.json"}
SUF=(".cosign.bundle",".bundle",".tsr",".tsq",".sig",".pem")
lines=[]
for r,_d,fs in os.walk(evid):
    for fn in fs:
        if fn in EXCL or fn.endswith(SUF): continue
        full=os.path.join(r,fn); rel=os.path.relpath(full,evid)
        lines.append(f"{hashlib.sha256(open(full,'rb').read()).hexdigest()}  {rel}")
open(os.path.join(evid,"manifest.sha256"),"w").write("\n".join(sorted(lines))+"\n")
PY

say "render README Merkle-root reference from merkle-root.txt (F3: never drift)"
python3 - "${EVID}/merkle-root.txt" "${PACK_DIR}/README.md" <<'PY'
import re, sys
root_file, readme = sys.argv[1], sys.argv[2]
try:
    root = open(root_file, encoding="utf-8").read().strip().split()[0]
except Exception as exc:
    sys.stderr.write(f"WARN: cannot read {root_file}: {exc}; README left as-is\n")
    sys.exit(0)
if not re.fullmatch(r"[0-9a-f]{64}", root):
    sys.stderr.write(f"WARN: merkle-root.txt not a 64-hex root ({root!r}); README left as-is\n")
    sys.exit(0)
prefix = root[:8]
text = open(readme, encoding="utf-8").read()
# Replace any "(RFC-6962 Merkle root `<8hex>…`)" token with the live prefix.
new = re.sub(r"(RFC-6962 Merkle root `)[0-9a-f]{8}(…`)", rf"\g<1>{prefix}\g<2>", text)
if new != text:
    open(readme, "w", encoding="utf-8").write(new)
    print(f">>> README Merkle-root reference synced to {prefix}… (from merkle-root.txt)")
else:
    print(f">>> README Merkle-root reference already {prefix}… (in sync)")
PY

say "verify"
env PATH="${NOSIG}" EVIDENCE_ALLOW_DEGRADE=1 bash "${S}/verify-evidence-pack.sh" "${EVID}"
RC=$?
rm -rf "${NOSIG}"
exit "${RC}"
