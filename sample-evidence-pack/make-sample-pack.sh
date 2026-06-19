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

# Part-G — governance / operational-resilience controls (C.9 / E.1 / E.2 / E.4 /
# A.7.7). Each runs its DEDICATED file-driven validator over the seeded governance/
# runbook input and emits its T-33 envelope INTO ${EVID} so the artifact is hashed
# into manifest.json + the RFC-6962 Merkle root AND read back by the matrix +
# re-aggregation passes (single source of truth). This MUST run BEFORE the matrix
# below so the matrix GOVERNANCE rows read the emitted envelopes (not INDETERMINATE
# "artifact missing"). Honest seeds flow straight through:
#   * pentest          -> BLOCKING FAIL  (no pen test on record)            exit 1
#   * tlpt             -> EVIDENCE-ONLY PASS (documented out-of-scope)      exit 0
#   * ict-risk         -> BLOCKING INDETERMINATE (pending initial review)   exit 2
#   * asset-map        -> BLOCKING PASS (real architectural data)           exit 0
#   * resilience       -> BLOCKING FAIL (no drill conducted yet)            exit 1
#   * access-log       -> EVIDENCE-ONLY INDETERMINATE (no live diag log)    exit 0/2
# `|| true` on the BLOCKING controls keeps the offline maker assembling the pack
# (the honest non-PASS envelope is STILL written into ${EVID}); these are real
# control gaps awaiting org-conducted evidence, exactly like the A.10 restore-test.
say "Part-G governance/resilience controls (C.9/E.1/E.2/E.4/A.7.7) -> evidence/"
GV="${S}/validators"
python3 "${GV}/check_pentest.py" "${PIPELINE_DIR}/docs/governance/pentest-report.yaml" \
  --schema "${PIPELINE_DIR}/schemas/pentest-report.schema.json" \
  --out "${EVID}/pentest-report.json" >/dev/null 2>&1 \
  || true   # honest BLOCKING FAIL (exit 1) — artifact still written
[ -s "${EVID}/pentest-report.json" ] \
  || echo "WARN: check_pentest produced no pentest-report.json (C.9 verdict missing)"
python3 "${GV}/check_tlpt.py" "${PIPELINE_DIR}/docs/governance/tlpt-record.yaml" \
  "${PIPELINE_DIR}/schemas/tlpt-record.schema.json" \
  --out "${EVID}/tlpt-record.json" >/dev/null 2>&1 \
  || echo "WARN: check_tlpt produced no tlpt-record.json (C.9 TLPT verdict missing)"
python3 "${GV}/check_ict_risk_framework.py" \
  "${PIPELINE_DIR}/docs/governance/ict-risk-management-framework.md" \
  --out "${EVID}/ict-risk-framework.json" >/dev/null 2>&1 \
  || true   # honest BLOCKING INDETERMINATE (exit 2) — artifact still written
[ -s "${EVID}/ict-risk-framework.json" ] \
  || echo "WARN: check_ict_risk_framework produced no ict-risk-framework.json (E.1 verdict missing)"
python3 "${GV}/check_asset_map.py" "${PIPELINE_DIR}/docs/governance/asset-map.yaml" \
  --schema "${PIPELINE_DIR}/schemas/asset-map.schema.json" \
  --out "${EVID}/asset-map.json" >/dev/null 2>&1 \
  || echo "WARN: check_asset_map produced no asset-map.json (E.2 verdict missing)"
python3 "${GV}/check_resilience_programme.py" \
  "${PIPELINE_DIR}/docs/runbooks/resilience-testing-programme.yaml" \
  --schema "${PIPELINE_DIR}/schemas/resilience-programme.schema.json" \
  --out "${EVID}/resilience-programme.json" >/dev/null 2>&1 \
  || true   # honest BLOCKING FAIL (exit 1) — artifact still written
[ -s "${EVID}/resilience-programme.json" ] \
  || echo "WARN: check_resilience_programme produced no resilience-programme.json (E.4 verdict missing)"
# A.7.7 — the live access log (evidence/access-log.jsonl) needs Azure Storage
# diagnostic logs routed to an immutable container; offline it does NOT exist, so
# the validator HONESTLY emits INDETERMINATE ("no live evidence-store access log").
# We never fabricate an access trail; the posture envelope is still sealed.
python3 "${GV}/check_access_log.py" "${EVID}/access-log.jsonl" \
  --schema "${PIPELINE_DIR}/schemas/access-log-posture.schema.json" \
  --out "${EVID}/access-log-posture.json" >/dev/null 2>&1 \
  || true   # EVIDENCE-ONLY INDETERMINATE offline — artifact still written
[ -s "${EVID}/access-log-posture.json" ] \
  || echo "WARN: check_access_log produced no access-log-posture.json (A.7.7 posture missing)"

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
# T-117 — CSPM / cloud-posture (Part C.14). OFFLINE there is NO live Azure scan and
# NO scan artifact, so cloud_posture.py takes its HONEST design-stage path and emits
# an EVIDENCE-ONLY INDETERMINATE ("design-stage / not-yet-scanned"). We point the
# scan arg at a path that does NOT exist on purpose so it can never read a stale or
# fabricated scan; this is the correct, non-fabricated CIS posture for an offline run.
# The envelope is written as cloud-posture.json so the pack carries the Part C.14
# artifact and it is Merkle-covered (it was absent from the pack entirely before).
python3 "${V}/cloud_posture.py" "${EVID}/cloud-posture-scan.json" \
  --doc "${PIPELINE_DIR}/docs/compliance/cspm-posture.md" \
  --out "${EVID}/cloud-posture.json" >/dev/null 2>&1 \
  || echo "WARN: cloud_posture validator unavailable — cloud-posture.json missing"
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
# T-35 — A.5 retention verdict (assert-retention). The organizational aggregator
# (aggregate-compliance.py) intentionally omits A.5 from its STATIC set because A.5
# is the deploy-time OPA retention gate (retention-policy.rego) that consumes a live
# tfplan — but the SAMPLE PACK must still carry an A.5 verdict so the pack's
# compliance set holds all 10 of A.1-A.10 (it was 9/10 without this). Offline, with
# no tfplan JSON, we derive the HONEST verdict from the Terraform SOURCE defaults of
# the storage module (immutability_period_days=1825, lock_worm=false) via --from-tf.
# This is the real configured posture, NOT a fabricated PASS (the validator emits an
# honest INDETERMINATE because WORM is retention-only / not irreversibly locked — a
# documented owner decision, T-46). Written as retention-policy.json so it is part of
# the Merkle-covered compliance set.
python3 "${V}/assert-retention.py" --from-tf "${PIPELINE_DIR}/infra/modules/storage" \
  --policy "${PIPELINE_DIR}/docs/governance/evidence-retention-policy.md" \
  --out "${EVID}/retention-policy.json" >/dev/null 2>&1 \
  || true   # honest INDETERMINATE (exit 2) is expected offline — the artifact is still written
[ -s "${EVID}/retention-policy.json" ] \
  || echo "WARN: assert-retention produced no retention-policy.json — A.5 verdict missing"

# T-109 — data-residency assertion (Evidence Pack Part 6 / §6.4). Emits residency.json
# recording the deployed Azure region + lawful-transfer basis. Offline there is NO
# `terraform apply`, so we read the SINGLE residency control point var.location from
# the Terraform SOURCE default (infra/variables.tf) rather than a live apply, and
# record applied_region honestly as "not-applied (offline)". The schema + worked
# values are the contract pre-described in docs/poland-residency-summary.pl.md §1.3.
# Legal determinations (transfer_basis etc.) are EVIDENCE-ONLY confirm-before-signoff,
# carried as documented, NOT auto-attested as a legal fact.
RESIDENCY_REGION="$(python3 - "${PIPELINE_DIR}/infra/variables.tf" <<'PY'
import re, sys
try:
    txt = open(sys.argv[1], encoding="utf-8").read()
except OSError:
    print("polandcentral"); sys.exit(0)
# Extract the default of variable "location" (the residency control point).
m = re.search(r'variable\s+"location"\s*\{.*?default\s*=\s*"([^"]+)"', txt, re.S)
print(m.group(1) if m else "polandcentral")
PY
)"
python3 - "${EVID}/residency.json" "${RESIDENCY_REGION}" <<'PY'
import json, sys
out, region = sys.argv[1], sys.argv[2]
# Region -> human-readable geography / at-rest jurisdiction. polandcentral is the
# only worked region; anything else is recorded faithfully but jurisdiction is left
# for confirm-before-signoff rather than guessed.
GEO = {"polandcentral": ("Poland (Warsaw)", "EU/EEA — Poland")}
geography, data_location = GEO.get(
    region, (f"{region} (confirm geography)", "confirm jurisdiction")
)
doc = {
    "schema": "cyberforge.residency/v1",
    "azure_region": region,
    "azure_region_geography": geography,
    "data_location": data_location,
    "transfer_basis": "intra-EU",
    "transfer_mechanism": None,
    "subprocessors_outside_eea": False,
    "data_plane_stages": [
        "azure-container-registry",
        "azure-container-apps",
        "azure-key-vault",
        "evidence-worm-blob",
    ],
    "egress_to_confirm": [
        {
            "stage": "github-actions-runner",
            "reason": "build/scan + security-gate execute on GitHub-hosted runners; commit metadata contains PII",
            "status": "confirm-per-engagement",
        }
    ],
    "retention_days": 1825,
    "source_of_truth": {
        "region": "infra/variables.tf:var.location",
        "applied_region": "terraform output / azurerm_resource_group.this.location",
    },
    # Honest offline note: no `terraform apply` ran in this offline maker, so the
    # APPLIED region is not measured here — azure_region is the source-of-truth
    # default (var.location), to be reconciled against the applied region at deploy.
    "applied_region": "not-applied (offline sample-pack run)",
    "confirm_before_signoff": [
        "applied region matches azure_region",
        "no sub-processor egresses EU/EEA (or transfer_mechanism recorded)",
        "GitHub Actions runner residency confirmed or SCCs-covered",
    ],
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(f">>> residency.json emitted (azure_region={region})")
PY

# T-55 — reproducibility statement (spec Part I.4). Generate via the real script's
# --emit path. Offline there is no provenance and no docker rebuild, so the script
# honestly records verdict DESIGN-ONLY with digest_match_demonstrated=false and
# byte_reproducibility_status=TARGET-STATE. We anchor it to the REAL HEAD commit of
# this repo (honest pinned input) when git is available, so the statement reflects
# the actual commit the pack was built from rather than "unknown". The artifact
# (with git_commit + rebuild_procedure) is what T-55 requires; the verdict is not faked.
REPRO_COMMIT="$(git rev-parse HEAD 2>/dev/null || true)"
if [ -n "${REPRO_COMMIT}" ]; then
  bash "${S}/verify-reproducibility.sh" --git-commit "${REPRO_COMMIT}" \
    --emit "${EVID}/reproducibility-statement.json" >/dev/null 2>&1 || true
else
  bash "${S}/verify-reproducibility.sh" \
    --emit "${EVID}/reproducibility-statement.json" >/dev/null 2>&1 || true
fi
# INDETERMINATE (exit 2) / DESIGN-ONLY is the honest offline verdict; artifact still written.
[ -s "${EVID}/reproducibility-statement.json" ] \
  || echo "WARN: verify-reproducibility produced no reproducibility-statement.json (T-55)"

# T-35 — copy the signed A.1-A.10 verdicts + compliance gate alongside (already in
# ${EVID} from the seed + aggregate step: compliance-status.json is the gate).

# Re-aggregation pass (T-30/T-73): the FIRST aggregate-compliance.py call above ran
# BEFORE the Part-C/D verdicts (threat-model-validation.json, runtime-hardening.json,
# residual-risk.json, scope-determination.json, vex/soa/cloud/source-control/crosswalk
# /gap) were generated, so those REQUIRED BLOCKING rows would otherwise read as
# missing-verdict FAIL. The aggregator is idempotent; re-run it now with --no-run so
# it INGESTS the already-produced Part-C/D verdicts (it does NOT re-run validators)
# and writes the full A.1-A.10 + Part-C/D compliance-status.json. Honest FAIL rows
# (e.g. A.10 restore-test) are preserved — this only stops the FALSE missing-verdict
# failures for controls that were simply generated after the first pass.
say "re-aggregate A.1-A.10 + Part-C/D verdicts (idempotent --no-run pass)"
python3 "${S}/aggregate-compliance.py" "${EVID}" --no-run >/dev/null 2>&1 || true

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
