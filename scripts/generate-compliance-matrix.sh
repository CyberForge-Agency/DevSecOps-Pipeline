#!/usr/bin/env bash
set -euo pipefail

# generate-compliance-matrix.sh — the compliance-matrix ORCHESTRATOR (T-12).
#
# WHAT CHANGED (T-12 keystone): this script used to be pure file-presence —
# `[ -f file ] && echo PASS` (the old check_file/check_all helpers). That meant an
# empty `{}` security-report.json, or one with 500 CRITICAL CVEs, both yielded
# "PASS" for DORA Art.16.1.a — the single fact a technical buyer needs ~60 seconds
# to falsify every "we check DORA/NIS2" claim (blueprint/04 §1.1; GTM-RESET §4).
#
# Now this script is an *orchestrator*: each of the 21 rows calls a small,
# single-purpose content validator that PARSES the artifact, ASSERTS the real
# threshold, and emits the libcompliance envelope
# `{status, tier, measured, threshold, detail, tool_version, validator, checked_at}`.
# An empty/missing artifact yields INDETERMINATE, never a silent PASS.
#
# Dispatch lives in scripts/validators/matrix_rows.py (the keystone module
# T-13..T-17 extend). This shell only maps row -> validator-id and assembles JSON.
#
# CONTENT-VALIDATED ROWS (T-13 — the three highest-visibility rows):
#   * DORA Art.16.1.a / ISO A.8.28 / SOC2 PI1.1  (validator-id: vuln-scan)
#       parses security-report.json + its embedded Trivy Results, counts CRITICAL/
#       HIGH CVEs; PASS iff CRITICAL==0 AND >=1 scan Result parsed; an empty {} or a
#       report with no Results -> INDETERMINATE (closes the "{} PASSes DORA 16.1.a"
#       hole, K1); any CRITICAL -> FAIL. tool_version read from trivy-*-summary.json.
#       Tier BLOCKING. (blueprint/04 §3.1; spec Part C.4)
#   * DORA Art.16.1.c          (validator-id: sca-scan -> validators/dora_16_1_c.py)
#       asserts the SCA gate filter includes CRITICAL+HIGH AND app/.trivyignore has 0
#       unjustified/expired suppressions (shared T-02 linter scripts/lint-trivyignore.py)
#       AND dependency-review.json is a real Trivy report (has Results), not a renamed
#       copy. Tier BLOCKING. A silently-added CVE waiver now FAILs the row (closes K3).
#       (T-14; blueprint/04 §3.2; spec Part C.5)
#   * NIS2 Art.21.2.b                            (validator-id: dast-findings)
#       parses zap-report.json, counts alerts with riskcode>=3 (the same parse the
#       DAST incident-issue uses); PASS iff 0 HIGH/CRITICAL; empty/no-site ->
#       INDETERMINATE; any riskcode>=3 alert -> FAIL. Tier BLOCKING.
#       (blueprint/04 §3.5; spec Part C.8)
#   * NIS2 Art.21.2.d / DORA Art.28  (validator-id: sbom-supply-chain ->
#       validators/nis2_21_2_d.py) asserts (a) sbom.cyclonedx.json is schema-valid
#       CycloneDX (bomFormat==CycloneDX, specVersion present, components>0) AND
#       (b) the SBOM is the one cryptographically attested to the DEPLOYED DIGEST —
#       re-running `cosign verify-attestation --type cyclonedx` with the tightened
#       T-08 identity when cosign+the image are reachable, else verifying the sealed
#       cosign-attestation-verification.log (Rekor-inclusion marker + digest match).
#       A malformed/empty SBOM or an SBOM not attested to the digest now FAILs;
#       an unmeasurable binding is INDETERMINATE, never a silent PASS. Tier BLOCKING.
#       (T-15; blueprint/04 §3.3; spec §4 SBOM/Provenance; spec Part C.10/C.12/F.4)
#   * NIS2 Art.21.2.h / SOC2 CC7.1  (validator-id: crypto-signing ->
#       validators/nis2_21_2_h.py) RE-RUNS `cosign verify --output json` against the
#       deployed image@DIGEST (never the tag) with the tightened T-08 identity and
#       asserts exit 0, parsing the Rekor logIndex + certificate identity into the
#       row detail. Live re-verify when cosign+the image are reachable, else the
#       sealed cosign-verification.log (accepted only if it records a successful
#       verify AND the deployed digest appears in it). A tampered/absent signature,
#       identity mismatch, or a log bound to a different digest now FAILs the row;
#       an unmeasurable verify is INDETERMINATE, never a silent PASS. Tier BLOCKING.
#       (T-16; blueprint/04 §3.4; spec Part C.12/H.4)
#   * ISO A.8.25 secure-design (validator-id: threat-model ->
#       validators/threat_model.py) parses the structured STRIDE threat model
#       (threat-model.yaml copied into the evidence dir) and asserts it is
#       schema-complete (every threat traced to a control_ref/gap_ref), spans the
#       full STRIDE set, and was reviewed within the freshness window — the spec
#       Part C.1 PASS criterion + §4 "single stale doc" rejection trigger, NOT a
#       file-presence check. A missing/empty/stale model FAILs or is INDETERMINATE,
#       never a silent PASS. Tier BLOCKING. (T-115; spec Part C.1; §4 Plan stage)
#   * ISO A.8.4/A.8.9 + SOC2 CC6.1/CC8.1 + NIS2 21.2.e + RODO Art.30
#       (validator-id: pipeline-gates) parse pipeline-run.json and assert (a) every
#       recorded gate result == "success" (a gate "failure" -> FAIL; "unknown"/
#       "skipped" -> INDETERMINATE) AND (b) the run SHA matches the DEPLOYED
#       provenance commit (the T-17 sha-binding folded in by the finalize step
#       below). A gate-result row PASSes only when BOTH halves hold; a green
#       pipeline-run.json paired with a provenance for a different commit now FAILs.
#       Tier BLOCKING. (T-17; blueprint/04 §3.6; spec Parts D.1/D.2/H)
#   * DORA Art.16.1.d (validator-id: anomaly-detection) reads pipeline-run.json and
#       records that a run with a run_id occurred — EVIDENCE-ONLY (the pipeline
#       cannot prove "anomaly detection" as a gate, only that a run was recorded).
#   * RODO Art.5.1.c/5.1.e/28 (validator-id: dpa-register) + RODO Art.25
#       (validator-id: data-flow) parse dpa-compliance-check.json / data-flow-
#       diagram.json and record the measured vendor / stage counts — EVIDENCE-ONLY
#       descriptive rows (register-freshness BLOCKING half is owned by T-21/T-31).
#       (T-17; blueprint/04 §3.6) An empty/missing artifact is INDETERMINATE for all
#       of the above, never a silent PASS.
#   The measured number (not a vibe) is carried into the row's "measured" field so an
#   auditor reads the count, never just PASS/MISSING.
#
# T-18 (tool versions measured, not hardcoded): the finalize step reads the T-32
# tool-versions.json (evidence/tool-versions.json, or $TOOL_VERSIONS_FILE), folds
# each tool's MEASURED version into the tool_version of every row whose validator
# relies on that tool (trivy->vuln-scan/sca-scan, zap->dast-findings, syft|cosign
# ->sbom-supply-chain, cosign->crypto-signing), surfaces it in the row detail, and
# attaches the full inventory as the top-level "tool_versions" block. No version
# is hardcoded; a missing/placeholder version leaves the validator's own value
# untouched (never fabricated). blueprint/04 §7; spec X.3.
#
# Exit code: 0 unless a BLOCKING row is FAIL/INDETERMINATE (then 1) — so an
# incomplete or over-threshold pack cannot be silently sealed. EVIDENCE-ONLY rows
# never change the exit code.
#
# Usage: generate-compliance-matrix.sh <evidence-dir>   (defaults to ".")

EVIDENCE_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATOR="${SCRIPT_DIR}/validators/matrix_rows.py"

# T-18: measured tool-version inventory (produced by generate-tool-versions.sh /
# T-32, written to evidence/tool-versions.json). The matrix MUST cite the
# versions that ACTUALLY ran, never hardcoded guesses (blueprint/04 §7; spec X.3
# "Tool & version inventory"). The finalize step below reads this file and folds
# each tool's MEASURED version into the row whose validator relies on that tool,
# and attaches the full inventory to the matrix output. The file is optional: if
# it is absent/empty/unparseable, rows keep whatever tool_version their own
# validator parsed (we never fabricate a version). The TOOL_VERSIONS_FILE env var
# allows pointing at a tool-versions.json outside the evidence dir (e.g. a job
# that wrote it to a sibling path).
TOOL_VERSIONS_FILE="${TOOL_VERSIONS_FILE:-${EVIDENCE_DIR}/tool-versions.json}"

# Dedicated single-row validator modules (T-13..T-17 may promote a row out of the
# matrix_rows.py dispatch into its own module without changing the orchestrator
# contract). A dedicated module is invoked as `python3 <module> <evidence-dir>`
# (NO validator-id arg) and emits the same libcompliance envelope.
#
# T-14: DORA Art.16.1.c gets its own `dora_16_1_c.py` so the row asserts the SCA
# severity gate (CRITICAL+HIGH) AND 0 unjustified/expired .trivyignore suppressions
# (shared T-02 linter) AND that dependency-review.json is a real Trivy report —
# instead of trusting a renamed `cp` of the SCA results (closes K3).
#
# T-15: the supply-chain rows (NIS2 Art.21.2.d + DORA Art.28, validator-id
# `sbom-supply-chain`) get their own `nis2_21_2_d.py` so the row asserts the
# CycloneDX SBOM is schema-valid with >=1 component AND is the artifact
# cryptographically attested to the deployed digest — `cosign verify-attestation
# --type cyclonedx` re-run live when cosign+the image are reachable, else the
# sealed cosign-attestation-verification.log proof. A malformed SBOM (missing
# specVersion / 0 components) or one not attested to the digest now FAILs the row;
# an unmeasurable binding is INDETERMINATE, never a silent PASS (blueprint/04 §3.3).
#
# T-16: the cryptography rows (NIS2 Art.21.2.h + SOC2 CC7.1, validator-id
# `crypto-signing`) get their own `nis2_21_2_h.py` so the row RE-EXECUTES
# `cosign verify --output json` against the deployed image@DIGEST (never the tag)
# with the tightened T-08 identity and asserts exit 0 — recording the Rekor
# logIndex + certificate identity into the row detail. Live re-verify when cosign+
# the image are reachable, else the sealed cosign-verification.log (accepted only
# if it records a successful verify AND the deployed digest appears in it). A
# tampered/absent signature, an identity mismatch, or a log bound to a different
# digest now FAILs the row; verifying a tag instead of a digest is rejected before
# cosign runs; an unmeasurable verify is INDETERMINATE, never a silent PASS
# (blueprint/04 §3.4; spec Part C.12/H.4).
dedicated_module_for() {
  case "$1" in
    sca-scan)          printf '%s' "${SCRIPT_DIR}/validators/dora_16_1_c.py" ;;
    sbom-supply-chain) printf '%s' "${SCRIPT_DIR}/validators/nis2_21_2_d.py" ;;
    crypto-signing)    printf '%s' "${SCRIPT_DIR}/validators/nis2_21_2_h.py" ;;
    threat-model)      printf '%s' "${SCRIPT_DIR}/validators/threat_model.py" ;;
    *)                 printf '' ;;
  esac
}

# T-115: the secure-design row (ISO A.8.25 / NIS2 Art.21.2.e) routes through the
# dedicated threat_model.py content validator (mirroring how DORA 16.1.c routes
# through dora_16_1_c.py). UNLIKE the other dedicated modules, threat_model.py is
# invoked with a YAML *file path* (not an evidence-dir) plus an optional --out:
#
#     python3 scripts/validators/threat_model.py <threat-model.yaml> --out /dev/null
#
# so the orchestrator must pass the threat-model artifact INSIDE the evidence dir
# (make-sample-pack.sh copies docs/security/threat-model.yaml to
# <evidence-dir>/threat-model.yaml) rather than the evidence-dir itself. We pass
# --out /dev/null so the row does not write a side-file into the evidence dir
# (the integration phase owns artifact generation); the envelope still prints to
# stdout exactly like every other dedicated module. A missing/empty threat-model
# YAML yields INDETERMINATE (BLOCKING), never a silent PASS — the validator's own
# honesty rule, not a file-presence check. The TOOL_VERSIONS_FILE-independent
# tool_version (pyyaml) is parsed by the validator itself.
THREAT_MODEL_FILE="${THREAT_MODEL_FILE:-${EVIDENCE_DIR}/threat-model.yaml}"

# row <framework-article> <requirement> <evidence-label> <validator-id>
#   Invokes the python content validator for one row, then merges the human-facing
#   fields with the validator's envelope (status/tier/measured/threshold/detail/
#   tool_version) into a single JSON row object. A single python call per row both
#   runs the validator-id parse AND assembles the row, so types are preserved and
#   a malformed/empty envelope can never be silently rendered as PASS.
#
#   The orchestrator exit signal (BLOCKING row non-PASS) is derived AFTER assembly
#   from the emitted JSON (see "blocking_failures" below) — counting in this
#   function would be lost across the command-substitution subshell.
row() {
  local article="$1" requirement="$2" evidence="$3" validator_id="$4"
  local envelope dedicated
  dedicated="$(dedicated_module_for "${validator_id}")"
  set +e
  if [ "${validator_id}" = "threat-model" ]; then
    # T-115: threat_model.py takes a YAML file path (the artifact copied into the
    # evidence dir) + --out, NOT an evidence-dir. See dedicated_module_for note.
    envelope="$(python3 "${dedicated}" "${THREAT_MODEL_FILE}" --out /dev/null 2>/dev/null)"
  elif [ -n "${dedicated}" ]; then
    envelope="$(python3 "${dedicated}" "${EVIDENCE_DIR}" 2>/dev/null)"
  else
    envelope="$(python3 "${VALIDATOR}" "${validator_id}" "${EVIDENCE_DIR}" 2>/dev/null)"
  fi
  set -e
  ARTICLE="${article}" REQUIREMENT="${requirement}" EVIDENCE_LABEL="${evidence}" \
  VALIDATOR_ID="${validator_id}" python3 - "${envelope}" <<'PY'
import json, os, sys
raw = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    env = json.loads(raw) if raw.strip() else {}
    if not isinstance(env, dict):
        raise ValueError("envelope is not an object")
except Exception as exc:  # noqa: BLE001 - never let a bad envelope read as PASS
    env = {"status": "INDETERMINATE", "tier": "BLOCKING", "measured": None,
           "threshold": None, "detail": f"validator produced no/invalid output: {exc}",
           "tool_version": None}
row = {
    "article": os.environ["ARTICLE"],
    "requirement": os.environ["REQUIREMENT"],
    "evidence": os.environ["EVIDENCE_LABEL"],
    "validator": os.environ["VALIDATOR_ID"],
    "status": env.get("status", "INDETERMINATE"),
    "tier": env.get("tier", "BLOCKING"),
    "measured": env.get("measured"),
    "threshold": env.get("threshold"),
    "detail": env.get("detail", ""),
    "tool_version": env.get("tool_version"),
}
sys.stdout.write("      " + json.dumps(row))
PY
}

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --------------------------------------------------------------------------- #
# T-17: run-SHA <-> provenance-commit binding (blueprint/04 §3.6)              #
# --------------------------------------------------------------------------- #
# §3.6 requires the gate-result rows to assert TWO things: (a) every relevant
# gate == "success" (done by the `pipeline-gates` validator) AND (b) the run SHA
# recorded in pipeline-run.json matches the commit the DEPLOYED provenance was
# built from. Without (b) a green pipeline-run.json could be paired with a
# provenance for a DIFFERENT commit — the gate results would then describe a run
# that never produced the attested artifact. This function computes that binding
# ONCE (it is a property of the pack, not of any single row) and the finalize
# step below folds it into every BLOCKING `pipeline-gates` row.
#
# Honesty rules (same as every validator): a missing/empty pipeline-run.json or
# provenance.intoto.jsonl, or a `trigger.sha` / `gitCommit` that is absent or the
# placeholder "unknown", yields INDETERMINATE (we measured no binding) — never a
# silent PASS. A present-on-both-sides MISMATCH yields FAIL. Only an exact match
# yields PASS. The measured SHAs are carried so an auditor reads the values.
sha_provenance_binding() {
  EVIDENCE_DIR="${EVIDENCE_DIR}" python3 - <<'PY'
import json, os
from pathlib import Path

ev = Path(os.environ["EVIDENCE_DIR"])
PLACEHOLDER = {"", "unknown", "none", "null"}


def indeterminate(detail, run_sha=None, prov_sha=None):
    return {"status": "INDETERMINATE", "measured": {"run_sha": run_sha,
            "provenance_commit": prov_sha}, "threshold": "run_sha == provenance_commit",
            "detail": detail}


# 1) run SHA from pipeline-run.json (trigger.sha; tolerate top-level "sha").
run_path = ev / "pipeline-run.json"
run_sha = None
if not run_path.is_file() or run_path.stat().st_size == 0:
    print(json.dumps(indeterminate(f"pipeline-run.json: {'missing' if not run_path.is_file() else 'empty'}")))
    raise SystemExit
try:
    run = json.loads(run_path.read_text(encoding="utf-8") or "{}")
except json.JSONDecodeError as exc:
    print(json.dumps(indeterminate(f"pipeline-run.json: invalid JSON ({exc})")))
    raise SystemExit
if isinstance(run, dict):
    trig = run.get("trigger") if isinstance(run.get("trigger"), dict) else {}
    run_sha = trig.get("sha") or run.get("sha")
run_sha = (str(run_sha).strip() if run_sha is not None else None)
if not run_sha or run_sha.lower() in PLACEHOLDER:
    print(json.dumps(indeterminate("pipeline-run.json has no usable trigger.sha", run_sha)))
    raise SystemExit

# 2) provenance commit from provenance.intoto.jsonl (first in-toto Statement's
#    SLSA resolvedDependencies[].digest.gitCommit).
prov_path = ev / "provenance.intoto.jsonl"
if not prov_path.is_file() or prov_path.stat().st_size == 0:
    print(json.dumps(indeterminate(
        f"provenance.intoto.jsonl: {'missing' if not prov_path.is_file() else 'empty'}", run_sha)))
    raise SystemExit
prov_sha = None
for line in prov_path.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        stmt = json.loads(line)
    except json.JSONDecodeError:
        continue
    pred = stmt.get("predicate", {}) if isinstance(stmt, dict) else {}
    bd = pred.get("buildDefinition", {}) if isinstance(pred, dict) else {}
    for dep in bd.get("resolvedDependencies", []) or []:
        gc = (dep.get("digest", {}) or {}).get("gitCommit") if isinstance(dep, dict) else None
        if gc:
            prov_sha = str(gc).strip()
            break
    if prov_sha:
        break
if not prov_sha or prov_sha.lower() in PLACEHOLDER:
    print(json.dumps(indeterminate(
        "provenance.intoto.jsonl has no resolvedDependencies gitCommit", run_sha, prov_sha)))
    raise SystemExit

# 3) compare (full SHA equality; also accept a short-vs-full prefix match so a
#    7-char short SHA on one side is not a false mismatch).
matched = run_sha == prov_sha or run_sha.startswith(prov_sha) or prov_sha.startswith(run_sha)
status = "PASS" if matched else "FAIL"
detail = (f"run SHA {run_sha} {'==' if matched else '!='} provenance commit {prov_sha}")
print(json.dumps({"status": status,
                  "measured": {"run_sha": run_sha, "provenance_commit": prov_sha},
                  "threshold": "run_sha == provenance_commit", "detail": detail}))
PY
}

# Compute the binding once; reused by the finalize step for every gate-result row.
SHA_BINDING="$(EVIDENCE_DIR="${EVIDENCE_DIR}" sha_provenance_binding 2>/dev/null)"

# Build each framework's rows into a buffer so we can compute the exit code AFTER
# every validator has run, then print the assembled JSON once.
DORA_ROWS="$(
  row "Art.16.1.a" "ICT risk management" "security-report.json (+embedded Trivy Results)" "vuln-scan"; printf ',\n'
  row "Art.16.1.c" "Updated systems" "trivy-sca-summary.json + dependency-review.json" "sca-scan"; printf ',\n'
  row "Art.16.1.d" "Anomaly detection" "pipeline-run.json" "anomaly-detection"; printf ',\n'
  row "Art.28" "Supply chain risk" "sbom.cyclonedx.json + provenance.intoto.jsonl" "sbom-supply-chain"
)"
NIS2_ROWS="$(
  row "Art.21.2.b" "Incident handling" "zap-report.json" "dast-findings"; printf ',\n'
  row "Art.21.2.d" "Supply chain security" "sbom.cyclonedx.json + provenance.intoto.jsonl" "sbom-supply-chain"; printf ',\n'
  row "Art.21.2.e" "Secure development" "pipeline-run.json" "pipeline-gates"; printf ',\n'
  row "Art.21.2.h" "Cryptography" "cosign-verification.log" "crypto-signing"
)"
ISO_ROWS="$(
  row "A.8.4" "Access to source code" "pipeline-run.json" "pipeline-gates"; printf ',\n'
  row "A.8.9" "Configuration management" "pipeline-run.json" "pipeline-gates"; printf ',\n'
  row "A.8.25" "Secure SDLC (threat model)" "threat-model.yaml" "threat-model"; printf ',\n'
  row "A.8.28" "Secure coding" "security-report.json" "vuln-scan"
)"
SOC2_ROWS="$(
  row "CC6.1" "Logical access" "pipeline-run.json" "pipeline-gates"; printf ',\n'
  row "CC7.1" "System operations" "cosign-verification.log" "crypto-signing"; printf ',\n'
  row "CC8.1" "Change management" "pipeline-run.json" "pipeline-gates"; printf ',\n'
  row "PI1.1" "Processing integrity" "security-report.json" "vuln-scan"
)"
RODO_ROWS="$(
  row "Art.5.1.c" "Data minimization" "dpa-compliance-check.json" "dpa-register"; printf ',\n'
  row "Art.5.1.e" "Storage limitation" "dpa-compliance-check.json" "dpa-register"; printf ',\n'
  row "Art.25" "Data protection by design" "data-flow-diagram.json" "data-flow"; printf ',\n'
  row "Art.28" "Processor agreements" "dpa-compliance-check.json" "dpa-register"; printf ',\n'
  row "Art.30" "Records of processing" "pipeline-run.json" "pipeline-gates"
)"
# Part-G governance / operational-resilience controls (C.9 / E.1 / E.2 / E.4 /
# A.7.7). Each routes through a DEDICATED file-driven validator (check_pentest.py
# etc.) whose T-33 envelope is emitted into the evidence dir BEFORE this matrix
# runs (make-sample-pack.sh / evidence-pack.yml), then READ BACK here by the
# matrix_rows.py dispatch id — mirroring how dora_16_1_c / threat-model route to
# dedicated validators, except these read the already-sealed envelope (single
# source of truth). BLOCKING where the obligation is mandatory; TLPT is dynamic
# (EVIDENCE-ONLY out-of-scope, BLOCKING when in scope) and access-log is
# EVIDENCE-ONLY. Honest defaults flow straight through (pentest FAIL, ICT-risk
# INDETERMINATE, resilience FAIL, access-log INDETERMINATE, asset-map PASS,
# TLPT documented-out-of-scope PASS/EVIDENCE-ONLY).
GOVERNANCE_ROWS="$(
  row "DORA Art.24-26 / NIS2 21(2)(e) / ISO A.8.8" "Penetration testing (independent, >= annual, signed, findings retested)" "pentest-report.json" "pentest"; printf ',\n'
  row "DORA Art.26-27 / RTS (EU) 2025/1190" "DORA Threat-Led Penetration Testing (TLPT)" "tlpt-record.json" "tlpt"; printf ',\n'
  row "DORA Art.6 / NIS2 21(2)(a) / ISO Cl.6.1,8.2" "ICT risk-management framework + annual review" "ict-risk-framework.json" "ict-risk-framework"; printf ',\n'
  row "DORA Art.8" "Asset / dependency & critical-function map" "asset-map.json" "asset-map"; printf ',\n'
  row "DORA Art.24-25" "Digital operational resilience testing programme" "resilience-programme.json" "resilience-programme"; printf ',\n'
  row "SPEC §7 item 7 / ISO A.8.15,A.5.28 / DORA Art.9(3)" "Tamper-evident evidence-store access log" "access-log-posture.json" "access-log"
)"

# Assemble the matrix JSON (blocking_failures is finalised by python below).
MATRIX_JSON="$(cat <<EOF
{
  "generated_at": "${GENERATED_AT}",
  "schema": "cyberforge-compliance-matrix/v2-content-validated",
  "blocking_failures": 0,
  "frameworks": {
    "DORA": [
${DORA_ROWS}
    ],
    "NIS2": [
${NIS2_ROWS}
    ],
    "ISO27001": [
${ISO_ROWS}
    ],
    "SOC2": [
${SOC2_ROWS}
    ],
    "RODO": [
${RODO_ROWS}
    ],
    "GOVERNANCE": [
${GOVERNANCE_ROWS}
    ]
  }
}
EOF
)"

# Finalise: (1) fold the T-17 run-SHA<->provenance binding into every BLOCKING
# `pipeline-gates` row (a gate-result row PASSes only if its gates succeeded AND
# the run SHA matches the deployed provenance commit), (2) T-18: fold the MEASURED
# tool-version inventory (tool-versions.json) into each row's tool_version and
# detail and attach the full inventory to the matrix, (3) count BLOCKING rows
# whose status is not PASS, write the real blocking_failures count, print the
# canonical JSON, and exit non-zero if any BLOCKING row failed/was indeterminate.
# Honesty: an incomplete/over-threshold pack must NOT be silently sealable.
# EVIDENCE-ONLY rows never change the exit code.
python3 - "${MATRIX_JSON}" "${SHA_BINDING}" "${TOOL_VERSIONS_FILE}" <<'PY'
import json, sys
from pathlib import Path

data = json.loads(sys.argv[1])

# Parse the precomputed SHA-binding envelope (INDETERMINATE if it produced
# nothing — a bad/empty binding can never be read as a passing constraint).
raw_binding = sys.argv[2] if len(sys.argv) > 2 else ""
try:
    binding = json.loads(raw_binding) if raw_binding.strip() else {}
    if not isinstance(binding, dict):
        raise ValueError("binding is not an object")
except Exception as exc:  # noqa: BLE001 - never let a bad binding read as PASS
    binding = {"status": "INDETERMINATE", "measured": None,
               "threshold": "run_sha == provenance_commit",
               "detail": f"sha-binding produced no/invalid output: {exc}"}
binding_status = binding.get("status", "INDETERMINATE")
binding_detail = binding.get("detail", "")

# Status precedence when combining a row's own gate result with the binding:
# FAIL is strictest, then INDETERMINATE, then PASS. A gate-result row is PASS
# only when BOTH the gates succeeded AND the SHA binding holds.
_RANK = {"FAIL": 2, "INDETERMINATE": 1, "PASS": 0}


def _combine(a, b):
    return a if _RANK.get(a, 1) >= _RANK.get(b, 1) else b


for rows in data.get("frameworks", {}).values():
    for r in rows:
        # Only the BLOCKING pipeline-run.json gate-result rows carry the §3.6
        # SHA binding. EVIDENCE-ONLY rows (anomaly-detection, RODO descriptive)
        # and non-pipeline rows are untouched.
        if r.get("validator") != "pipeline-gates" or r.get("tier") != "BLOCKING":
            continue
        combined = _combine(r.get("status", "INDETERMINATE"), binding_status)
        if combined != r.get("status"):
            r["status"] = combined
        # Record the measured binding alongside the gate measurement so an
        # auditor reads the two SHAs, not just PASS/FAIL.
        measured = r.get("measured")
        if not isinstance(measured, dict):
            measured = {} if measured is None else {"_value": measured}
        measured["sha_binding"] = {
            "status": binding_status,
            **(binding.get("measured") or {}),
        }
        r["measured"] = measured
        r["detail"] = f"{r.get('detail', '')}; sha-binding: {binding_detail}".lstrip("; ")

# --------------------------------------------------------------------------- #
# T-18: fold the MEASURED tool-version inventory into the matrix.              #
# --------------------------------------------------------------------------- #
# generate-tool-versions.sh (T-32) writes evidence/tool-versions.json with the
# shape {"measured_at", "source", "tools": {"<tool>": {"version","raw","present"}}}.
# The matrix must cite the versions that ACTUALLY ran (blueprint/04 §7; spec X.3),
# so we read that file and:
#   (a) attach the full inventory to the matrix as "tool_versions" (the auditor
#       reads which scanner versions produced the evidence), and
#   (b) set each row's tool_version from the MEASURED version of the tool its
#       validator relies on — authoritative over the per-scanner-summary value a
#       validator may have parsed, because tool-versions.json is the canonical
#       "what ran" record and is free of the junk a live `cosign version` banner
#       can leak into a summary.
# Honesty rules:
#   * The file is OPTIONAL. Missing/empty/unparseable -> rows keep their own
#     validator-parsed tool_version; we never fabricate one.
#   * A tool recorded as not-present / present-unparsed / empty is NOT a usable
#     version: such rows keep their existing tool_version (no fabrication).
#   * Rows whose validator has no associated scanner tool (pipeline-gates,
#     anomaly-detection, dpa-register, data-flow) are left untouched.

# validator-id -> the canonical scanner tool(s) that produced its evidence. The
# FIRST tool with a usable measured version wins (e.g. the SBOM row prefers syft,
# falling back to cosign for the attestation re-verify).
_VALIDATOR_TOOLS = {
    "vuln-scan": ("trivy",),            # security-report.json embeds Trivy Results
    "sca-scan": ("trivy",),             # Trivy SCA + dependency-review
    "dast-findings": ("zap",),          # zap-report.json
    "sbom-supply-chain": ("syft", "cosign"),  # syft SBOM, attested via cosign
    "crypto-signing": ("cosign",),      # cosign verify
}

_PLACEHOLDER_VERSIONS = {"", "not-present", "present-unparsed", "none", "null", "unknown"}


def _load_tool_versions(path_str):
    """Return (tools_map, source_note). Never raises; missing/bad -> ({}, note)."""
    p = Path(path_str)
    if not p.is_file() or p.stat().st_size == 0:
        return {}, ("missing" if not p.is_file() else "empty")
    try:
        raw = json.loads(p.read_text(encoding="utf-8") or "{}")
    except (json.JSONDecodeError, OSError) as exc:
        return {}, f"invalid ({exc})"
    tools = raw.get("tools") if isinstance(raw, dict) else None
    return (tools if isinstance(tools, dict) else {}), "loaded"


def _measured_version(tools_map, tool_name):
    """The usable measured version for a tool, or None (placeholder/absent)."""
    entry = tools_map.get(tool_name)
    if not isinstance(entry, dict):
        return None
    present = entry.get("present")
    ver = entry.get("version")
    ver = str(ver).strip() if ver is not None else ""
    if present is False or ver.lower() in _PLACEHOLDER_VERSIONS:
        return None
    return ver or None


tool_versions_path = sys.argv[3] if len(sys.argv) > 3 else ""
tools_map, tv_source = _load_tool_versions(tool_versions_path)

# (a) Attach the full inventory to the matrix output so the inventory is
#     referenced by the matrix (blueprint/04 §7). measured_versions is a compact
#     name->version view; tools carries the raw T-32 entries when present.
_inventory = {}
if tools_map:
    for _name, _entry in tools_map.items():
        if isinstance(_entry, dict):
            _inventory[_name] = _entry.get("version")
data["tool_versions"] = {
    "source_file": tool_versions_path,
    "status": tv_source,
    "measured_versions": _inventory,
}

# (b) Fold the measured version into every applicable row.
for rows in data.get("frameworks", {}).values():
    for r in rows:
        candidates = _VALIDATOR_TOOLS.get(r.get("validator"))
        if not candidates:
            continue
        measured_ver = None
        used_tool = None
        for tool_name in candidates:
            mv = _measured_version(tools_map, tool_name)
            if mv:
                measured_ver, used_tool = mv, tool_name
                break
        if not measured_ver:
            continue  # no usable measured version -> keep validator's own value
        prior = r.get("tool_version")
        r["tool_version"] = measured_ver
        note = f"tool_version: {used_tool} {measured_ver} (measured)"
        if prior and str(prior).strip() and str(prior) != measured_ver:
            note += f" [validator-reported: {prior}]"
        r["detail"] = f"{r.get('detail', '')}; {note}".lstrip("; ")

blocking_failures = 0
for rows in data.get("frameworks", {}).values():
    for r in rows:
        if r.get("tier") == "BLOCKING" and r.get("status") != "PASS":
            blocking_failures += 1
data["blocking_failures"] = blocking_failures
print(json.dumps(data, indent=2))
if blocking_failures:
    print(
        f"compliance-matrix: {blocking_failures} BLOCKING row(s) FAIL/INDETERMINATE",
        file=sys.stderr,
    )
    sys.exit(1)
sys.exit(0)
PY
