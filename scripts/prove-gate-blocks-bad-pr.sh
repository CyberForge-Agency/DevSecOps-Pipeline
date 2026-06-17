#!/usr/bin/env bash
set -uo pipefail

# prove-gate-blocks-bad-pr.sh — founder-independent NEGATIVE-TEST harness (T-89).
#
# WHY THIS EXISTS
#   Every other gate in this repo answers "does the GOOD pack pass?". A buyer's
#   first, cheapest falsification is the opposite question: "if I feed you a BAD
#   input, does the gate actually BLOCK — or does it wave everything through?".
#   This script is the deterministic, LOCAL, founder-independent answer. It feeds
#   six KNOWN-BAD inputs straight at the REAL gate logic (the same scripts the CI
#   jobs invoke — no mocks, no re-implementation) and ASSERTS each one BLOCKS
#   (exits non-zero / produces a non-empty OPA deny set). A green run is hard
#   evidence that the gates do their job; a red run means a gate has regressed
#   open and would let a bad PR through.
#
# NEGATIVE TESTS (each must BLOCK)
#   (a) security-report.json with 1 CRITICAL CVE  -> generate-compliance-matrix.sh exit!=0 (FAIL)
#   (b) empty `{}` evidence dir                    -> matrix exit!=0 AND aggregate-compliance exit!=0 (INDETERMINATE)
#   (c) SARIF document with version 2.0.0          -> sarif_conformance.py exit!=0 (FAIL)
#   (d) WORM retention of 365 days (< 1825 floor)  -> assert-retention.py exit!=0 (FAIL)
#   (e) planted unpinned `actions/checkout@v4`     -> check-action-pins.sh exit!=0 (FAIL)
#   (f) OPA deployment-gate input critical_cves=1  -> deny set NON-EMPTY (deploy blocked)
#
# CONTROL ASSERTIONS (each must NOT block — proves the tests are non-vacuous)
#   For the four cases where a "good" counterpart is cheap to construct (a/c/d/f) we
#   also feed the GOOD input and assert the gate PASSes. A gate that blocks BOTH the
#   good and bad input is broken (fail-closed-on-everything), not enforcing. Both the
#   "bad blocks" AND the "good passes" halves must hold for the case to be a PASS.
#
# HONESTY BOUNDARY (read docs/gate-enforcement-proof.md)
#   This proves the ENFORCEMENT LOGIC locally and deterministically. It does NOT and
#   CANNOT claim that a live GitHub PR was blocked by branch protection / required
#   checks — that is T-68 and needs a real CI run + repo settings (NEEDS-CI). This
#   harness asserts the gate *code* blocks bad input; T-68 asserts the *platform*
#   wires that code to merge/deploy. The two are complementary, not the same claim.
#
# USAGE
#   scripts/prove-gate-blocks-bad-pr.sh
#     (no arguments; all fixtures are created under mktemp -d and removed on exit.
#      This script NEVER writes into the repo working tree.)
#
# EXIT CODES
#   0  every bad input was correctly BLOCKED (and every good control PASSed) — the
#      gates did their job
#   1  one or more gates FAILED to block a bad input (or blocked a good one), or a
#      gate could not be exercised (missing dependency) — investigate immediately
#
# DEPENDENCIES: bash, python3, jq, opa (the same tools the gates themselves need).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VALIDATORS="${SCRIPT_DIR}/validators"

MATRIX="${SCRIPT_DIR}/generate-compliance-matrix.sh"
AGGREGATE="${SCRIPT_DIR}/aggregate-compliance.py"
SARIF="${VALIDATORS}/sarif_conformance.py"
RETENTION="${VALIDATORS}/assert-retention.py"
PINS="${SCRIPT_DIR}/check-action-pins.sh"
DEPLOY_POLICY="${REPO_ROOT}/policies/deployment-gate.rego"

# --- workspace: one mktemp tree for all fixtures; never the repo working tree ---
WORK="$(mktemp -d "${TMPDIR:-/tmp}/prove-gate-XXXXXX")"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

# --- results table -------------------------------------------------------------
declare -a ROW_ID=()
declare -a ROW_DESC=()
declare -a ROW_VERDICT=()   # PASS | FAIL
declare -a ROW_DETAIL=()
FAILURES=0

# record <id> <desc> <verdict PASS|FAIL> <detail>
record() {
  ROW_ID+=("$1"); ROW_DESC+=("$2"); ROW_VERDICT+=("$3"); ROW_DETAIL+=("$4")
  [ "$3" = "PASS" ] || FAILURES=$((FAILURES + 1))
}

# A negative test PASSes iff the bad input BLOCKED (rc != 0). 0 means the gate
# let a bad PR through — the worst outcome — so it is recorded as a FAIL.
# blocked_pass <id> <desc> <bad_rc> [good_rc] [control_label]
#   If good_rc is supplied it must be 0 (good input must pass); otherwise the
#   case FAILs as "blocks-everything" (fail-closed-on-all is not enforcement).
blocked_pass() {
  local id="$1" desc="$2" bad_rc="$3" good_rc="${4:-}" ctl="${5:-}"
  if [ "${bad_rc}" -eq 0 ]; then
    record "${id}" "${desc}" "FAIL" "bad input NOT blocked (gate exit 0) — gate is open!"
    return
  fi
  if [ -n "${good_rc}" ] && [ "${good_rc}" -ne 0 ]; then
    record "${id}" "${desc}" "FAIL" \
      "bad blocked (exit ${bad_rc}) BUT good ${ctl} also blocked (exit ${good_rc}) — gate blocks everything, not enforcing"
    return
  fi
  local detail="blocked: gate exit ${bad_rc} (non-zero)"
  [ -n "${good_rc}" ] && detail="${detail}; control good ${ctl} passed (exit 0)"
  record "${id}" "${desc}" "PASS" "${detail}"
}

# --- preflight: required tools / files -----------------------------------------
missing=""
command -v python3 >/dev/null 2>&1 || missing="${missing} python3"
command -v jq      >/dev/null 2>&1 || missing="${missing} jq"
command -v opa     >/dev/null 2>&1 || missing="${missing} opa"
for f in "${MATRIX}" "${AGGREGATE}" "${SARIF}" "${RETENTION}" "${PINS}" "${DEPLOY_POLICY}"; do
  [ -f "${f}" ] || missing="${missing} ${f}"
done
if [ -n "${missing}" ]; then
  echo "ERROR: cannot run gate-enforcement proof; missing:${missing}" >&2
  echo "       (this harness must exercise the REAL gates; it never mocks them)" >&2
  exit 1
fi

echo "== T-89 gate-enforcement proof: feeding KNOWN-BAD inputs at the REAL gates =="
echo "   workspace: ${WORK} (mktemp; auto-removed; repo working tree untouched)"
echo

# --------------------------------------------------------------------------- #
# (a) CRITICAL CVE -> compliance-matrix FAIL                                  #
# --------------------------------------------------------------------------- #
A_BAD="${WORK}/a-critical"; mkdir -p "${A_BAD}"
cat > "${A_BAD}/security-report.json" <<'JSON'
{"reports":{"image":{"Results":[{"Target":"app/package-lock.json",
  "Vulnerabilities":[{"VulnerabilityID":"CVE-2099-0001","Severity":"CRITICAL",
  "PkgName":"evil","InstalledVersion":"1.0.0"}]}]}}}
JSON
bash "${MATRIX}" "${A_BAD}" >/dev/null 2>&1; a_bad_rc=$?

A_GOOD="${WORK}/a-clean"; mkdir -p "${A_GOOD}"
cat > "${A_GOOD}/security-report.json" <<'JSON'
{"reports":{"image":{"Results":[{"Target":"app/package-lock.json","Vulnerabilities":[]}]}}}
JSON
# The clean report still leaves OTHER blocking rows INDETERMINATE in an otherwise
# empty dir, so the matrix exit is not a clean 0 here. We therefore assert the
# control on the vuln-scan ROW itself: it must be PASS (0 CRITICAL), proving the
# CRITICAL case is the discriminator, not a blanket block.
a_good_status="$(bash "${MATRIX}" "${A_GOOD}" 2>/dev/null \
  | jq -r '[.frameworks[][] | select(.validator=="vuln-scan")][0].status' 2>/dev/null)"
if [ "${a_good_status}" = "PASS" ]; then a_good_rc=0; else a_good_rc=1; fi
blocked_pass "a" "1 CRITICAL CVE -> compliance-matrix" "${a_bad_rc}" "${a_good_rc}" \
  "(0-CRITICAL vuln-scan row=${a_good_status:-?})"

# --------------------------------------------------------------------------- #
# (b) empty {} evidence dir -> matrix INDETERMINATE AND aggregate FAIL        #
# --------------------------------------------------------------------------- #
B_DIR="${WORK}/b-empty"; mkdir -p "${B_DIR}"
# Truly empty dir; also drop a literal `{}` security-report.json to exercise the
# "empty artifact must NOT silently PASS" hole (K1) directly.
printf '{}' > "${B_DIR}/security-report.json"
bash "${MATRIX}" "${B_DIR}" >/dev/null 2>&1; b_matrix_rc=$?
python3 "${AGGREGATE}" "${B_DIR}" --no-run >/dev/null 2>&1; b_agg_rc=$?
if [ "${b_matrix_rc}" -ne 0 ] && [ "${b_agg_rc}" -ne 0 ]; then
  record "b" "empty {} evidence dir -> matrix + aggregate" "PASS" \
    "blocked: matrix exit ${b_matrix_rc}, aggregate exit ${b_agg_rc} (both non-zero; no silent PASS)"
else
  record "b" "empty {} evidence dir -> matrix + aggregate" "FAIL" \
    "matrix exit ${b_matrix_rc}, aggregate exit ${b_agg_rc} — an empty pack must block both"
fi

# --------------------------------------------------------------------------- #
# (c) SARIF version 2.0.0 -> sarif_conformance FAIL                           #
# --------------------------------------------------------------------------- #
C_DIR="${WORK}/c-sarif"; mkdir -p "${C_DIR}"
cat > "${C_DIR}/bad.sarif" <<'JSON'
{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.0.0",
 "runs":[{"tool":{"driver":{"name":"codeql","rules":[]}},"results":[]}]}
JSON
python3 "${SARIF}" "${C_DIR}/bad.sarif" --stage codeql --out "${C_DIR}/bad-out.json" >/dev/null 2>&1
c_bad_rc=$?
cat > "${C_DIR}/good.sarif" <<'JSON'
{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",
 "runs":[{"tool":{"driver":{"name":"codeql","rules":[]}},"results":[]}]}
JSON
python3 "${SARIF}" "${C_DIR}/good.sarif" --stage codeql --out "${C_DIR}/good-out.json" >/dev/null 2>&1
c_good_rc=$?
blocked_pass "c" "SARIF version 2.0.0 -> sarif_conformance" "${c_bad_rc}" "${c_good_rc}" \
  "(SARIF 2.1.0)"

# --------------------------------------------------------------------------- #
# (d) retention 365 days (< 1825 floor) -> assert-retention FAIL              #
# --------------------------------------------------------------------------- #
D_DIR="${WORK}/d-retention"; mkdir -p "${D_DIR}"
cat > "${D_DIR}/tf-show-bad.json" <<'JSON'
{"planned_values":{"root_module":{"resources":[
  {"type":"azurerm_storage_container_immutability_policy","name":"worm",
   "values":{"immutability_period_in_days":365,"locked":true}}]}}}
JSON
python3 "${RETENTION}" "${D_DIR}/tf-show-bad.json" --out "${D_DIR}/bad-out.json" >/dev/null 2>&1
d_bad_rc=$?
cat > "${D_DIR}/tf-show-good.json" <<'JSON'
{"planned_values":{"root_module":{"resources":[
  {"type":"azurerm_storage_container_immutability_policy","name":"worm",
   "values":{"immutability_period_in_days":1825,"locked":true}}]}}}
JSON
python3 "${RETENTION}" "${D_DIR}/tf-show-good.json" --out "${D_DIR}/good-out.json" >/dev/null 2>&1
d_good_rc=$?
blocked_pass "d" "WORM retention 365d (<1825 floor) -> assert-retention" "${d_bad_rc}" \
  "${d_good_rc}" "(1825d locked)"

# --------------------------------------------------------------------------- #
# (e) planted unpinned actions/checkout@v4 -> check-action-pins FAIL          #
# --------------------------------------------------------------------------- #
E_BAD="${WORK}/e-unpinned/.github/workflows"; mkdir -p "${E_BAD}"
cat > "${E_BAD}/planted.yml" <<'YAML'
name: planted-bad
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
YAML
bash "${PINS}" "${E_BAD}" >/dev/null 2>&1; e_bad_rc=$?
E_GOOD="${WORK}/e-pinned/.github/workflows"; mkdir -p "${E_GOOD}"
cat > "${E_GOOD}/clean.yml" <<'YAML'
name: planted-good
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
YAML
bash "${PINS}" "${E_GOOD}" >/dev/null 2>&1; e_good_rc=$?
blocked_pass "e" "unpinned actions/checkout@v4 -> check-action-pins" "${e_bad_rc}" \
  "${e_good_rc}" "(SHA-pinned checkout)"

# --------------------------------------------------------------------------- #
# (f) OPA deployment-gate input critical_cves=1 -> deny set NON-EMPTY         #
# --------------------------------------------------------------------------- #
# Mirrors the REAL deploy.yml step exactly:
#   opa eval -d policies/deployment-gate.rego -i input.json
#     'data.compliance.deployment.deny' --format raw   ; deny length != 0 -> exit 1.
F_DIR="${WORK}/f-opa"; mkdir -p "${F_DIR}"
cat > "${F_DIR}/bad-input.json" <<'JSON'
{"image_signed":true,"sbom_attached":true,"critical_cves":1,"tests_passed":true,"coverage_pct":95}
JSON
F_BAD_DENY="$(opa eval -d "${DEPLOY_POLICY}" -i "${F_DIR}/bad-input.json" \
  'data.compliance.deployment.deny' --format raw 2>/dev/null)"
f_bad_len="$(printf '%s' "${F_BAD_DENY}" | jq 'length' 2>/dev/null || echo -1)"
cat > "${F_DIR}/good-input.json" <<'JSON'
{"image_signed":true,"sbom_attached":true,"critical_cves":0,"tests_passed":true,"coverage_pct":95}
JSON
F_GOOD_DENY="$(opa eval -d "${DEPLOY_POLICY}" -i "${F_DIR}/good-input.json" \
  'data.compliance.deployment.deny' --format raw 2>/dev/null)"
f_good_len="$(printf '%s' "${F_GOOD_DENY}" | jq 'length' 2>/dev/null || echo -1)"
if [ "${f_bad_len}" -gt 0 ] && [ "${f_good_len}" -eq 0 ]; then
  record "f" "OPA deployment-gate critical_cves=1 -> deny" "PASS" \
    "blocked: deny=${F_BAD_DENY} (len ${f_bad_len}); control good input deny empty (len 0)"
else
  record "f" "OPA deployment-gate critical_cves=1 -> deny" "FAIL" \
    "bad deny len=${f_bad_len} (want >0), good deny len=${f_good_len} (want 0)"
fi

# --------------------------------------------------------------------------- #
# PASS/FAIL table                                                             #
# --------------------------------------------------------------------------- #
echo "+----+--------------------------------------------------------------+---------+"
printf "| %-2s | %-60s | %-7s |\n" "ID" "NEGATIVE TEST (bad input must BLOCK)" "VERDICT"
echo "+----+--------------------------------------------------------------+---------+"
n=${#ROW_ID[@]}
for ((i = 0; i < n; i++)); do
  printf "| %-2s | %-60s | %-7s |\n" \
    "${ROW_ID[$i]}" "${ROW_DESC[$i]}" "${ROW_VERDICT[$i]}"
done
echo "+----+--------------------------------------------------------------+---------+"
echo
echo "Detail:"
for ((i = 0; i < n; i++)); do
  printf "  (%s) %s\n      %s\n" "${ROW_ID[$i]}" "${ROW_VERDICT[$i]}" "${ROW_DETAIL[$i]}"
done
echo

TOTAL=${#ROW_ID[@]}
PASSED=$((TOTAL - FAILURES))
if [ "${FAILURES}" -eq 0 ]; then
  echo "RESULT: ${PASSED}/${TOTAL} negative tests PASS — every bad input was correctly BLOCKED."
  echo "        The gate ENFORCEMENT LOGIC works locally (NOT a live-PR claim; see T-68 / NEEDS-CI)."
  exit 0
fi
echo "RESULT: ${FAILURES}/${TOTAL} negative tests FAILED — a gate let a bad input through (or blocks everything)."
echo "        A gate has regressed OPEN; do not trust the green pipeline until fixed."
exit 1
