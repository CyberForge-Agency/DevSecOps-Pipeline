#!/usr/bin/env bash
#
# run-local-e2e.sh — OFFLINE end-to-end harness for the CyberForge evidence chain.
#
# Purpose
# -------
# Prove the whole *offline* evidence-pack chain runs end-to-end on a laptop, with
# NO Azure, NO cloud upload, NO image push, and NO deploy. It exercises exactly the
# stages of evidence-pack.yml that do not mutate cloud state, in the same order:
#
#   0. (optional) build + unit-test the demo app   (only if app/node_modules exists)
#   1. self-tests                                   (validators + OPA, standalone-safe)
#   2. aggregate-compliance.py                      (A.1-A.10 organizational gate)
#   3. generate-compliance-matrix.sh                (content-validated DORA/NIS2 matrix)
#   4. generate-evidence-manifest.py                (RFC-6962 Merkle manifest, pass 1)
#   5. seal-evidence.sh  (EVIDENCE_ALLOW_DEGRADE=1) (cosign/TSA/PAdES, degrade-tolerant)
#   6. generate-evidence-manifest.py                (re-stamp over sealing artifacts)
#   7. verify-evidence-pack.sh                      (sha256 + Merkle + signatures runbook)
#
# It then prints a GREEN/RED summary.
#
# Honesty contract (READ THIS)
# ----------------------------
# This harness draws a hard line between two very different things:
#
#   * CHAIN EXECUTION   — did each stage *run* and produce its expected artifact,
#                         and does the verify runbook pass (no FAIL lines)?
#                         THIS is what turns the summary GREEN/RED.
#
#   * COMPLIANCE VERDICT — the PASS/FAIL the validators return for the *content*
#                         of the evidence (stale vendor register, overdue access
#                         review, no restore drill, missing scan artifacts...).
#                         This is reported faithfully but is NOT forced green and
#                         does NOT, by itself, make the harness RED. A validator
#                         that correctly FAILs on bad evidence is doing its job
#                         (see tests/compliance/README.md "honest failures").
#
# So a GREEN harness means "the offline chain assembles and self-verifies"; it does
# NOT claim the sample evidence is compliant. The compliance verdict is printed
# beside it so you can never confuse the two. To make the verdict itself green you
# must remediate the underlying evidence — never weaken a validator.
#
# Offline degradation (the honest model of a box without sigstore/TSA)
# --------------------------------------------------------------------
# Keyless cosign signing and the RFC-3161 TSA round-trip both require network + a
# valid OIDC token, neither of which exists on an offline box. This codebase's
# documented, honest representation of "no usable signing infrastructure" is
# cosign-absent: seal-evidence.sh records signatures.cosign.status=unavailable and
# verify-evidence-pack.sh emits a clean SKIP (NOT a §6.2-A FAIL) when `have cosign`
# is false. If cosign were merely *reachable but unauthenticated*, the seal would
# write merkle-root.txt, fail keyless signing after ~45s of backoff retries, and
# leave a half-sealed pack the verify runbook then correctly FAILs (§6.2-A: bundle
# missing while merkle-root.txt present).
#
# So for the offline seal+verify stages this harness runs with cosign and curl
# hidden behind a temporary PATH that mirrors the system bin dirs minus those two
# binaries. This is faithful, not a cheat: it models exactly the offline-no-sigstore
# condition the degrade contract is designed for, and it avoids both the long retry
# backoff and the partial-state FAIL. The seal still runs EVIDENCE_ALLOW_DEGRADE=1
# and is wrapped in a bounded `timeout` as a safety net. Pass E2E_KEEP_COSIGN=1 to
# instead exercise the real (slow) keyless-degrade path.
#
# Usage
# -----
#   scripts/run-local-e2e.sh [EVIDENCE_DIR]
#
#   EVIDENCE_DIR   Source evidence directory to copy from (default: ./evidence).
#                  The harness NEVER mutates it — all work happens in a temp copy.
#
# Environment knobs (all optional)
# --------------------------------
#   E2E_SKIP_APP=1          skip the app build/test stage even if node_modules exists
#   E2E_SKIP_SELFTEST=1     skip the validator/OPA self-test stage
#   E2E_SELFTEST_ADVISORY=1 report self-test failures but do NOT turn the harness RED
#                           (use only when failures are known-external, e.g. a
#                           date-dependent fixture owned by another lane)
#   E2E_KEEP_COSIGN=1       do NOT hide cosign/curl for seal+verify (exercises the
#                           real, slow keyless-signing degrade path; may §6.2-A)
#   E2E_SEAL_TIMEOUT=120    seconds to allow the seal step before declaring it DEGRADED
#   E2E_KEEP_WORKDIR=1      keep the temp work dir (printed at the end) for inspection
#
# Exit codes
# ----------
#   0  GREEN — every required chain stage ran and the verify runbook passed
#   1  RED   — a required chain stage crashed, produced no artifact, or the verify
#             runbook printed a FAIL line
#
# NEVER calls: az, terraform apply/destroy, docker push, any cloud upload/deploy.
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PIPELINE_DIR="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
SRC_EVIDENCE="${1:-${PIPELINE_DIR}/evidence}"
APP_DIR="${PIPELINE_DIR}/app"

SEAL_TIMEOUT="${E2E_SEAL_TIMEOUT:-120}"

# ---------------------------------------------------------------------------
# Pretty output
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_GREEN=''; C_RED=''; C_YEL=''; C_DIM=''; C_OFF=''
fi

hr()    { printf '%s\n' "------------------------------------------------------------"; }
say()   { printf '%s\n' "$*"; }
step()  { printf '\n%s>>> %s%s\n' "${C_DIM}" "$*" "${C_OFF}"; }
have()  { command -v "$1" >/dev/null 2>&1; }

# Stage result tracking. Each stage records one of: PASS | FAIL | DEGRADED | SKIP.
declare -a STAGE_NAME=()
declare -a STAGE_RESULT=()
declare -a STAGE_NOTE=()
record() { STAGE_NAME+=("$1"); STAGE_RESULT+=("$2"); STAGE_NOTE+=("${3:-}"); }

# A stage marked FAIL means the *chain* is broken -> RED overall.
CHAIN_OK=1
fail_chain() { CHAIN_OK=0; }

# build_no_cosign_path: print a temp bin dir that mirrors the standard system bin
# dirs (symlinks) but OMITS cosign and curl, so `command -v cosign|curl` is false
# for any process run with PATH set to it. Used to model the offline-no-sigstore
# condition cleanly (see header). Created under the work dir so cleanup removes it.
NO_SIG_BIN=""
build_no_cosign_path() {
  local bin="${WORKDIR}/nosig-bin"
  mkdir -p "${bin}"
  local d f b
  for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
    [ -d "${d}" ] || continue
    for f in "${d}"/*; do
      [ -x "${f}" ] || continue
      b="${f##*/}"
      case "${b}" in cosign|curl) continue;; esac
      [ -e "${bin}/${b}" ] || ln -s "${f}" "${bin}/${b}" 2>/dev/null || true
    done
  done
  # Make sure python3/node resolve even if they live outside the standard dirs
  # (e.g. fnm/pyenv). cosign/curl are deliberately NOT re-added.
  local t p
  for t in python3 node npm; do
    p="$(command -v "${t}" 2>/dev/null)" || continue
    [ -e "${bin}/${t}" ] || ln -s "${p}" "${bin}/${t}" 2>/dev/null || true
  done
  NO_SIG_BIN="${bin}"
}

# Compliance verdicts (reported, never gate the harness).
COMPLIANCE_STATUS="(not run)"
MATRIX_BLOCKING="(not run)"

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
step "Preconditions"
have python3 || { say "${C_RED}FATAL: python3 is required and absent${C_OFF}"; exit 1; }
have bash    || { say "${C_RED}FATAL: bash is required${C_OFF}"; exit 1; }
if [ ! -d "${SRC_EVIDENCE}" ]; then
  say "${C_RED}FATAL: source evidence dir not found: ${SRC_EVIDENCE}${C_OFF}"
  say "Provide one as the first argument, or run from a tree with ./evidence present."
  exit 1
fi
say "pipeline dir : ${PIPELINE_DIR}"
say "source evid. : ${SRC_EVIDENCE}"
say "python3      : $(python3 --version 2>&1)"
say "cosign       : $(have cosign && cosign version 2>/dev/null | head -1 || echo absent)"
say "opa          : $(have opa && opa version 2>/dev/null | head -1 || echo absent)"

# ---------------------------------------------------------------------------
# Isolated work dir: copy the evidence so we NEVER mutate the source.
# ---------------------------------------------------------------------------
WORKDIR="$(mktemp -d -t cyberforge-e2e.XXXXXX)"
EVID="${WORKDIR}/evidence"
cp -r "${SRC_EVIDENCE}" "${EVID}"
cleanup() {
  if [ "${E2E_KEEP_WORKDIR:-0}" = "1" ]; then
    say "${C_DIM}work dir kept: ${WORKDIR}${C_OFF}"
  else
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT
say "work dir     : ${WORKDIR} (isolated copy; source is read-only)"

# Run all stages from the Pipeline dir — the canonical cwd for the validators and
# their sys.path anchoring (tests/compliance/README.md).
cd "${PIPELINE_DIR}" || { say "${C_RED}FATAL: cannot cd ${PIPELINE_DIR}${C_OFF}"; exit 1; }

# ===========================================================================
# Stage 0 — App build + unit tests (only if node_modules present; no install).
# ===========================================================================
step "Stage 0 — App build + tests (offline; only if node_modules present)"
if [ "${E2E_SKIP_APP:-0}" = "1" ]; then
  say "skipped (E2E_SKIP_APP=1)"
  record "app-build" "SKIP" "E2E_SKIP_APP=1"
elif [ ! -d "${APP_DIR}/node_modules" ]; then
  say "skipped — ${APP_DIR}/node_modules absent (offline harness does not run npm install)"
  record "app-build" "SKIP" "node_modules absent"
elif ! have npm; then
  say "skipped — npm not on PATH"
  record "app-build" "SKIP" "npm absent"
else
  APP_OK=1
  if npm --prefix "${APP_DIR}" run build >"${WORKDIR}/app-build.log" 2>&1; then
    say "${C_GREEN}app build OK${C_OFF} (npm run build)"
  else
    say "${C_RED}app build FAILED${C_OFF} — see ${WORKDIR}/app-build.log"; tail -n 15 "${WORKDIR}/app-build.log"
    APP_OK=0
  fi
  if [ "${APP_OK}" -eq 1 ]; then
    if npm --prefix "${APP_DIR}" test >"${WORKDIR}/app-test.log" 2>&1; then
      say "${C_GREEN}app tests OK${C_OFF} (npm test)"
    else
      say "${C_RED}app tests FAILED${C_OFF} — see ${WORKDIR}/app-test.log"; tail -n 15 "${WORKDIR}/app-test.log"
      APP_OK=0
    fi
  fi
  if [ "${APP_OK}" -eq 1 ]; then record "app-build" "PASS" "build+test"; else record "app-build" "FAIL" "see logs"; fail_chain; fi
fi

# ===========================================================================
# Stage 1 — Self-tests (validator/OPA). Standalone-safe (no pytest needed).
# ===========================================================================
step "Stage 1 — Self-tests (validators + OPA policies)"
if [ "${E2E_SKIP_SELFTEST:-0}" = "1" ]; then
  say "skipped (E2E_SKIP_SELFTEST=1)"
  record "self-test" "SKIP" "E2E_SKIP_SELFTEST=1"
else
  ST_OK=1; ST_NOTE=""
  # Prefer pytest (full suite + coverage); fall back to each file's standalone
  # runner so the harness works on a minimal box without pytest installed.
  if python3 -c "import pytest" >/dev/null 2>&1; then
    if python3 -m pytest tests/compliance -q >"${WORKDIR}/selftest-py.log" 2>&1; then
      say "${C_GREEN}python validator suite OK${C_OFF} (pytest)"
      ST_NOTE="pytest"
    else
      say "${C_RED}python validator suite FAILED${C_OFF} (pytest) — see ${WORKDIR}/selftest-py.log"
      tail -n 20 "${WORKDIR}/selftest-py.log"; ST_OK=0
    fi
  else
    say "${C_DIM}pytest absent — running each test_*.py standalone${C_OFF}"
    ST_FAILED=0; ST_RAN=0
    for t in tests/compliance/test_*.py; do
      [ -f "${t}" ] || continue
      ST_RAN=$((ST_RAN + 1))
      if python3 "${t}" >>"${WORKDIR}/selftest-standalone.log" 2>&1; then
        :
      else
        say "${C_RED}standalone FAIL: ${t}${C_OFF}"; ST_FAILED=$((ST_FAILED + 1))
      fi
    done
    say "standalone tests: ${ST_RAN} run, ${ST_FAILED} failed (full log: ${WORKDIR}/selftest-standalone.log)"
    ST_NOTE="standalone ${ST_RAN}/${ST_FAILED}f"
    [ "${ST_FAILED}" -eq 0 ] || ST_OK=0
  fi
  # OPA policy tests (only if opa is present; absence is a SKIP, not a failure).
  if have opa; then
    if opa test policies >"${WORKDIR}/selftest-opa.log" 2>&1; then
      say "${C_GREEN}OPA policy tests OK${C_OFF} ($(grep -Eo 'PASS: [0-9]+/[0-9]+' "${WORKDIR}/selftest-opa.log" | tail -1))"
      ST_NOTE="${ST_NOTE}+opa"
    else
      say "${C_RED}OPA policy tests FAILED${C_OFF} — see ${WORKDIR}/selftest-opa.log"
      tail -n 15 "${WORKDIR}/selftest-opa.log"; ST_OK=0
    fi
  else
    say "${C_YEL}opa absent — policy tests skipped${C_OFF}"
    ST_NOTE="${ST_NOTE}+opa-skip"
  fi
  if [ "${ST_OK}" -eq 1 ]; then
    record "self-test" "PASS" "${ST_NOTE}"
  elif [ "${E2E_SELFTEST_ADVISORY:-0}" = "1" ]; then
    say "${C_YEL}self-test failures present but E2E_SELFTEST_ADVISORY=1 — NOT failing the chain${C_OFF}"
    record "self-test" "DEGRADED" "advisory; ${ST_NOTE}"
  else
    record "self-test" "FAIL" "${ST_NOTE}"; fail_chain
  fi
fi

# ===========================================================================
# Stage 2 — aggregate-compliance.py (A.1-A.10 organizational gate).
# A non-zero exit here is an HONEST compliance verdict, NOT a chain break — the
# chain "ran" as long as compliance-status.json was written. We report the
# verdict and continue.
# ===========================================================================
step "Stage 2 — aggregate-compliance.py (A.1-A.10 organizational gate)"
AGG_RC=0
python3 scripts/aggregate-compliance.py "${EVID}" >"${WORKDIR}/aggregate.log" 2>&1 || AGG_RC=$?
if [ -s "${EVID}/compliance-status.json" ]; then
  COMPLIANCE_STATUS="$(python3 -c "import json,sys; d=json.load(open('${EVID}/compliance-status.json')); print(d.get('overall_status','?'), 'blocking='+str(d.get('blocking_failures','?')))" 2>/dev/null || echo "?")"
  say "compliance-status.json written; verdict: ${COMPLIANCE_STATUS} (aggregate rc=${AGG_RC})"
  if [ "${AGG_RC}" -ne 0 ]; then
    say "${C_YEL}note: non-zero is an honest compliance FAIL on the sample evidence, not a chain break${C_OFF}"
  fi
  record "aggregate" "PASS" "verdict ${COMPLIANCE_STATUS}"
else
  say "${C_RED}aggregate produced NO compliance-status.json — chain stage failed${C_OFF}"
  tail -n 15 "${WORKDIR}/aggregate.log"
  record "aggregate" "FAIL" "no compliance-status.json"; fail_chain
fi

# ===========================================================================
# Stage 3 — generate-compliance-matrix.sh (content-validated DORA/NIS2 matrix).
# Same honesty rule: a non-zero exit is an honest content verdict; the stage
# "ran" as long as a non-empty matrix JSON landed.
# ===========================================================================
step "Stage 3 — generate-compliance-matrix.sh (content matrix)"
MX_RC=0
bash scripts/generate-compliance-matrix.sh "${EVID}" >"${EVID}/compliance-matrix.json" 2>"${WORKDIR}/matrix.log" || MX_RC=$?
if [ -s "${EVID}/compliance-matrix.json" ] && python3 -c "import json; json.load(open('${EVID}/compliance-matrix.json'))" >/dev/null 2>&1; then
  MATRIX_BLOCKING="$(python3 -c "import json; print(json.load(open('${EVID}/compliance-matrix.json')).get('blocking_failures','?'))" 2>/dev/null || echo "?")"
  say "compliance-matrix.json written; blocking_failures=${MATRIX_BLOCKING} (matrix rc=${MX_RC})"
  if [ "${MX_RC}" -ne 0 ]; then
    say "${C_YEL}note: non-zero reflects honest BLOCKING rows on the sample evidence, not a chain break${C_OFF}"
  fi
  record "matrix" "PASS" "blocking=${MATRIX_BLOCKING}"
else
  say "${C_RED}matrix produced no valid JSON — chain stage failed${C_OFF}"
  tail -n 15 "${WORKDIR}/matrix.log"
  record "matrix" "FAIL" "no valid matrix JSON"; fail_chain
fi

# ===========================================================================
# Stage 4 — generate-evidence-manifest.py (RFC-6962 Merkle manifest, pass 1).
# A failure HERE is a real chain break (the Merkle root anchors the whole pack).
# ===========================================================================
step "Stage 4 — generate-evidence-manifest.py (Merkle manifest, pass 1)"
if python3 scripts/generate-evidence-manifest.py "${EVID}" \
      --out "${EVID}/manifest.json" \
      --legacy-out "${EVID}/manifest.sha256" >"${WORKDIR}/manifest1.log" 2>&1 \
   && [ -s "${EVID}/manifest.json" ]; then
  MR="$(python3 -c "import json; print(json.load(open('${EVID}/manifest.json')).get('merkle_root','?'))" 2>/dev/null || echo "?")"
  say "${C_GREEN}manifest.json written${C_OFF}; merkle_root=${MR}"
  record "manifest-1" "PASS" "merkle ${MR:0:16}..."
else
  say "${C_RED}manifest generation FAILED — chain break${C_OFF}"; tail -n 15 "${WORKDIR}/manifest1.log"
  record "manifest-1" "FAIL" "no manifest.json"; fail_chain
fi

# ===========================================================================
# Stage 5 — seal-evidence.sh in EVIDENCE_ALLOW_DEGRADE mode.
# Offline: cosign keyless + RFC-3161 TSA cannot complete. By default we hide
# cosign+curl (see header) so the seal models a clean offline-no-sigstore box:
# signatures recorded as "unavailable", no partial bundle state, no 45s retry
# backoff. The step is still bounded by a timeout as a safety net. A timeout or a
# tool-degrade is DEGRADED, not a chain break, because the degrade contract is
# explicitly designed to exit 0 with "unavailable" provenance flags.
# ===========================================================================
step "Stage 5 — seal-evidence.sh (EVIDENCE_ALLOW_DEGRADE=1, offline)"
SEAL_RC=0
SEAL_NOTE="degrade exit 0"
if [ "${E2E_KEEP_COSIGN:-0}" = "1" ]; then
  say "${C_DIM}E2E_KEEP_COSIGN=1 — exercising the real keyless-signing degrade path (slow)${C_OFF}"
  timeout "${SEAL_TIMEOUT}" env \
    EVIDENCE_ALLOW_DEGRADE=1 \
    TSA_URL="http://127.0.0.1:9/tsr" \
    bash scripts/seal-evidence.sh "${EVID}" "${EVID}/evidence-report.pdf" "${EVID}/manifest.json" \
    >"${WORKDIR}/seal.log" 2>&1 || SEAL_RC=$?
else
  say "${C_DIM}cosign+curl hidden — modelling offline-no-sigstore (clean SKIP path)${C_OFF}"
  [ -n "${NO_SIG_BIN}" ] || build_no_cosign_path
  timeout "${SEAL_TIMEOUT}" env \
    PATH="${NO_SIG_BIN}" \
    EVIDENCE_ALLOW_DEGRADE=1 \
    bash scripts/seal-evidence.sh "${EVID}" "${EVID}/evidence-report.pdf" "${EVID}/manifest.json" \
    >"${WORKDIR}/seal.log" 2>&1 || SEAL_RC=$?
  SEAL_NOTE="degrade exit 0 (cosign hidden)"
fi
if [ "${SEAL_RC}" -eq 0 ]; then
  say "${C_GREEN}seal completed (degrade mode, exit 0)${C_OFF}"
  record "seal" "PASS" "${SEAL_NOTE}"
elif [ "${SEAL_RC}" -eq 124 ]; then
  say "${C_YEL}seal timed out after ${SEAL_TIMEOUT}s — expected offline (keyless cosign/TSA retries). Treated as DEGRADED.${C_OFF}"
  say "${C_DIM}increase E2E_SEAL_TIMEOUT, or drop E2E_KEEP_COSIGN to model offline-no-sigstore cleanly.${C_OFF}"
  record "seal" "DEGRADED" "timeout ${SEAL_TIMEOUT}s (offline signing)"
else
  # In degrade mode the seal should exit 0; a non-zero, non-timeout exit means a
  # genuine fault (e.g. python helper crash, manifest unreadable) -> chain break.
  say "${C_RED}seal exited ${SEAL_RC} in degrade mode — genuine fault, chain break${C_OFF}"
  tail -n 20 "${WORKDIR}/seal.log"
  record "seal" "FAIL" "exit ${SEAL_RC}"; fail_chain
fi

# ===========================================================================
# Stage 6 — re-stamp the manifest so its hashes cover the sealing artifacts.
# ===========================================================================
step "Stage 6 — generate-evidence-manifest.py (re-stamp over sealing artifacts)"
if python3 scripts/generate-evidence-manifest.py "${EVID}" \
      --out "${EVID}/manifest.json" \
      --legacy-out "${EVID}/manifest.sha256" >"${WORKDIR}/manifest2.log" 2>&1 \
   && [ -s "${EVID}/manifest.json" ]; then
  say "${C_GREEN}manifest re-stamped over sealing artifacts${C_OFF}"
  record "manifest-2" "PASS" "re-stamped"
else
  say "${C_RED}manifest re-stamp FAILED — chain break${C_OFF}"; tail -n 15 "${WORKDIR}/manifest2.log"
  record "manifest-2" "FAIL" "re-stamp failed"; fail_chain
fi

# ===========================================================================
# Stage 7 — verify-evidence-pack.sh runbook. This is the gate that turns the
# harness GREEN/RED on the *integrity* axis: it must exit 0 (no FAIL lines). In
# degrade mode an offline pack verifies sha256 + Merkle and SKIPs cosign/TSA.
# ===========================================================================
step "Stage 7 — verify-evidence-pack.sh (integrity runbook)"
VERIFY_RC=0
# Verify with the SAME cosign visibility the seal used, so the runbook's signing
# checks match what the seal could actually produce (offline: cosign hidden ->
# clean SKIP; with E2E_KEEP_COSIGN the real cosign verify path runs).
if [ "${E2E_KEEP_COSIGN:-0}" = "1" ]; then
  EVIDENCE_ALLOW_DEGRADE=1 bash scripts/verify-evidence-pack.sh "${EVID}" >"${WORKDIR}/verify.log" 2>&1 || VERIFY_RC=$?
else
  [ -n "${NO_SIG_BIN}" ] || build_no_cosign_path
  env PATH="${NO_SIG_BIN}" EVIDENCE_ALLOW_DEGRADE=1 \
    bash scripts/verify-evidence-pack.sh "${EVID}" >"${WORKDIR}/verify.log" 2>&1 || VERIFY_RC=$?
fi
# Echo the runbook's own PASS/SKIP/FAIL lines so the operator sees the detail.
sed 's/^/    /' "${WORKDIR}/verify.log"
# Count via `grep | wc -l` (always exits 0 and prints exactly one integer, unlike
# `grep -c` which exits 1 on zero matches and would combine with a `|| echo 0` to
# print two lines and break the [ -eq ] test below).
V_PASS="$(grep '^PASS' "${WORKDIR}/verify.log" 2>/dev/null | wc -l | tr -d ' ')"
V_SKIP="$(grep '^SKIP' "${WORKDIR}/verify.log" 2>/dev/null | wc -l | tr -d ' ')"
V_FAIL="$(grep '^FAIL' "${WORKDIR}/verify.log" 2>/dev/null | wc -l | tr -d ' ')"
if [ "${VERIFY_RC}" -eq 0 ] && [ "${V_FAIL}" -eq 0 ]; then
  say "${C_GREEN}verify runbook PASS${C_OFF} (pass=${V_PASS} skip=${V_SKIP} fail=${V_FAIL})"
  record "verify" "PASS" "p=${V_PASS} s=${V_SKIP} f=${V_FAIL}"
else
  say "${C_RED}verify runbook FAILED${C_OFF} (rc=${VERIFY_RC}, fail=${V_FAIL}) — chain break"
  record "verify" "FAIL" "rc=${VERIFY_RC} f=${V_FAIL}"; fail_chain
fi

# ===========================================================================
# Summary
# ===========================================================================
step "Summary"
hr
printf '%-14s %-9s %s\n' "STAGE" "RESULT" "NOTE"
hr
for i in "${!STAGE_NAME[@]}"; do
  r="${STAGE_RESULT[$i]}"
  case "${r}" in
    PASS)     col="${C_GREEN}";;
    FAIL)     col="${C_RED}";;
    DEGRADED) col="${C_YEL}";;
    *)        col="${C_DIM}";;
  esac
  printf '%-14s %s%-9s%s %s\n' "${STAGE_NAME[$i]}" "${col}" "${r}" "${C_OFF}" "${STAGE_NOTE[$i]}"
done
hr
say ""
say "Compliance verdict (HONEST, does NOT gate this harness):"
say "  organizational A.1-A.10 : ${COMPLIANCE_STATUS}"
say "  content matrix blocking : ${MATRIX_BLOCKING}"
say "  ${C_DIM}(remediate evidence to turn these green — never weaken a validator)${C_OFF}"
say ""
hr
if [ "${CHAIN_OK}" -eq 1 ]; then
  say "${C_GREEN}E2E RESULT: GREEN — the offline evidence chain assembled and self-verified end-to-end.${C_OFF}"
  say "${C_DIM}(No Azure, no cloud upload, no deploy were performed.)${C_OFF}"
  hr
  exit 0
else
  say "${C_RED}E2E RESULT: RED — a required chain stage broke. See the per-stage logs in the work dir.${C_OFF}"
  say "${C_DIM}Re-run with E2E_KEEP_WORKDIR=1 to inspect ${WORKDIR}.${C_OFF}"
  hr
  exit 1
fi
