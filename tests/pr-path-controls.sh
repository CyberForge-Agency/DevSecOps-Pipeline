#!/usr/bin/env bash
#
# pr-path-controls.sh — static control test for the pipeline's PR-conditional
# branches (T-124). It is the enforceable counterpart of
# docs/governance/pr-conditional-branches.md: it proves the documented
# enumeration still MATCHES the workflow source and that each PR-conditional is
# wired to the right kind of step, exiting non-zero if any documented control is
# missing or mis-wired.
#
# Scope: this is a STATIC test (greps the YAML source). It deliberately does NOT
# spin up a live PR against a real branch-protection rule — that behavioral proof
# is T-68 and is deferred (needs a real GitHub org + a live PR). What this test
# guarantees is the invariant that matters for honesty: no PR-path silently skips
# a gate that should block on push, and no "blocking on non-PR" step lost its
# posture switch.
#
# It is line-number independent on purpose (evidence-pack.yml grows over time):
# every assertion matches a STEP NAME and/or a PATTERN, never an absolute line.
#
# Usage:  bash tests/pr-path-controls.sh        (run from the Pipeline/ dir, or
#                                                 anywhere — it self-locates)
# Exit:   0 all controls present + correctly wired
#         1 a documented PR-conditional is missing or mis-wired
#         2 environment / usage error (workflows dir not found)
#
# Tools: bash, grep, awk only. No bats / external deps (bats is not installed in
# the target environment; this stays runnable everywhere CI runs).

set -uo pipefail

# --- locate the repo (Pipeline/) root from this script's own path ------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WF="${ROOT}/.github/workflows"

if [ ! -d "${WF}" ]; then
  echo "FATAL  workflows directory not found: ${WF}" >&2
  exit 2
fi

PASS=0
FAIL=0

ok()   { printf 'PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf 'FAIL  %s\n' "$1" >&2; FAIL=$((FAIL + 1)); }

# count_matches <file> <fixed-string-pattern>
count_matches() { grep -Fc -- "$2" "$1" 2>/dev/null || true; }

# assert_min <label> <file> <pattern> <min>
# Fails if <file> contains fewer than <min> lines matching <pattern> (fixed str).
assert_min() {
  local label="$1" file="$2" pat="$3" min="$4" n
  if [ ! -f "${file}" ]; then bad "${label} (file missing: ${file})"; return; fi
  n="$(count_matches "${file}" "${pat}")"
  if [ "${n}" -ge "${min}" ]; then
    ok "${label} (${n} >= ${min})"
  else
    bad "${label} — expected >= ${min} occurrence(s) of '${pat}', found ${n} in $(basename "${file}")"
  fi
}

# assert_step_has_gate <label> <file> <step-name> <gate-fixed-string>
# Verifies the named step (a '- name: <step-name>' line) has <gate-fixed-string>
# somewhere within its step block (from its own '- name:' up to the next
# '- name:' at the same or shallower indent, or EOF). Proves CORRECT WIRING:
# the conditional guards the step we claim it guards.
assert_step_has_gate() {
  local label="$1" file="$2" step="$3" gate="$4"
  if [ ! -f "${file}" ]; then bad "${label} (file missing: ${file})"; return; fi
  awk -v step="${step}" -v gate="${gate}" '
    BEGIN { instep = 0; found = 0; seen_step = 0 }
    # A new step boundary: a line whose trimmed form starts with "- name:"
    {
      line = $0
      trimmed = line
      sub(/^[[:space:]]+/, "", trimmed)
    }
    trimmed ~ /^- name:/ {
      # Close any open step before opening a new one.
      if (instep && !found) { } # (failure handled after loop via found flag)
      # Does THIS name line name our target step?
      name = trimmed
      sub(/^- name:[[:space:]]*/, "", name)
      gsub(/^["'\''"]|["'\''"]$/, "", name)
      if (index(name, step) > 0) { instep = 1; seen_step = 1; next }
      else { instep = 0; next }
    }
    instep && index(line, gate) > 0 { found = 1 }
    END {
      if (!seen_step) { print "NOSTEP"; exit 0 }
      if (found)      { print "FOUND";  exit 0 }
      print "NOGATE"; exit 0
    }
  ' "${file}" > /tmp/pr_path_step_check.$$ 2>/dev/null
  local res; res="$(cat /tmp/pr_path_step_check.$$ 2>/dev/null)"; rm -f /tmp/pr_path_step_check.$$
  case "${res}" in
    FOUND)  ok  "${label}" ;;
    NOSTEP) bad "${label} — step '${step}' not found in $(basename "${file}")" ;;
    *)      bad "${label} — step '${step}' present but missing gate '${gate}'" ;;
  esac
}

# assert_job_has_gate <label> <file> <job-display-name> <gate-fixed-string>
# Like assert_step_has_gate but for top-level JOBS, whose display name is on a
# bare 'name: <...>' line (not '- name:'). Checks the gate appears within the
# job's block (from its 'name:' line up to the next bare 'name:' / '- name:' or
# a top-level key, or EOF).
assert_job_has_gate() {
  local label="$1" file="$2" job="$3" gate="$4"
  if [ ! -f "${file}" ]; then bad "${label} (file missing: ${file})"; return; fi
  awk -v job="${job}" -v gate="${gate}" '
    BEGIN { injob = 0; found = 0; seen = 0 }
    { line = $0; t = $0; sub(/^[[:space:]]+/, "", t) }
    # A bare job display-name line: "name: ..." (NOT "- name:").
    t ~ /^name:/ {
      nm = t; sub(/^name:[[:space:]]*/, "", nm); gsub(/^["'\''"]|["'\''"]$/, "", nm)
      if (index(nm, job) > 0) { injob = 1; seen = 1; next } else { injob = 0; next }
    }
    # Any new job/step boundary closes the current job scope.
    t ~ /^- name:/ { injob = 0 }
    injob && index(line, gate) > 0 { found = 1 }
    END { if (!seen) { print "NOJOB" } else if (found) { print "FOUND" } else { print "NOGATE" } }
  ' "${file}" > /tmp/pr_path_job_check.$$ 2>/dev/null
  local res; res="$(cat /tmp/pr_path_job_check.$$ 2>/dev/null)"; rm -f /tmp/pr_path_job_check.$$
  case "${res}" in
    FOUND) ok  "${label}" ;;
    NOJOB) bad "${label} — job '${job}' not found in $(basename "${file}")" ;;
    *)     bad "${label} — job '${job}' present but missing gate '${gate}'" ;;
  esac
}

PIPELINE="${WF}/pipeline.yml"
DEPLOY="${WF}/deploy.yml"
EVIDENCE="${WF}/evidence-pack.yml"

echo "== T-124 PR-conditional control test =="
echo "workflows: ${WF}"
echo

# ---------------------------------------------------------------------------
# 1. pipeline.yml — the four production-only jobs are PR-skipped, and the two
#    trigger-propagation outputs exist.
# ---------------------------------------------------------------------------
# Three job-level skip gates (sign-and-attest, deploy, dast).
assert_min "pipeline.yml: production-only jobs carry PR-skip gate" \
  "${PIPELINE}" "if: github.event_name != 'pull_request'" 3

assert_job_has_gate "pipeline.yml: sign-and-attest job is PR-skipped" \
  "${PIPELINE}" "Phase 3: Sign & Attest" "if: github.event_name != 'pull_request'"
assert_job_has_gate "pipeline.yml: deploy job is PR-skipped" \
  "${PIPELINE}" "Phase 4: Deploy" "if: github.event_name != 'pull_request'"
assert_job_has_gate "pipeline.yml: dast job is PR-skipped" \
  "${PIPELINE}" "Phase 5: DAST" "if: github.event_name != 'pull_request'"

# Trigger-propagation outputs (image is never pushed on a PR; gate posture
# propagated to the reusable security-gate workflow).
assert_min "pipeline.yml: push_image gated to non-PR" \
  "${PIPELINE}" "github.event_name != 'pull_request'" 4   # 3 job gates + push_image
assert_min "pipeline.yml: is_pull_request propagated to security-gate" \
  "${PIPELINE}" "is_pull_request:" 1

# ---------------------------------------------------------------------------
# 2. deploy.yml — the three fail-closed shell event guards each guard a
#    sign/deploy/assert step, not an innocuous one.
# ---------------------------------------------------------------------------
assert_min "deploy.yml: fail-closed shell event guards present" \
  "${DEPLOY}" "github.event_name }}\" != 'pull_request'" 3

assert_step_has_gate "deploy.yml: Terraform Init refuses real apply on ephemeral state" \
  "${DEPLOY}" "Terraform Init" "github.event_name }}\" != 'pull_request'"
assert_step_has_gate "deploy.yml: assert-crypto (T-28) blocks on non-PR" \
  "${DEPLOY}" "assert-crypto (T-28" "github.event_name }}\" != 'pull_request'"
assert_step_has_gate "deploy.yml: assert-retention (T-48) blocks on non-PR" \
  "${DEPLOY}" "assert-retention (T-48" "github.event_name }}\" != 'pull_request'"

# ---------------------------------------------------------------------------
# 3. evidence-pack.yml — the degrade-on-PR verdict steps (IS_PR), the seal
#    steps (EVIDENCE_ALLOW_DEGRADE), and the push-only archival gates.
# ---------------------------------------------------------------------------
# The documented IS_PR verdict steps. The doc enumerates 12; require at least
# that many so a silent removal of any verdict gate fails the test.
assert_min "evidence-pack.yml: IS_PR degrade-on-PR verdict gates" \
  "${EVIDENCE}" "IS_PR: \${{ github.event_name == 'pull_request' }}" 12

# Each named verdict step that advertises a blocking posture must carry IS_PR.
assert_step_has_gate "evidence-pack.yml: consolidated security report has IS_PR" \
  "${EVIDENCE}" "Generate consolidated security report" "IS_PR:"
assert_step_has_gate "evidence-pack.yml: A.1-A.10 compliance aggregate has IS_PR" \
  "${EVIDENCE}" "Compliance gate — aggregate A.1-A.10" "IS_PR:"
assert_step_has_gate "evidence-pack.yml: compliance gate (blocking) has IS_PR" \
  "${EVIDENCE}" "Compliance gate (blocking on non-PR)" "IS_PR:"
assert_step_has_gate "evidence-pack.yml: source-control drift (T-119) has IS_PR" \
  "${EVIDENCE}" "source-control drift evidence (T-119)" "IS_PR:"
assert_step_has_gate "evidence-pack.yml: crosswalk/gap/residency (T-102/T-103/T-109) has IS_PR" \
  "${EVIDENCE}" "crosswalk, gap register, residency assertion" "IS_PR:"
assert_step_has_gate "evidence-pack.yml: OPA evidence completeness has IS_PR" \
  "${EVIDENCE}" "OPA evidence completeness (blocking on non-PR)" "IS_PR:"

# Seal steps: EVIDENCE_ALLOW_DEGRADE = '1' on PR, unset on push.
assert_min "evidence-pack.yml: EVIDENCE_ALLOW_DEGRADE seal switches" \
  "${EVIDENCE}" "EVIDENCE_ALLOW_DEGRADE: \${{ github.event_name == 'pull_request' && '1' || '' }}" 2
assert_step_has_gate "evidence-pack.yml: PDF seal step has degrade switch" \
  "${EVIDENCE}" "Build audit-grade PDF evidence" "EVIDENCE_ALLOW_DEGRADE:"
assert_step_has_gate "evidence-pack.yml: sealing completeness self-test has degrade switch" \
  "${EVIDENCE}" "Sealing completeness self-test (blocking on non-PR)" "EVIDENCE_ALLOW_DEGRADE:"

# Push-only archival / anti-regression gates (skipped on PR).
assert_step_has_gate "evidence-pack.yml: Merkle-root bundle anti-regression is push-only" \
  "${EVIDENCE}" "Assert Merkle-root cosign bundle" "if: github.event_name != 'pull_request'"
assert_step_has_gate "evidence-pack.yml: Azure Login (OIDC) is push-only" \
  "${EVIDENCE}" "Azure Login (OIDC)" "if: github.event_name != 'pull_request'"
assert_step_has_gate "evidence-pack.yml: WORM blob upload is push-only" \
  "${EVIDENCE}" "Upload to Azure Blob WORM storage" "if: github.event_name != 'pull_request'"

# ---------------------------------------------------------------------------
# 4. No latent demotion: every step whose NAME advertises "blocking on non-PR"
#    must actually carry a PR-posture switch (IS_PR, EVIDENCE_ALLOW_DEGRADE, an
#    if-gate, or a shell event guard). A step that claims to block on push but
#    has no posture switch is a finding.
# ---------------------------------------------------------------------------
check_no_latent_demotion() {
  local file="$1" missing=0 stepname
  # Collect step names containing the "blocking on non-PR" advertisement.
  while IFS= read -r stepname; do
    [ -n "${stepname}" ] || continue
    # Does that step block carry ANY posture switch?
    if awk -v step="${stepname}" '
      BEGIN { instep = 0; found = 0; seen = 0 }
      { line = $0; t = $0; sub(/^[[:space:]]+/, "", t) }
      t ~ /^- name:/ {
        nm = t; sub(/^- name:[[:space:]]*/, "", nm); gsub(/^["'\''"]|["'\''"]$/, "", nm)
        if (index(nm, step) > 0) { instep = 1; seen = 1; next } else { instep = 0; next }
      }
      instep && (index(line, "IS_PR:") > 0 \
                || index(line, "EVIDENCE_ALLOW_DEGRADE:") > 0 \
                || index(line, "github.event_name != ") > 0 \
                || index(line, "github.event_name }}") > 0) { found = 1 }
      END { exit (seen && found) ? 0 : 1 }
    ' "${file}"; then
      :
    else
      bad "no-latent-demotion: step '${stepname}' advertises blocking-on-non-PR but has NO posture switch"
      missing=$((missing + 1))
    fi
  done < <(grep -oE '^[[:space:]]*- name: .*blocking on non-PR.*$' "${file}" \
            | sed -E 's/^[[:space:]]*- name:[[:space:]]*//; s/^["'\'']//; s/["'\'']$//')
  if [ "${missing}" -eq 0 ]; then
    ok "no-latent-demotion: every 'blocking on non-PR' step in $(basename "${file}") has a posture switch"
  fi
}
check_no_latent_demotion "${EVIDENCE}"
check_no_latent_demotion "${DEPLOY}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "== summary: ${PASS} passed, ${FAIL} failed =="
if [ "${FAIL}" -ne 0 ]; then
  echo "A documented PR-conditional is missing or mis-wired; update the workflow" >&2
  echo "or docs/governance/pr-conditional-branches.md so they agree." >&2
  exit 1
fi
exit 0
