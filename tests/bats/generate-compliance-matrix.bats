#!/usr/bin/env bats
#
# T-81 shell sub-suite — scripts/generate-compliance-matrix.sh (the T-12 keystone
# orchestrator that replaced file-presence "PASS" with content-validated rows).
#
# Built-in bats only (run / $status / $output). Fixtures live in a per-test
# mktemp -d WORK; never written into the repo tree.
#
# The headline T-12 invariant: an empty `{}` security-report.json must NOT read as
# PASS for DORA Art.16.1.a — it must be INDETERMINATE, and a BLOCKING row that is
# not PASS must drive a non-zero exit (so an incomplete pack cannot be sealed).
#
# Behaviors asserted (cite the targeted line in generate-compliance-matrix.sh):
#   * empty evidence dir            -> exit 1 + "BLOCKING row(s) FAIL/INDETERMINATE"
#     (blocking_failures count + sys.exit(1) at line 518-531)
#   * empty {} security-report.json -> exit 1 + at least one "INDETERMINATE" row in
#     the emitted JSON (the row() envelope guard at line 178-181 turns an empty/no-
#     Results report into INDETERMINATE, never a silent PASS)
#   * the emitted matrix JSON carries a non-zero "blocking_failures" count
#     (written at line 523)
#   * the schema marker proves the content-validated v2 matrix ran, not the old
#     file-presence path (schema field at line 333)
#
# NOTE: this script requires python3 + scripts/validators/matrix_rows.py (both
# present in-repo). If python3 is absent the row validators cannot run, so the
# test SKIPs rather than asserting a fabricated result.

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  SCRIPT="${REPO_ROOT}/scripts/generate-compliance-matrix.sh"
  WORK="$(mktemp -d)"
  command -v python3 >/dev/null 2>&1 || skip "python3 absent — row validators cannot run"
}

teardown() {
  [ -n "${WORK:-}" ] && rm -rf "${WORK}"
}

@test "generate-compliance-matrix: empty evidence dir is non-zero (blocking rows fail)" {
  mkdir -p "${WORK}/pack"
  run bash "${SCRIPT}" "${WORK}/pack"
  [ "$status" -eq 1 ]
  [[ "$output" == *"BLOCKING row(s) FAIL/INDETERMINATE"* ]]
}

@test "generate-compliance-matrix: empty {} security-report.json is INDETERMINATE, not PASS" {
  mkdir -p "${WORK}/pack"
  printf '{}' > "${WORK}/pack/security-report.json"
  run bash "${SCRIPT}" "${WORK}/pack"
  [ "$status" -eq 1 ]
  [[ "$output" == *"INDETERMINATE"* ]]
}

@test "generate-compliance-matrix: emitted matrix records a non-zero blocking_failures count" {
  mkdir -p "${WORK}/pack"
  run bash "${SCRIPT}" "${WORK}/pack"
  [ "$status" -eq 1 ]
  # blocking_failures is 0 only on a fully-passing pack; an empty pack must be >0.
  [[ "$output" != *'"blocking_failures": 0'* ]]
  [[ "$output" == *'"blocking_failures":'* ]]
}

@test "generate-compliance-matrix: emits the content-validated v2 schema (not file-presence)" {
  mkdir -p "${WORK}/pack"
  run bash "${SCRIPT}" "${WORK}/pack"
  [[ "$output" == *"cyberforge-compliance-matrix/v2-content-validated"* ]]
}
