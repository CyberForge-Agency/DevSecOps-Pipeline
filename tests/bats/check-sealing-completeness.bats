#!/usr/bin/env bats
#
# T-81 shell sub-suite — scripts/check-sealing-completeness.sh (the evidence-
# integrity self-test that turns the §12 "8-component pack" into an enforced gate).
#
# Built-in bats only (run / $status / $output). Fixtures live in a per-test
# mktemp -d WORK; never written into the repo tree.
#
# Behaviors asserted (cite the targeted line in check-sealing-completeness.sh):
#   * wrong argc                       -> exit 64 + usage   (line 42-45)
#   * non-existent evidence dir        -> exit 1  + "evidence dir not found" (line 48)
#   * empty pack, fail-closed CI mode  -> exit 1  + "RESULT: INCOMPLETE" + a MISSING
#     FAIL line (miss() -> fail() at line 63-69; exit 1 at line 252-255)
#   * empty pack, EVIDENCE_ALLOW_DEGRADE=1 -> exit 0 + "RESULT: OK-DEGRADED" + WARN
#     (miss() -> warn() at line 63-69; exit 0 at line 256-261)
#   * the mode banner reflects the degrade env var (line 110)

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  SCRIPT="${REPO_ROOT}/scripts/check-sealing-completeness.sh"
  WORK="$(mktemp -d)"
}

teardown() {
  [ -n "${WORK:-}" ] && rm -rf "${WORK}"
}

@test "check-sealing-completeness: no argument is a usage error (exit 64)" {
  run bash "${SCRIPT}"
  [ "$status" -eq 64 ]
  [[ "$output" == *"usage: check-sealing-completeness.sh"* ]]
}

@test "check-sealing-completeness: missing evidence dir fails hard (exit 1)" {
  run bash "${SCRIPT}" "${WORK}/no-such-dir"
  [ "$status" -eq 1 ]
  [[ "$output" == *"evidence dir not found"* ]]
}

@test "check-sealing-completeness: empty pack fails closed in CI mode (exit 1)" {
  mkdir -p "${WORK}/pack"
  EVIDENCE_ALLOW_DEGRADE= run bash "${SCRIPT}" "${WORK}/pack"
  [ "$status" -eq 1 ]
  [[ "$output" == *"RESULT: INCOMPLETE"* ]]
}

@test "check-sealing-completeness: missing required artifact reported as FAIL line" {
  mkdir -p "${WORK}/pack"
  EVIDENCE_ALLOW_DEGRADE= run bash "${SCRIPT}" "${WORK}/pack"
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL  merkle-root.cosign.bundle MISSING"* ]]
}

@test "check-sealing-completeness: degrade mode downgrades missing artifacts to WARN (exit 0)" {
  mkdir -p "${WORK}/pack"
  EVIDENCE_ALLOW_DEGRADE=1 run bash "${SCRIPT}" "${WORK}/pack"
  [ "$status" -eq 0 ]
  [[ "$output" == *"RESULT: OK-DEGRADED"* ]]
}

@test "check-sealing-completeness: degrade banner is printed in degrade mode" {
  mkdir -p "${WORK}/pack"
  EVIDENCE_ALLOW_DEGRADE=1 run bash "${SCRIPT}" "${WORK}/pack"
  [ "$status" -eq 0 ]
  [[ "$output" == *"mode: degrade"* ]]
}
