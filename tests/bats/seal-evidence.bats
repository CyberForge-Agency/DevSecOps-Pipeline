#!/usr/bin/env bats
#
# T-81 shell sub-suite — scripts/seal-evidence.sh (the cryptographic sealing
# driver). seal-evidence.sh runs `set -euo pipefail` and executes its precondition
# checks at top level (argc gate at line 32-35; die-on-missing at line 132-134), so
# its helper functions (e.g. infer_qualified) cannot be safely *sourced* for
# white-box unit testing without triggering the script's own exit logic. We
# therefore black-box the two deterministic, tool-independent contract points: the
# usage gate and the missing-input die path. These exercise the same exit codes the
# verification runbook relies on and need no cosign/openssl/TSA toolchain.
#
# Built-in bats only (run / $status / $output). No repo-tree writes.
#
# Behaviors asserted (cite the targeted line in seal-evidence.sh):
#   * wrong argc                 -> exit 64 + usage   (line 32-35)
#   * missing evidence dir        -> exit 1  + "evidence dir not found" via die()
#     (precondition at line 132; die() at line 111)

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  SCRIPT="${REPO_ROOT}/scripts/seal-evidence.sh"
  WORK="$(mktemp -d)"
}

teardown() {
  [ -n "${WORK:-}" ] && rm -rf "${WORK}"
}

@test "seal-evidence: no arguments is a usage error (exit 64)" {
  run bash "${SCRIPT}"
  [ "$status" -eq 64 ]
  [[ "$output" == *"usage: seal-evidence.sh"* ]]
}

@test "seal-evidence: missing evidence dir dies (exit 1)" {
  run bash "${SCRIPT}" "${WORK}/no-such-dir" "${WORK}/x.pdf" "${WORK}/m.json"
  [ "$status" -eq 1 ]
  [[ "$output" == *"evidence dir not found"* ]]
}
