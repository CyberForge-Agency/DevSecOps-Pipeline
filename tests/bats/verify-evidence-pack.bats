#!/usr/bin/env bats
#
# T-81 shell sub-suite — scripts/verify-evidence-pack.sh (the shipped + CI-run
# verification runbook for a sealed evidence pack).
#
# Built-in bats only (run / $status / $output). Fixtures live in a per-test
# mktemp -d WORK; never written into the repo tree.
#
# Behaviors asserted (cite the targeted line in verify-evidence-pack.sh):
#   * wrong argc                  -> exit 64 + usage          (line 28-31)
#   * non-existent evidence dir   -> exit 1  + "evidence dir not found" (line 34)
#   * matching sha256 manifest    -> "PASS  sha256sum -c manifest.sha256" line
#     (the sha256 arm at line 60-65 emits this PASS regardless of cosign presence)
#   * tampered sha256 manifest    -> "FAIL  sha256sum" + exit 1
#     (the verbose re-run arm at line 67-75; RESULT: FAIL exit at line 492-494)
#   * merkle-root.txt present but its cosign bundle absent -> the §6.2-A regression
#     FAIL "merkle-root.cosign.bundle missing while merkle-root.txt present (§6.2-A)"
#     (line 213-218). This FAIL is only emitted when cosign is on PATH (the whole §3
#     block is gated by `if have cosign`, line 198); the test SKIPs when cosign is
#     absent so the assertion is honest in any environment.

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  SCRIPT="${REPO_ROOT}/scripts/verify-evidence-pack.sh"
  WORK="$(mktemp -d)"
}

teardown() {
  [ -n "${WORK:-}" ] && rm -rf "${WORK}"
}

@test "verify-evidence-pack: no argument is a usage error (exit 64)" {
  run bash "${SCRIPT}"
  [ "$status" -eq 64 ]
  [[ "$output" == *"usage: verify-evidence-pack.sh"* ]]
}

@test "verify-evidence-pack: missing evidence dir fails hard (exit 1)" {
  run bash "${SCRIPT}" "${WORK}/no-such-dir"
  [ "$status" -eq 1 ]
  [[ "$output" == *"evidence dir not found"* ]]
}

@test "verify-evidence-pack: matching sha256 manifest yields a PASS line" {
  mkdir -p "${WORK}/pack"
  printf 'hello\n' > "${WORK}/pack/data.txt"
  ( cd "${WORK}/pack" && sha256sum data.txt > manifest.sha256 )
  run bash "${SCRIPT}" "${WORK}/pack"
  [[ "$output" == *"PASS  sha256sum -c manifest.sha256"* ]]
}

@test "verify-evidence-pack: tampered sha256 manifest is a FAIL (exit 1)" {
  mkdir -p "${WORK}/pack"
  printf 'hello\n' > "${WORK}/pack/data.txt"
  ( cd "${WORK}/pack" && sha256sum data.txt > manifest.sha256 )
  printf 'TAMPERED\n' > "${WORK}/pack/data.txt"
  run bash "${SCRIPT}" "${WORK}/pack"
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL  sha256sum"* ]]
}

@test "verify-evidence-pack: merkle-root.txt without cosign bundle is the §6.2-A FAIL" {
  command -v cosign >/dev/null 2>&1 || skip "cosign absent — §3 cosign block is SKIPped, not a FAIL (honest NEEDS-tool)"
  mkdir -p "${WORK}/pack"
  printf 'deadbeef\n' > "${WORK}/pack/merkle-root.txt"
  run bash "${SCRIPT}" "${WORK}/pack"
  [ "$status" -eq 1 ]
  [[ "$output" == *"merkle-root.cosign.bundle missing while merkle-root.txt present"* ]]
}
