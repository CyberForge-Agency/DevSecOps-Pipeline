#!/usr/bin/env bats
#
# T-81 shell sub-suite — scripts/check-action-pins.sh (the supply-chain pin guard).
#
# Each @test asserts REAL behavior of the script: the process exit code AND a
# substring of its combined output, using only bats built-ins (`run`, $status,
# $output) — no bats-support/bats-assert (self-test.yml installs plain bats only).
#
# Fixtures are built inline in a per-test mktemp -d workspace (WORK) and torn down
# in teardown(); nothing is ever written into the repo tree.
#
# Behaviors asserted (cite the targeted script line in check-action-pins.sh):
#   * planted actions/checkout@v4 (mutable tag)  -> exit 1 + "::error::" + the ref
#     (classification falls through to BAD_LINES; exit 1 at script line 163-167)
#   * all-SHA-pinned workflow                     -> exit 0 + "all ... SHA/digest-pinned"
#     (SHA40 match at script line 120-122; exit 0 at line 169-170)
#   * missing workflows dir                       -> exit 2 + "workflows directory not found"
#     (guard at script line 44-47)
#   * dir with no *.yml|*.yaml files              -> exit 2 + "no workflow files"
#     (guard at script line 53-56)
#   * local ./ reusable call                      -> exit 0 + "local=1" (LOCAL branch,
#     script line 115-116; not counted as unpinned)

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  SCRIPT="${REPO_ROOT}/scripts/check-action-pins.sh"
  WORK="$(mktemp -d)"
}

teardown() {
  [ -n "${WORK:-}" ] && rm -rf "${WORK}"
}

@test "check-action-pins: planted @v4 tag is flagged (exit 1)" {
  mkdir -p "${WORK}/wf"
  cat > "${WORK}/wf/bad.yml" <<'YML'
name: bad
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
YML
  run bash "${SCRIPT}" "${WORK}/wf"
  [ "$status" -eq 1 ]
  [[ "$output" == *"tag/branch=1"* ]]
}

@test "check-action-pins: @v4 ref name appears in the error block" {
  mkdir -p "${WORK}/wf"
  cat > "${WORK}/wf/bad.yml" <<'YML'
jobs:
  b:
    steps:
      - uses: actions/checkout@v4
YML
  run bash "${SCRIPT}" "${WORK}/wf"
  [ "$status" -eq 1 ]
  [[ "$output" == *"actions/checkout@v4"* ]]
}

@test "check-action-pins: all-SHA-pinned workflow passes (exit 0)" {
  mkdir -p "${WORK}/wf"
  cat > "${WORK}/wf/good.yml" <<'YML'
jobs:
  g:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
YML
  run bash "${SCRIPT}" "${WORK}/wf"
  [ "$status" -eq 0 ]
  [[ "$output" == *"SHA/digest-pinned"* ]]
}

@test "check-action-pins: missing workflows dir is a usage error (exit 2)" {
  run bash "${SCRIPT}" "${WORK}/does-not-exist"
  [ "$status" -eq 2 ]
  [[ "$output" == *"workflows directory not found"* ]]
}

@test "check-action-pins: dir without workflow files is a usage error (exit 2)" {
  mkdir -p "${WORK}/empty"
  run bash "${SCRIPT}" "${WORK}/empty"
  [ "$status" -eq 2 ]
  [[ "$output" == *"no workflow files"* ]]
}

@test "check-action-pins: in-repo ./ reusable call is allowed, not unpinned (exit 0)" {
  mkdir -p "${WORK}/wf"
  cat > "${WORK}/wf/local.yml" <<'YML'
jobs:
  l:
    uses: ./.github/workflows/reusable.yml
YML
  run bash "${SCRIPT}" "${WORK}/wf"
  [ "$status" -eq 0 ]
  [[ "$output" == *"local=1"* ]]
}
