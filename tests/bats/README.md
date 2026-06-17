# Shell-script unit suite (`tests/bats/`) — T-81

A [bats](https://github.com/bats-core/bats-core) unit-test suite for the
**evidence shell scripts**. These are the highest-value, hardest-to-cover pieces
of the pipeline: the supply-chain pin guard, the sealing-completeness self-test,
the verification runbook, the compliance-matrix orchestrator, and the sealing
driver. The Python validators are covered by `tests/compliance` (pytest); this
suite covers the **bash** logic those Python modules are wrapped in.

Every `@test` asserts **real behavior** — the process exit code *and* a substring
of the captured output — using only bats built-ins (`run`, `$status`, `$output`).
No `bats-support` / `bats-assert` helper libraries are required, because the CI
job (`.github/workflows/self-test.yml`) installs plain `bats` via `apt-get`.

## Files

| File | Script under test | Tests |
|---|---|---|
| `check-action-pins.bats` | `scripts/check-action-pins.sh` | 6 |
| `check-sealing-completeness.bats` | `scripts/check-sealing-completeness.sh` | 6 |
| `verify-evidence-pack.bats` | `scripts/verify-evidence-pack.sh` | 5 |
| `generate-compliance-matrix.bats` | `scripts/generate-compliance-matrix.sh` | 4 |
| `seal-evidence.bats` | `scripts/seal-evidence.sh` | 2 |

## Coverage floor

**Floor: >= 12 behavioral assertions across the suite. Current: 23 `@test`
cases** (each asserts an exit code and/or an output substring), well above the
floor. The floor is a *minimum*, not a target — adding a script behavior should
add a test. CI does **not** auto-enforce the count today (bats has no built-in
count gate); the floor is enforced by review of this table. A quick local count:

```bash
grep -rhc '^@test' tests/bats/*.bats | paste -sd+ | bc   # -> 23
```

The chosen behaviors are the ones an auditor or attacker would probe first:

- **Negative / fail-closed paths** (a guard that does not trip is worthless): a
  planted `actions/checkout@v4` mutable tag must fail the pin audit; an empty
  pack must fail the completeness self-test in CI mode; a tampered `manifest.sha256`
  must fail verification; an empty `{}` `security-report.json` must read
  `INDETERMINATE`, never a silent `PASS` (the T-12 keystone invariant).
- **Degrade-mode contract**: the same empty pack that fails closed in CI must
  *pass* (exit 0, `OK-DEGRADED`) when `EVIDENCE_ALLOW_DEGRADE=1`.
- **Usage / precondition gates**: wrong argc -> `exit 64`; missing evidence dir
  -> `exit 1`; missing/empty workflows dir -> `exit 2`.

Each assertion cites the exact line of the script it targets in the test-file
header comment, so a future refactor that changes an exit code surfaces here.

## How CI runs them

Wired into **`.github/workflows/self-test.yml`** (T-83), which is the pipeline's
own quality gate. The relevant steps:

```yaml
- name: Install bats (T-81 shell sub-suite)
  run: |
    sudo apt-get update
    sudo apt-get install -y bats
    bats --version

- name: bats tests/bats (T-81)
  run: |
    if [ -d tests/bats ] && compgen -G 'tests/bats/*.bats' > /dev/null; then
      bats tests/bats
    else
      echo "::warning::T-81 bats suite not present yet"
    fi
```

A failed `@test` turns the `bats tests/bats` step red, which fails the
self-test job (BLOCKING). The suite runs from the **repo root** (`bats tests/bats`),
and each test resolves `scripts/` relative to its own file
(`$(dirname "${BATS_TEST_FILENAME}")/../..`), so it is cwd-independent.

## Running locally

`bats` is **not** installed in the local dev sandbox at the time of authoring, so
the suite was verified statically (`bash -n` on every script under test; each
asserted exit code / output substring was reproduced by running the scripts
directly against inline mktemp fixtures). Live `bats` execution is **NEEDS-CI** —
`self-test.yml` installs and runs it. To run locally once bats is available:

```bash
# from the Pipeline/ repo root
sudo apt-get install -y bats     # or: brew install bats-core
bats tests/bats                  # run the whole suite
bats tests/bats/check-action-pins.bats   # one file
```

## Environment-dependent skips (honest, never faked)

Two tests `skip` (bats's first-class skip, reported distinctly from a pass) when a
prerequisite is genuinely absent, rather than asserting a fabricated result:

- `verify-evidence-pack.bats` — the `§6.2-A` "bundle missing while merkle-root.txt
  present" FAIL is only emitted when **cosign** is on `PATH` (the whole §3 cosign
  block is gated by `if have cosign`). When cosign is absent that path is a `SKIP`
  in the script, so the test `skip`s.
- `generate-compliance-matrix.bats` / others gate on **python3**; the row
  validators cannot run without it, so the tests `skip` rather than assert.

This mirrors the pipeline's house rule: an honest `SKIP` on absent tooling is
correct; a fabricated pass is not.
