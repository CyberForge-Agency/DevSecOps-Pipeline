# Compliance self-test suite

Unit + behavioural self-tests for the CyberForge compliance/evidence validators — the
`scripts/validators/*` envelope library and per-clause checks (CAC A.1-A.10, DORA/NIS2
matrix rows, VEX, SoA-maturity, risk-acceptance, applicability, the T-33 envelope), the
`scripts/*.sh` sealing/verification scripts, and the three OPA Rego policies.

This is the **self-test phase** of the pipeline (task T-83): these tests run as a
gating CI quality job — `.github/workflows/self-test.yml` — on **both `push` and
`pull_request`** (and via `workflow_call`, so `pipeline.yml` invokes it as its
earliest phase, ahead of build/sign/deploy). A failing assertion in any sub-suite,
a failed OPA rule, or a re-introduced unpinned action fails the overall run.

## What runs where

| Sub-suite | Lives in | Runner | Gates on |
|-----------|----------|--------|----------|
| Python validator/script tests | `tests/compliance/test_*.py` | `pytest` | any failed assertion |
| OPA policy tests | `policies/*_test.rego` | `opa test` | any failed `test_*` rule |
| Action-pin audit (T-71) | `.github/workflows/*.yml` | `scripts/check-action-pins.sh` | any unpinned `uses:` |
| Shell-script tests (bats) | `tests/bats/*.bats` (T-81) | `bats` | any failed `@test` |

> `self-test.yml` (T-83) installs `pytest pytest-cov pyyaml jsonschema` (pip) and
> `bats` (apt) in CI, then invokes all four sub-suites fail-on-error. The bats
> sub-suite is owned by T-81: `bats` is installed and version-checked
> unconditionally, but until `tests/bats/*.bats` files land the bats step prints an
> honest "suite not yet present" warning rather than a silent skip or a fake pass.

## Running the suite

Run everything from the **`Pipeline/` directory** (this is the cwd the CI quality job
uses). The path-import anchoring also lets you run from the repo root via
`pytest Pipeline/tests/compliance`, but `Pipeline/` is the canonical cwd.

```bash
cd Pipeline

# 1. Python validator/script tests (the bulk of the suite)
python3 -m pytest tests/compliance -q

#    with the BLOCKING coverage floor the CI job enforces (T-82/T-83): scoped to
#    `scripts/validators` (the BLOCKING gate logic) and set to 70%. The suite
#    measures ~74% on that scope, so the number CLAIMED == the number ENFORCED.
#    The wider `scripts/` tree contains large generators this suite does not
#    exercise, so gating the whole tree at a fictional 80% would be decorative;
#    we honestly scope to the validators and enforce a floor that is genuinely met.
python3 -m pytest tests/compliance \
  --cov=scripts/validators --cov-report=term-missing --cov-fail-under=70

# 2. OPA policy tests
opa test policies -v

# 3. Shell-script tests (once T-81 lands tests/bats/*.bats)
bats tests/bats/
```

### Whole-chain offline harness

`scripts/run-local-e2e.sh` runs the **entire offline evidence chain** end-to-end on
a laptop — this self-test suite plus the build/seal/verify pipeline — and prints a
single GREEN/RED summary. It does **no** Azure, no cloud upload, and no deploy:

```bash
cd Pipeline
scripts/run-local-e2e.sh            # GREEN only if every chain stage runs + verify passes
```

Stages: (0) build+unit-test the demo app *iff* `app/node_modules` is present;
(1) this self-test suite (pytest if available, else each `test_*.py` standalone)
+ `opa test policies`; (2) `aggregate-compliance.py`; (3)
`generate-compliance-matrix.sh`; (4) `generate-evidence-manifest.py`; (5)
`seal-evidence.sh` in `EVIDENCE_ALLOW_DEGRADE=1`; (6) re-stamp the manifest; (7)
`verify-evidence-pack.sh`.

It draws a hard line between **chain execution** (does each stage run and produce
its artifact, and does verify pass with 0 FAILs? — this gates GREEN/RED) and the
**compliance verdict** (the honest PASS/FAIL of the *content*, reported beside the
summary but never forced green — see "Validator tiers and honest failures" below).
Offline, cosign/curl are hidden so the seal models a clean no-sigstore box
(signatures recorded `unavailable`, verify SKIPs them) instead of hanging on
keyless-signing retries. Useful knobs: `E2E_SELFTEST_ADVISORY=1` (downgrade
known-external self-test failures to advisory), `E2E_KEEP_COSIGN=1` (exercise the
real, slow keyless-degrade path), `E2E_KEEP_WORKDIR=1` (keep the temp work dir).
The harness works on an isolated copy of `evidence/` and never mutates the source.

### Discover without running

```bash
cd Pipeline
python3 -m pytest tests/compliance --collect-only -q   # lists every collected test id
opa test policies --explain fails                      # lists policy test rules
```

The meta self-test `test_suite_discovery.py` asserts the wiring itself: that the repo
root is on `sys.path`, that `scripts.validators` resolves *inside this repo*, that every
validator module imports clean, and that every sibling `test_*.py` (including the
hyphen-named `test_validate-ropa.py`) is collectable. If discovery is broken, that test
fails loudly instead of the suite silently collecting zero tests.

## Dependencies

| Tool | Used by | Install |
|------|---------|---------|
| `pytest` | Python sub-suite (pytest mode) | `pip install pytest` |
| `pytest-cov` | the `--cov-fail-under=70` blocking gate (scoped to `scripts/validators`) | `pip install pytest-cov` |
| `pyyaml` | YAML-reading validators (restore-test, incident-register, ROPA, ROI, applicability, assert-crypto) | `pip install pyyaml` |
| `jsonschema` | schema-validating validators (validate-roi, validate-ropa, applicability) | `pip install jsonschema` |
| `opa` | policy sub-suite | <https://www.openpolicyagent.org/docs/latest/#running-opa> |
| `bats` | shell sub-suite (T-81) | `bats-core` |

One-liner for the Python deps:

```bash
pip install pytest pytest-cov pyyaml jsonschema
```

> Missing `pyyaml`/`jsonschema` does not silently skip — the affected validators raise a
> clear `... is required (pip install ...)` error, which surfaces as a test failure. The
> CI quality job pins and installs these so the suite never degrades to a partial run.

## Dual-mode design (pytest + standalone)

Every `test_*.py` runs **two ways**:

1. **Under pytest** — full assertion introspection, parametrization, fixtures, coverage.
2. **Standalone** — `python3 tests/compliance/test_<name>.py` runs the same checks via a
   tiny built-in `pytest` shim and exits non-zero on failure, so the suite is verifiable
   on a host where `pytest` is not installed (e.g. a minimal evidence-replay box).

This is why each file inserts the Pipeline root onto `sys.path` itself *and* a
`conftest.py` does the same: the self-insert covers the standalone path, the conftest
covers pytest collection from any cwd. Both are idempotent; neither changes test
behaviour, only discovery robustness.

## Validator tiers and honest failures

Validators emit the **T-33 envelope** (`{status, tier, measured, threshold, detail,
tool_version, validator, checked_at}`) and fall into two tiers:

- **BLOCKING** — a `FAIL` here is meant to fail the aggregate gate on non-PR runs.
- **EVIDENCE-ONLY** — recorded for the audit pack but never gates the build.

The aggregate compliance gate fails **only on BLOCKING failures**. These self-tests
assert that each validator returns the *correct tier and status for given inputs* — they
do **not** force a green result. A validator that legitimately `FAIL`s on real, bad
evidence (e.g. a stale DPA register or a restore-test that was never conducted) is
**correct** and the gate *should* fail on it; the fix is to remediate the evidence, not
to weaken the test. See `OPERATIONALIZATION-TASKLIST.md` (T-83 and the validator tasks)
for the source-of-truth definitions.

## Adding a test

- Name the file `test_<thing>.py` and place it here.
- Follow the dual-mode pattern (pytest shim + `__main__` standalone runner) used by the
  existing files so it runs with or without pytest.
- Import the validator under test with `from scripts.validators import <module>` (the
  `conftest.py` anchor makes this resolve), or by `importlib` file-path load for
  hyphen-named modules (e.g. `validate-roi.py`).
- Do **not** add a `pytest.ini`/`pyproject.toml` here that changes import mode without
  re-running `test_suite_discovery.py` — it is the canary for the discovery wiring.
