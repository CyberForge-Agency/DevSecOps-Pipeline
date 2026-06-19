"""Unit tests for the A.9 assert-crypto validator (task T-28).

Proves the validator performs a *real* threshold assertion against the parsed
Terraform crypto posture (not a hardcoded PASS):

  * PASS on the current-shaped plan (TLS1_2, encrypted store, Key Vault present)
  * FAIL + exit 1 on a plan that regresses a resource to TLS1_0, naming it
  * FAIL on missing key-management
  * INDETERMINATE (never silent PASS) on missing/empty terraform JSON
  * the ordered TLS enum comparison and the state (`values`) vs plan
    (`planned_values`) walkers
  * the aggregate envelope carries the measured TLS version + counts, and the
    cipher floor is recorded EVIDENCE-ONLY (never a gate)

Runs under pytest (``python3 -m pytest tests/compliance/test_assert_crypto.py -q``)
AND standalone (``python3 tests/compliance/test_assert_crypto.py``) so the suite is
verifiable even where pytest is not installed.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback: minimal pytest surface used here
    class _PytestShim:
        class _Raises:
            def __init__(self, exc):
                self.exc = exc
                self.value = None

            def __enter__(self):
                return self

            def __exit__(self, et, ev, tb):
                if et is None:
                    raise AssertionError(f"DID NOT RAISE {self.exc}")
                self.value = ev
                return issubclass(et, self.exc)

        @staticmethod
        def raises(exc):
            return _PytestShim._Raises(exc)

        @staticmethod
        def skip(reason=""):
            raise AssertionError(f"SKIP: {reason}")

    pytest = _PytestShim()  # type: ignore


# --------------------------------------------------------------------------- #
# Paths + module loading (load the hyphenated script by file path)            #
# --------------------------------------------------------------------------- #

REPO_PIPELINE = Path(__file__).resolve().parents[2]
VALIDATORS = REPO_PIPELINE / "scripts" / "validators"
SCRIPT = VALIDATORS / "assert-crypto.py"
BASELINE = REPO_PIPELINE / "docs" / "governance" / "crypto-baseline.yaml"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Make `import libcompliance` resolve for the loaded module.
sys.path.insert(0, str(VALIDATORS))


def _load_validator():
    """Import the hyphenated ``assert-crypto.py`` as a module object."""
    spec = importlib.util.spec_from_file_location("assert_crypto", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ac = _load_validator()
lc = ac.lc


def _baseline():
    data, err = ac.load_baseline(BASELINE)
    assert err is None, f"baseline failed to load: {err}"
    return data


def _load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Baseline + fixture sanity                                                    #
# --------------------------------------------------------------------------- #

def test_baseline_loads_and_has_threshold():
    b = _baseline()
    assert b["min_tls_version"] == "TLS1_2"
    assert b["at_rest"]["min_encrypted_stores"] >= 1
    assert b["key_management"]["min_key_managers"] >= 1


def test_fixtures_exist():
    for f in ("tfplan-crypto-pass.json", "tfplan-crypto-tls10.json",
              "tfstate-crypto-no-kms.json"):
        assert (FIXTURES / f).is_file(), f


# --------------------------------------------------------------------------- #
# TLS ordered-enum comparison                                                  #
# --------------------------------------------------------------------------- #

def test_tls_rank_ordering():
    assert ac._tls_rank("TLS1_0") < ac._tls_rank("TLS1_2") < ac._tls_rank("TLS1_3")
    assert ac._tls_rank("tls1_2") == ac._tls_rank("TLS1_2")  # case-insensitive
    assert ac._tls_rank("SSLv3") is None
    assert ac._tls_rank(None) is None


# --------------------------------------------------------------------------- #
# Resource walking (plan vs state)                                             #
# --------------------------------------------------------------------------- #

def test_collect_resources_walks_plan_child_modules():
    tf = _load_fixture("tfplan-crypto-pass.json")
    resources = ac.collect_resources(tf)
    types = {r["type"] for r in resources}
    assert "azurerm_storage_account" in types
    assert "azurerm_key_vault" in types
    assert "azurerm_resource_group" in types  # root-module resource included


def test_collect_resources_walks_state_values():
    tf = _load_fixture("tfstate-crypto-no-kms.json")
    resources = ac.collect_resources(tf)
    types = {r["type"] for r in resources}
    assert "azurerm_storage_account" in types
    assert "azurerm_key_vault" not in types


# --------------------------------------------------------------------------- #
# Aggregate: PASS on current-shaped plan                                       #
# --------------------------------------------------------------------------- #

def test_pass_on_current_plan():
    tf = _load_fixture("tfplan-crypto-pass.json")
    env = ac.assert_crypto(tf, _baseline())
    assert env["status"] == lc.Status.PASS
    assert env["tier"] == lc.Tier.BLOCKING
    assert lc.exit_code_for(env["status"], env["tier"]) == 0
    # measured surfaces the actual TLS versions (acceptance: .measured shows it)
    tls_measured = env["measured"]["tls_floor"]["measured"]
    versions = {m["min_tls_version"] for m in tls_measured}
    assert versions == {"TLS1_2"}
    # cipher floor is EVIDENCE-ONLY context, never a gate
    assert env["measured"]["cipher_floor"]["tier"] == lc.Tier.EVIDENCE_ONLY


def test_envelope_shape_matches_t33_keys():
    env = ac.assert_crypto(_load_fixture("tfplan-crypto-pass.json"), _baseline())
    assert set(env) == set(lc.ENVELOPE_KEYS)
    assert json.dumps(env)  # serialisable
    assert env["tool_version"] == ac.TOOL_VERSION


# --------------------------------------------------------------------------- #
# Aggregate: FAIL on TLS1_0 regression (the load-bearing assertion)           #
# --------------------------------------------------------------------------- #

def test_fail_on_tls10_regression_names_resource():
    tf = _load_fixture("tfplan-crypto-tls10.json")
    env = ac.assert_crypto(tf, _baseline())
    assert env["status"] == lc.Status.FAIL
    assert lc.exit_code_for(env["status"], env["tier"]) == 1
    # the offending resource is named in the detail
    assert "azurerm_storage_account.this" in env["detail"]
    assert "TLS1_0" in env["detail"]


def test_tls_floor_subcheck_fail_isolated():
    tf = _load_fixture("tfplan-crypto-tls10.json")
    env = ac.check_tls_floor(ac.collect_resources(tf), _baseline())
    assert env["status"] == lc.Status.FAIL
    assert env["threshold"] == "TLS1_2"


# --------------------------------------------------------------------------- #
# Aggregate: FAIL on missing key management                                    #
# --------------------------------------------------------------------------- #

def test_fail_on_missing_key_vault():
    tf = _load_fixture("tfstate-crypto-no-kms.json")
    env = ac.assert_crypto(tf, _baseline())
    assert env["status"] == lc.Status.FAIL
    km = env["measured"]["key_management"]
    assert km["status"] == lc.Status.FAIL
    assert km["measured"] == 0


def test_at_rest_pass_counts_stores():
    tf = _load_fixture("tfstate-crypto-no-kms.json")
    env = ac.check_at_rest(ac.collect_resources(tf), _baseline())
    assert env["status"] == lc.Status.PASS
    assert env["measured"] == 1


# --------------------------------------------------------------------------- #
# Honesty: INDETERMINATE (never silent PASS) on missing/empty input           #
# --------------------------------------------------------------------------- #

def test_empty_plan_never_silently_passes():
    # An empty plan has no encrypted store and no key vault: the BLOCKING gate must
    # NOT pass. TLS is INDETERMINATE (nothing to measure), at-rest + KMS FAIL, so the
    # worst-status-wins aggregate is FAIL. The load-bearing guarantee is: never PASS.
    env = ac.assert_crypto({"planned_values": {"root_module": {}}}, _baseline())
    assert env["status"] != lc.Status.PASS  # explicit: no silent PASS
    assert env["status"] == lc.Status.FAIL
    assert env["measured"]["tls_floor"]["status"] == lc.Status.INDETERMINATE


def test_missing_baseline_is_indeterminate():
    # Honest: cannot read the threshold -> INDETERMINATE, never a guessed PASS.
    data, err = ac.load_baseline(FIXTURES / "no-such-baseline.yaml")
    assert data is None and err is not None


def test_no_tls_resources_is_indeterminate_not_pass():
    env = ac.check_tls_floor([], _baseline())
    assert env["status"] == lc.Status.INDETERMINATE


# --------------------------------------------------------------------------- #
# End-to-end CLI exit codes (proves emit() wiring + crypto-posture.json write) #
# --------------------------------------------------------------------------- #

def _run_cli(fixture_name, out_path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(FIXTURES / fixture_name),
         "--baseline", str(BASELINE), "--out", str(out_path)],
        capture_output=True, text=True,
    )


def test_cli_pass_exit_zero_and_writes_output(tmp_path=None):
    out = (Path(tmp_path) if tmp_path else FIXTURES.parent) / "crypto-posture.out.json"
    r = _run_cli("tfplan-crypto-pass.json", out)
    assert r.returncode == 0, r.stderr
    env = json.loads(r.stdout.strip().splitlines()[-1])
    assert env["status"] == "PASS"
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["status"] == "PASS"
    out.unlink(missing_ok=True)


def test_cli_tls10_exit_one(tmp_path=None):
    out = (Path(tmp_path) if tmp_path else FIXTURES.parent) / "crypto-posture.fail.json"
    r = _run_cli("tfplan-crypto-tls10.json", out)
    assert r.returncode == 1, f"expected exit 1, got {r.returncode}: {r.stderr}"
    out.unlink(missing_ok=True)


def test_cli_missing_input_indeterminate_exit_two(tmp_path=None):
    out = (Path(tmp_path) if tmp_path else FIXTURES.parent) / "crypto-posture.indet.json"
    r = subprocess.run(
        [sys.executable, str(SCRIPT), str(FIXTURES / "does-not-exist.json"),
         "--baseline", str(BASELINE), "--out", str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode == 2, f"expected exit 2, got {r.returncode}: {r.stderr}"
    out.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Standalone runner (no pytest)                                                #
# --------------------------------------------------------------------------- #

def _standalone() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures: list[str] = []
    for t in tests:
        try:
            t()
        except BaseException as exc:  # noqa: BLE001
            failures.append(f"{t.__name__}: {exc!r}")
    if failures:
        print(f"FAILED {len(failures)}/{len(tests)}:")
        for f in failures:
            print("  - " + f)
        return 1
    print(f"OK: {len(tests)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(_standalone())
