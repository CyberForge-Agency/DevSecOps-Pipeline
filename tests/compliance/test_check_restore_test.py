"""Unit tests for the A.10 ``check-restore-test`` validator (task T-29).

Proves the HONEST predicate (DORA Art. 11-12): a PASS requires a *logged*
restore drill that is outcome==success, within the cadence window (<=365d), and
RTO-met (rto_actual<=rto_target). The shipped seed log (``tests: []``) and the
bcdr-plan "Not yet conducted" reality must FAIL -- never a file-presence pass.

Also proves:
  * adding a successful, in-window, RTO-met entry flips it to PASS;
  * an RTO breach / stale / non-success entry stays FAIL;
  * a missing log is INDETERMINATE (not a silent pass, not a hard FAIL);
  * ``restore-test.json`` records ``last_successful_test_date`` in ``measured``;
  * the BLOCKING exit-code mapping (PASS 0 / FAIL 1 / INDETERMINATE 2).

Runs under pytest (``python3 -m pytest tests/compliance/test_check_restore_test.py -q``)
AND standalone (``python3 tests/compliance/test_check_restore_test.py``) so the
suite is verifiable even where pytest is not installed.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date
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

        class _Skipped(BaseException):
            pass

        @staticmethod
        def raises(exc):
            return _PytestShim._Raises(exc)

        @staticmethod
        def skip(reason=""):
            raise _PytestShim._Skipped(reason)

    pytest = _PytestShim()  # type: ignore[assignment]

PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

# The validator filename has hyphens, so import it by path rather than dotted name.
_VALIDATOR_PATH = PIPELINE_ROOT / "scripts" / "validators" / "check-restore-test.py"
_spec = importlib.util.spec_from_file_location("check_restore_test", _VALIDATOR_PATH)
assert _spec and _spec.loader, f"cannot load validator at {_VALIDATOR_PATH}"
crt = importlib.util.module_from_spec(_spec)
sys.modules["check_restore_test"] = crt
_spec.loader.exec_module(crt)  # type: ignore[union-attr]

# Skip every YAML-dependent test cleanly if PyYAML is unavailable in this env.
try:
    import yaml  # noqa: F401
    _HAVE_YAML = True
except ImportError:  # pragma: no cover - environment-dependent
    _HAVE_YAML = False

REF = date(2026, 6, 16)  # deterministic "today"
SEED_LOG = PIPELINE_ROOT / "docs" / "runbooks" / "restore-test-log.yaml"


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "restore-test-log.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def _need_yaml():
    if not _HAVE_YAML:
        pytest.skip("PyYAML not installed")


# --------------------------------------------------------------------------- #
# Honest default: empty / "Not yet conducted" -> FAIL                          #
# --------------------------------------------------------------------------- #

def test_empty_log_fails(tmp_path):
    _need_yaml()
    log = _write(tmp_path, "tests: []\n")
    env = crt.evaluate(log, today=REF)
    assert env["status"] == "FAIL"
    assert env["tier"] == "BLOCKING"
    assert env["measured"]["successful_in_window"] == 0
    assert env["measured"]["last_successful_test_date"] is None


def test_shipped_seed_log_fails():
    """The real seed file MUST fail today -- this is the honest opposite of presence."""
    _need_yaml()
    if not SEED_LOG.is_file():
        pytest.skip("seed restore-test-log.yaml not present")
    env = crt.evaluate(SEED_LOG, today=REF)
    assert env["status"] == "FAIL"
    assert "Not yet conducted" in env["detail"] or "no restore drill logged" in env["detail"]


def test_none_document_fails(tmp_path):
    _need_yaml()
    log = _write(tmp_path, "# only comments, no tests key\n")
    env = crt.evaluate(log, today=REF)
    assert env["status"] == "FAIL"
    assert env["measured"]["total_logged"] == 0


# --------------------------------------------------------------------------- #
# Adding a successful, in-window, RTO-met entry flips to PASS                   #
# --------------------------------------------------------------------------- #

_GOOD_ENTRY = """\
tests:
  - test_date: "2026-06-01"
    scenario: "Terraform state restore drill"
    rto_target: 60
    rto_actual: 38
    rpo_actual: 0
    outcome: "success"
    evidence: "bcdr-drills/bcdr-drill-2026-06-01.tar.gz"
    sign_off: "Szymon Mytych"
"""


def test_successful_in_window_rto_met_passes(tmp_path):
    _need_yaml()
    log = _write(tmp_path, _GOOD_ENTRY)
    env = crt.evaluate(log, today=REF)
    assert env["status"] == "PASS"
    assert env["tier"] == "BLOCKING"
    assert env["measured"]["last_successful_test_date"] == "2026-06-01"
    assert env["measured"]["rto_actual"] == 38
    assert env["measured"]["rto_target"] == 60
    assert env["measured"]["successful_in_window"] == 1


def test_pass_records_evidence_and_signoff(tmp_path):
    _need_yaml()
    log = _write(tmp_path, _GOOD_ENTRY)
    env = crt.evaluate(log, today=REF)
    assert env["measured"]["evidence"].endswith(".tar.gz")
    assert env["measured"]["sign_off"] == "Szymon Mytych"


def test_picks_most_recent_success(tmp_path):
    _need_yaml()
    body = """\
tests:
  - test_date: "2026-01-10"
    scenario: "old drill"
    rto_target: 60
    rto_actual: 50
    rpo_actual: 0
    outcome: "success"
  - test_date: "2026-05-20"
    scenario: "newer drill"
    rto_target: 60
    rto_actual: 41
    rpo_actual: 0
    outcome: "success"
"""
    env = crt.evaluate(_write(tmp_path, body), today=REF)
    assert env["status"] == "PASS"
    assert env["measured"]["last_successful_test_date"] == "2026-05-20"
    assert env["measured"]["successful_in_window"] == 2


# --------------------------------------------------------------------------- #
# Negative cases stay FAIL (no masking)                                        #
# --------------------------------------------------------------------------- #

def test_rto_breach_fails(tmp_path):
    _need_yaml()
    body = """\
tests:
  - test_date: "2026-06-01"
    scenario: "slow restore"
    rto_target: 60
    rto_actual: 95
    rpo_actual: 0
    outcome: "success"
"""
    env = crt.evaluate(_write(tmp_path, body), today=REF)
    assert env["status"] == "FAIL"
    assert any("RTO breached" in r for r in env["measured"]["rejections"])


def test_stale_success_fails(tmp_path):
    _need_yaml()
    # 2025-01-01 is > 365 days before 2026-06-16.
    body = """\
tests:
  - test_date: "2025-01-01"
    scenario: "ancient drill"
    rto_target: 60
    rto_actual: 30
    rpo_actual: 0
    outcome: "success"
"""
    env = crt.evaluate(_write(tmp_path, body), today=REF)
    assert env["status"] == "FAIL"
    assert any("stale" in r for r in env["measured"]["rejections"])


def test_non_success_outcome_fails(tmp_path):
    _need_yaml()
    body = """\
tests:
  - test_date: "2026-06-01"
    scenario: "failed drill"
    rto_target: 60
    rto_actual: 30
    rpo_actual: 0
    outcome: "fail"
"""
    env = crt.evaluate(_write(tmp_path, body), today=REF)
    assert env["status"] == "FAIL"
    assert any("not 'success'" in r for r in env["measured"]["rejections"])


def test_missing_required_field_fails(tmp_path):
    _need_yaml()
    body = """\
tests:
  - test_date: "2026-06-01"
    scenario: "incomplete drill"
    outcome: "success"
"""
    env = crt.evaluate(_write(tmp_path, body), today=REF)
    assert env["status"] == "FAIL"
    assert any("missing required field" in r for r in env["measured"]["rejections"])


def test_future_dated_success_fails(tmp_path):
    _need_yaml()
    body = """\
tests:
  - test_date: "2026-12-01"
    scenario: "future drill"
    rto_target: 60
    rto_actual: 30
    rpo_actual: 0
    outcome: "success"
"""
    env = crt.evaluate(_write(tmp_path, body), today=REF)
    assert env["status"] == "FAIL"
    assert any("future" in r for r in env["measured"]["rejections"])


# --------------------------------------------------------------------------- #
# Indeterminate (could not measure) -- not a silent pass                       #
# --------------------------------------------------------------------------- #

def test_missing_file_is_indeterminate(tmp_path):
    env = crt.evaluate(tmp_path / "does-not-exist.yaml", today=REF)
    assert env["status"] == "INDETERMINATE"
    assert env["tier"] == "BLOCKING"


def test_malformed_yaml_is_indeterminate(tmp_path):
    _need_yaml()
    log = _write(tmp_path, "tests: [ : : not valid : ]\n  - broken\n")
    env = crt.evaluate(log, today=REF)
    assert env["status"] == "INDETERMINATE"


def test_tests_not_a_list_is_indeterminate(tmp_path):
    _need_yaml()
    env = crt.evaluate(_write(tmp_path, "tests: not-a-list\n"), today=REF)
    assert env["status"] == "INDETERMINATE"


# --------------------------------------------------------------------------- #
# Exit-code mapping (BLOCKING tier)                                            #
# --------------------------------------------------------------------------- #

def test_exit_codes_match_status(tmp_path):
    _need_yaml()
    from scripts.validators import libcompliance as lc

    fail_env = crt.evaluate(_write(tmp_path, "tests: []\n"), today=REF)
    assert lc.exit_code_for(fail_env["status"], fail_env["tier"]) == 1

    pass_log = _write(tmp_path, _GOOD_ENTRY)
    pass_env = crt.evaluate(pass_log, today=REF)
    assert lc.exit_code_for(pass_env["status"], pass_env["tier"]) == 0

    indet_env = crt.evaluate(tmp_path / "nope.yaml", today=REF)
    assert lc.exit_code_for(indet_env["status"], indet_env["tier"]) == 2


# --------------------------------------------------------------------------- #
# main() writes restore-test.json recording last_successful_test_date          #
# --------------------------------------------------------------------------- #

def test_main_writes_restore_test_json_on_pass(tmp_path):
    _need_yaml()
    log = _write(tmp_path, _GOOD_ENTRY)
    out = tmp_path / "restore-test.json"
    with pytest.raises(SystemExit) as exc:
        crt.main([str(log), "--out", str(out)])
    assert exc.value.code == 0
    payload = json.loads(out.read_text())
    assert payload["status"] == "PASS"
    assert payload["measured"]["last_successful_test_date"] == "2026-06-01"
    assert payload["validator"] == "check-restore-test"


def test_main_exits_one_on_seed_fail(tmp_path):
    _need_yaml()
    log = _write(tmp_path, "tests: []\n")
    out = tmp_path / "restore-test.json"
    with pytest.raises(SystemExit) as exc:
        crt.main([str(log), "--out", str(out)])
    assert exc.value.code == 1
    payload = json.loads(out.read_text())
    assert payload["status"] == "FAIL"
    assert payload["measured"]["last_successful_test_date"] is None


# --------------------------------------------------------------------------- #
# Standalone fallback runner (no pytest required)                             #
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import inspect
    import tempfile
    import traceback

    fns = [
        (name, obj)
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    passed = failed = skipped = 0
    _Skipped = getattr(pytest, "_Skipped", None)

    def _run_one(name, fn, kwargs):
        global passed, failed, skipped
        try:
            fn(**kwargs)
            passed += 1
        except BaseException as exc:  # noqa: BLE001
            if _Skipped is not None and isinstance(exc, _Skipped):
                skipped += 1
                return
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()

    for name, fn in fns:
        params = list(inspect.signature(fn).parameters)
        if "tmp_path" in params:
            with tempfile.TemporaryDirectory() as d:
                _run_one(name, fn, {"tmp_path": Path(d)})
        else:
            _run_one(name, fn, {})

    print(f"\nstandalone: {passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)
