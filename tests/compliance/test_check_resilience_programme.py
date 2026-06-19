"""Unit tests for the E.4 ``check_resilience_programme`` validator (SPEC E.4).

Proves the HONEST predicate (DORA Art. 24-25): a PASS requires that the programme
validates against its schema, covers every required scenario class, and that each
required class has at least one scenario whose ``last_run.outcome=='success'`` and
is within its own cadence window. The shipped seed (all ``last_run: null``) must
FAIL with the pending list -- never a file-presence pass -- exactly mirroring the
A.10 restore-test honesty.

Also proves:
  * all scenarios run + in-cadence -> PASS;
  * a never-run required scenario -> FAIL with it listed pending;
  * an overdue scenario -> FAIL;
  * a missing required class -> FAIL;
  * a missing file is INDETERMINATE (not a silent pass, not a hard FAIL);
  * the BLOCKING exit-code mapping (PASS 0 / FAIL 1 / INDETERMINATE 2);
  * ``main`` writes resilience-programme.json with the verdict.

Runs under pytest AND standalone (no pytest required).
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

# Import the validator by path (module name has no hyphens, but be consistent).
_VALIDATOR_PATH = PIPELINE_ROOT / "scripts" / "validators" / "check_resilience_programme.py"
_spec = importlib.util.spec_from_file_location("check_resilience_programme", _VALIDATOR_PATH)
assert _spec and _spec.loader, f"cannot load validator at {_VALIDATOR_PATH}"
crp = importlib.util.module_from_spec(_spec)
sys.modules["check_resilience_programme"] = crp
_spec.loader.exec_module(crp)  # type: ignore[union-attr]

# Skip YAML/jsonschema-dependent tests cleanly if a dep is unavailable.
try:
    import yaml  # noqa: F401
    import jsonschema  # noqa: F401
    _HAVE_DEPS = True
except ImportError:  # pragma: no cover - environment-dependent
    _HAVE_DEPS = False

REF = date(2026, 6, 16)  # deterministic "today"
SEED = PIPELINE_ROOT / "docs" / "runbooks" / "resilience-testing-programme.yaml"
SCHEMA = PIPELINE_ROOT / "schemas" / "resilience-programme.schema.json"


def _need_deps():
    if not _HAVE_DEPS:
        pytest.skip("PyYAML/jsonschema not installed")


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "resilience-testing-programme.yaml"
    p.write_text(body, encoding="utf-8")
    return p


# A fully-conducted, in-cadence programme covering every required class.
def _all_good(run_date: str = "2026-06-01") -> str:
    classes = [
        ("RT-01", "backup-restore"),
        ("RT-02", "failover"),
        ("RT-03", "DR-drill"),
        ("RT-04", "dependency-outage"),
        ("RT-05", "tabletop"),
    ]
    lines = [
        'schema_version: "1.0"',
        'programme_owner: "Tester"',
        "scenarios:",
    ]
    for sid, sclass in classes:
        lines += [
            f'  - id: "{sid}"',
            f'    name: "{sclass} drill"',
            f'    class: "{sclass}"',
            "    cadence_days: 365",
            "    last_run:",
            f'      date: "{run_date}"',
            '      outcome: "success"',
            "    next_due: null",
        ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Honest default: seed (all last_run null) -> FAIL with the pending list       #
# --------------------------------------------------------------------------- #

def test_shipped_seed_fails_with_pending_list():
    """The real seed MUST fail today -- the honest opposite of presence."""
    _need_deps()
    if not SEED.is_file():
        pytest.skip("seed resilience-testing-programme.yaml not present")
    env = crp.evaluate(SEED, SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert env["tier"] == "BLOCKING"
    # Every required class is present in the seed but none conducted -> pending list.
    assert env["measured"]["missing_classes"] == []
    assert env["measured"]["conducted_in_cadence"] == 0
    assert env["measured"]["pending_count"] == 5
    assert any("never conducted" in r for r in env["measured"]["pending"])


# --------------------------------------------------------------------------- #
# All scenarios run + in-cadence -> PASS                                       #
# --------------------------------------------------------------------------- #

def test_all_conducted_in_cadence_passes(tmp_path):
    _need_deps()
    env = crp.evaluate(_write(tmp_path, _all_good()), SCHEMA, today=REF)
    assert env["status"] == "PASS"
    assert env["tier"] == "BLOCKING"
    assert env["measured"]["missing_classes"] == []
    assert env["measured"]["conducted_in_cadence"] == 5
    assert env["measured"]["pending_count"] == 0


# --------------------------------------------------------------------------- #
# A never-run required scenario -> FAIL                                        #
# --------------------------------------------------------------------------- #

def test_never_run_required_scenario_fails(tmp_path):
    _need_deps()
    body = _all_good().replace(
        '    last_run:\n      date: "2026-06-01"\n      outcome: "success"\n    next_due: null',
        "    last_run: null\n    next_due: null",
        1,  # only the first scenario (RT-01 backup-restore) becomes never-run
    )
    env = crp.evaluate(_write(tmp_path, body), SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert any("never conducted" in r for r in env["measured"]["pending"])
    assert "backup-restore" in env["measured"]["uncovered_required_classes"]


# --------------------------------------------------------------------------- #
# An overdue scenario -> FAIL                                                  #
# --------------------------------------------------------------------------- #

def test_overdue_scenario_fails(tmp_path):
    _need_deps()
    # 2025-01-01 is > 365 days before 2026-06-16 -> overdue for RT-01.
    body = _all_good().replace('"2026-06-01"', '"2025-01-01"', 1)
    env = crp.evaluate(_write(tmp_path, body), SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert any("overdue" in r for r in env["measured"]["pending"])


# --------------------------------------------------------------------------- #
# A non-success last run -> FAIL                                               #
# --------------------------------------------------------------------------- #

def test_non_success_outcome_fails(tmp_path):
    _need_deps()
    body = _all_good().replace('outcome: "success"', 'outcome: "fail"', 1)
    env = crp.evaluate(_write(tmp_path, body), SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert any("not 'success'" in r for r in env["measured"]["pending"])


# --------------------------------------------------------------------------- #
# A missing required class -> FAIL                                             #
# --------------------------------------------------------------------------- #

def test_missing_required_class_fails(tmp_path):
    _need_deps()
    body = """\
schema_version: "1.0"
programme_owner: "Tester"
scenarios:
  - id: "RT-01"
    name: "restore"
    class: "backup-restore"
    cadence_days: 365
    last_run:
      date: "2026-06-01"
      outcome: "success"
    next_due: null
"""
    env = crp.evaluate(_write(tmp_path, body), SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert "failover" in env["measured"]["missing_classes"]
    assert "tabletop" in env["measured"]["missing_classes"]


# --------------------------------------------------------------------------- #
# Indeterminate (could not measure) -- not a silent pass                       #
# --------------------------------------------------------------------------- #

def test_missing_file_is_indeterminate(tmp_path):
    env = crp.evaluate(tmp_path / "nope.yaml", SCHEMA, today=REF)
    assert env["status"] == "INDETERMINATE"
    assert env["tier"] == "BLOCKING"


def test_malformed_yaml_is_indeterminate(tmp_path):
    _need_deps()
    log = _write(tmp_path, "scenarios: [ : : not valid : ]\n  - broken\n")
    env = crp.evaluate(log, SCHEMA, today=REF)
    assert env["status"] == "INDETERMINATE"


# --------------------------------------------------------------------------- #
# Schema violation -> FAIL (not a silent pass)                                 #
# --------------------------------------------------------------------------- #

def test_schema_violation_fails(tmp_path):
    _need_deps()
    # bad class value -> schema enum violation.
    body = """\
schema_version: "1.0"
programme_owner: "Tester"
scenarios:
  - id: "RT-01"
    name: "x"
    class: "not-a-valid-class"
    cadence_days: 365
    last_run: null
    next_due: null
"""
    env = crp.evaluate(_write(tmp_path, body), SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert "schema" in env["detail"].lower()


# --------------------------------------------------------------------------- #
# Exit-code mapping (BLOCKING tier)                                            #
# --------------------------------------------------------------------------- #

def test_exit_codes_match_status(tmp_path):
    _need_deps()
    from scripts.validators import libcompliance as lc

    fail_env = crp.evaluate(SEED, SCHEMA, today=REF)
    assert lc.exit_code_for(fail_env["status"], fail_env["tier"]) == 1

    pass_env = crp.evaluate(_write(tmp_path, _all_good()), SCHEMA, today=REF)
    assert lc.exit_code_for(pass_env["status"], pass_env["tier"]) == 0

    indet_env = crp.evaluate(tmp_path / "nope.yaml", SCHEMA, today=REF)
    assert lc.exit_code_for(indet_env["status"], indet_env["tier"]) == 2


# --------------------------------------------------------------------------- #
# main() writes resilience-programme.json with the verdict                     #
# --------------------------------------------------------------------------- #

def test_main_writes_json_on_pass(tmp_path):
    _need_deps()
    prog = _write(tmp_path, _all_good())
    out = tmp_path / "resilience-programme.json"
    with pytest.raises(SystemExit) as exc:
        crp.main([str(prog), "--schema", str(SCHEMA), "--out", str(out)])
    assert exc.value.code == 0
    payload = json.loads(out.read_text())
    assert payload["status"] == "PASS"
    assert payload["validator"] == "check_resilience_programme"


def test_main_exits_one_on_seed_fail(tmp_path):
    _need_deps()
    if not SEED.is_file():
        pytest.skip("seed not present")
    out = tmp_path / "resilience-programme.json"
    with pytest.raises(SystemExit) as exc:
        crp.main([str(SEED), "--schema", str(SCHEMA), "--out", str(out)])
    assert exc.value.code == 1
    payload = json.loads(out.read_text())
    assert payload["status"] == "FAIL"
    assert payload["measured"]["conducted_in_cadence"] == 0


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
