"""Unit tests for check-incident-register (A.4 / task T-23).

Proves the T-23 acceptance criteria:
* the seeded register PASSes with all clock fields present (exit 0);
* an entry missing ``classification_ts`` or any clock field FAILs (exit 1);
* ``incident-readiness.json`` records the entry count in ``measured``;
plus schema/structure edge cases (bad severity, non-bool major_bool, empty/missing
register -> INDETERMINATE) and the EVIDENCE-ONLY tiering of the count.

Runs under pytest AND standalone (``python3 tests/compliance/test_check_incident_register.py``)
so the suite is verifiable even where pytest is not installed — mirrors
``test_libcompliance.py``.
"""

from __future__ import annotations

import importlib.util
import json
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

        class _Skipped(BaseException):
            pass

        @staticmethod
        def raises(exc):
            return _PytestShim._Raises(exc)

        @staticmethod
        def skip(reason=""):
            raise _PytestShim._Skipped(reason)

    pytest = _PytestShim()  # type: ignore[assignment]

# Make the Pipeline root importable so the validator + lib resolve regardless of CWD.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

# The validator module name has hyphens, so load it by path under a safe alias.
_VALIDATOR_PATH = PIPELINE_ROOT / "scripts" / "validators" / "check-incident-register.py"
_spec = importlib.util.spec_from_file_location("check_incident_register", _VALIDATOR_PATH)
assert _spec and _spec.loader
cir = importlib.util.module_from_spec(_spec)
sys.modules["check_incident_register"] = cir
_spec.loader.exec_module(cir)

from scripts.validators import libcompliance as lc  # noqa: E402

SEED_REGISTER = PIPELINE_ROOT / "docs" / "governance" / "incident-register.yaml"
SCHEMA = PIPELINE_ROOT / "schemas" / "incident-register.schema.json"


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #

def _good_entry() -> dict:
    return {
        "id": "INC-2026-100",
        "title": "test incident",
        "detection_ts": "2026-05-01T08:00:00Z",
        "classification_ts": "2026-05-01T09:00:00Z",
        "severity": "SEV-2",
        "major_bool": True,
        "clock": {
            "initial_4h": "2026-05-01T10:00:00Z",
            "early_warning_24h": "2026-05-01T20:00:00Z",
            "intermediate_72h": "2026-05-04T09:00:00Z",
            "final_1mo": "2026-05-28T09:00:00Z",
        },
    }


def _write_yaml(tmp_path: Path, data: dict) -> Path:
    import yaml
    p = tmp_path / "reg.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# the seeded register (the headline T-23 acceptance)                          #
# --------------------------------------------------------------------------- #

def test_seed_register_passes():
    env, readiness = cir.run(SEED_REGISTER, SCHEMA)
    assert env["status"] == "PASS", readiness.get("errors")
    assert env["tier"] == "BLOCKING"


def test_seed_register_exit_code_is_zero():
    env, _ = cir.run(SEED_REGISTER, SCHEMA)
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


def test_seed_register_records_entry_count_in_measured():
    env, _ = cir.run(SEED_REGISTER, SCHEMA)
    assert env["measured"]["entry_count"] >= 1
    assert env["measured"]["violations"] == 0


def test_seed_register_has_at_least_one_major_with_full_clock():
    import yaml
    data = yaml.safe_load(SEED_REGISTER.read_text(encoding="utf-8"))
    majors = [e for e in data["incidents"] if e.get("major_bool")]
    assert majors, "seed should contain at least one worked major-incident example"
    for cf in cir.CLOCK_FIELDS:
        assert cir._is_populated(majors[0]["clock"][cf])


# --------------------------------------------------------------------------- #
# FAIL: missing classification / clock fields (T-23 acceptance)               #
# --------------------------------------------------------------------------- #

def test_missing_classification_ts_fails(tmp_path):
    entry = _good_entry()
    del entry["classification_ts"]
    p = _write_yaml(tmp_path, {"incidents": [entry]})
    env, readiness = cir.run(p, SCHEMA)
    assert env["status"] == "FAIL"
    assert lc.exit_code_for(env["status"], env["tier"]) == 1
    assert any("classification_ts" in e for e in readiness["errors"])


def test_empty_classification_ts_fails(tmp_path):
    entry = _good_entry()
    entry["classification_ts"] = "   "  # present-but-blank must still FAIL
    p = _write_yaml(tmp_path, {"incidents": [entry]})
    env, _ = cir.run(p, SCHEMA)
    assert env["status"] == "FAIL"


def test_missing_one_clock_field_fails(tmp_path):
    entry = _good_entry()
    del entry["clock"]["intermediate_72h"]
    p = _write_yaml(tmp_path, {"incidents": [entry]})
    env, readiness = cir.run(p, SCHEMA)
    assert env["status"] == "FAIL"
    assert lc.exit_code_for(env["status"], env["tier"]) == 1
    assert any("intermediate_72h" in e for e in readiness["errors"])


def test_null_clock_field_fails(tmp_path):
    entry = _good_entry()
    entry["clock"]["final_1mo"] = None  # present key, null value -> not populated
    p = _write_yaml(tmp_path, {"incidents": [entry]})
    env, readiness = cir.run(p, SCHEMA)
    assert env["status"] == "FAIL"
    assert any("final_1mo" in e for e in readiness["errors"])


def test_empty_clock_field_fails(tmp_path):
    entry = _good_entry()
    entry["clock"]["initial_4h"] = ""
    p = _write_yaml(tmp_path, {"incidents": [entry]})
    env, _ = cir.run(p, SCHEMA)
    assert env["status"] == "FAIL"


def test_all_four_clock_fields_required(tmp_path):
    # Each individual clock field is independently required.
    for cf in cir.CLOCK_FIELDS:
        entry = _good_entry()
        del entry["clock"][cf]
        p = _write_yaml(tmp_path, {"incidents": [entry]})
        env, readiness = cir.run(p, SCHEMA)
        assert env["status"] == "FAIL", f"removing {cf} should FAIL"
        assert any(cf in e for e in readiness["errors"])


# --------------------------------------------------------------------------- #
# schema/structure validation                                                 #
# --------------------------------------------------------------------------- #

def test_bad_severity_fails(tmp_path):
    entry = _good_entry()
    entry["severity"] = "SEV-9"
    p = _write_yaml(tmp_path, {"incidents": [entry]})
    env, readiness = cir.run(p, SCHEMA)
    assert env["status"] == "FAIL"
    assert any("severity" in e for e in readiness["errors"])


def test_non_bool_major_fails(tmp_path):
    entry = _good_entry()
    entry["major_bool"] = "yes"
    p = _write_yaml(tmp_path, {"incidents": [entry]})
    env, readiness = cir.run(p, SCHEMA)
    assert env["status"] == "FAIL"
    assert any("major_bool" in e for e in readiness["errors"])


def test_missing_incidents_key_fails(tmp_path):
    p = _write_yaml(tmp_path, {"meta": {"owner": "x"}})
    env, readiness = cir.run(p, SCHEMA)
    assert env["status"] == "FAIL"
    assert any("incidents" in e for e in readiness["errors"])


def test_empty_register_is_indeterminate(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("", encoding="utf-8")
    env, _ = cir.run(p, SCHEMA)
    assert env["status"] == "INDETERMINATE"
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


def test_missing_register_is_indeterminate(tmp_path):
    env, _ = cir.run(tmp_path / "nope.yaml", SCHEMA)
    assert env["status"] == "INDETERMINATE"


def test_missing_schema_is_indeterminate_not_pass(tmp_path):
    # No schema -> cannot honestly claim a schema PASS.
    p = _write_yaml(tmp_path, {"incidents": [_good_entry()]})
    env, _ = cir.run(p, tmp_path / "no-schema.json")
    assert env["status"] == "INDETERMINATE"


def test_empty_incidents_list_passes_with_zero_count(tmp_path):
    # An empty incident list is a valid (no-incidents) register: schema-valid, count 0.
    import yaml
    p = tmp_path / "reg.yaml"
    p.write_text(yaml.safe_dump({"incidents": []}), encoding="utf-8")
    # safe_dump of {"incidents": []} is non-empty content, so it parses.
    env, _ = cir.run(p, SCHEMA)
    assert env["status"] == "PASS"
    assert env["measured"]["entry_count"] == 0


# --------------------------------------------------------------------------- #
# envelope + readiness-doc shape                                              #
# --------------------------------------------------------------------------- #

def test_envelope_has_t33_key_set():
    env, _ = cir.run(SEED_REGISTER, SCHEMA)
    assert set(env) == set(lc.ENVELOPE_KEYS)


def test_envelope_is_blocking_tier():
    env, _ = cir.run(SEED_REGISTER, SCHEMA)
    assert env["tier"] == "BLOCKING"


def test_count_is_evidence_only_in_readiness_doc():
    _, readiness = cir.run(SEED_REGISTER, SCHEMA)
    assert readiness["evidence_only"]["tier"] == "EVIDENCE-ONLY"
    assert "entry_count" in readiness["evidence_only"]


def test_readiness_doc_is_json_serialisable_with_status():
    _, readiness = cir.run(SEED_REGISTER, SCHEMA)
    encoded = json.dumps(readiness)
    assert json.loads(encoded)["status"] == "PASS"


def test_main_writes_readiness_file_and_exits_zero(tmp_path):
    out = tmp_path / "incident-readiness.json"
    with pytest.raises(SystemExit) as exc:
        cir.main([str(SEED_REGISTER), "--schema", str(SCHEMA), "--out", str(out)])
    assert exc.value.code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["status"] == "PASS"
    assert doc["measured"]["entry_count"] >= 1


def test_main_exits_one_on_failing_register(tmp_path):
    entry = _good_entry()
    del entry["clock"]["early_warning_24h"]
    reg = _write_yaml(tmp_path, {"incidents": [entry]})
    out = tmp_path / "incident-readiness.json"
    with pytest.raises(SystemExit) as exc:
        cir.main([str(reg), "--schema", str(SCHEMA), "--out", str(out)])
    assert exc.value.code == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["status"] == "FAIL"


# --------------------------------------------------------------------------- #
# Standalone fallback runner (no pytest required) — mirrors test_libcompliance #
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
        except BaseException as exc:  # noqa: BLE001 - report and continue
            if _Skipped is not None and isinstance(exc, _Skipped):
                skipped += 1
                return
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()

    for name, fn in fns:
        params = list(inspect.signature(fn).parameters)
        if "capsys" in params:
            skipped += 1
            continue
        if "tmp_path" in params:
            with tempfile.TemporaryDirectory() as d:
                _run_one(name, fn, {"tmp_path": Path(d)})
            continue
        _run_one(name, fn, {})

    print(f"\nstandalone: {passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)
