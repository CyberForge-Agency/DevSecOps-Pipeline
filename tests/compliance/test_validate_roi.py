"""Unit tests for the A.1 validate-roi validator (T-20, DORA Art.28(3)).

Proves the three acceptance criteria from the task block:
  1. validate-roi exits 0 on the seeded register and emits a schema-valid
     roi-validation.json with a measured LEI count.
  2. Removing a Critical vendor's exit_plan_ref makes it exit 1 with a specific
     completeness error.
  3. An invalid LEI format is reported in `detail` (and blocks).

Plus: schema violations block, NOT_LEI_ELIGIBLE providers are excluded from the
LEI-format set (not silently passed), stale registers fail on freshness, the
maintaining-entity PENDING LEI is EVIDENCE-ONLY (does not block), and an
unloadable register yields INDETERMINATE (never a silent PASS).

Runs under pytest (``python3 -m pytest tests/compliance/test_validate_roi.py -q``)
AND standalone (``python3 tests/compliance/test_validate_roi.py``) so the suite is
verifiable even where pytest is not installed.
"""

from __future__ import annotations

import copy
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

# Make the Pipeline root importable as ``scripts.validators.*``.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

import importlib.util  # noqa: E402

from scripts.validators import libcompliance as lc  # noqa: E402

# validate-roi.py has a hyphen, so import it by file path under a clean name.
_VR_PATH = PIPELINE_ROOT / "scripts" / "validators" / "validate-roi.py"
_spec = importlib.util.spec_from_file_location("validate_roi", _VR_PATH)
assert _spec and _spec.loader
vr = importlib.util.module_from_spec(_spec)
sys.modules["validate_roi"] = vr
_spec.loader.exec_module(vr)

REGISTER = PIPELINE_ROOT / "docs" / "governance" / "register-of-information.yaml"
SCHEMA = PIPELINE_ROOT / "schemas" / "roi.schema.json"


# --------------------------------------------------------------------------- #
# Fixtures / helpers                                                           #
# --------------------------------------------------------------------------- #

def _load_register() -> dict:
    import yaml
    return yaml.safe_load(REGISTER.read_text(encoding="utf-8"))


def _write(tmp_path: Path, data: dict) -> Path:
    import yaml
    p = tmp_path / "register.yaml"
    p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return p


def _envelope_for(register_path: Path) -> dict:
    return vr.build_envelope(register_path, SCHEMA)


# --------------------------------------------------------------------------- #
# Acceptance 1: seeded register passes + emits measured LEI count             #
# --------------------------------------------------------------------------- #

def test_seeded_register_passes():
    env = _envelope_for(REGISTER)
    assert env["status"] == "PASS"
    assert env["tier"] == "BLOCKING"


def test_seeded_register_exit_zero():
    assert lc.exit_code_for(*(lambda e: (e["status"], e["tier"]))(_envelope_for(REGISTER))) == 0


def test_seeded_register_envelope_has_t33_keys():
    env = _envelope_for(REGISTER)
    assert set(env) == set(lc.ENVELOPE_KEYS)


def test_measured_reports_lei_counts():
    env = _envelope_for(REGISTER)
    m = env["measured"]
    assert m["providers_total"] == 10
    # 2 placeholder LEIs are format-checked; 8 OSS tools are NOT_LEI_ELIGIBLE.
    assert m["lei_checked"] == 2
    assert m["lei_format_valid"] == 2
    assert m["lei_registration"]["not_lei_eligible"] == 8


def test_main_writes_schema_consistent_artifact(tmp_path):
    out = tmp_path / "roi-validation.json"
    rc = vr.main([str(REGISTER), str(SCHEMA), "--out", str(out)])
    assert rc == 0
    art = json.loads(out.read_text())
    assert art["status"] == "PASS"
    assert "lei_format_valid" in art["measured"]


# --------------------------------------------------------------------------- #
# Acceptance 2: removing a Critical vendor's exit_plan_ref -> FAIL (exit 1)    #
# --------------------------------------------------------------------------- #

def test_missing_exit_plan_for_critical_fails(tmp_path):
    data = _load_register()
    # TPP-001 (GitHub) is Critical; drop its exit_plan_ref.
    data["ict_third_party"][0]["exit_plan_ref"] = ""
    p = _write(tmp_path, data)
    env = _envelope_for(p)
    assert env["status"] == "FAIL"
    assert env["tier"] == "BLOCKING"
    assert "exit_plan_ref" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


def test_missing_substitutability_for_critical_fails(tmp_path):
    data = _load_register()
    data["ict_third_party"][1]["substitutability"] = "   "  # whitespace-only
    p = _write(tmp_path, data)
    env = _envelope_for(p)
    assert env["status"] == "FAIL"
    assert "substitutability" in env["detail"]


def test_missing_exit_plan_for_low_does_not_fail(tmp_path):
    data = _load_register()
    # Find a Low-criticality provider and blank its exit_plan_ref: must NOT block.
    low = next(t for t in data["ict_third_party"] if t["criticality"] == "Low")
    low["exit_plan_ref"] = ""
    p = _write(tmp_path, data)
    env = _envelope_for(p)
    assert env["status"] == "PASS"


# --------------------------------------------------------------------------- #
# Acceptance 3: invalid LEI format is reported in detail (and blocks)          #
# --------------------------------------------------------------------------- #

def test_invalid_lei_format_reported_and_blocks(tmp_path):
    data = _load_register()
    data["ict_third_party"][0]["lei"] = "NOT-A-VALID-LEI"
    p = _write(tmp_path, data)
    env = _envelope_for(p)
    assert env["status"] == "FAIL"
    assert "LEI format" in env["detail"]
    assert "NOT-A-VALID-LEI" in env["detail"]


def test_lei_too_short_blocks(tmp_path):
    data = _load_register()
    data["ict_third_party"][0]["lei"] = "549300FX7K9Q8MR3LE1"  # 19 chars
    p = _write(tmp_path, data)
    env = _envelope_for(p)
    assert env["status"] == "FAIL"


def test_lei_lowercase_blocks(tmp_path):
    data = _load_register()
    data["ict_third_party"][0]["lei"] = "549300fx7k9q8mr3le12"  # lowercase
    p = _write(tmp_path, data)
    assert _envelope_for(p)["status"] == "FAIL"


def test_check_lei_format_regex_directly():
    # Direct ISO 17442 assertions: 18 alnum + 2 digits.
    assert vr.LEI_RE.fullmatch("549300FX7K9Q8MR3LE12")
    assert not vr.LEI_RE.fullmatch("549300FX7K9Q8MR3LEXX")  # check digits not numeric
    assert not vr.LEI_RE.fullmatch("549300FX7K9Q8MR3LE1")   # 19 chars
    assert not vr.LEI_RE.fullmatch("")


# --------------------------------------------------------------------------- #
# LEI eligibility: NOT_LEI_ELIGIBLE providers are excluded, not passed         #
# --------------------------------------------------------------------------- #

def test_not_lei_eligible_excluded_from_format_set():
    data = _load_register()
    problems, checked, valid = vr.check_lei_format(data)
    assert problems == []
    assert checked == 2  # only the 2 placeholder-LEI providers
    assert valid == 2


def test_eligible_provider_with_null_lei_is_a_problem():
    data = _load_register()
    # Mark an OSS tool as ISSUED but leave lei null -> must be flagged, not skipped.
    data["ict_third_party"][2]["lei_status"] = "ISSUED"
    data["ict_third_party"][2]["lei"] = None
    problems, checked, valid = vr.check_lei_format(data)
    assert any("requires an LEI but none present" in p for p in problems)


# --------------------------------------------------------------------------- #
# Schema enforcement (BLOCKING)                                                #
# --------------------------------------------------------------------------- #

def test_schema_violation_blocks(tmp_path):
    data = _load_register()
    del data["ict_third_party"][0]["criticality"]  # required field
    p = _write(tmp_path, data)
    env = _envelope_for(p)
    assert env["status"] == "FAIL"
    assert "schema" in env["detail"]


def test_bad_criticality_enum_blocks(tmp_path):
    data = _load_register()
    data["ict_third_party"][0]["criticality"] = "Catastrophic"
    p = _write(tmp_path, data)
    assert _envelope_for(p)["status"] == "FAIL"


def test_empty_ict_third_party_blocks(tmp_path):
    data = _load_register()
    data["ict_third_party"] = []
    p = _write(tmp_path, data)
    # minItems:1 schema rule -> schema violation -> FAIL (not a silent PASS).
    assert _envelope_for(p)["status"] == "FAIL"


# --------------------------------------------------------------------------- #
# Freshness (BLOCKING)                                                         #
# --------------------------------------------------------------------------- #

def test_stale_register_fails_freshness(tmp_path):
    data = _load_register()
    data["maintaining_entity"]["last_updated"] = "2000-01-01"
    data["maintaining_entity"]["review_cadence_days"] = 365
    p = _write(tmp_path, data)
    env = _envelope_for(p)
    assert env["status"] == "FAIL"
    assert "freshness" in env["detail"]


# --------------------------------------------------------------------------- #
# EVIDENCE-ONLY boundary: maintaining-entity PENDING LEI does not block        #
# --------------------------------------------------------------------------- #

def test_maintaining_entity_pending_lei_does_not_block():
    env = _envelope_for(REGISTER)
    assert env["measured"]["maintaining_entity_lei_pending"] is True
    assert env["status"] == "PASS"  # PENDING entity LEI is EVIDENCE-ONLY, not BLOCKING


def test_registration_truth_is_evidence_only():
    # The validator records a registration tally but never blocks on it: zero
    # ISSUED LEIs (all placeholders) must still PASS.
    env = _envelope_for(REGISTER)
    assert env["measured"]["lei_registration"]["issued"] == 0
    assert env["status"] == "PASS"


# --------------------------------------------------------------------------- #
# INDETERMINATE: unloadable input is never a silent PASS                       #
# --------------------------------------------------------------------------- #

def test_missing_register_is_indeterminate(tmp_path):
    env = vr.build_envelope(tmp_path / "nope.yaml", SCHEMA)
    assert env["status"] == "INDETERMINATE"
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


def test_empty_register_is_indeterminate(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    env = vr.build_envelope(p, SCHEMA)
    assert env["status"] == "INDETERMINATE"


def test_non_mapping_register_is_indeterminate(tmp_path):
    p = tmp_path / "list.yaml"
    p.write_text("- just\n- a\n- list\n")
    env = vr.build_envelope(p, SCHEMA)
    assert env["status"] == "INDETERMINATE"


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
