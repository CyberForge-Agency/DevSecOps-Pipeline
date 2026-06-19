"""Unit tests for the T-115 threat_model validator (BLOCKING).

Proves the validator's real exit code + T-33 envelope on:
  * the seeded docs/security/threat-model.yaml (PASS, BLOCKING);
  * an incomplete entry (missing required field) -> FAIL;
  * a stale reviewed_date -> FAIL (the spec §4 single-stale-doc rejection);
  * a GAP row with no gap_ref -> FAIL (over-claim guard);
  * partial STRIDE coverage -> FAIL;
  * a missing / empty file -> INDETERMINATE (never a silent PASS).

Each fixture mutates a deep copy of the real model and re-serialises it so the
test exercises ``validate()`` end-to-end (not a stubbed shape). These FAIL if the
gate logic regresses (e.g. coverage floor lowered, freshness disabled, GAP guard
dropped).

Runs under pytest AND standalone (``python3 tests/compliance/test_threat_model.py``).
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback: minimal pytest surface used here
    class _PytestShim:
        class _Skipped(BaseException):
            pass

        @staticmethod
        def skip(reason=""):
            raise _PytestShim._Skipped(reason)

    pytest = _PytestShim()  # type: ignore[assignment]

PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402
from scripts.validators import threat_model as tm  # noqa: E402

MODEL = PIPELINE_ROOT / "docs" / "security" / "threat-model.yaml"


def _load() -> dict:
    import yaml
    return yaml.safe_load(MODEL.read_text(encoding="utf-8"))


def _write(tmp_path: Path, data: dict) -> Path:
    import yaml
    p = tmp_path / "threat-model.yaml"
    p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# PASS: the seeded model                                                       #
# --------------------------------------------------------------------------- #

def test_seeded_model_passes():
    env = tm.validate(MODEL)
    assert env["status"] == lc.Status.PASS
    assert env["tier"] == lc.Tier.BLOCKING
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


def test_seeded_model_envelope_has_t33_keys():
    env = tm.validate(MODEL)
    assert set(env) == set(lc.ENVELOPE_KEYS)
    assert env["measured"]["stride_coverage"] >= tm.MIN_STRIDE_CATEGORIES


# --------------------------------------------------------------------------- #
# FAIL: incomplete entry                                                       #
# --------------------------------------------------------------------------- #

def test_missing_required_field_fails(tmp_path):
    data = _load()
    data["threats"][0]["mitigation"] = ""  # blank a required field
    env = tm.validate(_write(tmp_path, data))
    assert env["status"] == lc.Status.FAIL
    assert env["tier"] == lc.Tier.BLOCKING
    assert "mitigation" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


def test_gap_status_without_gap_ref_fails(tmp_path):
    data = _load()
    t0 = data["threats"][0]
    t0["status"] = "GAP"
    t0.pop("gap_ref", None)  # GAP must carry a gap_ref, not just a control_ref
    env = tm.validate(_write(tmp_path, data))
    assert env["status"] == lc.Status.FAIL
    assert "gap_ref" in env["detail"]


def test_partial_stride_coverage_fails(tmp_path):
    data = _load()
    # Collapse every threat onto a single STRIDE letter -> coverage 1 < floor.
    for t in data["threats"]:
        t["stride"] = "S"
    env = tm.validate(_write(tmp_path, data))
    assert env["status"] == lc.Status.FAIL
    assert "STRIDE coverage" in env["detail"]


# --------------------------------------------------------------------------- #
# FAIL: stale model (the spec §4 rejection trigger)                            #
# --------------------------------------------------------------------------- #

def test_stale_reviewed_date_fails(tmp_path):
    data = _load()
    data["reviewed_date"] = "2000-01-01"
    data["review_window_days"] = 180
    env = tm.validate(_write(tmp_path, data))
    assert env["status"] == lc.Status.FAIL
    assert "stale" in env["detail"]


# --------------------------------------------------------------------------- #
# INDETERMINATE: nothing measurable                                            #
# --------------------------------------------------------------------------- #

def test_missing_file_is_indeterminate(tmp_path):
    env = tm.validate(tmp_path / "nope.yaml")
    assert env["status"] == lc.Status.INDETERMINATE
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


def test_empty_file_is_indeterminate(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    env = tm.validate(p)
    assert env["status"] == lc.Status.INDETERMINATE


def test_no_threats_is_indeterminate(tmp_path):
    data = _load()
    data["threats"] = []
    env = tm.validate(_write(tmp_path, data))
    assert env["status"] == lc.Status.INDETERMINATE


# --------------------------------------------------------------------------- #
# Standalone fallback runner (no pytest required)                              #
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import inspect
    import tempfile
    import traceback

    fns = [(n, o) for n, o in sorted(globals().items())
           if n.startswith("test_") and callable(o)]
    passed = failed = skipped = 0
    _Skipped = getattr(pytest, "_Skipped", None)
    for name, fn in fns:
        params = list(inspect.signature(fn).parameters)
        try:
            if "tmp_path" in params:
                with tempfile.TemporaryDirectory() as d:
                    fn(Path(d))
            else:
                fn()
            passed += 1
        except BaseException as exc:  # noqa: BLE001
            if _Skipped is not None and isinstance(exc, _Skipped):
                skipped += 1
                continue
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\nstandalone: {passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)
