"""Unit tests for the E.2 ``check_asset_map`` validator (DORA Art.8).

Proves the HONEST predicate: the asset map is REAL architectural data, so a
*complete* map PASSes; but every completeness gap is a BLOCKING FAIL, never a
silent pass:

  * shipped seed map (asset-map.yaml)            -> PASS (real, fully mapped);
  * orphan function (no supporting asset)        -> FAIL;
  * asset missing owner                          -> FAIL;
  * high-criticality function missing RTO        -> FAIL;
  * dangling supporting-asset reference          -> FAIL;
  * schema violation (bad criticality enum)      -> FAIL;
  * missing/empty/malformed map                  -> INDETERMINATE (not a pass);
  * main() writes asset-map.json + exit-code mapping (PASS 0 / FAIL 1 / INDET 2).

Runs under pytest AND standalone (no pytest required).
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

PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

_VALIDATOR_PATH = PIPELINE_ROOT / "scripts" / "validators" / "check_asset_map.py"
_spec = importlib.util.spec_from_file_location("check_asset_map", _VALIDATOR_PATH)
assert _spec and _spec.loader, f"cannot load validator at {_VALIDATOR_PATH}"
cam = importlib.util.module_from_spec(_spec)
sys.modules["check_asset_map"] = cam
_spec.loader.exec_module(cam)  # type: ignore[union-attr]

SCHEMA = PIPELINE_ROOT / "schemas" / "asset-map.schema.json"
SEED_MAP = PIPELINE_ROOT / "docs" / "governance" / "asset-map.yaml"

try:
    import yaml  # noqa: F401
    import jsonschema  # noqa: F401
    _HAVE_DEPS = True
except ImportError:  # pragma: no cover - environment-dependent
    _HAVE_DEPS = False


def _need_deps():
    if not _HAVE_DEPS:
        pytest.skip("PyYAML/jsonschema not installed")


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "asset-map.yaml"
    p.write_text(body, encoding="utf-8")
    return p


# A minimal, complete, schema-valid map used as the base for negative mutations.
_GOOD_MAP = """\
schema_version: "1.0"
maintaining_entity:
  name: "CyberForge"
  last_updated: "2026-06-18"
  review_cadence_days: 365
critical_functions:
  - name: "Pipeline"
    criticality: high
    supporting_assets: ["TA-001"]
    data_stores: ["IA-001"]
    third_parties: ["GitHub"]
    rto: "4 hours"
    rpo: "0"
assets:
  - id: "TA-001"
    name: "GitHub Organization"
    type: technology
    owner: "CTO"
    criticality: high
  - id: "IA-001"
    name: "Source Code"
    type: information
    owner: "CTO"
    criticality: high
"""


# --------------------------------------------------------------------------- #
# Honest PASS: real seed + a complete synthetic map                            #
# --------------------------------------------------------------------------- #

def test_good_map_passes(tmp_path):
    _need_deps()
    env = cam.build_envelope(_write(tmp_path, _GOOD_MAP), SCHEMA)
    assert env["status"] == "PASS"
    assert env["tier"] == "BLOCKING"
    assert env["measured"]["completeness_violations"] == 0
    assert env["measured"]["schema_violations"] == 0


def test_shipped_seed_map_passes():
    """The real seed map is genuine architectural data and MUST honestly PASS."""
    _need_deps()
    if not SEED_MAP.is_file():
        pytest.skip("seed asset-map.yaml not present")
    env = cam.build_envelope(SEED_MAP, SCHEMA)
    assert env["status"] == "PASS", env["detail"]
    assert env["measured"]["critical_functions_total"] >= 1
    assert env["measured"]["assets_missing_owner"] == 0


# --------------------------------------------------------------------------- #
# Completeness FAILs (no masking)                                              #
# --------------------------------------------------------------------------- #

def test_orphan_function_no_supporting_asset_fails(tmp_path):
    _need_deps()
    body = _GOOD_MAP.replace('    supporting_assets: ["TA-001"]\n', "    supporting_assets: []\n")
    env = cam.build_envelope(_write(tmp_path, body), SCHEMA)
    assert env["status"] == "FAIL"
    assert any("0 supporting" in p for p in [env["detail"]])


def test_asset_missing_owner_fails(tmp_path):
    _need_deps()
    # Null out the owner of TA-001 (schema allows null owner; validator FAILs it).
    body = _GOOD_MAP.replace('    owner: "CTO"\n    criticality: high\n  - id: "IA-001"',
                             '    owner: null\n    criticality: high\n  - id: "IA-001"')
    env = cam.build_envelope(_write(tmp_path, body), SCHEMA)
    assert env["status"] == "FAIL"
    assert "missing/empty 'owner'" in env["detail"]
    assert env["measured"]["assets_missing_owner"] == 1


def test_high_function_missing_rto_fails(tmp_path):
    _need_deps()
    body = _GOOD_MAP.replace('    rto: "4 hours"\n', "    rto: null\n")
    env = cam.build_envelope(_write(tmp_path, body), SCHEMA)
    assert env["status"] == "FAIL"
    assert "missing/empty 'rto'" in env["detail"]


def test_high_function_missing_rpo_fails(tmp_path):
    _need_deps()
    body = _GOOD_MAP.replace('    rpo: "0"\n', "    rpo: null\n")
    env = cam.build_envelope(_write(tmp_path, body), SCHEMA)
    assert env["status"] == "FAIL"
    assert "missing/empty 'rpo'" in env["detail"]


def test_dangling_supporting_asset_reference_fails(tmp_path):
    _need_deps()
    body = _GOOD_MAP.replace('    supporting_assets: ["TA-001"]\n',
                             '    supporting_assets: ["TA-999"]\n')
    env = cam.build_envelope(_write(tmp_path, body), SCHEMA)
    assert env["status"] == "FAIL"
    assert "does not resolve" in env["detail"]


def test_med_function_without_rto_passes(tmp_path):
    """RTO/RPO are only required for HIGH-criticality functions -- honest scoping."""
    _need_deps()
    body = _GOOD_MAP.replace("    criticality: high\n    supporting_assets",
                             "    criticality: med\n    supporting_assets")
    body = body.replace('    rto: "4 hours"\n', "    rto: null\n").replace('    rpo: "0"\n', "    rpo: null\n")
    env = cam.build_envelope(_write(tmp_path, body), SCHEMA)
    assert env["status"] == "PASS", env["detail"]


# --------------------------------------------------------------------------- #
# Schema FAIL                                                                  #
# --------------------------------------------------------------------------- #

def test_bad_criticality_enum_fails_schema(tmp_path):
    _need_deps()
    body = _GOOD_MAP.replace("    criticality: high\n    supporting_assets",
                             "    criticality: SEVERE\n    supporting_assets")
    env = cam.build_envelope(_write(tmp_path, body), SCHEMA)
    assert env["status"] == "FAIL"
    assert env["measured"]["schema_violations"] >= 1


# --------------------------------------------------------------------------- #
# INDETERMINATE (could not measure) -- not a silent pass                       #
# --------------------------------------------------------------------------- #

def test_missing_file_is_indeterminate(tmp_path):
    _need_deps()
    env = cam.build_envelope(tmp_path / "nope.yaml", SCHEMA)
    assert env["status"] == "INDETERMINATE"
    assert env["tier"] == "BLOCKING"


def test_empty_file_is_indeterminate(tmp_path):
    _need_deps()
    env = cam.build_envelope(_write(tmp_path, "\n"), SCHEMA)
    assert env["status"] == "INDETERMINATE"


def test_malformed_yaml_is_indeterminate(tmp_path):
    _need_deps()
    env = cam.build_envelope(_write(tmp_path, "assets: [ : : not valid : ]\n  - broken\n"), SCHEMA)
    assert env["status"] == "INDETERMINATE"


# --------------------------------------------------------------------------- #
# Exit-code mapping + main() writes asset-map.json                             #
# --------------------------------------------------------------------------- #

def test_exit_codes_match_status(tmp_path):
    _need_deps()
    from scripts.validators import libcompliance as lc

    pass_env = cam.build_envelope(_write(tmp_path, _GOOD_MAP), SCHEMA)
    assert lc.exit_code_for(pass_env["status"], pass_env["tier"]) == 0

    fail_body = _GOOD_MAP.replace('    rto: "4 hours"\n', "    rto: null\n")
    fail_env = cam.build_envelope(_write(tmp_path, fail_body), SCHEMA)
    assert lc.exit_code_for(fail_env["status"], fail_env["tier"]) == 1

    indet_env = cam.build_envelope(tmp_path / "nope.yaml", SCHEMA)
    assert lc.exit_code_for(indet_env["status"], indet_env["tier"]) == 2


def test_main_writes_asset_map_json_on_pass(tmp_path):
    _need_deps()
    src = _write(tmp_path, _GOOD_MAP)
    out = tmp_path / "asset-map.json"
    with pytest.raises(SystemExit) as exc:
        cam.main([str(src), "--schema", str(SCHEMA), "--out", str(out)])
    assert exc.value.code == 0
    payload = json.loads(out.read_text())
    assert payload["status"] == "PASS"
    assert payload["validator"] == "check_asset_map"
    assert payload["measured"]["assets_total"] == 2


def test_main_exits_one_on_completeness_fail(tmp_path):
    _need_deps()
    body = _GOOD_MAP.replace('    rpo: "0"\n', "    rpo: null\n")
    src = _write(tmp_path, body)
    out = tmp_path / "asset-map.json"
    with pytest.raises(SystemExit) as exc:
        cam.main([str(src), "--schema", str(SCHEMA), "--out", str(out)])
    assert exc.value.code == 1
    payload = json.loads(out.read_text())
    assert payload["status"] == "FAIL"


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
