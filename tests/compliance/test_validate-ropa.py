"""Unit tests for validate-ropa.py (A.3 RoPA/DPIA validator, task T-22).

Proves the three task acceptance criteria and the honest tiering:

  1. exits 0 on the seeded RoPA and emits a schema-valid PASS envelope (BLOCKING);
  2. an activity missing `retention` or `lawful_basis` makes it FAIL (exit 1);
  3. a high_risk activity with no dpia_ref and no not-required-reason FAILs (exit 1);

plus: missing file -> INDETERMINATE (exit 2, not a silent PASS), empty doc ->
INDETERMINATE, the schema itself is valid Draft-07, and the emitted envelope carries
the canonical T-33 key set.

Runs under pytest (`python3 -m pytest tests/compliance/test_validate-ropa.py -q`)
AND standalone (`python3 tests/compliance/test_validate-ropa.py`) so it is verifiable
even where pytest is not installed (mirrors test_libcompliance.py).
"""

from __future__ import annotations

import copy
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

from scripts.validators import libcompliance as lc  # noqa: E402

ROPA_YAML = PIPELINE_ROOT / "docs" / "governance" / "ropa.yaml"
ROPA_SCHEMA = PIPELINE_ROOT / "schemas" / "ropa.schema.json"


def _load_validator():
    """Import validate-ropa.py by path (hyphenated filename isn't a normal module)."""
    spec = importlib.util.spec_from_file_location(
        "validate_ropa", PIPELINE_ROOT / "scripts" / "validators" / "validate-ropa.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


VR = _load_validator()


def _have_deps() -> bool:
    return (
        importlib.util.find_spec("yaml") is not None
        and importlib.util.find_spec("jsonschema") is not None
    )


def _seed() -> dict:
    """Load the seeded RoPA into a mutable dict for negative-case mutation."""
    import yaml

    return yaml.safe_load(ROPA_YAML.read_text(encoding="utf-8"))


def _validate_dict(data: dict, tmp_path: Path) -> dict:
    """Write `data` to a temp YAML and validate it against the real schema."""
    import yaml

    p = tmp_path / "ropa.yaml"
    p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return VR.validate(p, ROPA_SCHEMA)


# --------------------------------------------------------------------------- #
# Schema sanity                                                               #
# --------------------------------------------------------------------------- #

def test_schema_is_valid_jsonschema():
    if importlib.util.find_spec("jsonschema") is None:
        pytest.skip("jsonschema not installed")
    import jsonschema

    schema = json.loads(ROPA_SCHEMA.read_text(encoding="utf-8"))
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)  # raises if the schema itself is malformed


# --------------------------------------------------------------------------- #
# AC1: seeded RoPA passes (BLOCKING, exit 0)                                  #
# --------------------------------------------------------------------------- #

def test_seeded_ropa_passes():
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    env = VR.validate(ROPA_YAML, ROPA_SCHEMA)
    assert env["status"] == lc.Status.PASS, env["detail"]
    assert env["tier"] == lc.Tier.BLOCKING
    assert set(env) == set(lc.ENVELOPE_KEYS)  # canonical T-33 envelope shape
    assert env["measured"]["violations"] == 0
    assert env["measured"]["activities"] >= 1
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


def test_main_writes_artifact_and_exit_zero(tmp_path):
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    out = tmp_path / "ropa-completeness.json"
    code = VR.main([str(ROPA_YAML), str(ROPA_SCHEMA), "--out", str(out)])
    assert code == 0
    artifact = json.loads(out.read_text(encoding="utf-8"))
    assert artifact["status"] == "PASS"
    assert set(artifact) == set(lc.ENVELOPE_KEYS)


# --------------------------------------------------------------------------- #
# AC2: missing retention / lawful_basis -> FAIL (exit 1)                      #
# --------------------------------------------------------------------------- #

def test_missing_retention_fails(tmp_path):
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    data = _seed()
    del data["activities"][0]["retention"]
    env = _validate_dict(data, tmp_path)
    assert env["status"] == lc.Status.FAIL, env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1
    assert "retention" in env["detail"]


def test_missing_lawful_basis_fails(tmp_path):
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    data = _seed()
    del data["activities"][0]["lawful_basis"]
    env = _validate_dict(data, tmp_path)
    assert env["status"] == lc.Status.FAIL, env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1
    assert "lawful_basis" in env["detail"]


def test_empty_retention_string_fails(tmp_path):
    """A present-but-empty retention is as bad as a missing one (minLength)."""
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    data = _seed()
    data["activities"][0]["retention"] = ""
    env = _validate_dict(data, tmp_path)
    assert env["status"] == lc.Status.FAIL, env["detail"]


# --------------------------------------------------------------------------- #
# AC3: high_risk with no DPIA evidence -> FAIL (exit 1)                       #
# --------------------------------------------------------------------------- #

def test_high_risk_without_dpia_ref_fails(tmp_path):
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    data = _seed()
    act = data["activities"][0]
    act["high_risk"] = True
    act.pop("dpia_ref", None)
    act.pop("dpia_not_required_reason", None)  # neither path satisfied
    env = _validate_dict(data, tmp_path)
    assert env["status"] == lc.Status.FAIL, env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1
    assert "dpia_ref" in env["detail"]


def test_high_risk_with_dpia_ref_passes(tmp_path):
    """The positive branch of AC3: a high_risk activity WITH a dpia_ref is fine."""
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    data = _seed()
    act = data["activities"][0]
    act["high_risk"] = True
    act["dpia_ref"] = "docs/governance/dpia/PA-001-dpia.md"
    act.pop("dpia_not_required_reason", None)
    env = _validate_dict(data, tmp_path)
    assert env["status"] == lc.Status.PASS, env["detail"]


def test_low_risk_without_reason_fails(tmp_path):
    """high_risk=false MUST carry a documented not-required reason (no silence)."""
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    data = _seed()
    act = data["activities"][0]
    act["high_risk"] = False
    act.pop("dpia_not_required_reason", None)
    env = _validate_dict(data, tmp_path)
    assert env["status"] == lc.Status.FAIL, env["detail"]
    assert "dpia_not_required_reason" in env["detail"]


def test_missing_dpia_determination_fails(tmp_path):
    """The org-level DPIA determination must be present, not silent."""
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    data = _seed()
    del data["dpia_determination"]
    env = _validate_dict(data, tmp_path)
    assert env["status"] == lc.Status.FAIL, env["detail"]


# --------------------------------------------------------------------------- #
# Honesty: missing / empty inputs -> INDETERMINATE, never a silent PASS       #
# --------------------------------------------------------------------------- #

def test_missing_file_is_indeterminate(tmp_path):
    env = VR.validate(tmp_path / "nope.yaml", ROPA_SCHEMA)
    assert env["status"] == lc.Status.INDETERMINATE
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


def test_empty_file_is_indeterminate(tmp_path):
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    p = tmp_path / "empty.yaml"
    p.write_text("", encoding="utf-8")
    env = VR.validate(p, ROPA_SCHEMA)
    assert env["status"] == lc.Status.INDETERMINATE


def test_empty_activities_fails(tmp_path):
    """A RoPA with zero activities is incomplete (schema minItems:1) -> FAIL."""
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    data = _seed()
    data["activities"] = []
    env = _validate_dict(data, tmp_path)
    assert env["status"] == lc.Status.FAIL, env["detail"]


def test_missing_controller_contact_fails(tmp_path):
    """Art.30(1)(a): controller contact is mandatory."""
    if not _have_deps():
        pytest.skip("pyyaml/jsonschema not installed")
    data = _seed()
    del data["controller"]["contact"]
    env = _validate_dict(data, tmp_path)
    assert env["status"] == lc.Status.FAIL, env["detail"]


# --------------------------------------------------------------------------- #
# Standalone runner (no pytest required)                                      #
# --------------------------------------------------------------------------- #

def _run_standalone() -> int:
    import inspect
    import tempfile
    import traceback

    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    passed = skipped = failed = 0
    for name, fn in tests:
        params = inspect.signature(fn).parameters
        try:
            if "tmp_path" in params:
                with tempfile.TemporaryDirectory() as d:
                    fn(Path(d))
            else:
                fn()
            passed += 1
        except BaseException as exc:  # noqa: BLE001
            # A skip (real pytest.skip.Exception or the shim's _Skipped) is not a failure.
            if exc.__class__.__name__ in ("_Skipped", "Skipped"):
                skipped += 1
                print(f"SKIP {name}: {exc}")
                continue
            failed += 1
            print(f"FAIL {name}: {exc}")
            traceback.print_exc()
    print(f"\n{passed} passed, {skipped} skipped, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
