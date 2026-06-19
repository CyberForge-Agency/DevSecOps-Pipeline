"""Unit tests for the C.9 ``check_tlpt`` validator (DORA Art. 26-27 / RTS 2025/1190).

Proves the HONEST applicability + freshness predicate:

  * ``in_scope == false`` (the shipped seed)            -> EVIDENCE-ONLY, documented
        out-of-scope determination (NOT a fabricated compliance pass).
  * ``in_scope == true`` + conducted, fresh, external,
        authority sign-off, closure status               -> PASS (BLOCKING).
  * ``in_scope == true`` + not conducted                 -> FAIL.
  * ``in_scope == true`` + stale (> 3 years)             -> FAIL.
  * ``in_scope == true`` + missing authority sign-off    -> FAIL.
  * missing / malformed record                           -> INDETERMINATE.
  * exit-code mapping (PASS/EVIDENCE 0, FAIL 1, INDETERMINATE 2).

Runs under pytest AND standalone (``python3 tests/compliance/test_check_tlpt.py``)
so the suite is verifiable even where pytest is not installed.
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

_VALIDATOR_PATH = PIPELINE_ROOT / "scripts" / "validators" / "check_tlpt.py"
_spec = importlib.util.spec_from_file_location("check_tlpt", _VALIDATOR_PATH)
assert _spec and _spec.loader, f"cannot load validator at {_VALIDATOR_PATH}"
ct = importlib.util.module_from_spec(_spec)
sys.modules["check_tlpt"] = ct
_spec.loader.exec_module(ct)  # type: ignore[union-attr]

try:
    import yaml  # noqa: F401
    import jsonschema  # noqa: F401
    _HAVE_DEPS = True
except ImportError:  # pragma: no cover - environment-dependent
    _HAVE_DEPS = False

REF = date(2026, 6, 18)  # deterministic "today"
SCHEMA = PIPELINE_ROOT / "schemas" / "tlpt-record.schema.json"
SEED = PIPELINE_ROOT / "docs" / "governance" / "tlpt-record.yaml"


def _need_deps():
    if not _HAVE_DEPS:
        pytest.skip("PyYAML / jsonschema not installed")


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "tlpt-record.yaml"
    p.write_text(body, encoding="utf-8")
    return p


_HEADER = 'schema_version: "1.0"\n'
_ENTITY = (
    "entity:\n"
    '  name: "CyberForge"\n'
    '  classification: "significant financial entity"\n'
)


def _in_scope_record(tlpt_yaml: str) -> str:
    return (
        _HEADER
        + _ENTITY
        + "in_scope: true\n"
        + 'scope_rationale: "Identified by competent authority as significant for TLPT."\n'
        + 'determination_date: "2026-01-10"\n'
        + tlpt_yaml
    )


_GOOD_TLPT = """\
tlpt:
  conducted: true
  test_date: "2025-09-01"
  external_testers: true
  testers: "Acme Red Team Ltd"
  authority_signoff: true
  authority: "KNF"
  closure_status: "remediated"
  report_ref: "tlpt/2025-09-tiber-report.pdf"
"""


# --------------------------------------------------------------------------- #
# Out of scope (shipped seed) -> EVIDENCE-ONLY                                 #
# --------------------------------------------------------------------------- #

def test_out_of_scope_is_evidence_only(tmp_path):
    _need_deps()
    body = (
        _HEADER
        + _ENTITY
        + "in_scope: false\n"
        + 'scope_rationale: "Service provider, not a DORA-identified significant entity."\n'
        + "tlpt: null\n"
    )
    env = ct.build_envelope(_write(tmp_path, body), SCHEMA, today=REF)
    assert env["status"] == "PASS"
    assert env["tier"] == "EVIDENCE-ONLY"
    assert env["measured"]["in_scope"] is False
    assert "TLPT not mandatory" in env["detail"]


def test_shipped_seed_is_evidence_only():
    """The real seed file is in_scope:false -> EVIDENCE-ONLY (honest, not a fake pass)."""
    _need_deps()
    if not SEED.is_file():
        pytest.skip("seed tlpt-record.yaml not present")
    env = ct.build_envelope(SEED, SCHEMA, today=REF)
    assert env["status"] == "PASS"
    assert env["tier"] == "EVIDENCE-ONLY"
    assert env["measured"]["in_scope"] is False
    assert "documented determination" in env["detail"]


# --------------------------------------------------------------------------- #
# In scope + qualifying TLPT -> PASS (BLOCKING)                                #
# --------------------------------------------------------------------------- #

def test_in_scope_conducted_fresh_passes(tmp_path):
    _need_deps()
    env = ct.build_envelope(_write(tmp_path, _in_scope_record(_GOOD_TLPT)), SCHEMA, today=REF)
    assert env["status"] == "PASS"
    assert env["tier"] == "BLOCKING"
    assert env["measured"]["last_test_date"] == "2025-09-01"
    assert env["measured"]["authority_signoff"] is True
    assert env["measured"]["external_testers"] is True


# --------------------------------------------------------------------------- #
# In scope negative cases -> FAIL (no masking)                                #
# --------------------------------------------------------------------------- #

def test_in_scope_not_conducted_fails(tmp_path):
    _need_deps()
    env = ct.build_envelope(_write(tmp_path, _in_scope_record("tlpt: null\n")), SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert env["tier"] == "BLOCKING"
    assert any("no TLPT record present" in r for r in env["measured"]["rejections"])


def test_in_scope_stale_fails(tmp_path):
    _need_deps()
    # 2022-01-01 is > 1095 days before 2026-06-18.
    stale = _GOOD_TLPT.replace('"2025-09-01"', '"2022-01-01"')
    env = ct.build_envelope(_write(tmp_path, _in_scope_record(stale)), SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert any("stale" in r for r in env["measured"]["rejections"])


def test_in_scope_missing_authority_signoff_fails(tmp_path):
    _need_deps()
    no_signoff = _GOOD_TLPT.replace("authority_signoff: true", "authority_signoff: false")
    env = ct.build_envelope(_write(tmp_path, _in_scope_record(no_signoff)), SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert any("authority_signoff" in r for r in env["measured"]["rejections"])


def test_in_scope_internal_testers_fails(tmp_path):
    _need_deps()
    internal = _GOOD_TLPT.replace("external_testers: true", "external_testers: false")
    env = ct.build_envelope(_write(tmp_path, _in_scope_record(internal)), SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert any("external_testers" in r for r in env["measured"]["rejections"])


def test_in_scope_missing_closure_fails(tmp_path):
    _need_deps()
    no_closure = _GOOD_TLPT.replace('closure_status: "remediated"', "closure_status: null")
    env = ct.build_envelope(_write(tmp_path, _in_scope_record(no_closure)), SCHEMA, today=REF)
    assert env["status"] == "FAIL"
    assert any("closure_status" in r for r in env["measured"]["rejections"])


# --------------------------------------------------------------------------- #
# Indeterminate (could not measure) -- not a silent pass                       #
# --------------------------------------------------------------------------- #

def test_missing_file_is_indeterminate(tmp_path):
    _need_deps()
    env = ct.build_envelope(tmp_path / "nope.yaml", SCHEMA, today=REF)
    assert env["status"] == "INDETERMINATE"
    assert env["tier"] == "BLOCKING"


def test_malformed_yaml_is_indeterminate(tmp_path):
    _need_deps()
    env = ct.build_envelope(_write(tmp_path, "in_scope: [ : : bad\n  - x\n"), SCHEMA, today=REF)
    assert env["status"] == "INDETERMINATE"


def test_schema_violation_is_indeterminate(tmp_path):
    _need_deps()
    # Missing required scope_rationale.
    body = _HEADER + _ENTITY + "in_scope: false\n"
    env = ct.build_envelope(_write(tmp_path, body), SCHEMA, today=REF)
    assert env["status"] == "INDETERMINATE"
    assert "schema" in env["detail"]


# --------------------------------------------------------------------------- #
# Exit-code mapping                                                           #
# --------------------------------------------------------------------------- #

def test_exit_codes_match_status(tmp_path):
    _need_deps()
    from scripts.validators import libcompliance as lc

    ev_env = ct.build_envelope(SEED, SCHEMA, today=REF) if SEED.is_file() else None
    if ev_env:
        assert lc.exit_code_for(ev_env["status"], ev_env["tier"]) == 0

    fail_env = ct.build_envelope(_write(tmp_path, _in_scope_record("tlpt: null\n")), SCHEMA, today=REF)
    assert lc.exit_code_for(fail_env["status"], fail_env["tier"]) == 1

    pass_env = ct.build_envelope(_write(tmp_path, _in_scope_record(_GOOD_TLPT)), SCHEMA, today=REF)
    assert lc.exit_code_for(pass_env["status"], pass_env["tier"]) == 0

    indet_env = ct.build_envelope(tmp_path / "nope.yaml", SCHEMA, today=REF)
    assert lc.exit_code_for(indet_env["status"], indet_env["tier"]) == 2


# --------------------------------------------------------------------------- #
# main() writes tlpt-record.json                                              #
# --------------------------------------------------------------------------- #

def test_main_writes_json_evidence_only_on_seed(tmp_path):
    _need_deps()
    if not SEED.is_file():
        pytest.skip("seed tlpt-record.yaml not present")
    out = tmp_path / "tlpt-record.json"
    with pytest.raises(SystemExit) as exc:
        ct.main([str(SEED), str(SCHEMA), "--out", str(out)])
    assert exc.value.code == 0
    payload = json.loads(out.read_text())
    assert payload["status"] == "PASS"
    assert payload["tier"] == "EVIDENCE-ONLY"
    assert payload["validator"] == "check_tlpt"
    assert payload["measured"]["in_scope"] is False


def test_main_exits_one_when_in_scope_not_conducted(tmp_path):
    _need_deps()
    rec = _write(tmp_path, _in_scope_record("tlpt: null\n"))
    out = tmp_path / "tlpt-record.json"
    with pytest.raises(SystemExit) as exc:
        ct.main([str(rec), str(SCHEMA), "--out", str(out)])
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
