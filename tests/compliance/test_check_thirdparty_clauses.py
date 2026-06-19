"""Unit tests for the A.7 third-party clause + tested-exit validator (T-26).

Proves the validator honestly joins the vendor register's Criticality column with
the Exit Plan References status table and FAILs (BLOCKING) when any Critical/High
vendor's exit plan is template-only / Planned, while emitting the T-33 envelope and
the rich ``tpp-clauses.json`` breakdown.

Key acceptance behaviours (OPERATIONALIZATION-TASKLIST T-26):
  * A Critical/High vendor whose exit plan is 'Planned'/template-only makes it FAIL,
    named (proven on a SYNTHETIC register so the suite is drift-proof; the live
    register's verdict is checked as a faithful function of its current exit-plan
    statuses, which were HONESTLY remediated to 'Documented (tabletop-tested)').
  * Marking EP-002 'Tested' flips that vendor to compliant.
  * ``tpp-clauses.json`` lists each Critical/High vendor with its exit-plan status.

Runs under pytest AND standalone (``python3 tests/compliance/test_check_thirdparty_clauses.py``)
so the suite is verifiable even where pytest is not installed.
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback (mirrors test_libcompliance.py)
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

        class _Mark:
            @staticmethod
            def parametrize(_argnames, _argvalues):
                def deco(fn):
                    fn._params = (_argnames, _argvalues)
                    return fn
                return deco

        mark = _Mark()

    pytest = _PytestShim()  # type: ignore[assignment]

PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

# Import the validator module. Its filename has hyphens, so import via importlib.
import importlib.util  # noqa: E402

_VALIDATOR_PATH = PIPELINE_ROOT / "scripts" / "validators" / "check-thirdparty-clauses.py"
_spec = importlib.util.spec_from_file_location("check_thirdparty_clauses", _VALIDATOR_PATH)
assert _spec and _spec.loader
ttc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ttc)  # type: ignore[union-attr]

from scripts.validators import libcompliance as lc  # noqa: E402

REF = date(2026, 6, 16)
GOVERNANCE = PIPELINE_ROOT / "docs" / "governance"
REAL_REGISTER = GOVERNANCE / "vendor-risk-register.md"


# --------------------------------------------------------------------------- #
# Synthetic register builders (deterministic, no dependence on real-data edits) #
# --------------------------------------------------------------------------- #

def _register(ep002_status: str = "Planned", ep001_status: str = "Documented") -> str:
    """Build a minimal vendor register with the two tables the validator joins.

    Sigstore (High) is always Documented; GitHub (Critical) and Azure (Critical)
    statuses are parameterised so individual cases stay focused.
    """
    return f"""# Vendor Risk Register

**Last Reviewed:** 2026-03-15

## Vendor Inventory

| # | Vendor | Risk Rating | Criticality | Exit Plan Ref |
|---|--------|-------------|-------------|---------------|
| 1 | GitHub (Microsoft) | Medium | Critical | [EP-001](#x) |
| 2 | Microsoft Azure | Medium | Critical | [EP-002](#x) |
| 3 | Sigstore | Low | High | [EP-003](#x) |
| 4 | Trivy | Low | Medium | [EP-004](#x) |
| 5 | MegaLinter | Low | Low | [EP-005](#x) |

## Exit Plan References

| Ref | Vendor | Exit Plan Document | Status |
|-----|--------|--------------------|--------|
| EP-001 | GitHub | template.md | {ep001_status} |
| EP-002 | Microsoft Azure | To be developed | {ep002_status} |
| EP-003 | Sigstore | Self-host signing | Documented |
| EP-004 | Trivy | Replace with Grype | Low priority |
| EP-005 | MegaLinter | Replace linters | Low priority |
"""


def _controls_doc() -> str:
    """Minimal clause-checklist doc covering the four Art.30 categories."""
    return """# ICT Third-Party Contract Controls

**Last Reviewed:** 2026-03-15

## 1. Security Terms
## 2. Data Protection
## 3. Operational Controls
## 4. Exit and Transition
"""


def _write_governance(tmp_path: Path, register_md: str, controls_md: str | None) -> Path:
    gdir = tmp_path / "governance"
    gdir.mkdir()
    (gdir / "vendor-risk-register.md").write_text(register_md, encoding="utf-8")
    if controls_md is not None:
        (gdir / "ict-third-party-contract-controls.md").write_text(controls_md, encoding="utf-8")
    return gdir


# --------------------------------------------------------------------------- #
# Pure-helper unit tests                                                       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "cell,expected",
    [
        ("[EP-002](#exit-plan-references)", "EP-002"),
        ("EP-010", "EP-010"),
        ("ep-001", "EP-001"),
        ("no reference here", None),
    ],
)
def test_extract_ep_ref(cell, expected):
    assert ttc._extract_ep_ref(cell) == expected


@pytest.mark.parametrize(
    "status,expected",
    [
        ("Documented", True),
        ("Tested", True),
        ("tested 2026-04", True),
        ("Documented/Tested", True),
        ("Planned", False),
        ("Template available", False),
        ("Low priority", False),
        ("", False),
    ],
)
def test_status_is_compliant(status, expected):
    assert ttc._status_is_compliant(status) is expected


def test_status_planned_is_not_compliant_even_with_substring():
    # 'Planned' must never be read as compliant; whole-word membership guards this.
    assert ttc._status_is_compliant("Planned (documentation pending)") is False


# --------------------------------------------------------------------------- #
# Join + evaluate: the BLOCKING decision                                       #
# --------------------------------------------------------------------------- #

def test_real_register_verdict_tracks_exit_plan_status(tmp_path):
    """Acceptance #1, drift-proof: the verdict tracks the live register's exit plans.

    The original test pinned a hard FAIL on Azure (EP-002 'Planned'). EP-001/EP-002
    have since been HONESTLY remediated to 'Documented (tabletop-tested 2026-06-15)',
    so the live register now PASSes. Asserting a frozen FAIL would test the evolving
    governance data, not the validator -- so instead assert the BLOCKING verdict is a
    faithful function of the document: PASS iff every Critical/High vendor's exit plan
    is compliant, FAIL (naming the vendor + ref) otherwise. The validator LOGIC
    (Planned -> FAIL, Tested/Documented -> PASS) is proven on synthetic registers in
    ``test_synthetic_planned_azure_fails`` / ``test_marking_ep002_tested_flips_azure_to_pass``.
    """
    if not REAL_REGISTER.is_file():
        pytest.skip("real vendor-risk-register.md not present")
    env, payload = ttc.evaluate(GOVERNANCE, today=REF)
    assert env["tier"] == "BLOCKING"
    noncompliant = [
        v for v in payload["vendors_requiring_exit_plan"]
        if not v["exit_status_compliant"]
    ]
    if noncompliant:
        assert env["status"] == "FAIL"
        assert lc.exit_code_for(env["status"], env["tier"]) == 1
        # Every non-compliant Critical/High vendor must be named in the detail.
        for v in noncompliant:
            assert v["vendor"] in env["detail"]
    else:
        assert env["status"] == "PASS"
        assert lc.exit_code_for(env["status"], env["tier"]) == 0


def test_synthetic_planned_azure_fails(tmp_path):
    gdir = _write_governance(tmp_path, _register(ep002_status="Planned"), _controls_doc())
    env, payload = ttc.evaluate(gdir, today=REF)
    assert env["status"] == "FAIL"
    assert "Microsoft Azure" in env["detail"]
    assert payload["measured"] == env["measured"] == 1


def test_marking_ep002_tested_flips_azure_to_pass(tmp_path):
    """Acceptance #2: EP-002 'Tested' (with EP-001 Documented) -> overall PASS."""
    gdir = _write_governance(
        tmp_path, _register(ep002_status="Tested", ep001_status="Documented"), _controls_doc()
    )
    env, payload = ttc.evaluate(gdir, today=REF)
    assert env["status"] == "PASS"
    assert env["measured"] == 0
    assert lc.exit_code_for(env["status"], env["tier"]) == 0
    # Azure now shows compliant in the breakdown.
    azure = next(v for v in payload["vendors_requiring_exit_plan"] if "Azure" in v["vendor"])
    assert azure["exit_status"] == "Tested"
    assert azure["exit_status_compliant"] is True


def test_documented_status_also_passes(tmp_path):
    gdir = _write_governance(
        tmp_path, _register(ep002_status="Documented", ep001_status="Tested"), _controls_doc()
    )
    env, _ = ttc.evaluate(gdir, today=REF)
    assert env["status"] == "PASS"


def test_low_and_medium_vendors_do_not_require_exit_plan(tmp_path):
    """Trivy (Medium) and MegaLinter (Low) have 'Low priority' status but must not FAIL."""
    gdir = _write_governance(
        tmp_path, _register(ep002_status="Tested", ep001_status="Tested"), _controls_doc()
    )
    env, payload = ttc.evaluate(gdir, today=REF)
    assert env["status"] == "PASS"
    required = {v["vendor"] for v in payload["vendors_requiring_exit_plan"]}
    assert not any("Trivy" in v or "MegaLinter" in v for v in required)


# --------------------------------------------------------------------------- #
# tpp-clauses.json payload shape (acceptance #3)                               #
# --------------------------------------------------------------------------- #

def test_payload_lists_each_critical_high_vendor_with_status(tmp_path):
    gdir = _write_governance(tmp_path, _register(), _controls_doc())
    _, payload = ttc.evaluate(gdir, today=REF)
    vendors = payload["vendors_requiring_exit_plan"]
    names = {v["vendor"] for v in vendors}
    # Exactly the Critical/High vendors (GitHub, Azure, Sigstore), not Medium/Low.
    assert names == {"GitHub (Microsoft)", "Microsoft Azure", "Sigstore"}
    for v in vendors:
        assert set(v) >= {"vendor", "criticality", "exit_ref", "exit_status", "exit_status_compliant"}


def test_payload_clause_checklist_is_evidence_only(tmp_path):
    gdir = _write_governance(tmp_path, _register(), _controls_doc())
    _, payload = ttc.evaluate(gdir, today=REF)
    cc = payload["clause_checklist"]
    assert cc["tier"] == "EVIDENCE-ONLY"
    assert cc["present"] is True
    assert cc["missing_categories"] == []
    assert set(cc["present_categories"]) == set(ttc.REQUIRED_CLAUSE_CATEGORIES)
    assert cc["cadence_status"] == "PASS"


def test_payload_records_missing_clause_categories(tmp_path):
    incomplete_controls = "# ICT Third-Party Contract Controls\n\n## 1. Security Terms\n"
    gdir = _write_governance(tmp_path, _register(ep002_status="Tested"), incomplete_controls)
    _, payload = ttc.evaluate(gdir, today=REF)
    cc = payload["clause_checklist"]
    # Missing the three other categories — recorded, but EVIDENCE-ONLY (no BLOCK).
    assert "Data Protection" in cc["missing_categories"]
    assert "Exit and Transition" in cc["missing_categories"]


def test_missing_clause_doc_does_not_block(tmp_path):
    """Clause-checklist absence is EVIDENCE-ONLY: it must not turn a PASS into FAIL."""
    gdir = _write_governance(
        tmp_path, _register(ep002_status="Tested", ep001_status="Tested"), controls_md=None
    )
    env, payload = ttc.evaluate(gdir, today=REF)
    assert env["status"] == "PASS"  # exit-plan join is the only BLOCKING signal
    assert payload["clause_checklist"]["present"] is False


# --------------------------------------------------------------------------- #
# Honesty: INDETERMINATE (never silent PASS) on unmeasurable input            #
# --------------------------------------------------------------------------- #

def test_missing_register_is_indeterminate(tmp_path):
    gdir = tmp_path / "empty-governance"
    gdir.mkdir()
    env, payload = ttc.evaluate(gdir, today=REF)
    assert env["status"] == "INDETERMINATE"
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


def test_register_without_exit_table_is_indeterminate(tmp_path):
    reg = """# Vendor Risk Register

## Vendor Inventory

| # | Vendor | Criticality | Exit Plan Ref |
|---|--------|-------------|---------------|
| 1 | Azure | Critical | EP-002 |
"""
    gdir = _write_governance(tmp_path, reg, _controls_doc())
    env, _ = ttc.evaluate(gdir, today=REF)
    assert env["status"] == "INDETERMINATE"


# --------------------------------------------------------------------------- #
# Envelope conforms to the T-33 contract                                       #
# --------------------------------------------------------------------------- #

def test_envelope_has_t33_keys_and_blocking_tier(tmp_path):
    gdir = _write_governance(tmp_path, _register(), _controls_doc())
    env, _ = ttc.evaluate(gdir, today=REF)
    assert set(env) == set(lc.ENVELOPE_KEYS)
    assert env["tier"] == "BLOCKING"
    assert env["threshold"] == 0
    assert env["validator"] == "check-thirdparty-clauses"


def test_main_writes_tpp_clauses_json(tmp_path):
    gdir = _write_governance(tmp_path, _register(ep002_status="Tested", ep001_status="Tested"),
                             _controls_doc())
    out = tmp_path / "tpp-clauses.json"
    code = ttc.main([str(gdir), "--out", str(out)])
    assert code == 0
    data = json.loads(out.read_text())
    assert data["status"] == "PASS"
    assert data["validator"] == "check-thirdparty-clauses"
    assert "vendors_requiring_exit_plan" in data


def test_main_returns_one_on_blocking_fail(tmp_path):
    gdir = _write_governance(tmp_path, _register(ep002_status="Planned"), _controls_doc())
    out = tmp_path / "tpp-clauses.json"
    code = ttc.main([str(gdir), "--out", str(out)])
    assert code == 1


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
            spec = getattr(fn, "_params", None)
            if spec:
                argnames, argvalues = spec
                names = [a.strip() for a in argnames.split(",")]
                non_tmp = [n for n in names if n != "tmp_path"]
                for row in argvalues:
                    row = row if isinstance(row, (tuple, list)) else (row,)
                    with tempfile.TemporaryDirectory() as d:
                        kw = dict(zip(non_tmp, row))
                        kw["tmp_path"] = Path(d)
                        _run_one(name, fn, kw)
            else:
                with tempfile.TemporaryDirectory() as d:
                    _run_one(name, fn, {"tmp_path": Path(d)})
            continue
        spec = getattr(fn, "_params", None)
        if spec:
            argnames, argvalues = spec
            names = [a.strip() for a in argnames.split(",")]
            for row in argvalues:
                row = row if isinstance(row, (tuple, list)) else (row,)
                _run_one(name, fn, dict(zip(names, row)))
            continue
        _run_one(name, fn, {})

    print(f"\nstandalone: {passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)
