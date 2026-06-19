"""Unit tests for the E.1 ``check_ict_risk_framework`` validator.

Proves the HONEST predicate (DORA Art.6 / NIS2 Art.21(2)(a)): a PASS requires a
framework doc that exists, carries every required section, AND was reviewed within
the annual window. The shipped seed records ``Last Reviewed: pending initial
management review`` and must therefore be INDETERMINATE (not a silent PASS on a
founder-typed date), because no genuine management review has occurred yet.

Also proves:
  * present + fresh + all sections -> PASS;
  * a missing required section -> FAIL;
  * a stale (>365d) review date -> FAIL;
  * an absent doc -> INDETERMINATE;
  * the shipped seed -> INDETERMINATE ("pending initial management review");
  * the management-body approval fact is EVIDENCE-ONLY (rides along, never gates);
  * ``ict-risk-framework.json`` is written and records the review date;
  * the BLOCKING exit-code mapping (PASS 0 / FAIL 1 / INDETERMINATE 2).

Runs under pytest AND standalone (``python3 tests/compliance/test_check_ict_risk_framework.py``).
"""

from __future__ import annotations

import importlib
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

# The validator filename is importable as a dotted module (underscores, no hyphens).
civ = importlib.import_module("scripts.validators.check_ict_risk_framework")
lc = importlib.import_module("scripts.validators.libcompliance")

REF = date(2026, 6, 16)  # deterministic "today"
SEED_DOC = PIPELINE_ROOT / "docs" / "governance" / "ict-risk-management-framework.md"

# A complete, well-formed framework doc with a REAL recent review date -> PASS.
_FRESH_DOC = """\
# ICT Risk-Management Framework

**Document Owner:** Security Lead
**Approved By:** Szymon Mytych (CyberForge management)
**Last Reviewed:** 2026-05-01
**Review Cadence:** Annually

## 2. Governance and Ownership
The framework owner is the Security Lead; the management body approves.

## 3. Risk Appetite and Tolerance
CyberForge operates a low risk appetite for confidentiality and integrity.

## 4. Methodology Reference
Adopts risk-assessment-methodology.md.

## 5. Control Framework Reference
The control framework of record is statement-of-applicability.md.

## 6. Review Cadence and Record
Reviewed at least annually per DORA Art.6(5).
"""


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "ict-risk-management-framework.md"
    p.write_text(body, encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# PASS: present + fresh + all sections                                         #
# --------------------------------------------------------------------------- #

def test_fresh_complete_doc_passes(tmp_path):
    doc = _write(tmp_path, _FRESH_DOC)
    env = civ.evaluate(doc, today=REF)
    assert env["status"] == "PASS"
    assert env["tier"] == "BLOCKING"
    assert env["measured"]["review_date"] == "2026-05-01"
    assert env["measured"]["missing_sections"] == []
    assert env["measured"]["review_age_days"] == 46


def test_pass_records_approval_evidence_only(tmp_path):
    doc = _write(tmp_path, _FRESH_DOC)
    env = civ.evaluate(doc, today=REF)
    approval = env["components"]["management_body_approval"]
    assert approval["tier"] == "EVIDENCE-ONLY"
    assert approval["status"] == "PASS"
    assert approval["measured"] is True


# --------------------------------------------------------------------------- #
# FAIL: a required section missing                                             #
# --------------------------------------------------------------------------- #

def test_missing_section_fails(tmp_path):
    # Drop the risk-appetite section entirely.
    body = _FRESH_DOC.replace(
        "## 3. Risk Appetite and Tolerance\n"
        "CyberForge operates a low risk appetite for confidentiality and integrity.\n",
        "",
    )
    env = civ.evaluate(_write(tmp_path, body), today=REF)
    assert env["status"] == "FAIL"
    assert env["tier"] == "BLOCKING"
    assert "risk appetite/tolerance" in env["measured"]["missing_sections"]


# --------------------------------------------------------------------------- #
# FAIL: stale review date                                                      #
# --------------------------------------------------------------------------- #

def test_stale_review_fails(tmp_path):
    # 2025-01-01 is > 365 days before 2026-06-16.
    body = _FRESH_DOC.replace("2026-05-01", "2025-01-01")
    env = civ.evaluate(_write(tmp_path, body), today=REF)
    assert env["status"] == "FAIL"
    assert env["tier"] == "BLOCKING"
    assert "STALE" in env["detail"]


def test_fresh_review_at_boundary_passes(tmp_path):
    # Exactly 365 days old -> still within the window (<=).
    body = _FRESH_DOC.replace("2026-05-01", "2025-06-16")
    env = civ.evaluate(_write(tmp_path, body), today=REF)
    assert env["status"] == "PASS"
    assert env["measured"]["review_age_days"] == 365


# --------------------------------------------------------------------------- #
# INDETERMINATE: absent doc, and the honest seed (no parseable review date)    #
# --------------------------------------------------------------------------- #

def test_absent_doc_is_indeterminate(tmp_path):
    env = civ.evaluate(tmp_path / "does-not-exist.md", today=REF)
    assert env["status"] == "INDETERMINATE"
    assert env["tier"] == "BLOCKING"


def test_no_parseable_review_date_is_indeterminate(tmp_path):
    body = _FRESH_DOC.replace("2026-05-01", "pending initial management review")
    env = civ.evaluate(_write(tmp_path, body), today=REF)
    assert env["status"] == "INDETERMINATE"
    assert env["tier"] == "BLOCKING"
    assert env["measured"]["review_date"] is None


def test_shipped_seed_is_indeterminate():
    """The real seed MUST be INDETERMINATE today -- honest 'not yet reviewed'."""
    if not SEED_DOC.is_file():
        pytest.skip("seed ict-risk-management-framework.md not present")
    env = civ.evaluate(SEED_DOC, today=REF)
    assert env["status"] == "INDETERMINATE"
    assert env["tier"] == "BLOCKING"
    assert env["measured"]["review_date"] is None
    # Seed has all required sections present -> no missing-section FAIL.
    assert env["measured"]["missing_sections"] == []
    # Seed's approval is a placeholder -> EVIDENCE-ONLY records it as not-yet-approved.
    assert env["components"]["management_body_approval"]["measured"] is False


# --------------------------------------------------------------------------- #
# Exit-code mapping (BLOCKING tier)                                            #
# --------------------------------------------------------------------------- #

def test_exit_codes_match_status(tmp_path):
    pass_env = civ.evaluate(_write(tmp_path, _FRESH_DOC), today=REF)
    assert lc.exit_code_for(pass_env["status"], pass_env["tier"]) == 0

    fail_body = _FRESH_DOC.replace("2026-05-01", "2025-01-01")
    fail_env = civ.evaluate(_write(tmp_path, fail_body), today=REF)
    assert lc.exit_code_for(fail_env["status"], fail_env["tier"]) == 1

    indet_env = civ.evaluate(tmp_path / "nope.md", today=REF)
    assert lc.exit_code_for(indet_env["status"], indet_env["tier"]) == 2


# --------------------------------------------------------------------------- #
# main() writes ict-risk-framework.json                                        #
# --------------------------------------------------------------------------- #

def test_main_writes_json_on_pass(tmp_path):
    doc = _write(tmp_path, _FRESH_DOC)
    out = tmp_path / "ict-risk-framework.json"
    with pytest.raises(SystemExit) as exc:
        civ.main([str(doc), "--out", str(out)])
    assert exc.value.code == 0
    payload = json.loads(out.read_text())
    assert payload["status"] == "PASS"
    assert payload["measured"]["review_date"] == "2026-05-01"
    assert payload["validator"] == "check_ict_risk_framework"


def test_main_exits_two_on_seed_indeterminate():
    if not SEED_DOC.is_file():
        pytest.skip("seed ict-risk-management-framework.md not present")
    out = SEED_DOC.parent / "_tmp_ict_test.json"
    try:
        with pytest.raises(SystemExit) as exc:
            civ.main([str(SEED_DOC), "--out", str(out)])
        assert exc.value.code == 2
        payload = json.loads(out.read_text())
        assert payload["status"] == "INDETERMINATE"
    finally:
        if out.is_file():
            out.unlink()


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
