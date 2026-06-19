"""Unit tests for the A.6 ``check-governance`` validator (task T-25).

Proves the DoD + acceptance criteria:
  * PASS on the *real* current governance docs (both within cadence) with a
    deterministic reference date.
  * Backdating the training record's ``Effective Date`` beyond 365 days makes the
    overall verdict BLOCKING FAIL with the NIS2 Art.20(2) citation.
  * Deleting either document yields a presence INDETERMINATE (a hard, non-zero gate
    failure — *never* a silent PASS), not a pass.
  * EVIDENCE-ONLY components (board sign-off, attendee count) ride along without
    gating the build (honest framing: the pipeline validates the log, not the event).

Runs under pytest (``python3 -m pytest tests/compliance/test_check_governance.py -q``)
AND standalone (``python3 tests/compliance/test_check_governance.py``) so it is
verifiable even where pytest is not installed — mirrors test_libcompliance.py.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from datetime import date
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback: minimal pytest surface (parametrize/raises)
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

# Make the Pipeline root importable so ``scripts.validators.*`` resolves anywhere.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402


def _load_validator():
    """Import the hyphenated ``check-governance.py`` module by file path.

    The validator filename uses a hyphen (CLI-style), so it is not importable as a
    normal dotted module — load it explicitly via importlib.
    """
    path = PIPELINE_ROOT / "scripts" / "validators" / "check-governance.py"
    spec = importlib.util.spec_from_file_location("check_governance", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


cg = _load_validator()

GOVERNANCE_DIR = PIPELINE_ROOT / "docs" / "governance"
MGMT_REVIEW = cg.MANAGEMENT_REVIEW_DOC
TRAINING = cg.TRAINING_RECORDS_DOC

# Deterministic "today": the real docs are dated 2026-03-15; 2026-06-16 -> 93 days,
# which is inside both 183d (semi-annual) and 365d (annual) cadences.
REF = date(2026, 6, 16)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _copy_governance(dest: Path) -> Path:
    """Copy the two real governance docs into a temp dir so tests never mutate them."""
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(GOVERNANCE_DIR / MGMT_REVIEW, dest / MGMT_REVIEW)
    shutil.copy(GOVERNANCE_DIR / TRAINING, dest / TRAINING)
    return dest


def _backdate_effective(dest: Path, new_date: str) -> None:
    """Rewrite the training record's ``Effective Date`` table value to ``new_date``."""
    f = dest / TRAINING
    text = f.read_text(encoding="utf-8")
    text = re.sub(
        r"(\|\s*Effective Date\s*\|\s*)\d{4}-\d{2}-\d{2}",
        rf"\g<1>{new_date}",
        text,
        count=1,
    )
    f.write_text(text, encoding="utf-8")


# --------------------------------------------------------------------------- #
# Real-doc parsing (no mutation)                                              #
# --------------------------------------------------------------------------- #

def test_real_docs_exist():
    assert (GOVERNANCE_DIR / MGMT_REVIEW).is_file()
    assert (GOVERNANCE_DIR / TRAINING).is_file()


def test_pass_on_current_docs_within_cadence():
    overall = cg.evaluate(GOVERNANCE_DIR, today=REF)
    assert overall["status"] == lc.Status.PASS
    assert overall["tier"] == lc.Tier.BLOCKING
    # Both freshness components measured 93 days and passed.
    comps = overall["components"]
    assert comps["management_review_freshness"]["status"] == lc.Status.PASS
    assert comps["management_review_freshness"]["measured"] == 93
    assert comps["training_record_freshness"]["status"] == lc.Status.PASS
    assert comps["training_record_freshness"]["measured"] == 93


def test_overall_envelope_has_t33_key_set():
    overall = cg.evaluate(GOVERNANCE_DIR, today=REF)
    # The overall envelope carries the canonical T-33 keys (plus a components map).
    assert set(lc.ENVELOPE_KEYS).issubset(set(overall))
    assert "components" in overall


def test_exit_code_pass_is_zero():
    overall = cg.evaluate(GOVERNANCE_DIR, today=REF)
    assert lc.exit_code_for(overall["status"], overall["tier"]) == 0


# --------------------------------------------------------------------------- #
# Freshness FAIL on backdated training record                                 #
# --------------------------------------------------------------------------- #

def test_backdated_training_fails_with_article(tmp_path):
    d = _copy_governance(tmp_path)
    _backdate_effective(d, "2024-01-01")  # >365 days before REF
    overall = cg.evaluate(d, today=REF)
    assert overall["status"] == lc.Status.FAIL
    training = overall["components"]["training_record_freshness"]
    assert training["status"] == lc.Status.FAIL
    assert training["measured"] > cg.MAX_AGE_TRAINING_DAYS
    # The NIS2 article must be cited on the FAIL detail.
    assert "NIS2 Art.20" in training["detail"]
    # And the BLOCKING FAIL maps to a non-zero exit.
    assert lc.exit_code_for(overall["status"], overall["tier"]) == 1


def test_backdated_management_review_fails(tmp_path):
    d = _copy_governance(tmp_path)
    # Backdate the bold-line "Last Reviewed:" beyond the 183-day semi-annual cadence.
    f = d / MGMT_REVIEW
    text = f.read_text(encoding="utf-8")
    text = text.replace("**Last Reviewed:** 2026-03-15", "**Last Reviewed:** 2025-01-01")
    f.write_text(text, encoding="utf-8")
    overall = cg.evaluate(d, today=REF)
    assert overall["status"] == lc.Status.FAIL
    mr = overall["components"]["management_review_freshness"]
    assert mr["status"] == lc.Status.FAIL
    assert mr["measured"] > cg.MAX_AGE_MANAGEMENT_REVIEW_DAYS
    assert "DORA Art.5" in mr["detail"]


def test_within_cadence_boundary_is_pass(tmp_path):
    d = _copy_governance(tmp_path)
    # Exactly 365 days old -> still PASS (<= threshold).
    _backdate_effective(d, "2025-06-16")  # 365 days before REF
    overall = cg.evaluate(d, today=REF)
    assert overall["components"]["training_record_freshness"]["measured"] == 365
    assert overall["components"]["training_record_freshness"]["status"] == lc.Status.PASS


def test_one_day_over_cadence_is_fail(tmp_path):
    d = _copy_governance(tmp_path)
    _backdate_effective(d, "2025-06-15")  # 366 days before REF
    overall = cg.evaluate(d, today=REF)
    assert overall["components"]["training_record_freshness"]["measured"] == 366
    assert overall["components"]["training_record_freshness"]["status"] == lc.Status.FAIL


# --------------------------------------------------------------------------- #
# Presence: deleting a document is a hard non-silent gate failure             #
# --------------------------------------------------------------------------- #

def test_missing_management_review_is_indeterminate_not_pass(tmp_path):
    d = _copy_governance(tmp_path)
    (d / MGMT_REVIEW).unlink()
    overall = cg.evaluate(d, today=REF)
    assert overall["status"] == lc.Status.INDETERMINATE
    assert overall["status"] != lc.Status.PASS  # explicitly: never a silent pass
    mr = overall["components"]["management_review_freshness"]
    assert mr["status"] == lc.Status.INDETERMINATE
    assert "not found" in mr["detail"].lower()
    # INDETERMINATE on a BLOCKING check -> non-zero (exit 2).
    assert lc.exit_code_for(overall["status"], overall["tier"]) == 2


def test_missing_training_record_is_indeterminate_not_pass(tmp_path):
    d = _copy_governance(tmp_path)
    (d / TRAINING).unlink()
    overall = cg.evaluate(d, today=REF)
    assert overall["status"] == lc.Status.INDETERMINATE
    tr = overall["components"]["training_record_freshness"]
    assert tr["status"] == lc.Status.INDETERMINATE
    assert lc.exit_code_for(overall["status"], overall["tier"]) != 0


def test_empty_directory_is_indeterminate(tmp_path):
    overall = cg.evaluate(tmp_path, today=REF)  # nothing copied in
    assert overall["status"] == lc.Status.INDETERMINATE
    assert lc.exit_code_for(overall["status"], overall["tier"]) == 2


# --------------------------------------------------------------------------- #
# EVIDENCE-ONLY components never gate the build                               #
# --------------------------------------------------------------------------- #

def test_board_approval_signoff_detected_on_real_doc():
    overall = cg.evaluate(GOVERNANCE_DIR, today=REF)
    approval = overall["components"]["board_approval_signoff"]
    assert approval["tier"] == lc.Tier.EVIDENCE_ONLY
    assert approval["status"] == lc.Status.PASS
    assert approval["measured"] is True
    assert "Art.20(1)" in approval["detail"]


def test_attendee_count_is_evidence_only_and_does_not_block(tmp_path):
    # Real template has empty attendee rows -> count 0 -> EVIDENCE-ONLY FAIL,
    # but it must NOT change the overall (still PASS via fresh dates).
    overall = cg.evaluate(GOVERNANCE_DIR, today=REF)
    attendees = overall["components"]["training_attendees_recorded"]
    assert attendees["tier"] == lc.Tier.EVIDENCE_ONLY
    assert attendees["measured"] == 0
    assert attendees["status"] == lc.Status.FAIL
    # Overall is still PASS — an EVIDENCE-ONLY FAIL never breaks the gate.
    assert overall["status"] == lc.Status.PASS
    assert lc.exit_code_for(overall["status"], overall["tier"]) == 0


def test_populated_attendee_row_counts(tmp_path):
    d = _copy_governance(tmp_path)
    f = d / TRAINING
    text = f.read_text(encoding="utf-8")
    # Insert one populated attendee row into the Training Records table.
    populated = (
        "| 2026-04-01 | Jane Doe | CTO | Regulatory obligations | Internal "
        "| 2h | Pass | confirm-2026-04-01 |"
    )
    text = text.replace(
        "| | | | | | | | |",
        "| | | | | | | | |\n" + populated,
        1,
    )
    f.write_text(text, encoding="utf-8")
    overall = cg.evaluate(d, today=REF)
    assert overall["components"]["training_attendees_recorded"]["measured"] == 1


def test_missing_approval_value_is_evidence_only_fail(tmp_path):
    d = _copy_governance(tmp_path)
    f = d / TRAINING
    text = f.read_text(encoding="utf-8")
    # Blank out the "Approved By" value AND remove any sign-off/signature markers.
    text = text.replace("| Approved By    | CyberForge Management", "| Approved By    | ____")
    f.write_text(text, encoding="utf-8")
    approval = cg._approval_component(d)
    assert approval["tier"] == lc.Tier.EVIDENCE_ONLY
    assert approval["status"] == lc.Status.FAIL
    assert approval["measured"] is False
    # Still EVIDENCE-ONLY: exit code stays 0.
    assert lc.exit_code_for(approval["status"], approval["tier"]) == 0


# --------------------------------------------------------------------------- #
# CLI: writes governance-evidence.json + exits with the tier-aware code        #
# --------------------------------------------------------------------------- #

def test_cli_writes_evidence_json_and_exits_zero_on_pass(tmp_path):
    out = tmp_path / "governance-evidence.json"
    code = cg.main([str(GOVERNANCE_DIR), "--out", str(out)])
    assert code == 0
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["status"] == "PASS"
    assert data["validator"] == cg.VALIDATOR
    assert "components" in data


def test_cli_exits_nonzero_on_backdated(tmp_path):
    d = _copy_governance(tmp_path)
    _backdate_effective(d, "2020-01-01")
    out = tmp_path / "gov.json"
    # No today injection through CLI; 2020 is stale under any real today.
    code = cg.main([str(d), "--out", str(out)])
    assert code == 1
    assert json.loads(out.read_text(encoding="utf-8"))["status"] == "FAIL"


# --------------------------------------------------------------------------- #
# Date-label extraction handles both bold-line and table-row forms            #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "text,labels,expected",
    [
        ("**Last Reviewed:** 2026-03-15", ("Last Reviewed",), "2026-03-15"),
        ("| Effective Date | 2026-03-15 |", ("Effective Date",), "2026-03-15"),
        ("Effective Date: 2025-12-31", ("Effective Date",), "2025-12-31"),
        ("no date here", ("Last Reviewed",), None),
    ],
)
def test_find_labelled_date(text, labels, expected):
    assert cg._find_labelled_date(text, *labels) == expected


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
            spec = getattr(fn, "_params", None)
            if spec:
                argnames, argvalues = spec
                names = [a.strip() for a in argnames.split(",")]
                non_tmp = [n for n in names if n != "tmp_path"]
                for row in argvalues:
                    row = row if isinstance(row, (tuple, list)) else (row,)
                    with tempfile.TemporaryDirectory() as dd:
                        kw = dict(zip(non_tmp, row))
                        kw["tmp_path"] = Path(dd)
                        _run_one(name, fn, kw)
            else:
                with tempfile.TemporaryDirectory() as dd:
                    _run_one(name, fn, {"tmp_path": Path(dd)})
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
