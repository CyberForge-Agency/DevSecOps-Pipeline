"""Unit tests for the T-33 shared compliance-validator envelope library.

Proves: envelope shape + key set, status/tier validation, the (status, tier) ->
exit-code mapping (PASS/EVIDENCE-ONLY -> 0, FAIL -> 1, INDETERMINATE -> 2),
freshness math, threshold/presence/json helpers, and the GFM table parser against
the real ``vendor-risk-register.md`` (must yield exactly 10 dicts — T-33 acceptance).

Runs under pytest (``python3 -m pytest tests/compliance/test_libcompliance.py -q``)
AND standalone (``python3 tests/compliance/test_libcompliance.py``) so the suite is
verifiable even where pytest is not installed.
"""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from datetime import date
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback: provide the minimal pytest surface we use
    class _PytestShim:
        """Tiny stand-in so this file imports + runs without pytest installed.

        Supports the subset used here: ``pytest.raises`` and ``pytest.mark.parametrize``.
        Under real pytest the genuine module is used; this only kicks in for the
        ``python3 test_libcompliance.py`` standalone path.
        """

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

# Make the Pipeline root importable as ``scripts.validators.libcompliance`` no matter
# where pytest's rootdir lands.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

REF = date(2026, 6, 16)  # deterministic "today" for freshness assertions
VENDOR_REGISTER = PIPELINE_ROOT / "docs" / "governance" / "vendor-risk-register.md"


# --------------------------------------------------------------------------- #
# envelope() shape + validation                                               #
# --------------------------------------------------------------------------- #

def test_envelope_has_exact_key_set():
    env = lc.envelope("PASS", "BLOCKING", measured=1, threshold=0, detail="ok")
    assert set(env) == set(lc.ENVELOPE_KEYS)


def test_envelope_is_json_serialisable():
    env = lc.envelope("FAIL", "EVIDENCE-ONLY", measured={"critical": 2}, threshold={"critical": 0})
    encoded = json.dumps(env)
    assert json.loads(encoded)["status"] == "FAIL"


def test_envelope_records_measured_and_threshold_values():
    env = lc.envelope("PASS", "BLOCKING", measured=1825, threshold=1825, detail="retention")
    assert env["measured"] == 1825
    assert env["threshold"] == 1825


def test_envelope_checked_at_is_utc_iso():
    env = lc.envelope("PASS", "BLOCKING")
    assert env["checked_at"].endswith("Z")
    assert len(env["checked_at"]) == 20  # YYYY-MM-DDThh:mm:ssZ


@pytest.mark.parametrize("bad_status", ["MAYBE", "pass", "", "OK"])
def test_envelope_rejects_invalid_status(bad_status):
    with pytest.raises(lc.ValidatorError):
        lc.envelope(bad_status, "BLOCKING")


@pytest.mark.parametrize("bad_tier", ["HARD", "blocking", "", "OUT-OF-PIPELINE"])
def test_envelope_rejects_invalid_tier(bad_tier):
    with pytest.raises(lc.ValidatorError):
        lc.envelope("PASS", bad_tier)


# --------------------------------------------------------------------------- #
# exit-code mapping                                                            #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "status,tier,expected",
    [
        ("PASS", "BLOCKING", 0),
        ("FAIL", "BLOCKING", 1),
        ("INDETERMINATE", "BLOCKING", 2),
        # EVIDENCE-ONLY never breaks the build regardless of measured status.
        ("PASS", "EVIDENCE-ONLY", 0),
        ("FAIL", "EVIDENCE-ONLY", 0),
        ("INDETERMINATE", "EVIDENCE-ONLY", 0),
    ],
)
def test_exit_code_for(status, tier, expected):
    assert lc.exit_code_for(status, tier) == expected


# --------------------------------------------------------------------------- #
# emit() — prints JSON + exits with the mapped code                           #
# --------------------------------------------------------------------------- #

def test_emit_returns_envelope_without_exiting(capsys):
    env = lc.emit("PASS", "BLOCKING", 1, 0, "ok", exit_process=False)
    out = capsys.readouterr().out.strip()
    assert json.loads(out)["status"] == "PASS"
    assert env["tier"] == "BLOCKING"


def test_emit_exits_zero_on_pass():
    with pytest.raises(SystemExit) as exc:
        lc.emit("PASS", "BLOCKING", 1, 0, "ok")
    assert exc.value.code == 0


def test_emit_exits_one_on_blocking_fail():
    with pytest.raises(SystemExit) as exc:
        lc.emit("FAIL", "BLOCKING", 5, 0, "5 CRITICAL CVEs")
    assert exc.value.code == 1


def test_emit_exits_two_on_indeterminate():
    with pytest.raises(SystemExit) as exc:
        lc.emit("INDETERMINATE", "BLOCKING", None, 0, "empty artifact")
    assert exc.value.code == 2


def test_emit_evidence_only_fail_exits_zero():
    with pytest.raises(SystemExit) as exc:
        lc.emit("FAIL", "EVIDENCE-ONLY", 3, 0, "medium findings count")
    assert exc.value.code == 0


# --------------------------------------------------------------------------- #
# freshness: days_since + check_fresh                                         #
# --------------------------------------------------------------------------- #

def test_days_since_same_day_is_zero():
    assert lc.days_since("2026-06-16", today=REF) == 0


def test_days_since_quarterly_window():
    # 2026-03-16 is exactly 92 days before 2026-06-16.
    assert lc.days_since("2026-03-16", today=REF) == 92


def test_days_since_future_is_negative():
    assert lc.days_since("2026-06-20", today=REF) == -4


def test_days_since_accepts_datetime_with_z():
    assert lc.days_since("2026-06-14T23:00:00Z", today=REF) == 2


def test_days_since_raises_on_garbage():
    with pytest.raises(lc.ValidatorError):
        lc.days_since("not-a-date", today=REF)


def test_check_fresh_pass_within_window():
    env = lc.check_fresh("2026-03-16", 92, today=REF, label="register")
    assert env["status"] == "PASS"
    assert env["measured"] == 92
    assert env["threshold"] == 92


def test_check_fresh_fail_when_stale():
    env = lc.check_fresh("2026-03-15", 92, today=REF, label="register")
    assert env["status"] == "FAIL"
    assert env["measured"] == 93


def test_check_fresh_indeterminate_on_bad_date():
    env = lc.check_fresh("???", 92, today=REF)
    assert env["status"] == "INDETERMINATE"
    assert env["measured"] is None


# --------------------------------------------------------------------------- #
# threshold helper                                                            #
# --------------------------------------------------------------------------- #

def test_check_threshold_pass():
    env = lc.check_threshold(0, "<=", 0, label="critical CVEs")
    assert env["status"] == "PASS"


def test_check_threshold_fail():
    env = lc.check_threshold(5, "<=", 0, label="critical CVEs")
    assert env["status"] == "FAIL"
    assert env["measured"] == 5


def test_check_threshold_indeterminate_on_none():
    env = lc.check_threshold(None, "<=", 0)
    assert env["status"] == "INDETERMINATE"


def test_check_threshold_bool_is_not_numeric():
    # True must not be treated as 1 — that would silently pass a missing measurement.
    env = lc.check_threshold(True, ">=", 1)
    assert env["status"] == "INDETERMINATE"


def test_check_threshold_rejects_bad_operator():
    with pytest.raises(lc.ValidatorError):
        lc.check_threshold(1, "=<", 0)


# --------------------------------------------------------------------------- #
# presence + load_json                                                        #
# --------------------------------------------------------------------------- #

def test_check_presence_pass(tmp_path):
    f = tmp_path / "evidence.json"
    f.write_text('{"k": 1}')
    env = lc.check_presence(f)
    assert env["status"] == "PASS"
    assert env["measured"] == f.stat().st_size


def test_check_presence_missing_is_indeterminate(tmp_path):
    env = lc.check_presence(tmp_path / "nope.json")
    assert env["status"] == "INDETERMINATE"


def test_check_presence_empty_is_indeterminate(tmp_path):
    f = tmp_path / "empty.json"
    f.write_text("")
    env = lc.check_presence(f)
    assert env["status"] == "INDETERMINATE"


def test_load_json_ok(tmp_path):
    f = tmp_path / "ok.json"
    f.write_text('{"reports": {"trivy": {}}}')
    data, err = lc.load_json(f)
    assert err is None
    assert data["reports"]["trivy"] == {}


def test_load_json_empty_object_is_no_content(tmp_path):
    # The "{} must not pass" hole: an empty object is treated as no measurable data.
    f = tmp_path / "blank.json"
    f.write_text("{}")
    data, err = lc.load_json(f)
    assert data is None
    assert "empty JSON content" in err


def test_load_json_malformed(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{not json")
    data, err = lc.load_json(f)
    assert data is None
    assert "invalid JSON" in err


def test_load_json_missing(tmp_path):
    data, err = lc.load_json(tmp_path / "absent.json")
    assert data is None
    assert "file not found" in err


# --------------------------------------------------------------------------- #
# gfm_table — the T-33 acceptance check                                       #
# --------------------------------------------------------------------------- #

def test_gfm_table_vendor_inventory_yields_ten_dicts():
    rows = lc.gfm_table(str(VENDOR_REGISTER), "Vendor Inventory")
    assert len(rows) == 10
    assert all(isinstance(r, dict) for r in rows)


def test_gfm_table_vendor_inventory_keys_and_values():
    rows = lc.gfm_table(str(VENDOR_REGISTER), "Vendor Inventory")
    assert "Vendor" in rows[0]
    assert "DPA Status" in rows[0]
    assert rows[0]["Vendor"].startswith("GitHub")
    assert rows[9]["Vendor"].startswith("Truffle")  # 10th vendor


def test_gfm_table_parses_inline_table(tmp_path):
    md = tmp_path / "t.md"
    md.write_text(
        "# Title\n\n"
        "## Review Schedule\n\n"
        "| Area | Owner | Next Due |\n"
        "|------|-------|----------|\n"
        "| IAM | Alice | 2026-09-01 |\n"
        "| Repo | Bob | 2026-07-15 |\n\n"
        "## Other\n"
    )
    rows = lc.gfm_table(str(md), "Review Schedule")
    assert rows == [
        {"Area": "IAM", "Owner": "Alice", "Next Due": "2026-09-01"},
        {"Area": "Repo", "Owner": "Bob", "Next Due": "2026-07-15"},
    ]


def test_gfm_table_stops_at_next_heading(tmp_path):
    md = tmp_path / "t.md"
    md.write_text(
        "## A\n\n| X |\n|---|\n| 1 |\n\n## B\n\n| Y |\n|---|\n| 2 |\n"
    )
    assert lc.gfm_table(str(md), "A") == [{"X": "1"}]
    assert lc.gfm_table(str(md), "B") == [{"Y": "2"}]


def test_gfm_table_handles_ragged_rows(tmp_path):
    md = tmp_path / "t.md"
    md.write_text(
        "## T\n\n| A | B | C |\n|---|---|---|\n| 1 | 2 |\n| 3 | 4 | 5 | 6 |\n"
    )
    rows = lc.gfm_table(str(md), "T")
    assert rows[0] == {"A": "1", "B": "2", "C": ""}      # padded
    assert rows[1] == {"A": "3", "B": "4", "C": "5"}     # truncated


def test_gfm_table_matches_numbered_heading(tmp_path):
    # Governance docs number their sections (e.g. "## 3. Review Schedule"); callers
    # pass the bare title. Both the bare and numbered forms must resolve.
    md = tmp_path / "t.md"
    md.write_text(
        "## 3. Review Schedule\n\n| Area | Next Due |\n|---|---|\n| IAM | 2026-09-01 |\n"
    )
    assert lc.gfm_table(str(md), "Review Schedule") == [{"Area": "IAM", "Next Due": "2026-09-01"}]
    assert lc.gfm_table(str(md), "3. Review Schedule") == [{"Area": "IAM", "Next Due": "2026-09-01"}]


def test_gfm_table_real_access_review_schedule():
    schedule = PIPELINE_ROOT / "docs" / "governance" / "access-review-schedule.md"
    if not schedule.is_file():
        pytest.skip("access-review-schedule.md not present")
    rows = lc.gfm_table(str(schedule), "Review Schedule")
    assert len(rows) >= 1
    assert "Next Due" in rows[0]


def test_gfm_table_missing_heading_raises(tmp_path):
    md = tmp_path / "t.md"
    md.write_text("## A\n\n| X |\n|---|\n| 1 |\n")
    with pytest.raises(lc.ValidatorError):
        lc.gfm_table(str(md), "Nonexistent")


def test_gfm_table_missing_file_raises():
    with pytest.raises(lc.ValidatorError):
        lc.gfm_table("/nonexistent/path.md", "Anything")


def test_gfm_table_heading_without_table_raises(tmp_path):
    md = tmp_path / "t.md"
    md.write_text("## Empty Section\n\nJust prose, no table.\n\n## Next\n")
    with pytest.raises(lc.ValidatorError):
        lc.gfm_table(str(md), "Empty Section")


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
        except BaseException as exc:  # noqa: BLE001 - report and continue
            if _Skipped is not None and isinstance(exc, _Skipped):
                skipped += 1
                return
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()

    for name, fn in fns:
        params = list(inspect.signature(fn).parameters)
        # capsys is a pytest-only fixture we cannot reproduce standalone.
        if "capsys" in params:
            skipped += 1
            continue
        # Supply a real temp dir for tmp_path fixtures.
        if "tmp_path" in params:
            spec = getattr(fn, "_params", None)
            if spec:  # parametrized + tmp_path: run each case
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
        # Parametrized (no fixtures): run each parameter row.
        spec = getattr(fn, "_params", None)
        if spec:
            argnames, argvalues = spec
            names = [a.strip() for a in argnames.split(",")]
            for row in argvalues:
                row = row if isinstance(row, (tuple, list)) else (row,)
                _run_one(name, fn, dict(zip(names, row)))
            continue
        _run_one(name, fn, {})

    print(f"\nstandalone: {passed} passed, {failed} failed, "
          f"{skipped} skipped (capsys-only; run via pytest for full coverage)")
    sys.exit(1 if failed else 0)
