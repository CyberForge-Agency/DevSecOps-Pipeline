"""Unit tests for the T-21 check-dpa validator (RODO/GDPR Art.28 processor DPAs).

Proves the three T-21 acceptance criteria plus envelope/tier correctness:

1. Output values for >=1 vendor differ when the register row is edited (the validator
   reads the file — it is not a hardcoded list).
2. A register whose ``Last Reviewed`` is >92 days old yields a BLOCKING FAIL with the
   exact day-count in ``detail``; within the window it PASSes.
3. No hardcoded vendor list remains in ``check-dpa.sh`` (the lie this task removes).

Per-vendor DPA statuses are EVIDENCE-ONLY (recorded, never gating); register freshness
is BLOCKING. The freshness gate drives the process exit code.

Runs under pytest (``python3 -m pytest tests/compliance/test_check_dpa.py -q``) AND
standalone (``python3 tests/compliance/test_check_dpa.py``) so it is verifiable where
pytest is not installed — mirroring test_libcompliance.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback — minimal surface used here
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

from scripts import check_dpa_validator as cdv  # noqa: E402
from scripts.validators import libcompliance as lc  # noqa: E402

REAL_REGISTER = PIPELINE_ROOT / "docs" / "governance" / "vendor-risk-register.md"
CHECK_DPA_SH = PIPELINE_ROOT / "scripts" / "check-dpa.sh"

# A reference "today" close enough to the real register that the boundary cases below
# are deterministic regardless of the wall clock.
FRESH_TODAY = date(2026, 6, 1)   # register Last Reviewed 2026-03-15 -> 78 days (fresh)
STALE_TODAY = date(2026, 7, 1)   # register Last Reviewed 2026-03-15 -> 108 days (stale)


# --------------------------------------------------------------------------- #
# Test-register builder (so tests never mutate the real register)             #
# --------------------------------------------------------------------------- #

def _write_register(tmp_path: Path, *, last_reviewed: str, vendor1_status: str = "ACTIVE",
                    vendor1_name: str = "GitHub (Microsoft)") -> Path:
    md = tmp_path / "vendor-risk-register.md"
    md.write_text(
        "# Vendor Risk Register\n\n"
        "**Document Owner:** Security Lead\n"
        f"**Last Reviewed:** {last_reviewed}\n"
        "**Review Cadence:** Quarterly\n\n"
        "## Vendor Inventory\n\n"
        "| # | Vendor | Service | Data Types Processed | Data Location | DPA Status | "
        "DPA URL / Reference | Risk Rating | Criticality |\n"
        "|---|--------|---------|----------------------|---------------|------------|"
        "--------------------|-------------|-------------|\n"
        f"| 1 | {vendor1_name} | CI | Source code | EU | {vendor1_status} | "
        "[DPA](https://example.test/dpa) | Medium | Critical |\n"
        "| 2 | Sigstore | Rekor | OIDC identity | Global | NOT_REQUIRED | "
        "N/A - public log | Low | High |\n\n"
        "## Data Retention Policy\n\n"
        "| Setting | Value | Notes |\n"
        "|---------|-------|-------|\n"
        "| Evidence pack retention (days) | 1825 | WORM |\n"
        "| Log retention (days) | 90 | logs |\n"
        "| Deletion schedule | Automated via Azure lifecycle | tier-to-cool |\n",
        encoding="utf-8",
    )
    return md


# --------------------------------------------------------------------------- #
# AC1: reads the file — output changes when the register row changes          #
# --------------------------------------------------------------------------- #

def test_output_reflects_register_vendor_name(tmp_path):
    reg = _write_register(tmp_path, last_reviewed="2026-03-15", vendor1_name="ACME Cloud Ltd")
    report, _ = cdv.build_report(reg, today=FRESH_TODAY)
    assert report["processors"][0]["name"] == "ACME Cloud Ltd"


def test_output_changes_when_status_edited(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    reg_a = _write_register(tmp_path / "a", last_reviewed="2026-03-15", vendor1_status="ACTIVE")
    reg_b = _write_register(tmp_path / "b", last_reviewed="2026-03-15", vendor1_status="EXPIRED")
    a, _ = cdv.build_report(reg_a, today=FRESH_TODAY)
    b, _ = cdv.build_report(reg_b, today=FRESH_TODAY)
    assert a["processors"][0]["dpa_status"] == "ACTIVE"
    assert b["processors"][0]["dpa_status"] == "EXPIRED"
    assert a["processors"][0]["dpa_status"] != b["processors"][0]["dpa_status"]


def test_real_register_yields_ten_processors():
    report, _ = cdv.build_report(REAL_REGISTER, today=FRESH_TODAY)
    assert len(report["processors"]) == 10
    assert report["processors"][0]["name"].startswith("GitHub")
    assert report["processors"][9]["name"].startswith("Truffle")


# --------------------------------------------------------------------------- #
# AC2: freshness is BLOCKING — stale FAILs with the day count, fresh PASSes   #
# --------------------------------------------------------------------------- #

def test_stale_register_fails_with_daycount(tmp_path):
    reg = _write_register(tmp_path, last_reviewed="2026-03-15")
    report, code = cdv.build_report(reg, today=STALE_TODAY)  # 108 days old
    assert report["status"] == "FAIL"
    assert report["freshness"]["tier"] == "BLOCKING"
    assert report["freshness"]["measured"] == 108
    assert "108 days ago" in report["freshness"]["detail"]
    assert code == 1  # BLOCKING FAIL -> non-zero exit


def test_fresh_register_passes(tmp_path):
    reg = _write_register(tmp_path, last_reviewed="2026-03-15")
    report, code = cdv.build_report(reg, today=FRESH_TODAY)  # 78 days old
    assert report["status"] == "PASS"
    assert report["freshness"]["measured"] == 78
    assert report["freshness"]["threshold"] == 92
    assert code == 0


def test_boundary_92_days_passes(tmp_path):
    # exactly 92 days -> still within the quarterly window (<=92).
    reg = _write_register(tmp_path, last_reviewed="2026-03-16")
    report, code = cdv.build_report(reg, today=date(2026, 6, 16))
    assert report["freshness"]["measured"] == 92
    assert report["status"] == "PASS"
    assert code == 0


def test_boundary_93_days_fails(tmp_path):
    reg = _write_register(tmp_path, last_reviewed="2026-03-15")
    report, code = cdv.build_report(reg, today=date(2026, 6, 16))
    assert report["freshness"]["measured"] == 93
    assert report["status"] == "FAIL"
    assert code == 1


def test_missing_last_reviewed_is_indeterminate(tmp_path):
    md = tmp_path / "vendor-risk-register.md"
    md.write_text(
        "# Vendor Risk Register\n\n## Vendor Inventory\n\n"
        "| Vendor | DPA Status |\n|--------|------------|\n| GitHub | ACTIVE |\n",
        encoding="utf-8",
    )
    report, code = cdv.build_report(md, today=FRESH_TODAY)
    assert report["status"] == "INDETERMINATE"
    assert report["freshness"]["measured"] is None
    assert code == 2  # BLOCKING INDETERMINATE -> exit 2


def test_missing_register_is_indeterminate(tmp_path):
    report, code = cdv.build_report(tmp_path / "nope.md", today=FRESH_TODAY)
    assert report["status"] == "INDETERMINATE"
    assert report["processors"] == []
    assert code == 2


# --------------------------------------------------------------------------- #
# Tiering correctness: per-vendor statuses are EVIDENCE-ONLY                   #
# --------------------------------------------------------------------------- #

def test_per_vendor_statuses_are_evidence_only(tmp_path):
    reg = _write_register(tmp_path, last_reviewed="2026-03-15")
    report, _ = cdv.build_report(reg, today=FRESH_TODAY)
    for p in report["processors"]:
        assert p["envelope"]["tier"] == lc.Tier.EVIDENCE_ONLY


def test_top_level_envelope_is_blocking_freshness(tmp_path):
    reg = _write_register(tmp_path, last_reviewed="2026-03-15")
    report, _ = cdv.build_report(reg, today=FRESH_TODAY)
    assert report["envelope"]["tier"] == lc.Tier.BLOCKING
    assert report["envelope"] is report["freshness"]


# --------------------------------------------------------------------------- #
# Output schema: fields the HTML report consumes are preserved                #
# --------------------------------------------------------------------------- #

def test_processor_record_has_html_report_fields(tmp_path):
    reg = _write_register(tmp_path, last_reviewed="2026-03-15")
    report, _ = cdv.build_report(reg, today=FRESH_TODAY)
    p = report["processors"][0]
    for field in ("name", "service", "dpa_status", "data_location", "justification"):
        assert field in p


def test_retention_policy_sourced_from_register(tmp_path):
    reg = _write_register(tmp_path, last_reviewed="2026-03-15")
    report, _ = cdv.build_report(reg, today=FRESH_TODAY)
    r = report["retention_policy"]
    assert r["evidence_pack_retention_days"] == 1825
    assert r["log_retention_days"] == 90
    assert "Azure" in r["deletion_schedule"]


def test_real_register_retention_is_read():
    report, _ = cdv.build_report(REAL_REGISTER, today=FRESH_TODAY)
    assert report["retention_policy"]["evidence_pack_retention_days"] == 1825


# --------------------------------------------------------------------------- #
# AC3: no hardcoded vendor list remains in check-dpa.sh                       #
# --------------------------------------------------------------------------- #

def test_check_dpa_sh_has_no_hardcoded_vendor_list():
    text = CHECK_DPA_SH.read_text(encoding="utf-8")
    # The lie this task removes: a static heredoc enumerating vendors + dpa_status.
    # Strip comment lines first so explanatory prose describing the removed lie does
    # not trip the check; the assertion targets emitted (non-comment) content.
    code = "\n".join(
        ln for ln in text.splitlines() if not ln.lstrip().startswith("#")
    )
    for vendor in ("GitHub", "Microsoft Azure", "Sigstore", "TruffleHog", "OWASP"):
        assert vendor not in code, f"hardcoded vendor {vendor!r} still present in check-dpa.sh"
    assert '"dpa_status"' not in code  # no inline JSON status literals
    assert "<<EOF" not in code  # no heredoc emitting JSON


def test_check_dpa_sh_delegates_to_validator():
    text = CHECK_DPA_SH.read_text(encoding="utf-8")
    assert "check_dpa_validator.py" in text


# --------------------------------------------------------------------------- #
# End-to-end: the shell entrypoint emits valid JSON with the expected shape   #
# --------------------------------------------------------------------------- #

def test_shell_entrypoint_emits_valid_json():
    proc = subprocess.run(
        ["bash", str(CHECK_DPA_SH)],
        capture_output=True,
        text=True,
        cwd=str(PIPELINE_ROOT),
    )
    # Exit code is the BLOCKING freshness result (0/1/2); stdout must be valid JSON
    # with the consumed shape regardless of pass/fail.
    assert proc.returncode in (0, 1, 2)
    data = json.loads(proc.stdout)
    assert isinstance(data["processors"], list)
    assert len(data["processors"]) == 10
    assert data["status"] in ("PASS", "FAIL", "INDETERMINATE")
    assert data["envelope"]["tier"] == "BLOCKING"


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

    for name, fn in fns:
        params = list(inspect.signature(fn).parameters)
        try:
            if "tmp_path" in params:
                with tempfile.TemporaryDirectory() as d:
                    fn(tmp_path=Path(d))
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
