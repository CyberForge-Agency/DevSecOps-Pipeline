"""Unit tests for the T-14 dora_16_1_c content validator (BLOCKING).

The DORA Art.16.1.c row replaced a file-presence check over a renamed ``cp`` of
the SCA results. This proves the three-part content assertion:

  (a) severity_filter includes CRITICAL+HIGH;
  (b) .trivyignore has 0 unjustified/expired suppressions (shared T-02 linter);
  (c) dependency-review.json is structurally a Trivy report (has Results[]).

Cases:
  * all three hold -> PASS (BLOCKING);
  * severity_filter missing HIGH -> FAIL;
  * dependency-review is not a Trivy report -> FAIL;
  * an unjustified .trivyignore suppression -> FAIL;
  * no SCA evidence at all -> INDETERMINATE (never a silent PASS).

Fixtures are built in tmp_path; the .trivyignore is pointed at via TRIVYIGNORE_PATH
(restored after each test). These FAIL if any of the three sub-checks is dropped.

Runs under pytest AND standalone.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    import pytest
except ImportError:
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
from scripts.validators import dora_16_1_c as dora  # noqa: E402

# A real Trivy report shape (has a Results array) — distinguishes a real report
# from a bare copy of something else.
_TRIVY_REPORT = {"SchemaVersion": 2, "Results": [{"Target": "app", "Vulnerabilities": []}]}


def _evidence_dir(tmp_path: Path, *, sev: str = "CRITICAL,HIGH",
                  review: dict | None = None) -> Path:
    d = tmp_path / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / "trivy-sca-summary.json").write_text(
        json.dumps({"severity_filter": sev, "tool_version": "trivy 0.71.0"}),
        encoding="utf-8",
    )
    (d / "dependency-review.json").write_text(
        json.dumps(review if review is not None else _TRIVY_REPORT),
        encoding="utf-8",
    )
    return d


def _set_trivyignore(tmp_path: Path, body: str) -> Path:
    p = tmp_path / ".trivyignore"
    p.write_text(body, encoding="utf-8")
    os.environ["TRIVYIGNORE_PATH"] = str(p)
    return p


def _clear_trivyignore() -> None:
    os.environ.pop("TRIVYIGNORE_PATH", None)


# An empty (no suppressions) .trivyignore is clean -> 0 unjustified.
_CLEAN_TI = "# no suppressions\n"
# An unjustified suppression (no preceding VEX comment) -> 1 unjustified.
_DIRTY_TI = "CVE-2099-0001\n"


# --------------------------------------------------------------------------- #
# PASS: all three sub-checks hold                                              #
# --------------------------------------------------------------------------- #

def test_all_three_pass(tmp_path):
    _set_trivyignore(tmp_path, _CLEAN_TI)
    try:
        env = dora.check(_evidence_dir(tmp_path))
    finally:
        _clear_trivyignore()
    assert env["status"] == lc.Status.PASS
    assert env["tier"] == lc.Tier.BLOCKING
    assert env["measured"]["unjustified_suppressions"] == 0
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


# --------------------------------------------------------------------------- #
# FAIL paths                                                                   #
# --------------------------------------------------------------------------- #

def test_severity_filter_missing_high_fails(tmp_path):
    _set_trivyignore(tmp_path, _CLEAN_TI)
    try:
        env = dora.check(_evidence_dir(tmp_path, sev="CRITICAL"))
    finally:
        _clear_trivyignore()
    assert env["status"] == lc.Status.FAIL
    assert "HIGH" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


def test_dependency_review_not_a_report_fails(tmp_path):
    _set_trivyignore(tmp_path, _CLEAN_TI)
    try:
        # A bare copy of something that is NOT a Trivy report (no Results array).
        env = dora.check(_evidence_dir(tmp_path, review={"some": "other-json"}))
    finally:
        _clear_trivyignore()
    assert env["status"] == lc.Status.FAIL
    assert "Trivy report" in env["detail"]


def test_unjustified_suppression_fails(tmp_path):
    _set_trivyignore(tmp_path, _DIRTY_TI)
    try:
        env = dora.check(_evidence_dir(tmp_path))
    finally:
        _clear_trivyignore()
    assert env["status"] == lc.Status.FAIL
    assert env["measured"]["unjustified_suppressions"] == 1
    assert "unjustified" in env["detail"]


# --------------------------------------------------------------------------- #
# INDETERMINATE: no measurable SCA evidence                                    #
# --------------------------------------------------------------------------- #

def test_no_sca_evidence_is_indeterminate(tmp_path):
    _set_trivyignore(tmp_path, _CLEAN_TI)
    empty = tmp_path / "empty-evidence"
    empty.mkdir()
    try:
        env = dora.check(empty)
    finally:
        _clear_trivyignore()
    assert env["status"] == lc.Status.INDETERMINATE
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


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
