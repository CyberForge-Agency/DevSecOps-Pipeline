"""Unit tests for the T-117 cloud_posture validator.

Exercises the validator's real exit code + T-33 envelope on:
  * a live scan with 0 CRITICAL -> PASS;
  * a live scan with CRITICAL > 0 -> FAIL (BLOCKING when --blocking);
  * a malformed scan (no summary.critical) -> INDETERMINATE;
  * NO scan artifact -> honest EVIDENCE-ONLY 'design-stage' INDETERMINATE
    (never a fabricated CIS PASS), exit 0 because EVIDENCE-ONLY.

These FAIL if the validator ever fabricates a CIS PASS from the static IaC mapping,
or stops blocking on a measured CRITICAL.

Runs under pytest AND standalone.
"""

from __future__ import annotations

import json
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
from scripts.validators import cloud_posture as cp  # noqa: E402


def _scan(tmp_path: Path, payload: dict) -> Path:
    p = tmp_path / "cloud-posture.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _doc(tmp_path: Path, present: bool = True) -> Path:
    p = tmp_path / "cspm-posture.md"
    if present:
        p.write_text("# CSPM design-stage posture\n", encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# PASS: live scan, 0 CRITICAL                                                  #
# --------------------------------------------------------------------------- #

def test_clean_scan_passes(tmp_path):
    scan = _scan(tmp_path, {
        "scanner": "prowler", "scanned_at": "2026-06-17T00:00:00Z",
        "summary": {"critical": 0, "high": 2}, "rows": [{"id": "1"}],
    })
    env = cp.validate(scan, _doc(tmp_path), blocking=True)
    assert env["status"] == lc.Status.PASS
    assert env["tier"] == lc.Tier.BLOCKING
    assert env["measured"]["critical"] == 0
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


# --------------------------------------------------------------------------- #
# FAIL: live scan, CRITICAL present (BLOCKING)                                 #
# --------------------------------------------------------------------------- #

def test_critical_scan_fails_blocking(tmp_path):
    scan = _scan(tmp_path, {
        "scanner": "prowler", "scanned_at": "2026-06-17T00:00:00Z",
        "summary": {"critical": 3}, "rows": [{"id": "1"}],
    })
    env = cp.validate(scan, _doc(tmp_path), blocking=True)
    assert env["status"] == lc.Status.FAIL
    assert env["tier"] == lc.Tier.BLOCKING
    assert env["measured"]["critical"] == 3
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


def test_malformed_scan_is_indeterminate(tmp_path):
    scan = _scan(tmp_path, {"scanner": "prowler"})  # no summary.critical
    env = cp.validate(scan, _doc(tmp_path), blocking=True)
    assert env["status"] == lc.Status.INDETERMINATE


# --------------------------------------------------------------------------- #
# No scan: honest EVIDENCE-ONLY design-stage INDETERMINATE (not a fake PASS)   #
# --------------------------------------------------------------------------- #

def test_no_scan_is_evidence_only_indeterminate(tmp_path):
    missing = tmp_path / "no-such-scan.json"
    env = cp.validate(missing, _doc(tmp_path), blocking=True)
    assert env["status"] == lc.Status.INDETERMINATE
    assert env["tier"] == lc.Tier.EVIDENCE_ONLY  # recorded, non-blocking
    assert env["measured"]["scan_present"] is False
    # EVIDENCE-ONLY tier downgrades the exit code to 0 (recorded, never blocks).
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


def test_no_scan_never_fabricates_pass(tmp_path):
    env = cp.validate(tmp_path / "absent.json", _doc(tmp_path))
    assert env["status"] != lc.Status.PASS
    assert env["measured"]["posture"] == "design-stage / not-yet-scanned"


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
