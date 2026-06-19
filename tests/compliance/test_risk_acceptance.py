"""Unit tests for risk_acceptance (Part J.2 / D.4 / task T-121).

Proves the T-121 acceptance criteria:
* the seeded register (one Active, bounded acceptance) PASSes (exit 0) and
  residual-risk.json lists it under open_risks;
* an acceptance missing the approver, justification, or expiry FAILs (exit 1) —
  spec §8 anti-pattern #5 "unbounded risk acceptances";
* an already-expired Active acceptance FAILs;
* an acceptance whose window exceeds 12 months FAILs;
* an empty register (no data rows) PASSes with open_count 0 ("no exceptions noted");
* a missing register file is INDETERMINATE (exit 2), never a silent FAIL.

Runs under pytest AND standalone
(``python3 tests/compliance/test_risk_acceptance.py``) so the suite is verifiable
even where pytest is not installed — mirrors test_check_incident_register.py.
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
        @staticmethod
        def skip(reason=""):
            raise SystemExit(0)

    pytest = _PytestShim()  # type: ignore[assignment]

# Make the Pipeline root importable so the validator + lib resolve regardless of CWD.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

# The validator module name is a plain identifier, but load by path for symmetry.
_VALIDATOR_PATH = PIPELINE_ROOT / "scripts" / "validators" / "risk_acceptance.py"
_spec = importlib.util.spec_from_file_location("risk_acceptance", _VALIDATOR_PATH)
assert _spec and _spec.loader
ra = importlib.util.module_from_spec(_spec)
sys.modules["risk_acceptance"] = ra
_spec.loader.exec_module(ra)

from scripts.validators import libcompliance as lc  # noqa: E402

SEED_REGISTER = PIPELINE_ROOT / "docs" / "compliance" / "exception-register.md"
TODAY = date(2026, 6, 16)  # deterministic reference for the suite

HEADER = (
    "## Exception Register\n\n"
    "| ID | Vuln ID | Component | Severity | Owner | Approver | Justification "
    "| Compensating Controls | Approved Date | Expiry Date | Status | Issue Link |\n"
    "|----|---------|-----------|----------|-------|----------|---------------"
    "|-----------------------|---------------|-------------|--------|------------|\n"
)


def _row(*, rid="EXC-001", vuln="CVE-2024-1", comp="lodash", sev="Medium",
         owner="Jan Kowalski", approver="Anna Nowak (CTO)", just="patch unavailable",
         comp_ctrl="WAF rule", approved="2026-03-15", expiry="2026-09-15",
         status="Active", link="#42") -> str:
    return (f"| {rid} | {vuln} | {comp} | {sev} | {owner} | {approver} | {just} "
            f"| {comp_ctrl} | {approved} | {expiry} | {status} | {link} |\n")


def _write(tmp_path, body: str) -> Path:
    p = tmp_path / "exception-register.md"
    p.write_text("# Security Exception Register\n\n" + body, encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# Happy path                                                                   #
# --------------------------------------------------------------------------- #

def test_bounded_active_acceptance_passes(tmp_path):
    reg = _write(tmp_path, HEADER + _row())
    env, doc = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.PASS, env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 0
    assert env["measured"]["open_count"] == 1
    assert doc["residual_risk"]["open_accepted_risks"] == 1
    assert doc["residual_risk"]["open_risks"][0]["approver"] == "Anna Nowak (CTO)"
    # Honesty: never asserts officer signature.
    assert doc["residual_risk"]["signed_by_accountable_officer"] is False


def test_seed_register_is_clean():
    """The committed exception-register.md must itself pass the gate (it is shipped)."""
    if not SEED_REGISTER.is_file():
        pytest.skip("seed register not present")
    env, _ = ra.run(SEED_REGISTER, today=TODAY)
    # The seeded EXC-001 expires 2026-09-15 (future relative to TODAY) and is bounded.
    assert env["status"] == lc.Status.PASS, env["detail"]


# --------------------------------------------------------------------------- #
# Unbounded / invalid acceptances -> FAIL (spec §8 anti-pattern #5)           #
# --------------------------------------------------------------------------- #

def test_missing_approver_fails(tmp_path):
    reg = _write(tmp_path, HEADER + _row(approver=""))
    env, _ = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.FAIL
    assert lc.exit_code_for(env["status"], env["tier"]) == 1
    assert "approver" in env["detail"].lower()


def test_missing_justification_fails(tmp_path):
    reg = _write(tmp_path, HEADER + _row(just=""))
    env, _ = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.FAIL
    assert "justification" in env["detail"].lower()


def test_missing_expiry_fails(tmp_path):
    reg = _write(tmp_path, HEADER + _row(expiry=""))
    env, _ = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.FAIL
    assert "expiry" in env["detail"].lower()


def test_already_expired_active_fails(tmp_path):
    reg = _write(tmp_path, HEADER + _row(approved="2025-06-01", expiry="2026-01-01"))
    env, _ = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.FAIL
    assert "passed" in env["detail"].lower()


def test_window_exceeds_12_months_fails(tmp_path):
    reg = _write(tmp_path, HEADER + _row(approved="2026-01-01", expiry="2027-06-01"))
    env, _ = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.FAIL
    assert "12-month" in env["detail"] or "exceeds" in env["detail"]


def test_approver_equals_owner_fails(tmp_path):
    reg = _write(tmp_path, HEADER + _row(owner="Jan Kowalski", approver="Jan Kowalski"))
    env, _ = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.FAIL
    assert "same individual" in env["detail"]


def test_unknown_status_fails(tmp_path):
    reg = _write(tmp_path, HEADER + _row(status="Approved"))
    env, _ = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.FAIL
    assert "status" in env["detail"].lower()


# --------------------------------------------------------------------------- #
# Non-Active rows are not enforced, but are recorded                           #
# --------------------------------------------------------------------------- #

def test_remediated_row_not_enforced(tmp_path):
    # A Remediated row with empty approver/expiry must NOT fail (it is closed).
    reg = _write(tmp_path, HEADER + _row(status="Remediated", approver="", expiry=""))
    env, doc = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.PASS, env["detail"]
    assert doc["residual_risk"]["open_accepted_risks"] == 0
    assert doc["residual_risk"]["status_counts"].get("remediated") == 1


# --------------------------------------------------------------------------- #
# Empty / missing register                                                     #
# --------------------------------------------------------------------------- #

def test_empty_register_passes(tmp_path):
    reg = _write(tmp_path, HEADER)  # header + separator, no data rows
    env, doc = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.PASS, env["detail"]
    assert env["measured"]["open_count"] == 0
    assert doc["residual_risk"]["open_accepted_risks"] == 0
    assert "no open accepted risks" in env["detail"].lower()


def test_missing_register_is_indeterminate(tmp_path):
    reg = tmp_path / "does-not-exist.md"
    env, _ = ra.run(reg, today=TODAY)
    assert env["status"] == lc.Status.INDETERMINATE
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


def test_no_heading_is_indeterminate(tmp_path):
    p = tmp_path / "exception-register.md"
    p.write_text("# Some Doc\n\nNo register table here.\n", encoding="utf-8")
    env, _ = ra.run(p, today=TODAY)
    assert env["status"] == lc.Status.INDETERMINATE


# --------------------------------------------------------------------------- #
# Envelope shape + residual doc serialisability                               #
# --------------------------------------------------------------------------- #

def test_envelope_keys_and_serialisable(tmp_path):
    reg = _write(tmp_path, HEADER + _row())
    env, doc = ra.run(reg, today=TODAY)
    assert set(env) == set(lc.ENVELOPE_KEYS)
    assert env["tier"] == lc.Tier.BLOCKING
    assert isinstance(json.dumps(doc), str)
    assert doc["residual_risk"]["board_tolerance"]["tolerance_document"].endswith(
        "risk-acceptance-process.md"
    )


# --------------------------------------------------------------------------- #
# Standalone runner                                                            #
# --------------------------------------------------------------------------- #

def _run_standalone() -> int:
    import tempfile

    failures: list[str] = []
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for fn in tests:
        try:
            with tempfile.TemporaryDirectory() as td:
                # Inject a tmp_path only for tests that declare it.
                import inspect
                if "tmp_path" in inspect.signature(fn).parameters:
                    fn(Path(td))
                else:
                    fn()
        except SystemExit:
            # pytest.skip shim raises SystemExit(0) -> treat as skipped/pass.
            pass
        except AssertionError as exc:
            failures.append(f"{fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{fn.__name__}: ERROR {exc!r}")
    if failures:
        print("STANDALONE FAIL:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1
    print(f"STANDALONE PASS ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
