"""Unit tests for the T-119 source_control drift validator (BLOCKING).

A committed branch-protection.json is a *desire*, not a *fact*; the honest
assertion compares it against a live export. This proves:

  * no live export -> INDETERMINATE ("drift cannot be evaluated"), never PASS;
  * live matches desired -> PASS;
  * a required status check removed live -> FAIL (named drift);
  * required reviewers dropped below desired -> FAIL;
  * signed commits / force-push hardening drifted to a weaker value -> FAIL.

The drift checks are exercised through the public per-check functions on
normalised configs, plus the ``evaluate`` aggregate for the no-live-export path.
These FAIL if any drift check stops failing closed.

Runs under pytest AND standalone.
"""

from __future__ import annotations

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
from scripts.validators import source_control as sct  # noqa: E402

# The committed desired config (inner "protection" object) and a real CODEOWNERS.
_DESIRED_PROTECTION = {
    "required_pull_request_reviews": {
        "required_approving_review_count": 2,
        "require_code_owner_reviews": True,
    },
    "required_status_checks": {"strict": True, "contexts": ["build", "test"]},
    "required_signatures": True,
    "required_linear_history": True,
    "enforce_admins": True,
    "allow_force_pushes": False,
    "allow_deletions": False,
}

# A live GitHub-API-shaped export that MATCHES the desire.
_LIVE_MATCH = {
    "required_pull_request_reviews": {
        "required_approving_review_count": 2,
        "require_code_owner_reviews": {"enabled": True},
    },
    "required_status_checks": {"strict": {"enabled": True}, "contexts": ["build", "test"]},
    "required_signatures": {"enabled": True},
    "required_linear_history": {"enabled": True},
    "enforce_admins": {"enabled": True},
    "allow_force_pushes": {"enabled": False},
    "allow_deletions": {"enabled": False},
}


def _norm(p: dict) -> dict:
    return sct.normalize_protection(p)


# --------------------------------------------------------------------------- #
# PASS: live matches desired                                                   #
# --------------------------------------------------------------------------- #

def test_matching_status_checks_pass():
    env = sct.check_required_status_checks(_norm(_DESIRED_PROTECTION), _norm(_LIVE_MATCH))
    assert env["status"] == lc.Status.PASS
    assert env["tier"] == lc.Tier.BLOCKING


def test_matching_reviewers_pass():
    env = sct.check_required_reviewers(_norm(_DESIRED_PROTECTION), _norm(_LIVE_MATCH))
    assert env["status"] == lc.Status.PASS


def test_matching_hardening_pass():
    env = sct.check_hardening_flags(_norm(_DESIRED_PROTECTION), _norm(_LIVE_MATCH))
    assert env["status"] == lc.Status.PASS


# --------------------------------------------------------------------------- #
# FAIL: drift                                                                  #
# --------------------------------------------------------------------------- #

def test_removed_status_check_fails():
    live = dict(_LIVE_MATCH)
    live["required_status_checks"] = {"contexts": ["build"]}  # "test" removed
    env = sct.check_required_status_checks(_norm(_DESIRED_PROTECTION), _norm(live))
    assert env["status"] == lc.Status.FAIL
    assert "test" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


def test_fewer_reviewers_fails():
    live = dict(_LIVE_MATCH)
    live["required_pull_request_reviews"] = {
        "required_approving_review_count": 1,
        "require_code_owner_reviews": {"enabled": True},
    }
    env = sct.check_required_reviewers(_norm(_DESIRED_PROTECTION), _norm(live))
    assert env["status"] == lc.Status.FAIL
    assert "1 < desired 2" in env["detail"]


def test_signed_commits_off_fails():
    live = dict(_LIVE_MATCH)
    live["required_signatures"] = {"enabled": False}
    env = sct.check_hardening_flags(_norm(_DESIRED_PROTECTION), _norm(live))
    assert env["status"] == lc.Status.FAIL
    assert "required_signatures" in env["detail"]


def test_force_push_reenabled_fails():
    live = dict(_LIVE_MATCH)
    live["allow_force_pushes"] = {"enabled": True}
    env = sct.check_hardening_flags(_norm(_DESIRED_PROTECTION), _norm(live))
    assert env["status"] == lc.Status.FAIL
    assert "allow_force_pushes" in env["detail"]


# --------------------------------------------------------------------------- #
# INDETERMINATE: no live export -> drift cannot be evaluated (never PASS)      #
# --------------------------------------------------------------------------- #

def test_no_live_export_is_indeterminate(tmp_path):
    codeowners = tmp_path / "CODEOWNERS"
    codeowners.write_text("* @team\n", encoding="utf-8")
    env = sct.evaluate(
        desired=_norm(_DESIRED_PROTECTION), desired_err=None,
        live=None, live_err="no export",
        codeowners=codeowners,
    )
    assert env["status"] == lc.Status.INDETERMINATE
    assert env["tier"] == lc.Tier.BLOCKING
    assert "drift cannot be" in env["detail"]


def test_aggregate_pass_when_all_match(tmp_path):
    codeowners = tmp_path / "CODEOWNERS"
    codeowners.write_text("* @team\n", encoding="utf-8")
    env = sct.evaluate(
        desired=_norm(_DESIRED_PROTECTION), desired_err=None,
        live=_norm(_LIVE_MATCH), live_err=None,
        codeowners=codeowners,
    )
    assert env["status"] == lc.Status.PASS


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
