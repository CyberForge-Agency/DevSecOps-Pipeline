"""Unit tests for the T-16 nis2_21_2_h cryptography content validator (BLOCKING).

Replaces a file-presence + loose log-grep with a digest-bound verification:
the image signature must verify against ``<uri>@<digest>`` with the tightened
identity (live cosign, else the sealed digest-bound log).

Cases (cosign is NOT installed here, so the live path is skipped via
NIS2_SKIP_LIVE_COSIGN and the binding falls back to the sealed log):
  * sealed verification log records success + the digest -> PASS;
  * the log records success but for a DIFFERENT digest -> FAIL (real, actionable);
  * verifying a TAG (no sha256 digest) is rejected -> INDETERMINATE before cosign;
  * no digest + no usable log -> INDETERMINATE (never a silent PASS).

These FAIL if the digest-binding requirement, the tag-rejection guard, or the
success-marker check regress.

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
from scripts.validators import nis2_21_2_h as nh  # noqa: E402

_DIGEST = "sha256:" + "c" * 64
_OTHER_DIGEST = "sha256:" + "d" * 64


def _evidence(tmp_path: Path, *, digest: str | None = _DIGEST,
              log_digest: str | None = _DIGEST, success: bool = True,
              with_log: bool = True) -> Path:
    d = tmp_path / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    if digest is not None:
        (d / "pipeline-run.json").write_text(
            json.dumps({"image": {"uri": "ghcr.io/demo/app", "digest": digest}}),
            encoding="utf-8",
        )
    if with_log:
        marker = "Verified OK\ntlog entry verified" if success else "verification failed"
        ref = f"ghcr.io/demo/app@{log_digest}" if log_digest else "ghcr.io/demo/app"
        (d / "cosign-verification.log").write_text(
            f"{marker}\nverified {ref}\n", encoding="utf-8",
        )
    return d


def _skip_live():
    os.environ["NIS2_SKIP_LIVE_COSIGN"] = "1"


def _restore_live():
    os.environ.pop("NIS2_SKIP_LIVE_COSIGN", None)


# --------------------------------------------------------------------------- #
# INDETERMINATE: sealed log records success + digest, but a text-log substring  #
# is not independently re-verifiable cryptographic proof (A08-2). Offline (no   #
# live cosign), a logged "Verified OK" can only be INDETERMINATE for this       #
# BLOCKING row — never a silent PASS; affirmative proof needs the LIVE re-verify #
# or a verifiable bundle. (A logged FAILURE is still a FAIL — see below.)        #
# --------------------------------------------------------------------------- #

def test_bound_success_log_is_indeterminate_offline(tmp_path):
    _skip_live()
    try:
        env = nh.check(_evidence(tmp_path))
    finally:
        _restore_live()
    assert env["status"] == lc.Status.INDETERMINATE
    assert env["tier"] == lc.Tier.BLOCKING
    assert lc.exit_code_for(env["status"], env["tier"]) == 2
    assert "not independently re-verifiable" in env["detail"]


# --------------------------------------------------------------------------- #
# FAIL: log success but bound to a DIFFERENT digest                           #
# --------------------------------------------------------------------------- #

def test_log_for_different_digest_fails(tmp_path):
    _skip_live()
    try:
        env = nh.check(_evidence(tmp_path, digest=_DIGEST, log_digest=_OTHER_DIGEST))
    finally:
        _restore_live()
    assert env["status"] == lc.Status.FAIL
    assert "NOT found in log" in env["detail"] or "different image" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


# --------------------------------------------------------------------------- #
# INDETERMINATE: tag rejection / nothing measurable                           #
# --------------------------------------------------------------------------- #

def test_tag_instead_of_digest_rejected(tmp_path):
    # A non-sha256 "digest" means we'd be verifying a tag -> rejected before cosign.
    _skip_live()
    try:
        env = nh.check(_evidence(tmp_path, digest="latest", log_digest=None))
    finally:
        _restore_live()
    assert env["status"] == lc.Status.INDETERMINATE
    assert "not a sha256 digest" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


def test_no_digest_no_log_is_indeterminate(tmp_path):
    _skip_live()
    empty = tmp_path / "empty"
    empty.mkdir()
    try:
        env = nh.check(empty)
    finally:
        _restore_live()
    assert env["status"] == lc.Status.INDETERMINATE


def test_failed_marker_log_is_indeterminate(tmp_path):
    # A log with no success marker is not a usable proof -> INDETERMINATE.
    _skip_live()
    try:
        env = nh.check(_evidence(tmp_path, success=False))
    finally:
        _restore_live()
    assert env["status"] == lc.Status.INDETERMINATE


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
