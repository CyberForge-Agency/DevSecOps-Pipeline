"""Unit tests for the T-15 nis2_21_2_d supply-chain content validator (BLOCKING).

Replaces a file-presence check over a renamed SBOM copy. Two halves must both
hold for PASS: (a) the SBOM is schema-valid CycloneDX with >=1 component, and
(b) the attestation binds that SBOM to the deployed digest.

Cases (cosign is NOT installed here, so the binding falls back to the sealed,
digest-bound verification log; the live path is skipped via NIS2_SKIP_LIVE_COSIGN):
  * valid SBOM + digest-bound sealed attestation log -> PASS;
  * a malformed SBOM (0 components) -> FAIL (a measured FAIL wins over INDETERMINATE);
  * wrong bomFormat -> FAIL;
  * valid SBOM but NO attestation evidence -> INDETERMINATE (never a silent PASS);
  * no SBOM at all -> INDETERMINATE.

These FAIL if the schema half stops checking components/bomFormat, or the binding
half ever returns PASS without a digest-bound proof.

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
from scripts.validators import nis2_21_2_d as nd  # noqa: E402

_DIGEST = "sha256:" + "b" * 64
_REKOR_MARKER = "REKOR_SBOM_ATTESTATION_INCLUSION_VERIFIED"


def _evidence(tmp_path: Path, *, components: int = 2, bom_format: str = "CycloneDX",
              spec: str = "1.5", with_log: bool = True, with_pipeline: bool = True) -> Path:
    d = tmp_path / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    sbom = {"bomFormat": bom_format, "specVersion": spec, "version": 1,
            "components": [{"name": f"c{i}"} for i in range(components)]}
    (d / "sbom.cyclonedx.json").write_text(json.dumps(sbom), encoding="utf-8")
    if with_pipeline:
        (d / "pipeline-run.json").write_text(
            json.dumps({"image": {"uri": "ghcr.io/demo/app", "digest": _DIGEST}}),
            encoding="utf-8",
        )
    if with_log:
        # The sealed proof: success marker + the digest cross-checked.
        (d / "cosign-attestation-verification.log").write_text(
            f"verify-attestation for ghcr.io/demo/app@{_DIGEST}\n{_REKOR_MARKER}\n",
            encoding="utf-8",
        )
    return d


def _skip_live():
    os.environ["NIS2_SKIP_LIVE_COSIGN"] = "1"


def _restore_live():
    os.environ.pop("NIS2_SKIP_LIVE_COSIGN", None)


# --------------------------------------------------------------------------- #
# PASS: valid SBOM + digest-bound sealed log                                   #
# --------------------------------------------------------------------------- #

def test_valid_sbom_and_bound_log_passes(tmp_path):
    _skip_live()
    try:
        env = nd.check(_evidence(tmp_path))
    finally:
        _restore_live()
    assert env["status"] == lc.Status.PASS
    assert env["tier"] == lc.Tier.BLOCKING
    assert env["measured"]["components"] == 2
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


# --------------------------------------------------------------------------- #
# FAIL: schema half                                                            #
# --------------------------------------------------------------------------- #

def test_zero_components_fails(tmp_path):
    _skip_live()
    try:
        env = nd.check(_evidence(tmp_path, components=0))
    finally:
        _restore_live()
    assert env["status"] == lc.Status.FAIL
    assert "components empty" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


def test_wrong_bom_format_fails(tmp_path):
    _skip_live()
    try:
        env = nd.check(_evidence(tmp_path, bom_format="SPDX"))
    finally:
        _restore_live()
    assert env["status"] == lc.Status.FAIL
    assert "bomFormat" in env["detail"]


# --------------------------------------------------------------------------- #
# INDETERMINATE: binding unmeasurable / no SBOM                                #
# --------------------------------------------------------------------------- #

def test_valid_sbom_no_attestation_is_indeterminate(tmp_path):
    _skip_live()
    try:
        env = nd.check(_evidence(tmp_path, with_log=False))
    finally:
        _restore_live()
    assert env["status"] == lc.Status.INDETERMINATE
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


def test_no_sbom_is_indeterminate(tmp_path):
    _skip_live()
    empty = tmp_path / "empty"
    empty.mkdir()
    try:
        env = nd.check(empty)
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
