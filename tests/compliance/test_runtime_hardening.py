"""Unit tests for the T-118 runtime_hardening validator (BLOCKING).

Exercises the validator's real exit code + T-33 envelope on:
  * a non-root Dockerfile + clean ACA Terraform -> PASS (non-root invariant MET);
  * a Dockerfile with ``USER root`` / ``USER 0`` -> FAIL (the BLOCKING invariant);
  * a Dockerfile with no USER directive -> FAIL;
  * privileged=true declared in the IaC -> FAIL;
  * a missing Dockerfile -> INDETERMINATE (never a silent PASS);
  * platform-not-expressible controls reported INDETERMINATE, not fabricated.

Fixtures are written into tmp_path so the test never touches the repo Dockerfile.
These FAIL if the non-root gate or the IaC privileged/host guards regress.

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
from scripts.validators import runtime_hardening as rh  # noqa: E402

_CLEAN_TF = """
resource "azurerm_container_app" "app" {
  identity {
    type = "SystemAssigned"
  }
  template {
    container {
      cpu    = 0.5
      memory = "1Gi"
    }
    max_replicas = 3
  }
  ingress {
    external_enabled = false
    target_port      = 3000
  }
}
"""

_PRIVILEGED_TF = _CLEAN_TF + "\nprivileged = true\n"


def _dockerfile(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "Dockerfile"
    p.write_text(body, encoding="utf-8")
    return p


def _tf(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "main.tf"
    p.write_text(body, encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# PASS: non-root USER + clean IaC                                              #
# --------------------------------------------------------------------------- #

def test_non_root_passes(tmp_path):
    df = _dockerfile(tmp_path, "FROM scratch\nUSER 65532\n")
    tf = _tf(tmp_path, _CLEAN_TF)
    env = rh.validate(df, tf)
    assert env["status"] == lc.Status.PASS
    assert env["tier"] == lc.Tier.BLOCKING
    assert env["measured"]["runs_as_non_root"] is True
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


def test_platform_controls_indeterminate_not_fabricated(tmp_path):
    df = _dockerfile(tmp_path, "FROM scratch\nUSER 65532\n")
    tf = _tf(tmp_path, _CLEAN_TF)
    env = rh.validate(df, tf)
    controls = env["measured"]["controls"]
    # seccomp / read-only rootfs are not settable on ACA -> reported INDETERMINATE,
    # never claimed MET.
    assert controls["seccomp_runtime_default"] == "INDETERMINATE"
    assert controls["read_only_rootfs"] == "INDETERMINATE"
    assert controls["run_as_non_root"] == "MET"


def test_multistage_last_user_wins(tmp_path):
    # First stage roots, final stage drops privileges -> non-root.
    df = _dockerfile(tmp_path, "FROM build AS b\nUSER root\nFROM scratch\nUSER 65532\n")
    tf = _tf(tmp_path, _CLEAN_TF)
    env = rh.validate(df, tf)
    assert env["status"] == lc.Status.PASS


# --------------------------------------------------------------------------- #
# FAIL: root / no USER / privileged IaC                                        #
# --------------------------------------------------------------------------- #

def test_user_root_fails(tmp_path):
    df = _dockerfile(tmp_path, "FROM scratch\nUSER root\n")
    tf = _tf(tmp_path, _CLEAN_TF)
    env = rh.validate(df, tf)
    assert env["status"] == lc.Status.FAIL
    assert env["tier"] == lc.Tier.BLOCKING
    assert "root" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


def test_user_zero_fails(tmp_path):
    df = _dockerfile(tmp_path, "FROM scratch\nUSER 0\n")
    tf = _tf(tmp_path, _CLEAN_TF)
    env = rh.validate(df, tf)
    assert env["status"] == lc.Status.FAIL


def test_no_user_directive_fails(tmp_path):
    df = _dockerfile(tmp_path, "FROM scratch\nRUN echo hi\n")
    tf = _tf(tmp_path, _CLEAN_TF)
    env = rh.validate(df, tf)
    assert env["status"] == lc.Status.FAIL
    assert env["measured"]["runs_as_non_root"] is False


def test_privileged_iac_fails(tmp_path):
    df = _dockerfile(tmp_path, "FROM scratch\nUSER 65532\n")
    tf = _tf(tmp_path, _PRIVILEGED_TF)
    env = rh.validate(df, tf)
    assert env["status"] == lc.Status.FAIL
    assert "privileged" in env["detail"].lower()


# --------------------------------------------------------------------------- #
# INDETERMINATE: no Dockerfile to measure                                      #
# --------------------------------------------------------------------------- #

def test_missing_dockerfile_is_indeterminate(tmp_path):
    env = rh.validate(tmp_path / "nope.Dockerfile", _tf(tmp_path, _CLEAN_TF))
    assert env["status"] == lc.Status.INDETERMINATE
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


def test_empty_dockerfile_is_indeterminate(tmp_path):
    df = _dockerfile(tmp_path, "")
    env = rh.validate(df, _tf(tmp_path, _CLEAN_TF))
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
