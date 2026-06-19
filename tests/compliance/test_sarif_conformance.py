"""Unit tests for the T-125 sarif_conformance validator (BLOCKING).

Exercises the validator's real status + T-33 envelope on:
  * a conformant SARIF 2.1.0 doc ($schema + runs[].tool.driver.name) -> PASS;
  * version 2.0.0 -> FAIL (known-bad format is deterministic);
  * SARIF 2.1.0 with structure OK but no $schema URI -> FAIL (conformance gap);
  * a run missing tool.driver.name -> FAIL;
  * Trivy native JSON (SchemaVersion/Results, not version/runs) -> INDETERMINATE
    reported honestly as not-SARIF, NEVER a fake pass;
  * a non-object top-level -> INDETERMINATE.

These FAIL if the version gate, the $schema requirement, the structural
tool.driver.name check, or the honest not-SARIF reporting regress.

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

# sarif_conformance imports libcompliance as a sibling (it inserts its own dir);
# import it by package path so coverage attributes it correctly.
from scripts.validators import libcompliance as lc  # noqa: E402
from scripts.validators import sarif_conformance as sc  # noqa: E402

_GOOD_SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": []}}, "results": []}],
}


# --------------------------------------------------------------------------- #
# PASS                                                                         #
# --------------------------------------------------------------------------- #

def test_conformant_sarif_passes():
    env = sc.assess(_GOOD_SARIF, stage="codeql")
    assert env["status"] == lc.Status.PASS
    assert env["tier"] == lc.Tier.BLOCKING
    assert env["measured"]["version"] == "2.1.0"
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


# --------------------------------------------------------------------------- #
# FAIL                                                                         #
# --------------------------------------------------------------------------- #

def test_wrong_version_fails():
    doc = dict(_GOOD_SARIF, version="2.0.0")
    env = sc.assess(doc, stage="codeql")
    assert env["status"] == lc.Status.FAIL
    assert "2.0.0" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


def test_missing_schema_uri_fails():
    doc = {k: v for k, v in _GOOD_SARIF.items() if k != "$schema"}
    env = sc.assess(doc, stage="codeql")
    assert env["status"] == lc.Status.FAIL
    assert "$schema" in env["detail"]


def test_missing_driver_name_fails():
    doc = {
        "version": "2.1.0",
        "$schema": "https://example/sarif.json",
        "runs": [{"tool": {"driver": {}}}],  # no driver.name
    }
    env = sc.assess(doc, stage="codeql")
    assert env["status"] == lc.Status.FAIL
    assert "driver.name" in env["detail"]


# --------------------------------------------------------------------------- #
# INDETERMINATE: honest not-SARIF reporting (never a fake pass)                #
# --------------------------------------------------------------------------- #

def test_trivy_native_json_is_indeterminate_not_sarif():
    trivy = {"SchemaVersion": 2, "Results": [{"Target": "app"}]}
    env = sc.assess(trivy, stage="trivy-sca")
    assert env["status"] == lc.Status.INDETERMINATE
    assert env["measured"]["format"] == "trivy-native-json"
    # EVIDENCE/BLOCKING tier but INDETERMINATE -> never PASS, never mislabeled.
    assert env["status"] != lc.Status.PASS


def test_non_object_is_indeterminate():
    env = sc.assess(["not", "an", "object"], stage=None)
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
