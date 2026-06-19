"""Unit tests for the T-116 vex validator (BLOCKING).

Proves the core OpenVEX justification rule + product binding on:
  * a valid OpenVEX doc (every non-affected statement justified + digest-bound) -> PASS;
  * a not_affected statement with NO justification -> FAIL;
  * a justification that is not a CISA/OpenVEX label -> FAIL;
  * a statement bound to no image digest -> FAIL;
  * a missing OpenVEX @context (bad shape) -> FAIL;
  * an empty {} document -> INDETERMINATE (never a silent PASS).

Fixtures are minimal OpenVEX docs written to tmp_path. These FAIL if the
justification rule, CISA-label validity, or product-binding check regress.

Runs under pytest AND standalone.
"""

from __future__ import annotations

import copy
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
from scripts.validators import vex  # noqa: E402

_DIGEST = "sha256:" + "a" * 64
_PRODUCT = {
    "@id": f"pkg:oci/demo/app@{_DIGEST}",
    "hashes": {"sha256": "a" * 64},
}

_VALID_DOC = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://example/vex/1",
    "author": "Security Team",
    "timestamp": "2026-06-17T00:00:00Z",
    "version": 1,
    "statements": [
        {
            "vulnerability": {"name": "CVE-2026-0001"},
            "products": [_PRODUCT],
            "status": "not_affected",
            "justification": "component_not_present",
        },
        {
            "vulnerability": {"name": "CVE-2026-0002"},
            "products": [_PRODUCT],
            "status": "under_investigation",
        },
    ],
}


def _write(tmp_path: Path, doc) -> Path:
    p = tmp_path / "vex.openvex.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# PASS                                                                         #
# --------------------------------------------------------------------------- #

def test_valid_doc_passes(tmp_path):
    env = vex.validate(_write(tmp_path, _VALID_DOC))
    assert env["status"] == lc.Status.PASS
    assert env["tier"] == lc.Tier.BLOCKING
    assert env["measured"]["under_investigation"] == 1
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


# --------------------------------------------------------------------------- #
# FAIL                                                                         #
# --------------------------------------------------------------------------- #

def test_not_affected_without_justification_fails(tmp_path):
    doc = copy.deepcopy(_VALID_DOC)
    doc["statements"][0].pop("justification")
    env = vex.validate(_write(tmp_path, doc))
    assert env["status"] == lc.Status.FAIL
    assert "no justification" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


def test_invalid_cisa_label_fails(tmp_path):
    doc = copy.deepcopy(_VALID_DOC)
    doc["statements"][0]["justification"] = "totally_made_up_label"
    env = vex.validate(_write(tmp_path, doc))
    assert env["status"] == lc.Status.FAIL
    assert "CISA/OpenVEX label" in env["detail"]


def test_unbound_product_fails(tmp_path):
    doc = copy.deepcopy(_VALID_DOC)
    # A product with no digest hash and no digest-pinned purl.
    doc["statements"][0]["products"] = [{"@id": "pkg:oci/demo/app:latest"}]
    env = vex.validate(_write(tmp_path, doc))
    assert env["status"] == lc.Status.FAIL
    assert "image digest" in env["detail"]


def test_missing_context_fails(tmp_path):
    doc = copy.deepcopy(_VALID_DOC)
    doc.pop("@context")
    env = vex.validate(_write(tmp_path, doc))
    assert env["status"] == lc.Status.FAIL
    assert "@context" in env["detail"]


# --------------------------------------------------------------------------- #
# INDETERMINATE                                                                #
# --------------------------------------------------------------------------- #

def test_empty_object_is_indeterminate(tmp_path):
    env = vex.validate(_write(tmp_path, {}))
    assert env["status"] == lc.Status.INDETERMINATE
    assert lc.exit_code_for(env["status"], env["tier"]) == 2


def test_missing_file_is_indeterminate(tmp_path):
    env = vex.validate(tmp_path / "nope.json")
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
