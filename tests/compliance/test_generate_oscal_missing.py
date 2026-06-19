"""T-82: a MISSING control maps to OSCAL finding state not-satisfied.

generate-oscal.py normalises a compliance-matrix status of ``MISSING`` (the
compliance-matrix.sh emitter's "evidence file is absent") to ``FAIL`` in
``load_controls`` (generate-oscal.py:93-106), and ``build_oscal`` then emits an
OSCAL finding whose ``target.status.state`` is ``not-satisfied`` (generate-oscal.py
:191-204). This proves a missing control is NEVER silently dropped or assessed as
satisfied — it surfaces as an auditor-visible not-satisfied finding.

Cases:
  * a control with status MISSING -> finding with state "not-satisfied";
  * a PASS control produces an observation but NO finding;
  * the not-satisfied finding's target-id is the control id (traceable);
  * other absent-evidence synonyms (ABSENT/FAILED) also map to not-satisfied.

The script is path-imported (hyphenated filename).

Runs under pytest AND standalone.
"""

from __future__ import annotations

import importlib.util
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

_OSCAL_PATH = PIPELINE_ROOT / "scripts" / "generate-oscal.py"
_spec = importlib.util.spec_from_file_location("generate_oscal", _OSCAL_PATH)
assert _spec and _spec.loader
go = importlib.util.module_from_spec(_spec)
sys.modules["generate_oscal"] = go
_spec.loader.exec_module(go)

GENERATED_AT = "2026-06-17T00:00:00Z"


def _findings(doc: dict) -> list:
    return doc["assessment-results"]["results"][0].get("findings", [])


def _build(matrix: object) -> dict:
    controls = go.load_controls(matrix)
    return go.build_oscal(controls, manifest=None, generated_at=GENERATED_AT)


# --------------------------------------------------------------------------- #
# MISSING -> not-satisfied                                                     #
# --------------------------------------------------------------------------- #

def test_missing_control_maps_to_not_satisfied():
    matrix = {"controls": [
        {"id": "DORA Art.16.1.c", "description": "Updated systems",
         "status": "MISSING", "evidence": "dependency-review.json"},
    ]}
    doc = _build(matrix)
    findings = _findings(doc)
    assert len(findings) == 1
    assert findings[0]["target"]["status"]["state"] == "not-satisfied"


def test_missing_control_finding_is_traceable_to_control_id():
    matrix = {"controls": [
        {"id": "NIS2 Art.21.2.d", "description": "Supply chain",
         "status": "MISSING", "evidence": "sbom.cyclonedx.json"},
    ]}
    finding = _findings(_build(matrix))[0]
    assert finding["target"]["target-id"] == "NIS2 Art.21.2.d"
    # The finding cross-links to its observation for auditor navigation.
    assert finding["related-observations"][0]["observation-uuid"]


# --------------------------------------------------------------------------- #
# PASS -> observation, no finding                                              #
# --------------------------------------------------------------------------- #

def test_pass_control_has_no_finding():
    matrix = {"controls": [
        {"id": "CC6.1", "description": "Logical access", "status": "PASS",
         "evidence": "scan.sarif"},
    ]}
    doc = _build(matrix)
    assert _findings(doc) == []
    obs = doc["assessment-results"]["results"][0]["observations"]
    assert len(obs) == 1
    # The observation records the assessed status as a prop.
    props = {p["name"]: p["value"] for p in obs[0]["props"]}
    assert props["assessment-status"] == "PASS"


# --------------------------------------------------------------------------- #
# Other absent-evidence synonyms also become not-satisfied                     #
# --------------------------------------------------------------------------- #

def test_absent_and_failed_synonyms_map_to_not_satisfied():
    matrix = {"controls": [
        {"id": "X.1", "description": "absent", "status": "ABSENT", "evidence": ""},
        {"id": "X.2", "description": "failed", "status": "FAILED", "evidence": ""},
    ]}
    findings = _findings(_build(matrix))
    states = {f["target"]["target-id"]: f["target"]["status"]["state"] for f in findings}
    assert states == {"X.1": "not-satisfied", "X.2": "not-satisfied"}


def test_load_controls_maps_missing_to_fail():
    # Unit-level: the normaliser itself maps MISSING -> FAIL (the keystone hop).
    controls = go.load_controls({"controls": [
        {"id": "Y.1", "status": "MISSING", "evidence": ""}]})
    assert controls[0]["status"] == "FAIL"


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
                with tempfile.TemporaryDirectory() as dd:
                    fn(Path(dd))
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
