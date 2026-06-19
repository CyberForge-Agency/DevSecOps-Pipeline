"""Unit tests for the T-31 data-flow YAML reader (generate-data-flow.py).

Proves the schema-validating reader is honest and data-driven:

* it READS docs/governance/data-flow.yaml — editing a stage's ``pii_present``
  changes the rendered JSON (no hardcoded stage list);
* ``pii_present: true`` with an empty/missing ``pii_justification`` is a BLOCKING
  schema FAIL (exit 1) — the RODO Art.30 invariant;
* a missing ``pii_present`` key is a BLOCKING FAIL (the hole T-31 closes);
* an empty/missing input file is INDETERMINATE (exit 2), never a silent PASS;
* the rendered JSON keeps the ``data-flow-diagram.json`` shape
  (``generated_at``/``description``/``stages``) and preserves the shipped record;
* only JSON reaches stdout; the T-33 envelope stays on stderr so the evidence-pack
  redirect (``... > data-flow-diagram.json``) never ingests the envelope.

Runs under pytest (``python3 -m pytest tests/compliance/test_generate_data_flow.py -q``)
AND standalone (``python3 tests/compliance/test_generate_data_flow.py``) — the same
dual-mode contract as test_libcompliance.py, so the suite is verifiable even where
pytest is not installed.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback: minimal pytest surface used below
    class _PytestShim:
        class _Raises:
            def __init__(self, exc):
                self.exc = exc
                self.value = None

            def __enter__(self):
                return self

            def __exit__(self, et, ev, tb):
                if et is None:
                    raise AssertionError(f"DID NOT RAISE {self.exc}")
                self.value = ev
                return issubclass(et, self.exc)

        class _Skipped(BaseException):
            pass

        @staticmethod
        def raises(exc):
            return _PytestShim._Raises(exc)

        @staticmethod
        def skip(reason=""):
            raise _PytestShim._Skipped(reason)

    pytest = _PytestShim()  # type: ignore[assignment]

# ------------------------------------------------------------------------- #
# Module + fixture locations                                                 #
# ------------------------------------------------------------------------- #

PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

SCRIPT_PY = PIPELINE_ROOT / "scripts" / "generate-data-flow.py"
SCRIPT_SH = PIPELINE_ROOT / "scripts" / "generate-data-flow.sh"
SHIPPED_YAML = PIPELINE_ROOT / "docs" / "governance" / "data-flow.yaml"


def _load_module():
    """Import the hyphenated generate-data-flow.py as a module object."""
    spec = importlib.util.spec_from_file_location("generate_data_flow", SCRIPT_PY)
    assert spec and spec.loader, "could not build import spec for generate-data-flow.py"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gdf = _load_module()


def _have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except ImportError:
        return False


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "data-flow.yaml"
    p.write_text(text, encoding="utf-8")
    return p


_MINIMAL_VALID = """\
description: "t"
stages:
  - name: "A"
    location: "loc"
    pii_present: false
    pii_types: []
"""


# ------------------------------------------------------------------------- #
# Schema validation (pure function, no process exit)                        #
# ------------------------------------------------------------------------- #

def test_validate_schema_accepts_minimal_valid():
    doc = {
        "description": "t",
        "stages": [{"name": "A", "location": "loc", "pii_present": False, "pii_types": []}],
    }
    stages = gdf.validate_schema(doc)
    assert len(stages) == 1


def test_pii_true_without_justification_fails():
    doc = {
        "description": "t",
        "stages": [
            {"name": "Leaky", "location": "x", "pii_present": True,
             "pii_types": ["ssn"], "pii_justification": ""}
        ],
    }
    with pytest.raises(gdf.SchemaError) as exc:
        gdf.validate_schema(doc)
    assert any("pii_justification" in p for p in exc.value.problems)


def test_pii_true_with_empty_types_fails():
    doc = {
        "description": "t",
        "stages": [
            {"name": "Leaky", "location": "x", "pii_present": True,
             "pii_types": [], "pii_justification": "because"}
        ],
    }
    with pytest.raises(gdf.SchemaError) as exc:
        gdf.validate_schema(doc)
    assert any("pii_types" in p for p in exc.value.problems)


def test_missing_pii_present_key_fails():
    doc = {"description": "t", "stages": [{"name": "A", "location": "x"}]}
    with pytest.raises(gdf.SchemaError) as exc:
        gdf.validate_schema(doc)
    assert any("pii_present" in p for p in exc.value.problems)


def test_pii_present_must_be_bool_not_string():
    doc = {
        "description": "t",
        "stages": [{"name": "A", "location": "x", "pii_present": "yes"}],
    }
    with pytest.raises(gdf.SchemaError) as exc:
        gdf.validate_schema(doc)
    assert any("pii_present" in p and "boolean" in p for p in exc.value.problems)


def test_empty_stages_fails():
    with pytest.raises(gdf.SchemaError):
        gdf.validate_schema({"description": "t", "stages": []})


def test_missing_description_fails():
    doc = {"stages": [{"name": "A", "location": "x", "pii_present": False, "pii_types": []}]}
    with pytest.raises(gdf.SchemaError) as exc:
        gdf.validate_schema(doc)
    assert any("description" in p for p in exc.value.problems)


def test_duplicate_stage_name_fails():
    doc = {
        "description": "t",
        "stages": [
            {"name": "A", "location": "x", "pii_present": False, "pii_types": []},
            {"name": "A", "location": "y", "pii_present": False, "pii_types": []},
        ],
    }
    with pytest.raises(gdf.SchemaError) as exc:
        gdf.validate_schema(doc)
    assert any("duplicate" in p for p in exc.value.problems)


def test_negative_retention_fails():
    doc = {
        "description": "t",
        "stages": [{"name": "A", "location": "x", "pii_present": False,
                    "pii_types": [], "retention_days": -1}],
    }
    with pytest.raises(gdf.SchemaError) as exc:
        gdf.validate_schema(doc)
    assert any("retention_days" in p for p in exc.value.problems)


def test_data_flows_to_must_be_string_list():
    doc = {
        "description": "t",
        "stages": [{"name": "A", "location": "x", "pii_present": False,
                    "pii_types": [], "data_flows_to": [1, 2]}],
    }
    with pytest.raises(gdf.SchemaError) as exc:
        gdf.validate_schema(doc)
    assert any("data_flows_to" in p for p in exc.value.problems)


# ------------------------------------------------------------------------- #
# render() shape                                                            #
# ------------------------------------------------------------------------- #

def test_render_keeps_diagram_shape():
    doc = {
        "description": "t",
        "stages": [{"name": "A", "location": "loc", "pii_present": False, "pii_types": []}],
    }
    out = gdf.render(doc, doc["stages"])
    assert set(out) == {"generated_at", "description", "stages"}
    assert out["description"] == "t"
    assert out["stages"][0]["name"] == "A"
    # JSON-serialisable.
    assert isinstance(json.dumps(out), str)


# ------------------------------------------------------------------------- #
# load_yaml() error handling                                                #
# ------------------------------------------------------------------------- #

def test_load_yaml_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        gdf.load_yaml(tmp_path / "nope.yaml")


def test_load_yaml_empty_file_raises(tmp_path: Path):
    p = _write(tmp_path, "")
    with pytest.raises(ValueError):
        gdf.load_yaml(p)


# ------------------------------------------------------------------------- #
# main() exit codes (the contract the shell wrapper propagates)            #
# ------------------------------------------------------------------------- #

def test_main_valid_returns_0_and_prints_json(tmp_path: Path, capsys):
    if not _have_yaml():
        pytest.skip("PyYAML not installed")
    p = _write(tmp_path, _MINIMAL_VALID)
    rc = gdf.main(["--input", str(p)])
    captured = capsys.readouterr()
    assert rc == 0
    data = json.loads(captured.out)  # stdout is pure JSON
    assert data["stages"][0]["name"] == "A"
    assert '"status": "PASS"' in captured.err  # envelope on stderr only


def test_main_schema_fail_returns_1_no_json(tmp_path: Path, capsys):
    if not _have_yaml():
        pytest.skip("PyYAML not installed")
    bad = _MINIMAL_VALID.replace(
        'pii_present: false\n    pii_types: []',
        'pii_present: true\n    pii_types: ["ssn"]\n    pii_justification: ""',
    )
    p = _write(tmp_path, bad)
    rc = gdf.main(["--input", str(p)])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out.strip() == ""  # no JSON leaked to stdout on FAIL
    assert '"status": "FAIL"' in captured.err


def test_main_missing_file_returns_2(tmp_path: Path, capsys):
    rc = gdf.main(["--input", str(tmp_path / "nope.yaml")])
    captured = capsys.readouterr()
    assert rc == 2
    assert '"status": "INDETERMINATE"' in captured.err


# ------------------------------------------------------------------------- #
# End-to-end via the shell wrapper (the real evidence-pack invocation)     #
# ------------------------------------------------------------------------- #

def test_shell_wrapper_emits_valid_json_to_stdout():
    if not _have_yaml():
        pytest.skip("PyYAML not installed")
    proc = subprocess.run(
        ["bash", str(SCRIPT_SH)],
        capture_output=True, text=True, cwd=str(PIPELINE_ROOT),
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)  # stdout parses as JSON => clean redirect target
    assert len(data["stages"]) == 6  # shipped record has 6 stages
    assert "status" not in data  # envelope is NOT on stdout
    assert '"tier": "BLOCKING"' in proc.stderr  # envelope is on stderr


def test_shipped_yaml_passes_schema():
    """The committed docs/governance/data-flow.yaml must itself be schema-valid."""
    if not _have_yaml():
        pytest.skip("PyYAML not installed")
    doc = gdf.load_yaml(SHIPPED_YAML)
    stages = gdf.validate_schema(doc)
    assert len(stages) == 6
    # Every stage carries an explicit pii_present flag (the T-31 invariant).
    assert all("pii_present" in s for s in stages)
    # Every PII stage carries a non-empty justification.
    for s in stages:
        if s.get("pii_present") is True:
            assert s.get("pii_justification", "").strip()


def test_editing_pii_present_changes_output(tmp_path: Path, capsys):
    """Acceptance #1: flipping pii_present in the YAML changes the rendered JSON."""
    if not _have_yaml():
        pytest.skip("PyYAML not installed")
    p = _write(tmp_path, _MINIMAL_VALID)
    gdf.main(["--input", str(p)])
    before = json.loads(capsys.readouterr().out)["stages"][0]["pii_present"]

    flipped = _MINIMAL_VALID.replace(
        "pii_present: false\n    pii_types: []",
        'pii_present: true\n    pii_types: ["dev_email"]\n    pii_justification: "audit"',
    )
    _write(tmp_path, flipped)
    gdf.main(["--input", str(p)])
    after = json.loads(capsys.readouterr().out)["stages"][0]["pii_present"]

    assert before is False and after is True


# ------------------------------------------------------------------------- #
# Standalone runner (works without pytest) — mirrors test_libcompliance.py  #
# ------------------------------------------------------------------------- #

if __name__ == "__main__":
    import inspect
    import io
    import tempfile
    import traceback
    from contextlib import redirect_stderr, redirect_stdout

    class _Capsys:
        """Minimal capsys stand-in: captures the last redirected stdout/stderr."""

        def __init__(self):
            self._out = ""
            self._err = ""

        def set(self, out, err):
            self._out, self._err = out, err

        def readouterr(self):
            out, err = self._out, self._err
            self._out = self._err = ""
            class _R:  # noqa: N801
                pass
            r = _R()
            r.out, r.err = out, err
            return r

    fns = [
        (name, obj)
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    passed = failed = skipped = 0
    _Skipped = getattr(pytest, "_Skipped", None)

    def _invoke(fn, params, tmp):
        """Build kwargs, capturing stdout/stderr when the test wants capsys."""
        kwargs = {}
        cap = None
        if "tmp_path" in params:
            kwargs["tmp_path"] = tmp
        if "capsys" in params:
            cap = _Capsys()
            kwargs["capsys"] = cap
        if cap is not None:
            out_buf, err_buf = io.StringIO(), io.StringIO()
            # Patch readouterr to snapshot the live buffers on each call.
            def _readouterr(_o=out_buf, _e=err_buf):
                o, e = _o.getvalue(), _e.getvalue()
                _o.seek(0); _o.truncate(0)
                _e.seek(0); _e.truncate(0)
                class _R:  # noqa: N801
                    pass
                r = _R(); r.out, r.err = o, e
                return r
            cap.readouterr = _readouterr  # type: ignore[method-assign]
            with redirect_stdout(out_buf), redirect_stderr(err_buf):
                fn(**kwargs)
        else:
            fn(**kwargs)

    for name, fn in fns:
        params = list(inspect.signature(fn).parameters)
        try:
            if "tmp_path" in params:
                with tempfile.TemporaryDirectory() as d:
                    _invoke(fn, params, Path(d))
            else:
                _invoke(fn, params, None)
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
