"""Test-discovery sanity check for the compliance self-test suite (task T-83 / SelfTest).

This is the *meta* self-test: it proves the suite is correctly wired so the CI quality
job (``cd Pipeline && pytest tests/compliance``) actually exercises the validators
rather than silently collecting zero tests or importing the wrong ``scripts`` package.

It asserts, from real disk state (no mocks):

  1. The ``conftest.py`` discovery anchor placed the Pipeline repo root on ``sys.path``
     so ``from scripts.validators import <module>`` resolves during collection from any
     cwd (the bug fixed in T-83: ``pytest Pipeline/tests/compliance`` from the repo root
     used to error out at collection).
  2. ``scripts`` and ``scripts/validators`` resolve as importable (PEP-420 namespace)
     packages pointing *inside this repo*, not at some same-named installed package.
  3. The shared T-33 envelope library (``libcompliance``) imports and exposes the
     envelope contract every other validator depends on.
  4. Every ``scripts/validators/*.py`` module is importable by file path (no syntax /
     top-level-import breakage that would only surface at CI time).
  5. pytest discovers every sibling ``test_*.py`` file, including the hyphenated
     ``test_validate-ropa.py`` whose name is not a valid module identifier — a known
     prepend-import-mode footgun — so no test is silently dropped.

Runs under pytest AND standalone (``python3 tests/compliance/test_suite_discovery.py``)
so the wiring is verifiable even where pytest is not installed — mirrors the dual-mode
pattern used across this suite (e.g. test_soa_maturity.py).
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

# Mirror the suite-wide self-insert so this file also runs standalone, before any
# ``from scripts...`` import. The conftest does the same for the pytest path; this is
# the belt-and-braces that lets ``python3 tests/compliance/test_suite_discovery.py`` work.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

THIS_DIR = Path(__file__).resolve().parent
VALIDATORS_DIR = PIPELINE_ROOT / "scripts" / "validators"


# --------------------------------------------------------------------------- #
# 1. Discovery anchor                                                          #
# --------------------------------------------------------------------------- #

def test_pipeline_root_on_sys_path():
    """The repo root is importable — the precondition for every ``scripts.*`` import."""
    assert str(PIPELINE_ROOT) in sys.path, (
        "Pipeline root is not on sys.path; conftest.py discovery anchor did not run. "
        "Validator imports would fail at collection time."
    )


def test_pipeline_root_layout_is_sane():
    """Guard against a wrong-root computation: the expected dirs must exist here."""
    assert (PIPELINE_ROOT / "scripts" / "validators").is_dir()
    assert (PIPELINE_ROOT / "tests" / "compliance").is_dir()
    assert (THIS_DIR / "conftest.py").is_file(), "conftest discovery anchor is missing"


# --------------------------------------------------------------------------- #
# 2 + 3. The scripts.validators namespace package + the shared envelope        #
# --------------------------------------------------------------------------- #

def test_scripts_validators_resolves_inside_this_repo():
    """``import scripts.validators`` must resolve to THIS repo, not an installed namesake."""
    pkg = importlib.import_module("scripts.validators")
    # A namespace package has __path__; assert at least one path entry is inside our repo.
    paths = [Path(p).resolve() for p in list(getattr(pkg, "__path__", []))]
    assert any(p == VALIDATORS_DIR for p in paths), (
        f"scripts.validators did not resolve to {VALIDATORS_DIR}; got {paths}"
    )


def test_libcompliance_envelope_contract_imports():
    """The T-33 shared envelope library imports and exposes the contract validators use."""
    lc = importlib.import_module("scripts.validators.libcompliance")
    # The envelope builder + the status/tier vocabulary are the load-bearing surface.
    assert hasattr(lc, "envelope") or hasattr(lc, "make_envelope") or hasattr(
        lc, "build_envelope"
    ), "libcompliance exposes no envelope constructor"
    src = (VALIDATORS_DIR / "libcompliance.py").read_text(encoding="utf-8")
    for token in ("PASS", "FAIL", "INDETERMINATE", "BLOCKING", "EVIDENCE-ONLY"):
        assert token in src, f"envelope vocabulary token {token!r} missing from libcompliance"


# --------------------------------------------------------------------------- #
# 4. Every validator module is importable by path                             #
# --------------------------------------------------------------------------- #

def _validator_modules() -> list[Path]:
    return sorted(
        p
        for p in VALIDATORS_DIR.glob("*.py")
        if p.name != "__init__.py" and not p.name.startswith("_")
    )


def test_at_least_the_core_validators_are_present():
    """Sanity floor: the suite would be hollow if the validators dir were near-empty."""
    mods = {p.stem for p in _validator_modules()}
    # libcompliance is the shared envelope; its absence means the whole tier is broken.
    assert "libcompliance" in mods
    assert len(mods) >= 10, f"only {len(mods)} validator modules found: {sorted(mods)}"


def test_every_validator_module_imports_clean():
    """No validator has a syntax error / broken top-level import that CI would trip on."""
    failures: list[str] = []
    for mod_path in _validator_modules():
        # Load under a unique module name so dashed names (e.g. validate-roi.py) load too.
        unique = "t83_disc_" + mod_path.stem.replace("-", "_")
        spec = importlib.util.spec_from_file_location(unique, mod_path)
        if spec is None or spec.loader is None:
            failures.append(f"{mod_path.name}: could not build import spec")
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001 - we want the name+reason for every failure
            failures.append(f"{mod_path.name}: {type(exc).__name__}: {exc}")
    assert not failures, "validator modules failed to import:\n  " + "\n  ".join(failures)


# --------------------------------------------------------------------------- #
# 5. pytest discovers every sibling test_*.py (incl. the hyphenated one)       #
# --------------------------------------------------------------------------- #

def test_all_sibling_test_files_are_collectable_by_path():
    """Every test_*.py here must be importable by path, esp. the hyphenated module name.

    ``test_validate-ropa.py`` is not a valid Python module identifier; under pytest's
    default prepend import mode this is the file most likely to be silently dropped or
    to break collection. We assert all of them load by explicit-path importlib (the same
    mechanism pytest's importlib mode uses), so none can be quietly skipped.
    """
    test_files = sorted(
        p for p in THIS_DIR.glob("test_*.py") if p.name != Path(__file__).name
    )
    assert test_files, "no sibling test files discovered — suite is empty"

    hyphenated = [p for p in test_files if "-" in p.stem]
    assert hyphenated, (
        "expected at least one hyphenated test file (test_validate-ropa.py) as the "
        "discovery canary; none found — has the suite layout changed?"
    )

    failures: list[str] = []
    for tf in test_files:
        unique = "t83_collect_" + tf.stem.replace("-", "_")
        spec = importlib.util.spec_from_file_location(unique, tf)
        if spec is None or spec.loader is None:
            failures.append(f"{tf.name}: no import spec")
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{tf.name}: {type(exc).__name__}: {exc}")
    assert not failures, "test files failed to import:\n  " + "\n  ".join(failures)


# --------------------------------------------------------------------------- #
# Standalone runner (no pytest required)                                       #
# --------------------------------------------------------------------------- #

def _run_standalone() -> int:
    tests = [
        test_pipeline_root_on_sys_path,
        test_pipeline_root_layout_is_sane,
        test_scripts_validators_resolves_inside_this_repo,
        test_libcompliance_envelope_contract_imports,
        test_at_least_the_core_validators_are_present,
        test_every_validator_module_imports_clean,
        test_all_sibling_test_files_are_collectable_by_path,
    ]
    failures: list[str] = []
    for t in tests:
        try:
            t()
        except AssertionError as exc:
            failures.append(f"{t.__name__}: {exc}")
    if failures:
        print("STANDALONE FAIL:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1
    print(f"STANDALONE PASS: {len(tests)} discovery checks")
    return 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
