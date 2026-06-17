"""Pytest discovery anchor for the compliance self-test suite (task T-83 / SelfTest lane).

Every test under ``tests/compliance/`` resolves its validator under test with
``from scripts.validators import <module>`` (T-33 envelope, libcompliance, the
A.1-A.10 CAC validators, VEX/SoA/risk/applicability scorers, matrix_rows, ...).
That import only succeeds when the Pipeline repo root is on ``sys.path`` so that
``scripts`` and ``scripts/validators`` resolve as PEP-420 implicit namespace
packages.

The individual test files already self-insert ``PIPELINE_ROOT`` (so they also run
standalone via ``python3 tests/compliance/test_*.py`` where pytest is absent), but
that insertion happens at *module import* time — which, under pytest's default
``prepend`` import mode, can race with collection when the suite is invoked from a
cwd other than ``Pipeline/`` (e.g. ``pytest Pipeline/tests/compliance`` from the
repo root). A ``conftest.py`` is imported by pytest *before* any test module is
collected, so inserting the root here makes ``scripts.validators`` importable
during collection regardless of the invocation directory.

This file is intentionally side-effect-minimal: it only ensures the path is present
(idempotent) and exposes no fixtures, so it cannot alter the behaviour of the
existing tests — it only hardens their discovery.
"""

from __future__ import annotations

import sys
from pathlib import Path

# tests/compliance/conftest.py -> parents[0]=compliance, [1]=tests, [2]=Pipeline root.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]

_root = str(PIPELINE_ROOT)
if _root not in sys.path:
    # Insert at the front so the in-repo ``scripts`` package wins over any
    # like-named package that might be installed in the environment.
    sys.path.insert(0, _root)
