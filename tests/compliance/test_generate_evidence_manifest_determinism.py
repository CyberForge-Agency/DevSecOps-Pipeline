"""T-82: Merkle determinism of generate-evidence-manifest.py (RFC-6962).

Asserts the two determinism invariants the T-82 task names:
  1. Same inputs -> identical merkle_root (re-running the build is reproducible).
  2. Writing the same files in a DIFFERENT creation order -> identical root
     (the generator sorts artifacts by POSIX path before hashing, so the leaf
     order — and hence the RFC-6962 tree — is independent of filesystem order).

Plus the RFC-6962 self-test vectors pass, and a content change DOES move the root
(so the determinism is not a degenerate constant).

The script is path-imported because its filename is hyphenated. Output goes only to
tmp_path; the repo evidence pack is never touched.

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

_GEM_PATH = PIPELINE_ROOT / "scripts" / "generate-evidence-manifest.py"
_spec = importlib.util.spec_from_file_location("generate_evidence_manifest", _GEM_PATH)
assert _spec and _spec.loader
gem = importlib.util.module_from_spec(_spec)
sys.modules["generate_evidence_manifest"] = gem
_spec.loader.exec_module(gem)


# Fixed file set used by several tests. Names chosen so creation order != sorted order.
_FILES = {
    "zeta.json": b'{"z":1}',
    "alpha.sarif": b'{"runs":[]}',
    "mid.txt": b"middle\n",
    "beta.json": b'{"b":2}',
}


def _populate(d: Path, files: dict[str, bytes], order=None) -> None:
    names = order if order is not None else list(files)
    for name in names:
        (d / name).write_bytes(files[name])


# --------------------------------------------------------------------------- #
# RFC-6962 self-test vectors                                                   #
# --------------------------------------------------------------------------- #

def test_rfc6962_selftest_passes():
    assert gem._selftest() == 0


# --------------------------------------------------------------------------- #
# Determinism 1: same inputs -> identical root                                 #
# --------------------------------------------------------------------------- #

def test_same_inputs_identical_root(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _populate(a, _FILES)
    _populate(b, _FILES)
    root_a = gem.build_manifest(str(a))["merkle_root"]
    root_b = gem.build_manifest(str(b))["merkle_root"]
    assert root_a == root_b
    assert len(root_a) == 64  # sha256 hex


def test_rebuild_same_dir_identical_root(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    _populate(d, _FILES)
    assert gem.build_manifest(str(d))["merkle_root"] == gem.build_manifest(str(d))["merkle_root"]


# --------------------------------------------------------------------------- #
# Determinism 2: reordered file set -> identical root                          #
# --------------------------------------------------------------------------- #

def test_reordered_creation_identical_root(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _populate(a, _FILES, order=["zeta.json", "alpha.sarif", "mid.txt", "beta.json"])
    _populate(b, _FILES, order=["beta.json", "mid.txt", "alpha.sarif", "zeta.json"])
    assert gem.build_manifest(str(a))["merkle_root"] == gem.build_manifest(str(b))["merkle_root"]


# --------------------------------------------------------------------------- #
# Non-degeneracy: a content change MOVES the root                              #
# --------------------------------------------------------------------------- #

def test_content_change_moves_root(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _populate(a, _FILES)
    changed = dict(_FILES)
    changed["beta.json"] = b'{"b":999}'  # one byte of content differs
    _populate(b, changed)
    assert gem.build_manifest(str(a))["merkle_root"] != gem.build_manifest(str(b))["merkle_root"]


def test_root_matches_direct_merkle_over_sorted_leaves(tmp_path):
    # Independent recompute: sort by POSIX path, hash the raw bytes, build MTH.
    d = tmp_path / "d"
    d.mkdir()
    _populate(d, _FILES)
    manifest = gem.build_manifest(str(d))
    leaves = [_FILES[name] for name in sorted(_FILES)]
    assert manifest["merkle_root"] == gem.merkle_root_hex(leaves)


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
