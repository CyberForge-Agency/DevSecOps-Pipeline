"""Self-test for the §6.2-A Merkle-root sealing ordering parity (task T-57).

§6.2-A is the regression surface where a pack's headline cryptographic claim —
``merkle-root.cosign.bundle`` — is silently absent while ``merkle-root.txt`` is
present, so the Merkle root was computed but never signed. ``verify-evidence-
pack.sh`` must NOT skip that: it must emit an explicit §6.2-A FAIL line and exit
non-zero. This proves the ordering invariant (a signable root with no signature
is a failure, not a degrade-skip).

What this asserts:
  * GOOD-FOR-FAIL — a pack with ``merkle-root.txt`` present but no
    ``merkle-root.cosign.bundle`` -> the §6.2-A FAIL line is emitted AND the
    runbook exits non-zero. The shipped ``sample-evidence-pack/evidence`` is
    exactly this shape (it honestly lacks the bundle), so this PASSES today.
  * NO-FALSE-POSITIVE — adding a ``merkle-root.cosign.bundle`` removes the
    §6.2-A FAIL line (the regression check is specific to the missing bundle,
    not noise from any other check). Run on a hermetic temp copy so the shipped
    pack is never mutated.

Honest skips: the §6.2-A arm only runs when ``cosign`` is on PATH (the runbook
gates the whole §3 cosign block on ``have cosign``). Where cosign or bash is
absent we skip rather than assert, so a CI box without cosign reports SKIP, not
a false failure.

Runs under pytest (``python3 -m pytest tests/compliance/test_sealing_ordering_parity.py -q``)
AND standalone (``python3 tests/compliance/test_sealing_ordering_parity.py``) so the
suite is verifiable where pytest is not installed — mirrors test_check_sealing_completeness.py.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback: minimal pytest surface used here
    class _PytestShim:
        @staticmethod
        def skip(reason=""):
            raise AssertionError(f"SKIP: {reason}")

    pytest = _PytestShim()  # type: ignore


REPO_PIPELINE = Path(__file__).resolve().parents[2]
VERIFY_SH = REPO_PIPELINE / "scripts" / "verify-evidence-pack.sh"
SAMPLE_EVIDENCE = REPO_PIPELINE / "sample-evidence-pack" / "evidence"

_BASH = shutil.which("bash")
_COSIGN = shutil.which("cosign")

# The stable marker the runbook prints for the §6.2-A regression (line 218 of
# scripts/verify-evidence-pack.sh emits "... (§6.2-A)"). We match this substring,
# not the whole sentence, so cosmetic wording tweaks do not silently disable the
# test.
SECTION_62A = "§6.2-A"


def _has_62a_fail(text: str) -> bool:
    """True iff a FAIL line carrying the §6.2-A marker was emitted."""
    for line in text.splitlines():
        if line.startswith("FAIL") and SECTION_62A in line:
            return True
    return False


def _need_tools():
    if _BASH is None:
        pytest.skip("bash not available")
    if _COSIGN is None:
        pytest.skip("cosign not on PATH — §6.2-A arm is gated on `have cosign`")
    if not VERIFY_SH.is_file():
        pytest.skip(f"verify-evidence-pack.sh not found at {VERIFY_SH}")


def _run_verify(evidence_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_BASH, str(VERIFY_SH), str(evidence_dir)],
        capture_output=True,
        text=True,
    )


def _copy_sample(dst_parent: Path) -> Path:
    """Copy the shipped sample evidence dir so we never mutate the source."""
    dst = dst_parent / "evidence"
    shutil.copytree(SAMPLE_EVIDENCE, dst)
    return dst


# --------------------------------------------------------------------------- #
# GOOD-FOR-FAIL: missing bundle while root present -> §6.2-A FAIL + non-zero    #
# --------------------------------------------------------------------------- #

def test_sample_pack_emits_62a_fail_and_nonzero_exit():
    """The shipped sample pack lacks merkle-root.cosign.bundle -> §6.2-A FAIL."""
    _need_tools()
    if not SAMPLE_EVIDENCE.is_dir():
        pytest.skip("sample-evidence-pack/evidence not present")
    # Sanity: the sample really is in the §6.2-A shape (root present, bundle absent).
    assert (SAMPLE_EVIDENCE / "merkle-root.txt").is_file()
    assert not (SAMPLE_EVIDENCE / "merkle-root.cosign.bundle").exists()

    r = _run_verify(SAMPLE_EVIDENCE)
    out = r.stdout + r.stderr
    assert _has_62a_fail(out), f"§6.2-A FAIL line not emitted:\n{out}"
    # A FAIL must drive a non-zero exit (the runbook never exits 0 with any FAIL).
    assert r.returncode != 0, out
    assert "RESULT: FAIL" in out, out


def test_62a_fail_requires_root_present():
    """Removing merkle-root.txt too removes the §6.2-A surface (no signable root)."""
    _need_tools()
    if not SAMPLE_EVIDENCE.is_dir():
        pytest.skip("sample-evidence-pack/evidence not present")
    with tempfile.TemporaryDirectory() as tmp:
        ev = _copy_sample(Path(tmp))
        (ev / "merkle-root.txt").unlink()
        r = _run_verify(ev)
        out = r.stdout + r.stderr
        # With no merkle-root.txt there is nothing to sign, so §6.2-A must NOT fire.
        assert not _has_62a_fail(out), f"§6.2-A fired with no root to sign:\n{out}"


# --------------------------------------------------------------------------- #
# NO-FALSE-POSITIVE: present bundle removes the §6.2-A FAIL                     #
# --------------------------------------------------------------------------- #

def test_present_bundle_removes_62a_fail():
    """Adding merkle-root.cosign.bundle clears the §6.2-A regression line.

    A structurally-present bundle (identity unpinned -> the cosign check SKIPs,
    not FAILs) means the §6.2-A "missing bundle" line must no longer appear. This
    confirms the FAIL is specific to the absent-bundle condition, not background
    noise. Run on a temp copy so the shipped pack is untouched.
    """
    _need_tools()
    if not SAMPLE_EVIDENCE.is_dir():
        pytest.skip("sample-evidence-pack/evidence not present")
    with tempfile.TemporaryDirectory() as tmp:
        ev = _copy_sample(Path(tmp))
        # A minimal cosign-shaped bundle; identity/issuer are unset, so the runbook
        # SKIPs the cryptographic verify (it does not FAIL on an unverifiable but
        # present bundle), which is what lets us isolate the §6.2-A line.
        (ev / "merkle-root.cosign.bundle").write_text(
            json.dumps({"base64Signature": "QUJD", "cert": "PEM"}),
            encoding="utf-8",
        )
        r = _run_verify(ev)
        out = r.stdout + r.stderr
        assert not _has_62a_fail(out), f"§6.2-A still fired with bundle present:\n{out}"


# --------------------------------------------------------------------------- #
# Standalone runner (no pytest)                                                #
# --------------------------------------------------------------------------- #

def _standalone() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures: list[str] = []
    skipped = 0
    for t in tests:
        try:
            t()
        except AssertionError as exc:
            if str(exc).startswith("SKIP:"):
                skipped += 1
                continue
            failures.append(f"{t.__name__}: {exc!r}")
        except BaseException as exc:  # noqa: BLE001
            failures.append(f"{t.__name__}: {exc!r}")
    if failures:
        print(f"FAILED {len(failures)}/{len(tests)} ({skipped} skipped):")
        for f in failures:
            print("  - " + f)
        return 1
    print(f"OK: {len(tests) - skipped} tests passed ({skipped} skipped)")
    return 0


if __name__ == "__main__":
    sys.exit(_standalone())
