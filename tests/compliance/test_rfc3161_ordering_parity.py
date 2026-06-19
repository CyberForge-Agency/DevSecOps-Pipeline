"""Self-test for the Merkle ``.tsr`` RFC-3161 ordering parity (task T-123).

The RFC-3161 timestamp over ``merkle-root.txt`` is the pack's independent
trusted-time anchor: it proves the Merkle root (which commits to every artifact)
existed at the stamped instant, even if cosign/Rekor are unavailable. This
self-test proves two things about that path in ``verify-evidence-pack.sh``:

  1. REACHABLE — the runbook's §4 RFC-3161 verification path FOR ``merkle-root``
     is actually exercised on the shipped sample pack (it is not dead code behind
     an unreachable branch). The §4 loop iterates ``merkle-root manifest pdf``
     and, finding ``merkle-root.tsr`` + ``merkle-root.txt`` + ``tsa-ca.pem``,
     emits a ``... merkle-root ...`` PASS/FAIL line.
  2. VERIFIES — given the shipped ``tsa-ca.pem``, ``openssl ts -verify`` PASSes on
     the sample pack's ``merkle-root.tsr`` (the token is valid against the TSA
     CA). We assert this both directly (running openssl ourselves) and through
     the runbook's emitted PASS line, so the ordering parity — root file, its
     token, and its CA all line up — is proven end to end.

Honest skips (NEVER a fabricated pass): if ``openssl`` is absent, or the sample
pack lacks ``merkle-root.tsr`` / ``merkle-root.txt`` / ``tsa-ca.pem``, the
affected test SKIPs rather than asserts. A genuinely invalid token would FAIL
here — that is the correct, honest outcome.

Runs under pytest (``python3 -m pytest tests/compliance/test_rfc3161_ordering_parity.py -q``)
AND standalone (``python3 tests/compliance/test_rfc3161_ordering_parity.py``) so the
suite is verifiable where pytest is not installed — mirrors test_check_sealing_completeness.py.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
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
_OPENSSL = shutil.which("openssl")

MERKLE_TXT = SAMPLE_EVIDENCE / "merkle-root.txt"
MERKLE_TSR = SAMPLE_EVIDENCE / "merkle-root.tsr"
TSA_CA = SAMPLE_EVIDENCE / "tsa-ca.pem"


def _need_openssl():
    if _OPENSSL is None:
        pytest.skip("openssl not on PATH")


def _need_sample_tsr():
    if not SAMPLE_EVIDENCE.is_dir():
        pytest.skip("sample-evidence-pack/evidence not present")
    if not MERKLE_TSR.is_file():
        pytest.skip("merkle-root.tsr absent (TSA unavailable at seal time)")
    if not MERKLE_TXT.is_file():
        pytest.skip("merkle-root.txt absent (no data file to verify the token against)")


def _need_ca():
    if not TSA_CA.is_file():
        pytest.skip("tsa-ca.pem absent (cannot do full CA-chain verify)")


# --------------------------------------------------------------------------- #
# VERIFIES: openssl ts -verify PASSes on merkle-root.tsr against the TSA CA     #
# --------------------------------------------------------------------------- #

def test_openssl_ts_verify_merkle_root_passes_against_ca():
    """Direct `openssl ts -verify -data merkle-root.txt -in merkle-root.tsr -CAfile tsa-ca.pem`."""
    _need_openssl()
    _need_sample_tsr()
    _need_ca()
    r = subprocess.run(
        [
            _OPENSSL, "ts", "-verify",
            "-data", str(MERKLE_TXT),
            "-in", str(MERKLE_TSR),
            "-CAfile", str(TSA_CA),
        ],
        capture_output=True,
        text=True,
    )
    out = r.stdout + r.stderr
    # openssl prints "Verification: OK" on success and exits 0.
    assert r.returncode == 0, f"openssl ts -verify failed (rc={r.returncode}):\n{out}"
    assert "Verification: OK" in out, out


def test_token_is_granted_and_over_the_merkle_root():
    """The .tsr is a GRANTED RFC-3161 reply (not a rejection / non-token body).

    Mirrors the runbook's parse-only granted-status gate: a token that merely
    DER-decodes but was not GRANTED must not be treated as a valid timestamp.
    """
    _need_openssl()
    _need_sample_tsr()
    r = subprocess.run(
        [_OPENSSL, "ts", "-reply", "-in", str(MERKLE_TSR), "-text"],
        capture_output=True,
        text=True,
    )
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "Granted" in out, f"TSA token not Granted:\n{out}"


def test_token_rejects_a_different_data_file():
    """Honesty guard: the token must NOT verify against the WRONG data.

    Verifying merkle-root.tsr against manifest.json (different bytes) must FAIL —
    this proves the openssl check is a real cryptographic binding to merkle-root,
    not a token that "verifies" against anything.
    """
    _need_openssl()
    _need_sample_tsr()
    _need_ca()
    wrong_data = SAMPLE_EVIDENCE / "manifest.json"
    if not wrong_data.is_file():
        pytest.skip("manifest.json absent to use as a mismatched data file")
    r = subprocess.run(
        [
            _OPENSSL, "ts", "-verify",
            "-data", str(wrong_data),
            "-in", str(MERKLE_TSR),
            "-CAfile", str(TSA_CA),
        ],
        capture_output=True,
        text=True,
    )
    # A mismatched data file must NOT verify (non-zero exit, no "Verification: OK").
    assert r.returncode != 0, "token wrongly verified against mismatched data"
    assert "Verification: OK" not in (r.stdout + r.stderr)


# --------------------------------------------------------------------------- #
# REACHABLE: the runbook's §4 path emits a PASS for merkle-root                 #
# --------------------------------------------------------------------------- #

def test_runbook_rfc3161_merkle_root_path_is_reachable_and_passes():
    """verify-evidence-pack.sh emits a PASS `openssl ts -verify merkle-root ...` line."""
    if _BASH is None:
        pytest.skip("bash not available")
    _need_openssl()
    _need_sample_tsr()
    _need_ca()
    if not VERIFY_SH.is_file():
        pytest.skip(f"verify-evidence-pack.sh not found at {VERIFY_SH}")
    r = subprocess.run(
        [_BASH, str(VERIFY_SH), str(SAMPLE_EVIDENCE)],
        capture_output=True,
        text=True,
    )
    out = r.stdout + r.stderr
    # The §4 loop must produce a merkle-root RFC-3161 line, and it must be a PASS
    # (token valid against the shipped TSA CA) — proving the path is live, not dead.
    pass_lines = [
        ln for ln in out.splitlines()
        if ln.startswith("PASS") and "ts -verify" in ln and "merkle-root" in ln
    ]
    assert pass_lines, f"no PASS openssl-ts merkle-root line emitted:\n{out}"
    # And no merkle-root RFC-3161 FAIL line slipped through.
    fail_lines = [
        ln for ln in out.splitlines()
        if ln.startswith("FAIL") and "merkle-root" in ln and ("ts -verify" in ln or "RFC-3161" in ln)
    ]
    assert not fail_lines, f"unexpected merkle-root RFC-3161 FAIL:\n{out}"


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
