"""Self-test for the sealing-artifact completeness gate (T-58 / T-82 SelfTest lane).

Proves ``scripts/check-sealing-completeness.sh`` is an *enforcing* gate, not a
presence-only formality:

  * GOOD case  — a fully-sealed evidence dir (all 8 integrity outputs + >=1 *.tsr,
    each structurally valid) -> exit 0, "RESULT: COMPLETE".
  * FAIL case  — any required artifact missing / zero-byte / structurally invalid,
    in fail-closed (non-PR) mode -> exit 1, "RESULT: INCOMPLETE".
  * DEGRADE    — the same missing artifact under ``EVIDENCE_ALLOW_DEGRADE=1``
    (local / PR) -> exit 0 with a WARN (the documented degraded-pack contract);
    confirms the gate is not weakened in CI, only in degrade mode.
  * STRUCTURAL — a non-empty-but-corrupt cosign bundle / non-CycloneDX SBOM /
    malformed provenance JSONL each FAIL fail-closed (the §6.2-A trust-leak this
    self-test exists to close: a file that exists but is garbage).
  * USAGE      — wrong arg count -> exit 64; missing dir -> exit 1.

Runs under pytest (``python3 -m pytest tests/compliance/test_check_sealing_completeness.py -q``)
AND standalone (``python3 tests/compliance/test_check_sealing_completeness.py``) so the
suite is verifiable where pytest is not installed — mirroring test_assert_crypto.py.
"""

from __future__ import annotations

import json
import os
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
SCRIPT = REPO_PIPELINE / "scripts" / "check-sealing-completeness.sh"

_BASH = shutil.which("bash")

# The full required set the script enforces. Values are the file bodies written by
# _make_complete_pack() — each is deliberately the *minimal structurally-valid*
# shape the script's structural arm accepts, so a GOOD pack truly passes.
_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
_PROV_LINE = json.dumps(
    {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "img", "digest": {"sha256": "ab" * 32}}],
    }
)
_COSIGN_BUNDLE = json.dumps({"base64Signature": "QUJD", "cert": "PEMDATA"})
_MANIFEST = json.dumps({"merkle_root": "f" * 64, "artifacts": []})


def _write(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def _make_complete_pack(root: Path) -> Path:
    """Materialise a fully-sealed, structurally-valid evidence dir under ``root``."""
    d = root / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    _write(d / "manifest.json", _MANIFEST)
    _write(d / "merkle-root.txt", "f" * 64 + "\n")
    _write(d / "merkle-root.cosign.bundle", _COSIGN_BUNDLE)
    _write(d / "pdf-sha256.cosign.bundle", _COSIGN_BUNDLE)
    _write(d / "verapdf-report.json", json.dumps({"jobs": [], "passed": True}))
    _write(d / "oscal-assessment-results.json", json.dumps({"assessment-results": {}}))
    _write(d / "sbom.cyclonedx.json", json.dumps(_SBOM))
    _write(d / "provenance.intoto.jsonl", _PROV_LINE + "\n")
    _write(d / "merkle-root.tsr", "\x30\x82binary-ish-token")  # non-empty *.tsr
    return d


def _run(evidence_dir, *, degrade=False, extra_args=None):
    if _BASH is None:  # pragma: no cover - environment guard
        pytest.skip("bash not available")
    env = dict(os.environ)
    if degrade:
        env["EVIDENCE_ALLOW_DEGRADE"] = "1"
    else:
        env.pop("EVIDENCE_ALLOW_DEGRADE", None)
    args = [_BASH, str(SCRIPT)]
    args += extra_args if extra_args is not None else [str(evidence_dir)]
    return subprocess.run(args, capture_output=True, text=True, env=env)


# --------------------------------------------------------------------------- #
# Sanity: the script parses (bash -n) and is on disk.                          #
# --------------------------------------------------------------------------- #

def test_script_exists_and_parses():
    assert SCRIPT.is_file(), SCRIPT
    if _BASH is None:
        pytest.skip("bash not available")
    r = subprocess.run([_BASH, "-n", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


# --------------------------------------------------------------------------- #
# GOOD case: a complete, structurally-valid pack exits 0.                      #
# --------------------------------------------------------------------------- #

def test_complete_pack_passes_fail_closed():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        r = _run(d)
        assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
        assert "RESULT: COMPLETE" in r.stdout
        assert "FAIL" not in r.stdout.split("completeness summary:")[0] or "0 FAIL" in r.stdout


# --------------------------------------------------------------------------- #
# FAIL case: any required artifact missing -> exit 1 in fail-closed mode.      #
# --------------------------------------------------------------------------- #

def test_missing_cosign_bundle_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        (d / "merkle-root.cosign.bundle").unlink()
        r = _run(d)
        assert r.returncode == 1, f"expected fail-closed exit 1, got {r.returncode}"
        assert "RESULT: INCOMPLETE" in r.stdout
        assert "merkle-root.cosign.bundle" in r.stdout


def test_missing_manifest_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        (d / "manifest.json").unlink()
        r = _run(d)
        assert r.returncode == 1
        assert "manifest.json" in r.stdout


def test_zero_byte_artifact_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        (d / "verapdf-report.json").write_text("", encoding="utf-8")
        r = _run(d)
        assert r.returncode == 1
        assert "verapdf-report.json" in r.stdout


def test_empty_merkle_root_in_manifest_fails_closed():
    # manifest parses but merkle_root is empty -> integrity root not committed.
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        _write(d / "manifest.json", json.dumps({"merkle_root": "", "artifacts": []}))
        r = _run(d)
        assert r.returncode == 1
        assert "merkle_root is EMPTY" in r.stdout


def test_no_tsr_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        (d / "merkle-root.tsr").unlink()
        r = _run(d)
        assert r.returncode == 1
        assert "RFC-3161" in r.stdout or ".tsr" in r.stdout


# --------------------------------------------------------------------------- #
# STRUCTURAL: present-but-corrupt artifacts FAIL (the §6.2-A trust leak).      #
# --------------------------------------------------------------------------- #

def test_corrupt_cosign_bundle_fails_closed():
    # A non-empty but non-JSON bundle (truncated/half-written) must FAIL — presence
    # alone is not enough.
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        _write(d / "pdf-sha256.cosign.bundle", "{not valid json")
        r = _run(d)
        assert r.returncode == 1
        assert "pdf-sha256.cosign.bundle" in r.stdout


def test_non_cyclonedx_sbom_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        _write(d / "sbom.cyclonedx.json", json.dumps({"bomFormat": "SPDX"}))
        r = _run(d)
        assert r.returncode == 1
        assert "CycloneDX" in r.stdout


def test_malformed_provenance_line_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        # valid JSON but neither an in-toto Statement nor a DSSE envelope
        _write(d / "provenance.intoto.jsonl", json.dumps({"hello": "world"}) + "\n")
        r = _run(d)
        assert r.returncode == 1
        assert "provenance.intoto.jsonl" in r.stdout


# --------------------------------------------------------------------------- #
# DEGRADE: the same missing artifact is tolerated under EVIDENCE_ALLOW_DEGRADE #
# --------------------------------------------------------------------------- #

def test_missing_artifact_degrade_mode_exits_zero():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        (d / "merkle-root.cosign.bundle").unlink()
        (d / "merkle-root.tsr").unlink()
        r = _run(d, degrade=True)
        assert r.returncode == 0, f"degrade mode must exit 0: {r.stdout}\n{r.stderr}"
        assert "OK-DEGRADED" in r.stdout or "degrade" in r.stdout.lower()
        assert "WARN" in r.stdout


def test_complete_pack_in_degrade_mode_is_complete():
    # A complete pack in degrade mode still reports COMPLETE (no WARNs).
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_complete_pack(Path(tmp))
        r = _run(d, degrade=True)
        assert r.returncode == 0
        assert "RESULT: COMPLETE" in r.stdout


# --------------------------------------------------------------------------- #
# USAGE / environment errors.                                                  #
# --------------------------------------------------------------------------- #

def test_wrong_argc_exits_64():
    r = _run(None, extra_args=[])  # no args
    assert r.returncode == 64, r.stderr
    assert "usage" in r.stderr.lower()


def test_missing_evidence_dir_exits_one():
    with tempfile.TemporaryDirectory() as tmp:
        r = _run(Path(tmp) / "does-not-exist")
        assert r.returncode == 1
        assert "not found" in (r.stdout + r.stderr).lower()


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
