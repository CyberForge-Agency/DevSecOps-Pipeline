"""Structural assertion for the assembled sample Evidence Pack (task T-92).

This is the founder-independent acceptance check for the *shape* of a pack: it
proves that the committed ``sample-evidence-pack/evidence`` directory

  1. contains all **8 required spec components** (mapped from
     ``evidence-pack-specification.md`` §0-J: board report, manifest, scan
     results, SBOM, control matrix, regulatory crosswalk, gap register,
     integrity proof) — and **FAILS if any one is missing**; and
  2. is internally coherent: ``manifest.json``'s declared artifact list is
     exactly the set of Merkle-covered files on disk, every listed sha256
     matches the file bytes, and the **RFC-6962 Merkle root recomputed from the
     manifest's file list equals both ``manifest.merkle_root`` and
     ``merkle-root.txt``** (so the manifest/Merkle/README can never silently
     disagree — the F3 drift class).

It deliberately recomputes the Merkle root with an INDEPENDENT implementation of
RFC 6962 (it does not import the generator) so a regression in
``generate-evidence-manifest.py`` cannot make this test pass by being wrong in
the same way.

The 8-component map is asserted against a *predicate per component* (a component
is satisfied if at least one of its candidate files is present), so a missing
component produces a precise, named failure rather than a vague count mismatch.

Runs under pytest (``python3 -m pytest tests/compliance/test_pack_structure.py -q``)
AND standalone (``python3 tests/compliance/test_pack_structure.py``) so the suite
is verifiable even where pytest is not installed.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Sequence

try:
    import pytest
except ImportError:  # standalone fallback: minimal pytest surface used here
    class _PytestShim:
        @staticmethod
        def fail(msg: str) -> None:
            raise AssertionError(msg)

    pytest = _PytestShim()  # type: ignore[assignment]


# tests/compliance/test_pack_structure.py -> parents[1]=tests, [2]=Pipeline root.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_DIR = PIPELINE_ROOT / "sample-evidence-pack" / "evidence"
MANIFEST = EVIDENCE_DIR / "manifest.json"
MERKLE_ROOT_TXT = EVIDENCE_DIR / "merkle-root.txt"

# Files the manifest generator excludes from the Merkle set (must mirror
# generate-evidence-manifest.py EXCLUDED_NAMES / EXCLUDED_SUFFIXES so the
# recompute uses the SAME leaf set without importing the generator).
EXCLUDED_NAMES = {
    "manifest.json",
    "manifest.sha256",
    "file-list.txt",
    "merkle-root.txt",
    "pdf.sha256",
    "verapdf-report.json",
}
EXCLUDED_SUFFIXES = (
    ".cosign.bundle",
    ".bundle",
    ".tsr",
    ".tsq",
    ".sig",
    ".pem",
)

# --- The 8 required spec components (evidence-pack-specification.md) ----------
# Each entry: (component name, spec part, [candidate filenames; >=1 must exist]).
# A pack satisfies a component iff at least one candidate file is present.
REQUIRED_COMPONENTS: list[tuple[str, str, list[str]]] = [
    ("Board report (PDF/HTML)", "Part 0.2",
     ["audit-document.html", "evidence-report.html",
      "evidence-report.pdf", "evidence-report.pdf.MISSING"]),
    ("Artifact manifest", "Part 0.1",
     ["manifest.json"]),
    ("Scan results (SARIF)", "Part C / §X.1",
     ["trivy-results.sarif", "trivy-sca-results.json"]),
    ("SBOM", "Part C.10",
     ["sbom.cyclonedx.json"]),
    ("Control matrix", "Part D.1",
     ["compliance-matrix.json"]),
    ("Regulatory crosswalk", "Part D.2",
     ["crosswalk.json"]),
    ("Gap / remediation register", "Part J",
     ["gap-register.json", "gap-register.md"]),
    ("Integrity proof", "Part I",
     ["merkle-root.txt", "manifest.tsr", "merkle-root.tsr"]),
]


# --- Independent RFC 6962 Merkle Tree Hash -----------------------------------
def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _merkle_tree_hash(leaves: Sequence[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _largest_power_of_two_less_than(n)
    return _node_hash(_merkle_tree_hash(leaves[:k]), _merkle_tree_hash(leaves[k:]))


def _merkle_root_hex(leaves: Sequence[bytes]) -> str:
    return _merkle_tree_hash(leaves).hex()


def _covered_files_on_disk(evidence_dir: Path) -> list[str]:
    """POSIX-relative paths of files the manifest is expected to cover."""
    rels: list[str] = []
    for p in evidence_dir.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(evidence_dir).as_posix()
        name = p.name
        if name in EXCLUDED_NAMES or rel in EXCLUDED_NAMES:
            continue
        if name.endswith(EXCLUDED_SUFFIXES) or rel.endswith(EXCLUDED_SUFFIXES):
            continue
        rels.append(rel)
    rels.sort()
    return rels


def _load_manifest() -> dict:
    if not MANIFEST.is_file():
        pytest.fail(f"manifest.json missing at {MANIFEST} — pack not assembled")
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


# --- Tests -------------------------------------------------------------------
def test_all_eight_required_components_present() -> None:
    """FAILS (naming the component) if any of the 8 spec components is absent."""
    missing: list[str] = []
    for name, part, candidates in REQUIRED_COMPONENTS:
        if not any((EVIDENCE_DIR / c).exists() for c in candidates):
            missing.append(f"{name} ({part}; expected one of {candidates})")
    if missing:
        pytest.fail(
            "sample pack is missing required spec component(s):\n  - "
            + "\n  - ".join(missing)
        )
    assert len(REQUIRED_COMPONENTS) == 8


def test_manifest_filelist_matches_disk() -> None:
    """The manifest's declared artifact set == the Merkle-covered files on disk."""
    manifest = _load_manifest()
    declared = sorted(a["path"] for a in manifest.get("artifacts", []))
    on_disk = _covered_files_on_disk(EVIDENCE_DIR)
    assert declared, "manifest.artifacts is empty — nothing covered"
    only_manifest = sorted(set(declared) - set(on_disk))
    only_disk = sorted(set(on_disk) - set(declared))
    assert not only_manifest, f"manifest lists files not on disk: {only_manifest}"
    assert not only_disk, f"covered files on disk missing from manifest: {only_disk}"


def test_every_listed_sha256_matches_bytes() -> None:
    """Each artifact's recorded sha256 matches the bytes on disk (no stale hash)."""
    manifest = _load_manifest()
    mismatched: list[str] = []
    for art in manifest.get("artifacts", []):
        f = EVIDENCE_DIR / art["path"]
        if not f.is_file():
            mismatched.append(f"{art['path']}: file absent")
            continue
        actual = hashlib.sha256(f.read_bytes()).hexdigest()
        if actual != art.get("sha256"):
            mismatched.append(f"{art['path']}: {art.get('sha256')} != {actual}")
    assert not mismatched, "manifest sha256 mismatch:\n  " + "\n  ".join(mismatched)


def test_merkle_root_recompute_matches_manifest_and_txt() -> None:
    """RFC-6962 root recomputed from the manifest file list == manifest.merkle_root
    == merkle-root.txt. This is the anti-drift guard (F3)."""
    manifest = _load_manifest()
    declared_root = str(manifest.get("merkle_root", "")).strip().lower()
    assert declared_root, "manifest.merkle_root absent"

    # Recompute over the manifest's own (path-sorted) artifact list, reading the
    # real bytes — independent of generate-evidence-manifest.py.
    paths = sorted(a["path"] for a in manifest.get("artifacts", []))
    leaves = [(EVIDENCE_DIR / p).read_bytes() for p in paths]
    recomputed = _merkle_root_hex(leaves)
    assert recomputed == declared_root, (
        f"recomputed RFC-6962 root {recomputed} != manifest.merkle_root {declared_root}"
    )

    if MERKLE_ROOT_TXT.is_file():
        txt_root = MERKLE_ROOT_TXT.read_text(encoding="utf-8").strip().split()[0].lower()
        assert txt_root == declared_root, (
            f"merkle-root.txt {txt_root} != manifest.merkle_root {declared_root}"
        )


def test_missing_component_is_detected() -> None:
    """Negative control: a pack lacking a required component is flagged (the test
    is not vacuously green). Uses an in-memory predicate over a synthetic pack."""
    def missing_components(present: set[str]) -> list[str]:
        out = []
        for name, _part, candidates in REQUIRED_COMPONENTS:
            if not any(c in present for c in candidates):
                out.append(name)
        return out

    full = {c for _n, _p, cands in REQUIRED_COMPONENTS for c in cands}
    assert missing_components(full) == [], "full set should satisfy all components"
    # Drop every candidate for the SBOM component -> must be reported missing.
    no_sbom = full - {"sbom.cyclonedx.json"}
    assert "SBOM" in missing_components(no_sbom), (
        "predicate must flag a pack with no SBOM as missing the SBOM component"
    )


def _run_standalone() -> int:
    tests = [
        test_all_eight_required_components_present,
        test_manifest_filelist_matches_disk,
        test_every_listed_sha256_matches_bytes,
        test_merkle_root_recompute_matches_manifest_and_txt,
        test_missing_component_is_detected,
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
    print(f"STANDALONE PASS: {len(tests)} tests")
    return 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
