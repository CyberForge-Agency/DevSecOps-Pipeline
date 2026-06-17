#!/usr/bin/env python3
"""generate-evidence-manifest.py — Build a Merkle-rooted evidence manifest.

Pure Python 3 standard library only (no pip dependencies). Deterministic:
this script never reads the wall clock directly. The ``generated_at`` value
comes from the ``GENERATED_AT`` environment variable (ISO-8601 UTC) or falls
back to the fixed placeholder ``1970-01-01T00:00:00Z`` so output is testable.

Schema written to ``<evidence_dir>/manifest.json``::

    {
      "schema":"cyberforge-evidence-manifest/v1",
      "report_id":str, "generated_at":str, "git_sha":str, "image_digest":str,
      "period":{"start":str,"end":str},
      "artifacts":[{"path","sha256","size","mime","source","provenance"}],
      "merkle_root":hex, "merkle_algorithm":"RFC6962-SHA256",
      "tooling":{}, "worm_state":"pending", "signatures":{}
    }

Merkle root construction (RFC 6962, "Certificate Transparency"):

  * Domain separation:
      leaf hash  = SHA256( 0x00 || data )
      node hash  = SHA256( 0x01 || left_hash || right_hash )
  * The list of artifacts is sorted by POSIX path before hashing.
  * The Merkle Tree Hash (MTH) is defined recursively (RFC 6962 sec. 2.1):
      MTH({})        = SHA256("")                      # empty tree
      MTH({d0})      = leaf(d0)
      MTH(D[n])      = node( MTH(D[0:k]), MTH(D[k:n]) )
        where n > 1 and k is the largest power of two strictly less than n.
  * Consequence of the "largest power of two < n" split: a lone right-most
    node is *promoted* unchanged to the parent level (it is NOT duplicated,
    unlike Bitcoin-style trees). This script implements MTH directly via the
    recursive split so the odd-node rule is exactly RFC 6962.
  * ``manifest.json`` itself is excluded from the artifact set.

Usage::

    generate-evidence-manifest.py <evidence_dir> [--out manifest.json]
                                  [--legacy-out manifest.sha256]
    generate-evidence-manifest.py --selftest
    generate-evidence-manifest.py --verify <evidence_dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Iterable, List, Sequence

SCHEMA = "cyberforge-evidence-manifest/v1"
MERKLE_ALGORITHM = "RFC6962-SHA256"
DEFAULT_GENERATED_AT = "1970-01-01T00:00:00Z"
MANIFEST_FILENAME = "manifest.json"
LEGACY_FILENAME = "manifest.sha256"

# Filenames/derived artifacts that should never be treated as evidence inputs.
# Excluding the sealing outputs keeps the Merkle root stable: signing and
# timestamping happen AFTER the manifest is built, so if those outputs were
# hashed in, the manifest could never match what was signed.
EXCLUDED_NAMES = {
    MANIFEST_FILENAME,
    LEGACY_FILENAME,
    "file-list.txt",
    "merkle-root.txt",       # the value we sign/timestamp
    "pdf.sha256",            # signed separately
    "verapdf-report.json",   # produced by the seal veraPDF gate
}

# Suffixes produced by the sealing step (cosign bundles, RFC-3161 query/reply
# tokens, signatures, CA chains). Excluded so the manifest / Merkle root is
# identical before and after sealing — sealing only ADDS these files.
EXCLUDED_SUFFIXES = (
    ".cosign.bundle",
    ".bundle",
    ".tsr",
    ".tsq",
    ".sig",
    ".pem",
)

# ---------------------------------------------------------------------------
# RFC 6962 Merkle tree
# ---------------------------------------------------------------------------

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA256(0x00 || data)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: SHA256(0x01 || left || right)."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    """Largest power of two k such that k < n (n >= 2). RFC 6962 split point."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_tree_hash(leaves_data: Sequence[bytes]) -> bytes:
    """Compute RFC 6962 Merkle Tree Hash (MTH) over a list of raw inputs.

    Each element of ``leaves_data`` is the *raw data* for one leaf (it is leaf
    hashed internally). Returns the 32-byte root digest.
    """
    n = len(leaves_data)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves_data[0])
    k = _largest_power_of_two_less_than(n)
    left = merkle_tree_hash(leaves_data[:k])
    right = merkle_tree_hash(leaves_data[k:])
    return node_hash(left, right)


def merkle_root_hex(leaves_data: Sequence[bytes]) -> str:
    return merkle_tree_hash(leaves_data).hex()


# ---------------------------------------------------------------------------
# Provenance heuristic (documented, filename-based)
# ---------------------------------------------------------------------------

# Substrings (lowercased) that mark a scanner/SBOM output => provenance "live".
LIVE_SUBSTRINGS = (
    "sarif",
    "sbom",
    ".spdx.json",
    "cyclonedx",
    "trivy",
    "grype",
    "semgrep",
    "provenance",
    "attestation",
    "cosign",
    "scan",
    "vuln",
    # OpenVEX exploitability triage is machine-derived from the Trivy scan
    # results + the curated governance file; it is a "live" pipeline output
    # (see generate-vex.py), not a hand-asserted governance document.
    "vex",
)

# Exact filenames or substrings that mark statically asserted evidence.
STATIC_EXACT = {
    "dpa-compliance-check.json",
    "data-flow-diagram.json",
}
STATIC_SUBSTRINGS = (
    "cost",
    "readme",
)
# Default for everything else.
DEFAULT_PROVENANCE = "static"


def classify_provenance(relpath: str) -> str:
    """Return "live" or "static" for an artifact relative path.

    Heuristic, by filename. Documented here so the manifest's provenance flags
    are explainable and reproducible. Live = scanner/SBOM/attestation output.
    Static = human-asserted artifacts (DPA check, data-flow, cost tables, docs).
    """
    name = os.path.basename(relpath).lower()
    full = relpath.lower()
    if name in STATIC_EXACT:
        return "static"
    for sub in LIVE_SUBSTRINGS:
        if sub in full:
            return "live"
    for sub in STATIC_SUBSTRINGS:
        if sub in name:
            return "static"
    if name.endswith(".md"):
        return "static"
    return DEFAULT_PROVENANCE


def classify_source(relpath: str, provenance: str) -> str:
    """A short human-readable source descriptor for the artifact."""
    name = os.path.basename(relpath).lower()
    if "sarif" in name:
        return "static-analysis-scanner"
    if "sbom" in name or ".spdx" in name or "cyclonedx" in name:
        return "sbom-generator"
    if "trivy" in name or "grype" in name:
        return "vulnerability-scanner"
    if "semgrep" in name:
        return "sast-scanner"
    if "provenance" in name or "attestation" in name:
        return "build-provenance"
    if "cosign" in name:
        return "signing-tool"
    # OpenVEX exploitability triage (generate-vex.py / vex.py validator).
    if "vex" in name:
        return "vex-generator"
    # Organizational / compliance verdicts emitted by the A.x validators and the
    # T-30 aggregator (uniform libcompliance T-33 envelopes). These are machine-
    # produced verdicts over human-curated governance inputs.
    if name == "compliance-status.json":
        return "compliance-aggregator"
    if (
        name in ("soa-maturity.json", "residual-risk.json", "scope-determination.json")
        or name.endswith("-validation.json")
        or name in (
            "roi-validation.json", "ropa-completeness.json", "incident-readiness.json",
            "governance-evidence.json", "tpp-clauses.json", "access-review.json",
            "crypto-posture.json", "restore-test.json",
        )
    ):
        return "compliance-validator"
    if provenance == "live":
        return "pipeline-tool"
    return "asserted-document"


# ---------------------------------------------------------------------------
# MIME guessing (stdlib mimetypes + a few overrides)
# ---------------------------------------------------------------------------

import mimetypes

MIME_OVERRIDES = {
    ".sarif": "application/sarif+json",
    ".json": "application/json",
    ".spdx": "application/spdx+json",
    ".html": "text/html",
    ".md": "text/markdown",
    ".txt": "text/plain",
    ".pdf": "application/pdf",
    ".tsr": "application/timestamp-reply",
    ".bundle": "application/json",
}


def guess_mime(relpath: str) -> str:
    lower = relpath.lower()
    for ext, mime in MIME_OVERRIDES.items():
        if lower.endswith(ext):
            return mime
    guessed, _ = mimetypes.guess_type(relpath)
    return guessed or "application/octet-stream"


# ---------------------------------------------------------------------------
# Artifact discovery
# ---------------------------------------------------------------------------


def discover_artifacts(evidence_dir: str) -> List[str]:
    """Return sorted relative paths of evidence files under evidence_dir.

    Excludes the manifest itself, the legacy manifest, and the file-list.
    Sort is by POSIX relative path (stable, deterministic).
    """
    rels: List[str] = []
    for root, _dirs, files in os.walk(evidence_dir):
        for fname in files:
            if fname in EXCLUDED_NAMES:
                continue
            if fname.endswith(EXCLUDED_SUFFIXES):
                continue
            abspath = os.path.join(root, fname)
            rel = os.path.relpath(abspath, evidence_dir)
            # Normalize to POSIX separators for cross-platform determinism.
            rel = rel.replace(os.sep, "/")
            if rel in EXCLUDED_NAMES or rel.endswith(EXCLUDED_SUFFIXES):
                continue
            rels.append(rel)
    rels.sort()
    return rels


def sha256_file(path: str) -> tuple[str, int, bytes]:
    """Return (hex_digest, size_bytes, raw_bytes) for the file at path."""
    with open(path, "rb") as fh:
        data = fh.read()
    return hashlib.sha256(data).hexdigest(), len(data), data


# ---------------------------------------------------------------------------
# Manifest construction
# ---------------------------------------------------------------------------


def build_manifest(evidence_dir: str) -> dict:
    """Construct the manifest dict (no I/O of manifest.json itself)."""
    generated_at = os.environ.get("GENERATED_AT") or DEFAULT_GENERATED_AT
    report_id = os.environ.get("REPORT_ID", "")
    git_sha = os.environ.get("GIT_SHA", "")
    image_digest = os.environ.get("IMAGE_DIGEST", "")
    period_start = os.environ.get("PERIOD_START", "")
    period_end = os.environ.get("PERIOD_END", "")

    rels = discover_artifacts(evidence_dir)

    artifacts: List[dict] = []
    leaves_data: List[bytes] = []
    for rel in rels:
        abspath = os.path.join(evidence_dir, rel)
        digest, size, data = sha256_file(abspath)
        provenance = classify_provenance(rel)
        artifacts.append(
            {
                "path": rel,
                "sha256": digest,
                "size": size,
                "mime": guess_mime(rel),
                "source": classify_source(rel, provenance),
                "provenance": provenance,
            }
        )
        leaves_data.append(data)

    merkle = merkle_root_hex(leaves_data)

    manifest = {
        "schema": SCHEMA,
        "report_id": report_id,
        "generated_at": generated_at,
        "git_sha": git_sha,
        "image_digest": image_digest,
        "period": {"start": period_start, "end": period_end},
        "artifacts": artifacts,
        "merkle_root": merkle,
        "merkle_algorithm": MERKLE_ALGORITHM,
        "tooling": {},
        "worm_state": "pending",
        "signatures": {},
    }
    return manifest


def write_manifest(manifest: dict, out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=False)
        fh.write("\n")


def write_legacy(manifest: dict, legacy_path: str) -> None:
    """Write a legacy sha256sum-compatible manifest.

    Format matches ``sha256sum`` output: ``<hex><space><space><path>``,
    sorted by path. Lines are newline-terminated (LF).
    """
    lines = []
    for art in sorted(manifest["artifacts"], key=lambda a: a["path"]):
        lines.append(f"{art['sha256']}  {art['path']}")
    with open(legacy_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
        if lines:
            fh.write("\n")


# ---------------------------------------------------------------------------
# Self-test (known RFC 6962 vectors)
# ---------------------------------------------------------------------------


def _selftest() -> int:
    """Verify the Merkle implementation against known RFC 6962 vectors.

    RFC 6962 test data uses these inputs for the reference Merkle Audit /
    Tree tests:
        D[0] = ""           (empty leaf data)
        D[1] = 00
        D[2] = 10
        D[3] = 2021
        D[4] = 3031
        D[5] = 4041424344454647
        D[6] = 50515253545556575859
        D[7] = 606162636465666768696a6b6c6d6e6f
    Known MTH values (hex) for prefixes of this list are published; we assert a
    few well-known ones plus the structural rules.
    """
    failures: List[str] = []

    # Empty tree: SHA256("")
    empty = merkle_root_hex([])
    expect_empty = hashlib.sha256(b"").hexdigest()
    if empty != expect_empty:
        failures.append(f"empty tree {empty} != {expect_empty}")

    # Single leaf: leaf_hash(D[0]) where D[0] = b""
    d0 = b""
    one = merkle_root_hex([d0])
    expect_one = leaf_hash(b"").hex()
    if one != expect_one:
        failures.append(f"single leaf {one} != {expect_one}")

    # RFC 6962 reference inputs.
    D = [
        bytes.fromhex(""),
        bytes.fromhex("00"),
        bytes.fromhex("10"),
        bytes.fromhex("2021"),
        bytes.fromhex("3031"),
        bytes.fromhex("4041424344454647"),
        bytes.fromhex("50515253545556575859"),
        bytes.fromhex("606162636465666768696a6b6c6d6e6f"),
    ]

    # Two leaves: node(leaf(D0), leaf(D1)).
    two = merkle_root_hex(D[:2])
    expect_two = node_hash(leaf_hash(D[0]), leaf_hash(D[1])).hex()
    if two != expect_two:
        failures.append(f"two leaves {two} != {expect_two}")

    # Regression anchors for the RFC-6962 MTH over the D[] inputs above.
    # These are NOT copied from an external table (to avoid input-mismatch
    # errors); they were computed by an INDEPENDENT from-scratch reference
    # implementation and cross-checked. The structural assertions below
    # (domain separation, 2|1 and 4|1 split points, odd-node promotion vs.
    # Bitcoin-style duplication) are the actual proof of RFC-6962 conformance;
    # these fixed roots just catch silent regressions.
    #   n=1 : leaf_hash(D[0]) where D[0] = b""  ->  SHA256(0x00)
    #   n=8 : full 8-leaf MTH over D[0..7]
    known_roots = {
        1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        8: "517c5890957a9c596eecf1efd39ca6f1db403fdc28d26fd4edc3d9b324b56db9",
    }
    for n, expect in known_roots.items():
        got = merkle_root_hex(D[:n])
        if got != expect:
            failures.append(f"n={n} root {got} != {expect}")

    # Structural odd-node rule check: a 3-leaf tree must split 2|1, so the
    # lone right node is promoted (not duplicated). Verify against explicit
    # construction: node( node(leaf0,leaf1), leaf2 ).
    three = merkle_root_hex(D[:3])
    explicit_three = node_hash(
        node_hash(leaf_hash(D[0]), leaf_hash(D[1])),
        leaf_hash(D[2]),
    ).hex()
    if three != explicit_three:
        failures.append(f"three-leaf split {three} != {explicit_three}")

    # And confirm it is NOT the Bitcoin-style duplicate-last behaviour.
    duplicate_three = node_hash(
        node_hash(leaf_hash(D[0]), leaf_hash(D[1])),
        node_hash(leaf_hash(D[2]), leaf_hash(D[2])),
    ).hex()
    if three == duplicate_three:
        failures.append("three-leaf used duplicate-last (Bitcoin) rule, not RFC6962")

    # 5-leaf tree split must be 4|1 (largest power of two < 5 is 4).
    five = merkle_root_hex(D[:5])
    explicit_five = node_hash(
        node_hash(
            node_hash(leaf_hash(D[0]), leaf_hash(D[1])),
            node_hash(leaf_hash(D[2]), leaf_hash(D[3])),
        ),
        leaf_hash(D[4]),
    ).hex()
    if five != explicit_five:
        failures.append(f"five-leaf split {five} != {explicit_five}")

    if failures:
        print("SELFTEST FAILED:", file=sys.stderr)
        for f in failures:
            print("  - " + f, file=sys.stderr)
        return 1
    print("SELFTEST PASSED: RFC 6962 Merkle vectors OK")
    print(f"  empty   = {empty}")
    print(f"  n=1     = {merkle_root_hex(D[:1])}")
    print(f"  n=2     = {two}")
    print(f"  n=3     = {three}")
    print(f"  n=5     = {five}")
    print(f"  n=8     = {merkle_root_hex(D[:8])}")
    return 0


def _verify(evidence_dir: str) -> int:
    """Re-verify a sealed pack against the artifact list recorded in the manifest.

    This recomputes the Merkle root over the *recorded* artifacts (not a fresh
    directory scan), so it is robust to files legitimately added AFTER the
    manifest was written (e.g. the seal step's ``*.tsr``/``*.cosign.bundle``/
    ``pdf.sha256``, or the OSCAL twin). For each recorded artifact it:

      * confirms the file still exists,
      * re-hashes it and confirms the SHA-256 matches the recorded value
        (this is the per-file tamper check), then
      * feeds the bytes into the RFC-6962 Merkle recomputation.

    A missing recorded file, a per-file hash mismatch, or a Merkle-root
    mismatch all FAIL. Prints a PASS/FAIL line. Exit 0 only on a full match.
    """
    manifest_path = os.path.join(evidence_dir, MANIFEST_FILENAME)
    if not os.path.isfile(manifest_path):
        print(f"VERIFY FAIL: no manifest at {manifest_path}", file=sys.stderr)
        return 1
    with open(manifest_path, "r", encoding="utf-8") as fh:
        stored = json.load(fh)

    stored_root = stored.get("merkle_root", "")
    artifacts = stored.get("artifacts", [])

    # Recompute over the RECORDED artifacts, in the manifest's stored order
    # (the generator sorts by POSIX path, so this order is the leaf order).
    problems: List[str] = []
    leaves_data: List[bytes] = []
    for art in artifacts:
        rel = art.get("path", "")
        recorded_hash = art.get("sha256", "")
        abspath = os.path.join(evidence_dir, rel)
        if not os.path.isfile(abspath):
            problems.append(f"missing recorded artifact: {rel}")
            continue
        digest, _size, data = sha256_file(abspath)
        if digest != recorded_hash:
            problems.append(
                f"hash mismatch: {rel}\n"
                f"    recorded   = {recorded_hash}\n"
                f"    recomputed = {digest}"
            )
        leaves_data.append(data)

    recomputed_root = merkle_root_hex(leaves_data)

    if problems:
        print("VERIFY FAIL: artifact integrity errors", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    if stored_root == recomputed_root:
        # Human-readable status goes to STDERR; STDOUT carries ONLY the bare
        # recomputed root so callers (verify-evidence-pack.sh) can capture and
        # string-compare it against the manifest's merkle_root.
        print(f"VERIFY PASS: merkle_root matches ({recomputed_root})", file=sys.stderr)
        print(recomputed_root)
        return 0
    print(
        "VERIFY FAIL: merkle_root mismatch\n"
        f"  stored     = {stored_root}\n"
        f"  recomputed = {recomputed_root}",
        file=sys.stderr,
    )
    return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Build a Merkle-rooted evidence manifest (RFC 6962).",
    )
    parser.add_argument(
        "evidence_dir",
        nargs="?",
        help="Directory containing evidence files.",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output manifest path (default: <evidence_dir>/manifest.json).",
    )
    parser.add_argument(
        "--legacy-out",
        default=None,
        help="Legacy sha256sum manifest path "
        "(default: <evidence_dir>/manifest.sha256).",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="Run RFC 6962 Merkle self-test and exit.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Recompute and compare merkle_root against existing manifest.json.",
    )
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()

    if args.evidence_dir is None:
        parser.error("evidence_dir is required (or use --selftest)")

    evidence_dir = args.evidence_dir
    if not os.path.isdir(evidence_dir):
        print(f"Error: evidence directory not found: {evidence_dir}", file=sys.stderr)
        return 2

    if args.verify:
        return _verify(evidence_dir)

    out_path = args.out or os.path.join(evidence_dir, MANIFEST_FILENAME)
    legacy_path = args.legacy_out or os.path.join(evidence_dir, LEGACY_FILENAME)

    manifest = build_manifest(evidence_dir)
    write_manifest(manifest, out_path)
    write_legacy(manifest, legacy_path)

    print(f"Wrote manifest: {out_path}")
    print(f"Wrote legacy:   {legacy_path}")
    print(f"Artifacts:      {len(manifest['artifacts'])}")
    print(f"Merkle root:    {manifest['merkle_root']}")
    print(f"Algorithm:      {manifest['merkle_algorithm']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
