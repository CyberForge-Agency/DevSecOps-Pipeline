#!/usr/bin/env python3
"""sarif_conformance.py — SARIF 2.1.0 conformance validator (task T-125).

A per-scanner-stage content validator that asserts a scanner artifact is a
conformant **SARIF 2.1.0** document (the format GitHub Code Scanning and the
pipeline's SARIF-consuming gates expect), and emits the shared T-33 envelope so
the compliance gate (T-30) aggregates a uniform, honest result.

What it asserts (BLOCKING)
--------------------------
1. The top-level ``version`` is exactly ``"2.1.0"``.
2. A top-level ``$schema`` is present (URI string) — SARIF documents SHOULD carry
   the schema URI; its absence is a conformance gap.
3. A minimal structural shape: ``runs`` is a list and each run carries a
   ``tool.driver`` (the OASIS SARIF 2.1.0 required core). When the ``jsonschema``
   package is available, the document is additionally validated against a small
   embedded SARIF-2.1.0 core schema; when it is not, the structural checks above
   still run (we say which path was taken in ``detail``).

Honesty boundary (blueprint/04 §2)
----------------------------------
* A genuine SARIF 2.1.0 doc that passes the checks -> ``PASS``.
* A wrong ``version`` (e.g. ``2.0.0``) -> ``FAIL`` (exit 1): a known-bad format is a
  deterministic conformance failure.
* An artifact that is **valid JSON but not SARIF at all** (e.g. Trivy *native* JSON,
  which has ``SchemaVersion`` / ``Results``, not ``version`` / ``runs``) is reported
  honestly as ``INDETERMINATE`` with ``measured.format`` reflecting *not-SARIF* —
  we never mislabel a non-SARIF artifact as a passing SARIF, nor fail-closed as if a
  scanner were broken; the caller decides whether SARIF was expected for that stage.
* A missing / empty / malformed-JSON artifact -> ``INDETERMINATE`` (measured nothing).

Per-stage usage
---------------
    # CodeQL emits SARIF natively:
    python3 scripts/validators/sarif_conformance.py codeql-results/javascript.sarif

    # Trivy can emit SARIF with --format sarif; label the stage:
    python3 scripts/validators/sarif_conformance.py trivy.sarif --stage trivy-image

    # Trivy NATIVE json (not SARIF) is reported as not-SARIF, not a fake pass:
    python3 scripts/validators/sarif_conformance.py trivy-sca-results.json --stage trivy-sca

Exit codes (via T-33): 0 PASS, 1 FAIL (BLOCKING), 2 INDETERMINATE.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# --- import the T-33 shared library (sibling module) ------------------------ #
sys.path.insert(0, str(Path(__file__).resolve().parent))
import libcompliance as lc  # noqa: E402  (path set above)

DEFAULT_OUT = "sarif-conformance.json"
TOOL_VERSION = "sarif_conformance/1.0 (T-125)"

REQUIRED_VERSION = "2.1.0"

# Minimal embedded SARIF 2.1.0 core schema — only the load-bearing constraints, so
# the check stays deterministic and false-positive-safe (it is NOT the full 4k-line
# OASIS schema, which would reject valid-but-extended docs). Used only when the
# optional `jsonschema` package is importable; the structural checks below run
# regardless.
_SARIF_CORE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["version", "runs"],
    "properties": {
        "version": {"const": REQUIRED_VERSION},
        "$schema": {"type": "string"},
        "runs": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tool"],
                "properties": {
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {"name": {"type": "string"}},
                            }
                        },
                    },
                    "results": {"type": "array"},
                },
            },
        },
    },
}


def _looks_like_other_format(doc: dict[str, Any]) -> str | None:
    """Name a recognised NON-SARIF JSON format, or None.

    Lets us report honestly that an artifact is e.g. Trivy native JSON rather than
    mislabelling it as a failed SARIF.
    """
    if "SchemaVersion" in doc and ("Results" in doc or "ArtifactName" in doc):
        return "trivy-native-json"
    if "vulnerabilities" in doc and "version" not in doc:
        return "non-sarif-json (has 'vulnerabilities', no 'version')"
    return None


def _schema_validate(doc: dict[str, Any]) -> tuple[bool, str]:
    """Validate ``doc`` against the embedded core schema if jsonschema is present.

    Returns ``(used, message)``. ``used`` is False when jsonschema is unavailable
    (the structural checks still cover the load-bearing constraints).
    """
    try:
        import jsonschema  # type: ignore
    except ImportError:  # pragma: no cover - depends on runner
        return False, "jsonschema not installed; structural checks only"
    try:
        jsonschema.validate(instance=doc, schema=_SARIF_CORE_SCHEMA)
    except jsonschema.ValidationError as exc:  # type: ignore[attr-defined]
        # First line keeps the detail concise.
        return True, f"schema invalid: {str(exc).splitlines()[0]}"
    return True, "schema valid (embedded SARIF 2.1.0 core)"


def assess(doc: Any, stage: str | None) -> dict[str, Any]:
    """Assess a parsed JSON document for SARIF 2.1.0 conformance -> T-33 envelope."""
    label = f"stage={stage}; " if stage else ""

    if not isinstance(doc, dict):
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured={"format": "not-an-object"}, threshold={"version": REQUIRED_VERSION},
            detail=f"{label}top-level JSON is not an object (not a SARIF document)",
            tool_version=TOOL_VERSION,
        )

    version = doc.get("version")
    has_schema = isinstance(doc.get("$schema"), str) and bool(doc.get("$schema"))
    runs = doc.get("runs")

    # Not SARIF at all -> INDETERMINATE (honest format report), never a fake pass.
    other = _looks_like_other_format(doc)
    if version is None and runs is None:
        fmt = other or "unknown-non-sarif"
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured={"format": fmt, "version": None, "has_schema": has_schema},
            threshold={"version": REQUIRED_VERSION},
            detail=(
                f"{label}artifact is not SARIF (no top-level 'version'/'runs'); "
                f"detected format: {fmt}. Report-only — caller decides if SARIF "
                "was expected for this stage."
            ),
            tool_version=TOOL_VERSION,
        )

    # Wrong version -> deterministic FAIL.
    if version != REQUIRED_VERSION:
        return lc.envelope(
            lc.Status.FAIL, lc.Tier.BLOCKING,
            measured={"format": "sarif?", "version": version, "has_schema": has_schema},
            threshold={"version": REQUIRED_VERSION},
            detail=(
                f"{label}SARIF version {version!r} != required {REQUIRED_VERSION!r}"
            ),
            tool_version=TOOL_VERSION,
        )

    # Structural: runs must be a list with tool.driver.name on each run.
    structural_problems: list[str] = []
    if not isinstance(runs, list):
        structural_problems.append("'runs' is not an array")
    else:
        for i, run in enumerate(runs):
            if not isinstance(run, dict):
                structural_problems.append(f"runs[{i}] is not an object")
                continue
            driver = (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else None
            if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
                structural_problems.append(f"runs[{i}].tool.driver.name missing")

    schema_used, schema_msg = _schema_validate(doc)
    if schema_used and schema_msg.startswith("schema invalid"):
        structural_problems.append(schema_msg)

    run_count = len(runs) if isinstance(runs, list) else 0
    result_count = 0
    if isinstance(runs, list):
        for run in runs:
            if isinstance(run, dict) and isinstance(run.get("results"), list):
                result_count += len(run["results"])

    measured = {
        "format": "sarif",
        "version": version,
        "has_schema": has_schema,
        "runs": run_count,
        "results": result_count,
        "schema_check": schema_msg,
    }
    threshold = {"version": REQUIRED_VERSION, "schema_present": True}

    if structural_problems:
        return lc.envelope(
            lc.Status.FAIL, lc.Tier.BLOCKING,
            measured=measured, threshold=threshold,
            detail=f"{label}SARIF 2.1.0 structural problems: " + "; ".join(structural_problems),
            tool_version=TOOL_VERSION,
        )
    if not has_schema:
        # version+structure OK but no $schema URI -> conformance gap, FAIL closed.
        return lc.envelope(
            lc.Status.FAIL, lc.Tier.BLOCKING,
            measured=measured, threshold=threshold,
            detail=(
                f"{label}SARIF version {REQUIRED_VERSION} and structure OK, but top-level "
                "'$schema' is missing (required by this gate for conformance)"
            ),
            tool_version=TOOL_VERSION,
        )

    return lc.envelope(
        lc.Status.PASS, lc.Tier.BLOCKING,
        measured=measured, threshold=threshold,
        detail=(
            f"{label}conformant SARIF {REQUIRED_VERSION}: $schema present, {run_count} run(s), "
            f"{result_count} result(s); {schema_msg}"
        ),
        tool_version=TOOL_VERSION,
    )


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def _finish(env: dict[str, Any], out_path: str) -> int:
    try:
        Path(out_path).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem edge
        print(f"warning: could not write {out_path}: {exc}", file=sys.stderr)
    print(json.dumps(env))
    return lc.exit_code_for(env["status"], env["tier"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SARIF 2.1.0 conformance (T-125)")
    parser.add_argument("sarif", help="path to a scanner artifact (SARIF or other JSON)")
    parser.add_argument(
        "--stage",
        default=None,
        help="scanner stage label for traceability (e.g. codeql, trivy-image, trivy-sca)",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"write the envelope to this path too (default: {DEFAULT_OUT})",
    )
    args = parser.parse_args(argv)

    doc, jerr = lc.load_json(args.sarif)
    if jerr is not None:
        env = lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured={"format": "unreadable"}, threshold={"version": REQUIRED_VERSION},
            detail=f"{('stage=' + args.stage + '; ') if args.stage else ''}{jerr}",
            tool_version=TOOL_VERSION,
        )
        return _finish(env, args.out)

    env = assess(doc, args.stage)
    return _finish(env, args.out)


if __name__ == "__main__":
    sys.exit(main())
