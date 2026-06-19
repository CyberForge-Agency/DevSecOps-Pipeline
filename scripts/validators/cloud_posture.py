#!/usr/bin/env python3
"""cloud_posture.py — CIS-mapped cloud-posture (CSPM) statement (T-117, honest relabel).

Spec mapping
------------
Evidence Pack master spec Part C.14 "CSPM posture" (``evidence-pack-specification.md:149``)
and §4 stage "Runtime / cloud posture" (``evidence-pack-specification.md:198``, which
REJECTS a point-in-time audit-week screenshot). The honest scope, the design-stage relabel
decision, and the exact validator contract are pre-described in
``docs/compliance/cspm-posture.md`` §5.3 — this validator implements that contract.

The honest T-117 decision (cspm-posture.md §1, §5)
--------------------------------------------------
No continuous CSPM tool (Prowler / Cloud Custodian / Microsoft Defender for Cloud) runs
against the deployed Azure subscription, and no ``evidence/cloud-posture.json`` is produced
or signed today. CSPM is *runtime* posture of the *deployed* tenant + drift detection —
distinct from the pre-deploy Checkov IaC scan, which cannot see drift (cspm-posture.md §2).

This validator therefore takes the DESIGN-STAGE path **honestly**:

* If a real scan artifact (``cloud-posture.json``) IS present and parseable, it parses it
  and emits ``summary.critical`` as the measured CRITICAL-misconfig count, PASS iff a scan
  actually ran AND ``critical == 0`` (BLOCKING by default, per cspm-posture.md §5.3).
* If NO scan artifact exists, it confirms the design-stage posture doc is present and
  returns an **EVIDENCE-tier INDETERMINATE** ("design-stage / not-yet-scanned") — it
  NEVER fabricates a CIS PASS from the static IaC mapping. Absence of a live scan is
  honestly "not measured", which is the CORRECT result here.

Why EVIDENCE-ONLY tier when there is no scan
--------------------------------------------
A missing live CSPM scan is a known, documented design-stage gap (cspm-posture.md §6 #1) —
it must be *recorded* (so the matrix shows "design-stage / not-yet-scanned"), but it must
NOT break the build today (that wiring is post-M0 target-state). So the no-scan path is
EVIDENCE-ONLY/INDETERMINATE: honest, recorded, non-blocking. A *present* scan with a
CRITICAL finding IS BLOCKING.

What it does NOT claim (honesty / libcompliance.py:9-11)
--------------------------------------------------------
With no live scan it claims NOTHING about the running tenant's CIS posture — not a PASS,
not even a count. The static IaC-derived CIS table in cspm-posture.md §4 is design-stage
context for humans, deliberately NOT consumed here as a pass signal.

Usage:
    cloud_posture.py [CLOUD_POSTURE_JSON] [--doc PATH] [--blocking] [--out FILE]
    Defaults: evidence/cloud-posture.json, docs/compliance/cspm-posture.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable regardless of cwd.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "cloud_posture"
DEFAULT_SCAN = "evidence/cloud-posture.json"
DEFAULT_DOC = "docs/compliance/cspm-posture.md"
DEFAULT_OUT = "cloud-posture-validation.json"

# CIS Microsoft Azure Foundations Benchmark version the scan/doc target.
CIS_BENCHMARK = "CIS Microsoft Azure Foundations Benchmark v3.0.0"


def _resolve(path_str: str) -> Path:
    """Resolve a path arg: use as-is if it exists, else relative to the Pipeline root."""
    p = Path(path_str)
    if p.is_file():
        return p
    candidate = PIPELINE_ROOT / path_str
    return candidate if candidate.is_file() else p


def _tool_version() -> str | None:
    """Parsed (not hardcoded) Python version for traceability (pure-stdlib parser)."""
    return f"python {sys.version.split()[0]}"


def _validate_scan(scan_path: Path, blocking: bool) -> dict[str, Any]:
    """Parse a real ``cloud-posture.json`` and emit the measured-CRITICAL envelope.

    PASS iff a scan actually ran AND ``summary.critical == 0``. A non-zero CRITICAL count
    FAILs. Tier is BLOCKING for production runs (``--blocking``), EVIDENCE-ONLY otherwise.
    """
    tier = lc.Tier.BLOCKING if blocking else lc.Tier.EVIDENCE_ONLY
    tv = _tool_version()
    threshold = {"critical": 0, "requires": "a live CSPM scan to have run"}

    data, err = lc.load_json(scan_path)
    if err is not None:
        # A path was given but the artifact is missing/empty/malformed -> INDETERMINATE.
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold=threshold,
            detail=f"cloud-posture scan not measurable: {err}", tool_version=tv,
            validator=VALIDATOR_NAME,
        )
    if not isinstance(data, dict):
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold=threshold,
            detail=f"{scan_path}: top-level cloud-posture must be a JSON object",
            tool_version=tv, validator=VALIDATOR_NAME,
        )

    summary = data.get("summary")
    if not isinstance(summary, dict) or "critical" not in summary:
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold=threshold,
            detail=f"{scan_path}: missing summary.critical — cannot measure CRITICAL count",
            tool_version=tv, validator=VALIDATOR_NAME,
        )
    critical = summary.get("critical")
    if not isinstance(critical, int) or isinstance(critical, bool):
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=critical, threshold=threshold,
            detail=f"{scan_path}: summary.critical is not an integer count",
            tool_version=tv, validator=VALIDATOR_NAME,
        )

    scanner = data.get("scanner")
    scanned_at = data.get("scanned_at")
    rows = data.get("rows") if isinstance(data.get("rows"), list) else []
    measured = {
        "critical": critical,
        "summary": summary,
        "scanner": scanner,
        "scanner_version": data.get("scanner_version"),
        "compliance": data.get("compliance"),
        "scanned_at": scanned_at,
        "rows": len(rows),
        "scan_present": True,
    }

    status = lc.Status.PASS if critical == 0 else lc.Status.FAIL
    detail = (
        f"live CSPM scan ({scanner} @ {scanned_at}): {critical} CRITICAL misconfig(s) "
        f"across {len(rows)} CIS row(s); {CIS_BENCHMARK}. "
        f"{'PASS — 0 CRITICAL.' if status == lc.Status.PASS else 'FAIL — CRITICAL exposure present.'}"
    )
    return lc.envelope(
        status, tier, measured=measured, threshold=threshold,
        detail=detail, tool_version=tv, validator=VALIDATOR_NAME,
    )


def _design_stage(doc_path: Path) -> dict[str, Any]:
    """No live scan exists: emit the honest EVIDENCE-tier 'design-stage' INDETERMINATE.

    NEVER a fabricated CIS PASS. The static IaC-derived table in the posture doc is
    design-stage context only and is deliberately NOT consumed as a pass signal.
    """
    tier = lc.Tier.EVIDENCE_ONLY  # recorded, non-blocking (design-stage gap, cspm §6 #1)
    tv = _tool_version()
    threshold = {"requires": "a live CSPM scan producing cloud-posture.json"}

    doc_present = doc_path.is_file() and doc_path.stat().st_size > 0
    measured = {
        "posture": "design-stage / not-yet-scanned",
        "scan_present": False,
        "posture_doc": str(doc_path) if doc_present else None,
        "posture_doc_present": doc_present,
        "cis_benchmark": CIS_BENCHMARK,
    }
    doc_note = (
        f"design-stage posture documented at {doc_path}"
        if doc_present
        else f"design-stage posture doc {doc_path} not found"
    )
    return lc.envelope(
        lc.Status.INDETERMINATE, tier, measured=measured, threshold=threshold,
        detail=(
            f"CSPM design-stage / not-yet-scanned: no live CSPM scan and no "
            f"cloud-posture.json present; {doc_note}. Reporting INDETERMINATE "
            f"(EVIDENCE-ONLY) — the static IaC-derived CIS mapping is design-stage "
            f"context and is NOT a fabricated CIS PASS (cspm-posture.md §1, §5, §6 #1). "
            f"Continuous scan + drift alerting are TARGET-STATE."
        ),
        tool_version=tv, validator=VALIDATOR_NAME,
    )


def validate(scan_path: Path, doc_path: Path, *, blocking: bool = False) -> dict[str, Any]:
    """Run the T-117 check and return a ready T-33 envelope (no exit).

    If a real scan artifact exists -> parse it (measured CRITICAL count). Otherwise ->
    honest EVIDENCE-tier 'design-stage' INDETERMINATE; never a fabricated CIS PASS.
    """
    if scan_path.is_file() and scan_path.stat().st_size > 0:
        return _validate_scan(scan_path, blocking)
    return _design_stage(doc_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CIS-mapped cloud-posture (CSPM) statement — honest design-stage relabel (T-117)."
    )
    parser.add_argument("scan", nargs="?", default=DEFAULT_SCAN, help="path to cloud-posture.json (live scan)")
    parser.add_argument("--doc", default=DEFAULT_DOC, help="path to the design-stage posture doc")
    parser.add_argument(
        "--blocking", action="store_true",
        help="treat a present-scan result as BLOCKING (production runs); default EVIDENCE-ONLY",
    )
    parser.add_argument("--out", default=DEFAULT_OUT, help="output envelope JSON path")
    args = parser.parse_args(argv)

    # Resolve the scan path WITHOUT requiring it to exist (absence is the honest path).
    scan_path = Path(args.scan)
    if not scan_path.is_file():
        candidate = PIPELINE_ROOT / args.scan
        scan_path = candidate if candidate.is_file() else scan_path

    env = validate(scan_path, _resolve(args.doc), blocking=args.blocking)
    try:
        Path(args.out).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"warning: could not write {args.out}: {exc}", file=sys.stderr)

    print(json.dumps(env))
    return lc.exit_code_for(env["status"], env["tier"])


if __name__ == "__main__":
    sys.exit(main())
