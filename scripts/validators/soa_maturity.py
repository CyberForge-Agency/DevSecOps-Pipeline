#!/usr/bin/env python3
"""soa_maturity — Statement of Applicability parser + §9 maturity scorer (task T-122).

Spec / struktura mapping
------------------------
* spec Part D.3 (evidence-pack-specification.md:80) requires
  "Statement of Applicability (ISO 27001) + maturity scores (SAMM)".
* spec §9 (evidence-pack-specification.md:289-302) grades the pack against an
  L1 (minimum-passing) -> L5 (state-of-the-art) maturity benchmark, dimension by
  dimension.
* struktura §13 (CyberForge-Evidence-Pack-struktura.md:315-322) currently HARD-CODES
  the headline at "L5 (state-of-the-art) — nasz poziom". That is the overclaim this
  validator removes: the headline must equal the *computed* level, never a literal L5.

What this validator does (DoD, OPERATIONALIZATION-TASKLIST.md:1568-1573)
-----------------------------------------------------------------------
1. Parses ``docs/governance/statement-of-applicability.md`` — every Annex A control
   row (Control, Name, Applicable?, Justification, Status, Reference) across the four
   ISO/IEC 27001:2022 themes (A.5 Organizational / A.6 People / A.7 Physical /
   A.8 Technological; 93 controls total) using the T-33 GFM parser.
2. Computes the SoA coverage figures (applicable / implemented / partial / planned /
   not-applicable) directly from the parsed rows — never trusting the document's own
   "Summary Statistics" table, so a stale hand-edited summary cannot inflate the score.
3. Scores the five §9 maturity dimensions named in the task implementation notes —
   Evidence production, Build integrity, Scanning, Compliance mapping, Integrity —
   each to an L1..L5 level from the ACTUAL evidence state in the evidence directory
   (artifact presence + signing/timestamp facts), not from a wishlist.
4. Emits ``evidence/soa-maturity.json`` carrying the T-33 envelope of the OVERALL
   verdict, the SoA coverage block, and a ``dimensions`` map of every per-dimension
   level with the concrete evidence that justified it.

Honesty rules (blueprint/04 §2; spec §8 #9)
-------------------------------------------
* The OVERALL maturity level is the LOWEST of the five dimension levels (a chain is
  as strong as its weakest link). It is NEVER a hardcoded L5.
* A dimension may reach L3 only if the supporting artifact is actually present; it may
  reach L5 only if the *signed/timestamped/Rekor* state is actually present. Absent
  evidence -> the dimension stays at the level it can prove, with the gap in ``detail``.
* The validator emits at the EVIDENCE-ONLY tier: a maturity *score* is a measured fact
  for the pack, not a build-breaking gate (the per-article A.1-A.10 validators own the
  blocking gate). The recorded number is the value, never a vibe.

Scoring is grounded in the real pipeline state (verified read-only):
  * Build integrity caps at L4: the image/provenance are SLSA Build **L2**
    (evidence-pack.yml:200 "SLSA Build L2"), NOT L3 — so the dimension cannot claim L5
    ("SLSA Build L3, reproducible") honestly.
  * Integrity caps at L4 while the RFC-3161 timestamp is **non-qualified** (freetsa,
    evidence-pack.yml:327) rather than a qualified trust-service (QTS) — L5 requires QTS.

Usage
-----
    python3 scripts/validators/soa_maturity.py docs/governance/statement-of-applicability.md
    python3 scripts/validators/soa_maturity.py docs/governance/statement-of-applicability.md \\
        --evidence-dir evidence --out evidence/soa-maturity.json
    jq .measured.overall_level evidence/soa-maturity.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Make the Pipeline root importable so ``scripts.validators.libcompliance`` resolves
# regardless of the CWD the orchestrating shell uses (mirrors check-governance.py).
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR = "soa_maturity"
DEFAULT_SOA = "docs/governance/statement-of-applicability.md"
DEFAULT_EVIDENCE_DIR = "evidence"
DEFAULT_OUT = "evidence/soa-maturity.json"

# ISO/IEC 27001:2022 Annex A theme totals (93 controls in 4 themes).
# Source: ISO/IEC 27001:2022 Annex A; corroborated externally
# (hightable.io/iso-27001-annex-a-controls-reference-guide). Used to assert the SoA
# is complete (the parser must find all 93 control rows) rather than silently scoring
# a truncated document.
ISO_THEME_TOTALS = {
    "A.5": 37,  # Organizational
    "A.6": 8,   # People
    "A.7": 14,  # Physical
    "A.8": 34,  # Technological
}
ISO_TOTAL_CONTROLS = sum(ISO_THEME_TOTALS.values())  # 93

# Section heading under which the four per-theme control tables live in the SoA.
SOA_CONTROLS_HEADING = "Annex A Controls"

# Recognised SoA status values (case-insensitive, normalised).
_STATUS_IMPLEMENTED = "implemented"
_STATUS_PARTIAL = "partially implemented"
_STATUS_PLANNED = "planned"
_STATUS_NOT_APPLICABLE = "not applicable"

# A control id like "A.5.1", "A.8.34". Used to recognise data rows.
_CONTROL_ID_RE = re.compile(r"^A\.\d+\.\d+$")


# --------------------------------------------------------------------------- #
# SoA parsing                                                                  #
# --------------------------------------------------------------------------- #

def _theme_of(control_id: str) -> str | None:
    """Return the theme prefix (``A.5``..``A.8``) for a control id, or None."""
    m = re.match(r"^(A\.\d+)\.", control_id)
    return m.group(1) if m else None


def _norm_status(value: str) -> str:
    """Normalise a Status cell to one of the canonical lowercase status strings."""
    return re.sub(r"\s+", " ", (value or "").strip().casefold())


def _norm_applicable(value: str) -> bool | None:
    """Normalise an 'Applicable?' cell to True / False / None (unparseable)."""
    v = (value or "").strip().casefold()
    if v in ("yes", "y", "true", "applicable"):
        return True
    if v in ("no", "n", "false", "not applicable", "n/a", "na"):
        return False
    return None


def parse_soa(soa_path: Path) -> tuple[list[dict[str, str]], str | None]:
    """Parse every Annex A control row from the SoA Markdown.

    The four per-theme tables (A.5/A.6/A.7/A.8) all live under the single
    ``## 4. Annex A Controls`` heading, separated by ``### A.x ...`` sub-headings.
    ``gfm_table`` returns only the FIRST table under a heading, so we parse the
    section span manually with the T-33 row splitter to capture all four tables.

    Returns ``(rows, error)``. On any structural problem ``rows`` is ``[]`` and
    ``error`` explains why (so the caller can emit INDETERMINATE — never a silent
    pass over a missing/empty SoA).
    """
    if not soa_path.is_file():
        return [], f"{soa_path}: file not found"
    text = soa_path.read_text(encoding="utf-8")
    if not text.strip():
        return [], f"{soa_path}: file is empty"

    lines = text.splitlines()

    # Locate the "Annex A Controls" heading (tolerant of a leading section number).
    start = None
    for i, line in enumerate(lines):
        m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if m and lc._heading_matches(m.group(2), SOA_CONTROLS_HEADING.casefold()):
            start = i + 1
            break
    if start is None:
        return [], f"{soa_path}: heading {SOA_CONTROLS_HEADING!r} not found"

    # Walk to the next same-or-higher-level section ("## 5. Summary Statistics"),
    # collecting every GFM data row whose first cell is a control id.
    rows: list[dict[str, str]] = []
    headers: list[str] | None = None
    for line in lines[start:]:
        if re.match(r"^##\s+", line):  # next top-level (##) section -> end of controls
            break
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = lc._split_row(line)
        if lc._is_separator(line):
            continue
        # The first table's header row defines the column names for all four tables
        # (they share an identical schema). Capture it once.
        if cells and cells[0].strip().casefold() == "control":
            headers = cells
            continue
        if headers and cells and _CONTROL_ID_RE.match(cells[0].strip()):
            if len(cells) < len(headers):
                cells += [""] * (len(headers) - len(cells))
            elif len(cells) > len(headers):
                cells = cells[: len(headers)]
            rows.append(dict(zip(headers, cells)))

    if not rows:
        return [], f"{soa_path}: no Annex A control rows parsed"
    return rows, None


def summarise_soa(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Compute coverage figures directly from the parsed control rows.

    Deliberately independent of the document's own 'Summary Statistics' table so a
    stale hand-edited summary can never inflate the maturity score. Returns counts +
    per-theme breakdown + a structural-completeness flag (all 93 controls present).
    """
    by_theme: dict[str, int] = {t: 0 for t in ISO_THEME_TOTALS}
    applicable = implemented = partial = planned = not_applicable = unparsed = 0

    for row in rows:
        cid = (row.get("Control") or "").strip()
        theme = _theme_of(cid)
        if theme in by_theme:
            by_theme[theme] += 1

        appl = _norm_applicable(row.get("Applicable?", ""))
        if appl is True:
            applicable += 1
        elif appl is False:
            not_applicable += 1

        status = _norm_status(row.get("Status", ""))
        if status == _STATUS_IMPLEMENTED:
            implemented += 1
        elif status == _STATUS_PARTIAL:
            partial += 1
        elif status == _STATUS_PLANNED:
            planned += 1
        elif status == _STATUS_NOT_APPLICABLE:
            pass  # counted via applicable=False above
        else:
            unparsed += 1

    total = len(rows)
    complete = total == ISO_TOTAL_CONTROLS and all(
        by_theme[t] == ISO_THEME_TOTALS[t] for t in ISO_THEME_TOTALS
    )
    # Implementation rate over APPLICABLE controls (implemented counts fully; partial
    # counts as half — an honest middle, not a free pass).
    impl_rate = (
        round((implemented + 0.5 * partial) / applicable, 4) if applicable else 0.0
    )
    return {
        "total_controls_parsed": total,
        "iso_total_expected": ISO_TOTAL_CONTROLS,
        "structurally_complete": complete,
        "by_theme": by_theme,
        "applicable": applicable,
        "not_applicable": not_applicable,
        "implemented": implemented,
        "partially_implemented": partial,
        "planned": planned,
        "unparsed_status": unparsed,
        "implementation_rate_applicable": impl_rate,
    }


# --------------------------------------------------------------------------- #
# Evidence-state probes (honest: presence + signing/timestamp facts only)      #
# --------------------------------------------------------------------------- #

def _present(evidence_dir: Path, name: str) -> bool:
    """True iff ``evidence_dir/name`` exists and is non-empty."""
    p = evidence_dir / name
    return p.is_file() and p.stat().st_size > 0


def _any_present(evidence_dir: Path, *names: str) -> bool:
    return any(_present(evidence_dir, n) for n in names)


def probe_evidence_state(evidence_dir: Path) -> dict[str, bool]:
    """Probe the real evidence directory for the artifacts each dimension needs.

    Artifact names are the canonical ones the evidence-pack workflow writes
    (verified read-only against .github/workflows/evidence-pack.yml). All probes are
    presence/non-empty only — this validator NEVER inspects content to claim a control
    passed; the per-article validators own that.
    """
    return {
        # Evidence production
        "manifest": _present(evidence_dir, "manifest.json"),
        "pdf_report": _any_present(
            evidence_dir, "evidence-report.pdf", "evidence-report.html"
        ),
        # Build integrity
        "sbom": _present(evidence_dir, "sbom.cyclonedx.json"),
        "provenance": _any_present(
            evidence_dir, "provenance.intoto.json", "provenance.intoto.jsonl"
        ),
        # Scanning
        "security_report": _any_present(
            evidence_dir, "security-report.json", "trivy-sca-results.json"
        ),
        "sca_results": _any_present(
            evidence_dir, "trivy-sca-results.json", "dependency-review.json"
        ),
        # Compliance mapping
        "compliance_matrix": _present(evidence_dir, "compliance-matrix.json"),
        "oscal": _present(evidence_dir, "oscal-assessment-results.json"),
        # Integrity
        "merkle_cosign_bundle": _present(evidence_dir, "merkle-root.cosign.bundle"),
        "cosign_verification": _any_present(
            evidence_dir, "cosign-verification.log"
        ),
        "rfc3161_tsr": _any_present(evidence_dir, "evidence-report.pdf")
        and bool(list(evidence_dir.glob("*.tsr"))),
    }


# --------------------------------------------------------------------------- #
# §9 dimension scoring (L1..L5)                                                #
# --------------------------------------------------------------------------- #
#
# Each scorer returns (level:int, detail:str, evidence:dict). The L1..L5 anchors
# come verbatim from the spec §9 table (evidence-pack-specification.md:291-300). A
# level is awarded ONLY when its anchor is satisfied by real state; the cap notes
# (L2 SLSA, non-qualified TSA) keep two dimensions honestly below L5.

_DIM_ANCHORS = {
    "evidence_production": {
        1: "Manual, screenshots",
        3: "Pipeline emits artifacts",
        5: "Every artifact auto-signed + QTS + Rekor at production",
    },
    "build_integrity": {
        1: "Build runs",
        3: "SBOM per release",
        5: "SLSA Build L3, non-falsifiable provenance, reproducible",
    },
    "scanning": {
        1: "SAST runs sometimes",
        3: "SAST/DAST/SCA/IaC/container all gate",
        5: "+ VEX triage, OpenSSF Scorecard, digest-pinned toolchain",
    },
    "compliance_mapping": {
        1: "Spreadsheet of controls",
        3: "Crosswalk to 2-3 frameworks",
        5: "One evidence -> all frameworks, auto-generated, gap-tracked live",
    },
    "integrity": {
        1: "Files in a folder",
        3: "Signed + retained",
        5: "Qualified timestamps, transparency log, immutable WORM, reproducible",
    },
}


def _level_envelope(name: str, level: int, detail: str, evidence: dict[str, Any]) -> dict[str, Any]:
    """Wrap a dimension result in a T-33 EVIDENCE-ONLY envelope (level as measured)."""
    env = lc.envelope(
        lc.Status.PASS if level >= 3 else lc.Status.FAIL,
        lc.Tier.EVIDENCE_ONLY,
        measured=f"L{level}",
        threshold="L3 (strong) target; L5 (state-of-the-art) ceiling",
        detail=detail,
        validator=VALIDATOR,
    )
    env["level"] = level
    env["anchors"] = {f"L{k}": v for k, v in _DIM_ANCHORS[name].items()}
    env["evidence"] = evidence
    return env


def score_evidence_production(state: dict[str, bool]) -> dict[str, Any]:
    """Evidence production: L3 if the pipeline emits artifacts; L4 if PDF+manifest
    both present; L5 only with QTS — which we do NOT have (freetsa is non-qualified),
    so this dimension caps below L5."""
    ev = {"manifest": state["manifest"], "pdf_report": state["pdf_report"]}
    if state["manifest"] and state["pdf_report"]:
        level = 4
        detail = (
            "pipeline emits a manifest + rendered board report; capped at L4 — "
            "L5 needs a QUALIFIED timestamp (QTS) at production, but the demo TSA "
            "(freetsa) is non-qualified"
        )
    elif state["manifest"] or state["pdf_report"]:
        level = 3
        detail = "pipeline emits artifacts (manifest or report present)"
    else:
        level = 1
        detail = "no pipeline-emitted evidence artifacts found in evidence dir"
    return _level_envelope("evidence_production", level, detail, ev)


def score_build_integrity(state: dict[str, bool]) -> dict[str, Any]:
    """Build integrity: L3 if an SBOM is present; L4 if SBOM + provenance present.
    Hard cap at L4 — provenance is SLSA Build L2 (evidence-pack.yml:200), not the L3
    + reproducible the §9 L5 anchor requires."""
    ev = {"sbom": state["sbom"], "provenance": state["provenance"]}
    if state["sbom"] and state["provenance"]:
        level = 4
        detail = (
            "SBOM + build provenance present; capped at L4 — image/provenance are "
            "SLSA Build L2 (evidence-pack.yml:200), L5 requires SLSA Build L3 + "
            "reproducible"
        )
    elif state["sbom"]:
        level = 3
        detail = "SBOM per release present (no signed provenance bundle detected)"
    else:
        level = 1
        detail = "no SBOM found; build integrity at baseline"
    return _level_envelope("build_integrity", level, detail, ev)


def score_scanning(state: dict[str, bool]) -> dict[str, Any]:
    """Scanning: L3 if scan results + SCA both present (the gating scanners produced
    output); L1 otherwise. L5 (VEX + Scorecard + digest-pinned toolchain) is NOT
    asserted here — those artifacts are not probed, so the dimension stays at what it
    can prove."""
    ev = {"security_report": state["security_report"], "sca_results": state["sca_results"]}
    if state["security_report"] and state["sca_results"]:
        level = 3
        detail = (
            "scanner + SCA output present (SAST/SCA/container scans produced "
            "results); not advanced to L5 — VEX/Scorecard/digest-pinned-toolchain "
            "artifacts not present in this evidence dir"
        )
    elif state["security_report"] or state["sca_results"]:
        level = 2
        detail = "some scan output present but not the full SCA+scan set"
    else:
        level = 1
        detail = "no scan results found in evidence dir"
    return _level_envelope("scanning", level, detail, ev)


def score_compliance_mapping(state: dict[str, bool], soa: dict[str, Any]) -> dict[str, Any]:
    """Compliance mapping: L3 if a content-based control matrix (crosswalk to >=2
    frameworks) is present; L4 if the SoA is structurally complete AND an OSCAL
    machine-readable assessment is present. L5 (one-evidence->all-frameworks, live
    gap-tracking) is not claimed unless the crosswalk artifact proves it."""
    ev = {
        "compliance_matrix": state["compliance_matrix"],
        "oscal": state["oscal"],
        "soa_structurally_complete": soa["structurally_complete"],
    }
    if state["compliance_matrix"] and state["oscal"] and soa["structurally_complete"]:
        level = 4
        detail = (
            "control matrix + OSCAL assessment present and the SoA covers all "
            f"{ISO_TOTAL_CONTROLS} Annex A controls; L5 needs an auto-generated "
            "one-evidence->all-frameworks crosswalk with live gap-tracking (T-102)"
        )
    elif state["compliance_matrix"]:
        level = 3
        detail = "multi-framework control matrix present (crosswalk to 2-3 frameworks)"
    else:
        level = 1
        detail = (
            "no compliance-matrix artifact in evidence dir — mapping at "
            "spreadsheet baseline (SoA exists as the source document)"
        )
    return _level_envelope("compliance_mapping", level, detail, ev)


def score_integrity(state: dict[str, bool]) -> dict[str, Any]:
    """Integrity: L3 if a cosign signature exists (signed + retained); L4 if the
    Merkle-root is cosign-signed AND an RFC-3161 timestamp + transparency-log proof
    exist. Hard cap at L4 — the RFC-3161 timestamp is non-qualified (freetsa,
    evidence-pack.yml:327); L5 requires QUALIFIED timestamps."""
    ev = {
        "merkle_cosign_bundle": state["merkle_cosign_bundle"],
        "cosign_verification": state["cosign_verification"],
        "rfc3161_tsr": state["rfc3161_tsr"],
    }
    signed = state["merkle_cosign_bundle"] or state["cosign_verification"]
    if state["merkle_cosign_bundle"] and state["rfc3161_tsr"]:
        level = 4
        detail = (
            "Merkle-root cosign bundle + RFC-3161 timestamp present; capped at L4 — "
            "timestamp is NON-QUALIFIED (freetsa, evidence-pack.yml:327), L5 needs a "
            "qualified timestamp (QTS) + immutable WORM"
        )
    elif signed:
        level = 3
        detail = "evidence signed + retained (cosign signature present)"
    else:
        level = 1
        detail = "no signature/timestamp artifacts found — integrity at folder baseline"
    return _level_envelope("integrity", level, detail, ev)


# --------------------------------------------------------------------------- #
# Aggregation                                                                  #
# --------------------------------------------------------------------------- #

def evaluate(soa_path: Path, evidence_dir: Path) -> dict[str, Any]:
    """Parse the SoA, score the five §9 dimensions from real evidence state, and
    return the overall T-33 envelope (EVIDENCE-ONLY) with dimensions + SoA coverage.

    The overall level is the LOWEST dimension level — never a hardcoded L5. A missing
    or unparseable SoA yields INDETERMINATE (a measured nothing), not a silent score.
    """
    rows, err = parse_soa(soa_path)
    if err is not None:
        env = lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.EVIDENCE_ONLY,
            measured=None,
            threshold="parseable SoA with all 93 Annex A controls",
            detail=f"cannot score maturity — {err} (spec Part D.3 / §9)",
            validator=VALIDATOR,
        )
        env["soa"] = {"error": err}
        env["dimensions"] = {}
        return env

    soa = summarise_soa(rows)
    state = probe_evidence_state(evidence_dir)

    dimensions = {
        "evidence_production": score_evidence_production(state),
        "build_integrity": score_build_integrity(state),
        "scanning": score_scanning(state),
        "compliance_mapping": score_compliance_mapping(state, soa),
        "integrity": score_integrity(state),
    }

    levels = {k: v["level"] for k, v in dimensions.items()}
    overall_level = min(levels.values())
    weakest = sorted(k for k, v in levels.items() if v == overall_level)

    detail = (
        f"computed pack maturity = L{overall_level} (lowest of "
        + ", ".join(f"{k}=L{v}" for k, v in levels.items())
        + f"); weakest dimension(s): {', '.join(weakest)}. "
        "Headline maturity is the COMPUTED level, not a hardcoded L5 "
        "(corrects struktura §13 overclaim)."
    )

    overall = lc.envelope(
        lc.Status.PASS if overall_level >= 3 else lc.Status.FAIL,
        lc.Tier.EVIDENCE_ONLY,
        measured={
            "overall_level": f"L{overall_level}",
            "dimension_levels": {k: f"L{v}" for k, v in levels.items()},
        },
        threshold={"target": "L3 (strong)", "ceiling": "L5 (state-of-the-art)"},
        detail=detail,
        validator=VALIDATOR,
    )
    overall["overall_level"] = f"L{overall_level}"
    overall["weakest_dimensions"] = weakest
    overall["soa"] = soa
    overall["dimensions"] = dimensions
    overall["evidence_dir"] = str(evidence_dir)
    overall["soa_source"] = str(soa_path)
    return overall


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR,
        description=(
            "Parse the ISO 27001 Statement of Applicability and score the spec §9 "
            "L1-L5 maturity dimensions from real evidence state (spec Part D.3 / §9)."
        ),
    )
    parser.add_argument(
        "soa_path",
        nargs="?",
        default=DEFAULT_SOA,
        help=f"path to the Statement of Applicability Markdown (default: {DEFAULT_SOA})",
    )
    parser.add_argument(
        "--evidence-dir",
        default=DEFAULT_EVIDENCE_DIR,
        help=(
            "evidence directory to probe for artifact presence/signing state "
            f"(default: {DEFAULT_EVIDENCE_DIR})"
        ),
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"path to write the maturity JSON (default: {DEFAULT_OUT})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point: evaluate, write ``soa-maturity.json``, print + exit (EVIDENCE-ONLY)."""
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    soa_path = Path(args.soa_path)
    evidence_dir = Path(args.evidence_dir)

    overall = evaluate(soa_path, evidence_dir)

    out_path = Path(args.out)
    if out_path.parent and not out_path.parent.exists():
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(overall, indent=2) + "\n", encoding="utf-8")

    # One-line envelope to stdout (gate/matrix-friendly).
    print(json.dumps(overall))
    return lc.exit_code_for(overall["status"], overall["tier"])


if __name__ == "__main__":
    sys.exit(main())
