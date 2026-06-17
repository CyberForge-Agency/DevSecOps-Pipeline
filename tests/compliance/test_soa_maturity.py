"""Unit tests for the SoA maturity scorer (task T-122).

Proves the DoD + acceptance criteria (OPERATIONALIZATION-TASKLIST.md:1568-1573):
  * The validator parses ALL 93 Annex A controls of the real SoA, with the correct
    per-theme split (37/8/14/34) and ``structurally_complete == True``.
  * Coverage figures are recomputed from the rows (not the document's stale summary).
  * ``soa-maturity.json`` scores each of the five §9 dimensions from real evidence
    state — an EMPTY evidence dir yields every dimension at L1 (no silent high score).
  * The headline level is the COMPUTED minimum of the dimensions, never a hardcoded L5;
    with a fully-populated evidence dir NO dimension reaches L5 (SLSA-L2 + non-qualified
    TSA caps hold at L4) and the overall is L3 (scanning ceiling).
  * A missing/unparseable SoA yields INDETERMINATE (a measured nothing), not a score.
  * The output carries the T-33 envelope key set and is JSON-serialisable.

Runs under pytest AND standalone (``python3 tests/compliance/test_soa_maturity.py``)
so it is verifiable even where pytest is not installed — mirrors test_check_governance.py.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

# Load the dashed-or-underscored validator module by path (its name is importable as a
# normal module here, but load explicitly to be robust to either naming).
_SPEC = importlib.util.spec_from_file_location(
    "soa_maturity",
    PIPELINE_ROOT / "scripts" / "validators" / "soa_maturity.py",
)
soa = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(soa)  # type: ignore[union-attr]

REAL_SOA = PIPELINE_ROOT / "docs" / "governance" / "statement-of-applicability.md"

# Canonical artifact set that lifts every dimension to its honest ceiling.
_FULL_EVIDENCE = (
    "manifest.json",
    "evidence-report.pdf",
    "sbom.cyclonedx.json",
    "provenance.intoto.json",
    "security-report.json",
    "trivy-sca-results.json",
    "dependency-review.json",
    "compliance-matrix.json",
    "oscal-assessment-results.json",
    "merkle-root.cosign.bundle",
    "cosign-verification.log",
    "evidence-report.tsr",
)


def _populate(evidence_dir: Path, names) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for n in names:
        (evidence_dir / n).write_text("x", encoding="utf-8")


def _synthetic_soa(rows: list[tuple[str, str, str]], stale_summary: str = "") -> str:
    """Build a minimal SoA doc whose row counts can be controlled independently of
    any (deliberately stale) Summary Statistics table.

    Each row is ``(control_id, applicable, status)``; the validator recomputes the
    coverage figures from these rows and must NOT trust ``stale_summary``.
    """
    lines = [
        "# Statement of Applicability",
        "",
        "## 4. Annex A Controls",
        "",
        "### A.5 Organizational Controls",
        "",
        "| Control | Name | Applicable? | Justification | Status | Reference |",
        "|---------|------|-------------|---------------|--------|-----------|",
    ]
    for cid, appl, status in rows:
        lines.append(f"| {cid} | Name {cid} | {appl} | because | {status} | `docs/` |")
    lines += ["", "## 5. Summary Statistics", "", stale_summary, ""]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# SoA parsing                                                                  #
# --------------------------------------------------------------------------- #

def test_parses_all_93_controls_with_theme_split():
    rows, err = soa.parse_soa(REAL_SOA)
    assert err is None, err
    assert len(rows) == 93
    summary = soa.summarise_soa(rows)
    assert summary["structurally_complete"] is True
    assert summary["by_theme"] == {"A.5": 37, "A.6": 8, "A.7": 14, "A.8": 34}
    assert summary["total_controls_parsed"] == 93


def test_coverage_recomputed_from_rows_not_summary():
    """Coverage is recomputed from the rows, NOT read from the doc's Summary table.

    Uses a SYNTHETIC SoA whose ``## 5. Summary Statistics`` block lies (claims 99
    implemented). The validator must report the row-derived counts and ignore the
    stale summary — this proves the anti-inflation behaviour without pinning the
    test to the live document's (evolving) implemented/partial split.
    """
    rows = [
        ("A.5.1", "Yes", "Implemented"),
        ("A.5.2", "Yes", "Implemented"),
        ("A.5.3", "Yes", "Partially Implemented"),
        ("A.5.4", "Yes", "Planned"),
        ("A.5.5", "No", "Not Applicable"),
    ]
    stale = (
        "| Implemented | Partial | Planned | Not Applicable |\n"
        "|---|---|---|---|\n"
        "| 99 | 88 | 77 | 66 |\n"  # deliberately wrong: must be ignored
    )
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        doc = Path(d) / "soa.md"
        doc.write_text(_synthetic_soa(rows, stale_summary=stale), encoding="utf-8")
        parsed, err = soa.parse_soa(doc)
        assert err is None, err
        summary = soa.summarise_soa(parsed)
    # Recomputed honestly from the 5 actual rows, NOT the lying summary (99/88/77/66).
    assert summary["applicable"] == 4
    assert summary["not_applicable"] == 1
    assert summary["implemented"] == 2
    assert summary["partially_implemented"] == 1
    assert summary["planned"] == 1
    assert summary["unparsed_status"] == 0
    # Implementation rate over applicable: (2 + 0.5*1) / 4 = 0.625.
    assert summary["implementation_rate_applicable"] == 0.625
    assert 0.0 < summary["implementation_rate_applicable"] <= 1.0


def test_real_soa_counts_are_internally_consistent():
    """Drift-proof live-data invariant: the recomputed counts must reconcile.

    Rather than pinning the exact implemented/partial split (which evolves as the
    governance doc is maintained), assert the row-derived figures stay internally
    consistent: applicable + not_applicable == 93, every status bucket reconciles to
    the applicable total, and the implementation rate stays in (0, 1].
    """
    rows, err = soa.parse_soa(REAL_SOA)
    assert err is None, err
    summary = soa.summarise_soa(rows)
    assert summary["applicable"] + summary["not_applicable"] == 93
    # Implemented + partial + planned + unparsed == applicable (NA is the other bucket).
    assert (
        summary["implemented"]
        + summary["partially_implemented"]
        + summary["planned"]
        + summary["unparsed_status"]
        == summary["applicable"]
    )
    assert summary["unparsed_status"] == 0
    assert 0.0 < summary["implementation_rate_applicable"] <= 1.0


# --------------------------------------------------------------------------- #
# Maturity scoring: empty evidence -> L1 everywhere (no silent high score)     #
# --------------------------------------------------------------------------- #

def test_empty_evidence_scores_l1_everywhere(tmp_path):
    out = soa.evaluate(REAL_SOA, tmp_path / "no-evidence")
    assert out["overall_level"] == "L1"
    for dim in out["dimensions"].values():
        assert dim["level"] == 1
    # SoA coverage still parsed even with no evidence artifacts.
    assert out["soa"]["structurally_complete"] is True


# --------------------------------------------------------------------------- #
# Maturity scoring: full evidence -> NO L5, overall is the computed minimum    #
# --------------------------------------------------------------------------- #

def test_full_evidence_never_reaches_l5(tmp_path):
    ev = tmp_path / "evidence"
    _populate(ev, _FULL_EVIDENCE)
    out = soa.evaluate(REAL_SOA, ev)
    levels = {k: v["level"] for k, v in out["dimensions"].items()}
    # No dimension may claim L5: SLSA Build L2 + non-qualified TSA cap at L4;
    # scanning caps at L3 (no VEX/Scorecard probe).
    assert max(levels.values()) <= 4, levels
    assert levels["scanning"] == 3
    # Overall headline is the COMPUTED minimum, never a hardcoded L5.
    assert out["overall_level"] == f"L{min(levels.values())}"
    assert out["overall_level"] == "L3"
    assert out["weakest_dimensions"] == ["scanning"]


def test_overall_is_minimum_of_dimensions(tmp_path):
    # Provide everything EXCEPT scan output -> scanning drops to L1, dragging overall.
    ev = tmp_path / "evidence"
    _populate(
        ev,
        [n for n in _FULL_EVIDENCE if n not in ("security-report.json", "trivy-sca-results.json", "dependency-review.json")],
    )
    out = soa.evaluate(REAL_SOA, ev)
    assert out["dimensions"]["scanning"]["level"] == 1
    assert out["overall_level"] == "L1"


# --------------------------------------------------------------------------- #
# Missing / unparseable SoA -> INDETERMINATE, not a score                      #
# --------------------------------------------------------------------------- #

def test_missing_soa_is_indeterminate(tmp_path):
    out = soa.evaluate(tmp_path / "does-not-exist.md", tmp_path / "evidence")
    assert out["status"] == lc.Status.INDETERMINATE
    assert out["measured"] is None
    assert out["dimensions"] == {}


def test_empty_soa_is_indeterminate(tmp_path):
    empty = tmp_path / "empty.md"
    empty.write_text("", encoding="utf-8")
    out = soa.evaluate(empty, tmp_path / "evidence")
    assert out["status"] == lc.Status.INDETERMINATE


def test_soa_without_control_rows_is_indeterminate(tmp_path):
    noctrl = tmp_path / "noctrl.md"
    noctrl.write_text("# SoA\n\n## 4. Annex A Controls\n\nno table here\n", encoding="utf-8")
    out = soa.evaluate(noctrl, tmp_path / "evidence")
    assert out["status"] == lc.Status.INDETERMINATE


# --------------------------------------------------------------------------- #
# Envelope shape + tier (EVIDENCE-ONLY never breaks the build)                 #
# --------------------------------------------------------------------------- #

def test_output_carries_t33_envelope_keys(tmp_path):
    out = soa.evaluate(REAL_SOA, tmp_path / "evidence")
    assert set(lc.ENVELOPE_KEYS).issubset(set(out))
    assert out["tier"] == lc.Tier.EVIDENCE_ONLY
    # EVIDENCE-ONLY always exits 0 regardless of status (it's a measured fact, not a gate).
    assert lc.exit_code_for(out["status"], out["tier"]) == 0
    assert isinstance(json.dumps(out), str)


# --------------------------------------------------------------------------- #
# Standalone runner (no pytest required)                                       #
# --------------------------------------------------------------------------- #

def _run_standalone() -> int:
    import tempfile

    tests = [
        test_parses_all_93_controls_with_theme_split,
        test_coverage_recomputed_from_rows_not_summary,
        test_real_soa_counts_are_internally_consistent,
    ]
    tmp_tests = [
        test_empty_evidence_scores_l1_everywhere,
        test_full_evidence_never_reaches_l5,
        test_overall_is_minimum_of_dimensions,
        test_missing_soa_is_indeterminate,
        test_empty_soa_is_indeterminate,
        test_soa_without_control_rows_is_indeterminate,
        test_output_carries_t33_envelope_keys,
    ]
    failures: list[str] = []
    for t in tests:
        try:
            t()
        except AssertionError as exc:  # noqa: PERF203
            failures.append(f"{t.__name__}: {exc}")
    for t in tmp_tests:
        try:
            with tempfile.TemporaryDirectory() as d:
                t(Path(d))
        except AssertionError as exc:
            failures.append(f"{t.__name__}: {exc}")
    if failures:
        print("STANDALONE FAIL:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1
    print(f"STANDALONE PASS: {len(tests) + len(tmp_tests)} tests")
    return 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
