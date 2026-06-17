#!/usr/bin/env python3
"""dora_16_1_c — DORA Art.16.1.c content validator (T-14).

Replaces the file-presence row that trusted a renamed ``cp`` of the SCA results.

The lie this closes (blueprint/04 §1.5/§3.2; blueprint/06 K3)
------------------------------------------------------------
The DORA Art.16.1.c ("updated systems") matrix row was fed by
``dependency-review.json``, which is literally ``cp trivy-sca-results.json`` and
then relabelled a "dependency review". File-presence over that copy meant the row
PASSed even if the SCA gate had been silently weakened or a CVE waiver had been
slipped into ``.trivyignore`` with no justification. The honest claim is:

    "SCA ran with a blocking CRITICAL+HIGH severity gate AND the suppression
     policy contains 0 unjustified/expired waivers AND the dependency-review
     artifact is a real Trivy report (not an arbitrary copy)."

What this validator asserts (all three must hold for PASS; tier BLOCKING)
------------------------------------------------------------------------
  (a) ``trivy-sca-summary.json.severity_filter`` includes **CRITICAL and HIGH**
      (the gate actually blocks the severities DORA cares about);
  (b) ``app/.trivyignore`` has **0 unjustified/expired suppressions** — reuses the
      shared T-02 linter (``scripts/lint-trivyignore.py``) so a silently-added CVE
      waiver fails the row;
  (c) ``dependency-review.json`` is **structurally a Trivy report** (has a
      ``Results`` array), not a bare copy of something else.

Honesty rules (libcompliance / blueprint/04 §2)
-----------------------------------------------
* A missing/empty/``{}`` artifact yields **INDETERMINATE**, never a silent PASS
  (``libcompliance.load_json`` treats ``{}`` as "no measurable content").
* A missing ``.trivyignore`` is INDETERMINATE for half (b) (we could not measure
  the suppression policy) — absence of evidence is not evidence of a clean policy.

Wiring (T-12 dispatch contract)
-------------------------------
Emits the libcompliance envelope on one JSON line and exits with the tier-aware
code (0 PASS, 1 FAIL, 2 INDETERMINATE) — identical to ``matrix_rows.py`` — so
``generate-compliance-matrix.sh`` invokes it exactly like any other row validator::

    python3 scripts/validators/dora_16_1_c.py <evidence-dir>

The ``app/.trivyignore`` path defaults to the repo copy but may be overridden with
the ``TRIVYIGNORE_PATH`` env var (used by fixtures/tests).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` and ``scripts.lint_trivyignore``
# importable no matter the cwd (mirrors matrix_rows.py).
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

# The T-02 linter lives at scripts/lint-trivyignore.py (a hyphenated filename, so
# import it by file location rather than as a package attribute).
import importlib.util as _ilu  # noqa: E402

_LINTER_PATH = _PIPELINE_ROOT / "scripts" / "lint-trivyignore.py"
_spec = _ilu.spec_from_file_location("lint_trivyignore", _LINTER_PATH)
assert _spec is not None and _spec.loader is not None, f"cannot load {_LINTER_PATH}"
_linter = _ilu.module_from_spec(_spec)
# Register before exec so @dataclass (and other __module__ lookups via sys.modules)
# resolve correctly on Python >=3.12/3.14 — the documented spec-loading pattern.
sys.modules[_spec.name] = _linter
_spec.loader.exec_module(_linter)
lint_trivyignore = _linter.lint_trivyignore

Envelope = dict[str, Any]

# Repo-default suppression policy; overridable for fixtures via TRIVYIGNORE_PATH.
DEFAULT_TRIVYIGNORE = _PIPELINE_ROOT / "app" / ".trivyignore"


def _trivyignore_path() -> Path:
    override = os.environ.get("TRIVYIGNORE_PATH")
    return Path(override) if override else DEFAULT_TRIVYIGNORE


def _read_tool_version(evidence_dir: Path) -> str | None:
    """Best-effort SCA scanner version from trivy-sca-summary.json (never fabricated)."""
    data, err = lc.load_json(evidence_dir / "trivy-sca-summary.json")
    if err or not isinstance(data, dict):
        return None
    for key in ("tool_version", "version", "trivy_version"):
        if data.get(key):
            return str(data[key])
    return None


def check(evidence_dir: str | Path) -> Envelope:
    """Evaluate DORA Art.16.1.c. Returns a libcompliance envelope (no process exit)."""
    evidence_dir = Path(evidence_dir)
    threshold = {
        "severity_filter": ["CRITICAL", "HIGH"],
        "dependency_review_is_report": True,
        "unjustified_suppressions": 0,
    }
    tool_version = _read_tool_version(evidence_dir)

    summary, serr = lc.load_json(evidence_dir / "trivy-sca-summary.json")
    review, rerr = lc.load_json(evidence_dir / "dependency-review.json")

    # No measurable SCA evidence at all -> INDETERMINATE (never a silent PASS).
    if serr is not None and rerr is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=None, threshold=threshold,
            detail=f"SCA evidence: {serr}; {rerr}",
            tool_version=tool_version, validator="dora_16_1_c",
        )

    # (a) severity gate includes CRITICAL and HIGH.
    sev_filter: Any = summary.get("severity_filter") if isinstance(summary, dict) else None
    sev_text = str(sev_filter or "").upper()
    gate_ok = "CRITICAL" in sev_text and "HIGH" in sev_text

    # (c) dependency-review.json is a real Trivy report (has Results), not a cp.
    review_is_report = isinstance(review, dict) and isinstance(review.get("Results"), list)

    # (b) .trivyignore has 0 unjustified/expired suppressions (shared T-02 linter).
    ti_path = _trivyignore_path()
    suppressions_total: int | None = None
    unjustified: int | None = None
    suppression_indeterminate = False
    suppression_detail = ""
    try:
        lint = lint_trivyignore(ti_path)
        suppressions_total = lint.total
        unjustified = lint.unjustified_count
        if unjustified:
            suppression_detail = "; ".join(
                f"{v.cve} (line {v.line_no}): {v.reason}" for v in lint.violations
            )
    except FileNotFoundError:
        # Cannot measure the suppression policy -> INDETERMINATE for this half.
        suppression_indeterminate = True
        suppression_detail = f"{ti_path}: .trivyignore not found (suppression policy unmeasured)"

    measured = {
        "severity_filter": sev_filter,
        "dependency_review_is_report": review_is_report,
        "suppressions_total": suppressions_total,
        "unjustified_suppressions": unjustified,
    }

    # If nothing measurable on either summary or review side, INDETERMINATE.
    if sev_filter is None and not review_is_report:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=measured, threshold=threshold,
            detail="SCA summary lacks severity_filter and dependency-review.json is "
                   "not a Trivy report (nothing measurable)",
            tool_version=tool_version, validator="dora_16_1_c",
        )

    # An unmeasurable suppression policy is INDETERMINATE only when the rest passes;
    # if the gate/report already FAIL, surface the FAIL (a real, actionable result).
    base_pass = gate_ok and review_is_report
    suppressions_clean = (unjustified == 0)

    if base_pass and suppression_indeterminate:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=measured, threshold=threshold,
            detail=f"SCA gate + dependency-review OK, but suppression policy "
                   f"could not be measured: {suppression_detail}",
            tool_version=tool_version, validator="dora_16_1_c",
        )

    status = lc.Status.PASS if (base_pass and suppressions_clean) else lc.Status.FAIL

    reasons: list[str] = []
    if not gate_ok:
        reasons.append(f"severity_filter={sev_filter!r} missing CRITICAL/HIGH")
    if not review_is_report:
        reasons.append("dependency-review.json is not a Trivy report (no Results)")
    if not suppression_indeterminate and unjustified:
        reasons.append(f"{unjustified} unjustified/expired .trivyignore suppression(s): "
                       f"{suppression_detail}")

    if status == lc.Status.PASS:
        detail = (
            f"SCA gate filter={sev_filter!r} (CRITICAL+HIGH); dependency-review is a "
            f"Trivy report; {suppressions_total or 0} suppression(s), 0 unjustified/expired"
        )
    else:
        detail = "DORA 16.1.c FAIL: " + "; ".join(reasons)

    return lc.envelope(
        status, lc.Tier.BLOCKING,
        measured=measured, threshold=threshold,
        detail=detail, tool_version=tool_version, validator="dora_16_1_c",
    )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: dora_16_1_c.py <evidence-dir>", file=sys.stderr)
        return 2
    env = check(args[0])
    return lc.emit(
        env["status"], env["tier"],
        measured=env["measured"], threshold=env["threshold"],
        detail=env["detail"], tool_version=env["tool_version"],
        validator="dora_16_1_c",
    )  # emit() prints the JSON line and exits with the tier-aware code


if __name__ == "__main__":
    raise SystemExit(main())
