#!/usr/bin/env python3
"""check-dpa validator (task T-21, struktura §6 A.2) — RODO/GDPR Art.28 processor DPAs.

Replaces the former static heredoc in ``check-dpa.sh`` (which printed a hardcoded
``"dpa_status":"ACTIVE"`` per vendor) with a reader of the *maintained* vendor
register at ``docs/governance/vendor-risk-register.md``. Every value in the output now
comes from that file — edit a register row and the JSON changes; nothing is hardcoded.

What this check actually proves (honest framing, blueprint/04 §5.1, line 253)
---------------------------------------------------------------------------
The pipeline can verify that the vendor register is **operated** (reviewed within the
declared cadence) — it CANNOT verify that a DPA is legally valid or signed. So:

* **Freshness** (``Last Reviewed`` within 92 days) is the **BLOCKING** assertion: a
  stale register FAILs the gate, with the exact day-count in ``detail``.
* **Per-vendor DPA statuses** are recorded **EVIDENCE-ONLY**: contract facts that are
  not pipeline-verifiable. They are reported as measured values, never as a PASS gate.

Output (stdout, redirected to ``evidence/dpa-compliance-check.json`` by check-dpa.sh)
------------------------------------------------------------------------------------
A JSON object whose ``processors`` array and ``retention_policy`` block match the shape
consumed by ``generate-html-report.sh`` (``p.name/service/dpa_status/data_location/
justification`` and ``r.evidence_pack_retention_days/log_retention_days/
deletion_schedule``), plus a top-level T-33 ``envelope`` carrying the BLOCKING
freshness result. The process exit code is the freshness envelope's tier-aware code
(0 PASS, 1 FAIL stale, 2 INDETERMINATE) so the orchestrating shell can gate on it.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

# Make the Pipeline root importable as ``scripts.validators.libcompliance`` regardless
# of the current working directory (the workflow runs from ``Pipeline/``).
_PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #

REGISTER_REL = "docs/governance/vendor-risk-register.md"
INVENTORY_HEADING = "Vendor Inventory"
RETENTION_HEADING = "Data Retention Policy"

# RODO/GDPR Art.5.1.e storage-limitation + register-cadence freshness budget.
# The register declares "Review Cadence: Quarterly"; 92 days is one quarter + grace.
FRESHNESS_MAX_DAYS = 92

# Register-column -> output-field mapping. The output field names are the ones the
# HTML report (generate-html-report.sh:1178-1192) already reads, so the report is
# unchanged. Each value is sourced verbatim from the GFM table cell.
_LAST_REVIEWED_RE = re.compile(r"(?im)^\s*\*{0,2}Last\s+Reviewed:?\*{0,2}\s*:?\s*(\S+)")


# --------------------------------------------------------------------------- #
# Parsing helpers                                                             #
# --------------------------------------------------------------------------- #

def _parse_last_reviewed(md_text: str) -> str | None:
    """Extract the ``Last Reviewed:`` date string from the register front-matter.

    Returns the raw token (e.g. ``2026-03-15``) or ``None`` if absent. Honest: a
    missing date is reported as INDETERMINATE downstream, never assumed fresh.
    """
    m = _LAST_REVIEWED_RE.search(md_text)
    return m.group(1).strip() if m else None


def _cell(row: dict[str, str], *names: str) -> str:
    """Return the first non-empty value among the given column names (case-tolerant)."""
    lowered = {k.strip().casefold(): v for k, v in row.items()}
    for name in names:
        val = lowered.get(name.strip().casefold(), "").strip()
        if val:
            return val
    return ""


def _strip_md_link(text: str) -> str:
    """Reduce a Markdown link ``[label](url)`` to its URL; pass plain text through."""
    m = re.search(r"\]\(([^)]+)\)", text)
    return m.group(1).strip() if m else text.strip()


def _processor_from_row(row: dict[str, str]) -> dict[str, Any]:
    """Map one Vendor Inventory row to an EVIDENCE-ONLY processor record.

    All field values are read from the register row — none are hardcoded. The
    per-vendor DPA status is wrapped in an EVIDENCE-ONLY envelope because the
    pipeline cannot verify a DPA is legally valid; it only records the asserted fact.
    """
    name = _cell(row, "Vendor")
    service = _cell(row, "Service")
    dpa_status = _cell(row, "DPA Status").upper().replace(" ", "_") or "UNKNOWN"
    data_location = _cell(row, "Data Location")
    data_types = _cell(row, "Data Types Processed", "Data Types")
    dpa_ref = _cell(row, "DPA URL / Reference", "DPA URL", "DPA Reference")
    dpa_url = _strip_md_link(dpa_ref) if dpa_ref.startswith("[") or dpa_ref.startswith("http") else ""
    # "justification" is the field the HTML report shows for non-ACTIVE statuses; for
    # NOT_REQUIRED/Covered-by rows the register's reference cell carries the rationale.
    justification = dpa_ref if not dpa_url else ""

    # Honest tiering: contract facts are recorded, not gated. A row missing a DPA
    # status is FAIL *within the EVIDENCE-ONLY tier* (exit 0) so it is visible but
    # never silently breaks the build.
    status = lc.Status.PASS if dpa_status != "UNKNOWN" else lc.Status.FAIL
    env = lc.envelope(
        status,
        lc.Tier.EVIDENCE_ONLY,
        measured=dpa_status,
        threshold="documented DPA status",
        detail=f"{name or '(unnamed vendor)'}: DPA status {dpa_status} (register-sourced; not pipeline-verifiable)",
    )

    record: dict[str, Any] = {
        "name": name,
        "service": service,
        "dpa_status": dpa_status,
        "data_location": data_location,
        "data_types": data_types,
        "justification": justification,
        "envelope": env,
    }
    if dpa_url:
        record["dpa_url"] = dpa_url
    return record


def _retention_policy(register_path: Path) -> dict[str, Any]:
    """Read the ``## Data Retention Policy`` table from the register, if present.

    Returns a dict with the three fields the HTML report consumes. Values are sourced
    from the register file (not hardcoded); a missing section yields an empty dict so
    the report degrades to em-dashes rather than fabricating numbers.
    """
    try:
        rows = lc.gfm_table(str(register_path), RETENTION_HEADING)
    except lc.ValidatorError:
        return {}
    settings = {
        _cell(r, "Setting").casefold(): _cell(r, "Value")
        for r in rows
        if _cell(r, "Setting")
    }

    def _int(val: str) -> int | str:
        m = re.search(r"-?\d+", val)
        return int(m.group(0)) if m else val

    policy: dict[str, Any] = {}
    if "evidence pack retention (days)" in settings:
        policy["evidence_pack_retention_days"] = _int(settings["evidence pack retention (days)"])
    if "log retention (days)" in settings:
        policy["log_retention_days"] = _int(settings["log retention (days)"])
    if "deletion schedule" in settings:
        policy["deletion_schedule"] = settings["deletion schedule"]
    return policy


# --------------------------------------------------------------------------- #
# Core                                                                        #
# --------------------------------------------------------------------------- #

def build_report(register_path: Path, *, today: date | None = None) -> tuple[dict[str, Any], int]:
    """Build the dpa-compliance-check report dict and its process exit code.

    The exit code is the freshness envelope's tier-aware code (BLOCKING): 0 fresh,
    1 stale, 2 indeterminate. Per-vendor statuses are EVIDENCE-ONLY and never affect it.
    """
    if not register_path.is_file():
        env = lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=FRESHNESS_MAX_DAYS,
            detail=f"vendor register not found at {register_path}",
        )
        report = {
            "generated_at": env["checked_at"],
            "description": "DPA compliance verification for pipeline third-party processors",
            "vendor_risk_register_ref": REGISTER_REL,
            "status": env["status"],
            "envelope": env,
            "freshness": env,
            "retention_policy": {},
            "processors": [],
        }
        return report, lc.exit_code_for(env["status"], env["tier"])

    md_text = register_path.read_text(encoding="utf-8")

    # 1) Per-vendor processor records (EVIDENCE-ONLY) from the Vendor Inventory table.
    rows = lc.gfm_table(str(register_path), INVENTORY_HEADING)
    processors = [_processor_from_row(r) for r in rows]

    # 2) Register freshness (BLOCKING) from the `Last Reviewed:` front-matter date.
    last_reviewed = _parse_last_reviewed(md_text)
    if last_reviewed is None:
        freshness = lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=FRESHNESS_MAX_DAYS,
            detail="register has no parseable 'Last Reviewed:' date",
        )
    else:
        freshness = lc.check_fresh(
            last_reviewed,
            FRESHNESS_MAX_DAYS,
            tier=lc.Tier.BLOCKING,
            label="vendor register",
            today=today,
        )

    report = {
        "generated_at": freshness["checked_at"],
        "description": "DPA compliance verification for pipeline third-party processors",
        "vendor_risk_register_ref": REGISTER_REL,
        "last_reviewed": last_reviewed,
        # Top-level status mirrors the BLOCKING freshness result so the matrix/gate and
        # the `jq '.status'` verification read a single authoritative gate value.
        "status": freshness["status"],
        "envelope": freshness,
        "freshness": freshness,
        "retention_policy": _retention_policy(register_path),
        "processors": processors,
    }
    return report, lc.exit_code_for(freshness["status"], freshness["tier"])


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    register_path = Path(argv[0]) if argv else (_PIPELINE_ROOT / REGISTER_REL)
    report, code = build_report(register_path)
    print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
