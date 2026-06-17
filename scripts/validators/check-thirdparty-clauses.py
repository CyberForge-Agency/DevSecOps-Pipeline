#!/usr/bin/env python3
"""check-thirdparty-clauses — A.7 ICT third-party clause + tested-exit validator (T-26).

DORA Art.28-30 require, **per critical/important ICT provider**:

1. the mandatory contractual clause set (Art.30(2) general + Art.30(3) extras for
   critical-or-important functions: audit rights, sub-outsourcing conditions,
   business contingency, exit strategy), captured here as the clause *checklist*
   document ``ict-third-party-contract-controls.md``; and
2. a **documented and tested** exit strategy (Art.28(8)) for each such provider.

This validator (struktura §6 A.7) joins the vendor register's **Criticality** column
with its **Exit Plan References** status table and asserts that every
Critical / High vendor has an exit plan whose status is ``Documented`` or ``Tested``
(not ``Planned`` / template-only). It also asserts the clause-checklist document is
present, structurally complete (the Art.30 clause categories), and within its review
cadence.

Honesty boundary (blueprint/04 §9; the rule that keeps this from being an overclaim)
------------------------------------------------------------------------------------
This check verifies that an exit plan is **DOCUMENTED and flagged TESTED** in the
register — it does **not** and cannot verify that an exit was actually *executed*, nor
that a clause is truly present in a signed contract. The signed-contract / executed-exit
truths are EVIDENCE-ONLY (a register fact a human attests to), surfaced in ``detail``
but never asserted as a pipeline PASS. Only the BLOCKING completeness join (Critical/High
exit-plan status) can break the build.

Tiering (T-33 envelope)
-----------------------
* BLOCKING       — exit-plan completeness for Critical/High vendors. A Critical/High
  vendor whose status is not Documented/Tested makes the whole check FAIL and exit 1.
* EVIDENCE-ONLY  — the clause-checklist presence/structure/cadence facts and the full
  per-vendor status breakdown (recorded numbers, never a vibe).

Output
------
Emits the T-33 envelope on stdout (one JSON line) **and** writes the full per-vendor
breakdown to ``tpp-clauses.json`` (path overridable with ``--out``). ``measured`` carries
the count of Critical/High vendors with incomplete exit plans; ``threshold`` is 0.

Usage
-----
    python3 scripts/validators/check-thirdparty-clauses.py docs/governance/
    python3 scripts/validators/check-thirdparty-clauses.py docs/governance/ --out tpp-clauses.json

Exit codes (via T-33): PASS->0, FAIL(BLOCKING)->1, INDETERMINATE(BLOCKING)->2.

This module is import-safe: ``main()`` does the work and ``emit``s only under
``__main__`` so unit tests can call the pure helpers without exiting the process.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable whether this file is run as a
# script (``python3 scripts/validators/check-thirdparty-clauses.py``) or imported as a
# module by the test suite.
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "check-thirdparty-clauses"

# --------------------------------------------------------------------------- #
# Domain constants                                                            #
# --------------------------------------------------------------------------- #

VENDOR_REGISTER = "vendor-risk-register.md"
CONTRACT_CONTROLS = "ict-third-party-contract-controls.md"

# Criticality levels that REQUIRE a documented+tested exit plan (DORA Art.28(8)
# applies to critical-or-important functions; we treat Critical and High that way).
REQUIRES_EXIT_PLAN = frozenset({"critical", "high"})

# Exit-plan statuses that count as compliant. Anything else (Planned, Template
# available, Low priority, blank) is an *incomplete* exit plan for a vendor that
# requires one. Matched case-insensitively on the leading word(s).
COMPLIANT_EXIT_STATUSES = frozenset({"documented", "tested"})

# Review cadence for the clause-checklist document. The doc itself states
# "Annually and upon regulatory changes"; we allow a small grace window.
CONTRACT_CONTROLS_MAX_AGE_DAYS = 400  # ~13 months: annual cadence + 1-month grace

# The Art.30 mandatory clause categories the checklist document must enumerate
# (Art.30(2) general + Art.30(3) critical-function extras). These are matched as
# case-insensitive substrings against the document's section headings so the
# structural assertion is regulatorily grounded, not a word-count proxy.
REQUIRED_CLAUSE_CATEGORIES = (
    "Security Terms",       # Art.30(2)(c) protection of data; Art.28(7) incident support
    "Data Protection",     # Art.30(2)(b)(c) locations + AICA of data incl. personal data
    "Operational Controls",  # Art.30(3)(a) SLAs; Art.30(3) business contingency
    "Exit and Transition",   # Art.28(8)/Art.30(3) exit strategy + transition assistance
)


class _ContentError(Exception):
    """Raised when register content cannot be parsed into a measurable join.

    Surfaced as an INDETERMINATE envelope (we measured nothing) rather than a
    silent PASS — consistent with the T-33 honesty rule.
    """


# --------------------------------------------------------------------------- #
# Parsing + join helpers (pure, unit-testable)                                #
# --------------------------------------------------------------------------- #

def _norm(s: str) -> str:
    """Lower-case + collapse whitespace for tolerant matching."""
    return " ".join((s or "").split()).strip().lower()


def _find_col(row: dict[str, str], *candidates: str) -> str | None:
    """Return the first header key in ``row`` matching any candidate (normalised)."""
    norm_map = {_norm(k): k for k in row}
    for cand in candidates:
        key = norm_map.get(_norm(cand))
        if key is not None:
            return key
    return None


def _extract_ep_ref(cell: str) -> str | None:
    """Pull the ``EP-NNN`` reference out of a register cell (may be a Markdown link).

    e.g. ``[EP-002](#exit-plan-references)`` -> ``EP-002``; ``EP-010`` -> ``EP-010``.
    Returns the upper-cased ref or ``None`` if no EP-style token is present.
    """
    import re

    m = re.search(r"EP[-‑]?\d+", cell or "", flags=re.IGNORECASE)
    if not m:
        return None
    return m.group(0).upper().replace("‑", "-")


def _status_word(status_cell: str) -> str:
    """Normalise an exit-plan status cell to its leading classification word(s)."""
    return _norm(status_cell)


def _status_is_compliant(status_cell: str) -> bool:
    """True iff the exit-plan status counts as Documented/Tested.

    Matched on whole-word membership so ``Documented`` / ``Tested`` (in any case,
    possibly with trailing notes like ``Tested 2026-04`` ) count, while
    ``Planned`` / ``Template available`` / ``Low priority`` do not.
    """
    words = set(_status_word(status_cell).replace("/", " ").split())
    return bool(words & COMPLIANT_EXIT_STATUSES)


def parse_vendors(register_path: str | Path) -> list[dict[str, str]]:
    """Parse the Vendor Inventory table into per-vendor dicts.

    Raises:
        _ContentError: if the inventory table is missing or empty.
    """
    try:
        rows = lc.gfm_table(str(register_path), "Vendor Inventory")
    except lc.ValidatorError as exc:
        raise _ContentError(f"Vendor Inventory not parseable: {exc}") from exc
    if not rows:
        raise _ContentError("Vendor Inventory table is empty")
    return rows


def parse_exit_status(register_path: str | Path) -> dict[str, dict[str, str]]:
    """Parse the Exit Plan References table into ``{EP-ref: {Vendor, Status, ...}}``.

    Raises:
        _ContentError: if the references table is missing or empty.
    """
    try:
        rows = lc.gfm_table(str(register_path), "Exit Plan References")
    except lc.ValidatorError as exc:
        raise _ContentError(f"Exit Plan References not parseable: {exc}") from exc
    if not rows:
        raise _ContentError("Exit Plan References table is empty")

    out: dict[str, dict[str, str]] = {}
    for r in rows:
        ref_col = _find_col(r, "Ref", "Reference")
        ref = _extract_ep_ref(r.get(ref_col, "")) if ref_col else None
        if ref is None:
            # Fall back: any cell may hold the EP token.
            for v in r.values():
                ref = _extract_ep_ref(v)
                if ref:
                    break
        if ref is None:
            continue
        out[ref] = r
    if not out:
        raise _ContentError("Exit Plan References table has no EP-style references")
    return out


def join_vendor_exit_status(
    vendors: list[dict[str, str]],
    exit_status: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    """Join each vendor with its exit-plan status; classify completeness.

    Returns one dict per vendor with: vendor, criticality, requires_exit_plan,
    exit_ref, exit_status, exit_status_compliant.
    """
    out: list[dict[str, Any]] = []
    for v in vendors:
        vendor_col = _find_col(v, "Vendor")
        crit_col = _find_col(v, "Criticality")
        epref_col = _find_col(v, "Exit Plan Ref", "Exit Plan Reference", "Exit Plan")

        vendor = (v.get(vendor_col, "") if vendor_col else "").strip()
        criticality = _norm(v.get(crit_col, "")) if crit_col else ""
        ep_ref = _extract_ep_ref(v.get(epref_col, "")) if epref_col else None

        requires = criticality in REQUIRES_EXIT_PLAN

        status_row = exit_status.get(ep_ref) if ep_ref else None
        if status_row is not None:
            status_col = _find_col(status_row, "Status")
            raw_status = (status_row.get(status_col, "") if status_col else "").strip()
        else:
            raw_status = ""

        compliant = _status_is_compliant(raw_status) if raw_status else False

        out.append(
            {
                "vendor": vendor,
                "criticality": criticality.title() if criticality else "",
                "requires_exit_plan": requires,
                "exit_ref": ep_ref,
                "exit_status": raw_status or None,
                "exit_status_compliant": compliant,
            }
        )
    return out


def check_clause_checklist_structure(controls_path: str | Path) -> tuple[list[str], list[str]]:
    """Return ``(present, missing)`` Art.30 clause categories in the checklist doc.

    Reads the document text once and looks for each required category as a heading
    substring. This is a *structural* presence assertion (EVIDENCE-ONLY), not proof
    that the clauses appear in any actual signed contract.
    """
    p = Path(controls_path)
    if not p.is_file():
        return [], list(REQUIRED_CLAUSE_CATEGORIES)
    text = p.read_text(encoding="utf-8").lower()
    present, missing = [], []
    for cat in REQUIRED_CLAUSE_CATEGORIES:
        (present if _norm(cat) in text else missing).append(cat)
    return present, missing


def _extract_last_reviewed(controls_path: str | Path) -> str | None:
    """Pull the ``Last Reviewed:`` date from the checklist doc header, if present."""
    import re

    p = Path(controls_path)
    if not p.is_file():
        return None
    for line in p.read_text(encoding="utf-8").splitlines()[:25]:
        m = re.search(r"last reviewed[^0-9]*(\d{4}-\d{2}-\d{2})", line, flags=re.IGNORECASE)
        if m:
            return m.group(1)
    return None


# --------------------------------------------------------------------------- #
# Core evaluation (pure: returns an envelope + the breakdown payload)         #
# --------------------------------------------------------------------------- #

def evaluate(governance_dir: str | Path, *, today=None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Evaluate A.7 over ``governance_dir``.

    Returns ``(envelope, payload)`` where ``payload`` is the rich per-vendor
    breakdown written to ``tpp-clauses.json``. The envelope's BLOCKING status is
    driven solely by Critical/High exit-plan completeness; clause-checklist facts
    are recorded as EVIDENCE-ONLY context inside the payload.
    """
    gdir = Path(governance_dir)
    register_path = gdir / VENDOR_REGISTER
    controls_path = gdir / CONTRACT_CONTROLS

    # --- Presence of the inputs (INDETERMINATE if we cannot measure) --------- #
    if not register_path.is_file():
        env = lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=0,
            detail=f"{VENDOR_REGISTER} not found under {gdir}",
            validator=VALIDATOR_NAME,
        )
        return env, {"error": env["detail"], "vendors": []}

    # --- Parse + join -------------------------------------------------------- #
    try:
        vendors = parse_vendors(register_path)
        exit_status = parse_exit_status(register_path)
    except _ContentError as exc:
        env = lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=0,
            detail=str(exc),
            validator=VALIDATOR_NAME,
        )
        return env, {"error": str(exc), "vendors": []}

    joined = join_vendor_exit_status(vendors, exit_status)

    # --- BLOCKING: Critical/High exit-plan completeness ---------------------- #
    required_vendors = [v for v in joined if v["requires_exit_plan"]]
    incomplete = [v for v in required_vendors if not v["exit_status_compliant"]]
    incomplete_names = [
        f"{v['vendor']} ({v['criticality']}, "
        f"{v['exit_ref'] or 'no-ref'}: {v['exit_status'] or 'missing'})"
        for v in incomplete
    ]

    # --- EVIDENCE-ONLY context: clause checklist presence/structure/cadence -- #
    controls_present = controls_path.is_file()
    present_cats, missing_cats = check_clause_checklist_structure(controls_path)
    last_reviewed = _extract_last_reviewed(controls_path)
    if last_reviewed is not None:
        cadence_env = lc.check_fresh(
            last_reviewed,
            CONTRACT_CONTROLS_MAX_AGE_DAYS,
            tier=lc.Tier.EVIDENCE_ONLY,
            label=CONTRACT_CONTROLS,
            today=today,
        )
        cadence_status = cadence_env["status"]
        cadence_age_days = cadence_env["measured"]
    else:
        cadence_status = lc.Status.INDETERMINATE
        cadence_age_days = None

    # --- Build the envelope (BLOCKING decision) ------------------------------ #
    n_incomplete = len(incomplete)
    if n_incomplete == 0:
        status = lc.Status.PASS
        detail = (
            f"All {len(required_vendors)} Critical/High vendor(s) have a "
            f"Documented/Tested exit plan."
        )
    else:
        status = lc.Status.FAIL
        detail = (
            f"{n_incomplete} of {len(required_vendors)} Critical/High vendor(s) "
            f"lack a Documented/Tested exit plan: " + "; ".join(incomplete_names)
        )

    env = lc.envelope(
        status,
        lc.Tier.BLOCKING,
        measured=n_incomplete,
        threshold=0,
        detail=detail,
        validator=VALIDATOR_NAME,
    )

    # --- Rich payload for tpp-clauses.json (EVIDENCE-ONLY breakdown) --------- #
    payload = {
        "validator": VALIDATOR_NAME,
        "status": status,
        "tier": lc.Tier.BLOCKING,
        "checked_at": env["checked_at"],
        "measured": n_incomplete,
        "threshold": 0,
        "detail": detail,
        "regulatory_basis": "DORA Art.28(8), Art.30(2)-(3); ISO 27001 A.5.19-A.5.23",
        "honesty_note": (
            "Verifies exit plans are DOCUMENTED/TESTED in the register and the clause "
            "checklist document is present/structured/in-cadence. Does NOT verify a "
            "clause appears in a signed contract nor that an exit was executed "
            "(EVIDENCE-ONLY register facts attested by a human)."
        ),
        "clause_checklist": {
            "document": CONTRACT_CONTROLS,
            "present": controls_present,
            "tier": lc.Tier.EVIDENCE_ONLY,
            "required_categories": list(REQUIRED_CLAUSE_CATEGORIES),
            "present_categories": present_cats,
            "missing_categories": missing_cats,
            "last_reviewed": last_reviewed,
            "cadence_status": cadence_status,
            "cadence_age_days": cadence_age_days,
            "max_age_days": CONTRACT_CONTROLS_MAX_AGE_DAYS,
        },
        "vendors_requiring_exit_plan": [
            {
                "vendor": v["vendor"],
                "criticality": v["criticality"],
                "exit_ref": v["exit_ref"],
                "exit_status": v["exit_status"],
                "exit_status_compliant": v["exit_status_compliant"],
            }
            for v in required_vendors
        ],
        "all_vendors": joined,
        "incomplete_exit_plans": incomplete_names,
    }
    return env, payload


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #

def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR_NAME,
        description=(
            "A.7 — validate per-critical-vendor Art.30 clause checklist presence "
            "and documented+tested exit plans (DORA Art.28-30)."
        ),
    )
    parser.add_argument(
        "governance_dir",
        nargs="?",
        default="docs/governance/",
        help="Path to the governance docs directory (default: docs/governance/).",
    )
    parser.add_argument(
        "--out",
        default="tpp-clauses.json",
        help="Where to write the rich per-vendor breakdown (default: tpp-clauses.json).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the validator: write ``tpp-clauses.json`` and emit the T-33 envelope.

    Returns the process exit code (PASS/EVIDENCE -> 0, FAIL -> 1, INDETERMINATE -> 2)
    rather than calling ``sys.exit`` itself, so it is callable from tests; the
    ``__main__`` guard performs the actual ``sys.exit``.
    """
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    env, payload = evaluate(args.governance_dir)

    # Always write the breakdown artifact (even on FAIL/INDETERMINATE) so the gate
    # and the HTML report have the per-vendor evidence.
    try:
        Path(args.out).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:  # do not let an artifact-write failure mask the result
        print(f"warning: could not write {args.out}: {exc}", file=sys.stderr)

    # Emit the envelope on stdout WITHOUT exiting; return the tier-aware code.
    lc.emit(
        env["status"],
        env["tier"],
        measured=env["measured"],
        threshold=env["threshold"],
        detail=env["detail"],
        validator=VALIDATOR_NAME,
        exit_process=False,
    )
    return lc.exit_code_for(env["status"], env["tier"])


if __name__ == "__main__":
    sys.exit(main())
