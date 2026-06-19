#!/usr/bin/env python3
"""check-governance — A.6 governance freshness validator (DORA Art.5 / NIS2 Art.20).

Spec / struktura mapping
------------------------
struktura §6 A.6 ("governance") = **presence + freshness** of the two organizational
governance artifacts auditors check first (spec Part A header; struktura §12 names a
missing board sign-off as a rejection trigger):

  1. ``management-review-template.md``        — ISO 27001 9.3 / DORA Art.5 senior-mgmt
     oversight; carries ``Last Reviewed:`` + a ``Review Cadence`` (semi-annual = 183d).
  2. ``nis2-management-training-records.md``  — NIS2 Art.20(2) mandatory management
     cybersecurity training; carries ``Effective Date`` + a ``Review Cycle`` (annual =
     365d) and an ``Approved By`` (board/management sign-off, NIS2 Art.20(1)).

What this validator can and cannot honestly assert (blueprint/04 §9, row 1)
--------------------------------------------------------------------------
The pipeline validates the **freshness of the governance LOG**, NOT that the board
actually met or that training actually happened — those are human events. So:

  * Freshness of each document (age vs its own stated cadence)  -> **BLOCKING**
    (deterministic, false-positive-safe: a stale or missing record is a real gate).
  * Presence of a board/management approval sign-off block, and the count of recorded
    training attendees                                           -> **EVIDENCE-ONLY**
    (the existence of a signature line / a recorded attendee is reported as a number,
    never used to fake "training occurred"; struktura §14 / blueprint/04 §9).

Tiers + exit codes are taken straight from the T-33 library (``libcompliance``):
``PASS``/any EVIDENCE-ONLY -> 0, BLOCKING ``FAIL`` -> 1, BLOCKING ``INDETERMINATE``
(missing/unparseable required doc) -> 2. There is no path that emits a hardcoded PASS:
every PASS is backed by a parsed date that met a parsed threshold.

Output
------
Writes ``governance-evidence.json`` next to the CWD (or ``--out PATH``) carrying the
T-33 envelope of the **overall** verdict plus a ``components`` map of every sub-check
(both BLOCKING freshness checks and the EVIDENCE-ONLY facts), so the compliance gate
(T-30) and the matrix can show the measured ages, not just PASS/MISSING.

Usage
-----
    python3 scripts/validators/check-governance.py docs/governance/
    python3 scripts/validators/check-governance.py docs/governance/ --out evidence/governance-evidence.json
    jq .status governance-evidence.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

# Make the Pipeline root importable so ``scripts.validators.libcompliance`` resolves
# no matter what CWD the orchestrating shell uses.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR = "check-governance"
DEFAULT_OUT = "governance-evidence.json"

# --------------------------------------------------------------------------- #
# Document specs (file name, the date label to parse, and its cadence in days) #
# --------------------------------------------------------------------------- #

MANAGEMENT_REVIEW_DOC = "management-review-template.md"
TRAINING_RECORDS_DOC = "nis2-management-training-records.md"

# Cadence ceilings come from each document's own stated cadence (struktura §6):
#   management review = semi-annual  -> 183 days
#   management training = annual     -> 365 days
MAX_AGE_MANAGEMENT_REVIEW_DAYS = 183
MAX_AGE_TRAINING_DAYS = 365

# Article citations emitted on FAIL so the gate/matrix carries the legal hook.
ARTICLE_MANAGEMENT_REVIEW = "DORA Art.5 / ISO 27001 Cl.9.3 (senior-management oversight)"
ARTICLE_TRAINING = "NIS2 Art.20(2) (mandatory management cybersecurity training)"
ARTICLE_APPROVAL = "NIS2 Art.20(1) (management-body approval / board sign-off)"


# --------------------------------------------------------------------------- #
# Date extraction                                                              #
# --------------------------------------------------------------------------- #

# Matches both styles seen in the governance docs:
#   "**Last Reviewed:** 2026-03-15"          (bold-markdown line)
#   "| Effective Date | 2026-03-15 |"        (GFM key/value table row)
# We anchor on the label and then pull the first ISO date token after it.
_ISO_DATE = r"(\d{4}-\d{2}-\d{2})"


def _find_labelled_date(text: str, *labels: str) -> str | None:
    """Return the first ISO-8601 date that follows any of ``labels`` in ``text``.

    Label matching is case-insensitive and ignores Markdown emphasis (``*``/``_``)
    and the optional ``:`` / ``|`` separators, so the same regex handles both the
    bold-line form (``**Last Reviewed:** 2026-03-15``) and the table-row form
    (``| Effective Date | 2026-03-15 |``).
    """
    for label in labels:
        # Build a tolerant pattern: optional emphasis around the label, then any
        # of  :  |  whitespace  before the date token.
        esc = re.escape(label)
        pattern = re.compile(
            rf"[*_ \t]*{esc}[*_ \t]*[:|]?[*_ \t|]*{_ISO_DATE}",
            re.IGNORECASE,
        )
        m = pattern.search(text)
        if m:
            return m.group(1)
    return None


def _has_approval_signoff(text: str) -> tuple[bool, str]:
    """Detect a board/management approval sign-off in the document.

    Honest, content-based detection (not a presence-of-file proxy): looks for an
    ``Approved By`` field carrying a non-placeholder value, OR a ``Sign-Off``
    section with a signature/date table. Returns ``(found, detail)``.
    """
    # Form 1: an "Approved By | <value>" table/line where <value> is not a blank
    # or an underscore placeholder.
    m = re.search(
        r"[*_ \t]*Approved\s*By[*_ \t]*[:|][*_ \t|]*([^|\n]+)",
        text,
        re.IGNORECASE,
    )
    if m:
        value = m.group(1).strip().strip("*_ ")
        # Reject blanks / underscore placeholders ("____") as not-yet-approved.
        if value and not re.fullmatch(r"[_\-\s]+", value):
            return True, f"approval recorded: 'Approved By' = {value!r}"

    # Form 2: a "Sign-Off" / "Sign Off" / "Signature" heading or a signature table.
    if re.search(r"#{1,6}\s+Sign[\s-]?Off\b", text, re.IGNORECASE):
        return True, "approval recorded: 'Sign-Off' section present"
    if re.search(r"\|\s*Signature\s*\|", text, re.IGNORECASE):
        return True, "approval recorded: signature table present"

    return False, "no board/management approval sign-off block found"


def _count_training_attendees(text: str) -> int:
    """Count non-empty rows in the training-records table (EVIDENCE-ONLY signal).

    Uses the T-33 GFM parser on the 'Training Records' section. A row counts only
    if at least the Date and Attendee cells are populated — empty template rows do
    NOT inflate the count. Returns 0 when the section/table is absent or all-blank.
    """
    doc = Path(text)
    try:
        rows = lc.gfm_table(str(doc), "Training Records")
    except lc.ValidatorError:
        return 0
    populated = 0
    for row in rows:
        date_cell = (row.get("Date") or "").strip()
        attendee_cell = (row.get("Attendee") or "").strip()
        if date_cell and attendee_cell:
            populated += 1
    return populated


# --------------------------------------------------------------------------- #
# Per-document freshness check (BLOCKING)                                      #
# --------------------------------------------------------------------------- #

def _freshness_component(
    governance_dir: Path,
    filename: str,
    date_labels: tuple[str, ...],
    max_age_days: int,
    article: str,
    label: str,
    *,
    today: date | None = None,
) -> dict[str, Any]:
    """Build a BLOCKING freshness envelope for one governance document.

    Returns INDETERMINATE if the file is missing/empty (a hard, non-silent gate
    failure — exit 2, never a pass) or if no parseable date label is present;
    otherwise delegates to T-33 ``check_fresh`` against ``max_age_days``.
    """
    path = governance_dir / filename

    presence = lc.check_presence(path, tier=lc.Tier.BLOCKING, label=label)
    if presence["status"] != lc.Status.PASS:
        # Missing/empty required document — surface it loudly, do not hide it.
        presence["detail"] = (
            f"{presence['detail']} — required governance evidence missing "
            f"({article})"
        )
        return presence

    text = path.read_text(encoding="utf-8")
    found = _find_labelled_date(text, *date_labels)
    if found is None:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=max_age_days,
            detail=(
                f"{label}: present but no parseable date "
                f"({' / '.join(date_labels)}) — cannot assess freshness ({article})"
            ),
        )

    env = lc.check_fresh(
        found,
        max_age_days,
        tier=lc.Tier.BLOCKING,
        label=label,
        today=today,
    )
    if env["status"] == lc.Status.FAIL:
        env["detail"] = f"{env['detail']} — STALE; rejection trigger: {article}"
    return env


# --------------------------------------------------------------------------- #
# Evidence-only components (human-event facts)                                 #
# --------------------------------------------------------------------------- #

def _approval_component(governance_dir: Path) -> dict[str, Any]:
    """EVIDENCE-ONLY: is a board/management approval sign-off block present?

    Never blocks the build (a signature line cannot prove the board actually met);
    it records the *fact* of a sign-off block so auditors can follow up. struktura
    §12 still flags a fully-absent sign-off — surfaced here as FAIL/EVIDENCE-ONLY.
    """
    path = governance_dir / TRAINING_RECORDS_DOC
    if not path.is_file():
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.EVIDENCE_ONLY,
            measured=None,
            threshold="approval block present",
            detail=f"{TRAINING_RECORDS_DOC}: file not found — cannot read approval",
        )
    found, detail = _has_approval_signoff(path.read_text(encoding="utf-8"))
    return lc.envelope(
        lc.Status.PASS if found else lc.Status.FAIL,
        lc.Tier.EVIDENCE_ONLY,
        measured=found,
        threshold="approval block present",
        detail=f"{detail} ({ARTICLE_APPROVAL})",
    )


def _attendees_component(governance_dir: Path) -> dict[str, Any]:
    """EVIDENCE-ONLY: how many populated training-attendee rows are recorded?

    Reports a count, not a verdict — training is a human event the pipeline cannot
    confirm happened (blueprint/04 §9). 0 populated rows is an honest signal for
    auditors, not a build-breaker.
    """
    path = governance_dir / TRAINING_RECORDS_DOC
    if not path.is_file():
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.EVIDENCE_ONLY,
            measured=None,
            threshold=">=1 recorded attendee",
            detail=f"{TRAINING_RECORDS_DOC}: file not found — cannot count attendees",
        )
    count = _count_training_attendees(str(path))
    status = lc.Status.PASS if count >= 1 else lc.Status.FAIL
    return lc.envelope(
        status,
        lc.Tier.EVIDENCE_ONLY,
        measured=count,
        threshold=">=1 recorded attendee",
        detail=(
            f"{count} populated training-attendee row(s) recorded "
            f"(EVIDENCE-ONLY: the pipeline records the log, not that training "
            f"occurred — {ARTICLE_TRAINING})"
        ),
    )


# --------------------------------------------------------------------------- #
# Aggregation                                                                  #
# --------------------------------------------------------------------------- #

# Status precedence for the overall BLOCKING verdict: the worst blocking outcome
# wins. EVIDENCE-ONLY components never change the overall status.
_OVERALL_RANK = {lc.Status.PASS: 0, lc.Status.FAIL: 2, lc.Status.INDETERMINATE: 1}


def evaluate(governance_dir: Path, *, today: date | None = None) -> dict[str, Any]:
    """Run all governance checks and return the overall envelope + components.

    The overall verdict is BLOCKING and reflects only the BLOCKING freshness
    components (worst-case: any FAIL -> FAIL; else any INDETERMINATE -> INDETERMINATE;
    else PASS). EVIDENCE-ONLY facts ride along in ``components`` without gating.
    """
    mgmt_review = _freshness_component(
        governance_dir,
        MANAGEMENT_REVIEW_DOC,
        ("Last Reviewed", "Last Review", "Reviewed"),
        MAX_AGE_MANAGEMENT_REVIEW_DAYS,
        ARTICLE_MANAGEMENT_REVIEW,
        "management review",
        today=today,
    )
    training = _freshness_component(
        governance_dir,
        TRAINING_RECORDS_DOC,
        ("Effective Date", "Last Reviewed", "Effective"),
        MAX_AGE_TRAINING_DAYS,
        ARTICLE_TRAINING,
        "management training record",
        today=today,
    )
    approval = _approval_component(governance_dir)
    attendees = _attendees_component(governance_dir)

    components = {
        "management_review_freshness": mgmt_review,
        "training_record_freshness": training,
        "board_approval_signoff": approval,
        "training_attendees_recorded": attendees,
    }

    blocking = [mgmt_review, training]
    overall_status = max(
        (c["status"] for c in blocking), key=lambda s: _OVERALL_RANK[s]
    )

    fail_details = [
        c["detail"] for c in blocking if c["status"] == lc.Status.FAIL
    ]
    indet_details = [
        c["detail"] for c in blocking if c["status"] == lc.Status.INDETERMINATE
    ]
    if overall_status == lc.Status.PASS:
        detail = (
            "governance evidence fresh: management review within "
            f"{MAX_AGE_MANAGEMENT_REVIEW_DAYS}d and management training within "
            f"{MAX_AGE_TRAINING_DAYS}d"
        )
    elif overall_status == lc.Status.FAIL:
        detail = "governance freshness FAIL — " + " | ".join(fail_details)
    else:
        detail = "governance evidence INDETERMINATE — " + " | ".join(indet_details)

    measured = {
        "management_review_age_days": mgmt_review.get("measured"),
        "training_record_age_days": training.get("measured"),
        "board_approval_signoff": approval.get("measured"),
        "training_attendees_recorded": attendees.get("measured"),
    }
    threshold = {
        "management_review_max_days": MAX_AGE_MANAGEMENT_REVIEW_DAYS,
        "training_record_max_days": MAX_AGE_TRAINING_DAYS,
    }

    overall = lc.envelope(
        overall_status,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold=threshold,
        detail=detail,
        validator=VALIDATOR,
    )
    overall["components"] = components
    return overall


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR,
        description="A.6 governance freshness validator (DORA Art.5 / NIS2 Art.20).",
    )
    parser.add_argument(
        "governance_dir",
        nargs="?",
        default="docs/governance",
        help="path to the governance docs directory (default: docs/governance)",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"path to write the evidence JSON (default: {DEFAULT_OUT})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point: evaluate, write ``governance-evidence.json``, print + exit."""
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    governance_dir = Path(args.governance_dir)

    overall = evaluate(governance_dir)

    out_path = Path(args.out)
    if out_path.parent and not out_path.parent.exists():
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(overall, indent=2) + "\n", encoding="utf-8")

    # Also print the one-line envelope to stdout (gate-friendly).
    print(json.dumps(overall))
    return lc.exit_code_for(overall["status"], overall["tier"])


if __name__ == "__main__":
    sys.exit(main())
