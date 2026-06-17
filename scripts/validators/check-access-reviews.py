#!/usr/bin/env python3
"""check-access-reviews -- A.8 access-review cadence freshness gate (task T-27).

NIS2 Art. 21(2)(i) (access control / least privilege), ISO/IEC 27001 A.8.2
(privileged access management) and SOC 2 CC6.1 all require *recurring* access
reviews -- privileged accounts re-certified on a stated cadence (quarterly for
privileged, semi-annually for standard here). struktura S.6 A.8 frames this as a
FRESHNESS check: the records must be present AND in-cycle.

``docs/governance/access-review-schedule.md`` already carries a machine-parseable
``Next Due`` column per review type (S.3 "Review Schedule" table). The honest check
this validator performs is therefore:

    For every row in the Review Schedule table, is its ``Next Due`` date still in
    the future (i.e. the review has NOT yet fallen overdue)?

If every row is in-cycle -> PASS. If ANY row's ``Next Due`` is in the past, the
cadence has slipped for that review type -> FAIL, listing the overdue type(s) and
recording the worst-case days-overdue in ``measured``. There is NO file-presence
shortcut: a schedule whose dates are stale fails exactly as it should.

Tier: BLOCKING. The assertion is deterministic and false-positive-safe -- a past
``Next Due`` can only make us FAIL, never wrongly PASS -- so per the T-33 tiering
rule it is allowed to gate the build. (blueprint/04 S.9: the pipeline validates
*cadence*, not the review's content.)

EVIDENCE-ONLY aspect (recorded in ``measured``, NOT gated): whether each review was
actually *performed and signed off* with the stated evidence artifact is human-
attested registration-truth not verifiable from this schedule alone. The schedule
proves the cadence is scheduled and not overdue; the sign-off record (referenced in
the ``Evidence Artifact`` column) is what an auditor inspects for execution-truth.

Emits the T-33 envelope to stdout AND writes ``access-review.json`` (path
overridable with ``--out``). ``measured`` records ``max_days_overdue`` (per the
acceptance criteria) plus the per-row breakdown.

Usage:
    python3 scripts/validators/check-access-reviews.py docs/governance/access-review-schedule.md
    python3 scripts/validators/check-access-reviews.py <schedule.md> --heading "Review Schedule" --out access-review.json

Exit codes (via T-33 emit / BLOCKING tier):
    0  PASS           -- every Next Due date is in the future (cadence in-cycle)
    1  FAIL           -- at least one review type is overdue (Next Due in the past)
    2  INDETERMINATE  -- the schedule/table could not be parsed (nothing measured)
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

# Make the Pipeline root importable so ``scripts.validators.libcompliance`` resolves
# no matter the current working directory (CI runs from the repo root; humans may
# run from anywhere).
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "check-access-reviews"

# Default location of the schedule and the heading whose table we parse.
DEFAULT_SCHEDULE = "docs/governance/access-review-schedule.md"
DEFAULT_HEADING = "Review Schedule"

# Column whose date drives the freshness verdict, and the human label column.
_DUE_COL = "Next Due"
_TYPE_COL = "Review Type"


def _row_label(row: dict[str, str], index: int) -> str:
    """Best-effort human label for a review row (the type, else its 1-based index)."""
    label = (row.get(_TYPE_COL) or "").strip()
    return label if label else f"row #{index + 1}"


def evaluate(
    schedule_path: str | Path,
    *,
    heading: str = DEFAULT_HEADING,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate the access-review schedule and return a T-33 envelope.

    Pure: no process exit, no file writes. Separated from ``main`` so unit tests
    can assert the verdict directly with an injectable ``today``.

    Logic:
      * INDETERMINATE if the file/table cannot be parsed, or no row carries a
        parseable ``Next Due`` date (we measured nothing -- never a silent PASS).
      * FAIL if any parseable ``Next Due`` is strictly in the past.
      * PASS only when every parseable ``Next Due`` is today or later.
    """
    threshold = {
        "rule": f"every '{_DUE_COL}' >= today (no overdue access review)",
        "max_days_overdue": 0,
    }

    # 1) Parse the schedule table via the T-33 GFM helper. A missing file or absent
    #    table means we could not measure the control -> INDETERMINATE (BLOCKING,
    #    exit 2), not a silent pass and not a hard FAIL (absence != failed control).
    try:
        rows = lc.gfm_table(schedule_path, heading)
    except lc.ValidatorError as exc:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=threshold,
            detail=f"{schedule_path}: cannot parse schedule table -- {exc}",
            validator=VALIDATOR_NAME,
        )

    if not rows:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured={"total_rows": 0},
            threshold=threshold,
            detail=(
                f"{schedule_path}: '{heading}' table has no data rows -- "
                "cannot verify any access-review cadence"
            ),
            validator=VALIDATOR_NAME,
        )

    if _DUE_COL not in rows[0]:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured={"total_rows": len(rows), "columns": list(rows[0].keys())},
            threshold=threshold,
            detail=(
                f"{schedule_path}: '{heading}' table has no '{_DUE_COL}' column "
                f"(found: {', '.join(rows[0].keys())})"
            ),
            validator=VALIDATOR_NAME,
        )

    # 2) Parse each row's Next Due date. Track overdue rows, the worst-case
    #    days-overdue, and any rows whose date we could not parse.
    overdue: list[dict[str, Any]] = []
    upcoming: list[dict[str, Any]] = []
    unparseable: list[str] = []
    max_days_overdue = 0

    for i, row in enumerate(rows):
        label = _row_label(row, i)
        raw_due = (row.get(_DUE_COL) or "").strip()
        if not raw_due:
            unparseable.append(f"{label}: empty '{_DUE_COL}'")
            continue
        try:
            # days_since returns positive when the date is in the PAST. For a due
            # date, days_since > 0 means days OVERDUE; <= 0 means still in-cycle.
            days_overdue = lc.days_since(raw_due, today=today)
        except lc.ValidatorError as exc:
            unparseable.append(f"{label}: unparseable '{_DUE_COL}' {raw_due!r} ({exc})")
            continue

        record = {"review_type": label, "next_due": raw_due, "days_overdue": days_overdue}
        if days_overdue > 0:
            overdue.append(record)
            max_days_overdue = max(max_days_overdue, days_overdue)
        else:
            # days_until_due is the friendlier framing for in-cycle rows.
            record["days_until_due"] = -days_overdue
            upcoming.append(record)

    parsed_count = len(overdue) + len(upcoming)

    # 3) If nothing parsed into a date, we measured no cadence -> INDETERMINATE.
    if parsed_count == 0:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured={"total_rows": len(rows), "unparseable": unparseable},
            threshold=threshold,
            detail=(
                f"{schedule_path}: no parseable '{_DUE_COL}' date in any of "
                f"{len(rows)} row(s) -- nothing measurable"
            ),
            validator=VALIDATOR_NAME,
        )

    measured = {
        "max_days_overdue": max_days_overdue,
        "overdue_count": len(overdue),
        "in_cycle_count": len(upcoming),
        "total_rows": len(rows),
        "overdue": overdue,
        # EVIDENCE-ONLY context for the auditor (recorded, not gated): the schedule
        # references a sign-off / export artifact per review type; execution-truth
        # lives there, not in this cadence check.
        "unparseable": unparseable,
    }

    # 4) Verdict. Any overdue row -> FAIL; otherwise PASS.
    if overdue:
        worst = max(overdue, key=lambda r: r["days_overdue"])
        names = ", ".join(
            f"{r['review_type']} (due {r['next_due']}, {r['days_overdue']}d overdue)"
            for r in overdue
        )
        return lc.envelope(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured=measured,
            threshold=threshold,
            detail=(
                f"FAIL: {len(overdue)} access review(s) overdue "
                f"(worst: {worst['review_type']} by {worst['days_overdue']}d): {names}"
            ),
            validator=VALIDATOR_NAME,
        )

    soonest = min(upcoming, key=lambda r: r["days_until_due"])
    return lc.envelope(
        lc.Status.PASS,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold=threshold,
        detail=(
            f"PASS: all {parsed_count} access review(s) in-cycle "
            f"(soonest: {soonest['review_type']} due {soonest['next_due']}, "
            f"{soonest['days_until_due']}d out)"
        ),
        validator=VALIDATOR_NAME,
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR_NAME,
        description="A.8 access-review cadence freshness gate (NIS2 21(2)(i) / ISO 27001 A.8.2).",
    )
    parser.add_argument(
        "schedule",
        nargs="?",
        default=DEFAULT_SCHEDULE,
        help=f"path to the access-review schedule Markdown (default: {DEFAULT_SCHEDULE})",
    )
    parser.add_argument(
        "--heading",
        default=DEFAULT_HEADING,
        help=f"heading of the schedule table to parse (default: {DEFAULT_HEADING!r})",
    )
    parser.add_argument(
        "--out",
        default="access-review.json",
        help="path to write the JSON envelope (default: access-review.json); '-' to skip the file",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    env = evaluate(args.schedule, heading=args.heading)

    # Persist access-review.json (the named artifact) before emitting/exiting.
    if args.out and args.out != "-":
        try:
            Path(args.out).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:  # do not mask the verdict on a write failure; warn loudly
            print(f"{VALIDATOR_NAME}: WARNING could not write {args.out}: {exc}", file=sys.stderr)

    # emit() prints the envelope as one JSON line on stdout and exits with the
    # tier-aware code (BLOCKING: PASS->0, FAIL->1, INDETERMINATE->2).
    lc.emit(
        env["status"],
        env["tier"],
        measured=env["measured"],
        threshold=env["threshold"],
        detail=env["detail"],
        tool_version=env["tool_version"],
        validator=VALIDATOR_NAME,
    )
    return lc.exit_code_for(env["status"], env["tier"])  # pragma: no cover - emit exits first


if __name__ == "__main__":
    sys.exit(main())
