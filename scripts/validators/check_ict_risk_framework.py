#!/usr/bin/env python3
"""check_ict_risk_framework -- E.1 ICT risk-management framework + annual review.

DORA Art. 6 requires a documented, governed ICT risk-management framework that is
reviewed **at least once a year** (Art. 6(5)); NIS2 Art. 21(2)(a) requires
"policies on risk analysis and information system security" approved by the
management body (Art. 20(1)). An auditor checks ONE top-level framework document
that (a) actually exists, (b) carries the required governance content, and (c) was
genuinely reviewed within the last year. The *content + freshness* of that document
is deterministically checkable; whether a human management review truly happened is
a human event the pipeline cannot prove.

This validator therefore answers two separated questions over
``docs/governance/ict-risk-management-framework.md``:

  BLOCKING (presence + freshness -- deterministic, false-positive-safe):
    1. Does the framework doc exist and is it non-empty?
    2. Does it contain every REQUIRED section (governance/ownership, risk
       appetite/tolerance, methodology reference, control-framework reference,
       review cadence)?
    3. Is there a parseable ``Last Reviewed:`` date AND is it within 365 days?

  EVIDENCE-ONLY (human attestation -- recorded, never gates):
    4. Is there a recorded management-body approval / review sign-off whose value
       is not a placeholder? This records the *fact* of an attestation; it cannot
       prove the review meeting actually occurred, so it never breaks the build.

Honest seed behaviour: the shipped framework doc records ``Last Reviewed: pending
initial management review`` (no real management review has occurred yet). The date
is therefore UNPARSEABLE -> this validator emits INDETERMINATE (BLOCKING, exit 2),
never a silent PASS on a founder-typed date. Once a genuine review is held and a
real ISO date is recorded, presence+freshness flips to PASS.

Tier: BLOCKING for presence/section/freshness (a missing section or stale/missing
review can only make us FAIL/INDETERMINATE, never wrongly PASS). The approval
sign-off fact is EVIDENCE-ONLY.

Emits the T-33 envelope to stdout AND writes ``ict-risk-framework.json`` (path
overridable with ``--out``).

Usage:
    python3 scripts/validators/check_ict_risk_framework.py docs/governance/ict-risk-management-framework.md
    python3 scripts/validators/check_ict_risk_framework.py <doc.md> --max-age-days 365 --out ict-risk-framework.json

Exit codes (via T-33 emit / BLOCKING tier):
    0  PASS           -- present, all sections, review within window
    1  FAIL           -- a required section missing, or the review is stale
    2  INDETERMINATE  -- doc missing/empty, or no parseable review date (the honest
                         seed state: "pending initial management review")
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
# regardless of the orchestrating shell's working directory.
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "check_ict_risk_framework"
DEFAULT_DOC = "docs/governance/ict-risk-management-framework.md"
DEFAULT_OUT = "ict-risk-framework.json"

# DORA Art. 6(5): the ICT risk-management framework is reviewed at least annually.
DEFAULT_MAX_AGE_DAYS = 365

ARTICLE = "DORA Art.6 / NIS2 Art.21(2)(a) (ICT risk-management framework + annual review)"
ARTICLE_APPROVAL = "NIS2 Art.20(1) (management-body approval of risk-management policies)"

# Required sections the framework MUST carry to be a credible DORA Art.6 framework.
# Each entry: (human label, regex matched against the document text, case-insensitive).
# Patterns match an ATX heading OR a recognisable phrase so the check is robust to
# minor heading wording while still being false-positive-safe (it asserts the concept
# is present, not merely a single keyword).
_REQUIRED_SECTIONS: tuple[tuple[str, str], ...] = (
    ("governance/ownership", r"#{1,6}[^\n]*\b(governance|ownership)\b"),
    ("risk appetite/tolerance", r"#{1,6}[^\n]*\brisk appetite\b|\brisk appetite\b"),
    ("methodology reference", r"#{1,6}[^\n]*\bmethodolog|risk-assessment-methodology\.md"),
    (
        "control-framework reference",
        r"#{1,6}[^\n]*\bcontrol framework\b|statement-of-applicability\.md",
    ),
    ("review cadence", r"#{1,6}[^\n]*\breview\b|\breview cadence\b"),
)

# ``Last Reviewed:`` label forms, in priority order, used to extract the review date.
_REVIEW_DATE_LABELS = ("Last Reviewed", "Last Review", "Reviewed")

_ISO_DATE = r"(\d{4}-\d{2}-\d{2})"


def _read_doc(path: Path) -> tuple[str | None, dict[str, Any] | None]:
    """Return ``(text, None)`` if the doc is present+non-empty, else ``(None, env)``.

    A missing or empty framework document means we could not measure the control
    -> INDETERMINATE (absence of evidence is not evidence of a failed control;
    the T-33 presence helper encodes this). BLOCKING tier, exit 2.
    """
    presence = lc.check_presence(path, tier=lc.Tier.BLOCKING, label="ICT risk framework")
    if presence["status"] != lc.Status.PASS:
        presence["detail"] = f"{presence['detail']} — required framework missing ({ARTICLE})"
        return None, presence
    return path.read_text(encoding="utf-8"), None


def _missing_sections(text: str) -> list[str]:
    """Return the labels of required sections NOT found in ``text``."""
    missing: list[str] = []
    for label, pattern in _REQUIRED_SECTIONS:
        if re.search(pattern, text, re.IGNORECASE) is None:
            missing.append(label)
    return missing


def _find_labelled_date(text: str, *labels: str) -> str | None:
    """Return the first ISO-8601 date that follows any of ``labels`` in ``text``.

    Tolerant of Markdown emphasis and ``:``/``|`` separators, mirroring
    check-governance's extractor. Returns None if the label is present but the value
    is non-ISO (e.g. the honest seed's ``pending initial management review``).
    """
    for label in labels:
        esc = re.escape(label)
        pattern = re.compile(
            rf"[*_ \t]*{esc}[*_ \t]*[:|]?[*_ \t|]*{_ISO_DATE}",
            re.IGNORECASE,
        )
        m = pattern.search(text)
        if m:
            return m.group(1)
    return None


def _approval_signoff(text: str) -> tuple[bool, str]:
    """EVIDENCE-ONLY: is a non-placeholder management-body approval recorded?

    Looks for an ``Approved By`` value that is not blank / underscores / a
    ``pending...`` placeholder. Returns ``(found, detail)``. Never gates the build.
    """
    m = re.search(
        r"[*_ \t]*Approved\s*By[*_ \t]*[:|][*_ \t|]*([^|\n]+)",
        text,
        re.IGNORECASE,
    )
    if m:
        value = m.group(1).strip().strip("*_ ")
        is_placeholder = (
            not value
            or re.fullmatch(r"[_\-\s]+", value) is not None
            or value.lower().startswith("pending")
            or value.lower().startswith("tbd")
        )
        if not is_placeholder:
            return True, f"management-body approval recorded: 'Approved By' = {value!r}"
        return False, f"approval field present but placeholder: {value!r}"
    return False, "no management-body approval ('Approved By') recorded"


def evaluate(
    doc_path: str | Path,
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate the ICT risk framework doc and return a T-33 envelope (no I/O, no exit).

    Separated from ``main`` so unit tests can assert the verdict directly. The
    overall verdict is BLOCKING and reflects presence + sections + freshness. The
    approval sign-off fact rides along in ``components`` as EVIDENCE-ONLY.
    """
    p = Path(doc_path)
    threshold = {
        "max_age_days": max_age_days,
        "required_sections": [label for label, _ in _REQUIRED_SECTIONS],
    }

    text, missing_env = _read_doc(p)
    if missing_env is not None:
        return missing_env  # INDETERMINATE, BLOCKING

    # 1) Required sections (BLOCKING FAIL if any missing).
    missing = _missing_sections(text)
    if missing:
        return lc.envelope(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured={"missing_sections": missing, "review_date": None},
            threshold=threshold,
            detail=(
                f"FAIL: framework missing required section(s): {', '.join(missing)} "
                f"({ARTICLE})"
            ),
            validator=VALIDATOR_NAME,
        )

    # 2) Parseable review date (INDETERMINATE if absent/non-ISO -- the honest seed).
    review_date = _find_labelled_date(text, *_REVIEW_DATE_LABELS)
    approval_found, approval_detail = _approval_signoff(text)
    approval = lc.envelope(
        lc.Status.PASS if approval_found else lc.Status.FAIL,
        lc.Tier.EVIDENCE_ONLY,
        measured=approval_found,
        threshold="management-body approval present",
        detail=f"{approval_detail} ({ARTICLE_APPROVAL})",
        validator=VALIDATOR_NAME,
    )

    if review_date is None:
        env = lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured={"missing_sections": [], "review_date": None},
            threshold=threshold,
            detail=(
                "INDETERMINATE: framework present with all required sections but no "
                "parseable 'Last Reviewed:' date (seed records 'pending initial "
                f"management review') — cannot assess annual review freshness ({ARTICLE})"
            ),
            validator=VALIDATOR_NAME,
        )
        env["components"] = {"management_body_approval": approval}
        return env

    # 3) Freshness against the annual cadence (BLOCKING).
    fresh = lc.check_fresh(
        review_date,
        max_age_days,
        tier=lc.Tier.BLOCKING,
        label="ICT risk framework review",
        today=today,
    )
    age = fresh.get("measured")
    if fresh["status"] == lc.Status.FAIL:
        detail = (
            f"FAIL: {fresh['detail']} — framework review STALE; rejection trigger: "
            f"{ARTICLE}"
        )
    elif fresh["status"] == lc.Status.INDETERMINATE:
        detail = f"INDETERMINATE: {fresh['detail']} ({ARTICLE})"
    else:
        detail = (
            f"PASS: framework present with all required sections; last reviewed "
            f"{review_date} ({age}d ago, <= {max_age_days}d) ({ARTICLE})"
        )

    env = lc.envelope(
        fresh["status"],
        lc.Tier.BLOCKING,
        measured={
            "missing_sections": [],
            "review_date": review_date,
            "review_age_days": age,
            "management_body_approval": approval_found,
        },
        threshold=threshold,
        detail=detail,
        validator=VALIDATOR_NAME,
    )
    env["components"] = {"management_body_approval": approval}
    return env


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR_NAME,
        description="E.1 ICT risk-management framework + annual review validator "
        "(DORA Art.6 / NIS2 Art.21(2)(a)).",
    )
    parser.add_argument(
        "doc",
        nargs="?",
        default=DEFAULT_DOC,
        help=f"path to the framework Markdown doc (default: {DEFAULT_DOC})",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help=f"annual review cadence window in days (default: {DEFAULT_MAX_AGE_DAYS})",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"path to write the JSON envelope (default: {DEFAULT_OUT}); '-' to skip the file",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    env = evaluate(args.doc, max_age_days=args.max_age_days)

    if args.out and args.out != "-":
        out_path = Path(args.out)
        if out_path.parent and not out_path.parent.exists():
            out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            out_path.write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:  # do not mask the verdict on a write failure
            print(
                f"{VALIDATOR_NAME}: WARNING could not write {args.out}: {exc}",
                file=sys.stderr,
            )

    # emit() prints the one-line envelope and exits with the tier-aware code.
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
