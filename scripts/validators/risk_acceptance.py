#!/usr/bin/env python3
"""risk_acceptance — risk-acceptance / exceptions-log validator + residual-risk emitter (task T-121).

The master spec (evidence-pack-specification.md §5.4-5.5) requires two coupled
compliance-state artifacts:

* **Risk-acceptance / exceptions log** (Part J.2) — every gap either remediated or
  *formally accepted* with a **named approver, a justification, and an expiry date**.
  Spec §8 anti-pattern #5 lists "Unbounded risk acceptances — no approver, no expiry"
  as an explicit **rejection trigger**. The register already exists at
  ``docs/compliance/exception-register.md`` (a GFM table with the columns
  ``ID | Vuln ID | Component | Severity | Owner | Approver | Justification |
  Compensating Controls | Approved Date | Expiry Date | Status | Issue Link``) but
  *nothing in the pipeline reads it* — so an unbounded acceptance would sail through.
* **Residual-risk statement** (Part D.4) — the post-mitigation residual posture,
  tied to the board-approved risk tolerance (DORA Art. 5(2): the management body
  "shall ... determine the appropriate risk tolerance level of ICT risk").

This validator closes both gaps in one deterministic, false-positive-safe check.

What it asserts (BLOCKING — deterministic, FP-safe)
---------------------------------------------------
For every **Active** acceptance row (the only rows that represent an *open* accepted
risk), the row must carry:

* a **named approver** (non-empty ``Approver`` cell);
* a **justification** (non-empty ``Justification`` cell);
* a **named risk owner** (non-empty ``Owner`` cell — the process requires the
  approver be a *different* named individual, so we also flag owner==approver);
* an **expiry date** that is present, parseable, **in the future**, and **within the
  12-month maximum** the process mandates (risk-acceptance-process.md §3, §5).

A single Active row that is missing approver / justification / owner, or whose
expiry is empty / unparseable / already past / more than 12 months after its
approval date, makes the whole check **FAIL (exit 1)** — that is exactly the
"unbounded risk acceptance" rejection trigger the spec calls out.

Rows whose Status is **Remediated** or **Expired** are *not* open accepted risks:
they are not enforced for the BLOCKING gate (a Remediated row needs no live approver;
an Expired row is already flagged by its own status). They are still recorded in the
residual-risk summary so the posture is complete and honest.

What it emits — residual-risk.json (Part D.4)
---------------------------------------------
A richer ``residual-risk.json`` aggregating the **open** (Active) accepted risks:
count, per-severity breakdown, the soonest expiry, each open acceptance's id /
control / approver / expiry, and a board-tolerance reference block. It carries the
T-33 envelope status so the compliance gate (T-30) and matrix can consume it
uniformly. The residual-risk *statement* is signed by the accountable officer at
seal time (sign-and-attest stream, post-M0) — this artifact is the machine-readable
substrate of that statement, NOT a claim that an officer has signed it.

HONESTY (struktura §14 / blueprint/04 §9)
-----------------------------------------
* An **empty register** (header only, no data rows) is a *valid* state — "no
  exceptions noted" — and is a **PASS** with ``open_count: 0``. It is never a silent
  pass dressed up as content: ``measured`` records the real number (0).
* A **missing register file** is **INDETERMINATE** (we could not measure the control),
  never FAIL — absence of evidence is not evidence of a failed control.
* This check verifies the *register's* discipline (approver/justification/expiry
  bounded). It does NOT assert that an accountable officer has actually signed the
  residual-risk statement — that is a human act, asserted only at signing time.

Output
------
Emits the T-33 envelope (one JSON line) on stdout AND writes the richer
``residual-risk.json``. Exit code follows the T-33 contract:
PASS->0, FAIL->1, INDETERMINATE->2 (BLOCKING tier).

Usage
-----
    python3 scripts/validators/risk_acceptance.py [EXCEPTION-REGISTER.md] [--out PATH]

EXCEPTION-REGISTER defaults to ``docs/compliance/exception-register.md`` resolved
relative to the Pipeline root.

Maps to: spec Part J.2 + D.4; evidence-pack-specification.md §5.4-5.5 + §8 #5;
DORA Art. 5(2) (board risk tolerance); ISO 27001:2022 Clause 6.1.2 (risk acceptance
criteria + risk owner); risk-acceptance-process.md §3, §5 (required fields, 12-month max).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

# Make the Pipeline root importable so ``scripts.validators.libcompliance`` resolves
# no matter the caller's CWD (mirrors the other validators' bootstrap).
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "risk_acceptance"
DEFAULT_REGISTER = _PIPELINE_ROOT / "docs" / "compliance" / "exception-register.md"
DEFAULT_OUT = _PIPELINE_ROOT / "residual-risk.json"
REGISTER_HEADING = "Exception Register"

# Status values that represent an *open* accepted risk: only these are enforced by
# the BLOCKING gate and counted as residual risk. (risk-acceptance-process.md §3.)
OPEN_STATUS = "active"
# Statuses recognised by the process (used to flag typos / unknown statuses).
KNOWN_STATUSES = {"active", "expired", "remediated"}

# Maximum acceptance duration the process mandates (risk-acceptance-process.md §3 §5:
# "Expiry Date ... maximum 12 months from approval date"). 12 months ~= 366 days to
# tolerate a leap year between approval and expiry without false-positiving.
MAX_ACCEPTANCE_DAYS = 366

# Column names in the register's GFM table (exception-register.md:21).
COL_ID = "ID"
COL_CONTROL = "Component"
COL_VULN = "Vuln ID"
COL_SEVERITY = "Severity"
COL_OWNER = "Owner"
COL_APPROVER = "Approver"
COL_JUSTIFICATION = "Justification"
COL_APPROVED = "Approved Date"
COL_EXPIRY = "Expiry Date"
COL_STATUS = "Status"

# Board-tolerance reference block embedded into residual-risk.json so the statement
# is anchored to the regulatory basis the spec requires (Part D.4 / DORA 5(2)).
BOARD_TOLERANCE_REF = {
    "basis": "DORA Art. 5(2) — the management body shall determine the appropriate "
             "risk tolerance level of ICT risk; residual risk must remain within it.",
    "iso_27001_2022": "Clause 6.1.2 — risk acceptance criteria are board-approved; "
                      "each accepted risk has a named risk owner.",
    "tolerance_document": "docs/governance/risk-acceptance-process.md",
    "risk_register": "docs/governance/risk-register.md",
}


def _cell(row: dict[str, str], key: str) -> str:
    """Return a trimmed cell value, '' when absent (GFM rows are str->str)."""
    return (row.get(key) or "").strip()


def _is_populated(value: str) -> bool:
    """A required field counts as populated iff it is a non-empty, non-placeholder string."""
    v = value.strip()
    if not v:
        return False
    # Treat common "empty" placeholders as not populated — these are exactly the
    # half-filled rows the check exists to surface.
    return v.lower() not in {"-", "—", "n/a", "na", "tbd", "todo", "none"}


def _status_key(value: str) -> str:
    """Normalise a Status cell to its lowercase token (strips Markdown emphasis/links)."""
    v = value.strip().lower()
    # Strip simple Markdown bold/italic markers around the status word.
    return v.strip("*_` ").strip()


def load_rows(register_path: Path) -> tuple[list[dict[str, str]] | None, str | None]:
    """Parse the register's GFM table; return ``(rows, error)``.

    A missing file or a register with no parseable table -> ``(None, reason)`` so the
    caller can emit INDETERMINATE. An *empty* table (header + separator, zero data
    rows) is a valid "no exceptions" state and returns ``([], None)``.
    """
    if not register_path.is_file():
        return None, f"{register_path}: file not found"
    try:
        rows = lc.gfm_table(str(register_path), REGISTER_HEADING)
    except lc.ValidatorError as exc:
        return None, f"{register_path}: {exc}"
    return rows, None


def _validate_row(row: dict[str, str], *, today: date) -> tuple[list[str], dict[str, Any]]:
    """Validate one Active acceptance row; return ``(violations, summary)``.

    ``violations`` is empty iff the row carries a named approver + named owner +
    justification + a bounded, future, <=12-month expiry. ``summary`` is the
    machine-readable record of the open risk for residual-risk.json.
    """
    rid = _cell(row, COL_ID) or "(no-id)"
    violations: list[str] = []

    approver = _cell(row, COL_APPROVER)
    owner = _cell(row, COL_OWNER)
    justification = _cell(row, COL_JUSTIFICATION)
    expiry_raw = _cell(row, COL_EXPIRY)
    approved_raw = _cell(row, COL_APPROVED)

    if not _is_populated(approver):
        violations.append(f"{rid}: missing named approver")
    if not _is_populated(owner):
        violations.append(f"{rid}: missing named risk owner")
    if not _is_populated(justification):
        violations.append(f"{rid}: missing justification")
    # Process §3: approver must be a *different* named individual from the owner.
    if _is_populated(approver) and _is_populated(owner) and \
            approver.casefold() == owner.casefold():
        violations.append(f"{rid}: approver is the same individual as the risk owner")

    expiry_date: date | None = None
    if not _is_populated(expiry_raw):
        violations.append(f"{rid}: missing expiry date (unbounded acceptance)")
    else:
        try:
            expiry_date = lc._parse_date(expiry_raw)
        except lc.ValidatorError:
            violations.append(f"{rid}: unparseable expiry date {expiry_raw!r}")
        else:
            if expiry_date < today:
                violations.append(
                    f"{rid}: expiry {expiry_raw} already passed (Active but expired)"
                )
            # 12-month cap is measured from approval date when present.
            if _is_populated(approved_raw):
                try:
                    approved_date = lc._parse_date(approved_raw)
                except lc.ValidatorError:
                    violations.append(f"{rid}: unparseable approved date {approved_raw!r}")
                else:
                    span = (expiry_date - approved_date).days
                    if span > MAX_ACCEPTANCE_DAYS:
                        violations.append(
                            f"{rid}: acceptance window {span}d exceeds 12-month max "
                            f"({MAX_ACCEPTANCE_DAYS}d) — approved {approved_raw}, "
                            f"expires {expiry_raw}"
                        )

    days_to_expiry = (expiry_date - today).days if expiry_date is not None else None
    summary = {
        "id": rid,
        "control": _cell(row, COL_CONTROL) or _cell(row, COL_VULN),
        "vuln_id": _cell(row, COL_VULN),
        "severity": _cell(row, COL_SEVERITY),
        "owner": owner,
        "approver": approver,
        "expiry": expiry_raw,
        "days_to_expiry": days_to_expiry,
        "violations": violations,
    }
    return violations, summary


def run(register_path: Path, *, today: date | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Execute the check; return ``(envelope, residual_doc)`` without exiting."""
    ref = today if today is not None else date.today()
    rows, err = load_rows(register_path)
    threshold = (
        "every Active acceptance has a named approver, named owner, justification, "
        "and a future expiry within 12 months of approval"
    )

    if err is not None:
        env = lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=threshold,
            detail=err,
            validator=VALIDATOR_NAME,
        )
        return env, {**env, "register": str(register_path), "errors": [err]}

    assert rows is not None
    open_risks: list[dict[str, Any]] = []
    all_violations: list[str] = []
    severity_breakdown: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    unknown_statuses: list[str] = []

    for row in rows:
        status = _status_key(_cell(row, COL_STATUS))
        status_counts[status] = status_counts.get(status, 0) + 1
        if status and status not in KNOWN_STATUSES:
            unknown_statuses.append(f"{_cell(row, COL_ID) or '(no-id)'}: status {status!r}")
        if status != OPEN_STATUS:
            continue  # only Active rows are open accepted risks subject to the gate
        violations, summary = _validate_row(row, today=ref)
        all_violations.extend(violations)
        open_risks.append(summary)
        sev = (summary["severity"] or "Unspecified").strip() or "Unspecified"
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    open_count = len(open_risks)
    # Unknown statuses are a data-hygiene FAIL too (a typo could hide an Active risk).
    if unknown_statuses:
        all_violations.extend(
            f"unrecognised status (expected Active/Expired/Remediated): {u}"
            for u in unknown_statuses
        )

    soonest_expiry = None
    dated = [r for r in open_risks if isinstance(r.get("days_to_expiry"), int)]
    if dated:
        nearest = min(dated, key=lambda r: r["days_to_expiry"])
        soonest_expiry = {"id": nearest["id"], "expiry": nearest["expiry"],
                          "days_to_expiry": nearest["days_to_expiry"]}

    status = lc.Status.PASS if not all_violations else lc.Status.FAIL
    if not all_violations:
        detail = (
            f"{open_count} open accepted risk(s); all bounded with named approver + "
            f"justification + future expiry (<=12mo)"
            if open_count
            else "no open accepted risks (register clean / no exceptions noted)"
        )
    else:
        detail = (
            f"{len(all_violations)} unbounded/invalid acceptance(s) across "
            f"{open_count} open risk(s) [spec §8 anti-pattern #5]: "
            + "; ".join(all_violations[:8])
            + (" ..." if len(all_violations) > 8 else "")
        )

    env = lc.envelope(
        status,
        lc.Tier.BLOCKING,
        measured={"open_count": open_count, "violations": len(all_violations)},
        threshold=threshold,
        detail=detail,
        validator=VALIDATOR_NAME,
    )

    residual_doc = {
        **env,
        "register": str(register_path),
        "errors": all_violations,
        # The residual-risk statement (Part D.4) substrate.
        "residual_risk": {
            "open_accepted_risks": open_count,
            "by_severity": severity_breakdown,
            "soonest_expiry": soonest_expiry,
            "open_risks": open_risks,
            "status_counts": status_counts,
            "board_tolerance": BOARD_TOLERANCE_REF,
            "statement": (
                f"As of {ref.isoformat()}, {open_count} accepted ICT risk(s) remain open, "
                "each formally approved, justified, and time-bounded. Residual risk is "
                "asserted to remain within the board-approved risk tolerance (DORA Art. 5(2)); "
                "this statement is to be signed by the accountable officer at seal time."
                if open_count
                else f"As of {ref.isoformat()}, no accepted ICT risks remain open. "
                "Residual risk is within the board-approved tolerance (DORA Art. 5(2))."
            ),
            "signed_by_accountable_officer": False,  # human act, asserted only at sign time
        },
    }
    return env, residual_doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the risk-acceptance/exceptions log and emit residual-risk.json (T-121).",
    )
    parser.add_argument(
        "register", nargs="?", default=str(DEFAULT_REGISTER),
        help="path to the exception register (Markdown, GFM table)",
    )
    parser.add_argument(
        "--out", default=str(DEFAULT_OUT),
        help="path to write residual-risk.json",
    )
    args = parser.parse_args(argv)

    env, residual_doc = run(Path(args.register))

    Path(args.out).write_text(json.dumps(residual_doc, indent=2) + "\n", encoding="utf-8")

    # Emit the T-33 envelope line and exit with the tier-aware code.
    lc.emit(
        env["status"],
        env["tier"],
        measured=env["measured"],
        threshold=env["threshold"],
        detail=env["detail"],
        validator=VALIDATOR_NAME,
    )
    return 0  # unreachable: emit() exits


if __name__ == "__main__":
    sys.exit(main())
