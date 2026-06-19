#!/usr/bin/env python3
"""check-restore-test -- A.10 successful-restore proof + freshness (task T-29).

DORA Art. 11-12 (and NIS2 21(2)(c) / ISO/IEC 27001 A.8.13) require *periodic
genuine restoration tests* -- not merely the existence of a backup. A restore is
only credible evidence of recoverability when it actually completed and met the
stated Recovery Time Objective (RTO) within the cadence window. "Backups without
a restore test" is a named auditor rejection trigger (struktura S.12).

This validator therefore answers ONE honest question over
``docs/runbooks/restore-test-log.yaml``::

    Is there at least one logged restore drill that
        (a) outcome == "success"
        (b) was performed within the cadence window (default 365 days), and
        (c) met its RTO target (rto_actual <= rto_target)?

If yes -> PASS. If not (including the seed state where bcdr-plan.md S.6.1 still
says "Not yet conducted" and the log is empty) -> FAIL. There is NO file-presence
shortcut and NO auto-PASS from the schedule table: only a *logged successful test*
counts. This is the deliberate, honest opposite of presence-only checking.

Tier: BLOCKING. The assertion is deterministic and false-positive-safe (a missing
or non-success result can only make us FAIL/INDETERMINATE, never wrongly PASS), so
per the T-33 tiering rule it is allowed to gate the build.

EVIDENCE-ONLY aspect: whether the drill *truly* exercised a physically/logically
segregated system and produced the off-site evidence artifact (bcdr-plan.md S.6.3)
is not pipeline-verifiable from this log alone; that registration-truth is recorded
in ``measured`` (evidence path, sign-off) for the auditor but is not what gates.

Emits the T-33 envelope to stdout AND writes ``restore-test.json`` (path
overridable with ``--out``). ``measured`` records ``last_successful_test_date``
(per the acceptance criteria) plus the supporting metrics.

Usage:
    python3 scripts/validators/check-restore-test.py docs/runbooks/restore-test-log.yaml
    python3 scripts/validators/check-restore-test.py <log.yaml> --max-age-days 365 --out restore-test.json

Exit codes (via T-33 emit / BLOCKING tier):
    0  PASS           -- a successful, in-window, RTO-met restore exists
    1  FAIL           -- no qualifying successful restore (the honest default today)
    2  INDETERMINATE  -- the log could not be parsed / a required field is unmeasurable
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

VALIDATOR_NAME = "check-restore-test"

# Cadence window for the restore drill. bcdr-plan.md S.6.1 lists the Terraform-state
# restore drill as "Annually" -> 365 days. Overridable via --max-age-days.
DEFAULT_MAX_AGE_DAYS = 365

# Fields every logged test entry must carry to be *measurable*. A missing field
# means we cannot honestly evaluate that entry (-> INDETERMINATE), never a pass.
_REQUIRED_FIELDS = ("test_date", "scenario", "rto_target", "rto_actual", "outcome")

# The only outcome value that can count toward a PASS.
_SUCCESS = "success"


class _LogError(Exception):
    """Raised when the log cannot be parsed into a measurable structure."""


def _load_yaml(path: Path) -> Any:
    """Load the YAML log, returning the parsed structure.

    Uses PyYAML when available. If PyYAML is not installed we cannot reliably
    parse the log, so we raise ``_LogError`` -> the caller emits INDETERMINATE.
    We never guess content we could not parse.
    """
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise _LogError(
            "PyYAML is not installed; cannot parse the restore-test log "
            "(install pyyaml or provide a parseable log)"
        ) from exc
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise _LogError(f"{path}: cannot read file ({exc})") from exc
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as exc:  # type: ignore[attr-defined]
        raise _LogError(f"{path}: invalid YAML ({exc})") from exc


def _extract_tests(parsed: Any) -> list[dict[str, Any]]:
    """Pull the list of test entries out of the parsed document.

    Accepts either a top-level ``tests:`` mapping key or a bare top-level list.
    An empty / None document yields an empty list (the honest seed state).
    """
    if parsed is None:
        return []
    if isinstance(parsed, dict):
        tests = parsed.get("tests", [])
    elif isinstance(parsed, list):
        tests = parsed
    else:
        raise _LogError("log root must be a mapping with 'tests:' or a list of tests")
    if tests is None:
        return []
    if not isinstance(tests, list):
        raise _LogError("'tests' must be a list of test entries")
    out: list[dict[str, Any]] = []
    for i, entry in enumerate(tests):
        if not isinstance(entry, dict):
            raise _LogError(f"test entry #{i + 1} is not a mapping")
        out.append(entry)
    return out


def _as_number(value: Any) -> float | None:
    """Coerce a numeric-looking value to float; return None if not numeric.

    Booleans are explicitly rejected (True is not a measurement) -- same honesty
    rule the T-33 ``check_threshold`` helper enforces.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _qualify(entry: dict[str, Any], max_age_days: int, *, today: date | None) -> tuple[bool, str]:
    """Return (qualifies, reason) for a single test entry.

    An entry qualifies (counts toward PASS) iff it is measurable AND
    outcome==success AND within the cadence window AND rto_actual <= rto_target.
    The reason string explains either why it qualifies or why it was rejected,
    for the human-readable detail / audit trail.
    """
    # Measurability: every required field present.
    missing = [f for f in _REQUIRED_FIELDS if f not in entry or entry[f] in (None, "")]
    if missing:
        return False, f"missing required field(s): {', '.join(missing)}"

    outcome = str(entry["outcome"]).strip().lower()
    if outcome != _SUCCESS:
        return False, f"outcome={outcome!r} (not 'success')"

    rto_target = _as_number(entry["rto_target"])
    rto_actual = _as_number(entry["rto_actual"])
    if rto_target is None or rto_actual is None:
        return False, "rto_target/rto_actual not numeric"

    try:
        age = lc.days_since(str(entry["test_date"]), today=today)
    except lc.ValidatorError as exc:
        return False, f"unparseable test_date: {exc}"
    if age < 0:
        return False, f"test_date {entry['test_date']} is in the future"
    if age > max_age_days:
        return False, f"stale: {age}d old > {max_age_days}d cadence window"

    if rto_actual > rto_target:
        return False, f"RTO breached: actual {rto_actual} > target {rto_target}"

    return True, (
        f"success on {entry['test_date']} ({age}d ago); "
        f"RTO {rto_actual}<= {rto_target}"
    )


def evaluate(
    log_path: str | Path,
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate the restore-test log and return a T-33 envelope (no exit, no I/O side effects).

    Separated from ``main`` so unit tests can assert the verdict directly.
    """
    p = Path(log_path)

    # Presence: a missing log means we could not measure the control -> INDETERMINATE
    # (absence of evidence is not evidence of a failed control; that is what the
    # T-33 presence helper encodes). It still blocks (BLOCKING tier) but with code 2.
    if not p.is_file():
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold={"max_age_days": max_age_days, "rto": "actual<=target", "outcome": _SUCCESS},
            detail=f"{p}: restore-test log not found -- cannot verify any restore drill",
            validator=VALIDATOR_NAME,
        )

    try:
        parsed = _load_yaml(p)
        tests = _extract_tests(parsed)
    except _LogError as exc:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold={"max_age_days": max_age_days, "rto": "actual<=target", "outcome": _SUCCESS},
            detail=f"{p}: {exc}",
            validator=VALIDATOR_NAME,
        )

    threshold = {
        "max_age_days": max_age_days,
        "rto": "rto_actual<=rto_target",
        "outcome": _SUCCESS,
        "min_successful_in_window": 1,
    }

    qualifying: list[dict[str, Any]] = []
    rejections: list[str] = []
    for entry in tests:
        ok, reason = _qualify(entry, max_age_days, today=today)
        if ok:
            qualifying.append(entry)
        else:
            rejections.append(f"[{entry.get('scenario', '?')}] {reason}")

    if not qualifying:
        if not tests:
            why = "no restore drill logged (bcdr-plan.md S.6.1: 'Not yet conducted')"
        else:
            why = "no successful, in-window, RTO-met restore: " + "; ".join(rejections)
        return lc.envelope(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured={
                "last_successful_test_date": None,
                "successful_in_window": 0,
                "total_logged": len(tests),
                "rejections": rejections,
            },
            threshold=threshold,
            detail=f"FAIL: {why}",
            validator=VALIDATOR_NAME,
        )

    # PASS: pick the most recent qualifying success for the headline date.
    def _key(e: dict[str, Any]) -> str:
        return str(e.get("test_date", ""))

    latest = max(qualifying, key=_key)
    age = lc.days_since(str(latest["test_date"]), today=today)
    measured = {
        "last_successful_test_date": str(latest["test_date"]),
        "age_days": age,
        "scenario": latest.get("scenario"),
        "rto_target": _as_number(latest["rto_target"]),
        "rto_actual": _as_number(latest["rto_actual"]),
        "rpo_actual": _as_number(latest.get("rpo_actual")),
        "successful_in_window": len(qualifying),
        "total_logged": len(tests),
        # EVIDENCE-ONLY registration-truth (recorded, not gated): off-site artifact
        # + sign-off prove the drill happened on a segregated system per DORA Art.12.
        "evidence": latest.get("evidence"),
        "sign_off": latest.get("sign_off"),
    }
    return lc.envelope(
        lc.Status.PASS,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold=threshold,
        detail=(
            f"PASS: successful restore '{latest.get('scenario')}' on "
            f"{latest['test_date']} ({age}d ago, <= {max_age_days}d), "
            f"RTO {measured['rto_actual']} <= {measured['rto_target']}"
        ),
        validator=VALIDATOR_NAME,
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR_NAME,
        description="A.10 successful-restore proof + freshness validator (DORA Art. 11-12).",
    )
    parser.add_argument(
        "log",
        nargs="?",
        default="docs/runbooks/restore-test-log.yaml",
        help="path to the restore-test log YAML (default: docs/runbooks/restore-test-log.yaml)",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help=f"cadence window in days (default: {DEFAULT_MAX_AGE_DAYS})",
    )
    parser.add_argument(
        "--out",
        default="restore-test.json",
        help="path to write the JSON envelope (default: restore-test.json); '-' to skip the file",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    env = evaluate(args.log, max_age_days=args.max_age_days)

    # Persist restore-test.json (the named artifact) before emitting/exiting.
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
