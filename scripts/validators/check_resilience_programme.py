#!/usr/bin/env python3
"""check_resilience_programme -- E.4 digital operational resilience testing PROGRAMME
(DORA Art. 24-25 / NIS2 21(2)(c) / ISO/IEC 27001 A.5.29-A.5.30).

DORA Art. 24-25 require a *programme* of resilience testing -- not merely the one
restore drill the A.10 control proves. The entity must define the scenario
CLASSES it exercises (backup-restore, failover, DR-drill, dependency-outage,
tabletop) and run each within a stated cadence. This validator answers ONE honest
question over ``docs/runbooks/resilience-testing-programme.yaml``::

    Does the programme (a) validate against its schema, (b) cover every REQUIRED
    scenario class, each carrying a positive cadence, and (c) is every scenario
    actually conducted -- i.e. last_run.outcome=="success" AND within its own
    cadence window (not never-run, not overdue)?

If yes -> PASS. If a required class is missing, a scenario was never run, a
scenario is overdue, or its last run was not a success -> FAIL, listing exactly
which scenarios are pending and why. There is NO file-presence shortcut: a
programme full of ``last_run: null`` (the honest seed state today) FAILs, just
like the A.10 restore-test FAILs while "Not yet conducted".

Tier: BLOCKING. The assertion is deterministic and false-positive-safe -- a
missing class, a never-run scenario, or an overdue/failed run can only make us
FAIL/INDETERMINATE, never wrongly PASS -- so per the T-33 tiering rule it gates.

No duplication of the A.10 restore-test: the ``backup-restore`` scenario merely
cross-references docs/runbooks/restore-test-log.yaml (the authoritative log for
THAT drill, validated by check-restore-test.py). This validator reads only the
programme's own ``last_run`` summary, never the restore-test log's RTO/RPO detail.

Emits the T-33 envelope to stdout AND writes ``resilience-programme.json`` (path
overridable with ``--out``).

Usage:
    python3 scripts/validators/check_resilience_programme.py \\
        docs/runbooks/resilience-testing-programme.yaml --out resilience-programme.json

Exit codes (via T-33 emit / BLOCKING tier):
    0  PASS           -- all required classes present, each conducted in-cadence
    1  FAIL           -- a missing class / never-run / overdue / failed scenario (honest default today)
    2  INDETERMINATE  -- the programme could not be parsed / schema unloadable
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

# Make the Pipeline root importable so ``scripts.validators.libcompliance`` resolves
# no matter the current working directory.
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "check_resilience_programme"

# Default schema location (overridable via --schema).
DEFAULT_SCHEMA = _PIPELINE_ROOT / "schemas" / "resilience-programme.schema.json"

# The scenario classes DORA Art.24-25 expects a resilience programme to cover.
# A programme missing any of these is incomplete -> BLOCKING FAIL.
REQUIRED_CLASSES = (
    "backup-restore",
    "failover",
    "DR-drill",
    "dependency-outage",
    "tabletop",
)

# The only last_run outcome that counts a scenario as conducted toward a PASS.
_SUCCESS = "success"


class _ProgError(Exception):
    """Raised when the programme cannot be parsed into a measurable structure."""


def _load_yaml(path: Path) -> Any:
    """Load the programme YAML. Raises _ProgError -> caller emits INDETERMINATE."""
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise _ProgError(
            "PyYAML is not installed; cannot parse the resilience programme "
            "(install pyyaml or provide a parseable file)"
        ) from exc
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise _ProgError(f"{path}: cannot read file ({exc})") from exc
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as exc:  # type: ignore[attr-defined]
        raise _ProgError(f"{path}: invalid YAML ({exc})") from exc


def _load_schema(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise _ProgError(f"schema not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise _ProgError(f"schema is not valid JSON: {exc}") from exc


def _validate_schema(data: Any, schema: dict[str, Any]) -> list[str]:
    """Return schema-violation messages (empty == valid). Raises if jsonschema missing."""
    try:
        import jsonschema  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment guard
        raise _ProgError("jsonschema is required (pip install jsonschema)") from exc
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    problems: list[str] = []
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "<root>"
        problems.append(f"schema: {loc}: {err.message}")
    return problems


def _assess_scenario(
    scenario: dict[str, Any], *, today: date | None
) -> tuple[bool, str]:
    """Return (conducted_in_cadence, reason) for one scenario.

    A scenario counts toward PASS iff it has a positive cadence, a non-null
    last_run with outcome=="success", and that run is within its own cadence
    window (not overdue). Anything else is a reason it is pending.
    """
    cadence = scenario.get("cadence_days")
    sid = scenario.get("id", "?")
    sclass = scenario.get("class", "?")
    if not isinstance(cadence, int) or isinstance(cadence, bool) or cadence < 1:
        return False, f"{sid} ({sclass}): no positive cadence_days"

    last_run = scenario.get("last_run")
    if last_run in (None, {}):
        return False, f"{sid} ({sclass}): never conducted (last_run null)"
    if not isinstance(last_run, dict):
        return False, f"{sid} ({sclass}): last_run is not a mapping"

    outcome = str(last_run.get("outcome", "")).strip().lower()
    run_date = last_run.get("date")
    if not run_date:
        return False, f"{sid} ({sclass}): last_run missing date"
    if outcome != _SUCCESS:
        return False, f"{sid} ({sclass}): last run outcome={outcome!r} (not 'success')"

    try:
        age = lc.days_since(str(run_date), today=today)
    except lc.ValidatorError as exc:
        return False, f"{sid} ({sclass}): unparseable last_run date ({exc})"
    if age < 0:
        return False, f"{sid} ({sclass}): last_run date {run_date} is in the future"
    if age > cadence:
        return False, (
            f"{sid} ({sclass}): overdue -- last run {run_date} is {age}d old "
            f"> {cadence}d cadence"
        )
    return True, f"{sid} ({sclass}): conducted {run_date} ({age}d ago, <= {cadence}d)"


def evaluate(
    programme_path: str | Path,
    schema_path: str | Path = DEFAULT_SCHEMA,
    *,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate the resilience programme and return a T-33 envelope (no exit/IO).

    Separated from ``main`` so unit tests can assert the verdict directly.
    """
    p = Path(programme_path)
    threshold = {
        "required_classes": list(REQUIRED_CLASSES),
        "per_scenario": "last_run.outcome=='success' AND age<=cadence_days",
        "min_conducted_per_class": 1,
    }

    if not p.is_file():
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=threshold,
            detail=f"{p}: resilience programme not found -- cannot verify any scenario",
            validator=VALIDATOR_NAME,
        )

    try:
        parsed = _load_yaml(p)
        schema = _load_schema(Path(schema_path))
        schema_problems = _validate_schema(parsed, schema)
    except _ProgError as exc:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=threshold,
            detail=f"{p}: {exc}",
            validator=VALIDATOR_NAME,
        )

    if schema_problems:
        return lc.envelope(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured={"schema_violations": len(schema_problems)},
            threshold=threshold,
            detail="schema FAIL: " + " | ".join(schema_problems),
            validator=VALIDATOR_NAME,
        )

    scenarios = parsed.get("scenarios", []) if isinstance(parsed, dict) else []
    classes_present = {str(s.get("class")) for s in scenarios}
    missing_classes = [c for c in REQUIRED_CLASSES if c not in classes_present]

    pending: list[str] = []
    conducted: list[str] = []
    # Track, per required class, whether at least one scenario of that class is
    # conducted-in-cadence.
    class_ok: dict[str, bool] = {c: False for c in REQUIRED_CLASSES}
    for s in scenarios:
        ok, reason = _assess_scenario(s, today=today)
        if ok:
            conducted.append(reason)
            sclass = str(s.get("class"))
            if sclass in class_ok:
                class_ok[sclass] = True
        else:
            pending.append(reason)

    # A required class with no in-cadence successful scenario is itself pending.
    uncovered_required = [
        c for c in REQUIRED_CLASSES if c not in missing_classes and not class_ok[c]
    ]

    measured = {
        "scenarios_total": len(scenarios),
        "required_classes": list(REQUIRED_CLASSES),
        "classes_present": sorted(classes_present),
        "missing_classes": missing_classes,
        "conducted_in_cadence": len(conducted),
        "pending_count": len(pending),
        "pending": pending,
        "uncovered_required_classes": uncovered_required,
    }

    if missing_classes or pending or uncovered_required:
        reasons: list[str] = []
        if missing_classes:
            reasons.append("missing required scenario class(es): " + ", ".join(missing_classes))
        if pending:
            reasons.append("pending scenarios: " + "; ".join(pending))
        return lc.envelope(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured=measured,
            threshold=threshold,
            detail="FAIL: " + " | ".join(reasons),
            validator=VALIDATOR_NAME,
        )

    return lc.envelope(
        lc.Status.PASS,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold=threshold,
        detail=(
            f"PASS: all {len(REQUIRED_CLASSES)} required resilience scenario classes "
            f"conducted within cadence ({len(conducted)} scenarios)"
        ),
        validator=VALIDATOR_NAME,
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR_NAME,
        description="E.4 digital operational resilience testing programme validator (DORA Art.24-25).",
    )
    parser.add_argument(
        "programme",
        nargs="?",
        default="docs/runbooks/resilience-testing-programme.yaml",
        help="path to the resilience-testing-programme YAML (default: docs/runbooks/resilience-testing-programme.yaml)",
    )
    parser.add_argument(
        "--schema",
        default=str(DEFAULT_SCHEMA),
        help=f"path to resilience-programme.schema.json (default: {DEFAULT_SCHEMA})",
    )
    parser.add_argument(
        "--out",
        default="resilience-programme.json",
        help="path to write the JSON envelope (default: resilience-programme.json); '-' to skip the file",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    env = evaluate(args.programme, args.schema)

    if args.out and args.out != "-":
        try:
            Path(args.out).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:  # do not mask the verdict on a write failure; warn loudly
            print(f"{VALIDATOR_NAME}: WARNING could not write {args.out}: {exc}", file=sys.stderr)

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
