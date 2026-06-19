#!/usr/bin/env python3
"""check_tlpt -- C.9 DORA Threat-Led Penetration Testing (TLPT) validator.

DORA Art. 26-27 and the RTS in **Commission Delegated Regulation (EU) 2025/1190**
require an intelligence-led, TIBER-EU-aligned red-team test of an entity's live
critical functions **at least every 3 years** -- but ONLY for financial entities
the competent authority has *identified as significant for TLPT purposes*
(DORA Art. 26(8)). TLPT is therefore not universally mandatory, and the FIRST
honest control here is the **scope determination**.

This validator reads ``docs/governance/tlpt-record.yaml``, schema-validates it
against ``schemas/tlpt-record.schema.json``, then handles applicability honestly:

* ``in_scope == false``  -> **EVIDENCE-ONLY** result recording the documented
  out-of-scope determination. This is honest: the absence of a mandatory TLPT is
  correct for a non-identified entity, and we record the *rationale*, never a
  fabricated "TLPT passed". An EVIDENCE-ONLY result never blocks the build.

* ``in_scope == true``   -> **BLOCKING**. A genuine TLPT must exist that is
    (a) ``conducted == true`` with a ``test_date`` within the last 3 years
        (1095 days, the DORA triennial cadence),
    (b) ``external_testers == true`` (DORA Art. 27 / RTS 2025/1190),
    (c) carries ``authority_signoff == true`` (Art. 26(6)-(7) scope validation /
        attestation), and
    (d) carries a ``closure_status``.
  Until such a record exists the control HONESTLY **FAILs** -- there is no
  file-presence shortcut and no fabricated pass.

Honesty boundary
----------------
Whether the documented out-of-scope determination is *correct* (i.e. that no
competent authority has in fact identified the entity) is not pipeline-verifiable;
it is a documented governance determination surfaced EVIDENCE-ONLY for the auditor.
The pipeline asserts *internal consistency + freshness of an in-scope TLPT*, not
the supervisory designation itself.

Output
------
Emits the T-33 envelope (one JSON line) to stdout AND writes ``tlpt-record.json``
(override with ``--out``). Exit codes follow the T-33 tier rules:
    0  PASS, or any EVIDENCE-ONLY result (incl. documented out-of-scope)
    1  FAIL           -- in scope but no qualifying TLPT (the honest default if
                          the entity becomes in scope before a test is run)
    2  INDETERMINATE  -- record/schema not loadable (cannot measure the control)

Usage
-----
    python3 scripts/validators/check_tlpt.py \\
        docs/governance/tlpt-record.yaml --out tlpt-record.json
    jq .status tlpt-record.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable no matter the cwd.
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR = "check_tlpt"

# DORA triennial TLPT cadence: at least every 3 years. 3 * 365 = 1095 days.
DEFAULT_MAX_AGE_DAYS = 1095

_DEFAULT_RECORD = _PIPELINE_ROOT / "docs" / "governance" / "tlpt-record.yaml"
_DEFAULT_SCHEMA = _PIPELINE_ROOT / "schemas" / "tlpt-record.schema.json"


class TlptError(Exception):
    """Raised for unrecoverable input problems (missing/unparseable record/schema)."""


# --------------------------------------------------------------------------- #
# Loading                                                                      #
# --------------------------------------------------------------------------- #

def _load_yaml(path: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - environment guard
        raise TlptError("PyYAML is required (pip install pyyaml jsonschema)") from exc
    if not path.is_file():
        raise TlptError(f"TLPT record not found: {path}")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise TlptError(f"TLPT record is empty: {path}")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TlptError(f"TLPT record is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise TlptError("TLPT record root must be a mapping/object")
    return data


def _load_schema(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise TlptError(f"schema not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TlptError(f"schema is not valid JSON: {exc}") from exc


def validate_schema(data: Any, schema: dict[str, Any]) -> list[str]:
    """Return a list of schema-violation messages (empty == valid)."""
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment guard
        raise TlptError("jsonschema is required (pip install pyyaml jsonschema)") from exc
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    problems: list[str] = []
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "<root>"
        problems.append(f"schema: {loc}: {err.message}")
    return problems


# --------------------------------------------------------------------------- #
# In-scope evaluation                                                          #
# --------------------------------------------------------------------------- #

def _qualify_tlpt(
    tlpt: dict[str, Any] | None,
    max_age_days: int,
    *,
    today: date | None,
) -> tuple[bool, list[str], int | None]:
    """Return (qualifies, reasons, age_days) for an in-scope TLPT block.

    A qualifying TLPT is conducted, in-window (<= max_age_days), uses external
    testers, has authority sign-off, and carries a closure status. The reasons
    list explains every failed condition (empty when it qualifies).
    """
    reasons: list[str] = []
    if not isinstance(tlpt, dict):
        return False, ["no TLPT record present (tlpt block is null/empty)"], None

    if tlpt.get("conducted") is not True:
        reasons.append("conducted != true (TLPT not yet conducted)")

    age: int | None = None
    test_date = tlpt.get("test_date")
    if not test_date:
        reasons.append("missing test_date")
    else:
        try:
            age = lc.days_since(str(test_date), today=today)
            if age < 0:
                reasons.append(f"test_date {test_date} is in the future")
            elif age > max_age_days:
                reasons.append(
                    f"stale: TLPT {age}d old > {max_age_days}d (3-year DORA cadence)"
                )
        except lc.ValidatorError as exc:
            reasons.append(f"unparseable test_date: {exc}")

    if tlpt.get("external_testers") is not True:
        reasons.append("external_testers != true (DORA Art. 27 requires external testers)")

    if tlpt.get("authority_signoff") is not True:
        reasons.append(
            "missing authority_signoff (DORA Art. 26(6)-(7) scope validation/attestation)"
        )

    closure = tlpt.get("closure_status")
    if not isinstance(closure, str) or not closure.strip():
        reasons.append("missing closure_status (remediation/closure not recorded)")

    return (len(reasons) == 0), reasons, age


def build_envelope(
    record_path: str | Path,
    schema_path: str | Path,
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    today: date | None = None,
) -> dict[str, Any]:
    """Run the C.9 TLPT check and return a T-33 envelope (no exit / no I/O)."""
    try:
        data = _load_yaml(Path(record_path))
        schema = _load_schema(Path(schema_path))
    except TlptError as exc:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold={"max_age_days": max_age_days},
            detail=f"TLPT record/schema not loadable: {exc}",
            validator=VALIDATOR,
        )

    schema_problems = validate_schema(data, schema)
    if schema_problems:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured={"schema_violations": len(schema_problems)},
            threshold={"schema_violations": 0},
            detail="TLPT record fails schema validation: " + " | ".join(schema_problems),
            validator=VALIDATOR,
        )

    in_scope = bool(data.get("in_scope"))
    rationale = data.get("scope_rationale", "")
    entity = data.get("entity", {}) or {}
    entity_name = entity.get("name", "?")
    classification = entity.get("classification", "?")

    # --- Out of scope: EVIDENCE-ONLY documented determination (honest, not a pass). ---
    if not in_scope:
        measured = {
            "in_scope": False,
            "entity": entity_name,
            "classification": classification,
            "determination_date": data.get("determination_date"),
            "tlpt_conducted": False,
        }
        return lc.envelope(
            lc.Status.PASS,
            lc.Tier.EVIDENCE_ONLY,
            measured=measured,
            threshold={"in_scope": "applicability determination only"},
            detail=(
                "TLPT not mandatory for current entity classification "
                "(documented determination). "
                f"{entity_name}: {classification}. Rationale: {rationale}"
            ),
            validator=VALIDATOR,
        )

    # --- In scope: BLOCKING. Require a qualifying TLPT within 3 years. ---
    tlpt = data.get("tlpt")
    qualifies, reasons, age = _qualify_tlpt(tlpt, max_age_days, today=today)
    tlpt = tlpt if isinstance(tlpt, dict) else {}

    measured = {
        "in_scope": True,
        "entity": entity_name,
        "classification": classification,
        "tlpt_conducted": tlpt.get("conducted") is True,
        "last_test_date": tlpt.get("test_date"),
        "age_days": age,
        "external_testers": tlpt.get("external_testers") is True,
        "authority_signoff": tlpt.get("authority_signoff") is True,
        "closure_status": tlpt.get("closure_status"),
        "report_ref": tlpt.get("report_ref"),
        "rejections": reasons,
    }
    threshold = {
        "max_age_days": max_age_days,
        "external_testers": True,
        "authority_signoff": True,
        "closure_status": "required",
    }

    if not qualifies:
        return lc.envelope(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured=measured,
            threshold=threshold,
            detail=(
                f"FAIL: entity is in scope for TLPT but no qualifying TLPT "
                f"(<= {max_age_days}d, external testers, authority sign-off, "
                f"closure status): {'; '.join(reasons)}"
            ),
            validator=VALIDATOR,
        )

    return lc.envelope(
        lc.Status.PASS,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold=threshold,
        detail=(
            f"PASS: TLPT conducted on {tlpt.get('test_date')} ({age}d ago, "
            f"<= {max_age_days}d) by external testers with authority sign-off; "
            f"closure status '{tlpt.get('closure_status')}'"
        ),
        validator=VALIDATOR,
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR,
        description="C.9 DORA Threat-Led Penetration Testing (TLPT) validator "
        "(DORA Art. 26-27, RTS 2025/1190).",
    )
    parser.add_argument(
        "record",
        nargs="?",
        default=str(_DEFAULT_RECORD),
        help="path to tlpt-record.yaml (default: docs/governance/tlpt-record.yaml)",
    )
    parser.add_argument(
        "schema",
        nargs="?",
        default=str(_DEFAULT_SCHEMA),
        help="path to tlpt-record.schema.json (default: schemas/tlpt-record.schema.json)",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help=f"TLPT cadence window in days (default: {DEFAULT_MAX_AGE_DAYS} = 3 years)",
    )
    parser.add_argument(
        "--out",
        default="tlpt-record.json",
        help="path to write tlpt-record.json (default: ./tlpt-record.json); '-' to skip",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    env = build_envelope(args.record, args.schema, max_age_days=args.max_age_days)

    if args.out and args.out != "-":
        try:
            Path(args.out).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:  # do not mask the verdict on a write failure; warn loudly
            print(f"{VALIDATOR}: WARNING could not write {args.out}: {exc}", file=sys.stderr)

    lc.emit(
        env["status"],
        env["tier"],
        measured=env["measured"],
        threshold=env["threshold"],
        detail=env["detail"],
        tool_version=env["tool_version"],
        validator=VALIDATOR,
    )
    return lc.exit_code_for(env["status"], env["tier"])  # pragma: no cover - emit exits first


if __name__ == "__main__":
    sys.exit(main())
