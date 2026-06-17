#!/usr/bin/env python3
"""validate-roi — A.1 DORA Register of Information validator (struktura §6 A.1).

Validates the machine-readable Register of Information mandated by **DORA
Art.28(3)** and **Commission Implementing Regulation (EU) 2024/2956** (the ITS on
the register of information). This is the single strongest compliance
differentiator (blueprint/04 §6.3) and the seed of the Tier-2 Operated-Register
product; a bank's vendor questionnaire asks for exactly this artifact.

What it checks (and at which honesty tier — see libcompliance.Tier)
-------------------------------------------------------------------
BLOCKING (deterministic, false-positive-safe — a FAIL exits non-zero):
  1. **Schema** — the YAML validates against ``schemas/roi.schema.json``
     (structure + mandatory EBA template fields present).
  2. **LEI format** — every *issued* provider LEI matches ISO 17442
     (20 chars, ``^[A-Z0-9]{18}[0-9]{2}$``). Providers flagged
     ``NOT_LEI_ELIGIBLE`` (open-source foundations / locally-run tools) are
     excluded from the format set, not silently passed.
  3. **Completeness** — every Critical/High provider has a non-empty
     ``exit_plan_ref`` AND ``substitutability`` (DORA Art.28 exit-strategy /
     substitutability requirement).
  4. **Freshness** — the register's ``last_updated`` is within
     ``review_cadence_days`` of today (the ITS expects at least annual
     maintenance).

EVIDENCE-ONLY (recorded as a measured number, never blocks the build):
  * **LEI registration truth** — whether an LEI is actually issued and ACTIVE in
    the GLEIF database is NOT verifiable from inside the pipeline without a live
    GLEIF lookup, so it is reported as a count, never a blocking PASS. This is the
    honest boundary: the pipeline asserts *format*, an auditor (or the Tier-2
    Operated-Register service) asserts *registration*.
  * **Maintaining-entity LEI** — CyberForge has not yet been issued its own LEI
    (struktura §6 A.1 open question); the documented ``PENDING`` placeholder is
    surfaced as a gap, EVIDENCE-ONLY, rather than blocking on a value that is
    legitimately not-yet-issued.

Output
------
Emits the T-33 envelope (one JSON line) and writes ``roi-validation.json`` next to
the invocation (or to ``--out``). Exit code follows the T-33 tier rules: a
BLOCKING FAIL exits 1, INDETERMINATE exits 2, PASS/EVIDENCE-ONLY exit 0.

Usage
-----
    python3 scripts/validators/validate-roi.py \\
        docs/governance/register-of-information.yaml schemas/roi.schema.json
    jq .status roi-validation.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable no matter the cwd.
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR = "validate-roi"

# ISO 17442 LEI: 18 alphanumeric (upper) + 2 numeric check digits = 20 chars.
LEI_RE = re.compile(r"^[A-Z0-9]{18}[0-9]{2}$")

# Documented sentinel for a not-yet-issued maintaining-entity LEI (struktura A.1).
LEI_PENDING_SENTINEL = "PENDING-NOT-YET-ISSUED"

# Criticality levels for which exit plan + substitutability are MANDATORY.
BLOCKING_CRITICALITY = frozenset({"Critical", "High"})

# Provider lei_status values that are excluded from the LEI-format BLOCKING set.
LEI_FORMAT_EXEMPT = frozenset({"NOT_LEI_ELIGIBLE", "PENDING"})


class RoiError(Exception):
    """Raised for unrecoverable input problems (missing/unparseable register)."""


# --------------------------------------------------------------------------- #
# Loading                                                                      #
# --------------------------------------------------------------------------- #

def _load_yaml(path: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - environment guard
        raise RoiError(
            "PyYAML is required (pip install pyyaml jsonschema)"
        ) from exc
    if not path.is_file():
        raise RoiError(f"register not found: {path}")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise RoiError(f"register is empty: {path}")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RoiError(f"register is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RoiError("register root must be a mapping/object")
    return data


def _load_schema(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RoiError(f"schema not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RoiError(f"schema is not valid JSON: {exc}") from exc


# --------------------------------------------------------------------------- #
# Individual checks (pure: take data, return (ok, list[str] problems))         #
# --------------------------------------------------------------------------- #

def validate_schema(data: Any, schema: dict[str, Any]) -> list[str]:
    """Return a list of schema-violation messages (empty == valid)."""
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment guard
        raise RoiError(
            "jsonschema is required (pip install pyyaml jsonschema)"
        ) from exc
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    problems: list[str] = []
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "<root>"
        problems.append(f"schema: {loc}: {err.message}")
    return problems


def check_lei_format(data: dict[str, Any]) -> tuple[list[str], int, int]:
    """Validate provider LEI *format* (ISO 17442) for LEI-eligible providers.

    Returns (problems, n_checked, n_valid). Providers flagged NOT_LEI_ELIGIBLE /
    PENDING are skipped (and counted in neither checked nor valid). A null LEI on a
    non-exempt provider is a problem (a Critical bank vendor must carry an LEI).
    """
    problems: list[str] = []
    checked = 0
    valid = 0
    for tpp in data.get("ict_third_party", []):
        status = tpp.get("lei_status", "")
        ident = tpp.get("id", tpp.get("provider", "?"))
        if status in LEI_FORMAT_EXEMPT:
            continue
        lei = tpp.get("lei")
        checked += 1
        if not isinstance(lei, str) or not lei:
            problems.append(
                f"LEI format: {ident}: lei_status={status or 'unset'} requires an "
                f"LEI but none present"
            )
            continue
        if LEI_RE.fullmatch(lei):
            valid += 1
        else:
            problems.append(
                f"LEI format: {ident}: '{lei}' is not a valid ISO 17442 LEI "
                f"(expected 20 chars ^[A-Z0-9]{{18}}[0-9]{{2}}$)"
            )
    return problems, checked, valid


def check_completeness(data: dict[str, Any]) -> list[str]:
    """Exit plan + substitutability mandatory for Critical/High providers."""
    problems: list[str] = []
    for tpp in data.get("ict_third_party", []):
        crit = tpp.get("criticality", "")
        if crit not in BLOCKING_CRITICALITY:
            continue
        ident = tpp.get("id", tpp.get("provider", "?"))
        for field in ("exit_plan_ref", "substitutability"):
            val = tpp.get(field)
            if not isinstance(val, str) or not val.strip():
                problems.append(
                    f"completeness: {ident} ({crit}): missing/empty '{field}' "
                    f"(DORA Art.28 requires exit strategy + substitutability for "
                    f"critical/important functions)"
                )
    return problems


def count_lei_registration_status(data: dict[str, Any]) -> dict[str, int]:
    """EVIDENCE-ONLY tally of LEI registration posture (not pipeline-verifiable)."""
    tally = {"issued": 0, "placeholder": 0, "pending": 0, "not_lei_eligible": 0, "other": 0}
    for tpp in data.get("ict_third_party", []):
        status = (tpp.get("lei_status") or "").upper()
        if status == "ISSUED":
            tally["issued"] += 1
        elif status == "PLACEHOLDER":
            tally["placeholder"] += 1
        elif status == "PENDING":
            tally["pending"] += 1
        elif status == "NOT_LEI_ELIGIBLE":
            tally["not_lei_eligible"] += 1
        else:
            tally["other"] += 1
    return tally


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #

def build_envelope(register_path: Path, schema_path: Path) -> dict[str, Any]:
    """Run all checks and return the T-33 envelope (does not exit / write)."""
    try:
        data = _load_yaml(register_path)
        schema = _load_schema(schema_path)
    except RoiError as exc:
        # Could not measure anything -> INDETERMINATE, never a silent PASS.
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=None,
            detail=f"register/schema not loadable: {exc}",
            validator=VALIDATOR,
        )

    blocking_problems: list[str] = []

    # 1) Schema (BLOCKING).
    schema_problems = validate_schema(data, schema)
    blocking_problems.extend(schema_problems)

    # 2) LEI format (BLOCKING) — only meaningful if schema parsed structurally.
    lei_problems, lei_checked, lei_valid = check_lei_format(data)
    blocking_problems.extend(lei_problems)

    # 3) Completeness (BLOCKING).
    completeness_problems = check_completeness(data)
    blocking_problems.extend(completeness_problems)

    # 4) Freshness (BLOCKING) — only when schema gave us the entity block.
    fresh_detail = ""
    age_days: int | None = None
    cadence: int | None = None
    me = data.get("maintaining_entity") or {}
    last_updated = me.get("last_updated")
    cadence = me.get("review_cadence_days")
    if isinstance(last_updated, str) and isinstance(cadence, int):
        try:
            age_days = lc.days_since(last_updated)
            if age_days > cadence:
                blocking_problems.append(
                    f"freshness: register last_updated {last_updated} is {age_days} "
                    f"days old; cadence is {cadence} days"
                )
            fresh_detail = f"register {age_days}d old (cadence {cadence}d)"
        except lc.ValidatorError as exc:
            blocking_problems.append(f"freshness: {exc}")

    # EVIDENCE-ONLY context (recorded in measured, never blocks).
    lei_tally = count_lei_registration_status(data)
    me_lei = me.get("lei")
    me_lei_pending = (
        me_lei == LEI_PENDING_SENTINEL
        or not (isinstance(me_lei, str) and LEI_RE.fullmatch(me_lei))
    )

    measured = {
        "providers_total": len(data.get("ict_third_party", [])),
        "lei_checked": lei_checked,          # LEI-eligible providers
        "lei_format_valid": lei_valid,       # of those, valid ISO 17442 format
        "lei_registration": lei_tally,       # EVIDENCE-ONLY: GLEIF-truth not checked
        "maintaining_entity_lei_pending": me_lei_pending,  # EVIDENCE-ONLY gap
        "schema_violations": len(schema_problems),
        "completeness_violations": len(completeness_problems),
        "register_age_days": age_days,
        "blocking_problem_count": len(blocking_problems),
    }
    threshold = {
        "schema_violations": 0,
        "lei_format_invalid": 0,
        "completeness_violations": 0,
        "register_age_days_max": cadence,
    }

    if blocking_problems:
        detail = "BLOCKING failures: " + " | ".join(blocking_problems)
        return lc.envelope(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured=measured,
            threshold=threshold,
            detail=detail,
            validator=VALIDATOR,
        )

    notes = [
        f"schema OK; {lei_valid}/{lei_checked} LEI-eligible providers carry a "
        f"valid ISO 17442 LEI format",
        fresh_detail or "freshness not asserted (no last_updated/cadence)",
        "LEI registration truth is EVIDENCE-ONLY (GLEIF lookup outside pipeline)",
    ]
    if me_lei_pending:
        notes.append(
            "maintaining-entity LEI PENDING (CyberForge has no issued LEI) — "
            "EVIDENCE-ONLY gap, not blocking"
        )
    return lc.envelope(
        lc.Status.PASS,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold=threshold,
        detail="; ".join(notes),
        validator=VALIDATOR,
    )


def _default_out(register_path: Path) -> Path:
    return Path.cwd() / "roi-validation.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the DORA Register of Information (schema + LEI + freshness)."
    )
    parser.add_argument(
        "register",
        nargs="?",
        default=str(_PIPELINE_ROOT / "docs" / "governance" / "register-of-information.yaml"),
        help="path to register-of-information.yaml",
    )
    parser.add_argument(
        "schema",
        nargs="?",
        default=str(_PIPELINE_ROOT / "schemas" / "roi.schema.json"),
        help="path to roi.schema.json",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="path to write roi-validation.json (default: ./roi-validation.json)",
    )
    args = parser.parse_args(argv)

    register_path = Path(args.register)
    schema_path = Path(args.schema)
    out_path = Path(args.out) if args.out else _default_out(register_path)

    env = build_envelope(register_path, schema_path)

    # Persist the artifact for the compliance gate (T-30) to aggregate.
    out_path.write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")

    # Print the envelope (one JSON line) and exit with the tier-aware code.
    print(json.dumps(env))
    return lc.exit_code_for(env["status"], env["tier"])


if __name__ == "__main__":
    sys.exit(main())
