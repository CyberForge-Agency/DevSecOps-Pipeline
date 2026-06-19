#!/usr/bin/env python3
"""check-incident-register — A.4 statutory-clock schema validator (task T-23).

struktura §6 A.4 requires that every incident-register entry carries a
*classification* (severity + major/non-major decision + when it was made) and the
statutory *reporting-clock* fields, and that the procedure maps statutory
thresholds onto an incident-readiness artifact. The runbook already encodes the
correct DORA Art.19 three-phase clock and the DAST workflow auto-creates incident
issues with an SLA block — but nothing validated a register's *schema*. This does.

What it asserts (BLOCKING — false-positive-safe, deterministic)
--------------------------------------------------------------
* the register parses and matches ``schemas/incident-register.schema.json`` at the
  structural level (top-level ``incidents`` array; each entry has the required
  fields with the right types/enums);
* **every** entry has a populated ``classification_ts`` and a ``severity``;
* **every** entry has all four reporting-clock fields present *and populated*
  (non-null, non-empty): ``initial_4h``, ``early_warning_24h``,
  ``intermediate_72h``, ``final_1mo``.

A single missing classification or clock field makes the whole check FAIL
(exit 1) — that is the readiness gap A.4 exists to catch.

What it records (EVIDENCE-ONLY — a number, not a gate)
-----------------------------------------------------
* the incident *count* (``measured.entry_count``);
* an optional cross-check of open GitHub issues labelled ``security-incident``
  (created by ``dast.yml``) against register ids — informational only, never
  blocking, and silently skipped when ``gh`` is unavailable.

HONESTY (struktura §14 / blueprint/04 §9)
-----------------------------------------
This validator checks reporting *readiness* — that the clock is recorded and
fillable — NOT that a report was actually filed with KNF/CSIRT. The act of filing
is a human act and is not pipeline-verifiable, so it is never asserted as PASS.

Output
------
Emits the T-33 envelope (one JSON line) on stdout AND writes the richer
``incident-readiness.json`` next to it. Exit code follows the T-33 contract:
PASS->0, FAIL->1, INDETERMINATE->2 (BLOCKING tier).

Usage
-----
    python3 scripts/validators/check-incident-register.py [REGISTER.yaml] [--out PATH]

REGISTER defaults to ``docs/governance/incident-register.yaml`` resolved relative
to the Pipeline root.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

# Make the Pipeline root importable so ``scripts.validators.libcompliance`` resolves
# no matter the caller's CWD (mirrors the test harness bootstrap).
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "check-incident-register"
DEFAULT_REGISTER = _PIPELINE_ROOT / "docs" / "governance" / "incident-register.yaml"
DEFAULT_SCHEMA = _PIPELINE_ROOT / "schemas" / "incident-register.schema.json"
DEFAULT_OUT = _PIPELINE_ROOT / "incident-readiness.json"

# The four statutory reporting-clock fields every entry must populate (T-23 DoD).
CLOCK_FIELDS = ("initial_4h", "early_warning_24h", "intermediate_72h", "final_1mo")
# Top-level required fields per incident (mirrors the JSON schema's `required`).
REQUIRED_ENTRY_FIELDS = (
    "id",
    "detection_ts",
    "classification_ts",
    "severity",
    "major_bool",
    "clock",
)
ALLOWED_SEVERITIES = {"SEV-1", "SEV-2", "SEV-3", "SEV-4"}


class _Missing:
    """Sentinel so an empty *value* is distinguishable from a missing *key*."""


_MISSING = _Missing()


def _is_populated(value: Any) -> bool:
    """A clock/classification field counts as populated iff it is a non-empty string.

    ``None``, ``""`` and whitespace-only are NOT populated — those are exactly the
    readiness gaps the check exists to surface (a register row left half-filled).
    """
    return isinstance(value, str) and value.strip() != ""


def load_register(path: Path) -> tuple[Any, str | None]:
    """Load a YAML (or JSON) register, returning ``(data, error)``.

    Treats missing/empty/``{}``/``[]`` as no measurable content (-> INDETERMINATE),
    consistent with ``libcompliance.load_json``'s honesty about empty artifacts.
    """
    if not path.is_file():
        return None, f"{path}: file not found"
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return None, f"{path}: file is empty"
    try:
        import yaml  # PyYAML; available in the pipeline image
    except ImportError:  # pragma: no cover - fall back to JSON-only parsing
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            return None, f"{path}: PyYAML missing and not valid JSON ({exc})"
    else:
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:  # type: ignore[attr-defined]
            return None, f"{path}: invalid YAML ({exc})"
    if data in (None, {}, []):
        return None, f"{path}: empty register content (no measurable data)"
    return data, None


def validate_entries(data: Any) -> tuple[list[str], int]:
    """Structurally validate the register; return ``(errors, entry_count)``.

    Checks the top-level shape, then every entry's required fields, severity enum,
    ``major_bool`` type, and that the classification timestamp and all four clock
    fields are present *and populated*. ``errors`` is empty iff the register is
    schema-valid and reporting-ready.
    """
    errors: list[str] = []

    if not isinstance(data, dict):
        return [f"register root must be a mapping, got {type(data).__name__}"], 0
    incidents = data.get("incidents", _MISSING)
    if incidents is _MISSING:
        return ["register missing required top-level key 'incidents'"], 0
    if not isinstance(incidents, list):
        return [f"'incidents' must be a list, got {type(incidents).__name__}"], 0

    for idx, entry in enumerate(incidents):
        # A stable label for diagnostics: prefer the entry id, fall back to index.
        label = (
            entry.get("id")
            if isinstance(entry, dict) and _is_populated(entry.get("id"))
            else f"#{idx}"
        )
        if not isinstance(entry, dict):
            errors.append(f"entry {label}: must be a mapping, got {type(entry).__name__}")
            continue

        # Required top-level fields present.
        for field in REQUIRED_ENTRY_FIELDS:
            if entry.get(field, _MISSING) is _MISSING:
                errors.append(f"entry {label}: missing required field '{field}'")

        # Classification: severity enum + populated classification_ts.
        severity = entry.get("severity")
        if severity is not None and severity not in ALLOWED_SEVERITIES:
            errors.append(
                f"entry {label}: severity {severity!r} not in {sorted(ALLOWED_SEVERITIES)}"
            )
        if not _is_populated(entry.get("classification_ts")):
            errors.append(f"entry {label}: 'classification_ts' missing or empty")
        if not _is_populated(entry.get("detection_ts")):
            errors.append(f"entry {label}: 'detection_ts' missing or empty")
        if not isinstance(entry.get("major_bool"), bool):
            errors.append(f"entry {label}: 'major_bool' must be a boolean")

        # The statutory reporting clock: all four fields present AND populated.
        clock = entry.get("clock")
        if not isinstance(clock, dict):
            errors.append(f"entry {label}: 'clock' missing or not a mapping")
            continue
        for cf in CLOCK_FIELDS:
            if cf not in clock:
                errors.append(f"entry {label}: clock field '{cf}' missing")
            elif not _is_populated(clock.get(cf)):
                errors.append(f"entry {label}: clock field '{cf}' present but not populated")

    return errors, len(incidents)


def cross_check_github_issues(register: Any) -> dict[str, Any] | None:
    """EVIDENCE-ONLY: compare open ``security-incident`` issues to register ids.

    Returns a small dict summarising the cross-check, or ``None`` when ``gh`` is
    unavailable / errors / times out (the check degrades silently — it must never
    affect the BLOCKING result or the exit code).
    """
    try:
        proc = subprocess.run(
            ["gh", "issue", "list", "--label", "security-incident",
             "--state", "open", "--json", "number,title", "--limit", "100"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        issues = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(issues, list):
        return None
    ids = {
        e.get("id")
        for e in (register.get("incidents", []) if isinstance(register, dict) else [])
        if isinstance(e, dict)
    }
    # An issue is "linked" if any register id appears in its title (best-effort).
    unlinked = [
        i for i in issues
        if not any(rid and rid in (i.get("title") or "") for rid in ids)
    ]
    return {
        "open_security_incident_issues": len(issues),
        "without_matching_register_entry": len(unlinked),
    }


def run(register_path: Path, schema_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Execute the check; return ``(envelope, readiness_doc)`` without exiting.

    ``envelope`` is the T-33 BLOCKING envelope (drives the exit code). ``readiness_doc``
    is the richer ``incident-readiness.json`` payload: the envelope fields plus the
    EVIDENCE-ONLY count and any GitHub cross-check.
    """
    data, err = load_register(register_path)
    if err is not None:
        env = lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold="schema-valid register with all clock fields populated",
            detail=err,
            validator=VALIDATOR_NAME,
        )
        return env, {**env, "register": str(register_path), "errors": [err]}

    errors, count = validate_entries(data)
    schema_present = schema_path.is_file()
    if not schema_present:
        # The schema is the source-of-truth contract; its absence means we cannot
        # claim a schema PASS honestly -> INDETERMINATE, not a silent PASS.
        env = lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured={"entry_count": count},
            threshold="schema-valid register with all clock fields populated",
            detail=f"schema not found: {schema_path}",
            validator=VALIDATOR_NAME,
        )
        return env, {
            **env,
            "register": str(register_path),
            "schema": str(schema_path),
            "errors": [f"schema not found: {schema_path}"],
        }

    status = lc.Status.PASS if not errors else lc.Status.FAIL
    detail = (
        f"{count} incident(s); all entries carry classification + 4 reporting-clock fields"
        if not errors
        else f"{len(errors)} schema/clock violation(s) across {count} incident(s): "
        + "; ".join(errors[:8])
        + (" ..." if len(errors) > 8 else "")
    )
    env = lc.envelope(
        status,
        lc.Tier.BLOCKING,
        measured={"entry_count": count, "violations": len(errors)},
        threshold="schema-valid register with all 4 clock fields populated per entry",
        detail=detail,
        validator=VALIDATOR_NAME,
    )

    readiness = {
        **env,
        "register": str(register_path),
        "schema": str(schema_path),
        "errors": errors,
        # EVIDENCE-ONLY block: a recorded number, explicitly non-blocking.
        "evidence_only": {
            "tier": lc.Tier.EVIDENCE_ONLY,
            "entry_count": count,
        },
    }
    gh = cross_check_github_issues(data)
    if gh is not None:
        readiness["evidence_only"]["github_issue_cross_check"] = gh
    return env, readiness


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the ICT incident register (A.4 / T-23).")
    parser.add_argument(
        "register", nargs="?", default=str(DEFAULT_REGISTER),
        help="path to the incident register (YAML or JSON)",
    )
    parser.add_argument(
        "--schema", default=str(DEFAULT_SCHEMA),
        help="path to incident-register.schema.json",
    )
    parser.add_argument(
        "--out", default=str(DEFAULT_OUT),
        help="path to write incident-readiness.json",
    )
    args = parser.parse_args(argv)

    env, readiness = run(Path(args.register), Path(args.schema))

    # Write the richer readiness doc (with .status for the jq verification one-liner).
    Path(args.out).write_text(json.dumps(readiness, indent=2) + "\n", encoding="utf-8")

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
