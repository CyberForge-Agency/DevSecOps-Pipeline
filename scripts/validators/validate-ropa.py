#!/usr/bin/env python3
"""validate-ropa.py — A.3 RoPA/DPIA presence + RODO Art.30 completeness validator (T-22).

Validates that the Records of Processing Activities (RoPA) document exists as a
discrete artifact and is COMPLETE per RODO/GDPR Art.30(1) (controller record) and
Art.30(2) (processor record), and that the Art.35 DPIA question is answered as a
documented determination — never silence (struktura §6 A.3, §12).

What it checks (BLOCKING)
-------------------------
1. PRESENCE   — the RoPA YAML and the JSON schema both exist and are non-empty.
2. SCHEMA     — the RoPA validates against schemas/ropa.schema.json (Draft-07):
                controller identity+contact, and per-activity: purposes, lawful_basis,
                categories of data subjects + personal data, recipients, third-country
                transfers, retention (erasure limits), Art.32 security measures.
3. DPIA LOGIC — cross-field rules the schema can't cleanly express:
                * every high_risk=true activity MUST carry a non-empty dpia_ref;
                * every high_risk=false activity MUST carry a dpia_not_required_reason;
                * a top-level dpia_determination MUST be present, and when its status is
                  'required'/'completed' it MUST list at least one dpia_ref.

What it does NOT claim (honesty / EVIDENCE-ONLY)
------------------------------------------------
It does NOT verify that the recorded controller details, retention periods, security
measures or DPIA references are FACTUALLY true or legally adequate — those are facts
asserted by the data controller in the record. The validator proves the RoPA is a
complete, internally consistent, discrete artifact (which is exactly the auditor
rejection trigger in struktura §12), not that the underlying processing is lawful.

Emits ``ropa-completeness.json`` via the T-33 envelope and exits with the tier-aware
code (PASS->0, FAIL->1, INDETERMINATE->2; see libcompliance.exit_code_for).

Usage:
    validate-ropa.py [ROPA_YAML] [SCHEMA_JSON] [--out FILE]

Defaults (resolved relative to the Pipeline root, so the verification one-liner
`python3 scripts/validators/validate-ropa.py docs/governance/ropa.yaml schemas/ropa.schema.json`
also works from the repo root):
    ROPA_YAML   = docs/governance/ropa.yaml
    SCHEMA_JSON = schemas/ropa.schema.json
    --out       = ropa-completeness.json   (cwd)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable no matter the cwd. The
# Pipeline root is two parents up from this file (Pipeline/scripts/validators/).
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "validate-ropa"
DEFAULT_ROPA = "docs/governance/ropa.yaml"
DEFAULT_SCHEMA = "schemas/ropa.schema.json"
DEFAULT_OUT = "ropa-completeness.json"


def _resolve(path_str: str) -> Path:
    """Resolve a path argument: use it as-is if it exists, else relative to root.

    Lets the validator be called with paths relative to the repo root (as the
    task's verification one-liner does) regardless of the current directory.
    """
    p = Path(path_str)
    if p.is_file():
        return p
    candidate = PIPELINE_ROOT / path_str
    return candidate if candidate.is_file() else p


def _tool_version() -> str | None:
    """Parsed (not hardcoded) version of the jsonschema engine, for traceability."""
    try:
        from importlib.metadata import version

        return f"jsonschema {version('jsonschema')}"
    except Exception:  # pragma: no cover - never let traceability break a check
        return None


def _load_yaml(path: Path) -> tuple[Any, str | None]:
    """Load a YAML artifact, returning ``(data, error)`` mirroring lib.load_json.

    An empty / ``{}`` / ``[]`` document is treated as "no measurable content"
    (INDETERMINATE), closing the empty-artifact hole for YAML too.
    """
    try:
        import yaml
    except ImportError:
        return None, "PyYAML is not installed (pip install pyyaml)"
    if not path.is_file():
        return None, f"{path}: file not found"
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return None, f"{path}: file is empty"
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return None, f"{path}: invalid YAML ({exc})"
    if data in (None, {}, []):
        return None, f"{path}: empty YAML content (no measurable data)"
    return data, None


def _schema_errors(data: Any, schema: dict[str, Any]) -> list[str]:
    """Return human-readable schema violations (empty list == valid)."""
    try:
        import jsonschema
    except ImportError:
        return ["jsonschema is not installed (pip install jsonschema)"]
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    errors = []
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path)):
        loc = "/".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"{loc}: {err.message}")
    return errors


def _dpia_logic_errors(data: dict[str, Any]) -> list[str]:
    """Cross-field DPIA-determination checks the JSON schema cannot cleanly express.

    Rules (task T-22 acceptance + the 'no silence' hint):
      * high_risk == True  -> dpia_ref must be present and non-empty.
      * high_risk == False -> dpia_not_required_reason must be present and non-empty.
      * dpia_determination must exist; status required/completed -> dpia_refs non-empty.
    """
    errors: list[str] = []

    determination = data.get("dpia_determination")
    if not isinstance(determination, dict):
        errors.append("dpia_determination: missing — the DPIA decision must be documented, not silent")
    else:
        status = determination.get("status")
        refs = determination.get("dpia_refs") or []
        if status in ("required", "completed") and not [r for r in refs if str(r).strip()]:
            errors.append(
                f"dpia_determination: status '{status}' requires at least one dpia_refs entry"
            )

    activities = data.get("activities")
    if not isinstance(activities, list) or not activities:
        # Schema already flags this; guard so the loop below is safe.
        return errors

    for idx, act in enumerate(activities):
        if not isinstance(act, dict):
            errors.append(f"activities[{idx}]: not a mapping")
            continue
        aid = act.get("id", f"index {idx}")
        high_risk = act.get("high_risk")
        if high_risk is True:
            ref = act.get("dpia_ref")
            if not (isinstance(ref, str) and ref.strip()):
                errors.append(
                    f"activity {aid}: high_risk=true requires a non-empty dpia_ref (Art.35)"
                )
        elif high_risk is False:
            reason = act.get("dpia_not_required_reason")
            if not (isinstance(reason, str) and reason.strip()):
                errors.append(
                    f"activity {aid}: high_risk=false requires a documented "
                    f"dpia_not_required_reason (no silence)"
                )
        # high_risk neither True nor False is caught by the schema (boolean required).

    return errors


def validate(ropa_path: Path, schema_path: Path) -> dict[str, Any]:
    """Run the full A.3 check and return a ready T-33 envelope (does not exit)."""
    tier = lc.Tier.BLOCKING
    tv = _tool_version()

    # 1) Presence of both inputs (BLOCKING). A missing input -> INDETERMINATE.
    for label, p in (("RoPA document", ropa_path), ("RoPA schema", schema_path)):
        pres = lc.check_presence(p, tier=tier, label=label, tool_version=tv)
        if pres["status"] != lc.Status.PASS:
            return pres  # INDETERMINATE: we could not measure the control

    # 2) Load both artifacts.
    data, err = _load_yaml(ropa_path)
    if err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold="schema-valid RoPA",
            detail=f"RoPA load failed: {err}", tool_version=tv, validator=VALIDATOR_NAME,
        )
    schema, serr = lc.load_json(schema_path)
    if serr is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold="loadable JSON schema",
            detail=f"schema load failed: {serr}", tool_version=tv, validator=VALIDATOR_NAME,
        )

    # 3) Schema validation (Art.30 field completeness).
    schema_errs = _schema_errors(data, schema)

    # 4) Cross-field DPIA-determination logic.
    dpia_errs = _dpia_logic_errors(data) if not schema_errs or isinstance(data, dict) else []

    all_errs = schema_errs + dpia_errs
    activities = data.get("activities") if isinstance(data, dict) else None
    n_activities = len(activities) if isinstance(activities, list) else 0

    if all_errs:
        preview = "; ".join(all_errs[:6])
        more = "" if len(all_errs) <= 6 else f" (+{len(all_errs) - 6} more)"
        return lc.envelope(
            lc.Status.FAIL, tier,
            measured={"activities": n_activities, "violations": len(all_errs)},
            threshold="0 violations; Art.30(1)/(2) complete + DPIA determination recorded",
            detail=f"RoPA incomplete: {preview}{more}",
            tool_version=tv, validator=VALIDATOR_NAME,
        )

    determination_status = (
        data.get("dpia_determination", {}).get("status") if isinstance(data, dict) else None
    )
    return lc.envelope(
        lc.Status.PASS, tier,
        measured={"activities": n_activities, "violations": 0,
                  "dpia_determination": determination_status},
        threshold="0 violations; Art.30(1)/(2) complete + DPIA determination recorded",
        detail=(
            f"RoPA present and complete: {n_activities} processing "
            f"activit{'y' if n_activities == 1 else 'ies'} satisfy RODO Art.30; "
            f"DPIA determination='{determination_status}'. "
            f"NOTE: completeness verified, factual truth of recorded content is EVIDENCE-ONLY."
        ),
        tool_version=tv, validator=VALIDATOR_NAME,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the RoPA against RODO Art.30 + DPIA logic.")
    parser.add_argument("ropa", nargs="?", default=DEFAULT_ROPA, help="path to ropa.yaml")
    parser.add_argument("schema", nargs="?", default=DEFAULT_SCHEMA, help="path to ropa.schema.json")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output JSON path (default: ropa-completeness.json)")
    args = parser.parse_args(argv)

    ropa_path = _resolve(args.ropa)
    schema_path = _resolve(args.schema)

    env = validate(ropa_path, schema_path)

    # Persist the artifact (the pipeline consumes ropa-completeness.json).
    Path(args.out).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")

    # Emit one JSON line to stdout (no process exit here — main() owns the return code).
    print(json.dumps(env))

    return lc.exit_code_for(env["status"], env["tier"])


if __name__ == "__main__":
    sys.exit(main())
