#!/usr/bin/env python3
"""applicability.py — B.1-B.3 / Part 0.4 scope & applicability determination validator (T-120).

Validates the machine-readable scope & applicability determination
(``docs/governance/applicability.yaml``) that the Evidence Pack master spec
mandates in PART B (B.1 entity classification; B.2 system/data inventory &
residency map; B.3 regulatory applicability matrix WITH RATIONALE) and in
struktura Part 0.4 ("Oświadczenie o stosowalności").

Why this is BLOCKING (spec §8 anti-pattern #10 — a documented rejection trigger)
--------------------------------------------------------------------------------
"Scope hand-waving — no documented rationale for why DORA/NIS2/CRA do or don't
apply" is an explicit auditor REJECTION TRIGGER
(evidence-pack-specification.md:282). A pack that only carries narrative
"In scope" prose (build-audit-document.py:853) fails this trigger. This
validator makes the scope determination a STRUCTURED, FALSE-POSITIVE-SAFE,
machine-checked artifact: it FAILs the pipeline if any regime lacks an explicit
``applies`` decision or a non-empty ``rationale``.

What it checks (BLOCKING)
-------------------------
1. PRESENCE   — the applicability YAML and the JSON schema both exist + non-empty.
2. SCHEMA     — validates against schemas/applicability.schema.json (Draft 2020-12):
                entity classification fields, determination ownership/freshness,
                and per-regime name/applies/rationale/clause_basis/legal_basis.
3. CROSS-FIELD — rules the schema cannot cleanly express:
                * the four spec-required regimes (DORA, NIS2-KSC, CRA, RODO) are
                  all present;
                * EVERY regime has a boolean ``applies`` AND a non-empty
                  ``rationale`` (the T-120 DoD BLOCKING rule) AND a non-empty
                  clause_basis + legal_basis (an auditable determination);
                * the determination carries a named approver + role + a parseable
                  ISO date (the decision is owned, not anonymous).

What it does NOT claim (honesty / EVIDENCE-ONLY)
------------------------------------------------
It does NOT verify that the recorded applicability decision is LEGALLY CORRECT —
whether CyberForge truly is/ isn't in DORA Art.2 scope, or a NIS2 kluczowy/ważny
entity, is a legal judgement, not a pipeline-provable fact (poland-appendix.md:46).
The validator proves the determination is STRUCTURALLY COMPLETE and OWNED (the
exact thing the §8 #10 rejection trigger is about); the correspondence to the
entity's real legal position is an EVIDENCE-ONLY human attestation by the named
accountable officer, dated, ⚠️ confirm before sign-off.

Emits ``scope-determination.json`` via the T-33 envelope and exits with the
tier-aware code (PASS->0, FAIL->1, INDETERMINATE->2; see lc.exit_code_for).

Usage:
    applicability.py [APPLICABILITY_YAML] [SCHEMA_JSON] [--out FILE]

Defaults (resolved relative to the Pipeline root so the verification one-liner
`python3 scripts/validators/applicability.py docs/governance/applicability.yaml`
also works from the repo root):
    APPLICABILITY_YAML = docs/governance/applicability.yaml
    SCHEMA_JSON        = schemas/applicability.schema.json
    --out              = scope-determination.json   (cwd)
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

VALIDATOR_NAME = "applicability"
DEFAULT_YAML = "docs/governance/applicability.yaml"
DEFAULT_SCHEMA = "schemas/applicability.schema.json"
DEFAULT_OUT = "scope-determination.json"

# The regimes the master spec (Part B.1/B.3, §8 #10) requires a determination for.
REQUIRED_REGIMES = ("DORA", "NIS2-KSC", "CRA", "RODO")


def _resolve(path_str: str) -> Path:
    """Resolve a path arg: use as-is if it exists, else relative to the Pipeline root."""
    p = Path(path_str)
    if p.is_file():
        return p
    candidate = PIPELINE_ROOT / path_str
    return candidate if candidate.is_file() else p


def _tool_version() -> str | None:
    """Parsed (not hardcoded) jsonschema version for traceability."""
    try:
        from importlib.metadata import version

        return f"jsonschema {version('jsonschema')}"
    except Exception:  # pragma: no cover - never let traceability break a check
        return None


def _load_yaml(path: Path) -> tuple[Any, str | None]:
    """Load a YAML artifact, returning ``(data, error)`` (mirrors lc.load_json).

    Empty / ``{}`` / ``[]`` -> "no measurable content" (INDETERMINATE), closing
    the empty-artifact hole for YAML too.
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


def _nonempty_str(value: Any) -> bool:
    """True iff ``value`` is a non-empty/non-whitespace string."""
    return isinstance(value, str) and bool(value.strip())


def _nonempty_str_list(value: Any) -> bool:
    """True iff ``value`` is a list with at least one non-empty string."""
    return isinstance(value, list) and any(_nonempty_str(v) for v in value)


def _determination_errors(data: dict[str, Any]) -> list[str]:
    """The determination must be OWNED: named approver + role + parseable date."""
    errors: list[str] = []
    det = data.get("determination")
    if not isinstance(det, dict):
        return ["determination: missing — the scope decision must be owned, not anonymous"]
    if not _nonempty_str(det.get("approved_by")):
        errors.append("determination.approved_by: missing — name the accountable officer")
    if not _nonempty_str(det.get("approver_role")):
        errors.append("determination.approver_role: missing — state the approver's role")
    dd = det.get("determination_date")
    if not _nonempty_str(dd):
        errors.append("determination.determination_date: missing")
    else:
        try:
            lc.days_since(dd)  # parseable ISO date
        except lc.ValidatorError:
            errors.append(f"determination.determination_date: unparseable date {dd!r}")
    return errors


def _regime_errors(data: dict[str, Any]) -> list[str]:
    """Per-regime BLOCKING rules: applies + rationale + clause/legal basis (T-120 DoD).

    * the four spec-required regimes must all be present;
    * every regime present must carry a boolean ``applies`` AND a non-empty
      ``rationale`` (the headline T-120 rule) AND non-empty clause_basis +
      legal_basis (so the determination is auditable, not a bare yes/no).
    """
    errors: list[str] = []
    regimes = data.get("regimes")
    if not isinstance(regimes, dict) or not regimes:
        return ["regimes: missing or empty — a per-regime applicability matrix is required"]

    # 1) Completeness: the spec demands DORA/NIS2-KSC/CRA/RODO are each determined.
    for req in REQUIRED_REGIMES:
        if req not in regimes:
            errors.append(
                f"regimes.{req}: missing — spec §8 #10 requires an explicit "
                f"determination for {req}"
            )

    # 2) Field-level rules for every regime block that IS present.
    for key, block in regimes.items():
        if not isinstance(block, dict):
            errors.append(f"regimes.{key}: not a mapping")
            continue
        if not isinstance(block.get("applies"), bool):
            errors.append(
                f"regimes.{key}.applies: missing or non-boolean — every regime "
                f"needs an explicit applies: true|false (no scope hand-waving)"
            )
        if not _nonempty_str(block.get("rationale")):
            errors.append(
                f"regimes.{key}.rationale: empty — a documented rationale is "
                f"mandatory (spec §8 anti-pattern #10)"
            )
        if not _nonempty_str_list(block.get("clause_basis")):
            errors.append(
                f"regimes.{key}.clause_basis: empty — cite the clause(s) the "
                f"determination rests on"
            )
        if not _nonempty_str_list(block.get("legal_basis")):
            errors.append(
                f"regimes.{key}.legal_basis: empty — cite the legal instrument(s)"
            )
    return errors


def validate(yaml_path: Path, schema_path: Path) -> dict[str, Any]:
    """Run the full Part B / 0.4 check and return a ready T-33 envelope (no exit)."""
    tier = lc.Tier.BLOCKING
    tv = _tool_version()
    threshold = (
        "schema-valid; DORA/NIS2-KSC/CRA/RODO each with applies + non-empty "
        "rationale + clause/legal basis; named approver + dated determination"
    )

    # 1) Presence of both inputs (BLOCKING). A missing input -> INDETERMINATE.
    for label, p in (("applicability determination", yaml_path), ("applicability schema", schema_path)):
        pres = lc.check_presence(p, tier=tier, label=label, tool_version=tv)
        if pres["status"] != lc.Status.PASS:
            return pres  # INDETERMINATE: we could not measure the control

    # 2) Load both artifacts.
    data, err = _load_yaml(yaml_path)
    if err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold=threshold,
            detail=f"applicability load failed: {err}", tool_version=tv,
            validator=VALIDATOR_NAME,
        )
    schema, serr = lc.load_json(schema_path)
    if serr is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold="loadable JSON schema",
            detail=f"schema load failed: {serr}", tool_version=tv,
            validator=VALIDATOR_NAME,
        )

    if not isinstance(data, dict):
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold=threshold,
            detail="applicability YAML is not a mapping (expected an object root)",
            tool_version=tv, validator=VALIDATOR_NAME,
        )

    # 3) Schema validation (structural completeness).
    schema_errs = _schema_errors(data, schema)

    # 4) Cross-field logic (the BLOCKING T-120 rule + ownership).
    cross_errs = _determination_errors(data) + _regime_errors(data)

    all_errs = schema_errs + cross_errs

    regimes = data.get("regimes") if isinstance(data.get("regimes"), dict) else {}
    n_regimes = len(regimes)
    applies_summary = {
        k: v.get("applies")
        for k, v in regimes.items()
        if isinstance(v, dict)
    }

    if all_errs:
        preview = "; ".join(all_errs[:6])
        more = "" if len(all_errs) <= 6 else f" (+{len(all_errs) - 6} more)"
        return lc.envelope(
            lc.Status.FAIL, tier,
            measured={"regimes": n_regimes, "violations": len(all_errs)},
            threshold=threshold,
            detail=f"scope determination incomplete: {preview}{more}",
            tool_version=tv, validator=VALIDATOR_NAME,
        )

    return lc.envelope(
        lc.Status.PASS, tier,
        measured={"regimes": n_regimes, "violations": 0, "applies": applies_summary},
        threshold=threshold,
        detail=(
            f"scope & applicability determination complete: {n_regimes} regimes "
            f"each with applies + rationale + clause/legal basis; "
            f"approved_by='{data.get('determination', {}).get('approved_by')}', "
            f"dated {data.get('determination', {}).get('determination_date')}. "
            f"NOTE: structural completeness + ownership verified; legal correctness "
            f"of the determination is EVIDENCE-ONLY (named-officer attestation)."
        ),
        tool_version=tv, validator=VALIDATOR_NAME,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the scope & applicability determination (Part B / Part 0.4)."
    )
    parser.add_argument("yaml", nargs="?", default=DEFAULT_YAML, help="path to applicability.yaml")
    parser.add_argument("schema", nargs="?", default=DEFAULT_SCHEMA, help="path to applicability.schema.json")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output JSON path (default: scope-determination.json)")
    args = parser.parse_args(argv)

    yaml_path = _resolve(args.yaml)
    schema_path = _resolve(args.schema)

    env = validate(yaml_path, schema_path)

    # Persist the artifact (the pipeline consumes scope-determination.json).
    Path(args.out).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")

    # Emit one JSON line to stdout (no process exit here — main() owns the return code).
    print(json.dumps(env))

    return lc.exit_code_for(env["status"], env["tier"])


if __name__ == "__main__":
    sys.exit(main())
