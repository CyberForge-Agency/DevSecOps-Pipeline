#!/usr/bin/env python3
"""check_asset_map -- E.2 asset / dependency & critical-function map (DORA Art.8).

DORA Art.8 requires a financial entity to *identify, classify and document* all
ICT-supported business functions, the information assets supporting them, and the
ICT assets and third-party dependencies on which those functions rely. The map is
the foundation every downstream control (risk assessment, BC/DR, third-party
oversight) builds on -- an incomplete map is a named auditor finding.

This validator answers, over ``docs/governance/asset-map.yaml``::

    1. Does the map validate against schemas/asset-map.schema.json?           (schema)
    2. Does every critical_function map to >= 1 supporting asset?         (completeness)
    3. Does every referenced supporting-asset id resolve to a real asset? (referential)
    4. Does every asset carry a non-empty owner AND a criticality?        (completeness)
    5. Does every HIGH-criticality function carry a non-empty rto AND rpo?(completeness)

All five are BLOCKING and false-positive-safe: a violation can only make us
FAIL/INDETERMINATE, never wrongly PASS.

HONESTY (the spec)
------------------
Unlike A.10 restore-test (an *activity* not yet conducted -> honest FAIL), the
asset map is REAL architectural data transcribed from the existing inventories
(service-inventory.md, asset-inventory.md, vendor-risk-register.md, bcdr-plan.md),
so an honest PASS is legitimate. But the validator asserts only what is actually
mappable: a genuinely-unknown owner or a missing high-criticality RTO must be left
empty in the seed, and is reported as a completeness FAIL -- never invented to
manufacture a green.

Emits the T-33 envelope (one JSON line) and writes ``asset-map.json`` (override
with ``--out``). ``measured`` records the counts an auditor cares about.

Usage:
    python3 scripts/validators/check_asset_map.py docs/governance/asset-map.yaml \\
        --schema schemas/asset-map.schema.json --out asset-map.json

Exit codes (BLOCKING tier, via libcompliance):
    0  PASS           -- schema valid + all completeness assertions hold
    1  FAIL           -- a schema or completeness violation
    2  INDETERMINATE  -- the map/schema could not be loaded/parsed
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable regardless of cwd.
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR = "check_asset_map"

# Criticality levels for which RTO + RPO are MANDATORY (DORA recoverability).
RTO_RPO_REQUIRED = frozenset({"high"})


class AssetMapError(Exception):
    """Raised for unrecoverable input problems (missing/unparseable map or schema)."""


# --------------------------------------------------------------------------- #
# Loading                                                                      #
# --------------------------------------------------------------------------- #

def _load_yaml(path: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - environment guard
        raise AssetMapError(
            "PyYAML is required (pip install pyyaml jsonschema)"
        ) from exc
    if not path.is_file():
        raise AssetMapError(f"asset map not found: {path}")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise AssetMapError(f"asset map is empty: {path}")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AssetMapError(f"asset map is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise AssetMapError("asset map root must be a mapping/object")
    return data


def _load_schema(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise AssetMapError(f"schema not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AssetMapError(f"schema is not valid JSON: {exc}") from exc


# --------------------------------------------------------------------------- #
# Individual checks (pure: take data, return list[str] problems)               #
# --------------------------------------------------------------------------- #

def validate_schema(data: Any, schema: dict[str, Any]) -> list[str]:
    """Return a list of schema-violation messages (empty == valid)."""
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment guard
        raise AssetMapError(
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


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def check_asset_completeness(data: dict[str, Any]) -> list[str]:
    """Every asset must carry a non-empty owner AND a criticality."""
    problems: list[str] = []
    for asset in data.get("assets", []):
        ident = asset.get("id", "<no-id>")
        if not _nonempty_str(asset.get("owner")):
            problems.append(
                f"completeness: asset {ident}: missing/empty 'owner' "
                f"(DORA Art.8 requires an accountable owner; do not invent one)"
            )
        if not _nonempty_str(asset.get("criticality")):
            problems.append(
                f"completeness: asset {ident}: missing/empty 'criticality'"
            )
    return problems


def check_function_completeness(data: dict[str, Any]) -> list[str]:
    """Every critical_function maps to >=1 supporting asset; HIGH ones need RTO+RPO.

    Also enforces referential integrity: every supporting_asset id must resolve to
    a real entry in assets[] (an orphan reference is a mapping gap).
    """
    problems: list[str] = []
    known_ids = {a.get("id") for a in data.get("assets", []) if a.get("id")}
    for fn in data.get("critical_functions", []):
        name = fn.get("name", "<unnamed>")
        supporting = fn.get("supporting_assets") or []
        if not supporting:
            problems.append(
                f"completeness: critical_function '{name}': maps to 0 supporting "
                f"assets (every function must depend on >=1 asset)"
            )
        else:
            for aid in supporting:
                if aid not in known_ids:
                    problems.append(
                        f"completeness: critical_function '{name}': supporting "
                        f"asset '{aid}' does not resolve to any assets[].id"
                    )
        if (fn.get("criticality") or "").strip().lower() in RTO_RPO_REQUIRED:
            for field in ("rto", "rpo"):
                if not _nonempty_str(fn.get(field)):
                    problems.append(
                        f"completeness: critical_function '{name}' (high): "
                        f"missing/empty '{field}' (high-criticality functions "
                        f"must declare recovery objectives; do not invent one)"
                    )
    return problems


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #

def build_envelope(map_path: Path, schema_path: Path) -> dict[str, Any]:
    """Run all checks and return the T-33 envelope (does not exit / write)."""
    try:
        data = _load_yaml(map_path)
        schema = _load_schema(schema_path)
    except AssetMapError as exc:
        # Could not measure anything -> INDETERMINATE, never a silent PASS.
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold=None,
            detail=f"asset map/schema not loadable: {exc}",
            validator=VALIDATOR,
        )

    schema_problems = validate_schema(data, schema)
    asset_problems = check_asset_completeness(data)
    function_problems = check_function_completeness(data)
    blocking_problems = schema_problems + asset_problems + function_problems

    functions = data.get("critical_functions", []) or []
    assets = data.get("assets", []) or []
    high_fns = [
        f for f in functions
        if (f.get("criticality") or "").strip().lower() == "high"
    ]

    measured = {
        "critical_functions_total": len(functions),
        "high_criticality_functions": len(high_fns),
        "assets_total": len(assets),
        "assets_missing_owner": sum(
            1 for a in assets if not _nonempty_str(a.get("owner"))
        ),
        "schema_violations": len(schema_problems),
        "completeness_violations": len(asset_problems) + len(function_problems),
        "blocking_problem_count": len(blocking_problems),
    }
    threshold = {
        "schema_violations": 0,
        "completeness_violations": 0,
        "min_supporting_assets_per_function": 1,
        "rto_rpo_required_for": sorted(RTO_RPO_REQUIRED),
    }

    if blocking_problems:
        return lc.envelope(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured=measured,
            threshold=threshold,
            detail="BLOCKING failures: " + " | ".join(blocking_problems),
            validator=VALIDATOR,
        )

    return lc.envelope(
        lc.Status.PASS,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold=threshold,
        detail=(
            f"asset map OK: {len(functions)} critical functions "
            f"({len(high_fns)} high, all with RTO+RPO) mapped onto {len(assets)} "
            f"assets; every asset owned + classified; references resolve"
        ),
        validator=VALIDATOR,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR,
        description="Validate the DORA Art.8 asset / critical-function map (schema + completeness).",
    )
    parser.add_argument(
        "map",
        nargs="?",
        default=str(_PIPELINE_ROOT / "docs" / "governance" / "asset-map.yaml"),
        help="path to asset-map.yaml",
    )
    parser.add_argument(
        "--schema",
        default=str(_PIPELINE_ROOT / "schemas" / "asset-map.schema.json"),
        help="path to asset-map.schema.json",
    )
    parser.add_argument(
        "--out",
        default="asset-map.json",
        help="path to write the JSON envelope (default: asset-map.json); '-' to skip the file",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    env = build_envelope(Path(args.map), Path(args.schema))

    if args.out and args.out != "-":
        try:
            Path(args.out).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:  # do not mask the verdict on a write failure
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
