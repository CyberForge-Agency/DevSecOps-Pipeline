#!/usr/bin/env python3
"""generate-data-flow — render the data-flow evidence JSON from a maintained YAML.

Task T-31 (struktura §6 "real readers", blueprint/04 §5.2). Replaces the previous
static heredoc in ``generate-data-flow.sh`` — the data-flow record (a RODO Art.25/
Art.30 privacy-by-design artifact) is now maintained in
``docs/governance/data-flow.yaml`` and *read + schema-validated* here, then printed
to stdout as ``data-flow-diagram.json`` (filename unchanged so the evidence-pack
call site is untouched).

Tiering (blueprint/04 §5.2)
---------------------------
* **BLOCKING on schema** — the structural invariants are deterministic and
  false-positive-safe, so a violation must stop the build:
    - the YAML parses to a mapping with a non-empty ``description``;
    - ``stages`` is a non-empty list;
    - every stage has ``name`` (non-empty, unique), ``location`` (non-empty) and a
      boolean ``pii_present`` key (REQUIRED — a missing PII flag is the exact hole
      this task closes);
    - **if ``pii_present`` is true, ``pii_justification`` is present AND non-empty**
      (RODO Art.30(1)(g): you must record *why* PII is processed) and
      ``pii_types`` is a non-empty list;
    - optional ``data_flows_to`` is a list of strings; optional ``retention_days``
      is a non-negative int.
  A schema violation prints a T-33 ``FAIL``/``BLOCKING`` envelope to **stderr** and
  exits non-zero (1). The shell wrapper redirects stderr to a log so a malformed
  record can never silently land in the evidence JSON on stdout.

* **EVIDENCE-ONLY (registration truth)** — that the recorded stages match the
  *real* production data flows is a human-maintained assertion the pipeline cannot
  verify. On success a T-33 ``PASS``/``EVIDENCE-ONLY`` envelope is written to
  stderr (measured = stage count) and the rendered JSON is written to stdout.

Usage::

    python3 scripts/generate-data-flow.py                 # default YAML, JSON->stdout
    python3 scripts/generate-data-flow.py --input X.yaml  # override input
    python3 scripts/generate-data-flow.py --validate-only # schema check, no JSON

Exit codes mirror T-33: 0 on a valid schema (PASS), 1 on a schema FAIL, 2 when the
input could not be read/parsed at all (INDETERMINATE — nothing measured).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable regardless of CWD: this file
# lives in <PipelineRoot>/scripts/, so the Pipeline root is one level up.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR = "generate-data-flow"
DEFAULT_INPUT = PIPELINE_ROOT / "docs" / "governance" / "data-flow.yaml"

# Keys rendered into each output stage, in a stable order, when present.
_STAGE_OUTPUT_KEYS = (
    "name",
    "location",
    "pii_present",
    "pii_types",
    "pii_justification",
    "data_flows_to",
    "retention_days",
)


class SchemaError(Exception):
    """A BLOCKING schema violation. ``problems`` is a list of human strings."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


def load_yaml(path: Path) -> Any:
    """Read + parse the YAML input.

    Raises ``FileNotFoundError`` if missing and ``ValueError`` on empty/unparseable
    content so the caller can map those to an INDETERMINATE result (we measured
    nothing) rather than a FAIL.
    """
    if not path.is_file():
        raise FileNotFoundError(f"{path}: file not found")
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        raise ValueError(f"{path}: file is empty")
    try:
        import yaml  # local import so --help works without PyYAML installed
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ValueError(f"PyYAML is required to read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: invalid YAML ({exc})") from exc
    if data is None:
        raise ValueError(f"{path}: parsed to empty content")
    return data


def validate_schema(doc: Any) -> list[dict[str, Any]]:
    """Validate the data-flow document. Returns the normalised stages list.

    Raises :class:`SchemaError` (BLOCKING) with every problem found — we report all
    violations at once so an editor fixes the record in one pass.
    """
    problems: list[str] = []

    if not isinstance(doc, dict):
        raise SchemaError(["top-level document must be a mapping"])

    description = doc.get("description")
    if not isinstance(description, str) or not description.strip():
        problems.append("description: missing or empty (must be a non-empty string)")

    stages = doc.get("stages")
    if not isinstance(stages, list) or not stages:
        problems.append("stages: missing or empty (must be a non-empty list)")
        # Without stages there is nothing further to check.
        raise SchemaError(problems)

    seen_names: set[str] = set()
    for idx, stage in enumerate(stages):
        ctx = f"stages[{idx}]"
        if not isinstance(stage, dict):
            problems.append(f"{ctx}: must be a mapping")
            continue

        name = stage.get("name")
        if not isinstance(name, str) or not name.strip():
            problems.append(f"{ctx}.name: missing or empty")
        else:
            ctx = f"stage '{name}'"
            if name in seen_names:
                problems.append(f"{ctx}: duplicate stage name")
            seen_names.add(name)

        location = stage.get("location")
        if not isinstance(location, str) or not location.strip():
            problems.append(f"{ctx}.location: missing or empty")

        # pii_present is REQUIRED on EVERY stage and must be a real bool.
        if "pii_present" not in stage:
            problems.append(f"{ctx}.pii_present: REQUIRED key is missing")
        elif not isinstance(stage["pii_present"], bool):
            problems.append(
                f"{ctx}.pii_present: must be a boolean (got "
                f"{type(stage['pii_present']).__name__})"
            )

        pii_types = stage.get("pii_types", [])
        if not isinstance(pii_types, list) or not all(
            isinstance(t, str) for t in pii_types
        ):
            problems.append(f"{ctx}.pii_types: must be a list of strings")

        # The core RODO Art.30(1)(g) invariant: PII => recorded justification.
        if stage.get("pii_present") is True:
            justification = stage.get("pii_justification")
            if not isinstance(justification, str) or not justification.strip():
                problems.append(
                    f"{ctx}: pii_present is true but pii_justification is "
                    f"missing/empty (RODO Art.30 requires recording why PII is "
                    f"processed)"
                )
            if not isinstance(pii_types, list) or len(pii_types) == 0:
                problems.append(
                    f"{ctx}: pii_present is true but pii_types is empty "
                    f"(name the personal-data categories handled here)"
                )

        data_flows_to = stage.get("data_flows_to")
        if data_flows_to is not None:
            if not isinstance(data_flows_to, list) or not all(
                isinstance(t, str) for t in data_flows_to
            ):
                problems.append(f"{ctx}.data_flows_to: must be a list of strings")

        retention = stage.get("retention_days")
        if retention is not None:
            if isinstance(retention, bool) or not isinstance(retention, int):
                problems.append(f"{ctx}.retention_days: must be an integer")
            elif retention < 0:
                problems.append(f"{ctx}.retention_days: must be >= 0")

    if problems:
        raise SchemaError(problems)
    return stages


def render(doc: dict[str, Any], stages: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the output JSON object, preserving the original heredoc shape."""
    out_stages: list[dict[str, Any]] = []
    for stage in stages:
        ordered: dict[str, Any] = {}
        for key in _STAGE_OUTPUT_KEYS:
            if key in stage:
                ordered[key] = stage[key]
        # Carry through any extra keys an editor may add, after the known ones.
        for key, value in stage.items():
            if key not in ordered:
                ordered[key] = value
        out_stages.append(ordered)
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "description": doc["description"],
        "stages": out_stages,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render data-flow-diagram.json from a maintained YAML record.")
    parser.add_argument(
        "--input",
        "-i",
        default=str(DEFAULT_INPUT),
        help="Path to the data-flow YAML (default: docs/governance/data-flow.yaml)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Schema-validate the YAML and emit only the T-33 envelope (no JSON).",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)

    # 1) Read + parse. A read/parse failure means we measured nothing -> INDETERMINATE.
    try:
        doc = load_yaml(input_path)
    except (FileNotFoundError, ValueError) as exc:
        lc.emit(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold="parseable data-flow YAML",
            detail=str(exc),
            validator=VALIDATOR,
            stream=sys.stderr,
            exit_process=False,
        )
        return 2

    # 2) Schema-validate (BLOCKING).
    try:
        stages = validate_schema(doc)
    except SchemaError as exc:
        lc.emit(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured=len(exc.problems),
            threshold=0,
            detail="data-flow schema invalid: " + "; ".join(exc.problems),
            validator=VALIDATOR,
            stream=sys.stderr,
            exit_process=False,
        )
        return 1

    # 3) Render the JSON evidence to stdout (unless validate-only was requested).
    if not args.validate_only:
        output = render(doc, stages)
        print(json.dumps(output, indent=2, ensure_ascii=False))

    # 4) Emit the success envelope to stderr (registration truth is EVIDENCE-ONLY).
    pii_stages = sum(1 for s in stages if s.get("pii_present") is True)
    lc.emit(
        lc.Status.PASS,
        lc.Tier.BLOCKING,
        measured=len(stages),
        threshold=">=1 stage, every stage has pii_present (+justification if true)",
        detail=(
            f"data-flow schema valid: {len(stages)} stages "
            f"({pii_stages} with PII, each justified). Stage<->reality "
            f"correspondence is EVIDENCE-ONLY (human-maintained record)."
        ),
        validator=VALIDATOR,
        stream=sys.stderr,
        exit_process=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
