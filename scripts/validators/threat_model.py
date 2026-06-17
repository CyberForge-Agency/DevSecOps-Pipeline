#!/usr/bin/env python3
"""threat_model.py — validate the structured STRIDE threat model (T-115).

Spec mapping
------------
Evidence Pack master spec Part C.1 "Threat model & secure-design records"
(``evidence-pack-specification.md:67``, ``:135``) and §4 pipeline stage
"Plan / threat-model" (``evidence-pack-specification.md:187``). PASS criteria:
"Exists per critical feature; updated on arch change; risks traced to controls."
A *single stale doc for the whole app* is an explicit rejection trigger
(``evidence-pack-specification.md:187``).

This validator targets the machine-readable model ``docs/security/threat-model.yaml``
(T-115), which is DERIVED from the prose ``docs/security/threat-model.md``. It makes the
spec's "risks traced to controls" + "versioned, updated on arch change" criteria a
STRUCTURED, FALSE-POSITIVE-SAFE, machine-checked assertion.

What it checks (BLOCKING)
-------------------------
1. PRESENCE/SCHEMA — the YAML exists, is non-empty, parses, and has a top-level
   ``version`` + ``reviewed_date`` + a non-empty ``threats`` list. An empty/``{}``
   artifact is INDETERMINATE (closes the "{} passes" hole), never a silent PASS.
2. PER-ENTRY COMPLETENESS — every threat carries ALL required fields
   (id, stride, component, threat, mitigation, status, residual), each non-empty;
   ``stride`` is one of S/T/R/I/D/E; ``status`` is one of MITIGATED/PARTIAL/GAP; and
   the traceability rule holds — a control_ref OR a gap_ref, and any GAP/PARTIAL row
   that cites a gap_ref must resolve to a declared gap (so a GAP is never silently
   claimed as a control). Duplicate ids FAIL.
3. STRIDE COVERAGE — at least ``MIN_STRIDE_CATEGORIES`` distinct STRIDE categories are
   represented across the model (a STRIDE model that only enumerates one letter is not
   a STRIDE model). Default 6 (all of S/T/R/I/D/E), the full STRIDE set the prose covers.
4. FRESHNESS — ``reviewed_date`` parses and is within ``review_window_days`` (default
   from the doc, capped at MAX_REVIEW_WINDOW_DAYS) of today; a stale model FAILs (the
   exact §4 rejection trigger). An unparseable date -> INDETERMINATE.

What it does NOT claim (honesty)
--------------------------------
It does NOT verify that a control *actually and fully* mitigates a threat in production
— that is a human-reviewed assertion (threat-model.md §"Honesty caveat"). It proves the
model is STRUCTURALLY COMPLETE, STRIDE-covering, traced, and FRESH — which is exactly
the spec's PASS criterion and §4 rejection trigger.

Emits the shared T-33 envelope (``scripts/validators/libcompliance.py``) and exits
PASS->0 / FAIL->1 / INDETERMINATE->2 (tier-aware; see ``lc.exit_code_for``).

Usage:
    threat_model.py [THREAT_MODEL_YAML] [--out FILE]
    Default THREAT_MODEL_YAML = docs/security/threat-model.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable regardless of cwd. The
# Pipeline root is two parents up from this file (Pipeline/scripts/validators/).
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "threat_model"
DEFAULT_YAML = "docs/security/threat-model.yaml"
DEFAULT_OUT = "threat-model-validation.json"

# Required fields on every threat entry (the per-entry completeness rule).
REQUIRED_THREAT_FIELDS = ("id", "stride", "component", "threat", "mitigation", "status", "residual")
# Allowed STRIDE letters and status vocabulary.
VALID_STRIDE = frozenset({"S", "T", "R", "I", "D", "E"})
VALID_STATUS = frozenset({"MITIGATED", "PARTIAL", "GAP"})
# A STRIDE model worthy of the name covers the full set; require all six categories.
MIN_STRIDE_CATEGORIES = 6
# Freshness ceiling — even if the doc declares a larger window, never accept a model
# older than this without re-review (defence against a self-declared 99-year window).
MAX_REVIEW_WINDOW_DAYS = 366
DEFAULT_REVIEW_WINDOW_DAYS = 180


def _resolve(path_str: str) -> Path:
    """Resolve a path arg: use as-is if it exists, else relative to the Pipeline root."""
    p = Path(path_str)
    if p.is_file():
        return p
    candidate = PIPELINE_ROOT / path_str
    return candidate if candidate.is_file() else p


def _tool_version() -> str | None:
    """Parsed (not hardcoded) PyYAML version for traceability."""
    try:
        import yaml

        return f"pyyaml {yaml.__version__}"
    except Exception:  # pragma: no cover - never let traceability break a check
        return None


def _load_yaml(path: Path) -> tuple[Any, str | None]:
    """Load a YAML artifact, returning ``(data, error)`` (mirrors lc.load_json).

    Empty / ``{}`` / ``[]`` / ``None`` -> "no measurable content" (INDETERMINATE),
    closing the empty-artifact hole for YAML too.
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


def _nonempty_str(value: Any) -> bool:
    """True iff ``value`` is a non-empty/non-whitespace string."""
    return isinstance(value, str) and bool(value.strip())


def _entry_errors(threats: list[Any], gap_ids: set[str]) -> tuple[list[str], set[str]]:
    """Per-entry completeness + traceability rules. Returns (errors, covered_stride)."""
    errors: list[str] = []
    covered: set[str] = set()
    seen_ids: set[str] = set()

    for idx, entry in enumerate(threats):
        if not isinstance(entry, dict):
            errors.append(f"threats[{idx}]: not a mapping")
            continue
        tid = entry.get("id")
        label = tid if _nonempty_str(tid) else f"threats[{idx}]"

        # Required-field completeness.
        for field in REQUIRED_THREAT_FIELDS:
            val = entry.get(field)
            # `stride`/`status` are validated separately below; here require presence.
            if not _nonempty_str(val):
                errors.append(f"{label}.{field}: missing or empty")

        # Unique id.
        if _nonempty_str(tid):
            if tid in seen_ids:
                errors.append(f"{label}.id: duplicate id {tid!r}")
            seen_ids.add(tid)

        # STRIDE vocabulary + coverage accounting.
        stride = entry.get("stride")
        if _nonempty_str(stride):
            if stride not in VALID_STRIDE:
                errors.append(
                    f"{label}.stride: {stride!r} not one of {sorted(VALID_STRIDE)}"
                )
            else:
                covered.add(stride)

        # Status vocabulary.
        status = entry.get("status")
        if _nonempty_str(status) and status not in VALID_STATUS:
            errors.append(
                f"{label}.status: {status!r} not one of {sorted(VALID_STATUS)}"
            )

        # Traceability: a control_ref OR a gap_ref. A row may not be untraced.
        control_ref = entry.get("control_ref")
        gap_ref = entry.get("gap_ref")
        has_control = _nonempty_str(control_ref)
        has_gap = _nonempty_str(gap_ref)
        if not (has_control or has_gap):
            errors.append(
                f"{label}: untraced — needs a control_ref (path:line) OR a gap_ref"
            )
        # A cited gap_ref must resolve to a declared gap (no phantom gaps).
        if has_gap and gap_ref not in gap_ids:
            errors.append(
                f"{label}.gap_ref: {gap_ref!r} does not resolve to a declared gap"
            )
        # Honesty rule: a GAP-status row must NOT masquerade as an achieved control —
        # a GAP traced ONLY by control_ref (no gap_ref) would over-claim.
        if status == "GAP" and not has_gap:
            errors.append(
                f"{label}: status GAP must carry a gap_ref (target-state, not a control)"
            )

    return errors, covered


def validate(yaml_path: Path) -> dict[str, Any]:
    """Run the full T-115 check and return a ready T-33 envelope (no exit)."""
    tier = lc.Tier.BLOCKING
    tv = _tool_version()
    threshold = (
        f"schema-complete threats (each with {','.join(REQUIRED_THREAT_FIELDS)} + "
        f"traceability); >= {MIN_STRIDE_CATEGORIES} STRIDE categories; "
        f"reviewed within review_window_days (<= {MAX_REVIEW_WINDOW_DAYS})"
    )

    # 1) Presence (BLOCKING). A missing file -> INDETERMINATE (could not measure).
    pres = lc.check_presence(yaml_path, tier=tier, label="threat model", tool_version=tv)
    if pres["status"] != lc.Status.PASS:
        return pres

    # 2) Load + top-level shape.
    data, err = _load_yaml(yaml_path)
    if err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold=threshold,
            detail=f"threat model load failed: {err}", tool_version=tv,
            validator=VALIDATOR_NAME,
        )
    if not isinstance(data, dict):
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold=threshold,
            detail="threat model YAML is not a mapping (expected an object root)",
            tool_version=tv, validator=VALIDATOR_NAME,
        )

    errors: list[str] = []

    version = data.get("version")
    if not _nonempty_str(version):
        errors.append("version: missing — the model must be versioned")

    reviewed_date = data.get("reviewed_date")
    if not _nonempty_str(reviewed_date):
        errors.append("reviewed_date: missing — the model must carry a review date")

    threats = data.get("threats")
    if not isinstance(threats, list) or not threats:
        # Without threats there is nothing to measure -> INDETERMINATE, not a FAIL.
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold=threshold,
            detail="threats[] missing or empty — no threats to validate",
            tool_version=tv, validator=VALIDATOR_NAME,
        )

    # 3) Gap register -> set of declared gap ids (for traceability resolution).
    gaps = data.get("gaps") if isinstance(data.get("gaps"), list) else []
    gap_ids = {g.get("id") for g in gaps if isinstance(g, dict) and _nonempty_str(g.get("id"))}

    # 4) Per-entry completeness + STRIDE coverage accounting.
    entry_errs, covered = _entry_errors(threats, gap_ids)
    errors.extend(entry_errs)

    # 5) STRIDE coverage threshold.
    if len(covered) < MIN_STRIDE_CATEGORIES:
        errors.append(
            f"STRIDE coverage {len(covered)}/{MIN_STRIDE_CATEGORIES} "
            f"(present: {sorted(covered)}) — a STRIDE model must span the categories"
        )

    # 6) Freshness — reviewed_date within the (capped) review window.
    age_days: int | None = None
    window = data.get("review_window_days")
    if not isinstance(window, int) or isinstance(window, bool) or window <= 0:
        window = DEFAULT_REVIEW_WINDOW_DAYS
    effective_window = min(window, MAX_REVIEW_WINDOW_DAYS)
    if _nonempty_str(reviewed_date):
        try:
            age_days = lc.days_since(reviewed_date)
        except lc.ValidatorError as exc:
            # Could not measure freshness at all -> INDETERMINATE (never a silent PASS).
            return lc.envelope(
                lc.Status.INDETERMINATE, tier, measured=None, threshold=threshold,
                detail=f"reviewed_date unparseable: {exc}", tool_version=tv,
                validator=VALIDATOR_NAME,
            )
        if age_days > effective_window:
            errors.append(
                f"reviewed_date stale: {age_days} days old > {effective_window} "
                f"day window (spec §4 rejects a single stale doc)"
            )

    measured = {
        "threats": len(threats),
        "stride_categories": sorted(covered),
        "stride_coverage": len(covered),
        "gaps": len(gap_ids),
        "version": version if _nonempty_str(version) else None,
        "reviewed_date": reviewed_date if _nonempty_str(reviewed_date) else None,
        "age_days": age_days,
        "review_window_days": effective_window,
        "violations": len(errors),
    }

    if errors:
        preview = "; ".join(errors[:6])
        more = "" if len(errors) <= 6 else f" (+{len(errors) - 6} more)"
        return lc.envelope(
            lc.Status.FAIL, tier, measured=measured, threshold=threshold,
            detail=f"threat model incomplete/stale: {preview}{more}",
            tool_version=tv, validator=VALIDATOR_NAME,
        )

    return lc.envelope(
        lc.Status.PASS, tier, measured=measured, threshold=threshold,
        detail=(
            f"threat model v{version}: {len(threats)} threats, "
            f"STRIDE {len(covered)}/{MIN_STRIDE_CATEGORIES} categories, "
            f"{len(gap_ids)} gaps; reviewed {reviewed_date} ({age_days}d ago, "
            f"window {effective_window}d). NOTE: structural completeness + coverage + "
            f"freshness verified; that each control fully mitigates its threat is an "
            f"EVIDENCE-ONLY human assertion."
        ),
        tool_version=tv, validator=VALIDATOR_NAME,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the structured STRIDE threat model (T-115)."
    )
    parser.add_argument("yaml", nargs="?", default=DEFAULT_YAML, help="path to threat-model.yaml")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output envelope JSON path")
    args = parser.parse_args(argv)

    env = validate(_resolve(args.yaml))
    try:
        Path(args.out).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"warning: could not write {args.out}: {exc}", file=sys.stderr)

    print(json.dumps(env))
    return lc.exit_code_for(env["status"], env["tier"])


if __name__ == "__main__":
    sys.exit(main())
