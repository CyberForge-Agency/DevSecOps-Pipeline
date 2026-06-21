#!/usr/bin/env python3
"""assert-retention.py — A.5 evidence-retention / WORM content validator (task T-48).

A real **BLOCKING** content validator that asserts the *measured* evidence
retention period against the statutory threshold and reports the WORM **lock**
posture honestly. It is the per-stage, content-asserting companion to the
extractor in ``scripts/tfplan-to-retention-input.py`` (T-24) and emits the
shared T-33 envelope so the compliance gate (T-30) aggregates a uniform result.

What it asserts
---------------
1. **Retention floor (BLOCKING)** — ``retention_days >= threshold`` where the
   threshold is read from ``docs/governance/evidence-retention-policy.md``
   (the ``Minimum evidence retention`` row), falling back to **1825** days
   (5 years — longest in-scope PL statutory minimum; DORA/NIS2 impose no numeric
   period — mirrored from ``policies/retention-policy.rego``). A value below the
   floor is a deterministic ``FAIL`` (exit 1).
2. **WORM lock posture (honest)** — reports ``worm_locked``. When WORM is enabled
   but the time-based immutability policy is **not** irreversibly locked
   (``var.lock_worm = false``, the default — see ``infra/modules/storage``), the
   data is still owner-deletable, so this is **not** true tamper-proof WORM. We do
   NOT emit a fake PASS for that posture: a below-floor retention is FAIL; an
   at/above-floor retention with WORM *unlocked* is downgraded to
   ``INDETERMINATE`` (retention-by-policy, not enforced WORM) — never a silent
   PASS. A locked WORM at/above the floor is the only ``PASS``.

Two input shapes (both supported)
---------------------------------
* **Terraform show JSON** (``terraform show -json`` of a plan or state): parsed for
  ``immutability_period_in_days``, the lifecycle delete schedule, and ``lock_worm``
  (the immutability resource's ``locked`` attribute when present). This reuses the
  proven extractor in ``tfplan-to-retention-input.py``.
* **Terraform source** (``--from-tf <dir>``): parses ``*.tf`` in the storage module
  for the ``immutability_period_days`` default and ``var.lock_worm`` default — for
  offline verification when no plan JSON is available.

Honesty boundary (blueprint/04 §2)
----------------------------------
* The retention *number* and the lock *flag* are deterministically parseable, so the
  floor assertion is **BLOCKING**.
* A plan proves *intent*, not applied state; the ``detail`` records which it parsed.
* A missing/unparseable input is ``INDETERMINATE`` (we measured nothing) — never PASS.

Usage
-----
    python3 scripts/validators/assert-retention.py <terraform-show.json> \
        [--threshold 1825] [--policy docs/governance/evidence-retention-policy.md] \
        [--out retention-content.json]

    # offline, from Terraform source (no plan JSON):
    python3 scripts/validators/assert-retention.py --from-tf infra/modules/storage

Exit codes (via T-33): 0 PASS, 1 FAIL (BLOCKING), 2 INDETERMINATE.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# --- import the T-33 shared library (sibling module) ------------------------ #
sys.path.insert(0, str(Path(__file__).resolve().parent))
import libcompliance as lc  # noqa: E402  (path set above)

_PIPELINE_ROOT = Path(__file__).resolve().parents[2]  # .../Pipeline

DEFAULT_POLICY_DOC = (
    _PIPELINE_ROOT / "docs" / "governance" / "evidence-retention-policy.md"
)
DEFAULT_OUT = "retention-content.json"
TOOL_VERSION = "assert-retention/1.0 (T-48)"

# Configured 5-year evidence floor (PL statutory basis: AML/tax/accounting);
# DORA/NIS2 = 5y+ audit-defensibility, no numeric mandate. Mirrored from
# policies/retention-policy.rego.
DEFAULT_THRESHOLD_DAYS = 1825

# azurerm resource type names (>= provider v4).
TYPE_IMMUTABILITY = "azurerm_storage_container_immutability_policy"
TYPE_MGMT_POLICY = "azurerm_storage_management_policy"


# --------------------------------------------------------------------------- #
# Threshold: read from the policy doc, else fall back to the rego constant.   #
# --------------------------------------------------------------------------- #

# "Minimum evidence retention | **1825 days (5 years)** |" or any "<n> days".
_THRESHOLD_RE = re.compile(
    r"minimum\s+evidence\s+retention.*?(\d{2,6})\s*days", re.IGNORECASE | re.DOTALL
)


def read_threshold(policy_path: Path) -> tuple[int, str]:
    """Read the retention floor (days) from the policy doc, else the default.

    Returns ``(threshold_days, source)``. The policy doc is human-readable spec;
    when it is missing or unparseable we fall back to the configured 5-year floor
    rather than guessing, and say so in the source string.
    """
    if policy_path.is_file():
        text = policy_path.read_text(encoding="utf-8")
        m = _THRESHOLD_RE.search(text)
        if m:
            return int(m.group(1)), f"{policy_path.name} (Minimum evidence retention)"
    return DEFAULT_THRESHOLD_DAYS, "default (1825-day configured floor, retention-policy.rego)"


# --------------------------------------------------------------------------- #
# Terraform show -json traversal (reuses the T-24 extractor where available).  #
# --------------------------------------------------------------------------- #

def _iter_resources(module: dict[str, Any]):
    """Yield every resource dict in ``module`` and all nested child_modules."""
    for res in module.get("resources", []) or []:
        if isinstance(res, dict):
            yield res
    for child in module.get("child_modules", []) or []:
        if isinstance(child, dict):
            yield from _iter_resources(child)


def _root_modules(tf: dict[str, Any]) -> list[dict[str, Any]]:
    """Return root_module nodes from a plan (planned_values) and/or state (values)."""
    roots: list[dict[str, Any]] = []
    for key in ("planned_values", "values"):
        node = tf.get(key)
        if isinstance(node, dict) and isinstance(node.get("root_module"), dict):
            roots.append(node["root_module"])
    return roots


def _collect(tf: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for root in _root_modules(tf):
        out.extend(_iter_resources(root))
    return out


def _source_mode(tf: dict[str, Any]) -> str:
    pv = tf.get("planned_values")
    if isinstance(pv, dict) and isinstance(pv.get("root_module"), dict):
        return "plan"
    return "state"


def assess_from_json(tf: dict[str, Any]) -> dict[str, Any] | None:
    """Extract ``{retention_days, worm_enabled, worm_locked, deletion_schedule}``.

    Returns ``None`` when no retention-relevant resource is found (caller -> INDET).
    """
    resources = _collect(tf)
    if not resources:
        return None

    immutability_days: int | None = None
    worm_locked = False
    saw_immutability = False
    for res in resources:
        if res.get("type") != TYPE_IMMUTABILITY:
            continue
        saw_immutability = True
        values = res.get("values") or {}
        days = values.get("immutability_period_in_days")
        if isinstance(days, bool):
            continue
        if isinstance(days, (int, float)):
            d = int(days)
            immutability_days = d if immutability_days is None else max(immutability_days, d)
        # azurerm exposes the irreversible lock as the resource's `locked` flag.
        if values.get("locked") is True:
            worm_locked = True

    # Lifecycle deletion schedule (and its delete-after threshold).
    delete_after: int | None = None
    sched_parts: list[str] = []
    for res in resources:
        if res.get("type") != TYPE_MGMT_POLICY:
            continue
        values = res.get("values") or {}
        for rule in values.get("rule", []) or []:
            if not isinstance(rule, dict) or not rule.get("enabled", True):
                continue
            name = rule.get("name", "rule")
            for actions in rule.get("actions", []) or []:
                if not isinstance(actions, dict):
                    continue
                for base in actions.get("base_blob", []) or []:
                    if not isinstance(base, dict):
                        continue
                    days = base.get(
                        "delete_after_days_since_modification_greater_than"
                    )
                    if isinstance(days, bool) or not isinstance(days, (int, float)):
                        continue
                    d = int(days)
                    sched_parts.append(f"lifecycle rule '{name}': delete after {d} days")
                    delete_after = d if delete_after is None else max(delete_after, d)

    worm_enabled = immutability_days is not None and immutability_days > 0
    retention_days = immutability_days if immutability_days is not None else delete_after
    if retention_days is None and not saw_immutability and not sched_parts:
        return None

    return {
        "retention_days": retention_days,
        "worm_enabled": worm_enabled,
        "worm_locked": worm_locked,
        "deletion_schedule": "; ".join(sched_parts),
        "source": _source_mode(tf),
    }


# --------------------------------------------------------------------------- #
# Terraform SOURCE parsing (offline fallback, no plan JSON).                   #
# --------------------------------------------------------------------------- #

_DEFAULT_BLOCK_RE = (
    r'variable\s+"{name}"\s*\{{.*?default\s*=\s*({value})'
)


def _tf_default(text: str, name: str, value_re: str) -> str | None:
    m = re.search(
        _DEFAULT_BLOCK_RE.format(name=re.escape(name), value=value_re),
        text,
        re.DOTALL,
    )
    return m.group(1) if m else None


def assess_from_tf(tf_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Parse ``*.tf`` defaults for retention period + ``lock_worm`` (offline mode).

    Returns ``(assessment, error)``. Reports honestly when the variables are not
    found rather than assuming a passing value.
    """
    if not tf_dir.is_dir():
        return None, f"{tf_dir}: not a directory"
    text = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted(tf_dir.glob("*.tf"))
    )
    if not text.strip():
        return None, f"{tf_dir}: no .tf files found"

    period_str = _tf_default(text, "immutability_period_days", r"\d+")
    if period_str is None:
        return None, (
            f"{tf_dir}: variable \"immutability_period_days\" default not found"
        )
    retention_days = int(period_str)

    lock_str = _tf_default(text, "lock_worm", r"true|false")
    worm_locked = lock_str == "true"

    has_delete = "delete_after_days_since_modification_greater_than" in text
    schedule = (
        "lifecycle delete action present (var.enable_lifecycle_delete-gated)"
        if has_delete
        else ""
    )

    return (
        {
            "retention_days": retention_days,
            "worm_enabled": retention_days > 0,
            "worm_locked": worm_locked,
            "deletion_schedule": schedule,
            "source": f"terraform source ({tf_dir.name}/*.tf defaults)",
        },
        None,
    )


# --------------------------------------------------------------------------- #
# Envelope construction                                                        #
# --------------------------------------------------------------------------- #

def build_envelope(assessment: dict[str, Any], threshold: int, threshold_src: str) -> dict[str, Any]:
    """Fold the assessment into one BLOCKING T-33 envelope.

    Decision table (honesty-first):
      * retention below floor                       -> FAIL  (exit 1)
      * WORM disabled (immutability absent / 0)      -> FAIL  (exit 1)
      * retention OK + WORM enabled but NOT locked   -> INDETERMINATE (retention-by-policy)
      * retention OK + WORM enabled AND locked       -> PASS
    """
    retention_days = assessment["retention_days"]
    worm_enabled = assessment["worm_enabled"]
    worm_locked = assessment["worm_locked"]
    source = assessment.get("source", "plan")

    measured = {
        "retention_days": retention_days,
        "worm_enabled": worm_enabled,
        "worm_locked": worm_locked,
        "deletion_schedule": assessment.get("deletion_schedule", ""),
        "source": source,
    }
    threshold_obj = {"min_retention_days": threshold, "from": threshold_src}

    # 1) No measurable retention number -> INDETERMINATE.
    if not isinstance(retention_days, int):
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=measured, threshold=threshold_obj,
            detail="no measurable retention_days in input",
            tool_version=TOOL_VERSION,
        )

    # 2) Below floor or WORM disabled -> FAIL.
    reasons: list[str] = []
    if retention_days < threshold:
        reasons.append(
            f"retention {retention_days} days < {threshold}-day floor ({threshold_src})"
        )
    if not worm_enabled:
        reasons.append("WORM immutability not enabled (no positive immutability period)")
    if reasons:
        return lc.envelope(
            lc.Status.FAIL, lc.Tier.BLOCKING,
            measured=measured, threshold=threshold_obj,
            detail="; ".join(reasons) + f"; parsed from {source}",
            tool_version=TOOL_VERSION,
        )

    # 3) Retention OK + WORM enabled but NOT locked -> INDETERMINATE (honest).
    if not worm_locked:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=measured, threshold=threshold_obj,
            detail=(
                f"retention {retention_days} >= {threshold} and WORM enabled, but the "
                "immutability policy is NOT locked (reversible): retention-by-policy, "
                "not tamper-proof WORM. The one-way lock is a deliberate owner "
                f"decision (T-46). Parsed from {source}."
            ),
            tool_version=TOOL_VERSION,
        )

    # 4) Retention OK + WORM enabled AND locked -> PASS.
    return lc.envelope(
        lc.Status.PASS, lc.Tier.BLOCKING,
        measured=measured, threshold=threshold_obj,
        detail=(
            f"retention {retention_days} >= {threshold} ({threshold_src}); WORM enabled "
            f"and LOCKED (irreversible). Parsed from {source}."
        ),
        tool_version=TOOL_VERSION,
    )


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def _finish(env: dict[str, Any], out_path: str) -> int:
    try:
        Path(out_path).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem edge
        print(f"warning: could not write {out_path}: {exc}", file=sys.stderr)
    print(json.dumps(env))
    return lc.exit_code_for(env["status"], env["tier"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A.5 assert-retention (T-48)")
    parser.add_argument(
        "tfjson",
        nargs="?",
        help="path to `terraform show -json` output (plan or state), or '-' for stdin",
    )
    parser.add_argument(
        "--from-tf",
        metavar="DIR",
        help="parse Terraform SOURCE defaults in DIR (offline; no plan JSON needed)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="override the retention floor in days (default: read from policy doc)",
    )
    parser.add_argument(
        "--policy",
        default=str(DEFAULT_POLICY_DOC),
        help="policy doc carrying the retention floor "
        "(default: docs/governance/evidence-retention-policy.md)",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"write the envelope to this path too (default: {DEFAULT_OUT})",
    )
    args = parser.parse_args(argv)

    if args.threshold is not None:
        threshold, threshold_src = args.threshold, "--threshold override"
    else:
        threshold, threshold_src = read_threshold(Path(args.policy))

    # Source mode (offline) vs JSON mode.
    if args.from_tf:
        assessment, err = assess_from_tf(Path(args.from_tf))
        if err is not None:
            env = lc.envelope(
                lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=None,
                threshold={"min_retention_days": threshold, "from": threshold_src},
                detail=f"terraform source error: {err}", tool_version=TOOL_VERSION,
            )
            return _finish(env, args.out)
        return _finish(build_envelope(assessment, threshold, threshold_src), args.out)

    if not args.tfjson:
        parser.error("provide a terraform-show JSON path (or '-'), or use --from-tf DIR")

    tf, jerr = (lc.load_json(args.tfjson) if args.tfjson != "-" else _load_stdin())
    if jerr is not None:
        env = lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=None,
            threshold={"min_retention_days": threshold, "from": threshold_src},
            detail=f"terraform JSON error: {jerr}", tool_version=TOOL_VERSION,
        )
        return _finish(env, args.out)
    if not isinstance(tf, dict):
        env = lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=None,
            threshold={"min_retention_days": threshold, "from": threshold_src},
            detail="terraform JSON is not an object", tool_version=TOOL_VERSION,
        )
        return _finish(env, args.out)

    assessment = assess_from_json(tf)
    if assessment is None:
        env = lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=None,
            threshold={"min_retention_days": threshold, "from": threshold_src},
            detail=(
                "no retention-relevant resources "
                f"({TYPE_IMMUTABILITY} / {TYPE_MGMT_POLICY}) found in terraform JSON"
            ),
            tool_version=TOOL_VERSION,
        )
        return _finish(env, args.out)

    return _finish(build_envelope(assessment, threshold, threshold_src), args.out)


def _load_stdin() -> tuple[Any, str | None]:
    raw = sys.stdin.read().strip()
    if not raw:
        return None, "stdin: empty input"
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as exc:
        return None, f"stdin: invalid JSON ({exc})"


if __name__ == "__main__":
    sys.exit(main())
