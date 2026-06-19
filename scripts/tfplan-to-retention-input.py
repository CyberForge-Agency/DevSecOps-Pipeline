#!/usr/bin/env python3
"""tfplan-to-retention-input — A.5 assert-retention validator (task T-24).

Extracts the WORM / retention configuration from a Terraform plan and asserts it
meets the statutory evidence-retention minimum of **1825 days (5 years)** that the
project derives from DORA's audit-defensibility / record-keeping expectations
(blueprint/04 §6.1; constant mirrored in ``policies/retention-policy.rego``).

Two cooperating jobs (DoD T-24)
-------------------------------
1. **OPA-input mode** (``--opa-input``, the default when piping):
   walk ``terraform show -json <plan>`` and print the minimal JSON document the
   dormant ``retention-policy.rego`` consumes::

       {"retention_days": 1825, "worm_enabled": true,
        "deletion_schedule": "<azurerm_storage_management_policy rule>"}

   so a gate step can run
   ``... | opa eval -d policies/retention-policy.rego -I 'data.compliance.retention.deny'``
   and fail the deploy on any non-empty ``deny`` set. (The OPA *wiring* into
   deploy.yml is owned by the gates stream — this script owns the extractor and the
   signed A.5 artifact, never the workflow edit.)

2. **Envelope mode** (``--envelope``):
   emit the T-33 compliance envelope (``retention-policy.json``) carrying the
   *measured* retention_days against the 1825 threshold, tier **BLOCKING** — a
   value below 1825, WORM disabled, or a missing deletion schedule is a FAIL that
   exits non-zero. A plan we cannot parse is INDETERMINATE (never a silent PASS).

What is pipeline-verifiable vs EVIDENCE-ONLY
--------------------------------------------
* The *number* in the plan (immutability_period_in_days, the lifecycle delete
  threshold, the WORM flag) IS deterministically parseable from
  ``terraform show -json`` -> the threshold assertion is **BLOCKING**.
* Whether that plan was actually *applied* and the live Azure container truly
  carries an enforced WORM lock is NOT provable from a plan file. The plan proves
  *intent*; live enforcement is asserted elsewhere (export-azure-rbac / state).
  Callers who pass applied-state JSON get a state assertion; callers who pass a
  speculative plan get an intent assertion. This script reports which it parsed in
  ``detail`` so the evidence is honest about its own scope.

Input shape
-----------
Accepts the JSON produced by ``terraform show -json <planfile>`` (a *plan*) OR by
``terraform show -json`` of applied state. Both expose resources under
``planned_values.root_module`` (plan) or ``values.root_module`` (state); this
script tries both roots and recurses through ``child_modules`` (struktura §6 A.5
implementation note: walk
``plan['planned_values']['root_module']['child_modules'][*]['resources']``).

Usage
-----
    # OPA input (default) — pipe straight into opa eval
    terraform -chdir=infra show -json tfplan > /tmp/p.json
    python3 scripts/tfplan-to-retention-input.py /tmp/p.json \
        | opa eval -d policies/retention-policy.rego -I 'data.compliance.retention.deny'

    # T-33 envelope artifact (BLOCKING)
    python3 scripts/tfplan-to-retention-input.py /tmp/p.json --envelope \
        > evidence/retention-policy.json

    # read plan JSON from stdin
    terraform -chdir=infra show -json tfplan | python3 scripts/tfplan-to-retention-input.py -
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Import the T-33 shared library (works regardless of CWD).                    #
# --------------------------------------------------------------------------- #
_THIS = Path(__file__).resolve()
_PIPELINE_ROOT = _THIS.parents[1]  # .../Pipeline
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

# --------------------------------------------------------------------------- #
# Constants (the statutory minimum + the azurerm attribute/type names).        #
# --------------------------------------------------------------------------- #

# DORA 5-year evidence-retention minimum, mirrored from policies/retention-policy.rego:5.
# This is the project's stated threshold; the *value below it* is a deterministic FAIL.
MINIMUM_RETENTION_DAYS = 1825

# Terraform resource type names emitted by the azurerm provider (>= v4).
TYPE_IMMUTABILITY = "azurerm_storage_container_immutability_policy"
TYPE_MGMT_POLICY = "azurerm_storage_management_policy"
TYPE_STORAGE_ACCOUNT = "azurerm_storage_account"

VALIDATOR_NAME = "tfplan-to-retention-input"


class ExtractionError(ValueError):
    """Raised when the plan JSON cannot be parsed into a retention assessment."""


# --------------------------------------------------------------------------- #
# Plan traversal                                                              #
# --------------------------------------------------------------------------- #

def _root_module(plan: dict[str, Any]) -> dict[str, Any]:
    """Return the root_module node, tolerating both plan and applied-state JSON.

    ``terraform show -json <planfile>`` puts resources under
    ``planned_values.root_module``; ``terraform show -json`` of state puts them
    under ``values.root_module``. We try planned first (the task's input), then
    state, so the same extractor serves both.
    """
    for key in ("planned_values", "values"):
        node = plan.get(key)
        if isinstance(node, dict) and isinstance(node.get("root_module"), dict):
            return node["root_module"]
    raise ExtractionError(
        "no planned_values.root_module or values.root_module in plan JSON "
        "(is this the output of `terraform show -json`?)"
    )


def _iter_resources(module: dict[str, Any]):
    """Yield every resource dict in ``module`` and all nested child_modules.

    Recurses through ``child_modules`` (struktura §6 A.5 note) so resources
    declared in ``module.storage`` are found from the root.
    """
    for res in module.get("resources", []) or []:
        if isinstance(res, dict):
            yield res
    for child in module.get("child_modules", []) or []:
        if isinstance(child, dict):
            yield from _iter_resources(child)


def _resource_input_root(plan: dict[str, Any]) -> dict[str, Any]:
    """Root module to traverse for resources, preferring the resolved values root."""
    return _root_module(plan)


# --------------------------------------------------------------------------- #
# Extraction of the three retention facts                                      #
# --------------------------------------------------------------------------- #

def _immutability_days(resources: list[dict[str, Any]]) -> int | None:
    """Largest ``immutability_period_in_days`` across all WORM policy resources.

    Returns ``None`` if no immutability-policy resource is present (WORM not
    configured). We take the max so a multi-container plan is judged by its
    strongest evidence container, and the caller can compare against the minimum.
    """
    found: list[int] = []
    for res in resources:
        if res.get("type") != TYPE_IMMUTABILITY:
            continue
        values = res.get("values") or {}
        days = values.get("immutability_period_in_days")
        if isinstance(days, bool):  # guard: bool is a subclass of int
            continue
        if isinstance(days, (int, float)):
            found.append(int(days))
    return max(found) if found else None


def _worm_enabled(resources: list[dict[str, Any]], immutability_days: int | None) -> bool:
    """WORM is enabled iff a container immutability policy exists with days > 0.

    The azurerm immutability resource only exists when ``count`` resolved to 1
    (``immutability_period_days > 0`` in the module), so its mere presence with a
    positive period is the WORM signal.
    """
    return immutability_days is not None and immutability_days > 0


def _deletion_schedule(resources: list[dict[str, Any]]) -> tuple[str, int | None]:
    """Describe the lifecycle deletion schedule and its delete-after threshold.

    Walks ``azurerm_storage_management_policy`` rules for a ``base_blob`` action's
    ``delete_after_days_since_modification_greater_than``. Returns
    ``(human_description, delete_after_days_or_None)``. An empty description means
    no deletion schedule is defined (the rego treats ``""`` as a deny).
    """
    descriptions: list[str] = []
    delete_after: int | None = None
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
                    if isinstance(days, bool):
                        continue
                    if isinstance(days, (int, float)):
                        d = int(days)
                        descriptions.append(
                            f"lifecycle rule '{name}': delete after {d} days"
                        )
                        delete_after = d if delete_after is None else max(delete_after, d)
    return "; ".join(descriptions), delete_after


def _source_mode(plan: dict[str, Any]) -> str:
    """'plan' if resources came from planned_values, else 'state'."""
    pv = plan.get("planned_values")
    if isinstance(pv, dict) and isinstance(pv.get("root_module"), dict):
        return "plan"
    return "state"


def extract(plan: dict[str, Any]) -> dict[str, Any]:
    """Extract the retention assessment from parsed plan JSON.

    Returns a dict with the OPA-input fields plus diagnostics::

        {
          "retention_days":     <int>,        # the binding WORM immutability period
          "worm_enabled":       <bool>,
          "deletion_schedule":  <str>,        # "" when none -> rego deny
          "delete_after_days":  <int|null>,   # lifecycle delete threshold (diagnostic)
          "immutability_days":  <int|null>,   # raw WORM period (diagnostic)
          "source":             "plan"|"state"
        }

    ``retention_days`` is the WORM immutability period — the figure the regulation
    binds (data cannot be deleted before it elapses). If WORM is absent we fall
    back to the lifecycle ``delete_after`` so the rego still gets a number to judge
    (and ``worm_enabled`` is False, which the rego separately denies).
    """
    root = _resource_input_root(plan)
    resources = list(_iter_resources(root))
    if not resources:
        raise ExtractionError("plan contains zero resources to inspect")

    immutability_days = _immutability_days(resources)
    worm = _worm_enabled(resources, immutability_days)
    schedule, delete_after = _deletion_schedule(resources)

    # retention_days is the binding immutability period; if WORM is absent, fall
    # back to the lifecycle delete threshold so the threshold check still has a
    # measured number (worm_enabled=False already triggers a separate deny).
    retention_days = immutability_days if immutability_days is not None else delete_after
    if retention_days is None:
        raise ExtractionError(
            "no immutability_period_in_days and no lifecycle delete schedule found "
            f"(looked for {TYPE_IMMUTABILITY} / {TYPE_MGMT_POLICY})"
        )

    return {
        "retention_days": retention_days,
        "worm_enabled": worm,
        "deletion_schedule": schedule,
        "delete_after_days": delete_after,
        "immutability_days": immutability_days,
        "source": _source_mode(plan),
    }


# --------------------------------------------------------------------------- #
# I/O + envelope                                                              #
# --------------------------------------------------------------------------- #

def load_plan(path: str) -> dict[str, Any]:
    """Read plan JSON from a path or '-' (stdin). Raises ExtractionError on misuse."""
    if path == "-":
        raw = sys.stdin.read()
    else:
        p = Path(path)
        if not p.is_file():
            raise ExtractionError(f"{path}: file not found")
        raw = p.read_text(encoding="utf-8")
    raw = raw.strip()
    if not raw:
        raise ExtractionError(f"{path}: empty input")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExtractionError(f"{path}: invalid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ExtractionError(f"{path}: top-level JSON is not an object")
    return data


def _opa_input(assessment: dict[str, Any]) -> dict[str, Any]:
    """Project the assessment to exactly the fields retention-policy.rego reads.

    ``delete_after_days`` lets the rego apply the footgun guard (deny a lifecycle
    delete shorter than the immutability period) while treating an absent delete
    (recommended posture) as compliant — see retention-policy.rego (T-10/T-62).
    """
    return {
        "retention_days": assessment["retention_days"],
        "worm_enabled": assessment["worm_enabled"],
        "deletion_schedule": assessment["deletion_schedule"],
        "delete_after_days": assessment.get("delete_after_days"),
    }


def build_envelope(assessment: dict[str, Any]) -> dict[str, Any]:
    """Build the T-33 BLOCKING envelope from an extracted assessment.

    PASS iff retention_days >= 1825 AND worm_enabled AND no lifecycle delete fires
    before the immutability period expires (mirrors the rego ``compliant`` rule,
    T-10/T-62). An ABSENT lifecycle delete is compliant — deletion is governed by
    the WORM/legal-hold window. Only a delete SHORTER than retention is a FAIL.
    """
    measured = assessment["retention_days"]
    base = lc.check_threshold(
        measured,
        ">=",
        MINIMUM_RETENTION_DAYS,
        tier=lc.Tier.BLOCKING,
        label="evidence retention_days",
        tool_version=None,
        # validator name is auto-detected by emit/envelope; check_threshold uses
        # its own caller frame, so we override below in emit().
    )

    reasons: list[str] = []
    if base["status"] == lc.Status.FAIL:
        reasons.append(
            f"retention {measured} days < DORA minimum {MINIMUM_RETENTION_DAYS}"
        )
    if not assessment["worm_enabled"]:
        reasons.append("WORM immutability not enabled")
    # Footgun (T-10/T-62, T-105/T-52): only a lifecycle delete SHORTER than the
    # immutability period is a violation. An absent delete (recommended posture)
    # is compliant — deletion is governed by the WORM/legal-hold window.
    delete_after = assessment.get("delete_after_days")
    if (
        isinstance(delete_after, int)
        and not isinstance(delete_after, bool)
        and 0 < delete_after < measured
    ):
        reasons.append(
            f"lifecycle delete after {delete_after} days is shorter than the "
            f"{measured}-day immutability period (would purge evidence before WORM expiry)"
        )

    if base["status"] == lc.Status.INDETERMINATE:
        status = lc.Status.INDETERMINATE
    elif reasons:
        status = lc.Status.FAIL
    else:
        status = lc.Status.PASS

    source = assessment.get("source", "plan")
    scope = (
        "parsed from Terraform PLAN (asserts configured intent, not applied state)"
        if source == "plan"
        else "parsed from applied Terraform STATE"
    )
    if status == lc.Status.PASS:
        detail = (
            f"retention_days={measured} >= {MINIMUM_RETENTION_DAYS}, "
            f"worm_enabled={assessment['worm_enabled']}, "
            f"deletion_schedule={assessment['deletion_schedule']!r}; {scope}"
        )
    else:
        detail = "; ".join(reasons) + f"; {scope}"

    return lc.envelope(
        status,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold=MINIMUM_RETENTION_DAYS,
        detail=detail,
        tool_version=None,
        validator=VALIDATOR_NAME,
    )


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR_NAME,
        description=(
            "Extract WORM/retention config from `terraform show -json` and assert "
            "it meets the 1825-day (5-year) DORA evidence-retention minimum."
        ),
    )
    parser.add_argument(
        "plan",
        help="path to `terraform show -json` output, or '-' for stdin",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--opa-input",
        action="store_true",
        help="(default) print the minimal JSON consumed by retention-policy.rego",
    )
    mode.add_argument(
        "--envelope",
        action="store_true",
        help="emit the T-33 compliance envelope (retention-policy.json) and exit "
        "with the tier-aware code (BLOCKING: FAIL->1, INDETERMINATE->2)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    try:
        plan = load_plan(args.plan)
        assessment = extract(plan)
    except ExtractionError as exc:
        if args.envelope:
            # Honest: we could not measure the control -> INDETERMINATE, exit 2.
            env = lc.envelope(
                lc.Status.INDETERMINATE,
                lc.Tier.BLOCKING,
                measured=None,
                threshold=MINIMUM_RETENTION_DAYS,
                detail=f"could not extract retention config: {exc}",
                tool_version=None,
                validator=VALIDATOR_NAME,
            )
            print(json.dumps(env))
            return lc.exit_code_for(env["status"], env["tier"])
        print(f"{VALIDATOR_NAME}: {exc}", file=sys.stderr)
        return 2

    if args.envelope:
        env = build_envelope(assessment)
        print(json.dumps(env))
        return lc.exit_code_for(env["status"], env["tier"])

    # Default: OPA-input mode.
    print(json.dumps(_opa_input(assessment)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
