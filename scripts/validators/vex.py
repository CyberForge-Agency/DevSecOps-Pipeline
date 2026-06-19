#!/usr/bin/env python3
"""vex.py — validate the per-release OpenVEX document (T-116).

Spec mapping
------------
evidence-pack-specification.md:145 (Part C.11 VEX — "`not_affected` claims justified
(CISA categories); kept current") and §8 anti-pattern "no VEX, so every CVE looks
unhandled" (evidence-pack-specification.md:285).

What it checks (BLOCKING)
-------------------------
1. PRESENCE/SCHEMA — the file exists, is non-empty, parses as JSON, declares an
   OpenVEX ``@context``, an ``author``, a ``timestamp`` and a non-empty
   ``statements`` array. An empty ``{}`` is INDETERMINATE (libcompliance.load_json
   closes the "{} passes" hole).
2. JUSTIFICATION RULE (the core T-116 DoD) — every statement whose ``status`` is NOT
   ``affected`` must carry a non-empty justification:
     * ``not_affected`` -> a CISA-category ``justification`` label
       (or, OpenVEX-legal, a non-empty ``impact_statement``);
     * ``fixed``        -> a non-empty ``justification`` and/or ``impact_statement``
       explaining HOW it was fixed;
     * ``under_investigation`` is allowed WITHOUT a justification (it is honest "not
       yet triaged"), but is COUNTED and surfaced so an auditor sees the open triage.
   Any ``not_affected``/``fixed`` statement lacking a justification -> FAIL.
3. CISA LABEL VALIDITY — any ``justification`` present must be one of the five CISA /
   OpenVEX labels; an invalid label -> FAIL (prevents typos masquerading as triage).
4. PRODUCT BINDING — every statement binds to a product carrying an image digest
   hash or a digest-pinned purl; an unbound statement cannot be committed-to by the
   Merkle root -> FAIL.

What it does NOT claim (honesty)
--------------------------------
It does not verify that a justification is FACTUALLY correct (that the vulnerable code
truly is absent) — that is an analyst assertion. It proves every non-`affected` claim
is *justified with a valid CISA label and bound to the released digest*, which is
exactly the auditor rejection trigger in spec §8.

Emits the T-33 envelope and exits PASS->0 / FAIL->1 / INDETERMINATE->2.

Usage:
    vex.py [VEX_JSON] [--out FILE]
    Default VEX_JSON = evidence/vex.openvex.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable regardless of cwd.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "vex"

DEFAULT_VEX = "evidence/vex.openvex.json"
DEFAULT_OUT = "vex-triage.json"

# OpenVEX status enum.
VALID_STATUSES = frozenset(
    {"not_affected", "affected", "fixed", "under_investigation"}
)
# Statuses that REQUIRE a justification (the T-116 DoD).
REQUIRES_JUSTIFICATION = frozenset({"not_affected", "fixed"})

# CISA `not_affected` justification labels (OpenVEX `justification` enum).
# CISA "VEX Status Justifications" Jun 2022 +
# https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
CISA_JUSTIFICATIONS = frozenset(
    {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }
)


def _product_is_bound(product: dict[str, Any]) -> bool:
    """True if a product object carries an image digest (hash or digest-pinned purl)."""
    if not isinstance(product, dict):
        return False
    hashes = product.get("hashes")
    if isinstance(hashes, dict) and any(hashes.values()):
        return True
    ids = product.get("identifiers")
    if isinstance(ids, dict):
        purl = str(ids.get("purl") or "")
        if "@sha256:" in purl or "@sha512:" in purl or "@sha256-" in purl:
            return True
    at_id = str(product.get("@id") or "")
    return "@sha256:" in at_id or "@sha512:" in at_id


def _statement_has_justification(stmt: dict[str, Any]) -> bool:
    """True if a not_affected/fixed statement carries a non-empty justification."""
    just = stmt.get("justification")
    impact = stmt.get("impact_statement")
    return bool((just and str(just).strip()) or (impact and str(impact).strip()))


def validate(vex_path: str | Path) -> dict[str, Any]:
    """Run all VEX checks and return a ready libcompliance envelope (no exit)."""
    data, err = lc.load_json(vex_path)
    if err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            measured=None,
            threshold="parseable OpenVEX document",
            detail=err,
            validator=VALIDATOR_NAME,
        )

    if not isinstance(data, dict):
        return lc.envelope(
            lc.Status.INDETERMINATE,
            lc.Tier.BLOCKING,
            detail=f"{vex_path}: top-level VEX must be a JSON object",
            validator=VALIDATOR_NAME,
        )

    # --- Document-level shape ------------------------------------------------ #
    shape_errors: list[str] = []
    ctx = str(data.get("@context") or "")
    if "openvex.dev/ns" not in ctx:
        shape_errors.append("missing/invalid OpenVEX @context")
    if not data.get("author"):
        shape_errors.append("missing author")
    if not data.get("timestamp"):
        shape_errors.append("missing timestamp")
    statements = data.get("statements")
    if not isinstance(statements, list) or not statements:
        shape_errors.append("statements[] missing or empty")

    if shape_errors:
        return lc.envelope(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured=shape_errors,
            threshold="valid OpenVEX document shape",
            detail="OpenVEX shape invalid: " + "; ".join(shape_errors),
            validator=VALIDATOR_NAME,
        )

    # --- Per-statement checks ------------------------------------------------ #
    total = len(statements)
    by_status: dict[str, int] = {}
    violations: list[str] = []
    under_investigation: list[str] = []

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            violations.append(f"statement[{idx}] is not an object")
            continue
        cve = (stmt.get("vulnerability") or {}).get("name") or f"<statement {idx}>"
        status = str(stmt.get("status") or "").strip()

        if status not in VALID_STATUSES:
            violations.append(f"{cve}: invalid/missing status {status!r}")
            continue
        by_status[status] = by_status.get(status, 0) + 1

        # Justification rule (the BLOCKING core of T-116).
        if status in REQUIRES_JUSTIFICATION:
            if not _statement_has_justification(stmt):
                violations.append(
                    f"{cve}: status '{status}' has no justification/impact_statement"
                )
            just = stmt.get("justification")
            if just and str(just) not in CISA_JUSTIFICATIONS:
                violations.append(
                    f"{cve}: justification {just!r} is not a CISA/OpenVEX label"
                )
        elif status == "affected":
            if not (stmt.get("action_statement") and str(stmt["action_statement"]).strip()):
                violations.append(f"{cve}: status 'affected' has no action_statement")
        elif status == "under_investigation":
            under_investigation.append(cve)

        # Any justification present (even on under_investigation) must be a valid label.
        just_any = stmt.get("justification")
        if just_any and str(just_any) not in CISA_JUSTIFICATIONS:
            if status not in REQUIRES_JUSTIFICATION:  # not already flagged above
                violations.append(
                    f"{cve}: justification {just_any!r} is not a CISA/OpenVEX label"
                )

        # Product binding to the image digest.
        products = stmt.get("products") or []
        if not products or not any(_product_is_bound(p) for p in products):
            violations.append(f"{cve}: no product bound to an image digest")

    measured = {
        "statements": total,
        "by_status": by_status,
        "under_investigation": len(under_investigation),
        "violations": len(violations),
    }

    if violations:
        return lc.envelope(
            lc.Status.FAIL,
            lc.Tier.BLOCKING,
            measured=measured,
            threshold="every non-affected statement justified + digest-bound",
            detail="VEX violations: " + "; ".join(violations[:20]),
            validator=VALIDATOR_NAME,
        )

    detail = (
        f"{total} OpenVEX statement(s) valid; "
        f"by_status={by_status}; "
        f"{len(under_investigation)} under_investigation"
    )
    return lc.envelope(
        lc.Status.PASS,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold="every non-affected statement justified + digest-bound",
        detail=detail,
        validator=VALIDATOR_NAME,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the per-release OpenVEX document (T-116)."
    )
    parser.add_argument("vex", nargs="?", default=DEFAULT_VEX, help="path to vex.openvex.json")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output envelope JSON path")
    args = parser.parse_args(argv)

    env = validate(args.vex)
    try:
        Path(args.out).write_text(json.dumps(env) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"warning: could not write {args.out}: {exc}", file=sys.stderr)

    print(json.dumps(env))
    return lc.exit_code_for(env["status"], env["tier"])


if __name__ == "__main__":
    sys.exit(main())
