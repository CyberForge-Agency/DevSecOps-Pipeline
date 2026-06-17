#!/usr/bin/env python3
"""aggregate-compliance — the organizational compliance gate (task T-30).

struktura §6 "bramka zgodności" requires the A.1–A.10 organizational-control
verdicts to be aggregated into ONE state-of-compliance report with an overall
PASS / FAIL decision, where a *missing or stale* evidence item yields FAIL with a
concrete remediation pointer. Today the matrix gate (T-19) aggregates the
*content* (build/scan) rows; this script is its organizational-layer twin: it
runs each A.x validator (the same modules unit-tested under tests/compliance/),
reads back every uniform T-33 envelope, folds in the content matrix's
``blocking_failures`` count, and writes a single ``compliance-status.json``.

Why this exists (closing the warn-only hole)
--------------------------------------------
Before T-30 the only completeness construct was warn-only (evidence-pack.yml
"does NOT block archival") and the A.* outputs were unsigned. This aggregator:

* iterates a FIXED list of expected verdict files — a *missing* required verdict
  is itself a FAIL (you cannot pass a control you never measured);
* honours the validator tiers from libcompliance: only a **BLOCKING** FAIL /
  INDETERMINATE trips the overall gate; an **EVIDENCE-ONLY** measurement is
  recorded with its number but never breaks the build;
* is *honest* — it does not invent PASSes. If the vendor register is stale, the
  restore test overdue, or an access review past due, the corresponding A.x
  validator FAILs and this gate FAILs with it (the caller signs the FAIL and the
  CI step exits non-zero on non-PR runs). That is the correct behaviour.

Output (``compliance-status.json``)
-----------------------------------
::

    {
      "schema": "cyberforge-compliance-status/v1",
      "generated_at": "<UTC ISO-8601>",
      "overall_status": "PASS" | "FAIL" | "INDETERMINATE",
      "blocking_failures": <int>,            # BLOCKING controls whose status != PASS
      "missing_verdicts": [ "<file>", ... ], # required verdict files not produced
      "matrix": { "blocking_failures": <int>, "source": "compliance-matrix.json" },
      "controls": [
        {
          "control": "A.8", "task": "T-27", "label": "...",
          "status": "FAIL", "tier": "BLOCKING",
          "measured": ..., "threshold": ..., "detail": "...",
          "source_file": "access-review.json",
          "remediation": "<concrete next action>"
        }, ...
      ],
      "summary": { "pass": n, "fail": n, "indeterminate": n, "evidence_only": n }
    }

Exit codes
----------
* 0  overall PASS  (every BLOCKING control PASS, no missing required verdict,
                    matrix blocking_failures == 0)
* 1  overall FAIL  (any BLOCKING control FAIL, OR a required verdict missing,
                    OR matrix blocking_failures > 0)
* 2  overall INDETERMINATE (a BLOCKING control could not be measured — e.g. an
                    empty / unparseable artifact — but nothing outright FAILed)

The cosign signature over this file is applied by the CALLER (the
``compliance-validate`` step in evidence-pack.yml) using the same keyless
``cosign sign-blob`` retry pattern as seal-evidence.sh; this script stays pure /
dependency-free so it can run (and be unit-tested) without sigstore.

Usage::

    python3 scripts/aggregate-compliance.py [EVIDENCE_DIR]
        [--governance-dir docs/governance] [--schemas-dir schemas]
        [--runbooks-dir docs/runbooks] [--tfplan PATH]
        [--no-run] [--out EVIDENCE_DIR/compliance-status.json]

``--no-run`` reads already-produced verdict files instead of invoking the
validators (used by the self-test lane and by a re-aggregation pass).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cyberforge-compliance-status/v1"

# Status / tier vocabulary mirrors libcompliance (kept local so the gate has no
# import-time dependency on the validators package layout).
PASS, FAIL, INDETERMINATE = "PASS", "FAIL", "INDETERMINATE"
BLOCKING, EVIDENCE_ONLY = "BLOCKING", "EVIDENCE-ONLY"

_SCRIPT_DIR = Path(__file__).resolve().parent
_PIPELINE_ROOT = _SCRIPT_DIR.parent


@dataclass(frozen=True)
class Control:
    """One A.x organizational control: how to run it and where it lands.

    ``argv_template`` is a list rendered with ``ctx`` (a dict of resolved paths)
    via ``str.format``. ``out_name`` is the verdict filename the validator writes
    inside the evidence dir. ``required`` controls whether a *missing* verdict in
    the evidence-pack context FAILs the gate: A.9 (crypto-vs-Terraform) is enforced
    at deploy time against the live tfplan, so it is only required here when a
    ``--tfplan`` is supplied.
    """

    id: str
    task: str
    label: str
    out_name: str
    argv_template: list[str]
    required: bool = True
    needs_tfplan: bool = False
    remediation: str = ""


# Fixed expected-verdict registry (A.1–A.10). A.5 (retention vs Terraform plan)
# is a deploy-time OPA gate (retention-policy.rego, T-24/T-10) and produces no
# evidence-pack envelope, so it is intentionally absent from this organizational
# aggregation (documented to avoid a "missing A.5" false FAIL).
CONTROLS: list[Control] = [
    Control(
        id="A.1", task="T-20", label="Register of Information (DORA Art.28(3))",
        out_name="roi-validation.json",
        argv_template=[
            "{py}", "{validators}/validate-roi.py",
            "{governance}/register-of-information.yaml", "{schemas}/roi.schema.json",
            "--out", "{out}",
        ],
        remediation="Fix RoI schema/LEI violations in docs/governance/register-of-information.yaml.",
    ),
    Control(
        id="A.2", task="T-21", label="Processor DPA freshness (RODO Art.28)",
        out_name="dpa-compliance-check.json",
        argv_template=["{bash}", "{scripts}/check-dpa.sh"],
        remediation="Re-review docs/governance/vendor-risk-register.md; update 'Last Reviewed:' (<=92d cadence).",
    ),
    Control(
        id="A.3", task="T-22", label="RoPA / DPIA completeness (RODO Art.30/35)",
        out_name="ropa-completeness.json",
        argv_template=[
            "{py}", "{validators}/validate-ropa.py",
            "{governance}/ropa.yaml", "{schemas}/ropa.schema.json", "--out", "{out}",
        ],
        remediation="Complete the per-activity RoPA in docs/governance/ropa.yaml; record DPIA determination.",
    ),
    Control(
        id="A.4", task="T-23", label="ICT incident register (DORA Art.17/NIS2 23)",
        out_name="incident-readiness.json",
        argv_template=[
            "{py}", "{validators}/check-incident-register.py",
            "{governance}/incident-register.yaml",
            "--schema", "{schemas}/incident-register.schema.json", "--out", "{out}",
        ],
        remediation="Fix schema/statutory-clock fields in docs/governance/incident-register.yaml.",
    ),
    Control(
        id="A.6", task="T-25", label="Governance: board approval + training (DORA Art.5)",
        out_name="governance-evidence.json",
        argv_template=["{py}", "{validators}/check-governance.py", "{governance}", "--out", "{out}"],
        remediation="Refresh board-approval / management-training records under docs/governance/.",
    ),
    Control(
        id="A.7", task="T-26", label="Third-party clauses + tested exit plans (DORA 28-30)",
        out_name="tpp-clauses.json",
        argv_template=["{py}", "{validators}/check-thirdparty-clauses.py", "{governance}", "--out", "{out}"],
        remediation="Document/test exit plans for Critical/High vendors in docs/governance/ict-third-party-contract-controls.md.",
    ),
    Control(
        id="A.8", task="T-27", label="Access-review cadence (NIS2 21(2)(i)/ISO 8.2)",
        out_name="access-review.json",
        argv_template=[
            "{py}", "{validators}/check-access-reviews.py",
            "{governance}/access-review-schedule.md", "--out", "{out}",
        ],
        remediation="Conduct the overdue access reviews and update Next-Due in docs/governance/access-review-schedule.md.",
    ),
    Control(
        id="A.9", task="T-28", label="Crypto posture vs IaC (NIS2 21(2)(h)/RODO 32)",
        out_name="crypto-posture.json",
        argv_template=[
            "{py}", "{validators}/assert-crypto.py", "{tfplan}",
            "--baseline", "{governance}/crypto-baseline.yaml", "--out", "{out}",
        ],
        required=False, needs_tfplan=True,
        remediation="Run at deploy time against `terraform show -json` (retention/crypto gate); reconcile with crypto-baseline.yaml.",
    ),
    Control(
        id="A.10", task="T-29", label="Restore-test proof + freshness (DORA Art.11-12)",
        out_name="restore-test.json",
        argv_template=[
            "{py}", "{validators}/check-restore-test.py",
            "{runbooks}/restore-test-log.yaml", "--out", "{out}",
        ],
        remediation="Conduct a successful restore test and record it in docs/runbooks/restore-test-log.yaml.",
    ),
]


@dataclass
class Row:
    """An aggregated per-control result row written to compliance-status.json."""

    control: str
    task: str
    label: str
    status: str
    tier: str
    measured: Any
    threshold: Any
    detail: str
    source_file: str
    remediation: str = ""
    notes: list[str] = field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render_argv(control: Control, ctx: dict[str, str], out_path: Path) -> list[str]:
    """Render a control's argv template against the resolved path context."""
    rctx = dict(ctx, out=str(out_path))
    return [part.format(**rctx) for part in control.argv_template]


def _unwrap_envelope(data: Any) -> dict[str, Any] | None:
    """Return the T-33 envelope from a verdict file's parsed JSON.

    Most validators write the envelope at the top level. check-dpa.sh wraps it as
    ``{"...": ..., "envelope": {...}}``. We accept either, and as a last resort a
    bare ``{status, tier}`` object. Returns None if no envelope can be located.
    """
    if not isinstance(data, dict):
        return None
    if "status" in data and "tier" in data:
        return data
    env = data.get("envelope")
    if isinstance(env, dict) and "status" in env:
        return env
    return None


def _run_validator(control: Control, ctx: dict[str, str], evidence_dir: Path) -> None:
    """Invoke one validator, redirecting stdout to its verdict file when needed.

    check-dpa.sh writes the JSON to stdout (no --out flag), so we capture stdout
    and write it ourselves. All other validators take --out and write the file
    directly (they also echo to stdout, which we ignore). A non-zero exit code is
    EXPECTED for a legitimate FAIL — we do not treat it as a runner error; the
    verdict file is the source of truth and is re-read afterwards.
    """
    out_path = evidence_dir / control.out_name
    argv = _render_argv(control, ctx, out_path)
    writes_stdout = "--out" not in argv  # check-dpa.sh
    try:
        proc = subprocess.run(
            argv, cwd=str(_PIPELINE_ROOT), capture_output=True, text=True, check=False,
        )
    except (OSError, ValueError) as exc:  # validator missing / unrunnable
        print(f"::warning::aggregate-compliance: could not run {control.id}: {exc}",
              file=sys.stderr)
        return
    if writes_stdout and proc.stdout.strip():
        out_path.write_text(proc.stdout, encoding="utf-8")
    if proc.returncode not in (0, 1, 2) and proc.stderr.strip():
        # Genuine runner error (not a tier exit code) — surface stderr tail.
        for line in proc.stderr.strip().splitlines()[-3:]:
            print(f"::warning::aggregate-compliance: {control.id}: {line}", file=sys.stderr)


def _aggregate(
    evidence_dir: Path, ctx: dict[str, str], *, have_tfplan: bool,
) -> tuple[list[Row], list[str]]:
    """Read every expected verdict file and build the per-control rows.

    Returns (rows, missing_required) where missing_required is the list of
    required verdict filenames that were not produced (each forces overall FAIL).
    """
    rows: list[Row] = []
    missing_required: list[str] = []

    for control in CONTROLS:
        required = control.required or (control.needs_tfplan and have_tfplan)
        out_path = evidence_dir / control.out_name

        if not out_path.is_file():
            if control.needs_tfplan and not have_tfplan:
                # A.9 with no tfplan in this context: not a failure here — it is the
                # deploy-time gate's job (retention/crypto vs live plan).
                rows.append(Row(
                    control.id, control.task, control.label,
                    status=INDETERMINATE, tier=EVIDENCE_ONLY,
                    measured=None, threshold=None,
                    detail="not evaluated in evidence-pack context (no Terraform plan); "
                           "enforced at deploy time against `terraform show -json`.",
                    source_file=control.out_name, remediation=control.remediation,
                    notes=["deploy-time control"],
                ))
                continue
            missing_required.append(control.out_name)
            rows.append(Row(
                control.id, control.task, control.label,
                status=FAIL, tier=BLOCKING, measured=None, threshold=None,
                detail=f"required verdict file missing: {control.out_name} "
                       "(control was never measured)",
                source_file=control.out_name,
                remediation=control.remediation or "Produce the verdict by running the A.x validator.",
                notes=["missing-verdict"],
            ))
            continue

        raw = out_path.read_text(encoding="utf-8").strip()
        try:
            data = json.loads(raw) if raw else None
        except json.JSONDecodeError as exc:
            rows.append(Row(
                control.id, control.task, control.label,
                status=INDETERMINATE, tier=BLOCKING, measured=None, threshold=None,
                detail=f"verdict file is not valid JSON: {exc}",
                source_file=control.out_name, remediation=control.remediation,
                notes=["unparseable-verdict"],
            ))
            continue

        env = _unwrap_envelope(data)
        if env is None:
            rows.append(Row(
                control.id, control.task, control.label,
                status=INDETERMINATE, tier=BLOCKING, measured=None, threshold=None,
                detail="verdict file has no recognizable {status,tier} envelope",
                source_file=control.out_name, remediation=control.remediation,
                notes=["no-envelope"],
            ))
            continue

        status = env.get("status", INDETERMINATE)
        tier = env.get("tier", BLOCKING)
        rows.append(Row(
            control.id, control.task, control.label,
            status=status if status in (PASS, FAIL, INDETERMINATE) else INDETERMINATE,
            tier=tier if tier in (BLOCKING, EVIDENCE_ONLY) else BLOCKING,
            measured=env.get("measured"), threshold=env.get("threshold"),
            detail=env.get("detail", ""), source_file=control.out_name,
            remediation=control.remediation if status != PASS else "",
        ))
        if not required and control.needs_tfplan:
            rows[-1].notes.append("optional-in-evidence-pack")

    return rows, missing_required


def _read_matrix_blocking(evidence_dir: Path) -> tuple[int, str]:
    """Read blocking_failures from the content compliance matrix (T-19).

    Returns (count, note). A missing/unparseable matrix is reported as a note but
    does NOT itself force FAIL here — the content gate (T-19 in evidence-pack.yml)
    owns the matrix verdict; we only fold its count into the organizational view.
    """
    matrix = evidence_dir / "compliance-matrix.json"
    if not matrix.is_file():
        return 0, "compliance-matrix.json absent (content gate not run)"
    try:
        data = json.loads(matrix.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return 0, f"compliance-matrix.json unparseable ({exc})"
    count = data.get("blocking_failures", 0)
    if not isinstance(count, int):
        return 0, "compliance-matrix.json has non-integer blocking_failures"
    return count, ""


def _compute_overall(
    rows: list[Row], missing_required: list[str], matrix_blocking: int,
) -> str:
    """Overall verdict by BLOCKING tier only (EVIDENCE-ONLY never trips the gate).

    FAIL          -> any required verdict missing, any BLOCKING row FAIL, or the
                     content matrix reports blocking_failures > 0.
    INDETERMINATE -> no outright FAIL, but a BLOCKING row could not be measured.
    PASS          -> otherwise.
    """
    if missing_required:
        return FAIL
    if matrix_blocking > 0:
        return FAIL
    blocking_fail = any(r.tier == BLOCKING and r.status == FAIL for r in rows)
    if blocking_fail:
        return FAIL
    blocking_indet = any(r.tier == BLOCKING and r.status == INDETERMINATE for r in rows)
    if blocking_indet:
        return INDETERMINATE
    return PASS


def _build_report(
    rows: list[Row], missing_required: list[str], matrix_blocking: int, matrix_note: str,
) -> dict[str, Any]:
    overall = _compute_overall(rows, missing_required, matrix_blocking)
    blocking_failures = sum(1 for r in rows if r.tier == BLOCKING and r.status != PASS)
    summary = {
        "pass": sum(1 for r in rows if r.status == PASS),
        "fail": sum(1 for r in rows if r.status == FAIL),
        "indeterminate": sum(1 for r in rows if r.status == INDETERMINATE),
        "evidence_only": sum(1 for r in rows if r.tier == EVIDENCE_ONLY),
    }
    matrix_block: dict[str, Any] = {
        "blocking_failures": matrix_blocking, "source": "compliance-matrix.json",
    }
    if matrix_note:
        matrix_block["note"] = matrix_note
    return {
        "schema": SCHEMA,
        "generated_at": _now(),
        "overall_status": overall,
        "blocking_failures": blocking_failures,
        "missing_verdicts": missing_required,
        "matrix": matrix_block,
        "controls": [
            {
                "control": r.control, "task": r.task, "label": r.label,
                "status": r.status, "tier": r.tier,
                "measured": r.measured, "threshold": r.threshold,
                "detail": r.detail, "source_file": r.source_file,
                **({"remediation": r.remediation} if r.remediation else {}),
                **({"notes": r.notes} if r.notes else {}),
            }
            for r in rows
        ],
        "summary": summary,
    }


def _exit_code(overall: str) -> int:
    return {PASS: 0, FAIL: 1, INDETERMINATE: 2}.get(overall, 1)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Aggregate A.1-A.10 organizational compliance verdicts into "
                    "one signed PASS/FAIL state-of-compliance report (T-30).",
    )
    p.add_argument("evidence_dir", nargs="?", default="evidence",
                   help="evidence directory holding/receiving the verdict files (default: evidence)")
    p.add_argument("--governance-dir", default=str(_PIPELINE_ROOT / "docs" / "governance"),
                   help="governance docs root (default: docs/governance)")
    p.add_argument("--schemas-dir", default=str(_PIPELINE_ROOT / "schemas"),
                   help="JSON schema root (default: schemas)")
    p.add_argument("--runbooks-dir", default=str(_PIPELINE_ROOT / "docs" / "runbooks"),
                   help="runbooks root (default: docs/runbooks)")
    p.add_argument("--tfplan", default="",
                   help="path to `terraform show -json` output to enable the A.9 crypto check")
    p.add_argument("--no-run", action="store_true",
                   help="do not invoke validators; aggregate already-produced verdict files")
    p.add_argument("--out", default="",
                   help="output path (default: <evidence_dir>/compliance-status.json)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    evidence_dir = Path(args.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else evidence_dir / "compliance-status.json"

    have_tfplan = bool(args.tfplan) and Path(args.tfplan).is_file()
    ctx = {
        "py": sys.executable or "python3",
        "bash": "bash",
        "validators": str(_SCRIPT_DIR / "validators"),
        "scripts": str(_SCRIPT_DIR),
        "governance": args.governance_dir,
        "schemas": args.schemas_dir,
        "runbooks": args.runbooks_dir,
        "tfplan": args.tfplan or "",
    }

    if not args.no_run:
        for control in CONTROLS:
            if control.needs_tfplan and not have_tfplan:
                continue  # A.9 only runs when a Terraform plan is available
            _run_validator(control, ctx, evidence_dir)

    rows, missing_required = _aggregate(evidence_dir, ctx, have_tfplan=have_tfplan)
    matrix_blocking, matrix_note = _read_matrix_blocking(evidence_dir)
    report = _build_report(rows, missing_required, matrix_blocking, matrix_note)

    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    overall = report["overall_status"]
    print(f"compliance-status: overall={overall} "
          f"blocking_failures={report['blocking_failures']} "
          f"missing={len(missing_required)} matrix_blocking={matrix_blocking} "
          f"-> {out_path}")
    for r in rows:
        if r.tier == BLOCKING and r.status != PASS:
            print(f"  {r.control} ({r.task}) {r.status}: {r.detail}")
    return _exit_code(overall)


if __name__ == "__main__":
    sys.exit(main())
