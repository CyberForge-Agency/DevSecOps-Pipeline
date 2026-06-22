#!/usr/bin/env python3
"""aggregate-compliance — the organizational compliance gate (tasks T-30/T-73).

struktura §6 "bramka zgodności" requires the organizational-control verdicts to
be aggregated into ONE state-of-compliance report with an overall PASS / FAIL
decision, where a *missing or stale* evidence item yields FAIL with a concrete
remediation pointer. Today the matrix gate (T-19) aggregates the *content*
(build/scan) rows; this script is its organizational-layer twin: it runs each A.x
validator (the same modules unit-tested under tests/compliance/), reads back
every uniform T-33 envelope, folds in the content matrix's ``blocking_failures``
count, and writes a single ``compliance-status.json``.

Aggregation scope (T-30/T-73 fix — closing the headline blind spot)
-------------------------------------------------------------------
The signed headline previously spanned ONLY A.1-A.10, so a FAILing Part-C control
(e.g. ``soa-maturity.json`` shipping FAIL, a missing threat-model verdict, an
unbounded accepted risk) was SEALED into the pack yet UNCOUNTED in the headline.
The registry now ALSO ingests the Part C / Part D verdict artifacts the pipeline
produces — VEX triage, residual-risk, scope/applicability, threat-model,
runtime-hardening, cloud-posture, source-control drift, and the derived crosswalk
/ gap register. Each artifact's OWN tier is respected: only BLOCKING verdicts
count toward ``blocking_failures`` / flip overall to FAIL; EVIDENCE-ONLY
measurements are recorded but never trip the gate; a missing *required* BLOCKING
verdict is a fail-closed FAIL (never a silent pass). These Part-C/D rows are
``aggregate_only`` — produced by OTHER pipeline steps, so this script only READS
them (see ``PART_CD_CONTROLS``). INTEGRATION NOTE: those generators currently run
AFTER the aggregator step, so the live pipeline must run a re-aggregation pass
(or order the aggregator after Part C/D generation) for these rows to populate.

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
    # --- Part C/D scope extension (T-30/T-73 aggregation-scope fix) ---
    # ``aggregate_only`` controls are READ-ONLY here: their verdict artifacts are
    # produced by OTHER pipeline steps (the Part C/D generators in
    # evidence-pack.yml / make-sample-pack.sh), so this aggregator NEVER invokes
    # them — it only ingests the JSON they already wrote. This keeps the headline
    # spanning the whole sealed pack without re-running (and possibly clobbering)
    # those generators with the wrong argv.
    aggregate_only: bool = False
    # ``informational`` controls (crosswalk, gap register) are DERIVED views with
    # no ``{status,tier}`` envelope. They are recorded as present/absent at the
    # EVIDENCE-ONLY tier and NEVER trip the gate (no envelope is not a FAIL here).
    informational: bool = False
    # Tier override for aggregate_only/informational rows whose artifact may be
    # absent or carries no envelope: this is the tier USED FOR MISSING-VERDICT
    # bookkeeping only. When the artifact IS present, its OWN envelope tier wins.
    default_tier: str = BLOCKING


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


# ---------------------------------------------------------------------------
# Part C / Part D verdict registry (T-30/T-73 aggregation-scope fix)
# ---------------------------------------------------------------------------
# The signed headline (compliance-status.json) previously spanned ONLY A.1-A.10,
# so a FAILing Part-C control (e.g. soa-maturity.json shipping FAIL, or a missing
# threat-model verdict) was SEALED into the pack yet UNCOUNTED in the headline.
# These controls close that gap: the aggregator now ALSO ingests the Part-C/D
# verdict artifacts the pipeline produces.
#
# Honesty rules preserved here:
#   * Each artifact's OWN envelope tier wins (read from {status,tier}); only
#     BLOCKING verdicts count toward blocking_failures / flip overall to FAIL.
#     EVIDENCE-ONLY measurements (SoA maturity, design-stage cloud posture) are
#     RECORDED with their number but NEVER trip the gate.
#   * A MISSING *required* BLOCKING verdict is itself a FAIL — identical fail-
#     closed handling to the A.x rows (you cannot pass a control you never
#     measured). Never a silent PASS, never a fabricated verdict.
#   * Artifacts that legitimately may be absent in a given context are marked
#     required=False with the reason on the row (digest-bound VEX with no image
#     digest; source-control drift needing live GitHub config; informational
#     derived views). Absent => recorded INDETERMINATE/EVIDENCE-ONLY, not FAIL.
#
# All of these are ``aggregate_only`` — produced by the Part C/D steps in
# evidence-pack.yml (and make-sample-pack.sh), so the aggregator only READS them.
# INTEGRATION NOTE: those generators run AFTER the current aggregator step, so a
# re-aggregation pass (or moving the aggregator after Part C/D generation) is
# required for these rows to be populated in the live pack — see the module
# docstring / the structured report's integration note.
PART_CD_CONTROLS: list[Control] = [
    Control(
        # T-116 — OpenVEX exploitability triage, digest-bound. BLOCKING per the
        # vex.py validator. NOT required: generate-vex.py refuses without a real
        # sha256 image digest (exit 2), so on a digest-less context the verdict
        # legitimately does not exist (mirrors A.9's deploy-time-only handling).
        id="C.VEX", task="T-116",
        label="OpenVEX exploitability triage (CRA vuln-handling / NIS2 21.2)",
        out_name="vex-triage.json", argv_template=[],
        aggregate_only=True, required=False, default_tier=BLOCKING,
        remediation="Re-run generate-vex.py against the released image digest; "
                    "give every non-affected statement a CISA-category justification.",
    ),
    Control(
        # T-30b — residual-risk statement from the exception register. BLOCKING:
        # an accepted risk without a named approver / future expiry is a real gap.
        id="D.RISK", task="T-30",
        label="Residual-risk statement / accepted-risk register (ISO 27001 Cl.6, DORA Art.6)",
        out_name="residual-risk.json", argv_template=[],
        aggregate_only=True, required=True, default_tier=BLOCKING,
        remediation="Bound every Active acceptance in docs/compliance/exception-register.md "
                    "with a named approver, owner, justification and future expiry (<=12mo).",
    ),
    Control(
        # T-120 — machine-validated scope & applicability determination. BLOCKING:
        # an undetermined regulatory scope is a documented rejection trigger.
        id="B.SCOPE", task="T-120",
        label="Scope & applicability determination (DORA/NIS2/CRA/RODO)",
        out_name="scope-determination.json", argv_template=[],
        aggregate_only=True, required=True, default_tier=BLOCKING,
        remediation="Complete docs/governance/applicability.yaml: each regime needs "
                    "applies + rationale + clause/legal basis + named approver + date.",
    ),
    Control(
        # T-115 — validated STRIDE threat model. BLOCKING: schema completeness +
        # STRIDE coverage + freshness are measured; a missing verdict means the
        # first DevSecOps stage (Plan / threat-model) is unanswered.
        id="C.THREAT", task="T-115",
        label="STRIDE threat-model validation (NIS2 21.2.e / ISO 8.25 / SSDF PW.1)",
        out_name="threat-model-validation.json", argv_template=[],
        aggregate_only=True, required=True, default_tier=BLOCKING,
        remediation="Fix schema/coverage/freshness in the threat model so "
                    "threat_model.py PASSes (every threat traced to a control_ref).",
    ),
    Control(
        # T-118 — Azure Container Apps runtime-hardening posture. BLOCKING on the
        # non-root invariant (a root container stops seal/deploy).
        id="C.RUNTIME", task="T-118",
        label="Runtime-hardening posture vs IaC (NIS2 21.2 / CIS)",
        out_name="runtime-hardening.json", argv_template=[],
        aggregate_only=True, required=True, default_tier=BLOCKING,
        remediation="Reconcile the runtime posture with the Dockerfile/Terraform; "
                    "the non-root USER invariant is BLOCKING.",
    ),
    Control(
        # T-117 — CIS-mapped cloud posture (CSPM). EVIDENCE-ONLY when no live scan
        # exists (honest design-stage INDETERMINATE; a present scan with a CRITICAL
        # is BLOCKING per the artifact's own tier). NOT required: absent until a
        # real CSPM scan runs — recorded as EVIDENCE-ONLY, never a fabricated PASS.
        id="C.CLOUD", task="T-117",
        label="Cloud-posture (CSPM) statement (CIS Azure Foundations)",
        out_name="cloud-posture-validation.json", argv_template=[],
        aggregate_only=True, required=False, default_tier=EVIDENCE_ONLY,
        remediation="Run a live CSPM scan producing cloud-posture.json; "
                    "continuous scan + drift alerting are TARGET-STATE.",
    ),
    Control(
        # ISO 27001 Statement-of-Applicability maturity SCORE. EVIDENCE-ONLY: a
        # maturity score is a measured fact, not a pass/fail gate (struktura §13
        # de-overclaim). A FAIL here (e.g. computed L1 < L3 target) is RECORDED in
        # the headline but does NOT trip the gate — its tier is EVIDENCE-ONLY.
        id="C.SOA", task="T-30b",
        label="ISO 27001 SoA maturity score (computed, not asserted)",
        out_name="soa-maturity.json", argv_template=[],
        aggregate_only=True, required=False, default_tier=EVIDENCE_ONLY,
        remediation="Strengthen the weakest SoA dimension(s) toward the L3 target "
                    "(score is informational; it never blocks).",
    ),
    Control(
        # T-119 — live source-control config drift. BLOCKING tier in the artifact,
        # but NOT required here: it needs live GitHub branch-protection config; with
        # no token the validator HONESTLY returns INDETERMINATE (never a fake PASS),
        # and the workflow degrades on PR. Absent => recorded, not a FAIL.
        id="D.SCM", task="T-119",
        label="Source-control config drift (desired vs live branch protection)",
        out_name="source-control-evidence.json", argv_template=[],
        aggregate_only=True, required=False, default_tier=BLOCKING,
        remediation="Provide a GitHub token so export-github-security-config.sh can "
                    "read live branch protection; reconcile drift vs branch-protection.json.",
    ),
    Control(
        # T-102/T-103 — DERIVED multi-framework crosswalk. Informational: no
        # {status,tier} envelope (it is a mapping view), recorded present/absent at
        # EVIDENCE-ONLY tier; never trips the gate.
        id="X.CROSSWALK", task="T-102",
        label="Multi-framework regulatory crosswalk (derived)",
        out_name="crosswalk.json", argv_template=[],
        aggregate_only=True, required=False, informational=True,
        default_tier=EVIDENCE_ONLY,
        remediation="Regenerate via derive-crosswalk-and-gaps.py from this run's verdicts.",
    ),
    Control(
        # T-103/T-109 — DERIVED machine-readable gap register. Informational view
        # of every non-PASS control; recorded present/absent, never blocking.
        id="X.GAP", task="T-103",
        label="Machine-readable gap register (derived)",
        out_name="gap-register.json", argv_template=[],
        aggregate_only=True, required=False, informational=True,
        default_tier=EVIDENCE_ONLY,
        remediation="Regenerate via derive-crosswalk-and-gaps.py from this run's verdicts.",
    ),
    # ----------------------------------------------------------------------- #
    # Part-G governance / operational-resilience controls (C.9 / E.1 / E.2 /  #
    # E.4 / A.7.7). Each is produced by a DEDICATED file-driven validator      #
    # (check_pentest.py etc.) run by the Part-G step in evidence-pack.yml /    #
    # make-sample-pack.sh BEFORE the aggregator's --no-run pass, so they are   #
    # aggregate_only here (READ, never re-run). Each artifact's OWN envelope    #
    # tier wins: BLOCKING verdicts count toward blocking_failures; the         #
    # EVIDENCE-ONLY ones (TLPT out-of-scope, access-log posture) are recorded  #
    # but never trip the gate. Honest fail-closed for the required BLOCKING    #
    # ones (a missing pentest/ict-risk/asset-map/resilience verdict is a FAIL).#
    # ----------------------------------------------------------------------- #
    Control(
        # C.9 / G1 — independent penetration testing. BLOCKING and REQUIRED:
        # a missing pentest verdict is an unmeasured mandatory control -> FAIL.
        # Honest default of the seed is BLOCKING FAIL ("no pen test on record").
        id="C.9.PENTEST", task="G1",
        label="Penetration testing (independent, >= annual, signed, findings retested)",
        out_name="pentest-report.json", argv_template=[],
        aggregate_only=True, required=True, default_tier=BLOCKING,
        remediation="Commission an independent penetration test, record the signed "
                    "report in docs/governance/pentest-report.yaml, and track "
                    "Critical/High findings to retested closure.",
    ),
    Control(
        # C.9 / G2 — DORA TLPT. Dynamic tier in the artifact (EVIDENCE-ONLY when
        # the documented determination is out-of-scope, BLOCKING when in scope).
        # NOT required here: a documented out-of-scope determination is the honest
        # current state and is recorded; the artifact's own tier governs gating.
        id="C.9.TLPT", task="G2",
        label="DORA Threat-Led Penetration Testing (TLPT)",
        out_name="tlpt-record.json", argv_template=[],
        aggregate_only=True, required=False, default_tier=EVIDENCE_ONLY,
        remediation="If a competent authority identifies the entity as significant "
                    "for TLPT (DORA Art.26(8)), set in_scope:true in "
                    "docs/governance/tlpt-record.yaml and record a conducted, "
                    "external, authority-signed-off TLPT with closure.",
    ),
    Control(
        # E.1 / G3 — ICT risk-management framework + annual review. BLOCKING and
        # REQUIRED. Honest default INDETERMINATE until a real management review
        # records a parseable date (no fabricated review date).
        id="E.1.ICTRISK", task="G3",
        label="ICT risk-management framework + annual review (DORA Art.6 / NIS2 21(2)(a))",
        out_name="ict-risk-framework.json", argv_template=[],
        aggregate_only=True, required=True, default_tier=BLOCKING,
        remediation="Hold the initial management review of "
                    "docs/governance/ict-risk-management-framework.md and record a "
                    "true ISO date + named approver in the 'Last Reviewed:' field.",
    ),
    Control(
        # E.2 / G4 — asset / dependency & critical-function map. BLOCKING and
        # REQUIRED. Honest PASS: real architectural data transcribed from the
        # existing approved inventories (a missing owner/RTO would FAIL).
        id="E.2.ASSETMAP", task="G4",
        label="Asset / dependency & critical-function map (DORA Art.8)",
        out_name="asset-map.json", argv_template=[],
        aggregate_only=True, required=True, default_tier=BLOCKING,
        remediation="Keep docs/governance/asset-map.yaml in sync with the service/"
                    "asset/vendor inventories; every asset needs an owner + "
                    "classification and every high-criticality function an RTO+RPO.",
    ),
    Control(
        # E.4 / G5 — digital operational resilience testing programme. BLOCKING
        # and REQUIRED. Honest default FAIL until each required scenario class is
        # conducted on cadence (no fabricated drill runs).
        id="E.4.RESILIENCE", task="G5",
        label="Digital operational resilience testing programme (DORA Art.24-25)",
        out_name="resilience-programme.json", argv_template=[],
        aggregate_only=True, required=True, default_tier=BLOCKING,
        remediation="Conduct each required resilience scenario class (backup-restore, "
                    "failover, DR-drill, dependency-outage, tabletop) on cadence and "
                    "record last_run in docs/runbooks/resilience-testing-programme.yaml.",
    ),
    Control(
        # A.7.7 / G6 — tamper-evident evidence-store access log. EVIDENCE-ONLY and
        # NOT required: the live access log legitimately may be absent offline
        # (no Azure Storage diagnostic logs / immutable container yet). Absent or
        # present-empty => honest INDETERMINATE, never a fabricated access trail.
        id="A.7.7.ACCESSLOG", task="G6",
        label="Tamper-evident evidence-store access log (SPEC §7 item 7)",
        out_name="access-log-posture.json", argv_template=[],
        aggregate_only=True, required=False, default_tier=EVIDENCE_ONLY,
        remediation="Provision Azure Storage diagnostic settings on the evidence "
                    "container routed to an immutable (WORM) log container, and "
                    "export the hash-chained access-log.jsonl into the pack.",
    ),
]

# The full aggregation scope: A.1-A.10 organizational controls PLUS the Part C/D
# verdicts. The headline overall + blocking_failures now span this whole set.
ALL_CONTROLS: list[Control] = CONTROLS + PART_CD_CONTROLS


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
    # EP-07: the in-toto control attestation that accompanies this verdict, if any.
    # Additive — a None/absent attestation never changes the verdict or the gate.
    attestation: dict[str, Any] | None = None


def _collect_attestation(evidence_dir: Path, out_name: str) -> dict[str, Any] | None:
    """Locate the EP-07 in-toto attestation accompanying a verdict file, if present.

    Convention (libattest.attestation_envelope): for a verdict ``<out_name>`` the
    attestation Statement is ``<out_name>.intoto.json`` and the keyless cosign
    bundle is ``<out_name>.cosign.bundle`` in the same evidence directory. This is
    READ-ONLY and additive: a missing attestation yields None and never alters the
    control's verdict, tier, or the overall gate. We record the attestation's
    presence + signing status HONESTLY (signed / unavailable / unsigned), never a
    fabricated "signed".
    """
    intoto = evidence_dir / f"{out_name}.intoto.json"
    bundle = evidence_dir / f"{out_name}.cosign.bundle"
    if not intoto.is_file():
        return None
    record: dict[str, Any] = {
        "statement_file": intoto.name,
        "predicate_type": None,
        "subject_sha256": None,
        "signature_status": "unsigned",
    }
    try:
        stmt = json.loads(intoto.read_text(encoding="utf-8"))
        record["predicate_type"] = stmt.get("predicateType")
        subjects = stmt.get("subject")
        if isinstance(subjects, list) and subjects:
            digest = subjects[0].get("digest", {})
            if isinstance(digest, dict):
                record["subject_sha256"] = digest.get("sha256")
    except (json.JSONDecodeError, OSError, AttributeError):
        # Present-but-unparseable attestation: record honestly, do not crash.
        record["signature_status"] = "unparseable"
        return record
    if bundle.is_file() and bundle.stat().st_size > 0:
        record["bundle_file"] = bundle.name
        record["signature_status"] = "signed"
    return record


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

    for control in ALL_CONTROLS:
        # ``required`` here drives MISSING-VERDICT handling: a missing required
        # verdict is a fail-closed BLOCKING FAIL (A.x and required Part-C rows);
        # a missing non-required verdict is recorded at the row's default_tier,
        # never a silent PASS and never a FAIL.
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
            if not required:
                # Part-C/D verdict legitimately absent in this context (digest-less
                # VEX, no live CSPM scan, no GitHub token for source-control, or a
                # derived informational view not yet generated). Record an honest
                # INDETERMINATE — NEVER a fabricated PASS — but at the EVIDENCE-ONLY
                # tier so a control that simply WASN'T MEASURED in this context does
                # not trip the gate. (When the artifact IS present its own envelope
                # tier wins, so a present BLOCKING control still gates normally.)
                rows.append(Row(
                    control.id, control.task, control.label,
                    status=INDETERMINATE, tier=EVIDENCE_ONLY,
                    measured=None, threshold=None,
                    detail=f"verdict not present in this context: {control.out_name} "
                           "(not required here; recorded, does not trip the gate)",
                    source_file=control.out_name, remediation=control.remediation,
                    notes=["not-produced", "optional-in-this-context"],
                ))
                continue
            missing_required.append(control.out_name)
            rows.append(Row(
                control.id, control.task, control.label,
                status=FAIL, tier=BLOCKING, measured=None, threshold=None,
                detail=f"required verdict file missing: {control.out_name} "
                       "(control was never measured)",
                source_file=control.out_name,
                remediation=control.remediation or "Produce the verdict by running the validator.",
                notes=["missing-verdict"],
            ))
            continue

        # Informational derived views (crosswalk, gap register) carry no
        # {status,tier} envelope — record present, EVIDENCE-ONLY, never blocking.
        if control.informational:
            rows.append(Row(
                control.id, control.task, control.label,
                status=PASS, tier=EVIDENCE_ONLY, measured=None, threshold=None,
                detail=f"derived view present: {control.out_name} "
                       "(informational; not a pass/fail control)",
                source_file=control.out_name, remediation="",
                notes=["informational"],
            ))
            continue

        raw = out_path.read_text(encoding="utf-8").strip()
        try:
            data = json.loads(raw) if raw else None
        except json.JSONDecodeError as exc:
            rows.append(Row(
                control.id, control.task, control.label,
                status=INDETERMINATE, tier=control.default_tier,
                measured=None, threshold=None,
                detail=f"verdict file is not valid JSON: {exc}",
                source_file=control.out_name, remediation=control.remediation,
                notes=["unparseable-verdict"],
            ))
            continue

        env = _unwrap_envelope(data)
        if env is None:
            rows.append(Row(
                control.id, control.task, control.label,
                status=INDETERMINATE, tier=control.default_tier,
                measured=None, threshold=None,
                detail="verdict file has no recognizable {status,tier} envelope",
                source_file=control.out_name, remediation=control.remediation,
                notes=["no-envelope"],
            ))
            continue

        # The artifact's OWN envelope tier WINS — an EVIDENCE-ONLY artifact
        # (SoA maturity, design-stage cloud posture) is recorded with its number
        # but never trips the gate; only a BLOCKING artifact does.
        status = env.get("status", INDETERMINATE)
        tier = env.get("tier", control.default_tier)
        rows.append(Row(
            control.id, control.task, control.label,
            status=status if status in (PASS, FAIL, INDETERMINATE) else INDETERMINATE,
            tier=tier if tier in (BLOCKING, EVIDENCE_ONLY) else control.default_tier,
            measured=env.get("measured"), threshold=env.get("threshold"),
            detail=env.get("detail", ""), source_file=control.out_name,
            remediation=control.remediation if status != PASS else "",
            attestation=_collect_attestation(evidence_dir, control.out_name),
        ))
        if not required and control.needs_tfplan:
            rows[-1].notes.append("optional-in-evidence-pack")
        elif control.aggregate_only:
            rows[-1].notes.append("part-c/d")

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
        # EP-07: how many controls carry an in-toto attestation, and how many of
        # those are cosign-signed (Rekor-loggable). Additive telemetry; it never
        # affects overall_status. Raising "signed" raises the live/measured ratio.
        "attested": sum(1 for r in rows if r.attestation is not None),
        "attested_signed": sum(
            1 for r in rows
            if r.attestation is not None and r.attestation.get("signature_status") == "signed"
        ),
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
                **({"attestation": r.attestation} if r.attestation else {}),
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
        # Only the A.1-A.10 organizational validators are RUN here. The Part C/D
        # controls (PART_CD_CONTROLS) are ``aggregate_only`` — produced by other
        # pipeline steps — so they are ingested in _aggregate(), never re-run.
        for control in CONTROLS:
            if control.aggregate_only:
                continue  # defensive: A.x rows are not aggregate_only, but be explicit
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
