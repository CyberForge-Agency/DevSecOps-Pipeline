#!/usr/bin/env python3
"""matrix_rows — content-evaluating validators for the compliance-matrix rows (T-12).

This module is the *keystone* that replaces the file-presence framework in
``generate-compliance-matrix.sh``. The shell script is the **orchestrator**: for
every one of the 21 matrix rows it shells out to::

    python3 validators/matrix_rows.py <validator-id> <evidence-dir>

which **parses the artifact, asserts the real threshold, and emits the
libcompliance envelope** (``status / tier / measured / threshold / detail /
tool_version``) on one JSON line, then exits with the tier-aware code:

    0  PASS, or any EVIDENCE-ONLY result
    1  FAIL  on a BLOCKING check
    2  INDETERMINATE on a BLOCKING check  (e.g. an empty ``{}`` artifact)

Design rule (blueprint/04 §2, line 69)
--------------------------------------
A row may emit ``PASS`` **only** if it parsed a value and that value met a stated
threshold. An empty ``{}`` / missing artifact yields ``INDETERMINATE`` — never a
silent PASS. ``libcompliance.load_json`` enforces this at source (treats ``{}`` /
``[]`` as "no measurable content"), so this is the single fact that closes the
"a ``{}`` security-report.json PASSes DORA 16.1.a" hole.

The dispatch table (T-12 establishes; T-13..T-17 extend)
-------------------------------------------------------
``DISPATCH`` maps a stable ``validator-id`` to a one-argument ``check(evidence_dir)``
function returning a libcompliance envelope. T-12 ships the keystone validators
(the highest-visibility content rows + a tier-honest evidence reader for the rest).
Subsequent tasks (T-13 DORA/DAST hardening, T-14..T-17 supply-chain/crypto/
ISO/SOC2/RODO) either tighten a function here or add a dedicated module and point
its ``validator-id`` at it — the orchestrator contract never changes.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable

# Make ``scripts.validators.libcompliance`` importable no matter the cwd.
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

Envelope = dict[str, Any]


# --------------------------------------------------------------------------- #
# Artifact parsers (each returns a measured value or an INDETERMINATE reason)  #
# --------------------------------------------------------------------------- #

def _count_trivy_severities(report: Any) -> dict[str, int]:
    """Count CRITICAL/HIGH/MEDIUM/LOW vulnerabilities in a Trivy-shaped report.

    Accepts both the consolidated ``security-report.json`` shape
    ``{"reports": {name: {"Results": [...]}}}`` and a bare Trivy report
    ``{"Results": [...]}``. Unknown shapes contribute zero — the caller decides
    whether "nothing parsed" is INDETERMINATE.
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    results_blocks: list[Any] = []

    if isinstance(report, dict) and isinstance(report.get("reports"), dict):
        for sub in report["reports"].values():
            if isinstance(sub, dict) and isinstance(sub.get("Results"), list):
                results_blocks.append(sub["Results"])
    if isinstance(report, dict) and isinstance(report.get("Results"), list):
        results_blocks.append(report["Results"])

    for results in results_blocks:
        for r in results:
            if not isinstance(r, dict):
                continue
            for v in r.get("Vulnerabilities") or []:
                if not isinstance(v, dict):
                    continue
                sev = str(v.get("Severity", "")).upper()
                if sev in counts:
                    counts[sev] += 1
    counts["_results_parsed"] = sum(len(b) for b in results_blocks)
    return counts


def _read_tool_version(evidence_dir: Path, *summary_names: str) -> str | None:
    """Best-effort parse of a scanner ``tool_version`` from a *-summary.json.

    Never fabricates: returns ``None`` if no summary carries a version.
    """
    for name in summary_names:
        data, err = lc.load_json(evidence_dir / name)
        if err or not isinstance(data, dict):
            continue
        for key in ("tool_version", "version", "trivy_version"):
            if data.get(key):
                return str(data[key])
    return None


# --------------------------------------------------------------------------- #
# Row validators — one small single-purpose function per artifact group        #
# --------------------------------------------------------------------------- #

def vuln_scan(evidence_dir: Path) -> Envelope:
    """Parse security-report.json, assert 0 CRITICAL CVEs (DORA 16.1.a, ISO 8.28, SOC2 PI1.1).

    BLOCKING. Empty ``{}`` -> INDETERMINATE (closes the "{} PASSes" hole). A report
    that parses but exposes a CRITICAL CVE -> FAIL with the measured count.

    This is the keystone row from blueprint/04 §3.1. T-13 may move this into a
    dedicated ``dora_16_1_a.py`` module; the dispatch contract is unchanged.
    """
    data, err = lc.load_json(evidence_dir / "security-report.json")
    tool_version = _read_tool_version(
        evidence_dir, "trivy-image-summary.json", "trivy-sca-summary.json"
    )
    if err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=None, threshold={"critical": 0},
            detail=f"security-report.json: {err}", tool_version=tool_version,
        )
    counts = _count_trivy_severities(data)
    if counts["_results_parsed"] == 0:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=None, threshold={"critical": 0},
            detail="security-report.json parsed but no scanner Results present "
                   "(no measurable scan content)",
            tool_version=tool_version,
        )
    measured = {"critical": counts["CRITICAL"], "high": counts["HIGH"]}
    status = lc.Status.PASS if counts["CRITICAL"] == 0 else lc.Status.FAIL
    return lc.envelope(
        status, lc.Tier.BLOCKING,
        measured=measured, threshold={"critical": 0},
        detail=f"{counts['CRITICAL']} CRITICAL / {counts['HIGH']} HIGH CVEs across "
               f"{counts['_results_parsed']} scan result blocks",
        tool_version=tool_version,
    )


def dast_findings(evidence_dir: Path) -> Envelope:
    """Parse zap-report.json, assert 0 HIGH/CRITICAL alerts (NIS2 21.2.b).

    Counts ZAP alerts with ``riskcode >= 3`` (same parse the incident-issue uses),
    BLOCKING. Empty/missing -> INDETERMINATE. blueprint/04 §3.5. T-13 may move this
    into ``dast_findings.py``.
    """
    data, err = lc.load_json(evidence_dir / "zap-report.json")
    if err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=None, threshold={"high_or_critical": 0},
            detail=f"zap-report.json: {err}",
        )
    # ZAP JSON: {"site": [{"alerts": [{"riskcode": "3", ...}]}]}
    sites = data.get("site") if isinstance(data, dict) else None
    if not isinstance(sites, list) or not sites:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=None, threshold={"high_or_critical": 0},
            detail="zap-report.json parsed but no 'site' entries (no scanned target)",
        )
    high = 0
    alerts_seen = 0
    for site in sites:
        for alert in (site.get("alerts") or []) if isinstance(site, dict) else []:
            alerts_seen += 1
            try:
                if int(alert.get("riskcode", 0)) >= 3:
                    high += 1
            except (TypeError, ValueError):
                continue
    status = lc.Status.PASS if high == 0 else lc.Status.FAIL
    return lc.envelope(
        status, lc.Tier.BLOCKING,
        measured={"high_or_critical": high, "alerts_total": alerts_seen},
        threshold={"high_or_critical": 0},
        detail=f"{high} HIGH/CRITICAL DAST alerts (riskcode>=3) of {alerts_seen} "
               f"across {len(sites)} site(s)",
    )


def sca_scan(evidence_dir: Path) -> Envelope:
    """DORA 16.1.c — SCA ran with a blocking severity gate (blueprint/04 §3.2).

    Asserts the SCA summary's ``severity_filter`` includes CRITICAL and HIGH and
    that ``dependency-review.json`` is a real Trivy report (has Results), not a
    renamed copy. BLOCKING. T-14 hardens the suppression-policy half.
    """
    summary, serr = lc.load_json(evidence_dir / "trivy-sca-summary.json")
    review, rerr = lc.load_json(evidence_dir / "dependency-review.json")
    tool_version = _read_tool_version(evidence_dir, "trivy-sca-summary.json")
    if serr is not None and rerr is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=None, threshold={"severity_filter": ["CRITICAL", "HIGH"]},
            detail=f"SCA evidence: {serr}; {rerr}", tool_version=tool_version,
        )
    sev_filter: Any = None
    if isinstance(summary, dict):
        sev_filter = summary.get("severity_filter")
    sev_text = str(sev_filter or "").upper()
    gate_ok = "CRITICAL" in sev_text and "HIGH" in sev_text
    review_is_report = isinstance(review, dict) and isinstance(review.get("Results"), list)
    if sev_filter is None and not review_is_report:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured={"severity_filter": sev_filter, "dependency_review_is_report": review_is_report},
            threshold={"severity_filter": ["CRITICAL", "HIGH"]},
            detail="SCA summary lacks severity_filter and dependency-review.json is "
                   "not a Trivy report (nothing measurable)",
            tool_version=tool_version,
        )
    status = lc.Status.PASS if (gate_ok and review_is_report) else lc.Status.FAIL
    return lc.envelope(
        status, lc.Tier.BLOCKING,
        measured={"severity_filter": sev_filter, "dependency_review_is_report": review_is_report},
        threshold={"severity_filter": ["CRITICAL", "HIGH"], "dependency_review_is_report": True},
        detail=f"SCA gate filter={sev_filter!r}; dependency-review is Trivy report="
               f"{review_is_report}",
        tool_version=tool_version,
    )


def sbom_supply_chain(evidence_dir: Path) -> Envelope:
    """NIS2 21.2.d / DORA 28 — CycloneDX SBOM well-formed + provenance present.

    Asserts ``bomFormat == CycloneDX``, ``specVersion`` present, ``components`` > 0,
    and an in-toto provenance line exists. BLOCKING on the SBOM structure. T-15
    adds the live ``cosign verify-attestation`` digest binding.
    """
    sbom, serr = lc.load_json(evidence_dir / "sbom.cyclonedx.json")
    prov_path = evidence_dir / "provenance.intoto.jsonl"
    if serr is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=None, threshold={"components": ">0", "bomFormat": "CycloneDX"},
            detail=f"sbom.cyclonedx.json: {serr}",
        )
    bom_format = sbom.get("bomFormat") if isinstance(sbom, dict) else None
    spec_version = sbom.get("specVersion") if isinstance(sbom, dict) else None
    components = sbom.get("components") if isinstance(sbom, dict) else None
    comp_count = len(components) if isinstance(components, list) else 0
    prov_ok = prov_path.is_file() and prov_path.stat().st_size > 0
    schema_ok = bom_format == "CycloneDX" and bool(spec_version) and comp_count > 0
    status = lc.Status.PASS if (schema_ok and prov_ok) else lc.Status.FAIL
    return lc.envelope(
        status, lc.Tier.BLOCKING,
        measured={"bomFormat": bom_format, "specVersion": spec_version,
                  "components": comp_count, "provenance_present": prov_ok},
        threshold={"bomFormat": "CycloneDX", "specVersion": "present",
                   "components": ">0", "provenance_present": True},
        detail=f"CycloneDX {spec_version}, {comp_count} components; "
               f"provenance.intoto.jsonl present={prov_ok}",
    )


def crypto_signing(evidence_dir: Path) -> Envelope:
    """NIS2 21.2.h / SOC2 CC7.1 — image signature verification recorded.

    Reads ``cosign-verification.log`` and asserts it records a successful
    verification (a Rekor entry / "Verified OK"). BLOCKING. T-16 re-executes
    ``cosign verify`` against the deployed digest for live proof.
    """
    log_path = evidence_dir / "cosign-verification.log"
    pres = lc.check_presence(log_path, require_non_empty=True, tier=lc.Tier.BLOCKING,
                             label="cosign-verification.log")
    if pres["status"] != lc.Status.PASS:
        # presence helper already returns INDETERMINATE for missing/empty
        pres["threshold"] = {"verified": True}
        return pres
    text = log_path.read_text(encoding="utf-8", errors="replace")
    lowered = text.lower()
    verified = ("verified ok" in lowered) or ("tlog entry verified" in lowered) or (
        "verification for" in lowered and "succeeded" in lowered)
    status = lc.Status.PASS if verified else lc.Status.FAIL
    return lc.envelope(
        status, lc.Tier.BLOCKING,
        measured={"verified": verified, "log_bytes": len(text)},
        threshold={"verified": True},
        detail="cosign-verification.log records a successful signature verification"
               if verified else
               "cosign-verification.log present but no successful-verification marker found",
    )


def _gates_block(evidence_dir: Path) -> tuple[dict | None, str | None]:
    """Load pipeline-run.json and return its gate-result map (or a reason)."""
    data, err = lc.load_json(evidence_dir / "pipeline-run.json")
    if err is not None:
        return None, err
    if not isinstance(data, dict):
        return None, "pipeline-run.json: not a JSON object"
    # Real shape uses "gates"; tolerate the spec's alternate "gate_results".
    gates = data.get("gates")
    if not isinstance(gates, dict):
        gates = data.get("gate_results")
    if not isinstance(gates, dict) or not gates:
        return None, "pipeline-run.json: no gates block"
    return gates, None


def pipeline_gates(evidence_dir: Path) -> Envelope:
    """ISO/SOC2 process rows — pipeline-run.json gates all succeeded.

    Asserts every recorded gate result is "success" and none is "unknown"/"failure".
    BLOCKING. blueprint/04 §3.6. T-17 cross-checks the run SHA against provenance.
    """
    gates, err = _gates_block(evidence_dir)
    if err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=None, threshold={"all_gates": "success"},
            detail=f"pipeline-run.json: {err}",
        )
    normalised = {k: str(v).lower() for k, v in gates.items()}
    failed = [k for k, v in normalised.items() if v in ("failure", "failed", "error")]
    unknown = [k for k, v in normalised.items() if v in ("unknown", "", "skipped")]
    if unknown and not failed:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured={"gates": normalised}, threshold={"all_gates": "success"},
            detail=f"gates not all measured: {', '.join(sorted(unknown))} unknown/skipped",
        )
    status = lc.Status.PASS if not failed else lc.Status.FAIL
    return lc.envelope(
        status, lc.Tier.BLOCKING,
        measured={"gates": normalised, "failed": failed},
        threshold={"all_gates": "success"},
        detail=("all pipeline gates succeeded" if not failed
                else f"failed gates: {', '.join(sorted(failed))}"),
    )


def anomaly_detection(evidence_dir: Path) -> Envelope:
    """DORA 16.1.d — pipeline ran and produced a run record (EVIDENCE-ONLY).

    Honest tiering: the pipeline cannot prove "anomaly detection" as a gate, but it
    can record that a run with metadata occurred. Reports the run id as a measured
    fact; never blocks. blueprint/04 §2 (EVIDENCE-ONLY).
    """
    data, err = lc.load_json(evidence_dir / "pipeline-run.json")
    if err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.EVIDENCE_ONLY,
            measured=None, threshold={"run_record": "present"},
            detail=f"pipeline-run.json: {err}",
        )
    run = data.get("pipeline", {}) if isinstance(data, dict) else {}
    run_id = run.get("run_id") if isinstance(run, dict) else None
    has_run = bool(run_id) and run_id != "unknown"
    status = lc.Status.PASS if has_run else lc.Status.INDETERMINATE
    return lc.envelope(
        status, lc.Tier.EVIDENCE_ONLY,
        measured={"run_id": run_id},
        threshold={"run_record": "present"},
        detail=f"pipeline run record present (run_id={run_id})" if has_run
               else "pipeline-run.json present but no run_id recorded",
    )


def dpa_register(evidence_dir: Path) -> Envelope:
    """RODO Art.28/5 — processor/DPA register operated within cadence (EVIDENCE-ONLY+freshness).

    Reads dpa-compliance-check.json (produced by check-dpa.sh, which reads the
    maintained vendor register). The per-vendor DPA statuses are EVIDENCE-ONLY; the
    register freshness is the honest signal. Reports the measured vendor count.
    T-21 owns the freshness BLOCKING half; here we record content, never silent-PASS.
    """
    data, err = lc.load_json(evidence_dir / "dpa-compliance-check.json")
    if err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.EVIDENCE_ONLY,
            measured=None, threshold={"register": "operated"},
            detail=f"dpa-compliance-check.json: {err}",
        )
    # Tolerate a few shapes: {"vendors": [...]}, {"measured": {...}}, or a list.
    vendors = None
    if isinstance(data, dict):
        vendors = data.get("vendors") or (data.get("measured") or {}).get("vendors")
    elif isinstance(data, list):
        vendors = data
    count = len(vendors) if isinstance(vendors, list) else None
    if count is None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.EVIDENCE_ONLY,
            measured=None, threshold={"register": "operated"},
            detail="dpa-compliance-check.json parsed but no vendor records found",
        )
    return lc.envelope(
        lc.Status.PASS, lc.Tier.EVIDENCE_ONLY,
        measured={"vendors": count},
        threshold={"register": "operated"},
        detail=f"DPA/processor register operated with {count} vendor records "
               f"(per-vendor DPA validity is EVIDENCE-ONLY)",
    )


def data_flow(evidence_dir: Path) -> Envelope:
    """RODO Art.25 — data-flow record present with PII justification (EVIDENCE-ONLY).

    Reads data-flow-diagram.json and records the number of stages. EVIDENCE-ONLY.
    T-31 owns the BLOCKING-on-schema (every PII stage has a justification) half.
    """
    data, err = lc.load_json(evidence_dir / "data-flow-diagram.json")
    if err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.EVIDENCE_ONLY,
            measured=None, threshold={"stages": ">0"},
            detail=f"data-flow-diagram.json: {err}",
        )
    stages = None
    if isinstance(data, dict):
        stages = data.get("stages") or data.get("flows") or data.get("nodes")
    elif isinstance(data, list):
        stages = data
    count = len(stages) if isinstance(stages, list) else None
    if not count:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.EVIDENCE_ONLY,
            measured={"stages": count}, threshold={"stages": ">0"},
            detail="data-flow-diagram.json parsed but no stages recorded",
        )
    return lc.envelope(
        lc.Status.PASS, lc.Tier.EVIDENCE_ONLY,
        measured={"stages": count}, threshold={"stages": ">0"},
        detail=f"data-flow record present with {count} stages",
    )


# --------------------------------------------------------------------------- #
# Dispatch table — stable validator-ids -> check function                      #
# --------------------------------------------------------------------------- #
# The orchestrator (generate-compliance-matrix.sh) references these ids only;
# changing a row's logic = editing one function here. T-13..T-17 add ids/modules.

DISPATCH: dict[str, Callable[[Path], Envelope]] = {
    # security-report.json — DORA 16.1.a (keystone), ISO A.8.28, SOC2 PI1.1
    "vuln-scan": vuln_scan,
    # zap-report.json — NIS2 21.2.b DAST
    "dast-findings": dast_findings,
    # trivy-sca-summary.json + dependency-review.json — DORA 16.1.c
    "sca-scan": sca_scan,
    # sbom.cyclonedx.json (+ provenance) — NIS2 21.2.d / DORA 28
    "sbom-supply-chain": sbom_supply_chain,
    # cosign-verification.log — NIS2 21.2.h / SOC2 CC7.1
    "crypto-signing": crypto_signing,
    # pipeline-run.json gates — ISO A.8.4/8.9/8.25, SOC2 CC6.1/CC8.1, RODO 30
    "pipeline-gates": pipeline_gates,
    # pipeline-run.json run record — DORA 16.1.d (EVIDENCE-ONLY)
    "anomaly-detection": anomaly_detection,
    # dpa-compliance-check.json — RODO 5.1.c/5.1.e/28 (EVIDENCE-ONLY)
    "dpa-register": dpa_register,
    # data-flow-diagram.json — RODO 25 (EVIDENCE-ONLY)
    "data-flow": data_flow,
}


def evaluate(validator_id: str, evidence_dir: str | Path) -> Envelope:
    """Run a single row validator by id and return its envelope.

    Importable by the gate (T-30) / tests without a process exit. An unknown id is
    a programmer error in the orchestrator -> raises ValidatorError (never a silent
    PASS row).
    """
    fn = DISPATCH.get(validator_id)
    if fn is None:
        raise lc.ValidatorError(
            f"unknown validator-id {validator_id!r}; "
            f"known: {sorted(DISPATCH)}"
        )
    return fn(Path(evidence_dir))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print(
            "usage: matrix_rows.py <validator-id> <evidence-dir>\n"
            f"validator-ids: {', '.join(sorted(DISPATCH))}",
            file=sys.stderr,
        )
        return 2
    validator_id, evidence_dir = args[0], args[1]
    try:
        env = evaluate(validator_id, evidence_dir)
    except lc.ValidatorError as exc:
        # Misuse of the orchestrator: emit an INDETERMINATE envelope so the row is
        # never rendered as PASS, and exit non-zero so it is visible.
        import json
        env = lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured=None, threshold=None, detail=str(exc),
            validator="matrix_rows",
        )
        print(json.dumps(env))
        return 2
    return lc.emit(
        env["status"], env["tier"],
        measured=env["measured"], threshold=env["threshold"],
        detail=env["detail"], tool_version=env["tool_version"],
        validator=env.get("validator") or "matrix_rows",
    )  # emit() exits the process with the tier-aware code


if __name__ == "__main__":
    raise SystemExit(main())
