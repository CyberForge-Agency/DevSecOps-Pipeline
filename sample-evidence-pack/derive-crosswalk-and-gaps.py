#!/usr/bin/env python3
"""derive-crosswalk-and-gaps.py — derive the regulatory crosswalk (Part D.2) and a
machine-readable gap register (Part J) from the live, content-validated verdicts
of THIS evidence-pack run.

It NEVER recomputes a verdict and NEVER invents a PASS. It groups the already-
validated compliance-matrix rows + the A.1-A.10 organizational-control statuses by
evidence artifact (crosswalk) and lists every control that is not PASS (gaps).

Usage:  derive-crosswalk-and-gaps.py <evidence-dir>
Writes: <evidence-dir>/crosswalk.json and <evidence-dir>/gap-register.json
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SATISFIED = {"PASS", "PASSED", "OK", "SATISFIED", "IMPLEMENTED"}

# A.1-A.10 clause/framework + evidence-file mapping (struktura §6 / "Część
# organizacyjna" golden thread). Each row is keyed by the SAME control id and
# bound to the SAME evidence artifact that compliance-status.json reports as the
# control's `source_file`, so the crosswalk can never disagree with the signed
# A.1-A.10 verdicts. (F5 fix: the prior table was shifted by one — it attached
# A.3's DPA clause to A.2, A.4's incident clause to A.3, etc.) Authoritative
# labels/clauses: CyberForge-Evidence-Pack-struktura.md §6 control table.
A_CLAUSES = {
    "A.1":  ("Register of Information", "DORA Art.28(3); ISO 27001 A.5.19", "roi-validation.json"),
    "A.2":  ("Processor DPA register", "RODO Art.28; DORA Art.30", "dpa-compliance-check.json"),
    "A.3":  ("RoPA / DPIA completeness", "RODO Art.30; RODO Art.35; ISO 27001 A.5.34", "ropa-completeness.json"),
    "A.4":  ("ICT incident register", "DORA Art.17; NIS2 Art.23; RODO Art.33", "incident-readiness.json"),
    "A.5":  ("Retention / WORM policy", "DORA Art.12; NIS2 Art.21(2)(c); ISO 27001 A.8.16", "retention-policy.json"),
    "A.6":  ("Governance: board approval + training", "DORA Art.5; NIS2 Art.20; ISO 27001 A.5.1", "governance-evidence.json"),
    "A.7":  ("Third-party Art.30 clauses + exit plans", "DORA Art.30(2)-(3); NIS2 Art.21(2)(d)", "tpp-clauses.json"),
    "A.8":  ("Access-review cadence", "NIS2 Art.21(2)(i); ISO 27001 A.5.18; SOC2 CC6.2", "access-review.json"),
    "A.9":  ("Crypto / encryption posture", "NIS2 Art.21(2)(h); RODO Art.32; DORA Art.9", "crypto-posture.json"),
    "A.10": ("Restore / BCDR test", "DORA Art.11-12; NIS2 Art.21(2)(c); ISO 27001 A.8.13", "restore-test.json"),
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_crosswalk(matrix: dict, status: dict) -> dict:
    buckets: dict[str, dict] = {}

    def add(evidence, label, framework, st):
        ev = str(evidence).strip() if evidence not in (None, "") else "(no evidence artifact)"
        norm = (str(st or "")).strip().upper()
        b = buckets.setdefault(ev, {"evidence": ev, "clauses": [], "_seen": set()})
        key = (label, str(framework or ""))
        if key in b["_seen"]:
            return
        b["_seen"].add(key)
        b["clauses"].append({
            "label": label,
            "framework": str(framework or "").strip() or "Unspecified",
            "status": norm or "NOT REPORTED",
            "satisfied": norm in SATISFIED,
        })

    for fw, rows in (matrix.get("frameworks") or {}).items():
        for r in rows:
            article = str(r.get("article") or "").strip()
            add(r.get("evidence"), f"{fw} {article}".strip(), fw, r.get("status"))

    for ctrl in status.get("controls", []):
        info = A_CLAUSES.get(str(ctrl.get("control") or "").strip())
        if not info:
            continue
        _label, clause_text, evfile = info
        for part in [p.strip() for p in clause_text.split(";") if p.strip()]:
            fw_token = part.split()[0] if part.split() else "Unspecified"
            add(evfile, part, fw_token, ctrl.get("status"))

    rows = []
    for b in buckets.values():
        clauses = b["clauses"]
        frameworks = sorted({c["framework"] for c in clauses})
        rows.append({
            "evidence": b["evidence"],
            "clauses": clauses,
            "frameworks": frameworks,
            "satisfied_count": sum(1 for c in clauses if c["satisfied"]),
            "total_count": len(clauses),
        })
    rows.sort(key=lambda r: (-len(r["frameworks"]), -r["total_count"], r["evidence"]))
    return {
        "schema": "cyberforge-regulatory-crosswalk/v1",
        "generated_at": _now(),
        "description": "Multi-framework crosswalk (spec 5.2 / struktura D.2): one evidence item -> many "
                       "framework clauses. Derived by grouping the content-validated compliance matrix rows "
                       "+ the A.1-A.10 organizational-control verdicts by evidence artifact. A clause is "
                       "'satisfied' only when present AND PASS; no verdicts are recomputed here.",
        "source": {"matrix": "compliance-matrix.json", "org_status": "compliance-status.json"},
        "frameworks_covered": sorted({c["framework"] for r in rows for c in r["clauses"]}),
        "rows": rows,
    }


def build_gaps(matrix: dict, status: dict) -> dict:
    gaps = []
    for c in status.get("controls", []):
        st = str(c.get("status", "")).upper()
        if st == "PASS":
            continue
        gaps.append({
            "id": f"GAP-{c.get('control')}",
            "control": c.get("control"),
            "task": c.get("task"),
            "label": c.get("label"),
            "gap": c.get("detail"),
            "status": st,
            "tier": c.get("tier"),
            "severity": "HIGH" if (c.get("tier") == "BLOCKING" and st == "FAIL")
                        else ("MEDIUM" if st == "INDETERMINATE" else "LOW"),
            "source_file": c.get("source_file"),
            "root_cause": "evidence not yet produced/remediated (offline demo run)"
                          if st == "INDETERMINATE" else "control measured FAIL on sample evidence",
        })
    for fw, rows in (matrix.get("frameworks") or {}).items():
        for r in rows:
            st = str(r.get("status", "")).upper()
            if st in ("PASS", "N/A", "NA"):
                continue
            detail = str(r.get("detail", ""))
            gaps.append({
                "id": f"GAP-{fw}-{str(r.get('article','')).replace(' ', '')}",
                "control": f"{fw} {r.get('article','')}".strip(),
                "label": r.get("requirement"),
                "gap": r.get("detail"),
                "status": st,
                "tier": r.get("tier"),
                "severity": "HIGH" if (r.get("tier") == "BLOCKING" and st == "FAIL")
                            else ("MEDIUM" if (st == "INDETERMINATE" and r.get("tier") == "BLOCKING") else "LOW"),
                "evidence": r.get("evidence"),
                "root_cause": "live-CI / cloud-only evidence artifact absent in offline demo run "
                              "(pending production CI on CyberForge Azure)"
                              if "not found" in detail else "content verdict not PASS",
            })
    return {
        "schema": "cyberforge-gap-register/v1",
        "generated_at": _now(),
        "description": "Machine-readable gap register (spec 5.3 / struktura Part J): control -> gap -> "
                       "severity -> root cause. Derived from the live A.1-A.10 verdicts and the "
                       "content-validated matrix of THIS run. Narrative register: gap-register.md.",
        "note": "Most INDETERMINATE rows are honest 'evidence not produced offline' gaps: the live-CI / "
                "cloud-only artifacts (security-report.json, trivy-sca-summary.json, pipeline-run.json, "
                "provenance.intoto.jsonl, zap-report.json, codeql SARIF, image scan, oscal) are produced by "
                "the production CI run on the CyberForge Azure subscription, which is PENDING for this pack.",
        "total_gaps": len(gaps),
        "by_severity": {s: sum(1 for g in gaps if g["severity"] == s) for s in ("HIGH", "MEDIUM", "LOW")},
        "gaps": gaps,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        sys.stderr.write("usage: derive-crosswalk-and-gaps.py <evidence-dir>\n")
        return 64
    evid = Path(argv[0])
    matrix = json.loads((evid / "compliance-matrix.json").read_text(encoding="utf-8"))
    status = json.loads((evid / "compliance-status.json").read_text(encoding="utf-8"))
    cross = build_crosswalk(matrix, status)
    gaps = build_gaps(matrix, status)
    (evid / "crosswalk.json").write_text(json.dumps(cross, indent=2, ensure_ascii=False), encoding="utf-8")
    (evid / "gap-register.json").write_text(json.dumps(gaps, indent=2, ensure_ascii=False), encoding="utf-8")
    sys.stdout.write(
        f"crosswalk.json: {len(cross['rows'])} evidence buckets, frameworks={cross['frameworks_covered']}\n"
        f"gap-register.json: {gaps['total_gaps']} gaps, by_severity={gaps['by_severity']}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
