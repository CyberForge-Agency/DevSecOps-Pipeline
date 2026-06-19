#!/usr/bin/env bash
set -euo pipefail

# Generate CyberForge Evidence Pack HTML Report
# Usage: ./scripts/generate-html-report.sh <evidence-dir> <output-file>
#
# Produces a comprehensive, interactive single-file HTML report from
# pipeline evidence artifacts. Self-contained — works offline, no external
# JS dependencies. Designed for auditor review and client demos.

EVIDENCE_DIR="${1:-.}"
OUTPUT="${2:-${EVIDENCE_DIR}/evidence-report.html}"

# Run a single Python script that parses every evidence file into one
# structured JSON blob, embeds it into a static HTML template, and writes
# the report. This is much more maintainable than dozens of separate bash
# python invocations.
python3 - "$EVIDENCE_DIR" "$OUTPUT" << 'PYEOF'
import json
import os
import sys
import re
from datetime import datetime
from pathlib import Path
from html import escape

EVIDENCE_DIR = Path(sys.argv[1])
OUTPUT = Path(sys.argv[2])

# ── Helpers ──────────────────────────────────────────────────────────────────
def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""

def file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except Exception:
        return 0

def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"

# ── Core data ────────────────────────────────────────────────────────────────
pipeline = load_json(EVIDENCE_DIR / "pipeline-run.json") or {}
compliance = load_json(EVIDENCE_DIR / "compliance-matrix.json") or {}
# Compliance-as-code gate output (A.1-A.10 organizational-control verdicts aggregate). Produced by
# scripts/aggregate-compliance.py from each validator's T-33 envelope; overall_status + per-check
# rows carrying status/measured/tier. May be absent (degrade to NOT AVAILABLE, never fabricate PASS).
compliance_status = load_json(EVIDENCE_DIR / "compliance-status.json") or {}
dpa = load_json(EVIDENCE_DIR / "dpa-compliance-check.json") or {}
data_flow = load_json(EVIDENCE_DIR / "data-flow-diagram.json") or {}
sbom = load_json(EVIDENCE_DIR / "sbom.cyclonedx.json") or {}
trivy_sca = load_json(EVIDENCE_DIR / "trivy-sca-results.json") or {}
trivy_image = load_json(EVIDENCE_DIR / "trivy-image-results.json") or {}
zap = load_json(EVIDENCE_DIR / "zap-report.json") or {}
cosign_log = load_text(EVIDENCE_DIR / "cosign-verification.log")
manifest = load_text(EVIDENCE_DIR / "manifest.sha256")
manifest_json = load_json(EVIDENCE_DIR / "manifest.json") or {}
provenance_text = load_text(EVIDENCE_DIR / "provenance.intoto.jsonl")
codeql = load_json(EVIDENCE_DIR / "codeql/javascript.sarif") or {}
checkov = load_json(EVIDENCE_DIR / "checkov-results.sarif") or {}
coverage = load_json(EVIDENCE_DIR / "coverage/coverage-summary.json") or {}

# ── Build embedded data ──────────────────────────────────────────────────────
def parse_pipeline():
    p = pipeline
    return {
        "name": p.get("pipeline", {}).get("name", "CyberForge Pipeline"),
        "run_id": p.get("pipeline", {}).get("run_id", "?"),
        "run_number": p.get("pipeline", {}).get("run_number", "?"),
        "run_attempt": p.get("pipeline", {}).get("run_attempt", "1"),
        "trigger": p.get("trigger", {}).get("event", "?"),
        "actor": p.get("trigger", {}).get("actor", "?"),
        "ref": p.get("trigger", {}).get("ref", "?"),
        "sha": p.get("trigger", {}).get("sha", "?"),
        "sha_short": p.get("trigger", {}).get("sha", "?")[:12],
        "timestamp": p.get("trigger", {}).get("timestamp", "?"),
        "repo": p.get("repository", {}).get("full_name", "?"),
        "repo_url": p.get("repository", {}).get("url", "#"),
        "environment": p.get("environment", "?"),
        "image_uri": p.get("image", {}).get("uri", "?"),
        "image_digest": p.get("image", {}).get("digest", "?"),
        "gates": p.get("gates", {}),
        "tools": p.get("tools", {}),
    }

def parse_trivy(report, kind):
    """Extract CVE rows from Trivy SCA or image scan."""
    rows = []
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    if not report:
        return {"rows": rows, "severity_count": severity_count, "total": 0}
    for result in report.get("Results", []):
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            if sev in severity_count:
                severity_count[sev] += 1
            rows.append({
                "kind": kind,
                "target": target,
                "cve": v.get("VulnerabilityID", "?"),
                "package": v.get("PkgName", "?"),
                "installed": v.get("InstalledVersion", "?"),
                "fixed": v.get("FixedVersion", ""),
                "severity": sev,
                "title": v.get("Title", v.get("Description", ""))[:200],
                "url": v.get("PrimaryURL", ""),
                "published": v.get("PublishedDate", ""),
                "cvss": (v.get("CVSS", {}) or {}).get("nvd", {}).get("V3Score", ""),
            })
    return {"rows": rows, "severity_count": severity_count, "total": len(rows)}

def parse_sbom():
    components = []
    types = {}
    licenses = {}
    if sbom:
        for c in sbom.get("components", []) or []:
            license_ids = []
            for l in c.get("licenses", []) or []:
                if isinstance(l, dict):
                    lid = (l.get("license") or {}).get("id") or (l.get("license") or {}).get("name")
                    if lid:
                        license_ids.append(lid)
            t = c.get("type", "?")
            types[t] = types.get(t, 0) + 1
            for lid in license_ids:
                licenses[lid] = licenses.get(lid, 0) + 1
            components.append({
                "name": c.get("name", "?"),
                "version": c.get("version", "?"),
                "type": t,
                "purl": c.get("purl", ""),
                "license": ", ".join(license_ids) if license_ids else "—",
                "description": (c.get("description") or "")[:200],
            })
    return {
        "components": components,
        "total": len(components),
        "format": f"{sbom.get('bomFormat','?')} {sbom.get('specVersion','?')}",
        "types": types,
        "licenses": dict(sorted(licenses.items(), key=lambda kv: -kv[1])[:15]),
    }

def parse_zap():
    alerts = []
    severity_count = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    sites = zap.get("site", [])
    target = sites[0].get("@name", "") if sites else ""
    if sites:
        for a in sites[0].get("alerts", []) or []:
            riskcode = int(a.get("riskcode", 0) or 0)
            risk_name = ["Informational", "Low", "Medium", "High"][min(riskcode, 3)]
            severity_count[risk_name] = severity_count.get(risk_name, 0) + 1
            instances = a.get("instances", []) or []
            alerts.append({
                "name": a.get("name", a.get("alert", "?")),
                "riskcode": riskcode,
                "risk": risk_name,
                "confidence": a.get("confidence", ""),
                "cwe": a.get("cweid", ""),
                "wasc": a.get("wascid", ""),
                "desc": re.sub(r"<[^>]+>", " ", a.get("desc", "")).strip()[:600],
                "solution": re.sub(r"<[^>]+>", " ", a.get("solution", "")).strip()[:400],
                "reference": re.sub(r"<[^>]+>", " ", a.get("reference", "")).strip()[:300],
                "count": int(a.get("count", len(instances)) or len(instances)),
                "instances": [
                    {"uri": i.get("uri", ""), "method": i.get("method", "GET"), "evidence": (i.get("evidence") or "")[:200]}
                    for i in instances[:10]
                ],
            })
    return {"alerts": alerts, "severity_count": severity_count, "target": target}

def parse_cosign(text):
    """Extract certificate/Rekor info from cosign verification log."""
    info = {"verified": "Verification" in text or "matching signatures" in text.lower(),
            "raw": text[:5000], "claims": {}}
    # Try to extract JSON from log (cosign sometimes outputs JSON-ish)
    for key in ["Subject", "Issuer", "GitHub Workflow Repository", "GitHub Workflow SHA", "GitHub Workflow Ref", "GitHub Workflow Trigger"]:
        m = re.search(rf"{re.escape(key)}\s*[:=]\s*(.+)", text)
        if m:
            info["claims"][key] = m.group(1).strip().strip(",").strip('"').strip(",")
    return info

def parse_manifest():
    rows = []
    for line in manifest.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("  ", 1)
        if len(parts) == 2:
            rows.append({"hash": parts[0], "file": parts[1]})
    return rows

def parse_compliance():
    fws = []
    for fname, controls in (compliance.get("frameworks") or {}).items():
        passed = sum(1 for c in controls if c.get("status") == "PASS")
        total = len(controls)
        fws.append({
            "name": fname,
            "passed": passed,
            "total": total,
            "controls": [
                {
                    "article": c.get("article", "?"),
                    "requirement": c.get("requirement", ""),
                    "evidence": c.get("evidence", ""),
                    "status": c.get("status", "?"),
                } for c in controls
            ],
        })
    return fws

# Canonical A.1-A.10 catalog: control -> verdict filenames, title, framework clause (struktura §6).
# Fixed editorial clause crosswalk; NOT a computed figure. Mirrors build-audit-document.py's catalog
# so the HTML report and the forensic PDF tell the same compliance-as-code story.
COMPLIANCE_AS_CODE_CATALOG = [
    ("A.1", "DORA Register of Information (RoI) — critical/important ICT providers, exit & substitutability",
     "DORA Art.28(3); Reg (EU) 2024/2956", ["roi-validation.json"], "validate-roi"),
    ("A.2", "Data Processing Agreements (DPA) register — Art.28 processor clauses",
     "GDPR/RODO Art.28(3)", ["dpa-compliance-check.json"], "check-dpa-register"),
    ("A.3", "Records of Processing (RoPA) + DPIA completeness",
     "GDPR/RODO Art.30(1)-(2), Art.35", ["ropa-completeness.json"], "validate-ropa"),
    ("A.4", "Incident register — statutory-clock schema (3-phase DORA clock)",
     "DORA Art.19; NIS2 Art.23", ["incident-readiness.json"], "check-incident-register"),
    ("A.5", "PII data-flow / transfer map",
     "GDPR/RODO Art.30(5), Art.25", ["data-flow-diagram.json"], "check-data-flow"),
    ("A.6", "Governance freshness — management review & NIS2 management training",
     "DORA Art.5; NIS2 Art.20(2); ISO 27001 9.3", ["governance-evidence.json"], "check-governance"),
    ("A.7", "ICT third-party clauses + documented & tested exit strategy",
     "DORA Art.28-30; ISO 27001 A.5.19-A.5.23", ["tpp-clauses.json"], "check-thirdparty-clauses"),
    ("A.8", "Access-review cadence freshness (privileged re-certification)",
     "NIS2 Art.21(2)(i); ISO 27001 A.8.2", ["access-review.json"], "check-access-reviews"),
    ("A.9", "Cryptographic posture — TLS floor & key-management threshold",
     "NIS2 Art.21(2)(h); ISO 27001 A.8.24; SOC2 CC7.1", ["crypto-posture.json"], "assert-crypto"),
    ("A.10", "Backup restore-test proof + freshness (successful restore conducted)",
     "DORA Art.11-12; NIS2 Art.21(2)(c); ISO 27001 A.8.13", ["restore-test.json"], "check-restore-test"),
]

def _norm_key(v):
    return re.sub(r"[^a-z0-9]", "", str(v or "").lower())

def _status_rows_index(status):
    """Index the aggregator's per-check list by every alias (id/validator/file/basename)."""
    if not isinstance(status, dict):
        return {}
    rows_list = []
    for key in ("checks", "controls", "results", "rows", "verdicts", "checks_list", "items"):
        val = status.get(key)
        if isinstance(val, list):
            rows_list = [r for r in val if isinstance(r, dict)]
            break
        if isinstance(val, dict):
            for k, v in val.items():
                if isinstance(v, dict):
                    r = dict(v); r.setdefault("_key", k); rows_list.append(r)
            break
    idx = {}
    for r in rows_list:
        for src in (r.get("id"), r.get("control"), r.get("control_id"), r.get("validator"),
                    r.get("name"), r.get("file"), r.get("artifact"), r.get("_key")):
            if src:
                idx.setdefault(_norm_key(src), r)
                base = os.path.splitext(os.path.basename(str(src)))[0]
                idx.setdefault(_norm_key(base), r)
    return idx

def _row_field(row, *keys):
    if not isinstance(row, dict):
        return None
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return None

def parse_compliance_status():
    """Render-ready A.1-A.10 verdicts from compliance-status.json (the signed aggregate gate).

    We RENDER, we do not recompute. Absent file -> available:False, every control NOT REPORTED;
    never a fabricated PASS. A BLOCKING FAIL (e.g. overdue access review) is surfaced honestly with
    its measured value + remediation pointer so the gate's fail-closed behaviour is visible."""
    status = compliance_status
    available = isinstance(status, dict) and bool(status)
    overall = (_row_field(status, "overall_status", "overall", "status", "result")
               if available else None)
    idx = _status_rows_index(status)
    controls = []
    for cid, title, clause, files, validator in COMPLIANCE_AS_CODE_CATALOG:
        aliases = [cid, cid.replace(".", ""), validator]
        for f in files:
            aliases += [f, os.path.splitext(f)[0]]
        row = None
        for a in aliases:
            row = idx.get(_norm_key(a))
            if row is not None:
                break
        measured = _row_field(row, "measured", "value", "measurement")
        if isinstance(measured, (dict, list)):
            measured = json.dumps(measured)[:120]
        st = _row_field(row, "status", "result", "state")
        rem = _row_field(row, "remediation", "remediation_hint", "hint", "fix", "next_step")
        detail = _row_field(row, "detail", "message", "description")
        if (str(st or "").upper() != "PASS") and not rem and row is not None:
            rem = detail
        controls.append({
            "id": cid, "title": title, "clause": clause,
            "validator": validator, "evidence": files[0] if files else "",
            "status": st, "tier": _row_field(row, "tier"),
            "measured": measured, "threshold": _row_field(row, "threshold"),
            "detail": detail,
            "remediation": rem if (str(st or "").upper() != "PASS") else None,
            "reported": row is not None,
        })
    counts = {"pass": 0, "fail": 0, "indeterminate": 0, "not_reported": 0, "blocking_fail": 0}
    for c in controls:
        s = str(c["status"] or "").upper()
        if s == "PASS": counts["pass"] += 1
        elif s == "FAIL":
            counts["fail"] += 1
            if str(c["tier"] or "").upper() == "BLOCKING":
                counts["blocking_fail"] += 1
        elif s == "INDETERMINATE": counts["indeterminate"] += 1
        if not c["reported"]: counts["not_reported"] += 1
    return {"available": available, "overall": overall, "controls": controls, "counts": counts}

def parse_codeql():
    if not codeql:
        return {"findings": [], "rules_count": 0}
    findings = []
    rules_count = 0
    for run in codeql.get("runs", []) or []:
        rules_count += len(run.get("tool", {}).get("driver", {}).get("rules", []) or [])
        for r in run.get("results", []) or []:
            findings.append({
                "rule": r.get("ruleId", "?"),
                "level": r.get("level", "note"),
                "message": (r.get("message", {}) or {}).get("text", "")[:300],
            })
    return {"findings": findings, "rules_count": rules_count}

def parse_checkov():
    if not checkov:
        return {"findings": [], "rules_count": 0}
    findings = []
    rules_count = 0
    for run in checkov.get("runs", []) or []:
        rules_count += len(run.get("tool", {}).get("driver", {}).get("rules", []) or [])
        for r in run.get("results", []) or []:
            findings.append({
                "rule": r.get("ruleId", "?"),
                "level": r.get("level", "note"),
                "message": (r.get("message", {}) or {}).get("text", "")[:300],
            })
    return {"findings": findings, "rules_count": rules_count}

def parse_coverage():
    if not coverage:
        return {"available": False}
    total = coverage.get("total", {})
    return {
        "available": True,
        "lines": total.get("lines", {}).get("pct", 0),
        "statements": total.get("statements", {}).get("pct", 0),
        "functions": total.get("functions", {}).get("pct", 0),
        "branches": total.get("branches", {}).get("pct", 0),
    }

# ── Evidence file inventory ──────────────────────────────────────────────────
EVIDENCE_FILES = [
    ("pipeline-run.json", "Metadane wykonania pipeline", "Wszystkie ramy"),
    ("security-report.json", "Skonsolidowane wyniki skanów", "DORA Art.16, NIS2 Art.21"),
    ("sbom.cyclonedx.json", "Wykaz składników oprogramowania (SBOM)", "DORA Art.28, NIS2 Art.21.2.d"),
    ("cosign-verification.log", "Dowód podpisu obrazu", "ISO A.8.24, SOC2 CC8.1"),
    ("provenance.intoto.jsonl", "Proweniencja budowy SLSA", "DORA Art.28, SLSA Build L2"),
    ("zap-report.json", "Wyniki skanu DAST (JSON)", "NIS2 Art.21.2.e, ISO A.8.28"),
    ("zap-report.html", "Wyniki skanu DAST (HTML)", "NIS2 Art.21.2.e, ISO A.8.28"),
    ("compliance-matrix.json", "Mapowanie kontroli na ramy regulacyjne", "Wszystkie ramy"),
    ("dpa-compliance-check.json", "Umowy powierzenia przetwarzania danych", "RODO Art.28"),
    ("data-flow-diagram.json", "Mapa przepływu danych osobowych (PII)", "RODO Art.25, Art.30"),
    ("manifest.sha256", "Sumy kontrolne integralności", "ISO A.8.4, SOC2 PI1.1"),
    ("trivy-sca-results.json", "Skan CVE zależności", "DORA Art.16.1.c"),
    ("trivy-image-results.json", "Skan CVE obrazu kontenera", "NIS2 Art.21.2.d"),
    ("checkov-results.sarif", "Skan bezpieczeństwa IaC", "ISO A.8.9, SOC2 CC8.1"),
    ("codeql/javascript.sarif", "Wyniki SAST", "ISO A.8.28, NIS2 Art.21.2.e"),
    ("dependency-review.json", "Przegląd zależności", "DORA Art.16.1.c"),
    ("README.md", "Opis zawartości pakietu", "—"),
]

def inventory():
    items = []
    for name, purpose, framework in EVIDENCE_FILES:
        path = EVIDENCE_DIR / name
        present = path.exists()
        items.append({
            "name": name,
            "purpose": purpose,
            "framework": framework,
            "present": present,
            "size": file_size(path) if present else 0,
            "size_fmt": fmt_size(file_size(path)) if present else "—",
        })
    return items

# ── Master payload ───────────────────────────────────────────────────────────
PAYLOAD = {
    # Deterministic: prefer the pipeline-wide GENERATED_AT (so the report is
    # byte-identical across regenerations and its manifest hash stays stable).
    # Fall back to wall-clock only when run standalone without the env var.
    "generated_at": os.environ.get("GENERATED_AT") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "pipeline": parse_pipeline(),
    "compliance": parse_compliance(),
    "compliance_status": parse_compliance_status(),
    "trivy_sca": parse_trivy(trivy_sca, "filesystem"),
    "trivy_image": parse_trivy(trivy_image, "container"),
    "sbom": parse_sbom(),
    "zap": parse_zap(),
    "cosign": parse_cosign(cosign_log),
    "manifest": parse_manifest(),
    "codeql": parse_codeql(),
    "checkov": parse_checkov(),
    "coverage": parse_coverage(),
    "dpa": dpa,
    "data_flow": data_flow,
    "inventory": inventory(),
    "provenance_excerpt": provenance_text[:2000],
}

# Stats for executive dashboard
total_cves = PAYLOAD["trivy_sca"]["total"] + PAYLOAD["trivy_image"]["total"]
critical_cves = (PAYLOAD["trivy_sca"]["severity_count"].get("CRITICAL", 0)
                 + PAYLOAD["trivy_image"]["severity_count"].get("CRITICAL", 0))
high_cves = (PAYLOAD["trivy_sca"]["severity_count"].get("HIGH", 0)
             + PAYLOAD["trivy_image"]["severity_count"].get("HIGH", 0))
PAYLOAD["stats"] = {
    "total_cves": total_cves,
    "critical_cves": critical_cves,
    "high_cves": high_cves,
    "zap_high": PAYLOAD["zap"]["severity_count"].get("High", 0),
    "zap_medium": PAYLOAD["zap"]["severity_count"].get("Medium", 0),
    "sbom_components": PAYLOAD["sbom"]["total"],
    "evidence_present": sum(1 for x in PAYLOAD["inventory"] if x["present"]),
    "evidence_total": len(PAYLOAD["inventory"]),
    "compliance_passed": sum(fw["passed"] for fw in PAYLOAD["compliance"]),
    "compliance_total": sum(fw["total"] for fw in PAYLOAD["compliance"]),
    "manifest_files": len(PAYLOAD["manifest"]),
    "coverage_lines": PAYLOAD["coverage"].get("lines", 0) if PAYLOAD["coverage"]["available"] else 0,
    "gates_passed": sum(1 for v in PAYLOAD["pipeline"]["gates"].values() if v == "success"),
    "gates_total": len(PAYLOAD["pipeline"]["gates"]),
}

# Serialise as embedded JSON, escape </ to avoid breaking <script> block
DATA_JSON = json.dumps(PAYLOAD, default=str).replace("</", "<\\/")

# WORM footer wording is DRIVEN by the manifest's worm_state, never hardcoded —
# mirrors build-audit-document.py's honesty banner. The absolute locked-archive
# claim is asserted ONLY when the live policy reads locked; until then
# (pending/unlocked/missing) the report says "WORM-designed (unlocked)".
worm_state = manifest_json.get("worm_state")
if isinstance(worm_state, dict):
    worm_state_label = worm_state.get("state") or json.dumps(worm_state)
else:
    worm_state_label = worm_state
if (str(worm_state_label or "").strip().lower()) == "locked":
    WORM_FOOTER = ("Ten pakiet jest przechowywany w niezmiennym archiwum WORM — ZABLOKOWANY "
                   "(Azure Blob, retencja 1825 dni).")
else:
    WORM_FOOTER = ("Ten pakiet jest zaprojektowany w modelu WORM (odblokowany) — retencja "
                   "egzekwowana przez politykę niezmiennego bloba Azure (cel docelowy); "
                   "blokada obiektu nie jest jeszcze włączona (worm_state odczytany na żywo "
                   "z manifestu, nigdy zakodowany na stałe).")

# ── HTML template ────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>Pakiet Dowodowy — Pipeline CyberForge</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--ink:#07111D;--navy:#0D2147;--blue:#1A54D9;--blue2:#2E75F0;--blue3:#5B9AF5;--white:#fff;--mist:#F3F7FD;--fog:#E8F0FB;--txt:#334155;--mid:#64748B;--dim:#94A3B8;--border:#CBD5E8;--blt:#E2EAF5;--red:#DC2626;--orange:#EA580C;--green:#059669;--amber:#D97706;--purple:#7C3AED;--serif:'Playfair Display',Georgia,serif;--sans:'Syne','Inter',system-ui,sans-serif;--mono:'IBM Plex Mono',Menlo,monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:var(--sans);color:var(--txt);background:var(--mist);line-height:1.6;font-size:14px}
.wrap{max-width:1200px;margin:0 auto;padding:0 28px}
h1{font-family:var(--serif);font-size:1.9rem;color:var(--navy);font-weight:900;margin-bottom:6px}
h1 em{font-style:italic;color:var(--blue)}
h2{font-family:var(--serif);font-size:1.3rem;color:var(--navy);font-weight:700;margin:0 0 14px;line-height:1.3}
h3{font-family:var(--sans);font-size:.98rem;font-weight:700;color:var(--navy);margin:14px 0 8px}
h4{font-family:var(--mono);font-size:.7rem;font-weight:600;color:var(--navy);letter-spacing:.06em;text-transform:uppercase;margin:10px 0 6px}
p{margin-bottom:8px;font-size:.86rem}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:var(--mono);font-size:.8em;background:var(--fog);padding:2px 5px;border-radius:3px;color:var(--navy)}
strong{color:var(--navy);font-weight:600}
button{font:inherit;cursor:pointer;border:none;background:none}
.eyebrow{font-family:var(--mono);font-size:.6rem;letter-spacing:.14em;text-transform:uppercase;color:var(--blue);display:block;margin-bottom:6px}
[hidden]{display:none!important}

/* ── Header ──────────────────────────────────────────────────────────────── */
header{background:var(--ink);color:var(--white);padding:24px 0 18px;border-bottom:3px solid var(--blue)}
header .wrap{display:grid;grid-template-columns:1fr auto;gap:20px;align-items:center}
.h-left h1{color:var(--white);font-size:1.6rem;margin-bottom:4px}
.h-left h1 em{color:var(--blue3)}
.h-meta{font-family:var(--mono);font-size:.7rem;color:var(--blue3);letter-spacing:.04em}
.logo{display:flex;align-items:stretch;gap:8px}
.logo-bar{width:3px;background:var(--blue);border-radius:2px}
.logo-cyber,.logo-forge{font-family:var(--mono);font-weight:500;font-size:13px;letter-spacing:.08em;line-height:1.1}
.logo-cyber{color:var(--white)}.logo-forge{color:var(--blue3)}

/* ── Tab nav ─────────────────────────────────────────────────────────────── */
.tabs{background:var(--white);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10;box-shadow:0 1px 3px rgba(13,33,71,.04)}
.tabs-inner{display:flex;overflow-x:auto;scrollbar-width:thin;gap:0;align-items:stretch}
.tab{font-family:var(--mono);font-size:.66rem;letter-spacing:.07em;text-transform:uppercase;color:var(--mid);padding:14px 18px;border-bottom:3px solid transparent;white-space:nowrap;cursor:pointer;transition:all .15s;display:flex;align-items:center;gap:6px}
.tab:hover{color:var(--navy);background:var(--mist)}
.tab.active{color:var(--blue);border-bottom-color:var(--blue);background:var(--white)}
.tab-count{display:inline-block;background:var(--fog);color:var(--mid);padding:1px 7px;border-radius:9px;font-size:.65rem}
.tab.active .tab-count{background:var(--blue);color:var(--white)}
.search-wrap{margin-left:auto;padding:8px 14px;display:flex;align-items:center}
.search-wrap input{font-family:var(--mono);font-size:.78rem;padding:7px 12px;border:1px solid var(--border);border-radius:5px;width:220px;color:var(--navy)}
.search-wrap input:focus{outline:none;border-color:var(--blue)}

/* ── Panels ──────────────────────────────────────────────────────────────── */
.panel{display:none;padding:28px 0 60px;animation:fadeIn .25s ease}
.panel.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* ── Cards & grids ───────────────────────────────────────────────────────── */
.kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
.kpi{background:var(--white);border:1px solid var(--border);border-left:3px solid var(--blue);border-radius:6px;padding:14px 16px}
.kpi.green{border-left-color:var(--green)}.kpi.amber{border-left-color:var(--amber)}.kpi.red{border-left-color:var(--red)}
.kpi-num{font-family:var(--serif);font-size:1.7rem;font-weight:900;color:var(--navy);line-height:1}
.kpi-lbl{font-family:var(--mono);font-size:.6rem;letter-spacing:.06em;text-transform:uppercase;color:var(--mid);margin-top:6px}
.kpi-sub{font-family:var(--mono);font-size:.65rem;color:var(--dim);margin-top:3px}

.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
@media(max-width:800px){.grid-2,.grid-3{grid-template-columns:1fr}}
.card{background:var(--white);border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:14px}
.card h3{margin-top:0}

/* ── Tables ──────────────────────────────────────────────────────────────── */
table{width:100%;border-collapse:collapse;font-size:.82rem;background:var(--white);border:1px solid var(--border);border-radius:6px;overflow:hidden}
thead th{font-family:var(--mono);font-size:.6rem;letter-spacing:.08em;text-transform:uppercase;color:var(--white);background:var(--navy);text-align:left;padding:9px 11px;cursor:pointer;user-select:none;white-space:nowrap}
thead th:hover{background:#1a3160}
thead th.sortable::after{content:' ⇅';color:var(--blue3);font-size:.7rem}
thead th.sort-asc::after{content:' ↑';color:var(--blue3)}
thead th.sort-desc::after{content:' ↓';color:var(--blue3)}
tbody td{padding:9px 11px;border-bottom:1px solid var(--blt);vertical-align:top}
tbody tr:hover{background:var(--mist)}
tbody tr.hide{display:none}

/* ── Severity badges ─────────────────────────────────────────────────────── */
.sev{display:inline-block;font-family:var(--mono);font-size:.6rem;font-weight:700;letter-spacing:.04em;padding:2px 7px;border-radius:3px}
.sev-CRITICAL,.sev-High{background:#FEE2E2;color:#991B1B}
.sev-HIGH{background:#FED7AA;color:#9A3412}
.sev-Medium,.sev-MEDIUM{background:#FEF3C7;color:#92400E}
.sev-Low,.sev-LOW{background:#DBEAFE;color:#1E40AF}
.sev-Informational,.sev-UNKNOWN{background:var(--fog);color:var(--mid)}
.badge-pass{background:#ECFDF5;color:var(--green);padding:2px 8px;border-radius:3px;font-family:var(--mono);font-size:.62rem;font-weight:600}
.badge-fail{background:#FEE2E2;color:#991B1B;padding:2px 8px;border-radius:3px;font-family:var(--mono);font-size:.62rem;font-weight:600}
.badge-skip{background:var(--fog);color:var(--mid);padding:2px 8px;border-radius:3px;font-family:var(--mono);font-size:.62rem;font-weight:600}
.badge-indet{background:#FFFBEB;color:#92400E;padding:2px 8px;border-radius:3px;font-family:var(--mono);font-size:.62rem;font-weight:600}
.badge-blocking{background:#FEE2E2;color:#991B1B;padding:2px 8px;border-radius:3px;font-family:var(--mono);font-size:.62rem;font-weight:600}
.badge-evidence{background:#EEF2FB;color:var(--blue);padding:2px 8px;border-radius:3px;font-family:var(--mono);font-size:.62rem;font-weight:600}

/* ── Filters ─────────────────────────────────────────────────────────────── */
.filter-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.chip{font-family:var(--mono);font-size:.62rem;padding:5px 11px;border:1px solid var(--border);border-radius:14px;background:var(--white);color:var(--mid);cursor:pointer;letter-spacing:.04em;transition:all .12s}
.chip:hover{color:var(--navy)}
.chip.active{background:var(--navy);color:var(--white);border-color:var(--navy)}
.filter-input{flex:1;min-width:200px;font-family:var(--mono);font-size:.76rem;padding:7px 11px;border:1px solid var(--border);border-radius:4px;color:var(--navy)}
.filter-input:focus{outline:none;border-color:var(--blue)}

/* ── Code blocks ─────────────────────────────────────────────────────────── */
.codeblock{font-family:var(--mono);font-size:.72rem;background:var(--ink);color:var(--blue3);padding:14px;border-radius:6px;overflow-x:auto;line-height:1.7;white-space:pre;margin:10px 0;position:relative}
.copy-btn{position:absolute;top:8px;right:8px;font-family:var(--mono);font-size:.58rem;background:var(--navy);color:var(--white);padding:4px 9px;border-radius:3px;cursor:pointer;opacity:.7;transition:opacity .15s}
.copy-btn:hover{opacity:1}
.copy-btn.copied{background:var(--green)}

/* ── Phase pipeline (mini) ───────────────────────────────────────────────── */
.phase-row{display:flex;gap:0;align-items:center;flex-wrap:wrap;margin:18px 0 26px;background:var(--white);border:1px solid var(--border);border-radius:8px;padding:18px}
.ph-node{flex:1;min-width:120px;text-align:center;padding:0 6px;position:relative}
.ph-node::after{content:'→';position:absolute;right:-6px;top:14px;color:var(--mid);font-family:var(--mono);font-size:.8rem}
.ph-node:last-child::after{display:none}
.ph-circle{width:36px;height:36px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:.8rem;font-weight:700;border:2px solid;margin-bottom:6px}
.ph-circle.success{border-color:var(--green);color:var(--green);background:#ECFDF5}
.ph-circle.failure{border-color:var(--red);color:var(--red);background:#FEE2E2}
.ph-circle.skipped{border-color:var(--dim);color:var(--dim);background:var(--fog)}
.ph-name{font-family:var(--mono);font-size:.62rem;letter-spacing:.04em;color:var(--mid)}
.ph-status{font-family:var(--mono);font-size:.55rem;text-transform:uppercase;letter-spacing:.06em;margin-top:2px;font-weight:600}
.ph-status.success{color:var(--green)}.ph-status.failure{color:var(--red)}.ph-status.skipped{color:var(--dim)}

/* ── Donut / charts ──────────────────────────────────────────────────────── */
.donut-wrap{display:flex;gap:20px;align-items:center;flex-wrap:wrap}
.donut{width:140px;height:140px;flex-shrink:0}
.donut-track{stroke:var(--fog);stroke-width:14;fill:none}
.donut-fill{fill:none;stroke-width:14;stroke-linecap:round;transform:rotate(-90deg);transform-origin:50% 50%}
.donut-text{font-family:var(--mono);font-weight:700;fill:var(--navy)}
.bar-row{display:grid;grid-template-columns:140px 1fr 60px;gap:10px;align-items:center;margin-bottom:6px;font-size:.78rem}
.bar-label{font-family:var(--mono);color:var(--navy);text-align:right}
.bar-track{background:var(--fog);height:14px;border-radius:7px;overflow:hidden}
.bar-fill{height:100%;border-radius:7px;transition:width .8s ease}
.bar-value{font-family:var(--mono);font-size:.7rem;color:var(--mid)}

/* ── Expandable rows ─────────────────────────────────────────────────────── */
.expander{cursor:pointer}
.expand-icon{display:inline-block;width:14px;color:var(--blue);transition:transform .2s;font-family:var(--mono)}
.expanded .expand-icon{transform:rotate(45deg)}
.detail-row{display:none}
.detail-row.show{display:table-row}
.detail-row td{background:var(--mist);padding:14px 18px;border-bottom:2px solid var(--border)}
.detail-content{font-size:.82rem}
.detail-content dl{display:grid;grid-template-columns:auto 1fr;gap:4px 16px;margin:8px 0}
.detail-content dt{font-family:var(--mono);font-size:.66rem;color:var(--mid);text-transform:uppercase;letter-spacing:.04em}
.detail-content dd{font-size:.8rem}

/* ── Compliance grid ─────────────────────────────────────────────────────── */
.fw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:14px}
.fw-card{background:var(--white);border:1px solid var(--border);border-radius:8px;padding:16px;cursor:pointer;text-align:center;transition:all .15s}
.fw-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(13,33,71,.06)}
.fw-card.active{border-color:var(--blue);border-width:2px;padding:15px}
.fw-name{font-family:var(--mono);font-size:.74rem;font-weight:600;color:var(--navy);letter-spacing:.04em}
.fw-cov{font-family:var(--mono);font-size:1.4rem;font-weight:700;color:var(--green);margin:4px 0}
.fw-lbl{font-family:var(--mono);font-size:.55rem;color:var(--dim);text-transform:uppercase;letter-spacing:.04em}
.fw-controls{display:none;background:var(--white);border:1px solid var(--border);border-radius:8px;padding:14px;margin-top:8px}
.fw-controls.active{display:block}

/* ── Footer ──────────────────────────────────────────────────────────────── */
footer{background:var(--ink);color:var(--dim);padding:30px 0;text-align:center;font-family:var(--mono);font-size:.7rem;letter-spacing:.04em}
footer a{color:var(--blue3)}
footer p{margin:4px 0}

/* ── Print ───────────────────────────────────────────────────────────────── */
@media print{
  .tabs,.search-wrap,.filter-row,.copy-btn{display:none!important}
  .panel{display:block!important;page-break-before:always;padding:18px 0}
  .panel:first-of-type{page-break-before:auto}
  body{background:var(--white);font-size:11pt}
  .card{break-inside:avoid}
}

/* ── Empty state ─────────────────────────────────────────────────────────── */
.empty{padding:40px;text-align:center;color:var(--dim);font-family:var(--mono);font-size:.85rem}
</style>
</head>
<body>

<header>
<div class="wrap">
  <div class="h-left">
    <span class="eyebrow" style="color:var(--blue3)">Raport Pakietu Dowodowego</span>
    <h1>Uruchomienie Pipeline #__RUN_NUM__ <em>— __ENV__</em></h1>
    <div class="h-meta">__REPO__ · commit __SHA_SHORT__ · __TIMESTAMP__ · uruchomienie __RUN_ID__</div>
  </div>
  <div class="logo">
    <div class="logo-bar"></div>
    <div><div class="logo-cyber">CYBER</div><div class="logo-forge">FORGE</div></div>
  </div>
</div>
</header>

<div class="tabs">
<div class="wrap">
<div class="tabs-inner">
  <button class="tab active" data-tab="dashboard">Pulpit</button>
  <button class="tab" data-tab="vulns">Podatności <span class="tab-count" id="cnt-vulns">0</span></button>
  <button class="tab" data-tab="sbom">SBOM <span class="tab-count" id="cnt-sbom">0</span></button>
  <button class="tab" data-tab="dast">DAST <span class="tab-count" id="cnt-dast">0</span></button>
  <button class="tab" data-tab="compliance">Zgodność</button>
  <button class="tab" data-tab="compliance-code">Zgodność jako Kod</button>
  <button class="tab" data-tab="signing">Podpisywanie</button>
  <button class="tab" data-tab="files">Pliki <span class="tab-count" id="cnt-files">0</span></button>
  <button class="tab" data-tab="dpa">Dostawcy</button>
  <button class="tab" data-tab="dataflow">Przepływ Danych</button>
  <button class="tab" data-tab="raw">Dane Surowe</button>
  <div class="search-wrap">
    <input type="text" id="globalSearch" placeholder="Szukaj wszędzie…">
  </div>
</div>
</div>
</div>

<div class="wrap">

<!-- ────────────────────────────── DASHBOARD ────────────────────────────── -->
<section class="panel active" id="panel-dashboard">

<div class="phase-row" id="phaseRow"></div>

<div class="kpi-row" id="kpiRow"></div>

<div class="grid-2">
  <div class="card">
    <h3>Uruchomienie Pipeline</h3>
    <table>
      <tbody>
        <tr><td><strong>Pipeline</strong></td><td id="d-name"></td></tr>
        <tr><td><strong>Uruchomienie</strong></td><td>#<span id="d-run-num"></span> (id <span id="d-run-id"></span>, próba <span id="d-run-attempt"></span>)</td></tr>
        <tr><td><strong>Wyzwalacz</strong></td><td><span id="d-trigger"></span> przez <span id="d-actor"></span></td></tr>
        <tr><td><strong>Referencja</strong></td><td><code id="d-ref"></code></td></tr>
        <tr><td><strong>Commit</strong></td><td><code id="d-sha"></code></td></tr>
        <tr><td><strong>Repozytorium</strong></td><td><a id="d-repo-link" target="_blank" rel="noopener"></a></td></tr>
        <tr><td><strong>Środowisko</strong></td><td id="d-env"></td></tr>
        <tr><td><strong>URI Obrazu</strong></td><td><code id="d-imguri" style="font-size:.74rem"></code></td></tr>
        <tr><td><strong>Skrót Obrazu</strong></td><td><code id="d-imgdigest" style="font-size:.7rem;word-break:break-all"></code></td></tr>
        <tr><td><strong>Wygenerowano</strong></td><td id="d-generated"></td></tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Pokrycie Zgodności</h3>
    <div class="donut-wrap">
      <svg class="donut" viewBox="0 0 120 120">
        <circle class="donut-track" cx="60" cy="60" r="48"/>
        <circle class="donut-fill" cx="60" cy="60" r="48" id="donutPathDash" stroke="var(--green)"/>
        <text class="donut-text" x="60" y="60" text-anchor="middle" font-size="18" id="donutPctDash">0%</text>
        <text class="donut-text" x="60" y="76" text-anchor="middle" font-size="8" fill="var(--dim)" font-weight="400">kontrole</text>
      </svg>
      <div style="flex:1">
        <div id="fwBars"></div>
      </div>
    </div>
  </div>
</div>

<div class="grid-2">
  <div class="card">
    <h3>Podział wg Istotności</h3>
    <h4>Zależności (Trivy SCA)</h4>
    <div id="trivyBars"></div>
    <h4>Obraz Kontenera (Trivy)</h4>
    <div id="trivyImgBars"></div>
    <h4>Środowisko Uruchomieniowe (OWASP ZAP)</h4>
    <div id="zapBars"></div>
  </div>

  <div class="card">
    <h3>Wersje Narzędzi</h3>
    <table>
      <thead><tr><th>Narzędzie</th><th>Wersja</th></tr></thead>
      <tbody id="toolsTable"></tbody>
    </table>
  </div>
</div>

</section>

<!-- ────────────────────────────── VULNS ────────────────────────────── -->
<section class="panel" id="panel-vulns">
<h2>Znaleziska Podatności</h2>
<p>Połączony widok podatności CVE na poziomie zależności (Trivy SCA wobec package-lock.json) oraz podatności CVE na poziomie kontenera (skan obrazu Trivy wobec zbudowanego obrazu Docker). Kliknij dowolny wiersz, aby rozwinąć szczegóły.</p>

<div class="filter-row">
  <input type="text" class="filter-input" id="vulnSearch" placeholder="Filtruj wg CVE, pakietu lub tytułu…">
  <button class="chip active" data-vsev="all">Wszystkie</button>
  <button class="chip" data-vsev="CRITICAL">Krytyczne</button>
  <button class="chip" data-vsev="HIGH">Wysokie</button>
  <button class="chip" data-vsev="MEDIUM">Średnie</button>
  <button class="chip" data-vsev="LOW">Niskie</button>
  <button class="chip" data-vsrc="all">Wszystkie źródła</button>
  <button class="chip" data-vsrc="filesystem">Tylko SCA</button>
  <button class="chip" data-vsrc="container">Tylko obraz</button>
</div>

<table id="vulnTable">
  <thead><tr>
    <th class="sortable" data-sort="severity">Istotność</th>
    <th class="sortable" data-sort="cve">CVE</th>
    <th class="sortable" data-sort="package">Pakiet</th>
    <th class="sortable" data-sort="installed">Zainstalowana</th>
    <th class="sortable" data-sort="fixed">Naprawiono w</th>
    <th class="sortable" data-sort="kind">Źródło</th>
    <th>Tytuł</th>
  </tr></thead>
  <tbody id="vulnRows"></tbody>
</table>
<p id="vulnEmpty" class="empty" style="display:none">Brak podatności pasujących do filtra.</p>
</section>

<!-- ────────────────────────────── SBOM ────────────────────────────── -->
<section class="panel" id="panel-sbom">
<h2>Wykaz Składników Oprogramowania (SBOM)</h2>
<p id="sbomMeta"></p>

<div class="grid-2">
  <div class="card">
    <h3>Wg Typu Składnika</h3>
    <div id="sbomTypes"></div>
  </div>
  <div class="card">
    <h3>Najczęstsze Licencje</h3>
    <div id="sbomLicenses"></div>
  </div>
</div>

<div class="filter-row">
  <input type="text" class="filter-input" id="sbomSearch" placeholder="Filtruj składniki…">
</div>

<table id="sbomTable">
  <thead><tr>
    <th class="sortable" data-sort="name">Nazwa</th>
    <th class="sortable" data-sort="version">Wersja</th>
    <th class="sortable" data-sort="type">Typ</th>
    <th class="sortable" data-sort="license">Licencja</th>
    <th>PURL</th>
  </tr></thead>
  <tbody id="sbomRows"></tbody>
</table>
</section>

<!-- ────────────────────────────── DAST ────────────────────────────── -->
<section class="panel" id="panel-dast">
<h2>Znaleziska DAST (OWASP ZAP)</h2>
<p>Skan podatności w środowisku uruchomieniowym wobec wdrożonej aplikacji: <code id="zapTarget"></code></p>

<div class="kpi-row" id="zapKpis"></div>

<div class="filter-row">
  <input type="text" class="filter-input" id="zapSearch" placeholder="Filtruj znaleziska…">
  <button class="chip active" data-zsev="all">Wszystkie</button>
  <button class="chip" data-zsev="High">Wysokie</button>
  <button class="chip" data-zsev="Medium">Średnie</button>
  <button class="chip" data-zsev="Low">Niskie</button>
  <button class="chip" data-zsev="Informational">Informacyjne</button>
</div>

<div id="zapAlerts"></div>
</section>

<!-- ────────────────────────────── COMPLIANCE ────────────────────────────── -->
<section class="panel" id="panel-compliance">
<h2>Mapowanie Ram Zgodności</h2>
<p>Kliknij dowolne ramy regulacyjne, aby zobaczyć ich mapowanie na poziomie kontroli. Każda kontrola wskazuje na artefakt dowodowy, który ją spełnia.</p>

<div class="fw-grid" id="fwGrid"></div>
<div id="fwControls"></div>
</section>

<!-- ──────────────────────── COMPLIANCE-AS-CODE (Part A) ──────────────────────── -->
<section class="panel" id="panel-compliance-code">
<h2>Zgodność jako Kod — Werdykty Kontroli Organizacyjnych (Część A)</h2>
<p>Podpisana warstwa kontroli organizacyjnych (bramka zgodności wg struktury &sect;6). Każda kontrola
A.1-A.10 jest sprawdzana przez walidator treści, który wydaje werdykt <strong>PASS wyłącznie</strong>
wtedy, gdy odczytał wartość spełniającą określony próg &mdash; nigdy nie wystawia cichego PASS.
Werdykty agregują się w bramkę odmawiającą domyślnie (fail-closed) poniżej. Jest to dowód, że
wyróżnik jest maszynowo weryfikowany: podpisane werdykty PASS/FAIL kontroli organizacyjnych, a nie
tylko raporty SARIF z DevSecOps.</p>
<div class="card" id="ccGateCard">
  <h3>Zbiorcza bramka zgodności</h3>
  <p id="ccGateLine"></p>
  <p class="empty" id="ccCounts" style="font-size:.82rem"></p>
</div>
<div id="ccTableWrap"></div>
<p style="font-size:.82rem;color:var(--mid);margin-top:10px"><strong>Złota nić (struktura
&sect;1):</strong> każdy wiersz mapuje kontrolę &rarr; werdykt dowodowy (powiązany skrótem SHA w
manifeście) &rarr; klauzulę ram regulacyjnych. BLOKUJĄCY FAIL (np. zaległy przegląd dostępu w A.8 lub
'odtworzenie jeszcze nieprzeprowadzone' w A.10) powoduje, że zbiorcza bramka kończy się kodem
niezerowym przy uruchomieniu spoza PR &mdash; uczciwe, odmawiające domyślnie egzekwowanie z konkretnym
wskazaniem działań naprawczych, a nie baner „na zielono dla pozoru”.</p>
</section>

<!-- ────────────────────────────── SIGNING ────────────────────────────── -->
<section class="panel" id="panel-signing">
<h2>Weryfikacja Cosign</h2>
<p>Kryptograficzny łańcuch nadzoru od kodu źródłowego do wdrożonego obrazu. Cosign stosuje podpisywanie bezkluczowe za pośrednictwem Sigstore — każde zdarzenie podpisania jest zapisywane w publicznym dzienniku przejrzystości Rekor.</p>

<div class="grid-2">
  <div class="card">
    <h3>Status Podpisu</h3>
    <p id="cosignStatus" style="font-size:1rem"></p>
    <h4>Wyodrębnione Oświadczenia</h4>
    <table id="cosignClaims"><tbody></tbody></table>
  </div>
  <div class="card">
    <h3>Zweryfikuj Samodzielnie</h3>
    <p>Każdy może niezależnie zweryfikować, że ten obraz został podpisany przez dokładnie ten pipeline:</p>
    <div class="codeblock"><span class="copy-btn" onclick="copyEl('cosignCmd')">kopiuj</span><span id="cosignCmd"></span></div>
  </div>
</div>

<div class="card">
  <h3>Surowy Dziennik Weryfikacji</h3>
  <p>Wynik polecenia <code>cosign verify</code> w czasie wdrożenia:</p>
  <div class="codeblock"><span class="copy-btn" onclick="copyEl('cosignRaw')">kopiuj</span><span id="cosignRaw"></span></div>
</div>

<div class="card">
  <h3>Proweniencja Budowy SLSA</h3>
  <p>Proweniencja SLSA v1.0 — dowodzi, jak obraz został zbudowany i jakie dane wejściowe wykorzystano. Fragment:</p>
  <div class="codeblock"><span class="copy-btn" onclick="copyEl('provExcerpt')">kopiuj</span><span id="provExcerpt"></span></div>
</div>
</section>

<!-- ────────────────────────────── FILES ────────────────────────────── -->
<section class="panel" id="panel-files">
<h2>Inwentarz Plików Dowodowych</h2>
<p>Wszystkie artefakty w tym pakiecie dowodowym wraz z ich przeznaczeniem, rozmiarem i skrótem SHA256. Manifest SHA256 jest generowany na nowo w chwili archiwizacji — audytorzy mogą ponownie przeliczyć skrót dowolnego pliku i porównać go, aby wykryć manipulację.</p>

<div class="filter-row">
  <input type="text" class="filter-input" id="fileSearch" placeholder="Filtruj pliki…">
  <button class="chip active" data-fpres="all">Wszystkie pliki</button>
  <button class="chip" data-fpres="present">Tylko obecne</button>
  <button class="chip" data-fpres="missing">Tylko brakujące</button>
</div>

<table id="invTable">
  <thead><tr>
    <th class="sortable" data-sort="name">Plik</th>
    <th class="sortable" data-sort="purpose">Przeznaczenie</th>
    <th>Odniesienie do Zgodności</th>
    <th class="sortable" data-sort="size">Rozmiar</th>
    <th>Status</th>
  </tr></thead>
  <tbody id="invRows"></tbody>
</table>

<h3 style="margin-top:24px">Manifest SHA256</h3>
<p>Dowód integralności adresowany treścią. Zweryfikuj dowolny plik, uruchamiając <code>sha256sum &lt;plik&gt;</code> i porównując wynik.</p>
<div class="filter-row">
  <input type="text" class="filter-input" id="manifestSearch" placeholder="Filtruj manifest…">
</div>
<table id="manifestTable">
  <thead><tr><th>Skrót SHA256</th><th>Plik</th></tr></thead>
  <tbody id="manifestRows"></tbody>
</table>
</section>

<!-- ────────────────────────────── DPA ────────────────────────────── -->
<section class="panel" id="panel-dpa">
<h2>Podmioty Przetwarzające (RODO Art. 28)</h2>
<p id="dpaIntro"></p>

<table id="dpaTable">
  <thead><tr>
    <th>Dostawca</th>
    <th>Usługa</th>
    <th>Status DPA</th>
    <th>Lokalizacja Danych</th>
    <th>Uzasadnienie</th>
  </tr></thead>
  <tbody id="dpaRows"></tbody>
</table>

<div class="card" style="margin-top:14px">
  <h3>Polityka Retencji</h3>
  <table id="retentionTable"><tbody></tbody></table>
</div>
</section>

<!-- ────────────────────────────── DATA FLOW ────────────────────────────── -->
<section class="panel" id="panel-dataflow">
<h2>Diagram Przepływu Danych (RODO Art. 25 i 30)</h2>
<p>Przepływ danych osobowych przez pipeline. Obecność danych osobowych (PII) jest uzasadniona dla każdego etapu; sanityzacja usuwa adresy e-mail deweloperów przed archiwizacją dowodów.</p>

<table id="dfTable">
  <thead><tr>
    <th>Etap</th>
    <th>Lokalizacja</th>
    <th>Obecność PII</th>
    <th>Typy</th>
    <th>Uzasadnienie</th>
    <th>Przepływa Do</th>
  </tr></thead>
  <tbody id="dfRows"></tbody>
</table>
</section>

<!-- ────────────────────────────── RAW ────────────────────────────── -->
<section class="panel" id="panel-raw">
<h2>Surowe Dane Uruchomienia Pipeline</h2>
<p>Pełny zrzut JSON pliku <code>pipeline-run.json</code> — źródło prawdy dla metadanych tego raportu.</p>
<div class="codeblock"><span class="copy-btn" onclick="copyEl('rawJson')">kopiuj</span><span id="rawJson"></span></div>

<h2 style="margin-top:24px">Podsumowanie Narzędzi</h2>
<div class="grid-3">
  <div class="card">
    <h3>CodeQL (SAST)</h3>
    <p id="codeqlStat"></p>
  </div>
  <div class="card">
    <h3>Checkov (IaC)</h3>
    <p id="checkovStat"></p>
  </div>
  <div class="card">
    <h3>Pokrycie Testami</h3>
    <div id="coverageStat"></div>
  </div>
</div>
</section>

</div><!-- /wrap -->

<footer>
<div class="wrap">
  <p>Pakiet Dowodowy wygenerowano <span id="genAt"></span> · Pipeline DevSecOps CyberForge · <a href="https://cyberforge.agency">cyberforge.agency</a></p>
  <p>__WORM_FOOTER__ Zabezpieczony manifestem SHA256 — audytorzy mogą ponownie przeliczyć skrót dowolnego pliku i porównać go, aby wykryć manipulację.</p>
</div>
</footer>

<script id="evidence-data" type="application/json">__DATA__</script>
<script>
// ═══════════════════════════════════════════════════════════════════
// Evidence report renderer
// ═══════════════════════════════════════════════════════════════════
const DATA = JSON.parse(document.getElementById('evidence-data').textContent);
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const safeUrl = u => { const s = String(u ?? '').trim(); return /^(https?:|mailto:|#|\/)/i.test(s) ? s : '#'; };

// ── Tab switching ────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    $('panel-' + t.dataset.tab).classList.add('active');
    window.scrollTo({top:0, behavior:'smooth'});
  });
});

// ── Copy helper ──────────────────────────────────────────────────────
function copyEl(id) {
  const el = $(id);
  if (!el) return;
  navigator.clipboard?.writeText(el.textContent).then(() => {
    const btn = el.parentElement.querySelector('.copy-btn');
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = 'copied!';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1300);
    }
  });
}
window.copyEl = copyEl;

// ── DASHBOARD ────────────────────────────────────────────────────────
function renderDashboard() {
  const p = DATA.pipeline;
  $('d-name').textContent = p.name;
  $('d-run-num').textContent = p.run_number;
  $('d-run-id').textContent = p.run_id;
  $('d-run-attempt').textContent = p.run_attempt;
  $('d-trigger').textContent = p.trigger;
  $('d-actor').textContent = p.actor;
  $('d-ref').textContent = p.ref;
  $('d-sha').textContent = p.sha;
  $('d-repo-link').textContent = p.repo;
  // Build the repo link from a sanitized slug + constant origin so no tainted
  // value can reach href (CodeQL js/xss-through-dom): the char-class replace
  // strips anything outside a safe slug, which also neutralizes any scheme.
  const _repoSlug = String(p.repo ?? '').replace(/[^\w.\-\/]/g, '');
  $('d-repo-link').href = _repoSlug ? 'https://github.com/' + _repoSlug : '#';
  $('d-env').textContent = p.environment;
  $('d-imguri').textContent = p.image_uri;
  $('d-imgdigest').textContent = p.image_digest;
  $('d-generated').textContent = DATA.generated_at;

  // Replace header tokens already done server-side; just mirror here
  document.title = `Pakiet Dowodowy — Uruchomienie #${p.run_number} (${p.environment})`;
  $('genAt').textContent = DATA.generated_at;

  // Phase row
  const phaseLabels = ['Bramka Bezpieczeństwa','Budowa i Skan','Podpis i Atestacja','Wdrożenie','DAST'];
  const phaseKeys = ['security_gate','build_scan','sign_attest','deploy','dast'];
  const phaseRow = $('phaseRow');
  phaseRow.innerHTML = phaseKeys.map((k, i) => {
    const status = p.gates[k] || 'skipped';
    return `<div class="ph-node"><div class="ph-circle ${esc(status)}">${i+1}</div><div class="ph-name">${phaseLabels[i]}</div><div class="ph-status ${esc(status)}">${esc(status)}</div></div>`;
  }).join('') + `<div class="ph-node"><div class="ph-circle success">6</div><div class="ph-name">Pakiet Dowodowy</div><div class="ph-status success">success</div></div>`;

  // KPI row
  const s = DATA.stats;
  const kpis = [
    {n: `${s.gates_passed}/${s.gates_total}`, l: 'Bramki Zaliczone', cls: s.gates_passed===s.gates_total?'green':'amber'},
    {n: s.evidence_present + '/' + s.evidence_total, l: 'Pliki Dowodowe', cls: s.evidence_present>=11?'green':'amber'},
    {n: s.compliance_passed + '/' + s.compliance_total, l: 'Kontrole Zgodności', cls: 'green'},
    {n: s.sbom_components, l: 'Składniki SBOM', cls: ''},
    {n: s.total_cves, l: 'Podatności', cls: s.critical_cves>0?'red':(s.high_cves>0?'amber':'green'), sub: `${s.critical_cves}K / ${s.high_cves}W`},
    {n: s.zap_high + s.zap_medium, l: 'DAST W+Ś', cls: s.zap_high>0?'red':(s.zap_medium>0?'amber':'green'), sub: `${s.zap_high}W / ${s.zap_medium}Ś`},
    {n: (s.coverage_lines||0).toFixed(0)+'%', l: 'Pokrycie Testami', cls: s.coverage_lines>=80?'green':'amber'},
    {n: s.manifest_files, l: 'Pliki w Manifeście', cls: ''},
  ];
  $('kpiRow').innerHTML = kpis.map(k =>
    `<div class="kpi ${k.cls}"><div class="kpi-num">${esc(k.n)}</div><div class="kpi-lbl">${esc(k.l)}</div>${k.sub?`<div class="kpi-sub">${esc(k.sub)}</div>`:''}</div>`
  ).join('');

  // Donut for compliance
  const total = s.compliance_total || 1;
  const pct = Math.round(s.compliance_passed * 100 / total);
  const circ = 2 * Math.PI * 48;
  const dash = circ * pct / 100;
  $('donutPathDash').setAttribute('stroke-dasharray', `${dash} ${circ}`);
  $('donutPctDash').textContent = pct + '%';

  // Per-framework bars
  $('fwBars').innerHTML = DATA.compliance.map(fw => {
    const p = fw.total ? (fw.passed*100/fw.total) : 0;
    return `<div class="bar-row"><div class="bar-label">${esc(fw.name)}</div><div class="bar-track"><div class="bar-fill" style="width:${p}%;background:linear-gradient(90deg,var(--blue) 0%,var(--green) 100%)"></div></div><div class="bar-value">${esc(fw.passed)}/${esc(fw.total)}</div></div>`;
  }).join('');

  // Trivy bars
  const sevColors = {CRITICAL:'#DC2626',HIGH:'#EA580C',MEDIUM:'#D97706',LOW:'#2563EB',UNKNOWN:'#94A3B8'};
  function sevBars(counts) {
    const max = Math.max(1, ...Object.values(counts));
    return Object.entries(counts).map(([sev,n]) =>
      `<div class="bar-row"><div class="bar-label">${esc(sev)}</div><div class="bar-track"><div class="bar-fill" style="width:${n/max*100}%;background:${sevColors[sev]||'var(--blue)'}"></div></div><div class="bar-value">${esc(n)}</div></div>`
    ).join('');
  }
  $('trivyBars').innerHTML = sevBars(DATA.trivy_sca.severity_count);
  $('trivyImgBars').innerHTML = sevBars(DATA.trivy_image.severity_count);
  $('zapBars').innerHTML = sevBars(DATA.zap.severity_count);

  // Tools table
  $('toolsTable').innerHTML = Object.entries(DATA.pipeline.tools || {}).map(([k,v]) =>
    `<tr><td><strong>${esc(k)}</strong></td><td><code>${esc(v)}</code></td></tr>`
  ).join('') || '<tr><td colspan="2" class="empty">Nie zarejestrowano wersji narzędzi.</td></tr>';
}

// ── VULNS ────────────────────────────────────────────────────────────
let vulnFilters = {sev:'all', src:'all', q:''};
function renderVulns() {
  const all = [...DATA.trivy_sca.rows, ...DATA.trivy_image.rows];
  const filtered = all.filter(v => {
    if (vulnFilters.sev !== 'all' && v.severity !== vulnFilters.sev) return false;
    if (vulnFilters.src !== 'all' && v.kind !== vulnFilters.src) return false;
    if (vulnFilters.q) {
      const q = vulnFilters.q.toLowerCase();
      const blob = (v.cve+v.package+v.title+v.target).toLowerCase();
      if (!blob.includes(q)) return false;
    }
    return true;
  });
  $('cnt-vulns').textContent = all.length;
  $('vulnEmpty').style.display = filtered.length ? 'none' : 'block';
  $('vulnRows').innerHTML = filtered.map((v, idx) => `
    <tr class="expander" data-idx="${idx}">
      <td><span class="sev sev-${esc(v.severity)}">${esc(v.severity)}</span></td>
      <td><code>${esc(v.cve)}</code><span class="expand-icon">+</span></td>
      <td><code>${esc(v.package)}</code></td>
      <td><code>${esc(v.installed)}</code></td>
      <td><code>${esc(v.fixed||'—')}</code></td>
      <td>${v.kind==='filesystem'?'SCA':'Obraz'}</td>
      <td>${esc(v.title)}</td>
    </tr>
    <tr class="detail-row" id="vd-${idx}"><td colspan="7"><div class="detail-content">
      <dl>
        <dt>CVE</dt><dd><a href="${esc(safeUrl(v.url))}" target="_blank" rel="noopener">${esc(v.cve)}</a></dd>
        <dt>Cel</dt><dd><code>${esc(v.target)}</code></dd>
        <dt>Wynik CVSS</dt><dd>${esc(v.cvss||'nd.')}</dd>
        <dt>Opublikowano</dt><dd>${esc(v.published||'—')}</dd>
        <dt>Działania naprawcze</dt><dd>${v.fixed?`Aktualizacja do <code>${esc(v.fixed)}</code>`:'Brak dostępnej poprawki — akceptacja ryzyka przez .trivyignore z uzasadnieniem VEX'}</dd>
      </dl>
    </div></td></tr>
  `).join('');
  // Wire expanders
  document.querySelectorAll('#vulnRows .expander').forEach(row => {
    row.addEventListener('click', () => {
      const idx = row.dataset.idx;
      const detail = $('vd-'+idx);
      row.classList.toggle('expanded');
      detail.classList.toggle('show');
    });
  });
}
$('vulnSearch').addEventListener('input', e => { vulnFilters.q = e.target.value; renderVulns(); });
document.querySelectorAll('[data-vsev]').forEach(c => c.addEventListener('click', () => {
  document.querySelectorAll('[data-vsev]').forEach(x => x.classList.remove('active'));
  c.classList.add('active'); vulnFilters.sev = c.dataset.vsev; renderVulns();
}));
document.querySelectorAll('[data-vsrc]').forEach(c => c.addEventListener('click', () => {
  document.querySelectorAll('[data-vsrc]').forEach(x => x.classList.remove('active'));
  c.classList.add('active'); vulnFilters.src = c.dataset.vsrc; renderVulns();
}));

// ── SBOM ─────────────────────────────────────────────────────────────
let sbomQ = '';
function renderSbom() {
  const s = DATA.sbom;
  $('cnt-sbom').textContent = s.total;
  $('sbomMeta').innerHTML = `<strong>${esc(s.total)}</strong> składników · format <code>${esc(s.format)}</code>`;
  // Type breakdown
  $('sbomTypes').innerHTML = Object.entries(s.types).map(([t,n]) => {
    const pct = (n/s.total*100).toFixed(1);
    return `<div class="bar-row"><div class="bar-label">${esc(t)}</div><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:var(--blue)"></div></div><div class="bar-value">${esc(n)}</div></div>`;
  }).join('');
  // Licenses
  $('sbomLicenses').innerHTML = Object.entries(s.licenses).map(([l,n]) => {
    const max = Math.max(...Object.values(s.licenses), 1);
    return `<div class="bar-row"><div class="bar-label">${esc(l)}</div><div class="bar-track"><div class="bar-fill" style="width:${n/max*100}%;background:var(--purple)"></div></div><div class="bar-value">${esc(n)}</div></div>`;
  }).join('') || '<p class="empty">Nie znaleziono metadanych licencji.</p>';
  // Filter & render
  const filtered = s.components.filter(c => {
    if (!sbomQ) return true;
    return (c.name+c.version+c.type+c.license+c.purl).toLowerCase().includes(sbomQ.toLowerCase());
  });
  $('sbomRows').innerHTML = filtered.slice(0, 500).map(c => `
    <tr><td><strong>${esc(c.name)}</strong></td><td><code>${esc(c.version)}</code></td><td>${esc(c.type)}</td><td>${esc(c.license)}</td><td><code style="font-size:.7rem">${esc(c.purl)}</code></td></tr>
  `).join('');
}
$('sbomSearch').addEventListener('input', e => { sbomQ = e.target.value; renderSbom(); });

// ── DAST ─────────────────────────────────────────────────────────────
let zapFilter = {sev:'all', q:''};
function renderDast() {
  const z = DATA.zap;
  const zapRiskLabels = {High:'Wysokie', Medium:'Średnie', Low:'Niskie', Informational:'Informacyjne'};
  $('cnt-dast').textContent = z.alerts.length;
  $('zapTarget').textContent = z.target || '(nieznany)';
  $('zapKpis').innerHTML = ['High','Medium','Low','Informational'].map(s => {
    const cls = s==='High'?'red':s==='Medium'?'amber':'';
    return `<div class="kpi ${cls}"><div class="kpi-num">${esc(z.severity_count[s]||0)}</div><div class="kpi-lbl">${esc(zapRiskLabels[s]||s)}</div></div>`;
  }).join('');
  const filtered = z.alerts.filter(a => {
    if (zapFilter.sev !== 'all' && a.risk !== zapFilter.sev) return false;
    if (zapFilter.q && !(a.name+a.desc+a.solution).toLowerCase().includes(zapFilter.q.toLowerCase())) return false;
    return true;
  });
  $('zapAlerts').innerHTML = filtered.length ? filtered.map((a,i) => `
    <div class="card">
      <h3><span class="sev sev-${esc(a.risk)}">${esc(zapRiskLabels[a.risk]||a.risk)}</span> ${esc(a.name)}</h3>
      <table><tbody>
        <tr><td><strong>Pewność</strong></td><td>${esc(a.confidence)}</td></tr>
        ${a.cwe?`<tr><td><strong>CWE</strong></td><td><a href="https://cwe.mitre.org/data/definitions/${esc(a.cwe)}.html" target="_blank" rel="noopener">CWE-${esc(a.cwe)}</a></td></tr>`:''}
        <tr><td><strong>Wystąpienia</strong></td><td>${esc(a.count)} (pokazano ${Math.min(a.instances.length,10)})</td></tr>
      </tbody></table>
      <h4>Opis</h4>
      <p>${esc(a.desc)}</p>
      <h4>Zalecane Rozwiązanie</h4>
      <p>${esc(a.solution)}</p>
      ${a.instances.length ? `
        <h4>Dotknięte Adresy URL</h4>
        <table><thead><tr><th>Metoda</th><th>URI</th></tr></thead><tbody>
          ${a.instances.map(i => `<tr><td><code>${esc(i.method)}</code></td><td><code style="font-size:.7rem">${esc(i.uri)}</code></td></tr>`).join('')}
        </tbody></table>` : ''}
    </div>
  `).join('') : '<p class="empty">Brak pasujących znalezisk DAST.</p>';
}
$('zapSearch').addEventListener('input', e => { zapFilter.q = e.target.value; renderDast(); });
document.querySelectorAll('[data-zsev]').forEach(c => c.addEventListener('click', () => {
  document.querySelectorAll('[data-zsev]').forEach(x => x.classList.remove('active'));
  c.classList.add('active'); zapFilter.sev = c.dataset.zsev; renderDast();
}));

// ── COMPLIANCE ───────────────────────────────────────────────────────
let activeFw = null;
function renderCompliance() {
  $('fwGrid').innerHTML = DATA.compliance.map(fw => {
    const cls = activeFw === fw.name ? 'active' : '';
    return `<div class="fw-card ${cls}" data-fw="${esc(fw.name)}"><div class="fw-name">${esc(fw.name)}</div><div class="fw-cov">${esc(fw.passed)}/${esc(fw.total)}</div><div class="fw-lbl">kontrole</div></div>`;
  }).join('');
  $('fwControls').innerHTML = DATA.compliance.map(fw => `
    <div class="fw-controls ${activeFw===fw.name?'active':''}" data-fw="${esc(fw.name)}">
      <h3>${esc(fw.name)} — spełniono ${esc(fw.passed)} z ${esc(fw.total)} kontroli</h3>
      <table><thead><tr><th>Artykuł</th><th>Wymaganie</th><th>Dowód</th><th>Status</th></tr></thead><tbody>
        ${fw.controls.map(c => `<tr>
          <td><strong>${esc(c.article)}</strong></td>
          <td>${esc(c.requirement)}</td>
          <td><code style="font-size:.74rem">${esc(c.evidence)}</code></td>
          <td><span class="${c.status==='PASS'?'badge-pass':c.status==='SKIP'?'badge-skip':'badge-fail'}">${esc(c.status)}</span></td>
        </tr>`).join('')}
      </tbody></table>
    </div>
  `).join('');
  document.querySelectorAll('.fw-card').forEach(c => c.addEventListener('click', () => {
    activeFw = activeFw === c.dataset.fw ? null : c.dataset.fw;
    renderCompliance();
  }));
}

// ── COMPLIANCE-AS-CODE (A.1-A.10 signed org-control verdicts) ─────────
function ccStatusBadge(s) {
  const n = String(s ?? '').toUpperCase();
  if (n === 'PASS') return '<span class="badge-pass">PASS</span>';
  if (n === 'FAIL') return '<span class="badge-fail">FAIL</span>';
  if (n === 'INDETERMINATE') return '<span class="badge-indet">INDETERMINATE</span>';
  if (n) return '<span class="badge-skip">' + esc(n) + '</span>';
  return '<span class="badge-skip">NOT REPORTED</span>';
}
function ccTierBadge(t) {
  const n = String(t ?? '').toUpperCase();
  if (n === 'BLOCKING') return '<span class="badge-blocking">BLOCKING</span>';
  if (n === 'EVIDENCE-ONLY' || n === 'EVIDENCE_ONLY') return '<span class="badge-evidence">EVIDENCE-ONLY</span>';
  if (n) return '<span class="badge-skip">' + esc(n) + '</span>';
  return '—';
}
function renderComplianceCode() {
  const cc = DATA.compliance_status || {available:false, overall:null, controls:[], counts:{}};
  // Gate verdict line — honest: NOT AVAILABLE when the signed status file is absent.
  if (cc.available) {
    $('ccGateLine').innerHTML = ccStatusBadge(cc.overall) +
      ' <span style="font-size:.82rem;color:var(--mid)">odczytano z pola overall_status w ' +
      'compliance-status.json — podpisany werdykt odmawiający domyślnie; nie przeliczany ponownie tutaj.</span>';
  } else {
    $('ccGateLine').innerHTML = '<span class="badge-skip">NIEDOSTĘPNE</span> ' +
      '<span style="font-size:.82rem;color:var(--mid)">plik compliance-status.json nie był obecny w ' +
      'tym pakiecie dowodowym; kontrole poniżej pokazują NIE RAPORTOWANO zamiast sfałszowanego PASS.</span>';
  }
  const k = cc.counts || {};
  $('ccCounts').textContent =
    'Werdykty A.1-A.10: ' + (k.pass||0) + ' PASS, ' + (k.fail||0) + ' FAIL (' +
    (k.blocking_fail||0) + ' BLOKUJĄCYCH), ' + (k.indeterminate||0) + ' INDETERMINATE, ' +
    (k.not_reported||0) + ' NIE RAPORTOWANO. Tylko BLOKUJĄCY FAIL powoduje niepowodzenie bramki; ' +
    'FAIL typu EVIDENCE-ONLY jest rejestrowany, ale nie przerywa budowy (poziomy libcompliance).';
  const rows = (cc.controls || []).map(c => {
    let measured = (c.measured === null || c.measured === undefined || c.measured === '') ? '—'
      : '<code style="font-size:.72rem">' + esc(c.measured) + '</code>';
    if (c.threshold !== null && c.threshold !== undefined && c.threshold !== '')
      measured += ' <span style="color:var(--mid);font-size:.72rem">/ próg ' + esc(c.threshold) + '</span>';
    const rem = c.remediation ? esc(c.remediation) : '—';
    const ev = c.evidence ? '<code style="font-size:.72rem">' + esc(c.evidence) + '</code>' : '—';
    return '<tr>' +
      '<td><strong>' + esc(c.id) + '</strong></td>' +
      '<td>' + esc(c.title) + '</td>' +
      '<td style="font-size:.78rem">' + esc(c.clause) + '</td>' +
      '<td>' + ev + '</td>' +
      '<td>' + ccTierBadge(c.tier) + '</td>' +
      '<td>' + ccStatusBadge(c.status) + '<br>' + measured + '</td>' +
      '<td style="font-size:.78rem">' + rem + '</td>' +
      '</tr>';
  }).join('');
  $('ccTableWrap').innerHTML =
    '<table><thead><tr><th>Kontrola</th><th>Kontrola organizacyjna</th><th>Klauzula ram regulacyjnych</th>' +
    '<th>Werdykt dowodowy</th><th>Poziom</th><th>Wynik / zmierzono</th><th>Wskazanie naprawcze</th>' +
    '</tr></thead><tbody>' + rows + '</tbody></table>';
}

// ── SIGNING ──────────────────────────────────────────────────────────
function renderSigning() {
  const c = DATA.cosign;
  $('cosignStatus').innerHTML = c.verified
    ? '<span class="badge-pass">✓ ZWERYFIKOWANO</span> Podpis obrazu zweryfikowany w czasie wdrożenia.'
    : '<span class="badge-fail">NIEZWERYFIKOWANY</span>';
  $('cosignClaims').innerHTML = `<tbody>${
    Object.entries(c.claims).map(([k,v]) =>
      `<tr><td><strong>${esc(k)}</strong></td><td><code style="font-size:.74rem">${esc(v)}</code></td></tr>`
    ).join('') || '<tr><td colspan="2" class="empty">Nie wyodrębniono oświadczeń</td></tr>'
  }</tbody>`;
  const repo = DATA.pipeline.repo;
  const img = DATA.pipeline.image_uri || '';
  const dig = DATA.pipeline.image_digest || '';
  $('cosignCmd').textContent =
    `cosign verify \\\n  --certificate-identity-regexp='^https://github.com/${repo}/.github/workflows/sign-and-attest.yml@refs/(heads/main|tags/.*)$' \\\n  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \\\n  ${img}@${dig}`;
  $('cosignRaw').textContent = c.raw || '(nie zarejestrowano dziennika)';
  $('provExcerpt').textContent = DATA.provenance_excerpt || '(nie zarejestrowano proweniencji)';
}

// ── FILES (inventory + manifest) ─────────────────────────────────────
let invFilter = {pres:'all', q:''};
let manifestQ = '';
function renderFiles() {
  $('cnt-files').textContent = DATA.inventory.length;
  const inv = DATA.inventory.filter(f => {
    if (invFilter.pres === 'present' && !f.present) return false;
    if (invFilter.pres === 'missing' && f.present) return false;
    if (invFilter.q && !(f.name+f.purpose+f.framework).toLowerCase().includes(invFilter.q.toLowerCase())) return false;
    return true;
  });
  $('invRows').innerHTML = inv.map(f => `
    <tr>
      <td><code>${esc(f.name)}</code></td>
      <td>${esc(f.purpose)}</td>
      <td><code style="font-size:.7rem">${esc(f.framework)}</code></td>
      <td>${esc(f.size_fmt)}</td>
      <td><span class="${f.present?'badge-pass':'badge-fail'}">${f.present?'OBECNY':'BRAKUJĄCY'}</span></td>
    </tr>
  `).join('');

  // Manifest
  const m = DATA.manifest.filter(r => !manifestQ || (r.hash+r.file).toLowerCase().includes(manifestQ.toLowerCase()));
  $('manifestRows').innerHTML = m.slice(0, 500).map(r => `
    <tr><td><code style="font-size:.66rem">${esc(r.hash)}</code></td><td><code>${esc(r.file)}</code></td></tr>
  `).join('');
}
$('fileSearch').addEventListener('input', e => { invFilter.q = e.target.value; renderFiles(); });
$('manifestSearch').addEventListener('input', e => { manifestQ = e.target.value; renderFiles(); });
document.querySelectorAll('[data-fpres]').forEach(c => c.addEventListener('click', () => {
  document.querySelectorAll('[data-fpres]').forEach(x => x.classList.remove('active'));
  c.classList.add('active'); invFilter.pres = c.dataset.fpres; renderFiles();
}));

// ── DPA ──────────────────────────────────────────────────────────────
function renderDpa() {
  const d = DATA.dpa || {};
  $('dpaIntro').textContent = d.description || '';
  $('dpaRows').innerHTML = (d.processors || []).map(p => `
    <tr>
      <td><strong>${esc(p.name)}</strong></td>
      <td>${esc(p.service)}</td>
      <td><span class="${p.dpa_status==='ACTIVE'||p.dpa_status==='COVERED_BY_GITHUB_DPA'?'badge-pass':'badge-skip'}">${esc(p.dpa_status)}</span></td>
      <td>${esc(p.data_location || '—')}</td>
      <td>${esc(p.justification || '—')}</td>
    </tr>
  `).join('');
  const r = d.retention_policy || {};
  $('retentionTable').innerHTML = `
    <tr><td><strong>Retencja pakietu dowodowego</strong></td><td>${esc(r.evidence_pack_retention_days || '—')} dni</td></tr>
    <tr><td><strong>Retencja dzienników</strong></td><td>${esc(r.log_retention_days || '—')} dni</td></tr>
    <tr><td><strong>Harmonogram usuwania</strong></td><td>${esc(r.deletion_schedule || '—')}</td></tr>
  `;
}

// ── DATA FLOW ────────────────────────────────────────────────────────
function renderDataFlow() {
  const d = DATA.data_flow || {};
  $('dfRows').innerHTML = (d.stages || []).map(s => `
    <tr>
      <td><strong>${esc(s.name)}</strong></td>
      <td>${esc(s.location)}</td>
      <td><span class="${s.pii_present?'badge-fail':'badge-pass'}">${s.pii_present?'TAK':'NIE'}</span></td>
      <td>${(s.pii_types||[]).map(t=>`<code style="font-size:.7rem">${esc(t)}</code>`).join('<br>')||'—'}</td>
      <td style="font-size:.78rem">${esc(s.pii_justification || '—')}</td>
      <td>${(s.data_flows_to||[]).map(t=>`<code style="font-size:.7rem">${esc(t)}</code>`).join('<br>')||'—'}</td>
    </tr>
  `).join('');
}

// ── RAW ──────────────────────────────────────────────────────────────
function renderRaw() {
  $('rawJson').textContent = JSON.stringify(DATA.pipeline, null, 2);
  $('codeqlStat').innerHTML = `<strong>${esc(DATA.codeql.findings.length)}</strong> znalezisk w <strong>${esc(DATA.codeql.rules_count)}</strong> regułach`;
  $('checkovStat').innerHTML = `<strong>${esc(DATA.checkov.findings.length)}</strong> znalezisk w <strong>${esc(DATA.checkov.rules_count)}</strong> regułach`;
  const cov = DATA.coverage;
  $('coverageStat').innerHTML = cov.available ? `
    <table><tbody>
      <tr><td>Linie</td><td><strong>${cov.lines.toFixed(1)}%</strong></td></tr>
      <tr><td>Instrukcje</td><td><strong>${cov.statements.toFixed(1)}%</strong></td></tr>
      <tr><td>Funkcje</td><td><strong>${cov.functions.toFixed(1)}%</strong></td></tr>
      <tr><td>Gałęzie</td><td><strong>${cov.branches.toFixed(1)}%</strong></td></tr>
    </tbody></table>` : '<p class="empty">Brak danych o pokryciu</p>';
}

// ── Global search ────────────────────────────────────────────────────
$('globalSearch').addEventListener('input', e => {
  const q = e.target.value;
  vulnFilters.q = q; sbomQ = q; zapFilter.q = q; invFilter.q = q;
  $('vulnSearch').value = q; $('sbomSearch').value = q; $('zapSearch').value = q; $('fileSearch').value = q;
  renderVulns(); renderSbom(); renderDast(); renderFiles();
});

// ── Init ─────────────────────────────────────────────────────────────
renderDashboard();
renderVulns();
renderSbom();
renderDast();
renderCompliance();
renderComplianceCode();
renderSigning();
renderFiles();
renderDpa();
renderDataFlow();
renderRaw();
</script>
</body>
</html>
"""

# Substitute header placeholders (the rest are filled by JS)
p = PAYLOAD["pipeline"]
HTML = (HTML
    .replace("__RUN_NUM__", escape(str(p["run_number"])))
    .replace("__ENV__", escape(str(p["environment"])))
    .replace("__REPO__", escape(str(p["repo"])))
    .replace("__SHA_SHORT__", escape(str(p["sha_short"])))
    .replace("__TIMESTAMP__", escape(str(p["timestamp"])))
    .replace("__RUN_ID__", escape(str(p["run_id"])))
    .replace("__WORM_FOOTER__", escape(WORM_FOOTER))
    .replace("__DATA__", DATA_JSON))

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"HTML report generated: {OUTPUT} ({len(HTML)} bytes)")
PYEOF
