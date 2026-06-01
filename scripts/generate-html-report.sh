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
dpa = load_json(EVIDENCE_DIR / "dpa-compliance-check.json") or {}
data_flow = load_json(EVIDENCE_DIR / "data-flow-diagram.json") or {}
sbom = load_json(EVIDENCE_DIR / "sbom.cyclonedx.json") or {}
trivy_sca = load_json(EVIDENCE_DIR / "trivy-sca-results.json") or {}
trivy_image = load_json(EVIDENCE_DIR / "trivy-image-results.json") or {}
zap = load_json(EVIDENCE_DIR / "zap-report.json") or {}
cosign_log = load_text(EVIDENCE_DIR / "cosign-verification.log")
manifest = load_text(EVIDENCE_DIR / "manifest.sha256")
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
    ("pipeline-run.json", "Pipeline execution metadata", "All frameworks"),
    ("security-report.json", "Consolidated scan results", "DORA Art.16, NIS2 Art.21"),
    ("sbom.cyclonedx.json", "Software Bill of Materials", "DORA Art.28, NIS2 Art.21.2.d"),
    ("cosign-verification.log", "Image signature proof", "ISO A.8.24, SOC2 CC8.1"),
    ("provenance.intoto.jsonl", "SLSA build provenance", "DORA Art.28, SLSA L2+"),
    ("zap-report.json", "DAST scan results (JSON)", "NIS2 Art.21.2.e, ISO A.8.28"),
    ("zap-report.html", "DAST scan results (HTML)", "NIS2 Art.21.2.e, ISO A.8.28"),
    ("compliance-matrix.json", "Framework control mapping", "All frameworks"),
    ("dpa-compliance-check.json", "Data processor agreements", "GDPR Art.28"),
    ("data-flow-diagram.json", "PII data flow map", "GDPR Art.25, Art.30"),
    ("manifest.sha256", "Integrity checksums", "ISO A.8.4, SOC2 PI1.1"),
    ("trivy-sca-results.json", "Dependency CVE scan", "DORA Art.16.1.c"),
    ("trivy-image-results.json", "Container image CVE scan", "NIS2 Art.21.2.d"),
    ("checkov-results.sarif", "IaC security scan", "ISO A.8.9, SOC2 CC8.1"),
    ("codeql/javascript.sarif", "SAST results", "ISO A.8.28, NIS2 Art.21.2.e"),
    ("dependency-review.json", "Dependency review", "DORA Art.16.1.c"),
    ("README.md", "Pack contents description", "—"),
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

# ── HTML template ────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Evidence Pack — CyberForge Pipeline</title>
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
    <span class="eyebrow" style="color:var(--blue3)">Evidence Pack Report</span>
    <h1>Pipeline Run #__RUN_NUM__ <em>— __ENV__</em></h1>
    <div class="h-meta">__REPO__ · commit __SHA_SHORT__ · __TIMESTAMP__ · run __RUN_ID__</div>
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
  <button class="tab active" data-tab="dashboard">Dashboard</button>
  <button class="tab" data-tab="vulns">Vulnerabilities <span class="tab-count" id="cnt-vulns">0</span></button>
  <button class="tab" data-tab="sbom">SBOM <span class="tab-count" id="cnt-sbom">0</span></button>
  <button class="tab" data-tab="dast">DAST <span class="tab-count" id="cnt-dast">0</span></button>
  <button class="tab" data-tab="compliance">Compliance</button>
  <button class="tab" data-tab="signing">Signing</button>
  <button class="tab" data-tab="files">Files <span class="tab-count" id="cnt-files">0</span></button>
  <button class="tab" data-tab="dpa">Vendors</button>
  <button class="tab" data-tab="dataflow">Data Flow</button>
  <button class="tab" data-tab="raw">Raw Data</button>
  <div class="search-wrap">
    <input type="text" id="globalSearch" placeholder="Search everything…">
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
    <h3>Pipeline Run</h3>
    <table>
      <tbody>
        <tr><td><strong>Pipeline</strong></td><td id="d-name"></td></tr>
        <tr><td><strong>Run</strong></td><td>#<span id="d-run-num"></span> (id <span id="d-run-id"></span>, attempt <span id="d-run-attempt"></span>)</td></tr>
        <tr><td><strong>Trigger</strong></td><td><span id="d-trigger"></span> by <span id="d-actor"></span></td></tr>
        <tr><td><strong>Ref</strong></td><td><code id="d-ref"></code></td></tr>
        <tr><td><strong>Commit</strong></td><td><code id="d-sha"></code></td></tr>
        <tr><td><strong>Repository</strong></td><td><a id="d-repo-link" target="_blank" rel="noopener"></a></td></tr>
        <tr><td><strong>Environment</strong></td><td id="d-env"></td></tr>
        <tr><td><strong>Image URI</strong></td><td><code id="d-imguri" style="font-size:.74rem"></code></td></tr>
        <tr><td><strong>Image Digest</strong></td><td><code id="d-imgdigest" style="font-size:.7rem;word-break:break-all"></code></td></tr>
        <tr><td><strong>Generated</strong></td><td id="d-generated"></td></tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Compliance Coverage</h3>
    <div class="donut-wrap">
      <svg class="donut" viewBox="0 0 120 120">
        <circle class="donut-track" cx="60" cy="60" r="48"/>
        <circle class="donut-fill" cx="60" cy="60" r="48" id="donutPathDash" stroke="var(--green)"/>
        <text class="donut-text" x="60" y="60" text-anchor="middle" font-size="18" id="donutPctDash">0%</text>
        <text class="donut-text" x="60" y="76" text-anchor="middle" font-size="8" fill="var(--dim)" font-weight="400">controls</text>
      </svg>
      <div style="flex:1">
        <div id="fwBars"></div>
      </div>
    </div>
  </div>
</div>

<div class="grid-2">
  <div class="card">
    <h3>Severity Breakdown</h3>
    <h4>Dependencies (Trivy SCA)</h4>
    <div id="trivyBars"></div>
    <h4>Container Image (Trivy)</h4>
    <div id="trivyImgBars"></div>
    <h4>Runtime (OWASP ZAP)</h4>
    <div id="zapBars"></div>
  </div>

  <div class="card">
    <h3>Tool Versions</h3>
    <table>
      <thead><tr><th>Tool</th><th>Version</th></tr></thead>
      <tbody id="toolsTable"></tbody>
    </table>
  </div>
</div>

</section>

<!-- ────────────────────────────── VULNS ────────────────────────────── -->
<section class="panel" id="panel-vulns">
<h2>Vulnerability Findings</h2>
<p>Combined view of dependency-level CVEs (Trivy SCA against package-lock.json) and container-level CVEs (Trivy image scan against the built Docker image). Click any row to expand for details.</p>

<div class="filter-row">
  <input type="text" class="filter-input" id="vulnSearch" placeholder="Filter by CVE, package, or title…">
  <button class="chip active" data-vsev="all">All</button>
  <button class="chip" data-vsev="CRITICAL">Critical</button>
  <button class="chip" data-vsev="HIGH">High</button>
  <button class="chip" data-vsev="MEDIUM">Medium</button>
  <button class="chip" data-vsev="LOW">Low</button>
  <button class="chip" data-vsrc="all">All sources</button>
  <button class="chip" data-vsrc="filesystem">SCA only</button>
  <button class="chip" data-vsrc="container">Image only</button>
</div>

<table id="vulnTable">
  <thead><tr>
    <th class="sortable" data-sort="severity">Severity</th>
    <th class="sortable" data-sort="cve">CVE</th>
    <th class="sortable" data-sort="package">Package</th>
    <th class="sortable" data-sort="installed">Installed</th>
    <th class="sortable" data-sort="fixed">Fixed in</th>
    <th class="sortable" data-sort="kind">Source</th>
    <th>Title</th>
  </tr></thead>
  <tbody id="vulnRows"></tbody>
</table>
<p id="vulnEmpty" class="empty" style="display:none">No vulnerabilities matching your filter.</p>
</section>

<!-- ────────────────────────────── SBOM ────────────────────────────── -->
<section class="panel" id="panel-sbom">
<h2>Software Bill of Materials</h2>
<p id="sbomMeta"></p>

<div class="grid-2">
  <div class="card">
    <h3>By Component Type</h3>
    <div id="sbomTypes"></div>
  </div>
  <div class="card">
    <h3>Top Licenses</h3>
    <div id="sbomLicenses"></div>
  </div>
</div>

<div class="filter-row">
  <input type="text" class="filter-input" id="sbomSearch" placeholder="Filter components…">
</div>

<table id="sbomTable">
  <thead><tr>
    <th class="sortable" data-sort="name">Name</th>
    <th class="sortable" data-sort="version">Version</th>
    <th class="sortable" data-sort="type">Type</th>
    <th class="sortable" data-sort="license">License</th>
    <th>PURL</th>
  </tr></thead>
  <tbody id="sbomRows"></tbody>
</table>
</section>

<!-- ────────────────────────────── DAST ────────────────────────────── -->
<section class="panel" id="panel-dast">
<h2>DAST Findings (OWASP ZAP)</h2>
<p>Runtime vulnerability scan against the deployed application: <code id="zapTarget"></code></p>

<div class="kpi-row" id="zapKpis"></div>

<div class="filter-row">
  <input type="text" class="filter-input" id="zapSearch" placeholder="Filter findings…">
  <button class="chip active" data-zsev="all">All</button>
  <button class="chip" data-zsev="High">High</button>
  <button class="chip" data-zsev="Medium">Medium</button>
  <button class="chip" data-zsev="Low">Low</button>
  <button class="chip" data-zsev="Informational">Info</button>
</div>

<div id="zapAlerts"></div>
</section>

<!-- ────────────────────────────── COMPLIANCE ────────────────────────────── -->
<section class="panel" id="panel-compliance">
<h2>Compliance Framework Mapping</h2>
<p>Click any framework to see its control-level mapping. Each control points to the evidence artifact that satisfies it.</p>

<div class="fw-grid" id="fwGrid"></div>
<div id="fwControls"></div>
</section>

<!-- ────────────────────────────── SIGNING ────────────────────────────── -->
<section class="panel" id="panel-signing">
<h2>Cosign Verification</h2>
<p>Cryptographic chain of custody from source code to deployed image. Cosign uses keyless signing via Sigstore — every signing event is recorded in the public Rekor transparency log.</p>

<div class="grid-2">
  <div class="card">
    <h3>Signature Status</h3>
    <p id="cosignStatus" style="font-size:1rem"></p>
    <h4>Extracted Claims</h4>
    <table id="cosignClaims"><tbody></tbody></table>
  </div>
  <div class="card">
    <h3>Verify Yourself</h3>
    <p>Anyone can independently verify this image was signed by this exact pipeline:</p>
    <div class="codeblock"><span class="copy-btn" onclick="copyEl('cosignCmd')">copy</span><span id="cosignCmd"></span></div>
  </div>
</div>

<div class="card">
  <h3>Raw Verification Log</h3>
  <p>Output of <code>cosign verify</code> at deploy time:</p>
  <div class="codeblock"><span class="copy-btn" onclick="copyEl('cosignRaw')">copy</span><span id="cosignRaw"></span></div>
</div>

<div class="card">
  <h3>SLSA Build Provenance</h3>
  <p>SLSA v1.0 provenance — proves how the image was built and what inputs were used. Excerpt:</p>
  <div class="codeblock"><span class="copy-btn" onclick="copyEl('provExcerpt')">copy</span><span id="provExcerpt"></span></div>
</div>
</section>

<!-- ────────────────────────────── FILES ────────────────────────────── -->
<section class="panel" id="panel-files">
<h2>Evidence File Inventory</h2>
<p>All artifacts in this evidence pack with their purpose, size, and SHA256 hash. The SHA256 manifest is regenerated at archive time — auditors can re-hash any file and compare to detect tampering.</p>

<div class="filter-row">
  <input type="text" class="filter-input" id="fileSearch" placeholder="Filter files…">
  <button class="chip active" data-fpres="all">All files</button>
  <button class="chip" data-fpres="present">Present only</button>
  <button class="chip" data-fpres="missing">Missing only</button>
</div>

<table id="invTable">
  <thead><tr>
    <th class="sortable" data-sort="name">File</th>
    <th class="sortable" data-sort="purpose">Purpose</th>
    <th>Compliance Anchor</th>
    <th class="sortable" data-sort="size">Size</th>
    <th>Status</th>
  </tr></thead>
  <tbody id="invRows"></tbody>
</table>

<h3 style="margin-top:24px">SHA256 Manifest</h3>
<p>Content-addressed integrity proof. Verify any file by running <code>sha256sum &lt;file&gt;</code> and comparing.</p>
<div class="filter-row">
  <input type="text" class="filter-input" id="manifestSearch" placeholder="Filter manifest…">
</div>
<table id="manifestTable">
  <thead><tr><th>SHA256 Hash</th><th>File</th></tr></thead>
  <tbody id="manifestRows"></tbody>
</table>
</section>

<!-- ────────────────────────────── DPA ────────────────────────────── -->
<section class="panel" id="panel-dpa">
<h2>Third-Party Processors (GDPR Art. 28)</h2>
<p id="dpaIntro"></p>

<table id="dpaTable">
  <thead><tr>
    <th>Vendor</th>
    <th>Service</th>
    <th>DPA Status</th>
    <th>Data Location</th>
    <th>Justification</th>
  </tr></thead>
  <tbody id="dpaRows"></tbody>
</table>

<div class="card" style="margin-top:14px">
  <h3>Retention Policy</h3>
  <table id="retentionTable"><tbody></tbody></table>
</div>
</section>

<!-- ────────────────────────────── DATA FLOW ────────────────────────────── -->
<section class="panel" id="panel-dataflow">
<h2>Data Flow Diagram (GDPR Art. 25 & 30)</h2>
<p>Personal data flow through the pipeline. PII presence is justified per stage; sanitisation removes developer emails before evidence archival.</p>

<table id="dfTable">
  <thead><tr>
    <th>Stage</th>
    <th>Location</th>
    <th>PII Present</th>
    <th>Types</th>
    <th>Justification</th>
    <th>Flows To</th>
  </tr></thead>
  <tbody id="dfRows"></tbody>
</table>
</section>

<!-- ────────────────────────────── RAW ────────────────────────────── -->
<section class="panel" id="panel-raw">
<h2>Raw Pipeline Run Data</h2>
<p>Complete JSON dump of <code>pipeline-run.json</code> — the source of truth for this report's metadata.</p>
<div class="codeblock"><span class="copy-btn" onclick="copyEl('rawJson')">copy</span><span id="rawJson"></span></div>

<h2 style="margin-top:24px">Tooling Summary</h2>
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
    <h3>Test Coverage</h3>
    <div id="coverageStat"></div>
  </div>
</div>
</section>

</div><!-- /wrap -->

<footer>
<div class="wrap">
  <p>Evidence Pack generated <span id="genAt"></span> · CyberForge DevSecOps Pipeline · <a href="https://cyberforge.agency">cyberforge.agency</a></p>
  <p>This pack is part of an immutable WORM archive (Azure Blob, 1825-day retention). SHA256-manifested. Tampering is detectable.</p>
</div>
</footer>

<script id="evidence-data" type="application/json">__DATA__</script>
<script>
// ═══════════════════════════════════════════════════════════════════
// Evidence report renderer
// ═══════════════════════════════════════════════════════════════════
const DATA = JSON.parse(document.getElementById('evidence-data').textContent);
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

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
  $('d-repo-link').href = p.repo_url;
  $('d-env').textContent = p.environment;
  $('d-imguri').textContent = p.image_uri;
  $('d-imgdigest').textContent = p.image_digest;
  $('d-generated').textContent = DATA.generated_at;

  // Replace header tokens already done server-side; just mirror here
  document.title = `Evidence Pack — Run #${p.run_number} (${p.environment})`;
  $('genAt').textContent = DATA.generated_at;

  // Phase row
  const phaseLabels = ['Security Gate','Build & Scan','Sign & Attest','Deploy','DAST'];
  const phaseKeys = ['security_gate','build_scan','sign_attest','deploy','dast'];
  const phaseRow = $('phaseRow');
  phaseRow.innerHTML = phaseKeys.map((k, i) => {
    const status = p.gates[k] || 'skipped';
    return `<div class="ph-node"><div class="ph-circle ${status}">${i+1}</div><div class="ph-name">${phaseLabels[i]}</div><div class="ph-status ${status}">${status}</div></div>`;
  }).join('') + `<div class="ph-node"><div class="ph-circle success">6</div><div class="ph-name">Evidence Pack</div><div class="ph-status success">success</div></div>`;

  // KPI row
  const s = DATA.stats;
  const kpis = [
    {n: `${s.gates_passed}/${s.gates_total}`, l: 'Gates Passed', cls: s.gates_passed===s.gates_total?'green':'amber'},
    {n: s.evidence_present + '/' + s.evidence_total, l: 'Evidence Files', cls: s.evidence_present>=11?'green':'amber'},
    {n: s.compliance_passed + '/' + s.compliance_total, l: 'Compliance Controls', cls: 'green'},
    {n: s.sbom_components, l: 'SBOM Components', cls: ''},
    {n: s.total_cves, l: 'Vulnerabilities', cls: s.critical_cves>0?'red':(s.high_cves>0?'amber':'green'), sub: `${s.critical_cves}C / ${s.high_cves}H`},
    {n: s.zap_high + s.zap_medium, l: 'DAST H+M', cls: s.zap_high>0?'red':(s.zap_medium>0?'amber':'green'), sub: `${s.zap_high}H / ${s.zap_medium}M`},
    {n: (s.coverage_lines||0).toFixed(0)+'%', l: 'Test Coverage', cls: s.coverage_lines>=80?'green':'amber'},
    {n: s.manifest_files, l: 'Manifested Files', cls: ''},
  ];
  $('kpiRow').innerHTML = kpis.map(k =>
    `<div class="kpi ${k.cls}"><div class="kpi-num">${k.n}</div><div class="kpi-lbl">${k.l}</div>${k.sub?`<div class="kpi-sub">${k.sub}</div>`:''}</div>`
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
    return `<div class="bar-row"><div class="bar-label">${fw.name}</div><div class="bar-track"><div class="bar-fill" style="width:${p}%;background:linear-gradient(90deg,var(--blue) 0%,var(--green) 100%)"></div></div><div class="bar-value">${fw.passed}/${fw.total}</div></div>`;
  }).join('');

  // Trivy bars
  const sevColors = {CRITICAL:'#DC2626',HIGH:'#EA580C',MEDIUM:'#D97706',LOW:'#2563EB',UNKNOWN:'#94A3B8'};
  function sevBars(counts) {
    const max = Math.max(1, ...Object.values(counts));
    return Object.entries(counts).map(([sev,n]) =>
      `<div class="bar-row"><div class="bar-label">${sev}</div><div class="bar-track"><div class="bar-fill" style="width:${n/max*100}%;background:${sevColors[sev]||'var(--blue)'}"></div></div><div class="bar-value">${n}</div></div>`
    ).join('');
  }
  $('trivyBars').innerHTML = sevBars(DATA.trivy_sca.severity_count);
  $('trivyImgBars').innerHTML = sevBars(DATA.trivy_image.severity_count);
  $('zapBars').innerHTML = sevBars(DATA.zap.severity_count);

  // Tools table
  $('toolsTable').innerHTML = Object.entries(DATA.pipeline.tools || {}).map(([k,v]) =>
    `<tr><td><strong>${esc(k)}</strong></td><td><code>${esc(v)}</code></td></tr>`
  ).join('') || '<tr><td colspan="2" class="empty">No tool versions recorded.</td></tr>';
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
      <td><span class="sev sev-${v.severity}">${v.severity}</span></td>
      <td><code>${esc(v.cve)}</code><span class="expand-icon">+</span></td>
      <td><code>${esc(v.package)}</code></td>
      <td><code>${esc(v.installed)}</code></td>
      <td><code>${esc(v.fixed||'—')}</code></td>
      <td>${v.kind==='filesystem'?'SCA':'Image'}</td>
      <td>${esc(v.title)}</td>
    </tr>
    <tr class="detail-row" id="vd-${idx}"><td colspan="7"><div class="detail-content">
      <dl>
        <dt>CVE</dt><dd><a href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.cve)}</a></dd>
        <dt>Target</dt><dd><code>${esc(v.target)}</code></dd>
        <dt>CVSS Score</dt><dd>${esc(v.cvss||'n/a')}</dd>
        <dt>Published</dt><dd>${esc(v.published||'—')}</dd>
        <dt>Remediation</dt><dd>${v.fixed?`Upgrade to <code>${esc(v.fixed)}</code>`:'No fix available — risk-accept via .trivyignore with VEX justification'}</dd>
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
  $('sbomMeta').innerHTML = `<strong>${s.total}</strong> components · format <code>${esc(s.format)}</code>`;
  // Type breakdown
  $('sbomTypes').innerHTML = Object.entries(s.types).map(([t,n]) => {
    const pct = (n/s.total*100).toFixed(1);
    return `<div class="bar-row"><div class="bar-label">${esc(t)}</div><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:var(--blue)"></div></div><div class="bar-value">${n}</div></div>`;
  }).join('');
  // Licenses
  $('sbomLicenses').innerHTML = Object.entries(s.licenses).map(([l,n]) => {
    const max = Math.max(...Object.values(s.licenses), 1);
    return `<div class="bar-row"><div class="bar-label">${esc(l)}</div><div class="bar-track"><div class="bar-fill" style="width:${n/max*100}%;background:var(--purple)"></div></div><div class="bar-value">${n}</div></div>`;
  }).join('') || '<p class="empty">No license metadata found.</p>';
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
  $('cnt-dast').textContent = z.alerts.length;
  $('zapTarget').textContent = z.target || '(unknown)';
  $('zapKpis').innerHTML = ['High','Medium','Low','Informational'].map(s => {
    const cls = s==='High'?'red':s==='Medium'?'amber':'';
    return `<div class="kpi ${cls}"><div class="kpi-num">${z.severity_count[s]||0}</div><div class="kpi-lbl">${s}</div></div>`;
  }).join('');
  const filtered = z.alerts.filter(a => {
    if (zapFilter.sev !== 'all' && a.risk !== zapFilter.sev) return false;
    if (zapFilter.q && !(a.name+a.desc+a.solution).toLowerCase().includes(zapFilter.q.toLowerCase())) return false;
    return true;
  });
  $('zapAlerts').innerHTML = filtered.length ? filtered.map((a,i) => `
    <div class="card">
      <h3><span class="sev sev-${a.risk}">${a.risk}</span> ${esc(a.name)}</h3>
      <table><tbody>
        <tr><td><strong>Confidence</strong></td><td>${esc(a.confidence)}</td></tr>
        ${a.cwe?`<tr><td><strong>CWE</strong></td><td><a href="https://cwe.mitre.org/data/definitions/${esc(a.cwe)}.html" target="_blank" rel="noopener">CWE-${esc(a.cwe)}</a></td></tr>`:''}
        <tr><td><strong>Instances</strong></td><td>${a.count} (showing ${Math.min(a.instances.length,10)})</td></tr>
      </tbody></table>
      <h4>Description</h4>
      <p>${esc(a.desc)}</p>
      <h4>Recommended Solution</h4>
      <p>${esc(a.solution)}</p>
      ${a.instances.length ? `
        <h4>Affected URLs</h4>
        <table><thead><tr><th>Method</th><th>URI</th></tr></thead><tbody>
          ${a.instances.map(i => `<tr><td><code>${esc(i.method)}</code></td><td><code style="font-size:.7rem">${esc(i.uri)}</code></td></tr>`).join('')}
        </tbody></table>` : ''}
    </div>
  `).join('') : '<p class="empty">No DAST findings match.</p>';
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
    return `<div class="fw-card ${cls}" data-fw="${esc(fw.name)}"><div class="fw-name">${esc(fw.name)}</div><div class="fw-cov">${fw.passed}/${fw.total}</div><div class="fw-lbl">controls</div></div>`;
  }).join('');
  $('fwControls').innerHTML = DATA.compliance.map(fw => `
    <div class="fw-controls ${activeFw===fw.name?'active':''}" data-fw="${esc(fw.name)}">
      <h3>${esc(fw.name)} — ${fw.passed} of ${fw.total} controls satisfied</h3>
      <table><thead><tr><th>Article</th><th>Requirement</th><th>Evidence</th><th>Status</th></tr></thead><tbody>
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

// ── SIGNING ──────────────────────────────────────────────────────────
function renderSigning() {
  const c = DATA.cosign;
  $('cosignStatus').innerHTML = c.verified
    ? '<span class="badge-pass">✓ VERIFIED</span> Image signature verified at deploy time.'
    : '<span class="badge-fail">UNVERIFIED</span>';
  $('cosignClaims').innerHTML = `<tbody>${
    Object.entries(c.claims).map(([k,v]) =>
      `<tr><td><strong>${esc(k)}</strong></td><td><code style="font-size:.74rem">${esc(v)}</code></td></tr>`
    ).join('') || '<tr><td colspan="2" class="empty">No claims extracted</td></tr>'
  }</tbody>`;
  const repo = DATA.pipeline.repo;
  const img = DATA.pipeline.image_uri || '';
  const dig = DATA.pipeline.image_digest || '';
  $('cosignCmd').textContent =
    `cosign verify \\\n  --certificate-identity-regexp='https://github.com/${repo}/' \\\n  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \\\n  ${img}@${dig}`;
  $('cosignRaw').textContent = c.raw || '(no log captured)';
  $('provExcerpt').textContent = DATA.provenance_excerpt || '(no provenance captured)';
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
      <td><span class="${f.present?'badge-pass':'badge-fail'}">${f.present?'PRESENT':'MISSING'}</span></td>
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
    <tr><td><strong>Evidence pack retention</strong></td><td>${esc(r.evidence_pack_retention_days || '—')} days</td></tr>
    <tr><td><strong>Log retention</strong></td><td>${esc(r.log_retention_days || '—')} days</td></tr>
    <tr><td><strong>Deletion schedule</strong></td><td>${esc(r.deletion_schedule || '—')}</td></tr>
  `;
}

// ── DATA FLOW ────────────────────────────────────────────────────────
function renderDataFlow() {
  const d = DATA.data_flow || {};
  $('dfRows').innerHTML = (d.stages || []).map(s => `
    <tr>
      <td><strong>${esc(s.name)}</strong></td>
      <td>${esc(s.location)}</td>
      <td><span class="${s.pii_present?'badge-fail':'badge-pass'}">${s.pii_present?'YES':'NO'}</span></td>
      <td>${(s.pii_types||[]).map(t=>`<code style="font-size:.7rem">${esc(t)}</code>`).join('<br>')||'—'}</td>
      <td style="font-size:.78rem">${esc(s.pii_justification || '—')}</td>
      <td>${(s.data_flows_to||[]).map(t=>`<code style="font-size:.7rem">${esc(t)}</code>`).join('<br>')||'—'}</td>
    </tr>
  `).join('');
}

// ── RAW ──────────────────────────────────────────────────────────────
function renderRaw() {
  $('rawJson').textContent = JSON.stringify(DATA.pipeline, null, 2);
  $('codeqlStat').innerHTML = `<strong>${DATA.codeql.findings.length}</strong> findings across <strong>${DATA.codeql.rules_count}</strong> rules`;
  $('checkovStat').innerHTML = `<strong>${DATA.checkov.findings.length}</strong> findings across <strong>${DATA.checkov.rules_count}</strong> rules`;
  const cov = DATA.coverage;
  $('coverageStat').innerHTML = cov.available ? `
    <table><tbody>
      <tr><td>Lines</td><td><strong>${cov.lines.toFixed(1)}%</strong></td></tr>
      <tr><td>Statements</td><td><strong>${cov.statements.toFixed(1)}%</strong></td></tr>
      <tr><td>Functions</td><td><strong>${cov.functions.toFixed(1)}%</strong></td></tr>
      <tr><td>Branches</td><td><strong>${cov.branches.toFixed(1)}%</strong></td></tr>
    </tbody></table>` : '<p class="empty">No coverage data</p>';
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
    .replace("__DATA__", DATA_JSON))

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"HTML report generated: {OUTPUT} ({len(HTML)} bytes)")
PYEOF
